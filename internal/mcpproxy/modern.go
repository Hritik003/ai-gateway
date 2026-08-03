// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0

package mcpproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// servePOSTStateless handles modern (2026-07-28) stateless POST requests.
// This is the Phase 1 entry point for modern clients talking to modern backends.
// The JSON-RPC request has already been parsed by servePOST.
func (m *mcpRequestContext) servePOSTStateless(w http.ResponseWriter, r *http.Request, req *jsonrpc.Request) {
	ctx := r.Context()

	// P1.11: Route header on every request.
	route := filterapi.MCPRouteName(r.Header.Get(internalapi.MCPRouteHeader))
	if route == "" {
		m.l.Error("missing route header on modern request")
		writeJSONRPCError(w, http.StatusInternalServerError, nil, -32603, "missing route header")
		return
	}

	// P1.2: Validate Mcp-Method matches body method.
	headerMethod := r.Header.Get(mcpMethodHeader)
	if headerMethod != req.Method {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, errCodeHeaderMismatch,
			fmt.Sprintf("Mcp-Method header '%s' does not match body method '%s'", headerMethod, req.Method))
		return
	}

	// P1.2: Validate protocol version.
	headerVersion := r.Header.Get(mcpProtocolVersionHeader)
	if headerVersion == "" {
		headerVersion = protocolVersion20260728
	}
	if !isSupportedVersion(headerVersion) {
		writeJSONRPCErrorWithData(w, http.StatusBadRequest, &req.ID, errCodeUnsupportedProtocolVersion,
			"unsupported protocol version", map[string]any{"supported": supportedVersions})
		return
	}

	// P1.10: Reject removed methods on modern path.
	switch req.Method {
	case "initialize", "notifications/initialized":
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, errCodeMethodNotFound, "method removed in 2026-07-28: use server/discover")
		return
	case "ping":
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, errCodeMethodNotFound, "ping removed in 2026-07-28")
		return
	case "logging/setLevel":
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, errCodeMethodNotFound, "logging/setLevel removed in 2026-07-28; use _meta logLevel")
		return
	}

	// Dispatch based on method.
	switch req.Method {
	case "server/discover":
		m.handleServerDiscover(ctx, w, req, route)
	case "tools/list":
		m.handleModernToolsList(ctx, w, r, req, route)
	case "tools/call":
		m.handleModernToolsCall(ctx, w, r, req, route)
	case "resources/list":
		m.handleModernResourcesList(ctx, w, r, req, route)
	case "resources/read":
		m.handleModernResourcesRead(ctx, w, r, req, route)
	case "prompts/list":
		m.handleModernPromptsList(ctx, w, r, req, route)
	case "prompts/get":
		m.handleModernPromptsGet(ctx, w, r, req, route)
	case "subscriptions/listen":
		m.handleSubscriptionsListen(ctx, w, r, req, route)
	case "completion/complete":
		m.handleModernComplete(ctx, w, r, req, route)
	default:
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, errCodeMethodNotFound,
			fmt.Sprintf("unknown method: %s", req.Method))
	}
}

// handleServerDiscover implements the server/discover handler (P1.4).
// Fans out server/discover to all backends, merges results.
func (m *mcpRequestContext) handleServerDiscover(ctx context.Context, w http.ResponseWriter, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	var results []*mcp.DiscoverResult
	for _, backend := range routeConfig.backends {
		result, err := m.capCache.discoverBackend(ctx, &m.client, m.backendListenerAddr, route, backend)
		if err != nil {
			m.l.Warn("server/discover failed for backend",
				slog.String("backend", string(backend.Name)),
				slog.String("error", err.Error()))
			continue
		}
		results = append(results, result)
	}

	merged := mergeDiscoverResults(results)
	merged.Instructions = fmt.Sprintf("Envoy AI Gateway — MCP proxy aggregating %d backends", len(routeConfig.backends))

	writeJSONRPCResult(w, req.ID, merged)
}

// handleModernToolsList handles tools/list on the modern stateless path (P1.7).
func (m *mcpRequestContext) handleModernToolsList(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	// Fan out to all backends.
	allTools := make([]*mcp.Tool, 0)
	for backendName, backend := range routeConfig.backends {
		resp, err := m.sendModernRequest(ctx, req, route, backend)
		if err != nil {
			m.l.Warn("tools/list failed for backend",
				slog.String("backend", string(backendName)),
				slog.String("error", err.Error()))
			continue
		}
		var listResult mcp.ListToolsResult
		if err := json.Unmarshal(resp, &listResult); err != nil {
			m.l.Warn("failed to unmarshal tools/list from backend",
				slog.String("backend", string(backendName)),
				slog.String("error", err.Error()))
			continue
		}
		selector := routeConfig.toolSelectors[backendName]
		for _, t := range listResult.Tools {
			// Enforce per-route tool selector filters.
			if selector != nil && !selector.allows(t.Name) {
				continue
			}
			// Enforce per-route authorization so callers only see invokable tools.
			if routeConfig.authorization != nil {
				allowed, _ := m.authorizeRequest(routeConfig.authorization, &authorizationRequest{
					Headers:   r.Header,
					MCPMethod: "tools/call",
					Backend:   string(backendName),
					Tool:      t.Name,
				})
				if !allowed {
					continue
				}
			}
			// Prefix tool names with backend name for namespace isolation.
			t.Name = downstreamResourceName(t.Name, string(backendName))
			allTools = append(allTools, t)
		}
	}

	result := &mcp.ListToolsResult{Tools: allTools}
	writeJSONRPCResult(w, req.ID, result)
}

// handleModernToolsCall handles tools/call on the modern stateless path (P1.5).
// Routes to the single backend identified by the backend__toolName prefix.
func (m *mcpRequestContext) handleModernToolsCall(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	// Extract tool name from params.
	var params mcp.CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, "invalid tools/call params")
		return
	}

	// Decode backend from prefixed tool name.
	backendName, upstreamName, err := upstreamResourceName(params.Name)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid tool name: %v", err))
		return
	}

	backend, ok := routeConfig.backends[filterapi.MCPBackendName(backendName)]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, errCodeResourceNotFound, fmt.Sprintf("backend not found: %s", backendName))
		return
	}

	// Rewrite the params with the unprefixed name.
	params.Name = upstreamName
	rewrittenParams, _ := json.Marshal(params)
	req.Params = rewrittenParams

	// Send to backend and proxy the response (P1.9: MRTR passthrough).
	resp, err := m.sendModernRequest(ctx, req, route, backend)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadGateway, &req.ID, -32603, fmt.Sprintf("backend error: %v", err))
		return
	}

	// Pass through verbatim — includes resultType (complete or input_required).
	writeRawJSONRPCResult(w, req.ID, resp)
}

// handleModernResourcesList handles resources/list (P1.7 fan-out).
func (m *mcpRequestContext) handleModernResourcesList(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	var allResources []*mcp.Resource
	for backendName, backend := range routeConfig.backends {
		resp, err := m.sendModernRequest(ctx, req, route, backend)
		if err != nil {
			m.l.Warn("resources/list failed for backend", slog.String("backend", string(backendName)), slog.String("error", err.Error()))
			continue
		}
		var listResult mcp.ListResourcesResult
		if err := json.Unmarshal(resp, &listResult); err != nil {
			continue
		}
		for _, r := range listResult.Resources {
			r.URI = downstreamResourceURI(r.URI, string(backendName))
		}
		allResources = append(allResources, listResult.Resources...)
	}
	result := &mcp.ListResourcesResult{Resources: allResources}
	writeJSONRPCResult(w, req.ID, result)
}

// handleModernResourcesRead handles resources/read (P1.5 single-target).
func (m *mcpRequestContext) handleModernResourcesRead(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	var params mcp.ReadResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, "invalid resources/read params")
		return
	}

	backendName, upstreamURI, err := upstreamResourceURI(params.URI)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid resource URI: %v", err))
		return
	}

	backend, ok := routeConfig.backends[filterapi.MCPBackendName(backendName)]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, errCodeResourceNotFound, fmt.Sprintf("backend not found: %s", backendName))
		return
	}

	params.URI = upstreamURI
	rewrittenParams, _ := json.Marshal(params)
	req.Params = rewrittenParams

	resp, err := m.sendModernRequest(ctx, req, route, backend)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadGateway, &req.ID, -32603, fmt.Sprintf("backend error: %v", err))
		return
	}
	writeRawJSONRPCResult(w, req.ID, resp)
}

// handleModernPromptsList handles prompts/list (P1.7 fan-out).
func (m *mcpRequestContext) handleModernPromptsList(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	var allPrompts []*mcp.Prompt
	for backendName, backend := range routeConfig.backends {
		resp, err := m.sendModernRequest(ctx, req, route, backend)
		if err != nil {
			m.l.Warn("prompts/list failed for backend", slog.String("backend", string(backendName)), slog.String("error", err.Error()))
			continue
		}
		var listResult mcp.ListPromptsResult
		if err := json.Unmarshal(resp, &listResult); err != nil {
			continue
		}
		for _, p := range listResult.Prompts {
			p.Name = downstreamResourceName(p.Name, string(backendName))
		}
		allPrompts = append(allPrompts, listResult.Prompts...)
	}
	result := &mcp.ListPromptsResult{Prompts: allPrompts}
	writeJSONRPCResult(w, req.ID, result)
}

// handleModernPromptsGet handles prompts/get (P1.5 single-target).
func (m *mcpRequestContext) handleModernPromptsGet(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	var params mcp.GetPromptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, "invalid prompts/get params")
		return
	}

	backendName, upstreamName, err := upstreamResourceName(params.Name)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid prompt name: %v", err))
		return
	}

	backend, ok := routeConfig.backends[filterapi.MCPBackendName(backendName)]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, errCodeResourceNotFound, fmt.Sprintf("backend not found: %s", backendName))
		return
	}

	params.Name = upstreamName
	rewrittenParams, _ := json.Marshal(params)
	req.Params = rewrittenParams

	resp, err := m.sendModernRequest(ctx, req, route, backend)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadGateway, &req.ID, -32603, fmt.Sprintf("backend error: %v", err))
		return
	}
	writeRawJSONRPCResult(w, req.ID, resp)
}

// handleModernComplete handles completion/complete (P1.5 single-target).
func (m *mcpRequestContext) handleModernComplete(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	// completion/complete targets a specific resource by ref; for the POC just proxy to first backend.
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}
	for _, backend := range routeConfig.backends {
		resp, err := m.sendModernRequest(ctx, req, route, backend)
		if err != nil {
			continue
		}
		writeRawJSONRPCResult(w, req.ID, resp)
		return
	}
	writeJSONRPCError(w, http.StatusBadGateway, &req.ID, -32603, "all backends failed")
}

// handleSubscriptionsListen handles subscriptions/listen (P1.8).
// Opens SSE streams to backends and merges notification events.
func (m *mcpRequestContext) handleSubscriptionsListen(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	// Set SSE response headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	if flusher != nil {
		flusher.Flush()
	}

	// Fan out subscriptions/listen to all backends.
	type backendStream struct {
		name string
		resp *http.Response
	}
	var streams []backendStream
	for _, backend := range routeConfig.backends {
		body, _ := jsonrpc.EncodeMessage(req)
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.backendListenerAddr, bytes.NewReader(body))
		if err != nil {
			continue
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "text/event-stream")
		httpReq.Header.Set(mcpProtocolVersionHeader, protocolVersion20260728)
		httpReq.Header.Set(mcpMethodHeader, "subscriptions/listen")
		httpReq.Header.Set(internalapi.MCPBackendHeader, string(backend.Name))
		httpReq.Header.Set(internalapi.MCPRouteHeader, string(route))

		resp, err := m.client.Do(httpReq)
		if err != nil {
			m.l.Warn("subscriptions/listen failed", slog.String("backend", string(backend.Name)), slog.String("error", err.Error()))
			continue
		}
		if resp.StatusCode == http.StatusOK {
			streams = append(streams, backendStream{name: string(backend.Name), resp: resp})
		} else {
			resp.Body.Close()
		}
	}

	// Merge streams: forward events from any backend to the client.
	// For the POC, we do a simple sequential read from each stream.
	// A production implementation would use goroutines + select.
	done := ctx.Done()
	buf := make([]byte, 4096)
	for _, s := range streams {
		defer s.resp.Body.Close()
	}

	// Simple keep-alive + event forwarding loop.
	for {
		select {
		case <-done:
			return
		default:
		}
		forwarded := false
		for _, s := range streams {
			n, err := s.resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if flusher != nil {
					flusher.Flush()
				}
				forwarded = true
				// Invalidate cache on list_changed notifications.
				if strings.Contains(string(buf[:n]), "list_changed") {
					m.capCache.invalidateRoute(route)
				}
			}
			if err != nil {
				break
			}
		}
		if !forwarded {
			// Send keep-alive comment.
			_, _ = w.Write([]byte(": keep-alive\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// sendModernRequest sends a JSON-RPC request to a modern backend with proper headers (P1.6).
// Returns the raw result JSON. Handles both plain JSON and SSE response formats.
func (m *mcpRequestContext) sendModernRequest(ctx context.Context, req *jsonrpc.Request, route filterapi.MCPRouteName, backend filterapi.MCPBackend) (json.RawMessage, error) {
	body, err := jsonrpc.EncodeMessage(req)
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, m.backendListenerAddr, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// P1.6: Set modern headers. No Mcp-Session-Id, no Last-Event-Id.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream, application/json")
	httpReq.Header.Set(mcpProtocolVersionHeader, protocolVersion20260728)
	httpReq.Header.Set(mcpMethodHeader, req.Method)
	httpReq.Header.Set(internalapi.MCPBackendHeader, string(backend.Name))
	httpReq.Header.Set(internalapi.MCPRouteHeader, string(route))

	// Set Mcp-Name if applicable.
	if name := extractNameForMethod(req.Method, json.RawMessage(req.Params)); name != "" {
		httpReq.Header.Set(mcpNameHeader, name)
	}

	resp, err := m.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("backend returned status %d: %s", resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Determine response format: SSE or plain JSON.
	contentType := resp.Header.Get("Content-Type")
	var jsonPayload []byte

	if strings.Contains(contentType, "text/event-stream") || strings.HasPrefix(string(respBody), "event:") || strings.HasPrefix(string(respBody), "data:") {
		// Parse SSE: find the last "data:" line which contains the JSON-RPC response.
		jsonPayload = extractJSONFromSSE(respBody)
		if jsonPayload == nil {
			return nil, fmt.Errorf("no JSON-RPC response found in SSE stream")
		}
	} else {
		jsonPayload = respBody
	}

	// Parse JSON-RPC response. Use map to avoid jsonrpc.ID unmarshal issues with sonic.
	var rpcResp map[string]json.RawMessage
	if err := json.Unmarshal(jsonPayload, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse response: %w (body: %.200s)", err, string(jsonPayload))
	}
	if errField, ok := rpcResp["error"]; ok && string(errField) != "null" {
		return nil, fmt.Errorf("backend error: %s", string(errField))
	}
	result, ok := rpcResp["result"]
	if !ok || string(result) == "null" {
		return nil, fmt.Errorf("backend returned no result")
	}
	return result, nil
}

// extractJSONFromSSE parses an SSE response body and extracts the last JSON-RPC
// message from "data:" lines. MCP backends return the final result as the last event.
func extractJSONFromSSE(body []byte) []byte {
	var lastData []byte
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if data != "" && data != "[DONE]" {
				lastData = []byte(data)
			}
		}
	}
	return lastData
}

// extractNameForMethod returns the name/uri field for methods that require Mcp-Name header.
func extractNameForMethod(method string, params json.RawMessage) string {
	if params == nil {
		return ""
	}
	switch method {
	case "tools/call":
		var p struct{ Name string }
		if json.Unmarshal(params, &p) == nil {
			return p.Name
		}
	case "prompts/get":
		var p struct{ Name string }
		if json.Unmarshal(params, &p) == nil {
			return p.Name
		}
	case "resources/read":
		var p struct{ URI string }
		if json.Unmarshal(params, &p) == nil {
			return p.URI
		}
	}
	return ""
}

// --- JSON-RPC response helpers ---

func writeJSONRPCError(w http.ResponseWriter, httpStatus int, id *jsonrpc.ID, code int, message string) {
	writeJSONRPCErrorWithData(w, httpStatus, id, code, message, nil)
}

func writeJSONRPCErrorWithData(w http.ResponseWriter, httpStatus int, id *jsonrpc.ID, code int, message string, data any) {
	resp := map[string]any{
		"jsonrpc": "2.0",
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}
	if id != nil {
		resp["id"] = id.Raw()
	} else {
		resp["id"] = nil
	}
	if data != nil {
		resp["error"].(map[string]any)["data"] = data
	}
	encoded, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	_, _ = w.Write(encoded)
}

func writeJSONRPCResult(w http.ResponseWriter, id jsonrpc.ID, result any) {
	encoded, _ := json.Marshal(result)
	writeRawJSONRPCResult(w, id, encoded)
}

func writeRawJSONRPCResult(w http.ResponseWriter, id jsonrpc.ID, result json.RawMessage) {
	// P1.12: Ensure resultType: "complete" is present.
	result = ensureResultType(result)

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      id.Raw(),
		"result":  json.RawMessage(result),
	}
	encoded, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(encoded)
}

// ensureResultType injects "resultType":"complete" if the field is absent (P1.12).
func ensureResultType(result json.RawMessage) json.RawMessage {
	if result == nil {
		return []byte(`{"resultType":"complete"}`)
	}
	var check map[string]json.RawMessage
	if json.Unmarshal(result, &check) != nil {
		return result
	}
	if _, ok := check["resultType"]; ok {
		return result // Already has resultType (could be "input_required" from MRTR).
	}
	check["resultType"] = json.RawMessage(`"complete"`)
	out, _ := json.Marshal(check)
	return out
}

// isSupportedVersion checks if a protocol version is in our supported set.
func isSupportedVersion(v string) bool {
	for _, sv := range supportedVersions {
		if sv == v {
			return true
		}
	}
	return false
}
