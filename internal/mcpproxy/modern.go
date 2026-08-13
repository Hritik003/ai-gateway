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
	"strconv"
	"strings"
	"sync"
	"time"

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
	case "resources/templates/list":
		m.handleModernResourceTemplatesList(ctx, w, r, req, route)
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
		result, err := m.discoverBackend(ctx, route, backend)
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
	// Caching spec: server/discover results MUST carry caching hints. Identity
	// and capabilities are identical for all callers, so the response is public.
	merged.TTLMs = defaultListTTLMs
	merged.CacheScope = cacheScopePublic

	writeJSONRPCResult(w, req.ID, merged)
}

// sendToAllModernBackendsAndAggregateResponses fans out a modern (stateless) list request to all backends in
// the route and collects each backend's result unmarshaled into T. Backends that
// fail the request or whose result cannot be unmarshaled are logged and skipped,
// mirroring the "partial failure is non-fatal" behavior of the legacy aggregation
// path (sendToAllBackendsAndAggregateResponses).
//
// The returned []broadCastResponse[T] is intentionally shaped like the legacy
// aggregation input so the modern handlers can reuse the same merge* functions
// (mergeToolsList, mergeResourceList, ...) and avoid drifting from the legacy
// prefixing/filtering/authorization logic.
func sendToAllModernBackendsAndAggregateResponses[T any](ctx context.Context, m *mcpRequestContext, req *jsonrpc.Request, route filterapi.MCPRouteName, routeConfig *mcpProxyConfigRoute) []broadCastResponse[T] {
	responses := make([]broadCastResponse[T], 0, len(routeConfig.backends))
	for backendName, backend := range routeConfig.backends {
		resp, err := m.sendModernRequest(ctx, req, route, backend)
		if err != nil {
			m.l.Warn("modern list request failed for backend",
				slog.String("method", req.Method),
				slog.String("backend", string(backendName)),
				slog.String("error", err.Error()))
			continue
		}
		var result T
		if err := json.Unmarshal(resp, &result); err != nil {
			m.l.Warn("failed to unmarshal modern list response from backend",
				slog.String("method", req.Method),
				slog.String("backend", string(backendName)),
				slog.String("error", err.Error()))
			continue
		}
		responses = append(responses, broadCastResponse[T]{backendName: string(backendName), res: result})
	}
	return responses
}

// handleModernToolsList handles tools/list on the modern stateless path (P1.7).
func (m *mcpRequestContext) handleModernToolsList(ctx context.Context, w http.ResponseWriter, r *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	// mergeToolsList reads per-caller headers from m.requestHeaders for authorization.
	// In production this is set at construction (== r.Header); ensure it is populated
	// even when this handler is invoked directly (e.g. in tests) so auth stays enforced.
	m.requestHeaders = r.Header

	responses := sendToAllModernBackendsAndAggregateResponses[mcp.ListToolsResult](ctx, m, req, route, routeConfig)
	// Reuse the shared merge logic so tool-selector filtering, per-caller
	// authorization, and backend name prefixing stay identical to the legacy path.
	result := m.mergeToolsList(&session{route: route}, responses)
	// Caching spec: tools/list results MUST carry caching hints. The set is
	// filtered per-caller authorization, so it is scoped private.
	result.TTLMs = defaultListTTLMs
	result.CacheScope = cacheScopePrivate
	writeJSONRPCResult(w, req.ID, &result)
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

	// Enforce per-route tool selector filters.
	if selector := routeConfig.toolSelectors[filterapi.MCPBackendName(backendName)]; selector != nil && !selector.allows(upstreamName) {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid tool name: %s", upstreamName))
		return
	}

	// Enforce per-route authorization (same semantics as legacy path).
	if routeConfig.authorization != nil {
		httpPath := ""
		if r.URL != nil {
			httpPath = r.URL.Path
		}
		allowed, requiredScopes := m.authorizeRequest(routeConfig.authorization, &authorizationRequest{
			Headers:    r.Header,
			HTTPMethod: r.Method,
			Host:       r.Host,
			HTTPPath:   httpPath,
			MCPMethod:  req.Method,
			Backend:    backendName,
			Tool:       upstreamName,
			Params:     &params,
		})
		if !allowed {
			// Include a scope challenge when available.
			if len(requiredScopes) > 0 {
				if challenge := buildInsufficientScopeHeader(requiredScopes, routeConfig.authorization.ResourceMetadataURL); challenge != "" {
					w.Header().Set("WWW-Authenticate", challenge)
				}
			}
			writeJSONRPCError(w, http.StatusForbidden, &req.ID, -32603, "access denied")
			return
		}
	}

	// Rewrite the params with the unprefixed name.
	params.Name = upstreamName
	rewrittenParams, err := json.Marshal(params)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid tools/call params: %v", err))
		return
	}
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
func (m *mcpRequestContext) handleModernResourcesList(ctx context.Context, w http.ResponseWriter, _ *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	responses := sendToAllModernBackendsAndAggregateResponses[mcp.ListResourcesResult](ctx, m, req, route, routeConfig)
	// Reuse the shared merge logic so name/URI prefixing stays identical to the legacy path.
	result := m.mergeResourceList(&session{route: route}, responses)
	// Caching spec: resources/list results MUST carry caching hints.
	result.TTLMs = defaultListTTLMs
	result.CacheScope = cacheScopePublic
	writeJSONRPCResult(w, req.ID, &result)
}

// handleModernResourceTemplatesList handles resources/templates/list (P1.7 fan-out).
// Fans out to all backends and namespaces each template's uriTemplate with the
// backend prefix, mirroring resources/list.
func (m *mcpRequestContext) handleModernResourceTemplatesList(ctx context.Context, w http.ResponseWriter, _ *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	responses := sendToAllModernBackendsAndAggregateResponses[mcp.ListResourceTemplatesResult](ctx, m, req, route, routeConfig)
	// Reuse the shared merge logic so name/URI-template prefixing stays identical to the legacy path.
	result := m.mergeResourcesTemplateList(&session{route: route}, responses)
	// Caching spec: resources/templates/list results MUST carry caching hints.
	result.TTLMs = defaultListTTLMs
	result.CacheScope = cacheScopePublic
	writeJSONRPCResult(w, req.ID, &result)
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
	rewrittenParams, err := json.Marshal(params)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid resources/read params: %v", err))
		return
	}
	req.Params = rewrittenParams

	resp, err := m.sendModernRequest(ctx, req, route, backend)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadGateway, &req.ID, -32603, fmt.Sprintf("backend error: %v", err))
		return
	}

	// Re-prefix content URIs back to downstream form so clients see consistent
	// namespaced URIs, and ensure caching hints are present. resources/read
	// results are user-specific, so default to a private scope when the backend
	// omits its own hints.
	//
	// Interim MRTR results (resultType: "input_required") are not cacheable and
	// must pass through verbatim, so only rewrite "complete" results.
	rewritten, ok := rewriteResourcesReadResult(resp, backendName)
	if !ok {
		writeRawJSONRPCResult(w, req.ID, resp)
		return
	}
	writeRawJSONRPCResult(w, req.ID, rewritten)
}

// rewriteResourcesReadResult re-prefixes content URIs and injects caching hints
// on a complete resources/read result. It operates on the raw JSON map so that
// unknown fields (e.g. MRTR input_required state) are preserved. It returns
// (rewritten, true) for a complete result, or (nil, false) when the result
// should be passed through verbatim (parse failure or non-complete result).
func rewriteResourcesReadResult(result json.RawMessage, backendName string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	if json.Unmarshal(result, &m) != nil {
		return nil, false
	}
	// Non-complete (input_required) results are not cacheable; leave untouched.
	if rt, ok := m["resultType"]; ok {
		var s string
		if json.Unmarshal(rt, &s) == nil && s != "" && s != "complete" {
			return nil, false
		}
	}
	if _, ok := m["inputRequests"]; ok {
		return nil, false
	}

	if raw, ok := m["contents"]; ok {
		var contents []map[string]json.RawMessage
		if json.Unmarshal(raw, &contents) == nil {
			for _, c := range contents {
				uriRaw, ok := c["uri"]
				if !ok {
					continue
				}
				var uri string
				if json.Unmarshal(uriRaw, &uri) == nil && uri != "" {
					prefixed, _ := json.Marshal(downstreamResourceURI(uri, backendName))
					c["uri"] = prefixed
				}
			}
			if out, err := json.Marshal(contents); err == nil {
				m["contents"] = out
			}
		}
	}

	if _, ok := m["ttlMs"]; !ok {
		m["ttlMs"] = json.RawMessage(strconv.Itoa(defaultListTTLMs))
	}
	if _, ok := m["cacheScope"]; !ok {
		scope, _ := json.Marshal(cacheScopePrivate)
		m["cacheScope"] = scope
	}

	out, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return out, true
}

// handleModernPromptsList handles prompts/list (P1.7 fan-out).
func (m *mcpRequestContext) handleModernPromptsList(ctx context.Context, w http.ResponseWriter, _ *http.Request, req *jsonrpc.Request, route filterapi.MCPRouteName) {
	routeConfig, ok := m.routes[route]
	if !ok {
		writeJSONRPCError(w, http.StatusNotFound, &req.ID, -32602, "route not found")
		return
	}

	responses := sendToAllModernBackendsAndAggregateResponses[mcp.ListPromptsResult](ctx, m, req, route, routeConfig)
	// Reuse the shared merge logic so name prefixing stays identical to the legacy path.
	result := m.mergePromptsList(&session{route: route}, responses)
	// Caching spec: prompts/list results MUST carry caching hints.
	result.TTLMs = defaultListTTLMs
	result.CacheScope = cacheScopePublic
	writeJSONRPCResult(w, req.ID, &result)
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
	rewrittenParams, err := json.Marshal(params)
	if err != nil {
		writeJSONRPCError(w, http.StatusBadRequest, &req.ID, -32602, fmt.Sprintf("invalid prompts/get params: %v", err))
		return
	}
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

	// Fan out subscriptions/listen to all backends and parse each stream so we
	// can rewrite backend-scoped notification payloads (e.g. resources/updated
	// URIs) into the gateway's downstream namespace before forwarding.
	var backendResps []*http.Response
	events := make(chan *sseEvent)
	var wg sync.WaitGroup
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
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		backendResps = append(backendResps, resp)
		backendName := backend.Name
		wg.Go(func() {
			parser := newSSEEventParser(resp.Body, backendName)
			for {
				event, err := parser.next()
				if event != nil {
					select {
					case events <- event:
					case <-ctx.Done():
						return
					}
				}
				if err != nil {
					return
				}
			}
		})
	}

	for _, resp := range backendResps {
		defer resp.Body.Close()
	}

	// Close the events channel once all backend readers finish so the merge loop
	// can drain and exit cleanly.
	go func() {
		wg.Wait()
		close(events)
	}()

	// Merge loop: forward rewritten events to the client, sending periodic
	// keep-alives while idle.
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()
	done := ctx.Done()
	for {
		select {
		case <-done:
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			m.forwardSubscriptionEvent(w, route, event)
			if flusher != nil {
				flusher.Flush()
			}
		case <-keepAlive.C:
			_, _ = w.Write([]byte(": keep-alive\n\n"))
			if flusher != nil {
				flusher.Flush()
			}
		}
	}
}

// forwardSubscriptionEvent rewrites and forwards a single SSE notification event
// from a backend to the downstream client. It de-prefixes resources/updated URIs
// into the gateway's downstream namespace and invalidates the capability cache on
// list_changed notifications.
func (m *mcpRequestContext) forwardSubscriptionEvent(w io.Writer, route filterapi.MCPRouteName, event *sseEvent) {
	for _, msg := range event.messages {
		req, ok := msg.(*jsonrpc.Request)
		if !ok || req == nil {
			continue
		}
		switch req.Method {
		case "notifications/resources/updated":
			// Re-prefix the resource URI so the client sees the same namespaced
			// URI it subscribed with.
			if rewritten, ok := rewriteUpdatedURI(json.RawMessage(req.Params), string(event.backend)); ok {
				req.Params = []byte(rewritten)
			}
		case "notifications/tools/list_changed",
			"notifications/resources/list_changed",
			"notifications/prompts/list_changed":
			// A backend's primitive list changed; drop any cached discover result
			// so the next list re-fetches.
			m.capCache.invalidateRoute(route)
		}
	}
	event.writeAndMaybeFlush(w)
}

// rewriteUpdatedURI re-prefixes the "uri" field in a notifications/resources/updated
// params payload with the backend name, returning (rewritten, true) on success.
func rewriteUpdatedURI(params json.RawMessage, backendName string) (json.RawMessage, bool) {
	if len(params) == 0 {
		return nil, false
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(params, &m) != nil {
		return nil, false
	}
	uriRaw, ok := m["uri"]
	if !ok {
		return nil, false
	}
	var uri string
	if json.Unmarshal(uriRaw, &uri) != nil || uri == "" {
		return nil, false
	}
	prefixed, _ := json.Marshal(downstreamResourceURI(uri, backendName))
	m["uri"] = prefixed
	out, err := json.Marshal(m)
	if err != nil {
		return nil, false
	}
	return out, true
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

	// Keep modern forwarding behavior aligned with the legacy proxy path:
	// backend/route metadata headers, optional log/header mappings, and original path.
	addMCPHeaders(httpReq, req, modernParamsForHeaderMetadata(req), route, backend.Name)
	m.applyLogHeaderMappings(httpReq, req)
	m.applyOriginalPathHeaders(httpReq)

	// P1.6: Set modern headers. No Mcp-Session-Id, no Last-Event-Id.
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream, application/json")
	httpReq.Header.Set(mcpProtocolVersionHeader, protocolVersion20260728)
	httpReq.Header.Set(mcpMethodHeader, req.Method)
	httpReq.Header.Set(internalapi.MCPBackendHeader, string(backend.Name))
	httpReq.Header.Set(internalapi.MCPRouteHeader, string(route))

	// Forward configured headers to backend.
	if routeConfig := m.routes[route]; routeConfig != nil {
		// Route-level headers (e.g. auth claimToHeaders).
		for _, header := range routeConfig.forwardHeaders {
			if value := m.requestHeaders.Get(header); value != "" {
				httpReq.Header.Set(header, value)
			}
		}
		// Per-backend headers (from MCPRouteBackendRef.forwardHeaders) with optional renaming.
		if b, ok := routeConfig.backends[backend.Name]; ok {
			for _, fh := range b.ForwardHeaders {
				if value := m.requestHeaders.Get(fh.Name); value != "" {
					httpReq.Header.Set(fh.ForwardName(), value)
				}
			}
		}
	}

	// Set Mcp-Name if applicable.
	if name := extractNameForMethod(req.Method, json.RawMessage(req.Params)); name != "" {
		httpReq.Header.Set(mcpNameHeader, name)
	} else if req.Method == "tools/call" {
		return nil, fmt.Errorf("invalid tools/call params: missing required name")
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
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(params, &p) == nil {
			return p.Name
		}
	case "prompts/get":
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(params, &p) == nil {
			return p.Name
		}
	case "resources/read":
		var p struct {
			URI string `json:"uri"`
		}
		if json.Unmarshal(params, &p) == nil {
			return p.URI
		}
	}
	return ""
}

// modernParamsForHeaderMetadata best-effort parses params for methods where
// addMCPHeaders can enrich upstream metadata (tool name/resource URI).
func modernParamsForHeaderMetadata(req *jsonrpc.Request) mcp.Params {
	if req == nil || req.Params == nil {
		return nil
	}
	switch req.Method {
	case "tools/call":
		var p mcp.CallToolParams
		if json.Unmarshal(req.Params, &p) == nil {
			return &p
		}
	case "resources/read":
		var p mcp.ReadResourceParams
		if json.Unmarshal(req.Params, &p) == nil {
			return &p
		}
	case "resources/subscribe":
		var p mcp.SubscribeParams
		if json.Unmarshal(req.Params, &p) == nil {
			return &p
		}
	case "resources/unsubscribe":
		var p mcp.UnsubscribeParams
		if json.Unmarshal(req.Params, &p) == nil {
			return &p
		}
	}
	return nil
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
