// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0

package mcpproxy

import (
	"context"
	stdjson "encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/internalapi"
)

func TestHandleModernToolsList_AppliesToolSelector(t *testing.T) {
	proxy := newTestMCPProxy()
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var result mcp.ListToolsResult
		switch r.Header.Get(internalapi.MCPBackendHeader) {
		case "backend1":
			result = mcp.ListToolsResult{
				Tools: []*mcp.Tool{
					{Name: "test-tool"},
					{Name: "blocked-tool"},
				},
			}
		case "backend2":
			result = mcp.ListToolsResult{
				Tools: []*mcp.Tool{
					{Name: "backend2-tool"},
				},
			}
		default:
			t.Fatalf("unexpected backend header: %s", r.Header.Get(internalapi.MCPBackendHeader))
		}
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      "1",
			"result":  result,
		}
		_ = stdjson.NewEncoder(w).Encode(resp)
	}))
	defer backendServer.Close()

	proxy.backendListenerAddr = backendServer.URL
	proxy.client = *backendServer.Client()

	id, err := jsonrpc.MakeID("1")
	require.NoError(t, err)
	req := &jsonrpc.Request{
		ID:     id,
		Method: "tools/list",
		Params: []byte(`{}`),
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rr := httptest.NewRecorder()
	proxy.handleModernToolsList(context.Background(), rr, httpReq, req, "test-route")

	require.Equal(t, http.StatusOK, rr.Code)
	tools := modernToolsFromResponse(t, rr.Body.Bytes())
	got := make([]string, 0, len(tools))
	for _, tool := range tools {
		got = append(got, tool.Name)
	}
	slices.Sort(got)
	require.Equal(t, []string{"backend1__test-tool", "backend2__backend2-tool"}, got)
}

func TestHandleModernToolsList_AppliesAuthorization(t *testing.T) {
	makeToken := func(scopes ...string) string {
		claims := jwt.MapClaims{}
		if len(scopes) > 0 {
			claims["scope"] = scopes
		}
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		signed, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		return signed
	}
	auth := &filterapi.MCPRouteAuthorization{
		DefaultAction: filterapi.AuthorizationActionDeny,
		Rules: []filterapi.MCPRouteAuthorizationRule{
			{
				Action: filterapi.AuthorizationActionAllow,
				Source: &filterapi.MCPAuthorizationSource{
					JWT: filterapi.JWTSource{Scopes: []string{"tools:read"}},
				},
				Target: &filterapi.MCPAuthorizationTarget{
					Tools: []filterapi.ToolCall{{Backend: "backend1", Tool: "allowed-tool"}},
				},
			},
		},
	}
	compiled, err := compileAuthorization(auth)
	require.NoError(t, err)

	proxy := newTestMCPProxy()
	proxy.routes["test-route"].authorization = compiled
	proxy.routes["test-route"].toolSelectors = nil // Ensure authorization is the only filter.

	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      "1",
			"result": mcp.ListToolsResult{
				Tools: []*mcp.Tool{
					{Name: "allowed-tool"},
					{Name: "restricted-tool"},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = stdjson.NewEncoder(w).Encode(resp)
	}))
	defer backendServer.Close()
	proxy.backendListenerAddr = backendServer.URL
	proxy.client = *backendServer.Client()

	id, err := jsonrpc.MakeID("1")
	require.NoError(t, err)
	rpcReq := &jsonrpc.Request{ID: id, Method: "tools/list", Params: []byte(`{}`)}

	t.Run("caller with scope sees allowed tool", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		httpReq.Header.Set("Authorization", "Bearer "+makeToken("tools:read"))
		rr := httptest.NewRecorder()
		proxy.handleModernToolsList(context.Background(), rr, httpReq, rpcReq, "test-route")
		tools := modernToolsFromResponse(t, rr.Body.Bytes())
		require.Len(t, tools, 1)
		require.Equal(t, "backend1__allowed-tool", tools[0].Name)
	})

	t.Run("caller without scope sees no tools", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		httpReq.Header.Set("Authorization", "Bearer "+makeToken("other:scope"))
		rr := httptest.NewRecorder()
		proxy.handleModernToolsList(context.Background(), rr, httpReq, rpcReq, "test-route")
		tools := modernToolsFromResponse(t, rr.Body.Bytes())
		require.Empty(t, tools)
	})
}

func modernToolsFromResponse(t *testing.T, body []byte) []*mcp.Tool {
	t.Helper()
	var rpcResp struct {
		Result stdjson.RawMessage `json:"result"`
	}
	require.NoError(t, stdjson.Unmarshal(body, &rpcResp))
	var result mcp.ListToolsResult
	require.NoError(t, stdjson.Unmarshal(rpcResp.Result, &result))
	return result.Tools
}

func TestHandleModernToolsCall_EnforcesToolSelectorAndAuthorization(t *testing.T) {
	makeToken := func(scopes ...string) string {
		claims := jwt.MapClaims{}
		if len(scopes) > 0 {
			claims["scope"] = scopes
		}
		token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		signed, _ := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
		return signed
	}

	auth := &filterapi.MCPRouteAuthorization{
		DefaultAction:       filterapi.AuthorizationActionDeny,
		ResourceMetadataURL: "https://api.example.com/.well-known/oauth-protected-resource/mcp",
		Rules: []filterapi.MCPRouteAuthorizationRule{
			{
				Action: filterapi.AuthorizationActionAllow,
				Source: &filterapi.MCPAuthorizationSource{
					JWT: filterapi.JWTSource{Scopes: []string{"tools:run"}},
				},
				Target: &filterapi.MCPAuthorizationTarget{
					Tools: []filterapi.ToolCall{{Backend: "backend1", Tool: "allowed-tool"}},
				},
			},
		},
	}
	compiled, err := compileAuthorization(auth)
	require.NoError(t, err)

	var upstreamCalls int32
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"jsonrpc": "2.0",
			"id":      "1",
			"result": map[string]any{
				"content": []map[string]any{{"type": "text", "text": "ok"}},
			},
		}
		_ = stdjson.NewEncoder(w).Encode(resp)
	}))
	defer backendServer.Close()

	proxy := newTestMCPProxy()
	proxy.backendListenerAddr = backendServer.URL
	proxy.client = *backendServer.Client()
	proxy.routes["test-route"].authorization = compiled

	// Allow only allowed-tool via selector too, so both selector and auth are exercised.
	proxy.routes["test-route"].toolSelectors = map[filterapi.MCPBackendName]*toolSelector{
		"backend1": {
			include: map[string]struct{}{"allowed-tool": {}},
			exclude: map[string]struct{}{},
		},
	}

	makeReq := func(tool string) *jsonrpc.Request {
		id, _ := jsonrpc.MakeID("1")
		p := mcp.CallToolParams{Name: tool}
		raw, _ := stdjson.Marshal(p)
		return &jsonrpc.Request{ID: id, Method: "tools/call", Params: raw}
	}

	t.Run("denied by selector blocks upstream call", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		httpReq.Header.Set("Authorization", "Bearer "+makeToken("tools:run"))
		rr := httptest.NewRecorder()
		proxy.handleModernToolsCall(context.Background(), rr, httpReq, makeReq("backend1__blocked-tool"), "test-route")
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "invalid tool name")
		require.Equal(t, int32(0), atomic.LoadInt32(&upstreamCalls))
	})

	t.Run("denied by auth blocks upstream and sets challenge", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		httpReq.Header.Set("Authorization", "Bearer "+makeToken("other:scope"))
		rr := httptest.NewRecorder()
		proxy.handleModernToolsCall(context.Background(), rr, httpReq, makeReq("backend1__allowed-tool"), "test-route")
		require.Equal(t, http.StatusForbidden, rr.Code)
		require.Contains(t, rr.Body.String(), "access denied")
		require.Contains(t, rr.Header().Get("WWW-Authenticate"), `scope="tools:run"`)
		require.Equal(t, int32(0), atomic.LoadInt32(&upstreamCalls))
	})

	t.Run("allowed call reaches upstream", func(t *testing.T) {
		httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		httpReq.Header.Set("Authorization", "Bearer "+makeToken("tools:run"))
		rr := httptest.NewRecorder()
		proxy.handleModernToolsCall(context.Background(), rr, httpReq, makeReq("backend1__allowed-tool"), "test-route")
		require.Equal(t, http.StatusOK, rr.Code)
		require.Equal(t, int32(1), atomic.LoadInt32(&upstreamCalls))
	})
}
