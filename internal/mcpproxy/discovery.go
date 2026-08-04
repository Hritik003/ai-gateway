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
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// capabilityCache is a per-instance in-memory cache of backend server/discover results.
// Keyed by route+backend, it avoids repeated server/discover calls on every request.
type capabilityCache struct {
	mu      sync.RWMutex
	entries map[discoverCacheKey]*discoverCacheEntry
	l       *slog.Logger
}

type discoverCacheKey struct {
	route   filterapi.MCPRouteName
	backend filterapi.MCPBackendName
}

type discoverCacheEntry struct {
	result    *mcp.DiscoverResult
	expiresAt time.Time
}

func newCapabilityCache(l *slog.Logger) *capabilityCache {
	return &capabilityCache{
		entries: make(map[discoverCacheKey]*discoverCacheEntry),
		l:       l,
	}
}

// get retrieves the cached DiscoverResult for the given route+backend.
// Returns nil if not cached or expired.
func (c *capabilityCache) get(route filterapi.MCPRouteName, backend filterapi.MCPBackendName) *mcp.DiscoverResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := discoverCacheKey{route: route, backend: backend}
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if !entry.expiresAt.IsZero() && time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.result
}

// set stores a DiscoverResult in the cache.
func (c *capabilityCache) set(route filterapi.MCPRouteName, backend filterapi.MCPBackendName, result *mcp.DiscoverResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := discoverCacheKey{route: route, backend: backend}
	entry := &discoverCacheEntry{result: result}
	if ttl := result.GetTTLMs(); ttl > 0 {
		entry.expiresAt = time.Now().Add(time.Duration(ttl) * time.Millisecond)
	} else {
		entry.expiresAt = time.Now().Add(5 * time.Minute)
	}
	c.entries[key] = entry
}

// invalidate removes a cached entry for the given route+backend.
func (c *capabilityCache) invalidate(route filterapi.MCPRouteName, backend filterapi.MCPBackendName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, discoverCacheKey{route: route, backend: backend})
}

// invalidateRoute removes all cached entries for a route (e.g., on list_changed notification).
func (c *capabilityCache) invalidateRoute(route filterapi.MCPRouteName) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key := range c.entries {
		if key.route == route {
			delete(c.entries, key)
		}
	}
}

// discoverBackend sends a server/discover request to a single backend and caches the result.
// If the result is already cached and fresh, returns it immediately.
func (c *capabilityCache) discoverBackend(ctx context.Context, client *http.Client, backendAddr string, route filterapi.MCPRouteName, backend filterapi.MCPBackend) (*mcp.DiscoverResult, error) {
	if cached := c.get(route, backend.Name); cached != nil {
		return cached, nil
	}

	id, _ := jsonrpc.MakeID(fmt.Sprintf("gw-discover-%s-%d", backend.Name, time.Now().UnixNano()))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "server/discover",
	}
	body, err := jsonrpc.EncodeMessage(req)
	if err != nil {
		return nil, fmt.Errorf("encode server/discover: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, backendAddr, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	httpReq.Header.Set(mcpProtocolVersionHeader, protocolVersion20260728)
	httpReq.Header.Set(mcpMethodHeader, "server/discover")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("server/discover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.l.Warn("server/discover non-200; backend may be legacy",
			slog.String("backend", string(backend.Name)),
			slog.Int("status", resp.StatusCode))
		return nil, fmt.Errorf("server/discover returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// Parse the JSON-RPC response envelope. Use map to avoid jsonrpc.ID issues with sonic.
	var rpcResp map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("parse server/discover response: %w", err)
	}
	if errField, ok := rpcResp["error"]; ok && string(errField) != "null" {
		return nil, fmt.Errorf("server/discover error: %s", string(errField))
	}
	resultRaw, ok := rpcResp["result"]
	if !ok || string(resultRaw) == "null" {
		return nil, fmt.Errorf("server/discover returned nil result")
	}

	var result mcp.DiscoverResult
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return nil, fmt.Errorf("unmarshal DiscoverResult: %w", err)
	}

	c.set(route, backend.Name, &result)
	return &result, nil
}

// mergeDiscoverResults merges multiple DiscoverResult from route backends into
// a single DiscoverResult representing the gateway's aggregated capabilities.
func mergeDiscoverResults(results []*mcp.DiscoverResult) *mcp.DiscoverResult {
	merged := &mcp.DiscoverResult{
		SupportedVersions: supportedVersions,
		Capabilities: &mcp.ServerCapabilities{
			// The gateway implements these modern list/call surfaces even when backends
			// do not advertise capabilities in server/discover.
			Tools:       &mcp.ToolCapabilities{},
			Resources:   &mcp.ResourceCapabilities{},
			Prompts:     &mcp.PromptCapabilities{},
			Completions: &mcp.CompletionCapabilities{},
		},
	}

	for _, r := range results {
		if r.Capabilities == nil {
			continue
		}
		// Union of capabilities: if any backend has it, the gateway has it.
		if r.Capabilities.Tools != nil {
			merged.Capabilities.Tools.ListChanged = merged.Capabilities.Tools.ListChanged || r.Capabilities.Tools.ListChanged
		}
		if r.Capabilities.Resources != nil {
			merged.Capabilities.Resources.ListChanged = merged.Capabilities.Resources.ListChanged || r.Capabilities.Resources.ListChanged
			merged.Capabilities.Resources.Subscribe = merged.Capabilities.Resources.Subscribe || r.Capabilities.Resources.Subscribe
		}
		if r.Capabilities.Prompts != nil {
			merged.Capabilities.Prompts.ListChanged = merged.Capabilities.Prompts.ListChanged || r.Capabilities.Prompts.ListChanged
		}
		if r.Capabilities.Logging != nil {
			merged.Capabilities.Logging = &mcp.LoggingCapabilities{}
		}
		if r.Capabilities.Completions != nil {
			merged.Capabilities.Completions = &mcp.CompletionCapabilities{}
		}
	}
	return merged
}
