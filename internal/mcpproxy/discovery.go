// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0

package mcpproxy

import (
	"context"
	"fmt"
	"log/slog"
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
//
// It reuses sendModernRequest so the fan-out carries the exact same headers as
// every other modern request (original-path, forwarded/auth headers, log header
// mappings). Building the request independently previously dropped those headers,
// which caused the gateway backend listener to reject server/discover with a 400
// while resources/list, prompts/list, and tools/call kept working — collapsing the
// aggregated capabilities to whatever survived an empty union.
func (m *mcpRequestContext) discoverBackend(ctx context.Context, route filterapi.MCPRouteName, backend filterapi.MCPBackend) (*mcp.DiscoverResult, error) {
	if cached := m.capCache.get(route, backend.Name); cached != nil {
		return cached, nil
	}

	id, _ := jsonrpc.MakeID(fmt.Sprintf("gw-discover-%s-%d", backend.Name, time.Now().UnixNano()))
	req := &jsonrpc.Request{
		ID:     id,
		Method: "server/discover",
		Params: discoverParams(),
	}

	resultRaw, err := m.sendModernRequest(ctx, req, route, backend)
	if err != nil {
		return nil, fmt.Errorf("server/discover request failed: %w", err)
	}

	var result mcp.DiscoverResult
	if err := json.Unmarshal(resultRaw, &result); err != nil {
		return nil, fmt.Errorf("unmarshal DiscoverResult: %w", err)
	}

	m.capCache.set(route, backend.Name, &result)
	return &result, nil
}


func discoverParams() []byte {
	return []byte(`{"_meta":{` +
		`"` + metaProtocolVersion + `":"` + protocolVersion20260728 + `",` +
		`"` + metaClientInfo + `":{"name":"envoy-ai-gateway","version":"1.0.0"},` +
		`"` + metaClientCapabilities + `":{}` +
		`}}`)
}

// mergeDiscoverResults merges multiple DiscoverResult from route backends into
// a single DiscoverResult representing the gateway's aggregated capabilities.
//
// Capabilities are aggregated using the same union/OR semantics as the stateful
// initialize path (see unionServerCapabilities): a capability is advertised only
// when at least one backend advertises it, rather than being hardcoded. This
// returns whatever the backends actually report.
func mergeDiscoverResults(results []*mcp.DiscoverResult) *mcp.DiscoverResult {
	caps := make([]*mcp.ServerCapabilities, 0, len(results))
	for _, r := range results {
		caps = append(caps, r.Capabilities)
	}
	return &mcp.DiscoverResult{
		SupportedVersions: supportedVersions,
		Capabilities:      unionServerCapabilities(caps),
	}
}
