// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0

package mcpproxy

import (
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Protocol version constants.
const (
	protocolVersion20251125 = "2025-11-25"
	protocolVersion20260728 = "2026-07-28"

	// Modern MCP headers (2026-07-28 spec).
	// These mirror the unexported constants from the go-sdk.
	mcpMethodHeader          = "Mcp-Method"
	mcpNameHeader            = "Mcp-Name"
	mcpProtocolVersionHeader = "Mcp-Protocol-Version"
	mcpParamHeaderPrefix     = "Mcp-Param-"

	// _meta key constants for per-request metadata.
	metaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	metaClientInfo         = "io.modelcontextprotocol/clientInfo"
	metaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	metaLogLevel           = "io.modelcontextprotocol/logLevel"
	metaServerInfo         = "io.modelcontextprotocol/serverInfo"
	metaSubscriptionID     = "io.modelcontextprotocol/subscriptionId"
)

// MCP JSON-RPC error codes from the SDK (re-exported for local use).
const (
	errCodeMethodNotFound             = -32601
	errCodeHeaderMismatch             = mcp.CodeHeaderMismatch                    // -32020
	errCodeMissingRequiredCapability  = mcp.CodeMissingRequiredClientCapabilities // -32021
	errCodeUnsupportedProtocolVersion = mcp.CodeUnsupportedProtocolVersion        // -32022
	errCodeResourceNotFound           = -32602                                    // was -32002 in legacy
)

// supportedVersions lists all protocol versions the gateway supports, newest first.
var supportedVersions = []string{protocolVersion20260728, protocolVersion20251125, protocolVersion20250618}

// era represents whether a client/backend speaks legacy or modern MCP protocol.
type era int

const (
	eraLegacy era = iota
	eraModern
)

// detectClientEra determines whether an incoming request is from a legacy or modern client.
//
// Detection logic:
//   - An "initialize" method is always legacy (session-based handshake).
//   - Presence of Mcp-Session-Id header indicates legacy.
//   - Presence of Mcp-Method header indicates modern (stateless).
//   - Fallback: conservative default to legacy.
func detectClientEra(r *http.Request, msg jsonrpc.Message) era {
	if req, ok := msg.(*jsonrpc.Request); ok && req.Method == "initialize" {
		return eraLegacy
	}
	if r.Header.Get(sessionIDHeader) != "" {
		return eraLegacy
	}
	if r.Header.Get(mcpMethodHeader) != "" {
		return eraModern
	}
	return eraLegacy
}

// modernRequestMeta holds extracted _meta fields from a modern request's params.
type modernRequestMeta struct {
	ProtocolVersion    string          `json:"io.modelcontextprotocol/protocolVersion"`
	ClientInfo         json.RawMessage `json:"io.modelcontextprotocol/clientInfo"`
	ClientCapabilities json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
	LogLevel           string          `json:"io.modelcontextprotocol/logLevel,omitempty"`
}

// extractModernMeta extracts the _meta fields from a JSON-RPC request's params.
func extractModernMeta(params json.RawMessage) (*modernRequestMeta, error) {
	if params == nil {
		return nil, nil
	}
	var wrapper struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	}
	if err := json.Unmarshal(params, &wrapper); err != nil {
		return nil, err
	}
	if wrapper.Meta == nil {
		return nil, nil
	}
	meta := &modernRequestMeta{}
	if v, ok := wrapper.Meta[metaProtocolVersion]; ok {
		_ = json.Unmarshal(v, &meta.ProtocolVersion)
	}
	if v, ok := wrapper.Meta[metaClientInfo]; ok {
		meta.ClientInfo = v
	}
	if v, ok := wrapper.Meta[metaClientCapabilities]; ok {
		meta.ClientCapabilities = v
	}
	if v, ok := wrapper.Meta[metaLogLevel]; ok {
		_ = json.Unmarshal(v, &meta.LogLevel)
	}
	return meta, nil
}
