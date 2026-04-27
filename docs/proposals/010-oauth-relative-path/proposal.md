# OAuth Metadata Discovery with Path-Based Issuers

## Table of Contents

<!-- toc -->

- [Summary](#summary)
- [Background](#background)
- [Goals](#goals)
- [Design](#design)
  - [API Changes](#api-changes)
  - [Issuer Resolution Strategies](#issuer-resolution-strategies)
  - [Flow 1: URI Issuer (Existing)](#flow-1-uri-issuer-existing)
  - [Flow 2: Path Issuer (New)](#flow-2-path-issuer-new)
- [Implementation](#implementation)
  - [Controller Changes](#controller-changes)
  - [MCP Proxy: Dynamic Metadata Serving](#mcp-proxy-dynamic-metadata-serving)
  - [HTTPRoute Routing for Path-Based Issuers](#httproute-routing-for-path-based-issuers)
  - [Extension Server: Cluster Rewriting](#extension-server-cluster-rewriting)
- [Files Involved](#files-involved)
- [Future Work & Notes](#future-work--notes)

<!-- /toc -->

## Summary

This proposal adds support for **path-based OAuth issuers** in `MCPRoute`, where the authorization server is co-located behind the same Gateway as the MCP endpoint. When the issuer is specified as a relative path (e.g., `/realms/myrealm`) instead of a full URI, the gateway's external hostname is unknown at controller reconcile time. The MCP Proxy dynamically constructs full OAuth metadata URLs at request time by reading the incoming request's `Host` header.

## Background

The existing OAuth metadata discovery in MCPRoute relies on `issuer.uri` — a full external URL pointing to the authorization server (e.g., `https://auth.example.com/realms/myrealm`). At controller reconcile time, the controller fetches the auth server's metadata, bakes the complete JSON into `DirectResponse` HTTPRouteFilters, and Envoy serves it statically. This works when the authorization server is externally reachable at a well-known URL.

However, many deployments co-locate the authorization server behind the same Gateway:

- The auth server runs as a Kubernetes Service (e.g., Keycloak, IAM proxy) in the same cluster.
- External clients reach it via the Gateway's public DNS/IP, which the controller does not know at reconcile time.
- The controller *can* reach the auth server internally via its cluster-internal address (e.g., `keycloak.ns.svc.cluster.local`), but this address must not appear in metadata served to external clients.

This creates a fundamental challenge: the OAuth metadata JSON must contain **absolute URLs** with the gateway's public hostname, but that hostname is only known at request time from the `Host` header.

## Goals

- Support `issuer.path` as an alternative to `issuer.uri` for co-located authorization servers.
- Dynamically resolve the gateway's external hostname at request time to construct full OAuth metadata URLs.
- Reuse the existing MCP Proxy architecture ([proposal 006]) without introducing new components.
- Retain backward compatibility — `issuer.uri` continues to work via static `DirectResponse` filters.
- Auto-discover JWKS endpoints using the auth server's cluster-internal address for JWT validation.

## Design

### API Changes

A new `MCPRouteOAuthIssuer` struct replaces the previous single `URI` field with a mutually exclusive choice:

```yaml
securityPolicy:
  oauth:
    issuer:
      # Option A: Full external URL (existing behavior)
      uri: "https://auth.example.com/realms/myrealm"

      # Option B: Relative path — auth server behind same Gateway (new)
      path: "/realms/myrealm"
      backendRef:
        kind: Service
        name: keycloak
        namespace: auth
        port: 8080
```

Exactly one of `uri` or `path` must be set. When `path` is set, `backendRef` provides the cluster-internal address for JWKS discovery.

### Issuer Resolution Strategies

The controller applies different resolution strategies depending on which issuer field is set:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                   MCPRoute CR with securityPolicy.oauth                │
│                                                                       │
│   issuer.uri = "https://auth.example.com/realms/myrealm"             │
│                     OR                                                 │
│   issuer.path = "/realms/myrealm"                                     │
│   issuer.backendRef → keycloak.auth.svc.cluster.local:8080            │
└────────────────────┬─────────────────────────────┬────────────────────┘
                     │                             │
            ┌────────▼────────┐           ┌────────▼────────┐
            │   URI Issuer    │           │  Path Issuer    │
            │   (existing)    │           │   (new)         │
            └────────┬────────┘           └────────┬────────┘
                     │                             │
    ┌────────────────▼──────────────┐  ┌───────────▼──────────────────┐
    │ Controller fetches metadata   │  │ Controller builds internal   │
    │ from external URI.            │  │ URL from backendRef.         │
    │                               │  │                              │
    │ Bakes full JSON into          │  │ Fetches JWKS URI internally  │
    │ DirectResponse HRFs.          │  │ for SecurityPolicy JWT       │
    │                               │  │ validation.                  │
    │ Envoy serves statically.      │  │                              │
    │ MCP Proxy not involved.       │  │ Passes IssuerPath + partial  │
    │                               │  │ metadata to MCP Proxy.       │
    │                               │  │                              │
    │                               │  │ MCP Proxy serves dynamically │
    │                               │  │ at request time using Host.  │
    └───────────────────────────────┘  └──────────────────────────────┘
```

### Flow 1: URI Issuer (Existing)

When `issuer.uri` is set, everything is resolved **statically at controller reconcile time**:

1. The controller fetches `/.well-known/oauth-authorization-server` from the full URI.
2. The metadata JSON is baked into `DirectResponse` HTTPRouteFilters.
3. Envoy serves the response directly — the MCP Proxy is never involved for metadata endpoints.

```
Client ──GET /.well-known/oauth-protected-resource/mcp──▶ Envoy
                                                           │
                                                    HTTPRoute matches
                                                    path exactly
                                                           │
Client ◀───────── 200 OK (DirectResponse) ────────────────┘
                  Static JSON, no proxy involved
```

### Flow 2: Path Issuer (New)

When `issuer.path` is set, the gateway's external URL is **unknown at controller time**. Metadata is served **dynamically at request time** by the MCP Proxy:

```
                    Reconcile Time
                    ─────────────
Controller ──resolveIssuerURLs()──▶ issuerURL = "" (unknown externally)
           │                        internalIssuer = "http://keycloak.ns.svc:8080/realms/myrealm"
           │
           ├──GET /.well-known/oauth-authorization-server/realms/myrealm──▶ Auth Server (internal)
           │◀──── JWKS URI for SecurityPolicy JWT validation ──────────────┘
           │
           ├──Build filterapi.MCPOAuthMetadata:
           │    IssuerPath = "/realms/myrealm"
           │    ProtectedResourceMetadataJSON = static JSON
           │    AuthServerMetadataJSON = partial (paths only, no host)
           │    ScopesSupported = [...]
           │
           ├──Create HTTPRoute rules: /.well-known/* → MCP Proxy Backend
           │    + header: x-ai-eg-mcp-oauth-metadata-type
           │
           └──Push filterapi config to MCP Proxy

                    Request Time
                    ────────────
Client ──GET /.well-known/oauth-protected-resource/mcp──▶ Envoy
         Host: gateway.example.com                          │
                                                     HTTPRoute matches,
                                                     adds metadata-type header
                                                            │
                                                     MCP Proxy (127.0.0.1:9856)
                                                            │
                                                     serveOAuthMetadata()
                                                     ├── protected-resource → return static JSON
                                                     └── authorization-server → build dynamic JSON:
                                                           baseURL = scheme://Host
                                                           issuerURL = baseURL + IssuerPath
                                                           All URLs = absolute
                                                            │
Client ◀───────── 200 OK (dynamic JSON with full URLs) ────┘
```

The key insight: the MCP Proxy reads `Host: gateway.example.com` and `X-Forwarded-Proto: https` from the incoming request to construct `https://gateway.example.com/realms/myrealm` as the issuer URL. All endpoint URLs in the metadata derive from this.

## Implementation

### Controller Changes

The `resolveIssuerURLs()` function in the MCPRoute security policy controller handles both issuer modes:

- **URI mode**: Uses the full URL directly. Fetches metadata externally. Bakes complete JSON into `DirectResponse` filters.
- **Path mode**: Constructs an internal URL from `backendRef` (e.g., `http://keycloak.auth.svc.cluster.local:8080/realms/myrealm`). Fetches the JWKS URI from this internal address for JWT validation in `SecurityPolicy`. Populates `filterapi.MCPOAuthMetadata` with `IssuerPath`, partial metadata JSON, and scopes. Creates HTTPRoute rules that route `/.well-known/*` requests to the MCP Proxy backend instead of using `DirectResponse`.

### MCP Proxy: Dynamic Metadata Serving

The MCP Proxy gains a new `serveOAuthMetadata()` handler that intercepts requests bearing the `x-ai-eg-mcp-oauth-metadata-type` header:

1. The metadata type is determined from the request URL path:
   - Paths containing `oauth-protected-resource` → serve protected resource metadata (pre-built, static JSON).
   - Paths containing `oauth-authorization-server` or `openid-configuration` → serve authorization server metadata (dynamically constructed).

2. For authorization server metadata, `buildDynamicAuthServerMetadata()`:
   - Derives `baseURL` from `X-Forwarded-Proto` + `Host` headers.
   - If the controller fetched auth server metadata at reconcile time (`AuthServerMetadataJSON` is non-empty), replaces relative paths with full URLs.
   - Otherwise, falls back to constructing Keycloak-style OIDC endpoint URLs from the issuer path.

### HTTPRoute Routing for Path-Based Issuers

For path-based issuers, the controller creates HTTPRoute rules that:

1. Match the well-known metadata paths (`/.well-known/oauth-protected-resource/<path>`, `/.well-known/oauth-authorization-server/<path>`, `/.well-known/openid-configuration/<path>`).
2. Add a request header (`x-ai-eg-mcp-oauth-metadata-type`) to signal the MCP Proxy which metadata type to serve.
3. Route to the MCP Proxy backend (the same backend used for MCP protocol requests, reachable via the dummy IP `192.0.2.42:9856` that gets rewritten to `127.0.0.1:9856` by the extension server).

This differs from URI-based issuers where the same well-known paths use `DirectResponse` filters with baked-in JSON.

### Extension Server: Cluster Rewriting

The extension server's `modifyMCPGatewayGeneratedCluster()` intercepts xDS pushes and rewrites clusters whose names contain `ai-eg-mcp-main-` and whose endpoints point to the dummy IP `192.0.2.42`. These clusters are rewritten to `STATIC` type with endpoint `127.0.0.1:9856`, ensuring all MCP Proxy traffic (including OAuth metadata requests for path-based issuers) reaches the local sidecar process.

## Files Involved

| File | Role |
|------|------|
| `api/v1alpha1/mcp_route.go` | Defines `MCPRouteOAuthIssuer` with mutually exclusive `uri` / `path` fields |
| `internal/controller/mcp_route.go` | Builds HTTPRoute rules — `DirectResponse` (URI) vs proxy routing (Path) |
| `internal/controller/mcp_route_security_policy.go` | Builds metadata JSON, resolves issuer URLs, creates HTTPRouteFilters and SecurityPolicies |
| `internal/controller/gateway.go` | Populates `filterapi.MCPOAuthMetadata` in the proxy config for path-based issuers |
| `internal/filterapi/mcpconfig.go` | Defines `MCPOAuthMetadata` struct passed to the MCP Proxy |
| `internal/mcpproxy/oauth_metadata.go` | Handles dynamic metadata serving — reads Host, constructs full URLs |
| `internal/mcpproxy/mcpproxy.go` | Main proxy handler — intercepts metadata requests via header check |
| `internal/mcpproxy/config.go` | Loads `OAuthMetadata` from filterapi config into proxy route state |
| `internal/internalapi/internalapi.go` | Defines `MCPOAuthMetadataTypeHeader` constant |
| `internal/extensionserver/mcproute.go` | Rewrites MCP proxy clusters from dummy IP to `127.0.0.1:9856` |

## Future Work & Notes

- **TLS verification for internal JWKS fetch**: Currently, when fetching the JWKS URI from the cluster-internal auth server address, TLS verification may be skipped. A future improvement could leverage the auth server's CA certificate for secure internal communication.
- **Caching of dynamic metadata**: The MCP Proxy reconstructs authorization server metadata on every request. For high-traffic deployments, caching the constructed JSON keyed by `Host` header could reduce overhead.
- **Multiple Gateways**: If a single MCPRoute is attached to multiple Gateways with different public hostnames, the dynamic approach handles this naturally — each request's `Host` header produces the correct URLs for that Gateway.
- **Auth server metadata refresh**: When using `issuer.path`, the controller fetches metadata once at reconcile time. If the auth server's endpoints change, the MCPRoute must be re-reconciled. A watch or periodic refresh could be added later.

[proposal 006]: ../006-mcp-gateway/proposal.md
