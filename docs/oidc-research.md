# MCP Authorization & OIDC Research

**Date:** March 2026  
**Author:** Prachi Pandey  
**Scope:** Research for "Authorization POC with OIDC support, Authorization Server Metadata" task (P1)

---

## 1. Current State — What Exists Today

### 1a. Java POC (`okta-mcp-poc`) — this repo

| Property | Value |
|---|---|
| Language | Java 21 |
| Framework | Spring Boot 3.4.3 + Spring AI 1.0.0-M6 |
| Transport | **stdio** (`StdioServerTransport`) |
| Okta SDK | okta-sdk-api v25.0.3 |
| Auth to Okta | Private Key JWT (client_credentials) OR SSWS token fallback |
| MCP Client Auth | **None** — stdio = implicit trust |

**Tool classes (3):**
- `OktaUserManagementTool` — list, get, create, update, deactivate, delete users
- `OktaGroupsTool` — list, get, add/remove user to group, list group users
- `OktaApplicationsTool` — list apps, list app groups/users, list user apps/groups

**Key config files:**
- `OktaClientProvider.java` — lazy-init Okta SDK client (double-checked locking)
- `McpTransportConfig.java` — custom `ObjectMapper` with `FAIL_ON_UNKNOWN_PROPERTIES=false` (fixes VS Code `elicitation` field crash)
- `ToolConfig.java` — registers tools via `MethodToolCallbackProvider`
- `.vscode/mcp.json` — VS Code MCP server config (stdio, env var inputs)

---

### 1b. Python server (`okta-mcp-server`) — Okta's official server

| Property | Value |
|---|---|
| Language | Python 3.13 |
| Framework | `mcp.server.fastmcp.FastMCP` |
| Transport | **stdio** only |
| Auth | Device Authorization Grant (browser) OR Browserless (Private Key JWT client_credentials) |
| Token storage | System keyring |

**Tool categories (much broader scope than Java POC):**

| Category | Tools |
|---|---|
| Users | `list_users`, `get_user`, `get_user_profile_attributes`, `create_user`, `update_user`, `deactivate_user`, `delete_deactivated_user` |
| Groups | `list_groups`, `get_group`, `add_user_to_group`, `remove_user_from_group`, `list_group_users` |
| Applications | `list_applications`, `list_app_groups`, `list_app_users`, `list_user_apps`, `list_user_groups` |
| Policies | `list_policies`, policy rules CRUD (OKTA_SIGN_ON, PASSWORD, MFA_ENROLL, ACCESS_POLICY, etc.) |
| System Logs | `get_logs` (with since/until/filter/q, auto-pagination up to 50 pages) |
| Device Assurance | device assurance CRUD |
| Customization | brands, custom_domains, custom_pages, custom_templates, email_domains, themes |

**Unique Python features missing from Java POC:**
1. **Elicitation** — MCP `elicitation` protocol for structured confirmation forms before destructive ops (deactivate/delete). Gracefully falls back if client doesn't support it.
2. **Auto-pagination** — `fetch_all=True` parameter auto-paginates up to 50 pages (0.1s delay between requests). Works with both Okta SDK v2 and v3 response formats via `Link` header parsing.
3. **Standardized pagination response** — `{ items, total_fetched, has_more, next_cursor, fetch_all_used, pagination_info }`

---

## 2. MCP Authorization Spec (2025-03-26) — Key Rules

Source: https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization

| Rule | Requirement |
|---|---|
| **Transport scope** | HTTP transports ONLY. **stdio SHOULD NOT implement this spec** — use env vars instead |
| **Token on every request** | `Authorization: Bearer <token>` on **every** HTTP request (even same session) |
| **Token in URL** | **NEVER** — tokens must not appear in query strings |
| **Missing/bad token** | Server MUST return `HTTP 401` with `WWW-Authenticate` header |
| **Insufficient scope** | Server MUST return `HTTP 403` |
| **PKCE** | Required for all clients (S256 method) |
| **Discovery** | Server MUST expose `GET /.well-known/oauth-authorization-server` (RFC 8414) |
| **Discovery URL** | Strip path from MCP server URL. `https://api.acme.com/v1/mcp` → `https://api.acme.com/.well-known/oauth-authorization-server` |
| **Dynamic Client Registration** | SHOULD support RFC 7591 `/register` endpoint |

### Authorization Server Metadata Document (RFC 8414)

What `GET /.well-known/oauth-authorization-server` must return:

```json
{
  "issuer": "https://okta-mcp-server.oktapreview.com/oauth2/default",
  "authorization_endpoint": "https://okta-mcp-server.oktapreview.com/oauth2/default/v1/authorize",
  "token_endpoint": "https://okta-mcp-server.oktapreview.com/oauth2/default/v1/token",
  "jwks_uri": "https://okta-mcp-server.oktapreview.com/oauth2/default/v1/keys",
  "registration_endpoint": "https://okta-mcp-server.oktapreview.com/oauth2/v1/clients",
  "userinfo_endpoint": "https://okta-mcp-server.oktapreview.com/oauth2/default/v1/userinfo",
  "introspection_endpoint": "https://okta-mcp-server.oktapreview.com/oauth2/default/v1/introspect",
  "revocation_endpoint": "https://okta-mcp-server.oktapreview.com/oauth2/default/v1/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "client_credentials", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "scopes_supported": ["openid", "email", "profile", "offline_access"]
}
```

Okta already exposes this at:
```
https://{your-okta-domain}/oauth2/{authorizationServerId}/.well-known/oauth-authorization-server
```
Our MCP server can proxy or reference this directly.

---

## 3. Two Authorization Patterns in the Spec

### Pattern A — Resource Server Only (Recommended for POC)

The MCP server **never issues tokens**. It only validates them. The MCP client gets a token directly from Okta and presents it on every request.

```
MCP Client  ──GET /.well-known/oauth-authorization-server──►  MCP Server
            ◄── { authorization_endpoint: Okta, token_endpoint: Okta, ... } ──

MCP Client  ──── PKCE Auth Code Flow ────►  Okta
            ◄──── access_token (JWT) ──────

MCP Client  ──── POST /mcp ─────────────►  MCP Server
                 Authorization: Bearer <okta_jwt>
                 (Spring Security validates signature via Okta JWKS)
            ◄──── tool result ────────────
```

**Pros:** Simple, stateless, no token storage, Spring Security does all validation.  
**Cons:** MCP client must support PKCE auth code flow (VS Code does as of 2025).

### Pattern B — Third-Party AS Flow (MCP server issues its own tokens)

The MCP server acts as a mini OAuth server AND delegates login to Okta.

```
MCP Client  ──► MCP server /authorize
MCP server  ──► Okta /authorize (redirect)
User logs in at Okta
Okta ──────────► MCP server /callback (code)
MCP server exchanges code with Okta → gets Okta token
MCP server issues its OWN MCP token (stored in DB, bound to Okta session)
MCP Client receives MCP token
MCP Client uses MCP token on every request
MCP server validates MCP token + periodically checks Okta token validity
```

**Pros:** Works with clients that can't do PKCE directly.  
**Cons:** Requires token storage, session management, token rotation, token lifecycle — massive scope. **Not recommended for POC.**

---

## 4. How Other MCP Servers Handle It

### 4a. Anthropic TypeScript SDK (Reference Implementation)

The official SDK provides a complete pluggable auth framework:

**`requireBearerAuth` middleware** — extracts Bearer token, calls `verifier.verifyAccessToken()`, checks scopes + expiry, sets `req.auth`:
```typescript
export interface OAuthTokenVerifier {
  verifyAccessToken(token: string): Promise<AuthInfo>;  // single pluggable hook
}
```

**`mcpAuthMetadataRouter()`** — serves both RFC 8414 and RFC 9728 endpoints:
- `GET /.well-known/oauth-authorization-server` — AS metadata
- `GET /.well-known/oauth-protected-resource` — tells clients which AS to use

**PKCE** is validated in the token endpoint: S256 challenge verified with `crypto.subtle.digest`.

### 4b. Cloudflare Workers OAuth Provider

Most complete open-source implementation. Handles both internal tokens and external tokens (e.g. Okta JWTs):

**Dual token path:**
```typescript
// Path 1: internal token (issued by this provider, stored in KV)
if (token.split(':').length === 3) {  // format: "userId:grantId:secret"
  tokenData = await kv.get(`token:${userId}:${grantId}:${sha256(token)}`);
}

// Path 2: external token (e.g. Okta JWT) — pluggable hook
if (!tokenData && options.resolveExternalToken) {
  const result = await options.resolveExternalToken({ token, request, env });
  ctx.props = result.props;  // pass user data to API handler
}
```

**External token hook — how you'd integrate Okta:**
```typescript
resolveExternalToken: async ({ token }) => {
  const res = await fetch('https://your-okta-domain/oauth2/v1/introspect', {
    method: 'POST',
    body: `token=${token}&token_type_hint=access_token`,
  });
  const data = await res.json();
  if (!data.active) return null;
  return { props: { userId: data.sub, scopes: data.scope }, audience: data.aud };
}
```

**Third-Party AS flow** (GitHub OAuth as upstream, same pattern for Okta):
```typescript
export default new OAuthProvider({
  apiRoute: "/mcp",
  apiHandler: MyMCP.serve("/mcp"),
  defaultHandler: GitHubHandler,   // handles /authorize redirect to GitHub + /callback
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
});
// GitHub/Okta issues token → provider calls completeAuthorization() → issues its OWN MCP token
```

### 4c. GitHub MCP Server (Go)

Uses PATs or OAuth tokens directly — no MCP-level auth server. Token passed via `Authorization: Bearer` header in every HTTP request or via env var for stdio.

```json
// HTTP mode (OAuth handled by GitHub's infrastructure)
{ "servers": { "github": { "type": "http", "url": "https://api.githubcopilot.com/mcp/" } } }

// stdio mode (token from env)
{ "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "<YOUR_TOKEN>" } }
```

### 4d. Spring AI MCP (`mcp-server-security` community module)

A community module (`org.springaicommunity:mcp-server-security`) wraps Spring Security into a clean MCP-aware configurer:

```java
@Bean
SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .with(McpServerOAuth2Configurer.mcpServerOAuth2(), cfg -> {
            cfg.authorizationServer(issuerUrl);   // Okta issuer URI
            cfg.validateAudienceClaim(true);      // RFC 8707 aud claim
        })
        .build();
}
```

**Known limits:** WebMVC only, JWT only (no opaque tokens), STREAMABLE or STATELESS transport only (not SSE).

---

## 5. Spring AI Transport Architecture (Critical for Implementation)

### SSE vs Streamable HTTP

| | SSE (legacy, deprecated) | Streamable HTTP (use this) |
|---|---|---|
| Endpoint | `GET /sse` + `POST /mcp/message?sessionId=` | Single `POST/GET/DELETE /mcp` |
| Session ID | Query param | `mcp-session-id` header |
| Protocol versions | `2024-11-05` only | All versions incl. `2025-03-26` |
| First request | `GET /sse` opens stream | `POST /mcp` with `initialize` body |

### `McpTransportContext` — How the Auth Header Gets Into Tools

This is the critical bridge from HTTP → tool method:

```
HTTP POST /mcp
Authorization: Bearer <jwt>
    │
    ▼ (in transport provider)
contextExtractor.extract(request) → McpTransportContext { "authorization" → "Bearer <jwt>" }
    │
    ▼ (stored via Reactor contextWrite)
ctx.put(McpTransportContext.KEY, transportContext)
    │
    ▼ (Spring AI injects into tool parameter)
McpSyncRequestContext requestContext
requestContext.transportContext().get("authorization")  → "Bearer <jwt>"
```

**Wiring the extractor** (overrides auto-configured bean via `@ConditionalOnMissingBean`):
```java
@Bean
WebMvcStreamableServerTransportProvider webMvcStreamableServerTransportProvider(
        JsonMapper jsonMapper, McpServerStreamableHttpProperties props) {
    return WebMvcStreamableServerTransportProvider.builder()
        .jsonMapper(new JacksonMcpJsonMapper(jsonMapper))
        .mcpEndpoint(props.getMcpEndpoint())
        .keepAliveInterval(props.getKeepAliveInterval())
        .disallowDelete(props.isDisallowDelete())
        .contextExtractor(request -> {
            String auth = request.headers().firstHeader("Authorization");
            return McpTransportContext.create(Map.of(
                "authorization", auth != null ? auth : ""
            ));
        })
        .build();
}
```

### `ServerTransportSecurityValidator` — Pre-routing Header Guard

Runs **inside the MVC route handler**, before Spring Security filter chain. Use for protocol-level checks, not JWT validation:

```java
ServerTransportSecurityValidator headerGuard = headers -> {
    List<String> authValues = headers.get("authorization");
    if (authValues == null || authValues.isEmpty()) {
        throw new ServerTransportSecurityException(401, "Missing Authorization header");
    }
};
```

---

## 6. Okta Access Token JWT (for reference)

What Spring Security will receive and validate on every request:

```json
{
  "ver": 1,
  "jti": "AT.abc123",
  "iss": "https://okta-mcp-server.oktapreview.com/oauth2/default",
  "aud": "api://default",
  "iat": 1711396800,
  "exp": 1711400400,
  "cid": "<client_id_of_mcp_client_app>",
  "uid": "<user_id>",
  "scp": ["openid", "profile"],
  "sub": "prachi@okta.com"
}
```

Spring Security's `JwtDecoder` auto-fetches the JWKS from `jwks_uri` and validates RS256 signature. No manual key management needed. `iss` claim is matched against the configured `issuer-uri`.

---

## 7. Recommended Implementation Plan (Resource Server Pattern)

### Files to Create/Modify

| File | Action | What |
|---|---|---|
| `pom.xml` | Modify | Add `spring-boot-starter-oauth2-resource-server` |
| `application.properties` | Modify | Switch transport stdio→STREAMABLE, add `issuer-uri` |
| `McpTransportConfig.java` | Modify | Replace `StdioServerTransport` bean with `WebMvcStreamableServerTransportProvider` + `contextExtractor` |
| `SecurityConfig.java` | **Create** | Spring Security `SecurityFilterChain` — JWT resource server |
| `AuthorizationServerMetadataController.java` | **Create** | `GET /.well-known/oauth-authorization-server` |
| `.vscode/mcp.json` | Modify | Change `type` from `stdio` to `http`, add `url` |

---

### `pom.xml` additions

```xml
<!-- Switch from stdio-only to WebMVC (HTTP) transport -->
<dependency>
    <groupId>org.springframework.ai</groupId>
    <artifactId>spring-ai-starter-mcp-server-webmvc</artifactId>
</dependency>

<!-- JWT validation (Spring Security OAuth2 Resource Server) -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
</dependency>
```

Remove or keep the stdio starter depending on whether you want to support both transports.

---

### `application.properties` changes

```properties
# Switch from stdio to HTTP Streamable transport
spring.ai.mcp.server.stdio=false
spring.ai.mcp.server.protocol=STREAMABLE
spring.ai.mcp.server.name=okta-mcp-server
spring.ai.mcp.server.version=0.0.1

# Okta Custom AS issuer URI (the Authorization Server the MCP clients will get tokens from)
spring.security.oauth2.resourceserver.jwt.issuer-uri=https://okta-mcp-server.oktapreview.com/oauth2/default

# Okta org credentials for the server's own API calls (unchanged)
okta.client.orgUrl=${OKTA_ORG_URL}
okta.client.clientId=${OKTA_CLIENT_ID:}
okta.client.privateKey=${OKTA_PRIVATE_KEY:}
okta.client.keyId=${OKTA_KEY_ID:}
okta.client.token=${OKTA_CLIENT_TOKEN:}
okta.client.scopes=${OKTA_SCOPES:okta.users.read okta.users.manage okta.groups.read okta.groups.manage}
```

---

### `SecurityConfig.java`

**Option A — Protect everything (simplest for POC):**
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            // Permit the AS metadata endpoint publicly — no token needed to discover where to get one
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/.well-known/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.issuerUri(issuerUri))
            );
        return http.build();
    }
}
```

**Option B — Protect tool calls only, allow `initialize` + `tools/list` publicly:**
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(authz -> authz
                .requestMatchers("/.well-known/**").permitAll()
                .anyRequest().permitAll()  // method-level @PreAuthorize on tools
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );
        return http.build();
    }
}

// Then on each tool method:
@PreAuthorize("isAuthenticated()")
@Tool(name = "list_users", description = "...")
public Object listUsers(McpSyncRequestContext ctx) { ... }
```

---

### `AuthorizationServerMetadataController.java`

```java
@RestController
public class AuthorizationServerMetadataController {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String oktaIssuer;

    /**
     * RFC 8414 — Authorization Server Metadata.
     * MCP clients call this first to discover where to get an access token.
     * We proxy Okta's own metadata document so our server URL is transparent.
     */
    @GetMapping(value = "/.well-known/oauth-authorization-server",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata() {
        // Option 1 (simplest): proxy Okta's own metadata
        try {
            var url = new URL(oktaIssuer + "/.well-known/oauth-authorization-server");
            var oktaMeta = new ObjectMapper().readValue(url, new TypeReference<Map<String, Object>>() {});
            return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")  // CORS required by spec
                .body(oktaMeta);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch Okta AS metadata", e);
        }

        // Option 2 (explicit): return your own document
        // return ResponseEntity.ok(Map.of(
        //     "issuer", oktaIssuer,
        //     "authorization_endpoint", oktaIssuer + "/v1/authorize",
        //     "token_endpoint", oktaIssuer + "/v1/token",
        //     "jwks_uri", oktaIssuer + "/v1/keys",
        //     "response_types_supported", List.of("code"),
        //     "code_challenge_methods_supported", List.of("S256"),
        //     "grant_types_supported", List.of("authorization_code", "client_credentials")
        // ));
    }
}
```

---

### Accessing identity inside a tool (after all wiring)

```java
@Tool(name = "list_users", description = "List Okta users")
public Object listUsers(McpSyncRequestContext requestCtx) {
    // 1. From Spring Security — the JWT's claims
    var auth = (JwtAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
    String callerSub = auth.getName();             // "prachi@okta.com"
    Collection<String> scopes = auth.getAuthorities()...;

    // 2. Raw Bearer header (from McpTransportContext)
    String authHeader = (String) requestCtx.transportContext().get("authorization");

    // 3. Server's own Okta SDK (unchanged — uses server's service account token)
    var users = okta.userApi().listUsers(...);
}
```

---

### `.vscode/mcp.json` change (for HTTP transport)

```json
{
  "servers": {
    "okta-mcp-poc": {
      "type": "http",
      "url": "http://localhost:8080/mcp"
    }
  }
}
```

The server no longer needs env var inputs from VS Code — it starts standalone and the MCP client authenticates via OAuth.

---

## 8. End-to-End Flow (Final)

```
Step 1 — Discovery (RFC 8414)
  MCP Client  ──GET /.well-known/oauth-authorization-server──►  MCP Server (:8080)
              ◄── { Okta endpoints... } ──────────────────────

Step 2 — Token Acquisition (MCP client ↔ Okta directly)
  MCP Client  ──PKCE Authorization Code Flow──────────────────►  Okta AS
              ◄── access_token (RS256 JWT, iss=okta, aud=api://default) ──

Step 3 — Authenticated MCP Session
  MCP Client  ──POST /mcp ──────────────────────────────────►  MCP Server
               Authorization: Bearer <okta_jwt>
               {"method": "initialize", ...}
              Spring Security intercepts → fetches JWKS from Okta → validates JWT
              McpTransportContextExtractor captures Authorization header
              MCP initialize handshake completes
              ◄── {"result": {"serverInfo": ...}} ──────────────

Step 4 — Tool Call
  MCP Client  ──POST /mcp ──────────────────────────────────►  MCP Server
               Authorization: Bearer <okta_jwt>
               {"method": "tools/call", "params": {"name": "list_users"}}
              Spring Security re-validates JWT (stateless — every request)
              Tool method receives McpSyncRequestContext
              Tool calls Okta SDK (server's own service account token)
              ◄── {"result": {"content": [...]}} ──────────────
```

---

## 9. Key Decisions Made

| Decision | Choice | Reason |
|---|---|---|
| Auth pattern | Resource Server (Option A) | No token storage, no session management, stateless — right scope for POC |
| Who issues tokens? | Okta | Our server never issues tokens; simpler, standard |
| Transport | Streamable HTTP | Supports all MCP protocol versions; SSE is deprecated |
| Token validation | Spring Security `oauth2ResourceServer().jwt()` | Auto-fetches JWKS, handles rotation, standard |
| `/.well-known` | Proxy Okta's metadata | Single source of truth; no duplication of endpoint config |
| Tool-level security | `SecurityContextHolder` + `McpTransportContext` | Both available simultaneously after wiring |
| Python server's elicitation | Not in Java POC scope | Different task |

---

## 10. References

| Resource | URL |
|---|---|
| MCP Authorization Spec (2025-03-26) | https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization |
| RFC 8414 — AS Metadata | https://www.rfc-editor.org/rfc/rfc8414 |
| RFC 9728 — Protected Resource Metadata | https://www.rfc-editor.org/rfc/rfc9728 |
| RFC 7591 — Dynamic Client Registration | https://www.rfc-editor.org/rfc/rfc7591 |
| Spring AI MCP Server Docs | https://docs.spring.io/spring-ai/reference/api/mcp/mcp-server-boot-starter-docs.html |
| Spring AI MCP Security (community) | https://github.com/spring-ai-community/mcp-server-security |
| Cloudflare Workers OAuth Provider | https://github.com/cloudflare/workers-oauth-provider |
| Anthropic TypeScript SDK Auth | https://github.com/modelcontextprotocol/typescript-sdk/tree/main/src/server/auth |
| Okta AS Metadata Endpoint | `https://{domain}/oauth2/{authServerId}/.well-known/oauth-authorization-server` |
