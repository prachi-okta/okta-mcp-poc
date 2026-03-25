# Okta MCP Server

A **Model Context Protocol (MCP) server** built with **Spring AI** and the **Okta Java SDK** that exposes tools for AI assistants (GitHub Copilot, Claude, etc.) to manage Okta users, groups, and applications programmatically.

---

## Architecture

```
MCP Client (GitHub Copilot / Claude / AI Agent)
        │  stdin / stdout (JSON-RPC over stdio)
        ▼
┌──────────────────────────────────────┐
│   Spring Boot MCP Server (stdio)     │
│  ┌────────────────────────────────┐  │
│  │  Spring AI MCP                 │  │
│  │  15+ @Tool methods             │  │
│  └───────────────┬────────────────┘  │
│                  │                   │
│  OktaClientProvider (lazy init)      │
└──────────────────┼───────────────────┘
                   │  Okta Java SDK v25 (SSWS / Private Key JWT)
                   ▼
          Okta Management API
```

The server runs as a **stdio process** — the MCP client spawns it and communicates via JSON-RPC over stdin/stdout. All logging goes to stderr so stdout stays clean for the MCP protocol.

---

## Prerequisites

| Tool | Version |
|------|---------|
| Java | 21+ |
| Maven | 3.9+ (or use the included `./mvnw`) |
| Okta org | Developer or production |

---

## 1 — Okta Setup

### Option A — API Token (simplest for development)

1. In the Okta Admin Console → **Security → API → Tokens**
2. Click **Create Token**, copy the value → this is `OKTA_CLIENT_TOKEN`

### Option B — OAuth2 Service App (recommended for production)

1. **Admin Console → Applications → Create App Integration**
   - Sign-in method: **API Services** (Machine-to-Machine)
2. In the new app's **Okta API Scopes** tab, grant:
   - `okta.users.read` / `okta.users.manage`
   - `okta.groups.read` / `okta.groups.manage`
   - `okta.apps.read` (for application listing)
3. Under **Client Credentials**, note the **Client ID**
4. Generate a **Public/Private Key Pair** and download the private key PEM

---

## 2 — Build

```bash
# Using the Maven Wrapper (no Maven installation required)
./mvnw clean package -DskipTests

# Or with Maven directly
mvn clean package -DskipTests
```

The fat jar will be at `target/okta-mcp-poc-0.0.1-SNAPSHOT.jar`.

---

## 3 — VS Code Integration

The repository includes a `.vscode/mcp.json` that registers this server with VS Code's MCP client. It prompts you for credentials at first start.

| Variable | Description |
|----------|-------------|
| `OKTA_ORG_URL` | Your Okta org URL, e.g. `https://dev-123456.okta.com` |
| `OKTA_CLIENT_TOKEN` | SSWS API token (Option A) — leave blank for OAuth2 |
| `OKTA_CLIENT_ID` | Service app Client ID (Option B) |
| `OKTA_PRIVATE_KEY` | RSA private key PEM (Option B) |
| `OKTA_KEY_ID` | Key ID registered in the Okta app's JWK set (Option B) |
| `OKTA_SCOPES` | Space-separated OAuth2 scopes (default covers users/groups/apps) |

After building the jar, open VS Code, go to **Copilot Chat → Agent mode**, and the `okta-mcp-poc` server will be available.

---

## 4 — Run Manually

```bash
# Option A – SSWS token
OKTA_ORG_URL=https://dev-12345678.okta.com \
OKTA_CLIENT_TOKEN=ssws_your_api_token \
java -jar target/okta-mcp-poc-0.0.1-SNAPSHOT.jar

# Option B – Private Key JWT
OKTA_ORG_URL=https://dev-12345678.okta.com \
OKTA_CLIENT_ID=0oa... \
OKTA_PRIVATE_KEY="$(cat private_key.pem)" \
OKTA_KEY_ID=your-key-id \
java -jar target/okta-mcp-poc-0.0.1-SNAPSHOT.jar
```

---

## 5 — MCP Tool Reference

### User Tools

| Tool | Required | Optional | Description |
|------|----------|----------|-------------|
| `list_users` | — | search, filter, q, after, limit | List users with optional filtering |
| `get_user` | userId | — | Get a user by ID or login |
| `create_user` | firstName, lastName, email, login | password | Create and activate a new user |
| `update_user` | userId | firstName, lastName, email | Partial-update a user's profile |
| `deactivate_user` | userId | — | Deactivate a user (required before delete) |
| `delete_user` | userId | — | Permanently delete a deactivated user |

### Group Tools

| Tool | Required | Optional | Description |
|------|----------|----------|-------------|
| `list_groups` | — | search, filter, q, after, limit | List groups with optional filtering |
| `get_group` | groupId | — | Get a group by ID |
| `add_user_to_group` | groupId, userId | — | Add a user to a group (idempotent) |
| `remove_user_from_group` | groupId, userId | — | Remove a user from a group |
| `list_group_users` | groupId | after, limit | List users in a group |

### Application Tools

| Tool | Required | Optional | Description |
|------|----------|----------|-------------|
| `list_applications` | — | q, filter, after, limit | List applications |
| `list_app_groups` | appId | q, after, limit | List groups assigned to an app |
| `list_app_users` | appId | q, after, limit | List users assigned to an app |
| `list_user_apps` | userId | after, limit | List apps assigned to a user |
| `list_user_groups` | userId | — | List groups a user belongs to |

---

## 6 — Security Notes

- All credentials are passed via environment variables — never commit secrets to source control.
- For production, prefer **Option B** (OAuth2 Private Key JWT) over API tokens.
- The SSWS token option is labeled as a dev fallback in the server logs.

---

## Project Structure

```
okta-mcp-poc/
├── pom.xml
├── scripts/
│   └── run-mcp.sh                        # Wrapper script used by VS Code MCP client
└── src/main/
    ├── java/com/okta/mcp/
    │   ├── OktaMcpApplication.java        # Spring Boot entry point
    │   ├── config/
    │   │   ├── McpTransportConfig.java    # Stdio transport with lenient JSON parsing
    │   │   ├── OktaClientProvider.java    # Lazy Okta SDK client initialization
    │   │   └── ToolConfig.java            # Registers all @Tool methods with Spring AI MCP
    │   └── tools/
    │       ├── OktaUserManagementTool.java   # User CRUD tools
    │       ├── OktaGroupsTool.java            # Group management tools
    │       └── OktaApplicationsTool.java      # Application query tools
    └── resources/
        ├── application.properties             # Spring Boot & Okta SDK config
        └── logback-spring.xml                 # Routes all logs to stderr
```

---

## POC Findings

### What worked well
- **Spring AI MCP + stdio transport** is a clean fit for a local MCP server. No HTTP server, no port conflicts, no TLS — the client spawns the process and talks JSON-RPC over stdin/stdout.
- **`@Tool` + `MethodToolCallbackProvider`** made wiring Okta SDK calls into MCP tools straightforward — no boilerplate beyond the annotation.
- **Okta SDK v25** covers all required user, group, and application APIs under separate typed API classes (`UserApi`, `GroupApi`, `ApplicationApi`, etc.).
- **Dual auth modes** (SSWS token for dev, Private Key JWT for production) work with the same codebase by inspecting the presence of `OKTA_PRIVATE_KEY` / `OKTA_KEY_ID` at client-build time.

### Challenges & workarounds

| Problem | Root cause | Fix |
|---------|-----------|-----|
| MCP handshake fails with `-32603` on VS Code | VS Code sends an `"elicitation"` field in `ClientCapabilities` not yet modelled by MCP SDK 0.7.0 — Jackson throws on unknown fields | `McpTransportConfig` supplies a custom `ObjectMapper` with `FAIL_ON_UNKNOWN_PROPERTIES` disabled |
| Spring context crashes before MCP handshake | Okta SDK makes OIDC-discovery HTTP calls when `ApiClient` is constructed at startup | `OktaClientProvider` defers `ApiClient` construction to the first actual tool call (lazy double-checked locking) |
| `stdout` corruption | Spring Boot banner and logs go to stdout by default, corrupting the JSON-RPC stream | `spring.main.banner-mode=off` + `logback-spring.xml` routes all logging to `stderr` |
| SDK v25 API surface changes | `UserCredentials` replaced by `UserCredentialsWritable`; deactivate moved to `UserLifecycleApi`; etc. | Addressed per method with inline SDK-version comments |

### Limitations of this POC
- No persistent sessions: each tool call re-uses the lazily cached `ApiClient`, but the process exits when the MCP client disconnects.
- Pagination is manual: callers must pass the `after` cursor from one call to the next.
- No write-back of private-key JWTs to a secrets store — credentials are environment variables only.
