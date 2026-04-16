package com.okta.mcp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OAuth 2.0 Authorization Server Metadata (RFC 8414) + Dynamic Client Registration (RFC 7591).
 *
 * VS Code reads these endpoints to discover how to authenticate with this MCP server.
 * The MCP server acts as a proxy AS — it accepts VS Code's PKCE requests and relays
 * them to the real Okta AS. This solves the random loopback port problem:
 *
 *   VS Code → POST /oauth2/authorize (random port redirect_uri)
 *          → MCP server stores port, relays to Okta with fixed redirect_uri
 *          → Okta → /oauth2/callback → MCP server relays code back to VS Code's random port
 *          → VS Code → POST /oauth2/token → MCP server proxies to Okta → returns real token
 *
 * Discovery URL: GET /.well-known/oauth-authorization-server
 * Registration:  POST /oauth2/register  (returns pre-configured Okta SPA client_id)
 */
@RestController
public class AuthorizationServerMetadataController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerMetadataController.class);

    /** Base URL of this MCP server — used as the proxy AS issuer. */
    @Value("${okta.server.base-url:http://127.0.0.1:8080}")
    private String serverBaseUrl;

    /** Client ID of the Okta SPA app — returned to VS Code via dynamic client registration. */
    @Value("${okta.ui.clientId:}")
    private String uiClientId;

    /** Scopes this AS supports. */
    @Value("${okta.ui.scopes:openid profile email}")
    private String uiScopes;

    /**
     * RFC 8414 — Authorization Server Metadata.
     *
     * VS Code fetches this to discover the authorize/token/registration endpoints.
     * The issuer is our MCP server (proxy AS), not Okta directly.
     */
    @GetMapping(value = "/.well-known/oauth-authorization-server",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> metadata() {
        log.info("[OAuthProxy AS] GET /.well-known/oauth-authorization-server");
        List<String> scopeList = Arrays.asList(uiScopes.split("\\s+"));
        // No registration_endpoint — client_id is pre-registered in the customer's Okta org.
        // VS Code 1.103+ will prompt the user to enter client_id once, then store and reuse it.
        // Advertising a registration_endpoint causes VS Code to attempt DCR which we don't need.
        return Map.of(
            "issuer",                                  serverBaseUrl,
            "authorization_endpoint",                  serverBaseUrl + "/authorize",
            "token_endpoint",                          serverBaseUrl + "/token",
            "response_types_supported",                List.of("code"),
            "grant_types_supported",                   List.of("authorization_code"),
            "code_challenge_methods_supported",        List.of("S256"),
            "token_endpoint_auth_methods_supported",   List.of("none"),
            "scopes_supported",                        scopeList
        );
    }

    /**
     * RFC 7591 — Dynamic Client Registration.
     *
     * VS Code calls this to obtain a client_id before starting the PKCE flow.
     * We return the pre-configured Okta SPA client_id so that subsequent
     * /oauth2/authorize and /oauth2/token requests carry the right client_id
     * when we relay them to Okta.
     *
     * POST /oauth2/register
     * Body: { "redirect_uris": ["http://127.0.0.1:{randomPort}/callback"], ... }
     * Response: { "client_id": "<okta-spa-client-id>", ... }
     */
    @PostMapping(value = {"/oauth2/register", "/register"},
                 consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(@RequestBody Map<String, Object> request) {
        log.info("[OAuthProxy AS] POST /oauth2/register — client_name={}", request.get("client_name"));

        Map<String, Object> response = new HashMap<>();
        response.put("client_id",                  uiClientId);
        response.put("client_name",                "Okta MCP Server");
        response.put("redirect_uris",              List.of(serverBaseUrl + "/oauth2/callback", serverBaseUrl + "/callback"));
        response.put("grant_types",                List.of("authorization_code"));
        response.put("response_types",             List.of("code"));
        response.put("token_endpoint_auth_method", "none"); // public PKCE client — no secret

        log.info("[OAuthProxy AS] Returning client_id={} to VS Code", uiClientId);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
