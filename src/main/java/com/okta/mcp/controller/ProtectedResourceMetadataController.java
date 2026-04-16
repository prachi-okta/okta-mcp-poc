package com.okta.mcp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * Exposes the OAuth 2.0 Protected Resource Metadata document (RFC 9728).
 *
 * MCP clients call this after receiving a 401 with WWW-Authenticate pointing here.
 * The response points clients directly at the customer's Okta AS. The MCP server
 * plays no further role in the OAuth flow — auth is entirely between the client and Okta.
 *
 * Discovery URL: GET /.well-known/oauth-protected-resource
 *
 * Flow:
 *   1. Client makes unauthenticated request → 401 + WWW-Authenticate: Bearer resource_metadata="..."
 *   2. Client fetches this endpoint → { resource, authorization_servers: ["https://org.okta.com/..."] }
 *   3. Client talks directly to Okta for discovery, PKCE, and token exchange
 *   4. Client sends Authorization: Bearer <jwt> on every /sse and /mcp request
 *   5. MCP server validates the JWT and serves tools
 */
@RestController
public class ProtectedResourceMetadataController {

    private static final Logger log = LoggerFactory.getLogger(ProtectedResourceMetadataController.class);

    /** Canonical URI of this MCP server (used as OAuth resource identifier per RFC 8707). */
    @Value("${okta.resource.uri}")
    private String resourceUri;

    /**
     * Base URL of this MCP server — returned as authorization_servers so VS Code discovers
     * our proxy AS endpoints instead of going directly to Okta.
     * This is what enables the proxy callback pattern for random-port clients.
     */
    @Value("${okta.server.base-url:http://127.0.0.1:8080}")
    private String serverBaseUrl;

    /** Scopes required to access this resource (surfaced in WWW-Authenticate + this document). */
    @Value("${okta.ui.scopes:openid profile email}")
    private String scopes;

    @GetMapping(value = "/.well-known/oauth-protected-resource",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata() {
        List<String> scopeList = Arrays.asList(scopes.split("\\s+"));
        log.info("[OIDC] GET /.well-known/oauth-protected-resource — resource={}, authorization_servers=[{}]",
                resourceUri, serverBaseUrl);

        Map<String, Object> meta = Map.of(
            // RFC 9728 §2: the resource identifier (must match the resource= param clients send)
            "resource",                 resourceUri,
            // RFC 9728 §2: this MCP server acts as a proxy AS.
            // VS Code will discover /.well-known/oauth-authorization-server from this URL,
            // which points at our proxy endpoints (/oauth2/authorize, /oauth2/token).
            "authorization_servers",    List.of(serverBaseUrl),
            // Scopes this resource accepts (clients use this for scope selection per MCP spec §6)
            "scopes_supported",         scopeList,
            // Only header-based bearer tokens are accepted (no query-string tokens)
            "bearer_methods_supported", List.of("header")
        );

        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .header("Cache-Control", "max-age=3600")
                .body(meta);
    }
}

