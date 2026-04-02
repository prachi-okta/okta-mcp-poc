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
 * The response tells the client which Authorization Server protects this resource.
 *
 * Discovery URL: GET /.well-known/oauth-protected-resource
 *
 * Flow:
 *   1. Client makes unauthenticated request → 401 + WWW-Authenticate: Bearer resource_metadata="..."
 *   2. Client fetches this endpoint → { resource, authorization_servers, scopes_supported }
 *   3. Client appends /.well-known/oauth-authorization-server to authorization_servers[0]
 *      → fetches our AS metadata (with proxied authorize/token/register endpoints)
 *   4. Client calls POST /register → gets back pre-registered client_id automatically
 *   5. Client performs PKCE flow through our proxy → obtains Okta JWT
 *   6. Client sends Authorization: Bearer <jwt> on every /sse and /mcp request
 */
@RestController
public class ProtectedResourceMetadataController {

    private static final Logger log = LoggerFactory.getLogger(ProtectedResourceMetadataController.class);

    /** Canonical URI of this MCP server (used as OAuth resource identifier per RFC 8707). */
    @Value("${okta.resource.uri}")
    private String resourceUri;

    /** Scopes required to access this resource (surfaced in WWW-Authenticate + this document). */
    @Value("${okta.ui.scopes:openid profile email}")
    private String scopes;

    /** Returns just the origin (scheme://host:port) of the resource URI. */
    private String serverBaseUri() {
        try {
            java.net.URI uri = new java.net.URI(resourceUri);
            return uri.getScheme() + "://" + uri.getAuthority();
        } catch (Exception e) {
            return "http://localhost:8080";
        }
    }

    @GetMapping(value = "/.well-known/oauth-protected-resource",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata() {
        List<String> scopeList = Arrays.asList(scopes.split("\\s+"));
        String baseUri = serverBaseUri();
        log.info("[OIDC] GET /.well-known/oauth-protected-resource — resource={}, authorization_servers=[{}]",
                resourceUri, baseUri);

        Map<String, Object> meta = Map.of(
            // RFC 9728 §2: the resource identifier (must match the resource= param clients send)
            "resource",                 resourceUri,
            // RFC 9728 §2: issuer identifier of the AS protecting this resource.
            // Clients append /.well-known/oauth-authorization-server to derive the metadata URL.
            // We point at ourselves so our proxy authorization_endpoint / token_endpoint are used.
            "authorization_servers",    List.of(baseUri),
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
