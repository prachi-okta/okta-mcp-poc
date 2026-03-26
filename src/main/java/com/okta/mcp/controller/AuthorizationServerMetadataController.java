package com.okta.mcp.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URL;
import java.util.List;
import java.util.Map;

/**
 * Exposes the OAuth 2.0 Authorization Server Metadata endpoint (RFC 8414).
 *
 * MCP clients call GET /.well-known/oauth-authorization-server before starting
 * any OAuth flow. This response tells the client where to obtain an access token
 * (Okta's authorize, token, and JWKS endpoints).
 *
 * Per the MCP spec (2025-03-26), the discovery URL is derived by stripping the
 * path from the MCP server URL:
 *   MCP server:    https://mcp.acme.com/mcp
 *   Discovery URL: https://mcp.acme.com/.well-known/oauth-authorization-server
 *
 * Strategy: proxy Okta's own RFC 8414 metadata document so there is a single
 * source of truth. If Okta is unreachable, return a minimal static fallback
 * derived from the configured issuer URI.
 *
 * CORS is permitted from any origin — required by the MCP spec so that
 * browser-based MCP clients can fetch the discovery document.
 */
@RestController
public class AuthorizationServerMetadataController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerMetadataController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Value("${okta.auth.issuer-uri}")
    private String issuerUri;

    @GetMapping(value = "/.well-known/oauth-authorization-server",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata() {

        // Primary: proxy Okta's own RFC 8414 metadata document.
        // Okta exposes this at: {issuer}/.well-known/oauth-authorization-server
        try {
            URL metaUrl = new URL(issuerUri + "/.well-known/oauth-authorization-server");
            Map<String, Object> oktaMeta = MAPPER.readValue(metaUrl, new TypeReference<>() {});
            log.debug("Returning proxied Okta AS metadata from {}", metaUrl);
            return ResponseEntity.ok()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Cache-Control", "max-age=3600")
                    .body(oktaMeta);
        } catch (Exception e) {
            log.warn("Could not fetch Okta AS metadata from {} — returning static fallback. Reason: {}",
                    issuerUri, e.getMessage());
        }

        // Fallback: return a minimal static document built from the issuer URI.
        // This covers the case where the Okta org is unreachable at request time.
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body(Map.of(
                        "issuer",                                issuerUri,
                        "authorization_endpoint",               issuerUri + "/v1/authorize",
                        "token_endpoint",                        issuerUri + "/v1/token",
                        "jwks_uri",                              issuerUri + "/v1/keys",
                        "userinfo_endpoint",                     issuerUri + "/v1/userinfo",
                        "introspection_endpoint",                issuerUri + "/v1/introspect",
                        "response_types_supported",              List.of("code"),
                        "code_challenge_methods_supported",      List.of("S256"),
                        "grant_types_supported",                 List.of("authorization_code", "client_credentials"),
                        "token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none")
                ));
    }
}
