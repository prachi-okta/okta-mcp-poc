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
 * Returns our server's own metadata with three key overrides on top of Okta's:
 *   - authorization_endpoint → /authorize  (redirect_uri proxy)
 *   - token_endpoint         → /token       (redirect_uri proxy)
 *   - registration_endpoint  → /register    (fake DCR — returns pre-registered client_id)
 *   - issuer                 → http://127.0.0.1:8080 (must match fetch URL per RFC 8414 §3.3)
 *
 * This allows VS Code Copilot to complete the full PKCE flow with a fixed
 * redirect URI (http://127.0.0.1:8080/oauth2/callback) registered in Okta,
 * while VS Code's random loopback port is handled transparently by the proxy.
 */
@RestController
public class AuthorizationServerMetadataController {

    private static final Logger log = LoggerFactory.getLogger(AuthorizationServerMetadataController.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Value("${okta.auth.issuer-uri}")
    private String issuerUri;

    @Value("${okta.resource.uri}")
    private String resourceUri;

    /**
     * Returns the proxy authorization endpoint on THIS server.
     * VS Code will send its random redirect_uri here; OAuthProxyController handles
     * the substitution so only one fixed redirect URI needs to be in Okta.
     */
    private String proxyAuthEndpoint() {
        try {
            java.net.URI uri = new java.net.URI(resourceUri);
            return uri.getScheme() + "://" + uri.getAuthority() + "/authorize";
        } catch (Exception e) {
            return "http://localhost:8080/oauth2/authorize";
        }
    }

    private String proxyTokenEndpoint() {
        try {
            java.net.URI uri = new java.net.URI(resourceUri);
            return uri.getScheme() + "://" + uri.getAuthority() + "/token";
        } catch (Exception e) {
            return "http://localhost:8080/token";
        }
    }

    private String proxyRegistrationEndpoint() {
        try {
            java.net.URI uri = new java.net.URI(resourceUri);
            return uri.getScheme() + "://" + uri.getAuthority() + "/register";
        } catch (Exception e) {
            return "http://localhost:8080/register";
        }
    }

    @GetMapping(value = "/.well-known/oauth-authorization-server",
                produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> metadata() {

        // Primary: proxy Okta's own RFC 8414 metadata document.
        // Okta exposes this at: {issuer}/.well-known/oauth-authorization-server
        String metaUrlStr = issuerUri + "/.well-known/oauth-authorization-server";
        log.info("[OIDC] GET /.well-known/oauth-authorization-server — fetching Okta AS metadata from: {}", metaUrlStr);
        try {
            URL metaUrl = new URL(metaUrlStr);
            Map<String, Object> oktaMeta = new java.util.LinkedHashMap<>(MAPPER.readValue(metaUrl, new TypeReference<>() {}));
            // Override authorization_endpoint with our proxy so VS Code's random redirect_uri
            // is accepted — OAuthProxyController translates it to the fixed Okta-registered URI.
            oktaMeta.put("authorization_endpoint", proxyAuthEndpoint());
            oktaMeta.put("token_endpoint", proxyTokenEndpoint());
            oktaMeta.put("registration_endpoint", proxyRegistrationEndpoint());
            try {
                java.net.URI uri = new java.net.URI(resourceUri);
                oktaMeta.put("issuer", uri.getScheme() + "://" + uri.getAuthority());
            } catch (Exception ignored) {}
            log.info("[OIDC] ✅ AS metadata proxied — authorization_endpoint={}, token_endpoint={}, registration_endpoint={}",
                    proxyAuthEndpoint(), proxyTokenEndpoint(), proxyRegistrationEndpoint());
            return ResponseEntity.ok()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Cache-Control", "no-store")
                    .body(oktaMeta);
        } catch (Exception e) {
            log.warn("[OIDC] ⚠️  Could not fetch Okta AS metadata from {} — returning static fallback. Reason: {}",
                    metaUrlStr, e.getMessage());
        }

        // Fallback: return a minimal static document built from the issuer URI.
        // This covers the case where the Okta org is unreachable at request time.
        log.info("[OIDC] Returning static fallback AS metadata for issuer: {}", issuerUri);
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body(Map.ofEntries(
                        Map.entry("issuer",                                issuerUri),
                        Map.entry("authorization_endpoint",               proxyAuthEndpoint()),
                        Map.entry("token_endpoint",                        proxyTokenEndpoint()),
                        Map.entry("registration_endpoint",                 proxyRegistrationEndpoint()),
                        Map.entry("jwks_uri",                              issuerUri + "/v1/keys"),
                        Map.entry("userinfo_endpoint",                     issuerUri + "/v1/userinfo"),
                        Map.entry("introspection_endpoint",                issuerUri + "/v1/introspect"),
                        Map.entry("response_types_supported",              List.of("code")),
                        Map.entry("code_challenge_methods_supported",      List.of("S256")),
                        Map.entry("grant_types_supported",                 List.of("authorization_code", "client_credentials")),
                        Map.entry("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post", "none"))
                ));
    }
}
