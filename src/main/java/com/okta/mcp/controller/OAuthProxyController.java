package com.okta.mcp.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestClient;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth 2.0 PKCE proxy — bridges VS Code Copilot's random loopback redirect URIs
 * to the single fixed redirect URI registered in Okta.
 *
 * VS Code picks a random port (e.g. http://127.0.0.1:33418/) on every PKCE flow.
 * We intercept three steps:
 *
 *   POST /register        — fake DCR: returns pre-registered client_id immediately
 *   GET  /authorize       — saves VS Code's random redirect_uri, forwards to Okta
 *                            with redirect_uri=http://127.0.0.1:8080/oauth2/callback
 *   GET  /oauth2/callback — Okta posts code here; we forward it to VS Code's random port
 *   POST /token           — swaps redirect_uri back to fixed callback, calls Okta token endpoint
 *
 * Only ONE redirect URI needs to be registered in Okta:
 *   http://127.0.0.1:8080/oauth2/callback
 */
@Controller
public class OAuthProxyController {

    private static final Logger log = LoggerFactory.getLogger(OAuthProxyController.class);

    @Value("${okta.auth.issuer-uri}")
    private String issuerUri;

    @Value("${okta.resource.uri}")
    private String resourceUri;

    @Value("${okta.ui.clientId:}")
    private String configuredClientId;

    /** state → original redirect_uri sent by VS Code */
    private final ConcurrentHashMap<String, String> pendingStates = new ConcurrentHashMap<>();

    /**
     * Fake Dynamic Client Registration (RFC 7591) endpoint.
     *
     * VS Code attempts DCR when it has no stored client_id. Rather than letting it fail
     * (which causes immediate "Canceled: Canceled"), we return our pre-registered client_id
     * so VS Code proceeds with the PKCE flow using the correct Okta app.
     */
    @PostMapping(value = "/register", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> register(@RequestBody(required = false) Map<String, Object> body) {
        log.info("[OAuth Proxy] 📋 DCR /register — returning pre-registered client_id={}", configuredClientId);
        return ResponseEntity.ok(Map.of(
                "client_id",                  configuredClientId,
                "client_id_issued_at",         System.currentTimeMillis() / 1000,
                "token_endpoint_auth_method",  "none",
                "grant_types",                 java.util.List.of("authorization_code"),
                "response_types",              java.util.List.of("code"),
                "redirect_uris",               java.util.List.of(callbackUri()),
                "scope",                       "openid profile email"
        ));
    }

    /** Fixed callback URI registered in Okta — derived from the server base URL. */
    private String callbackUri() {
        try {
            java.net.URI uri = new java.net.URI(resourceUri);
            return uri.getScheme() + "://" + uri.getAuthority() + "/oauth2/callback";
        } catch (Exception e) {
            return "http://localhost:8080/oauth2/callback";
        }
    }

    /**
     * Step 1 — VS Code hits this endpoint with its random redirect_uri.
     * We save that redirect_uri keyed by state, then forward to Okta substituting
     * our fixed callback URI.
     */
    @GetMapping("/authorize")
    public void authorize(@RequestParam Map<String, String> params,
                          HttpServletResponse response) throws IOException {

        String originalRedirectUri = params.get("redirect_uri");
        String state = params.get("state");
        log.info("[OAuth Proxy] ▶ authorize — state={} originalRedirectUri={}", state, originalRedirectUri);

        if (state != null && originalRedirectUri != null) {
            pendingStates.put(state, originalRedirectUri);
        }

        // Forward all params to Okta, replacing redirect_uri with our fixed callback
        StringBuilder url = new StringBuilder(issuerUri + "/v1/authorize?");
        String sep = "";
        for (Map.Entry<String, String> e : params.entrySet()) {
            String key = e.getKey();
            String val = "redirect_uri".equals(key) ? callbackUri() : e.getValue();
            url.append(sep)
               .append(URLEncoder.encode(key, StandardCharsets.UTF_8))
               .append("=")
               .append(URLEncoder.encode(val, StandardCharsets.UTF_8));
            sep = "&";
        }

        log.info("[OAuth Proxy] ↗ redirecting to Okta authorize");
        response.sendRedirect(url.toString());
    }

    /**
     * Step 2 — Okta redirects here with the auth code.
     * We look up the original redirect_uri for this state and forward everything to
     * VS Code's local callback server so it can complete the token exchange.
     */
    @GetMapping("/oauth2/callback")
    public void callback(@RequestParam Map<String, String> params,
                         HttpServletResponse response) throws IOException {

        String state = params.get("state");
        String originalRedirectUri = pendingStates.remove(state);
        log.info("[OAuth Proxy] ◀ callback — state={} code={} originalRedirectUri={}",
                state, params.containsKey("code") ? "<present>" : "<missing>", originalRedirectUri);

        if (originalRedirectUri == null) {
            log.error("[OAuth Proxy] ❌ Unknown state — no pending auth for state={}", state);
            response.sendError(HttpServletResponse.SC_BAD_REQUEST,
                    "Unknown OAuth state — no pending authorization found.");
            return;
        }

        // Forward all params (code, state, etc.) to VS Code's original callback URI
        StringBuilder redirectUrl = new StringBuilder(originalRedirectUri);
        String sep = originalRedirectUri.contains("?") ? "&" : "?";
        for (Map.Entry<String, String> e : params.entrySet()) {
            redirectUrl.append(sep)
                       .append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8))
                       .append("=")
                       .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            sep = "&";
        }

        log.info("[OAuth Proxy] ↗ forwarding code to VS Code callback");
        response.sendRedirect(redirectUrl.toString());
    }

    /**
     * Step 3 — VS Code calls POST /token (derived from our base URL).
     * We swap the redirect_uri back to our fixed callback URI before forwarding to
     * Okta's real token endpoint, so the redirect_uri matches what was sent in Step 1.
     */
    @PostMapping(value = "/token",
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> token(@RequestParam Map<String, String> params) {
        log.info("[OAuth Proxy] ▶ token exchange — grant_type={}, has_code={}",
                params.get("grant_type"), params.containsKey("code"));

        // Swap VS Code's original random redirect_uri with our fixed callback URI
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        for (Map.Entry<String, String> e : params.entrySet()) {
            String val = "redirect_uri".equals(e.getKey()) ? callbackUri() : e.getValue();
            body.add(e.getKey(), val);
        }
        log.info("[OAuth Proxy] ↗ forwarding token request to Okta (redirect_uri={})", callbackUri());

        String oktaTokenEndpoint = issuerUri + "/v1/token";
        try {
            String oktaResponse = RestClient.create()
                    .post()
                    .uri(oktaTokenEndpoint)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(body)
                    .retrieve()
                    .body(String.class);
            log.info("[OAuth Proxy] ✅ token exchange succeeded");
            return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(oktaResponse);
        } catch (Exception e) {
            log.error("[OAuth Proxy] ❌ token exchange failed: {}", e.getMessage());
            return ResponseEntity.status(400)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body("{\"error\":\"token_exchange_failed\",\"error_description\":\"" + e.getMessage() + "\"}");
        }
    }
}
