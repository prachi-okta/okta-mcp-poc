package com.okta.mcp.controller;

import com.okta.mcp.config.OAuthProxyService;
import com.okta.mcp.config.OAuthProxyService.PendingCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.net.URI;
import java.util.Map;

/**
 * OAuth 2.0 Proxy — Authorization and Token endpoints.
 *
 * This is the heart of the "proxy AS" pattern that solves VS Code's random loopback port problem.
 *
 * Problem recap:
 *   VS Code starts a local HTTP server on a random port (e.g. 54321) and uses it as redirect_uri.
 *   Okta Custom AS requires exact redirect_uri match — random ports can't be pre-registered.
 *
 * Solution:
 *   This controller intercepts VS Code's PKCE flow and replaces the random redirect_uri with our
 *   fixed URI (http://127.0.0.1:8080/oauth2/callback), then relays everything through.
 *
 * Full VS Code flow:
 *   1. VS Code reads /.well-known/oauth-protected-resource → authorization_servers=[http://127.0.0.1:8080]
 *   2. VS Code reads /.well-known/oauth-authorization-server → our proxy endpoints
 *   3. VS Code calls POST /oauth2/register → gets back client_id=<okta-spa-client-id>
 *   4. VS Code opens browser: GET /oauth2/authorize?redirect_uri=http://127.0.0.1:54321/callback&state=...
 *   5. THIS controller stores state→54321, 302s to Okta's real /authorize with fixed redirect_uri
 *   6. User logs in → Okta → GET /oauth2/callback?code=...&state=...
 *   7. OAuthCallbackController looks up state → 302 to http://127.0.0.1:54321/callback?code=...
 *   8. VS Code's local server receives code, calls POST /oauth2/token
 *   9. THIS controller proxies token request to Okta with corrected redirect_uri
 *  10. VS Code receives real Okta access token, sends it as Bearer on all MCP requests ✅
 */
@RestController
public class OAuthProxyController {

    private static final Logger log = LoggerFactory.getLogger(OAuthProxyController.class);

    @Autowired
    private OAuthProxyService proxyService;

    /** Base URL of this MCP server — used as the fixed redirect_uri sent to Okta. */
    @Value("${okta.server.base-url:http://127.0.0.1:8080}")
    private String serverBaseUrl;

    /** Issuer URI of the real Okta AS — used to derive authorize + token endpoint URLs. */
    @Value("${okta.auth.issuer-uri}")
    private String oktaIssuerUri;

    /**
     * Proxy Authorization Endpoint.
     *
     * VS Code sends its random-port redirect_uri here. We:
     *   1. Parse the random port from VS Code's redirect_uri
     *   2. Store state → port mapping (so /oauth2/callback can relay back)
     *   3. 302 redirect to Okta's real authorize endpoint with our fixed redirect_uri
     *   4. Drop the `resource` param — Okta Custom AS rejects it (causes policy failure)
     */
    @GetMapping({"/oauth2/authorize", "/authorize"})
    public ResponseEntity<Void> authorize(
            @RequestParam("client_id")             String clientId,
            @RequestParam("redirect_uri")          String redirectUri,    // VS Code's random port
            @RequestParam("state")                 String state,
            @RequestParam("code_challenge")        String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            @RequestParam(value = "scope",    defaultValue = "openid profile email") String scope,
            @RequestParam(value = "response_type", defaultValue = "code") String responseType,
            @RequestParam(value = "resource",      required = false) String resource) {

        // Parse VS Code's random port + callback path from the redirect_uri.
        // VS Code sends redirect_uri=http://127.0.0.1:33418 (no path) or with trailing "/".
        // URI.getPath() returns "" for no-path URIs — relay to "/" (VS Code listens at root).
        URI vsCodeRedirectUri = URI.create(redirectUri);
        int port = vsCodeRedirectUri.getPort();
        String path = vsCodeRedirectUri.getPath();
        if (path == null || path.isEmpty()) path = "/";

        if (port < 1024 || port > 65535) {
            log.warn("[OAuthProxy] Rejected invalid port={} from redirect_uri={}", port, redirectUri);
            return ResponseEntity.badRequest().build();
        }

        // Store state → VS Code's random port so OAuthCallbackController can relay
        proxyService.register(state, port, path);

        // Build the real Okta authorize URL with our fixed redirect_uri
        String ourCallbackUri = serverBaseUrl + "/oauth2/callback";
        String oktaAuthorizeEp = oktaIssuerUri + "/v1/authorize";

        String oktaAuthorizeUrl = oktaAuthorizeEp
                + "?response_type="         + encode(responseType)
                + "&client_id="             + encode(clientId)
                + "&redirect_uri="          + encode(ourCallbackUri)
                + "&scope="                 + encode(scope)
                + "&state="                 + encode(state)
                + "&code_challenge="        + encode(codeChallenge)
                + "&code_challenge_method=" + encode(codeChallengeMethod);

        // Pass through the resource parameter if provided — Okta Custom AS may use it
        // to bind the aud claim in the issued token.  VS Code sends it so that the
        // token audience matches the MCP resource URI.
        // NOTE: if your Okta Custom AS rejects the resource param, you can remove this.
        if (resource != null && !resource.isBlank()) {
            oktaAuthorizeUrl += "&resource=" + encode(resource);
            log.info("[OAuthProxy] Authorize: passing resource={} to Okta", resource);
        }

        log.info("[OAuthProxy] Authorize: port={} state={} → relaying to Okta", port, state);
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(oktaAuthorizeUrl))
                .build();
    }

    /**
     * Proxy Token Endpoint.
     *
     * VS Code sends the authorization code + PKCE verifier here.
     * We substitute the redirect_uri with our fixed URI (Okta requires it to match what
     * was used in the authorize request) and proxy the request to Okta's token endpoint.
     * The real Okta access token is returned directly to VS Code.
     */
    @PostMapping(value = {"/oauth2/token", "/token"},
                 consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<String> token(
            @RequestParam MultiValueMap<String, String> body) {

        // Replace VS Code's random redirect_uri with our fixed one
        MultiValueMap<String, String> proxiedBody = new LinkedMultiValueMap<>(body);
        proxiedBody.set("redirect_uri", serverBaseUrl + "/oauth2/callback");

        String code = body.getFirst("code");
        log.info("[OAuthProxy] Token: code={} → proxying to Okta", code != null ? code.substring(0, 8) + "..." : "null");

        String oktaTokenEp = oktaIssuerUri + "/v1/token";

        try {
            ResponseEntity<String> oktaResponse = RestClient.create()
                    .post()
                    .uri(URI.create(oktaTokenEp))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(proxiedBody)
                    .retrieve()
                    .onStatus(status -> status.isError(), (req, resp) -> {
                        // Don't throw — let us read the body and relay the error to VS Code
                    })
                    .toEntity(String.class);

            log.info("[OAuthProxy] Token: Okta responded with status={}", oktaResponse.getStatusCode());

            // Log partial token response body for diagnostics (helps diagnose aud / iss mismatch)
            String responseBody = oktaResponse.getBody();
            if (responseBody != null && log.isDebugEnabled()) {
                log.debug("[OAuthProxy] Token response body (first 300 chars): {}",
                        responseBody.length() > 300 ? responseBody.substring(0, 300) + "…" : responseBody);
            } else if (responseBody != null) {
                // Always log enough to see token_type and whether access_token is present
                int atIdx = responseBody.indexOf("access_token");
                log.info("[OAuthProxy] Token response: access_token={}, token_type={}",
                        atIdx >= 0 ? "present" : "MISSING",
                        responseBody.contains("Bearer") ? "Bearer" : responseBody.contains("bearer") ? "bearer" : "?");
            }

            return ResponseEntity.status(oktaResponse.getStatusCode())
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(responseBody);
        } catch (Exception e) {
            log.error("[OAuthProxy] Token proxy failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("{\"error\":\"proxy_error\",\"error_description\":\"" + e.getMessage() + "\"}");
        }
    }

    private static String encode(String value) {
        try {
            return java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }
}
