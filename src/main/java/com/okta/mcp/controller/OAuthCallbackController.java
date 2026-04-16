package com.okta.mcp.controller;

import com.okta.mcp.config.OAuthProxyService;
import com.okta.mcp.config.OAuthProxyService.PendingCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Option 1 POC — Proxy Callback (POC Acceptance Criteria #1).
 *
 * Solves the "random loopback port" problem for desktop MCP clients (VS Code, Claude Desktop).
 *
 * Problem:
 *   Desktop clients pick a random ephemeral port (e.g. 54321) as redirect_uri on every PKCE
 *   flow. Okta Custom AS requires exact redirect_uri match — you can't pre-register a random
 *   port. RFC 8252 §7.3 says the AS MUST allow any port for loopback redirects, but Okta
 *   Custom AS does not implement this.
 *
 * Solution:
 *   Register ONE fixed URI in the customer's Okta org (prachi.oktapreview.com):
 *     http://127.0.0.1:8080/oauth2/callback   ← POC (MCP server running locally)
 *     https://mcp.okta.com/oauth2/callback     ← production (when/if MCP server is hosted)
 *   The MCP client redirects to this fixed URI. This controller receives the auth code
 *   from Okta, looks up the client's actual random local port (stored by the client in
 *   the 'state' parameter before redirecting), and relays the code back to the client.
 *
 *   Note: okta-mcp-server.oktapreview.com is Org 2 used ONLY for Option 2 XAA.
 *   It has nothing to do with the Option 1 redirect URI.
 *
 * Flow:
 *   1. VS Code generates PKCE params + random port 54321
 *   2. VS Code calls /oauth2/callback/init?localPort=54321 → gets back a state token
 *   3. VS Code sends GET /authorize?redirect_uri=https://.../oauth2/callback&state=<token>
 *   4. User logs in → Okta redirects to https://.../oauth2/callback?code=...&state=<token>
 *   5. THIS controller looks up state → localPort 54321 → 302 to http://127.0.0.1:54321/...
 *   6. VS Code's local HTTP server receives the code and completes PKCE exchange with Okta
 *
 * Security note:
 *   - state tokens are single-use and expire after STATE_TTL_MS
 *   - relay only ever goes to 127.0.0.1 (loopback) — never an external URL
 *   - state map is in-memory (per-instance); for multi-node prod, use a short-lived KV store
 */
@RestController
public class OAuthCallbackController {

    private static final Logger log = LoggerFactory.getLogger(OAuthCallbackController.class);

    @Autowired
    private OAuthProxyService proxyService;

    /**
     * Called by the MCP client BEFORE starting the PKCE /authorize redirect.
     * The client registers its random local port here and gets back a state token
     * to include in the /authorize request.
     *
     * POST /oauth2/callback/init?localPort=54321
     * Response: { "state": "<opaque-token>" }
     */
    @GetMapping("/oauth2/callback/init")
    public ResponseEntity<Map<String, String>> init(@RequestParam("localPort") int localPort,
                                                    @RequestParam(value = "callbackPath",
                                                                  defaultValue = "/oauth2/callback") String callbackPath) {
        if (localPort < 1024 || localPort > 65535) {
            log.warn("[OAuth Callback] Rejected invalid localPort={}", localPort);
            return ResponseEntity.badRequest().body(Map.of("error", "invalid localPort"));
        }

        String state = java.util.UUID.randomUUID().toString();
        proxyService.register(state, localPort, callbackPath);
        return ResponseEntity.ok(Map.of("state", state));
    }

    /**
     * Okta redirects here after the user logs in.
     * This relay sends the auth code back to the client's random local port.
     *
     * GET /oauth2/callback?code=...&state=...
     */
    @GetMapping("/oauth2/callback")
    public ResponseEntity<Void> callback(@RequestParam(value = "code", required = false) String code,
                                         @RequestParam(value = "error", required = false) String error,
                                         @RequestParam(value = "error_description", required = false) String errorDesc,
                                         @RequestParam("state") String state) {

        PendingCallback pending = proxyService.consume(state);

        if (pending == null) {
            log.warn("[OAuth Callback] Unknown or expired state={}", state);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        if (error != null) {
            log.warn("[OAuth Callback] Okta returned error={} desc={} for state={}", error, errorDesc, state);
            // Relay error to client so it can surface it to the user
            String relayUrl = "http://127.0.0.1:" + pending.localPort() + pending.callbackPath()
                    + "?error=" + encode(error)
                    + (errorDesc != null ? "&error_description=" + encode(errorDesc) : "")
                    + "&state=" + encode(state);
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(relayUrl))
                    .build();
        }

        // Relay auth code back to VS Code's local HTTP server.
        // URL-encode code + state so that characters like '+' and '=' in the state
        // are not misinterpreted ('+' would be decoded as space by VS Code's HTTP server,
        // causing the PKCE state check to fail and VS Code to open the browser a second time).
        String relayUrl = "http://127.0.0.1:" + pending.localPort() + pending.callbackPath()
                + "?code=" + encode(code)
                + "&state=" + encode(state);

        log.info("[OAuth Callback] Relaying code to 127.0.0.1:{}{} (state={})",
                pending.localPort(), pending.callbackPath(), state);
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create(relayUrl))
                .build();
    }

    private static String encode(String value) {
        if (value == null) return "";
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

}

