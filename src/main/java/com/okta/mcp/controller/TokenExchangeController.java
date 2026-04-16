package com.okta.mcp.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import java.util.Map;

/**
 * Option 2 POC — Cross-Org XAA Token Exchange (POC Acceptance Criteria #1).
 *
 * Accepts a subject token from Org 1 (prachi.oktapreview.com) and exchanges it
 * for an MCP-scoped token from Org 2 (okta-mcp-server.oktapreview.com) using
 * RFC 8693 Token Exchange grant type.
 *
 * This endpoint is for POC testing only — in production the customer's application
 * performs this exchange directly against Org 2's token endpoint.
 *
 * Request:
 *   POST /poc/token-exchange
 *   Content-Type: application/json
 *   {
 *     "subject_token": "<access token from prachi.oktapreview.com>",
 *     "actor_token":   "<user token from prachi.oktapreview.com>"  // optional, for POC criteria #4
 *   }
 *
 * Response (success):
 *   {
 *     "access_token": "<XAA token from okta-mcp-server.oktapreview.com>",
 *     "token_type":   "Bearer",
 *     "expires_in":   3600
 *   }
 *
 * What this tests (per POC Acceptance Criteria):
 *   #1 — cross-org token exchange returns a valid JWT (aud = "Okta Hosted MCP" client ID)
 *   #4 — when actor_token is supplied, the returned JWT should carry an `act.sub` claim
 *
 * If Okta XAA does not support cross-org token-exchange, this will return Okta's error
 * response verbatim so the failure reason is clearly visible.
 */
@RestController
public class TokenExchangeController {

    private static final Logger log = LoggerFactory.getLogger(TokenExchangeController.class);

    private static final String TOKEN_EXCHANGE_GRANT =
            "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final String ACCESS_TOKEN_TYPE =
            "urn:ietf:params:oauth:token-type:access_token";

    /**
     * Token endpoint of Org 2 (okta-mcp-server.oktapreview.com).
     * Exchange requests go here — Org 2 validates the XAA grant and issues the MCP token.
     */
    @Value("${okta.xaa.token-endpoint:https://okta-mcp-server.oktapreview.com/oauth2/default/v1/token}")
    private String xaaTokenEndpoint;

    /**
     * Client ID of the "Okta Hosted MCP" app in Org 2.
     * Used as the `audience` in the exchange request and as the expected `aud` in the result.
     */
    @Value("${okta.xaa.client-id:}")
    private String xaaClientId;

    /**
     * Client secret of the "Okta Hosted MCP" app in Org 2.
     * For an API Services app this is typically a client secret or private key JWT.
     * POC uses client_secret_basic for simplicity; swap to private_key_jwt for production.
     */
    @Value("${okta.xaa.client-secret:}")
    private String xaaClientSecret;

    private final RestClient restClient = RestClient.create();

    @PostMapping("/poc/token-exchange")
    public ResponseEntity<Map> exchange(@RequestBody Map<String, String> request) {

        String subjectToken = request.get("subject_token");
        String actorToken   = request.get("actor_token"); // optional — POC criteria #4

        if (subjectToken == null || subjectToken.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "subject_token is required"));
        }

        log.info("[XAA] Starting cross-org token exchange → {}", xaaTokenEndpoint);
        log.info("[XAA] subject_token present=true, actor_token present={}", actorToken != null);

        MultiValueMap<String, String> formParams = new LinkedMultiValueMap<>();
        formParams.add("grant_type",             TOKEN_EXCHANGE_GRANT);
        formParams.add("subject_token",           subjectToken);
        formParams.add("subject_token_type",      ACCESS_TOKEN_TYPE);
        formParams.add("requested_token_type",    ACCESS_TOKEN_TYPE);
        formParams.add("audience",                xaaClientId);

        // POC criteria #4: include actor_token to propagate per-user identity (RFC 8693 §2.1)
        if (actorToken != null && !actorToken.isBlank()) {
            formParams.add("actor_token",       actorToken);
            formParams.add("actor_token_type",  ACCESS_TOKEN_TYPE);
            log.info("[XAA] actor_token included — testing per-user identity propagation (RFC 8693 §2.1)");
        }

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        // Basic auth with Org 2 client credentials
        headers.setBasicAuth(xaaClientId, xaaClientSecret);

        try {
            ResponseEntity<Map> response = restClient.post()
                    .uri(xaaTokenEndpoint)
                    .headers(h -> h.addAll(headers))
                    .body(new HttpEntity<>(formParams, headers).getBody())
                    .retrieve()
                    .toEntity(Map.class);

            log.info("[XAA] Token exchange response status={}", response.getStatusCode());

            if (response.getBody() != null && response.getBody().containsKey("access_token")) {
                log.info("[XAA] ✅ Token exchange succeeded — access_token present");
                // Log aud claim for POC criteria #1 verification
                String accessToken = (String) response.getBody().get("access_token");
                logJwtClaims(accessToken);
            }

            return ResponseEntity.status(response.getStatusCode()).body(response.getBody());

        } catch (Exception e) {
            log.error("[XAA] ❌ Token exchange failed: {}", e.getMessage());
            return ResponseEntity.status(500)
                    .body(Map.of("error", "token_exchange_failed", "error_description", e.getMessage()));
        }
    }

    /**
     * Logs key JWT claims from the base64-decoded payload for POC verification.
     * Specifically checks `aud` (criteria #1) and `act.sub` (criteria #4).
     */
    private void logJwtClaims(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length < 2) return;
            byte[] payloadBytes = java.util.Base64.getUrlDecoder()
                    .decode(parts[1] + "==".substring(parts[1].length() % 3 == 0 ? 2 : parts[1].length() % 3 == 2 ? 1 : 0));
            String payload = new String(payloadBytes);
            log.info("[XAA] JWT claims: {}", payload);
        } catch (Exception e) {
            log.debug("[XAA] Could not decode JWT claims for logging: {}", e.getMessage());
        }
    }
}
