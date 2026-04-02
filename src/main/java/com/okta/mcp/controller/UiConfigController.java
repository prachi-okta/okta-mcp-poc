package com.okta.mcp.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Exposes a small public JSON config blob that the browser SPA needs to
 * bootstrap the PKCE Authorization Code flow with Okta.
 *
 * GET /api/ui-config → { issuerUri, clientId, scopes, demoMode }
 *
 * This endpoint is explicitly permitted in SecurityConfig (no Bearer token
 * required) so the page can fetch it before the user has signed in.
 */
@RestController
@RequestMapping("/api")
public class UiConfigController {

    @Value("${okta.auth.issuer-uri}")
    private String issuerUri;

    @Value("${okta.ui.clientId:}")
    private String clientId;

    @Value("${okta.ui.scopes:openid profile email}")
    private String scopes;

    @GetMapping(value = "/ui-config", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> uiConfig() {
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "*")
                .body(Map.of(
                        "issuerUri", issuerUri,
                        "clientId",  clientId,
                        "scopes",    scopes
                ));
    }
}
