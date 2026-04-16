package com.okta.mcp.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;

/**
 * Spring Security configuration for the MCP HTTP transport.
 *
 * Validates Okta-issued JWT access tokens on every MCP request (except public endpoints).
 * Token validation is fully stateless — JWT signature and claims are verified on each
 * request using Okta's JWKS endpoint auto-discovered from the configured issuer URI.
 *
 * The MCP server is a pure resource server. Auth flow:
 *   1. MCP client hits /sse → 401 + WWW-Authenticate: Bearer resource_metadata="..."
 *   2. Client fetches /.well-known/oauth-protected-resource → gets Okta AS URL
 *   3. Client talks directly to Okta for discovery, PKCE, and token exchange
 *   4. Client sends Authorization: Bearer <jwt> on every /sse and /mcp request
 *   5. Spring Security validates JWT signature + claims here (stateless)
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    /** Canonical URI of this MCP server — used in WWW-Authenticate resource_metadata URL (RFC 9728). */
    @Value("${okta.resource.uri}")
    private String resourceUri;

    /**
     * Base URL of this MCP server (scheme://host:port) — used in WWW-Authenticate so the
     * resource_metadata URL always matches the host:port VS Code actually connects to.
     * Must be 127.0.0.1 (not localhost) to match VS Code's loopback handling.
     */
    @Value("${okta.server.base-url:http://127.0.0.1:8080}")
    private String serverBaseUrl;

    /**
     * Option 1 POC criteria #2 — toggle audience validation.
     * Set to false if Okta Custom AS does not bind aud to the resource param yet.
     * Once Okta claim policy is configured, flip to true (default: false during POC).
     */
    @Value("${okta.resource.uri.audience.validate:false}")
    private boolean audienceValidationEnabled;

    /** Scopes surfaced in WWW-Authenticate scope parameter (MCP spec §4.2). */
    @Value("${okta.ui.scopes:openid profile email}")
    private String uiScopes;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        log.info("[OIDC] Configuring JWT resource server — issuer: {}", issuerUri);
        log.info("[OIDC] Public  : GET /.well-known/**, /, /index.html, /api/ui-config, /error");
        log.info("[OIDC] Protected: ALL other endpoints require Authorization: Bearer <okta-jwt>");

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authz -> authz
                        // Public: OIDC discovery
                        .requestMatchers("/.well-known/**").permitAll()
                        // Public: browser SPA — static assets and PKCE config API
                        .requestMatchers("/", "/index.html", "/favicon.ico").permitAll()
                        .requestMatchers("/api/ui-config").permitAll()
                        // Public: OAuth proxy AS endpoints — VS Code PKCE flow
                        // /oauth2/authorize  — proxy authorize (stores VS Code's random port, relays to Okta)
                        // /oauth2/token      — proxy token exchange (relays to Okta with fixed redirect_uri)
                        // /oauth2/register   — dynamic client registration (returns Okta SPA client_id)
                        // /oauth2/callback   — Okta redirects here; relays code to VS Code's random port
                        // /oauth2/callback/init — browser SPA flow: explicit port registration
                        .requestMatchers("/oauth2/authorize", "/oauth2/token", "/oauth2/register",
                                         "/oauth2/callback", "/oauth2/callback/init",
                                         "/authorize", "/token", "/register").permitAll()
                        // GET /sse opens the SSE push stream after an authenticated initialize.
                        // VS Code opens it without a Bearer token (browser EventSource-style).
                        // The session ID — only issued after JWT-validated initialize — is the credential.
                        .requestMatchers(HttpMethod.GET, "/sse").permitAll()
                        // Public: Option 2 POC — token exchange test endpoint (POC criteria #1–4)
                        .requestMatchers("/poc/**").permitAll()
                        // Public: Spring Boot error endpoint (must be accessible without a token
                        //         so that error responses are not swallowed by a 401 loop)
                        .requestMatchers("/error").permitAll()
                        // Everything else requires a valid Okta JWT
                        .anyRequest().authenticated()
                )

                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(loggingEntryPoint())
                        .accessDeniedHandler(loggingAccessDeniedHandler())
                )

                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .decoder(jwtDecoder())
                                .jwtAuthenticationConverter(token -> {
                                    // Must pass an authorities collection so Authenticated=true
                                    JwtAuthenticationToken auth = new JwtAuthenticationToken(
                                            token, java.util.Collections.emptyList());
                                    log.info("[OIDC] ✅ JWT valid — sub={}, aud={}, scopes={}, exp={}",
                                            token.getSubject(),
                                            token.getAudience(),
                                            token.getClaimAsStringList("scp"),
                                            token.getExpiresAt());
                                    return auth;
                                })
                        )
                );

        return http.build();
    }

    /**
     * Option 1 POC criteria #2 — Audience validation.
     *
     * Builds a JwtDecoder that validates:
     *   1. JWT signature + issuer (standard Spring Security behaviour)
     *   2. aud claim contains the MCP server's resource URI
     *      (set by Okta when client sends resource=<resourceUri> in authorize + token requests)
     *
     * If Okta Custom AS does not bind aud to the resource parameter, the token will be
     * rejected here with a clear log message — making the failure immediately visible.
     *
     * Set okta.resource.uri.audience.validate=false to disable audience check while
     * investigating Okta Custom AS claim policy configuration.
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuerUri);

        // Compose: standard issuer validator + audience validator
        OAuth2TokenValidator<Jwt> defaultValidators = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> audienceValidator = token -> {
            if (!audienceValidationEnabled) {
                log.debug("[OIDC] Audience validation disabled — skipping aud check");
                return OAuth2TokenValidatorResult.success();
            }
            java.util.List<String> aud = token.getAudience();
            if (aud != null && !aud.isEmpty() && aud.contains(resourceUri)) {
                log.debug("[OIDC] aud claim valid — contains resourceUri={}", resourceUri);
                return OAuth2TokenValidatorResult.success();
            }
            // Also accept if aud is missing entirely (Okta may not set it without resource param)
            if (aud == null || aud.isEmpty()) {
                log.warn("[OIDC] ⚠️  JWT has no aud claim — Okta may not be binding aud to resource param. "
                        + "Set okta.resource.uri.audience.validate=false to suppress this warning.");
                return OAuth2TokenValidatorResult.success();
            }
            log.error("[OIDC] ❌ JWT aud={} does not contain resourceUri={} — rejecting token. "
                    + "Check Okta Custom AS claim policy or set okta.resource.uri.audience.validate=false.",
                    aud, resourceUri);
            return OAuth2TokenValidatorResult.failure(
                    new org.springframework.security.oauth2.core.OAuth2Error(
                            "invalid_token",
                            "JWT aud claim does not contain the MCP server resource URI",
                            null));
        };

        decoder.setJwtValidator(
                new org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator<>(
                        defaultValidators, audienceValidator));
        return decoder;
    }

    /**
     * CORS configuration — required because VS Code sends sec-fetch-mode=cors on POST /sse.
     * Without Access-Control-Expose-Headers the browser security layer silently strips the
     * mcp-session-id response header, so VS Code never gets the session ID after initialize
     * and cannot proceed to notifications/initialized or tools/list.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        // Accept any origin (including VS Code WebView's null origin)
        config.addAllowedOriginPattern("*");
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        // Expose mcp-session-id so VS Code can read it from the initialize response
        config.addExposedHeader("mcp-session-id");
        config.addExposedHeader("Mcp-Session-Id");
        config.setAllowCredentials(false);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        log.info("[CORS] Configured: Access-Control-Expose-Headers: mcp-session-id");
        return source;
    }

    /**
     * Builds the resource_metadata URL for the WWW-Authenticate header.
     * Uses serverBaseUrl (127.0.0.1) — not resourceUri (localhost) — so VS Code can
     * correlate the metadata URL to the same host:port it connected to.
     * Mixing localhost/127.0.0.1 causes VS Code to restart the auth loop.
     */
    private String resourceMetadataUrl() {
        return serverBaseUrl + "/.well-known/oauth-protected-resource";
    }

    /**
     * Logs every request that is rejected due to missing / invalid token (401).
     *
     * Per MCP spec (draft) §4.2 and RFC 9728 §5.1, the WWW-Authenticate header MUST include:
     *   resource_metadata — URL of this server's Protected Resource Metadata document
     *   scope             — scopes required to access this resource (guides client scope selection)
     */
    private AuthenticationEntryPoint loggingEntryPoint() {
        return (HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) -> {
            log.warn("[OIDC] ❌ 401 Unauthorized — {} {} — reason: {}",
                    req.getMethod(), req.getRequestURI(), ex.getMessage());
            String wwwAuth = "Bearer" +
                    " resource_metadata=\"" + resourceMetadataUrl() + "\"" +
                    ", scope=\"" + uiScopes + "\"";
            res.setHeader("WWW-Authenticate", wwwAuth);
            log.info("[OIDC] WWW-Authenticate: {}", wwwAuth);
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Bearer token required");
        };
    }

    /**
     * Logs every request that has a valid token but insufficient scope/role (403).
     *
     * Per MCP spec §11.1.1 / RFC 6750 §3.1, the WWW-Authenticate header on 403 MUST include
     * error="insufficient_scope" and the required scopes so clients can initiate step-up auth.
     */
    private AccessDeniedHandler loggingAccessDeniedHandler() {
        return (HttpServletRequest req, HttpServletResponse res, AccessDeniedException ex) -> {
            log.warn("[OIDC] ❌ 403 Forbidden — {} {} — reason: {}",
                    req.getMethod(), req.getRequestURI(), ex.getMessage());
            res.setHeader("WWW-Authenticate",
                    "Bearer error=\"insufficient_scope\"" +
                    ", scope=\"" + uiScopes + "\"" +
                    ", resource_metadata=\"" + resourceMetadataUrl() + "\"");
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "Insufficient scope");
        };
    }
}
