package com.okta.mcp.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.AuthenticationException;
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
 * Auth flow (MCP spec 2025-03-26 + RFC 9728):
 *   1. MCP client hits /sse → 401 + WWW-Authenticate: Bearer resource_metadata="..."
 *   2. Client fetches /.well-known/oauth-protected-resource → discovers our AS
 *   3. Client fetches /.well-known/oauth-authorization-server → gets proxy endpoints
 *   4. Client calls POST /register → gets pre-registered client_id
 *   5. Client performs PKCE flow through our proxy → Okta issues a signed JWT
 *   6. Client sends Authorization: Bearer <jwt> on every /sse and /mcp request
 *   7. Spring Security validates JWT signature + claims here (stateless)
 *
 * The server never issues its own tokens — it is purely a resource server.
 * Okta is the Authorization Server; our proxy merely fixes the redirect_uri.
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
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authz -> authz
                        // Public: OIDC discovery
                        .requestMatchers("/.well-known/**").permitAll()
                        // Public: browser SPA — static assets and PKCE config API
                        .requestMatchers("/", "/index.html", "/favicon.ico").permitAll()
                        .requestMatchers("/api/ui-config").permitAll()
                        // Public: OAuth proxy endpoints
                        .requestMatchers("/authorize", "/token", "/register", "/oauth2/**").permitAll()
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
                                .jwtAuthenticationConverter(token -> {
                                    // Must pass an authorities collection so Authenticated=true
                                    JwtAuthenticationToken auth = new JwtAuthenticationToken(
                                            token, java.util.Collections.emptyList());
                                    log.info("[OIDC] ✅ JWT valid — sub={}, scopes={}, exp={}",
                                            token.getSubject(),
                                            token.getClaimAsStringList("scp"),
                                            token.getExpiresAt());
                                    return auth;
                                })
                        )
                );

        return http.build();
    }

    /**
     * Derives the origin (scheme://host:port) from resourceUri so the resource_metadata URL
     * is always at the root — e.g. http://localhost:8080/.well-known/oauth-protected-resource
     * even when resourceUri = http://localhost:8080/sse.
     */
    private String resourceMetadataUrl() {
        try {
            java.net.URI uri = new java.net.URI(resourceUri);
            String origin = uri.getScheme() + "://" + uri.getAuthority();
            return origin + "/.well-known/oauth-protected-resource";
        } catch (Exception e) {
            return resourceUri + "/.well-known/oauth-protected-resource";
        }
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
