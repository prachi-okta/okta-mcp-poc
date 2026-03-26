package com.okta.mcp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security configuration for the MCP HTTP transport.
 *
 * Validates Okta-issued JWT access tokens on every MCP request (except the
 * public /.well-known discovery endpoint). Token validation is fully stateless
 * — the JWT signature and claims are verified on each request using Okta's
 * JWKS endpoint auto-discovered from the configured issuer URI.
 *
 * Auth flow (MCP spec 2025-03-26, Resource Server pattern):
 *   1. MCP client hits GET /.well-known/oauth-authorization-server (public)
 *      → receives Okta endpoint URLs (authorize, token, keys)
 *   2. MCP client performs PKCE Authorization Code flow directly with Okta
 *      → receives Okta-signed JWT access token
 *   3. MCP client sends Authorization: Bearer <jwt> on every POST /mcp request
 *   4. Spring Security validates JWT signature + claims here (stateless)
 *   5. Tool methods execute using the server's own Okta service account
 *
 * The server never issues its own tokens — it is purely a resource server.
 * Okta is the Authorization Server.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
    private String issuerUri;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // MCP clients do not send CSRF tokens
                .csrf(AbstractHttpConfigurer::disable)

                // Stateless — JWT re-validated on every request; no server-side session
                .sessionManagement(sm ->
                        sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(authz -> authz
                        // RFC 8414 discovery endpoint must be public.
                        // Clients need it to find out WHERE to get a token — before they have one.
                        .requestMatchers("/.well-known/**").permitAll()

                        // Every MCP request (POST /mcp, GET /mcp, DELETE /mcp)
                        // requires a valid Okta JWT.
                        .anyRequest().authenticated()
                )

                // Validate Bearer tokens as JWTs signed by Okta.
                // Spring Security auto-fetches JWKS from {issuer-uri}/v1/keys
                // and caches public keys. No manual key management needed.
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));

        return http.build();
    }
}
