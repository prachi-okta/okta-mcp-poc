package com.okta.mcp.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Enumeration;

/**
 * Diagnostic filter — logs Authorization header presence for every MCP/SSE/token request.
 *
 * This filter runs BEFORE Spring Security so it captures the raw request headers exactly
 * as VS Code sends them. The output answers the key question:
 *   "Is VS Code including Authorization: Bearer <token> on the retry after PKCE auth?"
 *
 * Only logs for the endpoints we care about: /sse, /mcp, /token, /.well-known/
 * Remove or set to TRACE level once the auth loop is fixed.
 */
@Component
@Order(-200)   // must be lower than Spring Security's -100 to run before it
public class RequestDiagnosticsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestDiagnosticsFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String uri = request.getRequestURI();

        // Only log for MCP-relevant endpoints — skip static assets, actuator, etc.
        if (isInteresting(uri)) {
            String authHeader = request.getHeader("Authorization");
            String origin     = request.getHeader("Origin");
            String contentType = request.getHeader("Content-Type");

            if (authHeader != null) {
                // Mask the token — log only first 20 chars
                String masked = authHeader.length() > 27
                        ? authHeader.substring(0, 27) + "…"
                        : authHeader;
                String sessionId = request.getHeader("mcp-session-id");
                log.info("[Diag] ✅ {} {} — Authorization: {} | session: {} | Origin: {} | CT: {}",
                        request.getMethod(), uri, masked,
                        sessionId != null ? sessionId.substring(0, Math.min(8, sessionId.length())) + "…" : "none",
                        origin, contentType);
            } else {
                // No Authorization header — log all headers to help diagnose
                StringBuilder headers = new StringBuilder();
                Enumeration<String> names = request.getHeaderNames();
                while (names != null && names.hasMoreElements()) {
                    String name = names.nextElement();
                    if (!name.equalsIgnoreCase("cookie")) {   // skip noisy cookie header
                        headers.append(name).append("=").append(request.getHeader(name)).append("; ");
                    }
                }
                log.warn("[Diag] ❌ {} {} — NO Authorization header. All headers: {}",
                        request.getMethod(), uri, headers);
            }
        } else {
            // Log EVERY request so we catch VS Code sending to unexpected paths
            String auth2 = request.getHeader("Authorization");
            String sid2 = request.getHeader("mcp-session-id") != null
                    ? request.getHeader("mcp-session-id") : request.getHeader("Mcp-Session-Id");
            log.info("[Diag] {} {} | auth={} | session={}",
                    request.getMethod(), uri,
                    auth2 != null ? "Bearer…" : "none",
                    sid2 != null ? sid2.substring(0, Math.min(8, sid2.length())) + "…" : "none");
        }

        chain.doFilter(request, response);

        // Log response header AFTER processing — confirms Mcp-Session-Id survived the filter chain
        if (isInteresting(uri)) {
            // Check both casings — HTTP headers are case-insensitive but log whichever is set
            String respSessionId = response.getHeader("Mcp-Session-Id");
            if (respSessionId == null) respSessionId = response.getHeader("mcp-session-id");
            log.info("[Diag] Response Mcp-Session-Id for {} {}: {}",
                    request.getMethod(), uri,
                    respSessionId != null ? respSessionId.substring(0, Math.min(8, respSessionId.length())) + "…" : "NOT_SET");
        }
    }

    private boolean isInteresting(String uri) {
        return uri.startsWith("/sse")
                || uri.startsWith("/mcp")
                || uri.startsWith("/token")
                || uri.startsWith("/oauth2")
                || uri.startsWith("/.well-known")
                || uri.startsWith("/authorize");
    }
}
