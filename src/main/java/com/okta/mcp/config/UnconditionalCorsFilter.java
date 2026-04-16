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

/**
 * Unconditionally adds CORS headers to every response.
 *
 * Spring's CorsFilter (and Spring Security's cors() config) only add
 * Access-Control-* headers when the request has an "Origin" header.
 *
 * VS Code's MCP client runs in Electron's Chromium renderer. It uses the
 * browser Fetch API with sec-fetch-mode=cors but sends NO Origin header
 * (Chromium treats the VS Code extension context as a null/opaque origin
 * and omits the Origin header). Without an Origin header, Spring CorsFilter
 * is a no-op — so no Access-Control-Allow-Origin goes out.
 *
 * Chromium enforces CORS on the CLIENT side: if the response doesn't include
 * Access-Control-Allow-Origin, Chromium blocks JavaScript from reading ANY
 * response header — including mcp-session-id. VS Code never gets the session
 * ID, considers auth failed, and restarts the auth loop.
 *
 * Fix: add Access-Control-Allow-Origin: * and expose mcp-session-id
 * unconditionally, before Spring Security and before our handlers run.
 */
@Component
@Order(-300)   // before Spring Security (-100) and before RequestDiagnosticsFilter (-200)
public class UnconditionalCorsFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(UnconditionalCorsFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Always allow any origin — needed for VS Code's null/opaque origin
        response.setHeader("Access-Control-Allow-Origin", "*");
        // VS Code must be able to read mcp-session-id from the initialize response
        response.setHeader("Access-Control-Expose-Headers", "mcp-session-id, Mcp-Session-Id");
        response.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        response.setHeader("Access-Control-Allow-Headers",
                "Authorization, Content-Type, Accept, mcp-session-id, mcp-protocol-version");

        // Respond immediately to preflight OPTIONS requests
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            response.setContentLength(0);
            log.debug("[CORS] Preflight OPTIONS {} → 200", request.getRequestURI());
            return;
        }

        chain.doFilter(request, response);
    }
}
