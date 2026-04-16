package com.okta.mcp.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Injects the "mcp-session-id" HTTP response header for the initialize handshake.
 *
 * SseEmitter doesn't expose access to the underlying HttpServletResponse headers, so
 * the controller stores the new session ID in a ThreadLocal and this interceptor
 * writes it as an HTTP response header before the response is committed.
 *
 * VS Code reads mcp-session-id from the HTTP response header (not the SSE event id)
 * to track the session for all subsequent requests.
 */
@Component
public class McpSessionHeaderInterceptor implements HandlerInterceptor {

    public static final ThreadLocal<String> PENDING_SESSION_ID = new ThreadLocal<>();

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        PENDING_SESSION_ID.remove();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,
                             Object handler) {
        // No-op here; the controller sets PENDING_SESSION_ID after creating the session.
        // We write the header in postHandle, before the response is committed.
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response,
                           Object handler,
                           org.springframework.web.servlet.ModelAndView modelAndView) {
        String sessionId = PENDING_SESSION_ID.get();
        if (sessionId != null && !response.isCommitted()) {
            response.setHeader("mcp-session-id", sessionId);
        }
    }
}
