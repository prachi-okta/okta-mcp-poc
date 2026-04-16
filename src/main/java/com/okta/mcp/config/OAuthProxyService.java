package com.okta.mcp.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared state store for the OAuth proxy flow.
 *
 * When VS Code calls GET /oauth2/authorize, the proxy controller stores the
 * VS Code's random redirect_uri (port + path) keyed by the OAuth state parameter.
 * When Okta redirects back to /oauth2/callback, OAuthCallbackController looks up
 * the state here and relays the auth code to the correct random port.
 *
 * Also used by /oauth2/callback/init for the browser SPA flow.
 */
@Component
public class OAuthProxyService {

    private static final Logger log = LoggerFactory.getLogger(OAuthProxyService.class);

    static final long STATE_TTL_MS = 5 * 60 * 1000; // 5 minutes

    private final Map<String, PendingCallback> pendingCallbacks = new ConcurrentHashMap<>();

    /**
     * Register a pending callback. Called either by:
     *   - OAuthProxyController.authorize()  (VS Code PKCE flow — random port from redirect_uri)
     *   - OAuthCallbackController.init()    (browser SPA flow — explicit /init call)
     */
    public void register(String state, int localPort, String callbackPath) {
        evictExpired();
        pendingCallbacks.put(state, new PendingCallback(localPort, callbackPath, System.currentTimeMillis()));
        log.info("[OAuthProxy] Registered state={} → 127.0.0.1:{}{}", state, localPort, callbackPath);
    }

    /**
     * Consume a pending callback. Returns null if the state is unknown or expired.
     * Single-use — entry is removed on first call.
     */
    public PendingCallback consume(String state) {
        PendingCallback cb = pendingCallbacks.remove(state);
        if (cb == null) {
            log.warn("[OAuthProxy] Unknown state={}", state);
            return null;
        }
        if (System.currentTimeMillis() - cb.createdAt() > STATE_TTL_MS) {
            log.warn("[OAuthProxy] Expired state={} (age={}ms)", state,
                    System.currentTimeMillis() - cb.createdAt());
            return null;
        }
        return cb;
    }

    /** Lazily evict stale entries to keep the map bounded. */
    private void evictExpired() {
        long now = System.currentTimeMillis();
        pendingCallbacks.entrySet().removeIf(e -> now - e.getValue().createdAt() > STATE_TTL_MS);
    }

    /** Immutable holder for a pending callback registration. */
    public record PendingCallback(int localPort, String callbackPath, long createdAt) {}
}
