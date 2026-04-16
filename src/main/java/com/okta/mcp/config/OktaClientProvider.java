package com.okta.mcp.config;

import com.okta.sdk.client.AuthorizationMode;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.api.ApplicationApi;
import com.okta.sdk.resource.api.ApplicationGroupsApi;
import com.okta.sdk.resource.api.ApplicationUsersApi;
import com.okta.sdk.resource.api.GroupApi;
import com.okta.sdk.resource.api.UserApi;
import com.okta.sdk.resource.api.UserLifecycleApi;
import com.okta.sdk.resource.api.UserResourcesApi;
import com.okta.sdk.resource.client.ApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Lazily creates the Okta SDK ApiClient and all domain API instances.
 *
 * The ApiClient is NOT created at Spring startup — it is built on the first
 * actual tool call, mirroring the Python server's get_okta_client() pattern:
 *
 *   Python: client = await get_okta_client(manager)   # called per request
 *   Java:   okta.userApi().listUsers(...)              # built on first call, cached
 *
 * This avoids the SDK making OIDC-discovery / DPoP HTTP calls during Spring
 * context initialization, which crashed the process before the MCP stdio
 * handshake could complete.
 */
@Component
public class OktaClientProvider {

    private static final Logger log = LoggerFactory.getLogger(OktaClientProvider.class);

    @Value("${okta.client.orgUrl}")
    private String orgUrl;

    @Value("${okta.client.clientId:#{null}}")
    private String clientId;

    @Value("${okta.client.privateKey:#{null}}")
    private String privateKey;

    @Value("${okta.client.keyId:#{null}}")
    private String keyId;

    @Value("${okta.client.scopes:okta.users.manage okta.users.read okta.groups.manage okta.groups.read}")
    private String scopes;

    @Value("${okta.client.token:#{null}}")
    private String apiToken;

    // All fields volatile; individual getters use double-checked locking
    private volatile ApiClient           apiClient;
    private volatile UserApi             userApi;
    private volatile UserLifecycleApi    userLifecycleApi;
    private volatile UserResourcesApi    userResourcesApi;
    private volatile GroupApi            groupApi;
    private volatile ApplicationApi      applicationApi;
    private volatile ApplicationGroupsApi applicationGroupsApi;
    private volatile ApplicationUsersApi applicationUsersApi;

    // ── ApiClient ────────────────────────────────────────────────────────────

    public ApiClient apiClient() {
        if (apiClient == null) {
            synchronized (this) {
                if (apiClient == null) {
                    apiClient = build();
                }
            }
        }
        return apiClient;
    }

    private ApiClient build() {
        if (privateKey != null && !privateKey.isBlank()
                && keyId != null && !keyId.isBlank()) {
            log.info("Okta SDK: PRIVATE_KEY auth (client_credentials) clientId={}", clientId);
            return Clients.builder()
                    .setOrgUrl(orgUrl)
                    .setAuthorizationMode(AuthorizationMode.PRIVATE_KEY)
                    .setClientId(clientId)
                    .setPrivateKey(privateKey.replace("\\n", "\n"))
                    .setKid(keyId)
                    .setScopes(Arrays.stream(scopes.split("\\s+")).collect(Collectors.toSet()))
                    .build();
        }
        log.warn("Okta SDK: SSWS token auth (dev fallback). Set OKTA_PRIVATE_KEY+OKTA_KEY_ID for production.");
        return Clients.builder()
                .setOrgUrl(orgUrl)
                .setAuthorizationMode(AuthorizationMode.SSWS)
                .setClientCredentials(() -> apiToken)
                .build();
    }

    // ── API accessors (lazy, thread-safe) ────────────────────────────────────

    public UserApi userApi() {
        if (userApi == null) {
            synchronized (this) {
                if (userApi == null) userApi = new UserApi(apiClient());
            }
        }
        return userApi;
    }

    public UserLifecycleApi userLifecycleApi() {
        if (userLifecycleApi == null) {
            synchronized (this) {
                if (userLifecycleApi == null) userLifecycleApi = new UserLifecycleApi(apiClient());
            }
        }
        return userLifecycleApi;
    }

    public UserResourcesApi userResourcesApi() {
        if (userResourcesApi == null) {
            synchronized (this) {
                if (userResourcesApi == null) userResourcesApi = new UserResourcesApi(apiClient());
            }
        }
        return userResourcesApi;
    }

    public GroupApi groupApi() {
        if (groupApi == null) {
            synchronized (this) {
                if (groupApi == null) groupApi = new GroupApi(apiClient());
            }
        }
        return groupApi;
    }

    public ApplicationApi applicationApi() {
        if (applicationApi == null) {
            synchronized (this) {
                if (applicationApi == null) applicationApi = new ApplicationApi(apiClient());
            }
        }
        return applicationApi;
    }

    public ApplicationGroupsApi applicationGroupsApi() {
        if (applicationGroupsApi == null) {
            synchronized (this) {
                if (applicationGroupsApi == null) applicationGroupsApi = new ApplicationGroupsApi(apiClient());
            }
        }
        return applicationGroupsApi;
    }

    public ApplicationUsersApi applicationUsersApi() {
        if (applicationUsersApi == null) {
            synchronized (this) {
                if (applicationUsersApi == null) applicationUsersApi = new ApplicationUsersApi(apiClient());
            }
        }
        return applicationUsersApi;
    }

    // ── Option 2 POC: per-request org routing (POC criteria #3) ─────────────

    /**
     * Returns an ApiClient pointed at the given orgUrl, using the same SSWS/PKJ credentials
     * configured for this provider.
     *
     * Used by Option 2 (XAA cross-org): the exchanged JWT from okta-mcp-server.oktapreview.com
     * carries a custom claim `customer_org` containing the customer's org URL
     * (e.g. https://prachi.oktapreview.com). The MCP tool handler reads this claim and calls
     * forOrg(customerOrgUrl).userApi() to route SDK calls to the right org.
     *
     * The returned client is NOT cached — a new instance is built per tool call.
     * For production, add a bounded cache keyed by orgUrl.
     *
     * POC acceptance criteria #3:
     *   list_users tool call returns users from prachi.oktapreview.com, not okta-mcp-server.oktapreview.com.
     */
    public OktaClientProvider forOrg(String targetOrgUrl) {
        if (targetOrgUrl == null || targetOrgUrl.isBlank() || targetOrgUrl.equals(orgUrl)) {
            return this; // same org — use cached default
        }
        log.info("[XAA] Building per-request ApiClient for org={}", targetOrgUrl);
        OktaClientProvider proxy = new OktaClientProvider();
        proxy.orgUrl     = targetOrgUrl;
        proxy.clientId   = this.clientId;
        proxy.privateKey = this.privateKey;
        proxy.keyId      = this.keyId;
        proxy.scopes     = this.scopes;
        proxy.apiToken   = this.apiToken;
        // Force build immediately (no lazy init needed — short-lived instance)
        proxy.apiClient  = proxy.build();
        proxy.userApi    = new UserApi(proxy.apiClient);
        proxy.groupApi   = new GroupApi(proxy.apiClient);
        proxy.applicationApi = new ApplicationApi(proxy.apiClient);
        return proxy;
    }

    /**
     * Extracts the customer_org custom claim from an XAA-issued JWT (Option 2).
     *
     * The XAA grant policy in okta-mcp-server.oktapreview.com must be configured to
     * embed the customer's org URL as a custom claim named "customer_org".
     * Returns null if the claim is absent (pre-XAA tokens / Option 1 tokens).
     */
    public static String extractCustomerOrg(org.springframework.security.oauth2.jwt.Jwt jwt) {
        String customerOrg = jwt.getClaimAsString("customer_org");
        if (customerOrg != null && !customerOrg.isBlank()) {
            LoggerFactory.getLogger(OktaClientProvider.class)
                    .info("[XAA] customer_org claim found in JWT: {}", customerOrg);
        }
        return customerOrg;
    }
}
