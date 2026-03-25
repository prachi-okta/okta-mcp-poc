package com.okta.mcp.tools;

import com.okta.mcp.config.OktaClientProvider;
import com.okta.sdk.resource.model.AppUser;
import com.okta.sdk.resource.model.Application;
import com.okta.sdk.resource.model.ApplicationGroupAssignment;
import com.okta.sdk.resource.model.Group;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring AI MCP tools — Okta Application operations (SDK v25).
 *
 * Mirrors the Python server's application-related SDK calls:
 *   list_applications              -> client.list_applications(...)
 *   list_app_groups (app -> groups) -> client.list_application_group_assignments(app_id)
 *   list_app_users  (app -> users)  -> client.list_application_users(app_id)
 *   list_user_apps  (user -> apps)  -> client.list_applications(filter='user.id eq "..."')
 *   list_user_groups (user -> groups) -> client.list_user_groups(user_id)
 */
@Service
public class OktaApplicationsTool {

    private static final Logger log = LoggerFactory.getLogger(OktaApplicationsTool.class);

    private final OktaClientProvider okta;

    public OktaApplicationsTool(OktaClientProvider okta) {
        this.okta = okta;
    }

    @Tool(name = "list_applications", description = """
            List applications in the Okta organization.

            Parameters:
              q      (optional) – Prefix search on application label.
              filter (optional) – Okta filter expression, e.g. status eq "ACTIVE".
              after  (optional) – Pagination cursor.
              limit  (optional) – Max apps per page (1–200, default 20).
            """)
    public Map<String, Object> listApplications(
            @ToolParam(description = "Prefix search on application label.", required = false) String q,
            @ToolParam(description = "Okta filter expression.",             required = false) String filter,
            @ToolParam(description = "Pagination cursor.",                  required = false) String after,
            @ToolParam(description = "Max apps per page (1–200).",         required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 1, 200);
        log.info("list_applications q='{}' filter='{}' after='{}' limit={}", q, filter, after, pageLimit);
        try {
            // listApplications(q, after, useOptimization, alwaysIncludeVpnSettings, limit, filter, expand, includeNonDeleted)
            List<Application> apps = okta.applicationApi().listApplications(q, after, null, null, pageLimit, filter, null, null);
            List<Map<String, Object>> items = apps.stream().map(this::appToMap).toList();
            log.info("list_applications returned {} apps", items.size());
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_applications error", e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "list_app_groups", description = """
            List groups assigned to an application (app → groups direction).

            Parameters:
              appId (required) – Okta application ID (0oa…).
              q     (optional) – Search query on group name.
              after (optional) – Pagination cursor.
              limit (optional) – Max results per page (1–200, default 20).
            """)
    public Map<String, Object> listAppGroups(
            @ToolParam(description = "Okta application ID (0oa…).")    String appId,
            @ToolParam(description = "Search query on group name.",     required = false) String q,
            @ToolParam(description = "Pagination cursor.",              required = false) String after,
            @ToolParam(description = "Max results per page (1–200).",  required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 1, 200);
        log.info("list_app_groups appId={} q='{}' after='{}' limit={}", appId, q, after, pageLimit);
        try {
            // listApplicationGroupAssignments(appId, q, after, limit, expand)
            List<ApplicationGroupAssignment> assignments =
                    okta.applicationGroupsApi().listApplicationGroupAssignments(appId, q, after, pageLimit, null);
            List<Map<String, Object>> items = assignments.stream().map(this::groupAssignmentToMap).toList();
            log.info("list_app_groups returned {} groups for appId={}", items.size(), appId);
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_app_groups error appId={}", appId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "list_app_users", description = """
            List users assigned to an application (app → users direction).

            Parameters:
              appId (required) – Okta application ID (0oa…).
              q     (optional) – Search/filter query.
              after (optional) – Pagination cursor.
              limit (optional) – Max results per page (1–500, default 50).
            """)
    public Map<String, Object> listAppUsers(
            @ToolParam(description = "Okta application ID (0oa…).")    String appId,
            @ToolParam(description = "Search/filter query.",            required = false) String q,
            @ToolParam(description = "Pagination cursor.",              required = false) String after,
            @ToolParam(description = "Max results per page (1–500).",  required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 1, 500);
        log.info("list_app_users appId={} q='{}' after='{}' limit={}", appId, q, after, pageLimit);
        try {
            // listApplicationUsers(appId, after, limit, q, expand)
            List<AppUser> users = okta.applicationUsersApi().listApplicationUsers(appId, after, pageLimit, q, null);
            List<Map<String, Object>> items = users.stream().map(this::appUserToMap).toList();
            log.info("list_app_users returned {} users for appId={}", items.size(), appId);
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_app_users error appId={}", appId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "list_user_apps", description = """
            List applications assigned to a specific user (user → apps direction).
            Uses an Okta filter expression internally: user.id eq "<userId>".

            Parameters:
              userId (required) – Okta user ID (00u…) or login/email.
              after  (optional) – Pagination cursor.
              limit  (optional) – Max apps per page (1–200, default 50).
            """)
    public Map<String, Object> listUserApps(
            @ToolParam(description = "Okta user ID (00u…) or login/email.") String userId,
            @ToolParam(description = "Pagination cursor.",                   required = false) String after,
            @ToolParam(description = "Max apps per page (1–200).",          required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 1, 200);
        String filter = "user.id eq \"" + userId + "\"";
        log.info("list_user_apps userId={} filter='{}' after='{}' limit={}", userId, filter, after, pageLimit);
        try {
            // listApplications(q, after, useOptimization, alwaysIncludeVpnSettings, limit, filter, expand, includeNonDeleted)
            List<Application> apps = okta.applicationApi().listApplications(null, after, null, null, pageLimit, filter, null, null);
            List<Map<String, Object>> items = apps.stream().map(this::appToMap).toList();
            log.info("list_user_apps returned {} apps for userId={}", items.size(), userId);
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_user_apps error userId={}", userId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "list_user_groups", description = """
            List groups that a user belongs to (user → groups direction).

            Parameters:
              userId (required) – Okta user ID (00u…) or login/email.
            """)
    public Map<String, Object> listUserGroups(
            @ToolParam(description = "Okta user ID (00u…) or login/email.") String userId
    ) {
        log.info("list_user_groups userId={}", userId);
        try {
            List<Group> groups = okta.userResourcesApi().listUserGroups(userId);
            List<Map<String, Object>> items = groups.stream().map(g -> {
                var p = g.getProfile();
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id",          g.getId());
                m.put("type",        g.getType() != null ? g.getType().getValue() : null);
                m.put("name",        p != null ? p.getName()        : null);
                m.put("description", p != null ? p.getDescription() : null);
                return m;
            }).toList();
            log.info("list_user_groups returned {} groups for userId={}", items.size(), userId);
            return Map.of("items", items, "total_fetched", items.size());
        } catch (Exception e) {
            log.error("list_user_groups error userId={}", userId, e);
            return Map.of("error", e.getMessage());
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Map<String, Object> appToMap(Application a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",     a.getId());
        m.put("label",  a.getLabel());
        m.put("status", a.getStatus() != null ? a.getStatus().getValue() : null);
        return m;
    }

    private Map<String, Object> groupAssignmentToMap(ApplicationGroupAssignment a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",       a.getId());
        m.put("priority", a.getPriority());
        m.put("profile",  a.getProfile());
        return m;
    }

    private Map<String, Object> appUserToMap(AppUser u) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",       u.getId());
        m.put("scope",    u.getScope()    != null ? u.getScope().getValue()  : null);
        m.put("status",   u.getStatus()   != null ? u.getStatus().getValue() : null);
        m.put("profile",  u.getProfile());
        return m;
    }

    private static int clamp(Integer v, int min, int max) {
        if (v == null) return min;
        return Math.min(Math.max(v, min), max);
    }
}
