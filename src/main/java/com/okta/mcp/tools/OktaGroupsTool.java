package com.okta.mcp.tools;

import com.okta.mcp.config.OktaClientProvider;
import com.okta.sdk.resource.model.Group;
import com.okta.sdk.resource.model.GroupProfile;
import com.okta.sdk.resource.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring AI MCP tools — Okta Group operations (SDK v25).
 */
@Service
public class OktaGroupsTool {

    private static final Logger log = LoggerFactory.getLogger(OktaGroupsTool.class);

    private final OktaClientProvider okta;

    public OktaGroupsTool(OktaClientProvider okta) {
        this.okta = okta;
    }

    @Tool(name = "list_groups", description = """
            List groups from the Okta organization.

            Parameters:
              search (optional) – Okta search expression, e.g. profile.name sw "Engineering"
              filter (optional) – Okta filter expression, e.g. type eq "OKTA_GROUP"
              q      (optional) – Prefix query on group name.
              after  (optional) – Pagination cursor.
              limit  (optional) – Max groups per page (20–100, default 20).
            """)
    public Map<String, Object> listGroups(
            @ToolParam(description = "Okta search expression.", required = false) String search,
            @ToolParam(description = "Okta filter expression.", required = false) String filter,
            @ToolParam(description = "Prefix query on name.",  required = false) String q,
            @ToolParam(description = "Pagination cursor.",     required = false) String after,
            @ToolParam(description = "Max groups per page (20–100).", required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 20, 100);
        log.info("list_groups search='{}' filter='{}' q='{}' after='{}' limit={}", search, filter, q, after, pageLimit);
        try {
            // SDK v25: listGroups(search, filter, q, after, limit, expand, sortBy, sortOrder)
            List<Group> groups = okta.groupApi().listGroups(search, filter, q, after, pageLimit, null, null, null);
            List<Map<String, Object>> items = groups.stream().map(this::toMap).toList();
            log.info("list_groups returned {} groups", items.size());
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_groups error", e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "get_group", description = """
            Get a group by ID.

            Parameters:
              groupId (required) – Okta group ID (00g…)
            """)
    public Map<String, Object> getGroup(
            @ToolParam(description = "Okta group ID (00g…).") String groupId
    ) {
        log.info("get_group groupId={}", groupId);
        try {
            Group group = okta.groupApi().getGroup(groupId);
            Map<String, Object> result = toMap(group);
            result.put("created",     group.getCreated());
            result.put("lastUpdated", group.getLastUpdated());
            return result;
        } catch (Exception e) {
            log.error("get_group error groupId={}", groupId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "add_user_to_group", description = """
            Add a user to a group. Idempotent — returns early if already a member.

            Parameters:
              groupId (required) – Okta group ID (00g…)
              userId  (required) – Okta user ID (00u…) or login
            """)
    public Map<String, Object> addUserToGroup(
            @ToolParam(description = "Okta group ID (00g…).") String groupId,
            @ToolParam(description = "Okta user ID or login.") String userId
    ) {
        log.info("add_user_to_group userId={} groupId={}", userId, groupId);
        try {
            // Idempotency check via UserResourcesApi.listUserGroups (mirrors Python server)
            List<Group> userGroups = okta.userResourcesApi().listUserGroups(userId);
            if (userGroups.stream().anyMatch(g -> groupId.equals(g.getId()))) {
                log.info("add_user_to_group: already a member");
                return Map.of("message", "User " + userId + " is already a member of group " + groupId + ".");
            }
            okta.groupApi().assignUserToGroup(groupId, userId);
            log.info("add_user_to_group succeeded");
            return Map.of("message", "User " + userId + " added to group " + groupId + " successfully.");
        } catch (Exception e) {
            log.error("add_user_to_group error", e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "remove_user_from_group", description = """
            Remove a user from a group.

            Parameters:
              groupId (required) – Okta group ID (00g…)
              userId  (required) – Okta user ID (00u…) or login
            """)
    public Map<String, Object> removeUserFromGroup(
            @ToolParam(description = "Okta group ID (00g…).") String groupId,
            @ToolParam(description = "Okta user ID or login.") String userId
    ) {
        log.info("remove_user_from_group userId={} groupId={}", userId, groupId);
        try {
            okta.groupApi().unassignUserFromGroup(groupId, userId);
            log.info("remove_user_from_group succeeded");
            return Map.of("message", "User " + userId + " removed from group " + groupId + " successfully.");
        } catch (Exception e) {
            log.error("remove_user_from_group error", e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "list_group_users", description = """
            List users in a group.

            Parameters:
              groupId (required) – Okta group ID (00g…)
              after   (optional) – Pagination cursor.
              limit   (optional) – Max users per page (20–100, default 20).
            """)
    public Map<String, Object> listGroupUsers(
            @ToolParam(description = "Okta group ID (00g…).") String groupId,
            @ToolParam(description = "Pagination cursor.",     required = false) String after,
            @ToolParam(description = "Max users per page.",    required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 20, 100);
        log.info("list_group_users groupId={} after='{}' limit={}", groupId, after, pageLimit);
        try {
            // SDK v25: listGroupUsers(groupId, after, limit)
            List<User> users = okta.groupApi().listGroupUsers(groupId, after, pageLimit);
            List<Map<String, Object>> items = users.stream().map(u -> {
                var p = u.getProfile();
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id",        u.getId());
                m.put("login",     p != null ? p.getLogin()     : null);
                m.put("email",     p != null ? p.getEmail()     : null);
                m.put("firstName", p != null ? p.getFirstName() : null);
                m.put("lastName",  p != null ? p.getLastName()  : null);
                m.put("status",    u.getStatus() != null ? u.getStatus().getValue() : null);
                return m;
            }).toList();
            log.info("list_group_users returned {} users", items.size());
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_group_users error groupId={}", groupId, e);
            return Map.of("error", e.getMessage());
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────────────────

    private Map<String, Object> toMap(Group g) {
        GroupProfile p = g.getProfile();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",          g.getId());
        m.put("type",        g.getType() != null ? g.getType().getValue() : null);
        m.put("name",        p != null ? p.getName()        : null);
        m.put("description", p != null ? p.getDescription() : null);
        return m;
    }

    private static int clamp(Integer v, int min, int max) {
        if (v == null) return min;
        return Math.min(Math.max(v, min), max);
    }
}

