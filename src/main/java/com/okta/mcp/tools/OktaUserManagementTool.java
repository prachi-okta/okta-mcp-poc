package com.okta.mcp.tools;

import com.okta.mcp.config.OktaClientProvider;
import com.okta.sdk.resource.model.CreateUserRequest;
import com.okta.sdk.resource.model.PasswordCredential;
import com.okta.sdk.resource.model.UpdateUserRequest;
import com.okta.sdk.resource.model.User;
import com.okta.sdk.resource.model.UserCredentialsWritable;
import com.okta.sdk.resource.model.UserProfile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Spring AI MCP tools — Okta User operations (SDK v25).
 *
 * Each {@code @Tool} calls one Okta SDK method which proxies to the Okta Management API.
 */
@Service
public class OktaUserManagementTool {

    private static final Logger log = LoggerFactory.getLogger(OktaUserManagementTool.class);

    private final OktaClientProvider okta;

    public OktaUserManagementTool(OktaClientProvider okta) {
        this.okta = okta;
    }

    @Tool(name = "list_users", description = """
            List users from the Okta organization with optional filtering.

            Parameters:
              search (optional) – Okta search expression, e.g. profile.department eq "Engineering"
              filter (optional) – Okta filter string on profile attributes.
              q      (optional) – Simple prefix-search query on name/email/login.
              after  (optional) – Pagination cursor from a previous call.
              limit  (optional) – Max users per page (min 20, max 200, default 20).
            """)
    public Map<String, Object> listUsers(
            @ToolParam(description = "Okta search expression.", required = false) String search,
            @ToolParam(description = "Okta filter string.",     required = false) String filter,
            @ToolParam(description = "Simple prefix query.",    required = false) String q,
            @ToolParam(description = "Pagination cursor.",      required = false) String after,
            @ToolParam(description = "Max users per page (20–200, default 20).", required = false) Integer limit
    ) {
        int pageLimit = clamp(limit, 20, 200);
        log.info("list_users search='{}' filter='{}' q='{}' after='{}' limit={}", search, filter, q, after, pageLimit);
        try {
            // SDK v25: listUsers(contentType, search, filter, q, after, limit, sortBy, sortOrder, expand, oauthTokens)
            List<User> users = okta.userApi().listUsers(null, search, filter, q, after, pageLimit, null, null, null, null);
            List<Map<String, Object>> items = users.stream().map(this::toMap).toList();
            log.info("list_users returned {} users", items.size());
            return Map.of("items", items, "total_fetched", items.size(), "has_more", items.size() == pageLimit);
        } catch (Exception e) {
            log.error("list_users error", e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "get_user", description = """
            Get a user by ID or login from the Okta organization.

            Parameters:
              userId (required) – Okta user ID (00u…) or login/email.
            """)
    public Map<String, Object> getUser(
            @ToolParam(description = "Okta user ID (00u…) or login/email.") String userId
    ) {
        log.info("get_user userId={}", userId);
        try {
            // SDK v25: getUser(id, contentType, expand)
            User user = okta.userApi().getUser(userId, null, null);
            Map<String, Object> result = toMap(user);
            result.put("created",     user.getCreated());
            result.put("lastLogin",   user.getLastLogin());
            result.put("lastUpdated", user.getLastUpdated());
            log.info("get_user succeeded userId={}", userId);
            return result;
        } catch (Exception e) {
            log.error("get_user error userId={}", userId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "create_user", description = """
            Create a new user in the Okta organization.

            Parameters:
              firstName (required) – first name
              lastName  (required) – last name
              email     (required) – primary email
              login     (required) – Okta login (usually same as email)
              password  (optional) – if omitted, Okta sends an activation email
            """)
    public Map<String, Object> createUser(
            @ToolParam(description = "First name.") String firstName,
            @ToolParam(description = "Last name.")  String lastName,
            @ToolParam(description = "Email.")      String email,
            @ToolParam(description = "Login.")      String login,
            @ToolParam(description = "Initial password.", required = false) String password
    ) {
        log.info("create_user login={}", login);
        try {
            UserProfile profile = new UserProfile()
                    .firstName(firstName).lastName(lastName).email(email).login(login);
            CreateUserRequest req = new CreateUserRequest().profile(profile);
            if (password != null && !password.isBlank()) {
                // SDK v25: credentials field is UserCredentialsWritable (not UserCredentials)
                req.credentials(new UserCredentialsWritable()
                        .password(new PasswordCredential().value(password)));
            }
            // SDK v25: createUser(body, activate, provider, nextLogin)
            User user = okta.userApi().createUser(req, true, null, null);
            log.info("create_user succeeded id={}", user.getId());
            return Map.of("id", user.getId(), "login", login,
                    "status", user.getStatus() != null ? user.getStatus().getValue() : "UNKNOWN",
                    "message", "User created successfully.");
        } catch (Exception e) {
            log.error("create_user error login={}", login, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "update_user", description = """
            Partial-update a user's profile in the Okta organization.

            Parameters:
              userId    (required) – Okta user ID or login
              firstName (optional) – new first name
              lastName  (optional) – new last name
              email     (optional) – new email
            """)
    public Map<String, Object> updateUser(
            @ToolParam(description = "Okta user ID or login.") String userId,
            @ToolParam(description = "New first name.", required = false) String firstName,
            @ToolParam(description = "New last name.",  required = false) String lastName,
            @ToolParam(description = "New email.",      required = false) String email
    ) {
        log.info("update_user userId={}", userId);
        try {
            UserProfile profile = new UserProfile();
            if (firstName != null && !firstName.isBlank()) profile.setFirstName(firstName);
            if (lastName  != null && !lastName.isBlank())  profile.setLastName(lastName);
            if (email     != null && !email.isBlank())     profile.setEmail(email);
            UpdateUserRequest req = new UpdateUserRequest().profile(profile);
            // SDK v25: updateUser(id, body, strict, ifMatch)
            User updated = okta.userApi().updateUser(userId, req, false, null);
            log.info("update_user succeeded userId={}", userId);
            return Map.of("id", updated.getId(),
                    "status", updated.getStatus() != null ? updated.getStatus().getValue() : "UNKNOWN",
                    "message", "User updated successfully.");
        } catch (Exception e) {
            log.error("update_user error userId={}", userId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "deactivate_user", description = """
            Deactivate a user. Must be done before deleting.

            Parameters:
              userId (required) – Okta user ID or login
            """)
    public Map<String, Object> deactivateUser(
            @ToolParam(description = "Okta user ID or login.") String userId
    ) {
        log.info("deactivate_user userId={}", userId);
        try {
            // SDK v25: deactivateUser is on UserLifecycleApi
            // signature: deactivateUser(id, sendEmail, prefer)
            okta.userLifecycleApi().deactivateUser(userId, false, null);
            log.info("deactivate_user succeeded userId={}", userId);
            return Map.of("message", "User " + userId + " deactivated successfully.");
        } catch (Exception e) {
            log.error("deactivate_user error userId={}", userId, e);
            return Map.of("error", e.getMessage());
        }
    }

    @Tool(name = "delete_user", description = """
            Permanently delete a deactivated user. User must be deactivated first.

            Parameters:
              userId (required) – Okta user ID or login of a DEACTIVATED user
            """)
    public Map<String, Object> deleteUser(
            @ToolParam(description = "Okta user ID or login of a DEACTIVATED user.") String userId
    ) {
        log.info("delete_user userId={}", userId);
        try {
            // SDK v25: deleteUser(id, sendEmail, prefer)
            okta.userApi().deleteUser(userId, false, null);
            log.info("delete_user succeeded userId={}", userId);
            return Map.of("message", "User " + userId + " deleted successfully.");
        } catch (Exception e) {
            log.error("delete_user error userId={}", userId, e);
            return Map.of("error", e.getMessage());
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────────────────

    private Map<String, Object> toMap(User u) {
        UserProfile p = u.getProfile();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id",        u.getId());
        m.put("status",    u.getStatus() != null ? u.getStatus().getValue() : null);
        m.put("login",     p != null ? p.getLogin()     : null);
        m.put("email",     p != null ? p.getEmail()     : null);
        m.put("firstName", p != null ? p.getFirstName() : null);
        m.put("lastName",  p != null ? p.getLastName()  : null);
        return m;
    }

    private static int clamp(Integer v, int min, int max) {
        if (v == null) return min;
        return Math.min(Math.max(v, min), max);
    }
}
