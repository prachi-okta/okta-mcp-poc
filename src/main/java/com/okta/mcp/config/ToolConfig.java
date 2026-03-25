package com.okta.mcp.config;

import com.okta.mcp.tools.OktaApplicationsTool;
import com.okta.mcp.tools.OktaGroupsTool;
import com.okta.mcp.tools.OktaUserManagementTool;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers Spring AI {@link ToolCallbackProvider} beans so that the
 * MCP server auto-configuration can expose them as MCP tools over SSE.
 *
 * <p>Mirrors the Python server's {@code main()} which imports each tool
 * module so that the {@code @mcp.tool()} decorators are registered:
 * <pre>
 *   from okta_mcp_server.tools.users  import users   # registers list_users, get_user, …
 *   from okta_mcp_server.tools.groups import groups  # registers list_groups, add_user_to_group, …
 * </pre>
 */
@Configuration
public class ToolConfig {

    /**
     * Scans all {@code @Tool}-annotated methods across the three tool classes
     * and makes them available to the Spring AI MCP server over stdio transport.
     */
    @Bean
    public ToolCallbackProvider oktaToolCallbackProvider(
            OktaUserManagementTool userTool,
            OktaGroupsTool groupsTool,
            OktaApplicationsTool appsTool
    ) {
        return MethodToolCallbackProvider.builder()
                .toolObjects(userTool, groupsTool, appsTool)
                .build();
    }
}
