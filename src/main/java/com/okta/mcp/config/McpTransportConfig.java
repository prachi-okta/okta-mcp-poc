package com.okta.mcp.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.modelcontextprotocol.server.transport.StdioServerTransport;
import io.modelcontextprotocol.spec.ServerMcpTransport;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Provides a custom StdioServerTransport with an ObjectMapper configured to
 * ignore unknown fields.
 *
 * VS Code's MCP client sends an "elicitation" field in ClientCapabilities
 * (MCP spec 2025-03-26+) which the MCP SDK 0.7.0 class McpSchema$ClientCapabilities
 * does not declare. Without this, Jackson throws:
 *   Unrecognized field "elicitation" ... not marked as ignorable
 * and the MCP handshake fails with error -32603.
 *
 * StdioServerTransport has a constructor that accepts an ObjectMapper, and
 * MpcServerAutoConfiguration registers the transport as @ConditionalOnMissingBean,
 * so this bean takes precedence.
 */
@Configuration
public class McpTransportConfig {

    @Bean
    public ServerMcpTransport stdioServerTransport() {
        ObjectMapper mapper = new ObjectMapper()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        return new StdioServerTransport(mapper);
    }
}
