package com.okta.mcp.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * MCP transport configuration for Streamable HTTP transport.
 *
 * Replaces the previous StdioServerTransport with HTTP-based Streamable transport
 * so the server can enforce OAuth 2.0 authorization per the MCP 2025-03-26 spec.
 *
 * The mcpServerJsonMapper bean overrides the MCP autoconfiguration's default
 * JsonMapper (via @ConditionalOnMissingBean in McpServerAutoConfiguration).
 * Disabling FAIL_ON_UNKNOWN_PROPERTIES ensures VS Code's "elicitation" field
 * in ClientCapabilities (MCP spec 2025-03-26+) is silently ignored rather
 * than causing a -32603 handshake failure.
 */
@Configuration
public class McpTransportConfig {

    @Bean("mcpServerJsonMapper")
    public JsonMapper mcpServerJsonMapper() {
        return JsonMapper.builder()
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                // VS Code sends LoggingLevel as a JSON object instead of a string enum;
                // treat unrecognised enum values as null rather than throwing -32603.
                .enable(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL)
                .build();
    }
}
