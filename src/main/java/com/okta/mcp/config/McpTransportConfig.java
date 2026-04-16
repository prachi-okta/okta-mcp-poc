package com.okta.mcp.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.deser.DeserializationProblemHandler;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;

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
                // Handles enum deserialized from an unknown *string* value → null
                .enable(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_AS_NULL)
                .enable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                // VS Code sends LoggingLevel as a JSON *object* {} instead of a string enum.
                // READ_UNKNOWN_ENUM_VALUES_AS_NULL only works for string tokens.
                // This handler catches any unexpected token during deserialization
                // (including START_OBJECT where a scalar/enum is expected), skips the
                // entire value tree, and returns null — preventing the -32603 crash on initialize.
                .addHandler(new DeserializationProblemHandler() {
                    @Override
                    public Object handleUnexpectedToken(DeserializationContext ctxt,
                            JavaType targetType, JsonToken t, JsonParser p,
                            String failureMsg) throws IOException {
                        p.skipChildren(); // consume the unexpected token tree
                        return null;
                    }
                })
                .build();
    }
}
