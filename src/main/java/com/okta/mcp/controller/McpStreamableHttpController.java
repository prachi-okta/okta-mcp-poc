package com.okta.mcp.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.ToolCallback;
import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Streamable HTTP transport for VS Code's MCP client (MCP spec 2025-03-26).
 *
 * Key spec requirements implemented here:
 *   1. POST /sse initialize  → must return "mcp-session-id" response header.
 *      VS Code discards the session and restarts auth if this header is absent.
 *   2. Subsequent POST /sse  → client sends "mcp-session-id" request header;
 *      server returns 404 if the session is unknown.
 *   3. GET /sse              → opens an SSE keep-alive stream bound to the session.
 *      VS Code opens this after initialize to receive server-push messages.
 *   4. tools/call            → dispatched directly via ToolCallbackProvider.
 */
@RestController
public class McpStreamableHttpController {

    private static final Logger log = LoggerFactory.getLogger(McpStreamableHttpController.class);

    /** Live sessions: sessionId → placeholder (value unused). */
    private final ConcurrentHashMap<String, Boolean> sessions = new ConcurrentHashMap<>();


    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ToolCallbackProvider toolCallbackProvider;

    @Value("${spring.ai.mcp.server.name:okta-mcp-server}")
    private String serverName;

    @Value("${spring.ai.mcp.server.version:1.0.0}")
    private String serverVersion;

    // -------------------------------------------------------------------------
    // POST /sse  — all JSON-RPC methods (MCP Streamable HTTP, spec 2025-11-25)
    //
    // Written SYNCHRONOUSLY to HttpServletResponse. This is intentional:
    //
    //   SseEmitter uses Tomcat async dispatch (AsyncContext.start()). Tomcat
    //   commits response headers as part of the async handshake, BEFORE Spring
    //   gets to write mcp-session-id — so the header is silently dropped on the
    //   wire regardless of ResponseEntity or response.setHeader() calls. VS Code
    //   never gets the session ID and restarts auth on every request.
    //
    //   Synchronous writes bypass async dispatch entirely: we set mcp-session-id
    //   BEFORE writing the first body byte, so Tomcat includes it in the same
    //   TCP packet as the response line and headers.
    //
    // Response format: text/event-stream with "event: message" field.
    //   VS Code sends Accept: text/event-stream, application/json.
    //   It reads SSE events by event *type*. Unnamed events (no event: field)
    //   are dispatched as "message" by the browser EventSource API, but VS Code's
    //   Node-based MCP client explicitly filters for event type "message".
    //   Without the event: field the event is silently ignored.
    // -------------------------------------------------------------------------

    @PostMapping(value = "/sse", consumes = MediaType.APPLICATION_JSON_VALUE)
    public void handlePost(
            @RequestHeader(value = "mcp-session-id", required = false) String sessionId,
            @RequestBody String body,
            HttpServletResponse response) throws Exception {

        JsonNode request = objectMapper.readTree(body);
        String method = request.path("method").asText("");
        JsonNode id    = request.get("id");

        log.info("[MCP] POST /sse method={} id={} session={}", method, id, sessionId);

        // ── initialize ────────────────────────────────────────────────────────
        if ("initialize".equals(method)) {
            String clientVersion = request.path("params").path("protocolVersion").asText("2025-11-25");
            String newSession    = UUID.randomUUID().toString();
            sessions.put(newSession, Boolean.TRUE);
            log.info("[MCP] Session created: {} protocolVersion={}", newSession, clientVersion);

            // Set header FIRST — before setContentType() so Tomcat hasn't
            // committed the response yet. Any header set after getOutputStream()
            // is called is silently ignored by the servlet container.
            // Mcp-Session-Id (title-case): VS Code reads res.headers.get('Mcp-Session-Id')
            // per WHATWG Fetch spec, header names are case-insensitive on get() but we
            // match the casing VS Code uses in its source to be unambiguous.
            response.setHeader("Mcp-Session-Id", newSession);
            writeStreamableSse(response, buildInitializeResponse(id, clientVersion));
            log.info("[MCP] initialize done — Mcp-Session-Id={}", newSession);
            return;
        }

        // ── all other methods require a valid session ─────────────────────────
        if (sessionId == null || !sessions.containsKey(sessionId)) {
            log.warn("[MCP] Unknown/missing session={} for method={}", sessionId, method);
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            writeSse(response, buildErrorResponse(id, -32001, "Session not found. Send initialize first."));
            return;
        }

        // ── notifications (no response body per spec) ─────────────────────────
        if ("notifications/initialized".equals(method)) {
            log.info("[MCP] notifications/initialized — session={}", sessionId);
            response.setStatus(HttpServletResponse.SC_ACCEPTED);
            response.setContentLength(0);
            return;
        }

        // ── standard request/response methods ────────────────────────────────
        String responseJson = switch (method) {
            case "tools/list" -> buildToolsListResponse(id);
            case "tools/call" -> buildToolsCallResponse(id, request.path("params"));
            case "ping"       -> buildResult(id, objectMapper.createObjectNode());
            default -> {
                log.warn("[MCP] Unhandled method={}", method);
                yield buildErrorResponse(id, -32601, "Method not found: " + method);
            }
        };

        writeSse(response, responseJson);
    }

    /**
     * Writes the initialize response as text/event-stream.
     *
     * Why SSE for initialize (not application/json):
     *   After initialize VS Code concurrently fires _attachStreamableBackchannel() (GET /sse)
     *   AND dispatches notifications/initialized — both need a fresh auth token at the same
     *   instant. With application/json the body is read synchronously, then both calls race
     *   to $getTokenFromServerMetadata(); the token from PKCE #1 hasn't been committed yet,
     *   so one of them triggers PKCE #2 and the handle is torn down before notifications/
     *   initialized is ever sent.
     *
     *   With text/event-stream VS Code enters _doSSE() which reads the stream event-by-event.
     *   The response body is drained BEFORE the concurrent auth calls can collide, so
     *   notifications/initialized is sent while the token is already in cache.
     *
     *   VS Code sends Accept: text/event-stream, application/json, so this format is legal.
     *   A single event stream with one "data:" line and a trailing blank line is all it needs.
     */
    private void writeStreamableSse(HttpServletResponse response, String json) throws Exception {
        String sseFrame = "event: message\ndata: " + json + "\n\n";
        byte[] bytes = sseFrame.getBytes(StandardCharsets.UTF_8);
        response.setContentType("text/event-stream;charset=UTF-8");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
        response.getOutputStream().flush();
    }

    /**
     * Writes a single MCP response as application/json (MCP Streamable HTTP §6.1).
     *
     * Returns plain JSON — VS Code's _handleSuccessfulStreamableHttp reads it via
     * res.text() and returns immediately, allowing notifications/initialized to be
     * sent without waiting for an SSE reader loop.
     *
     * MCP Streamable HTTP spec §6.1 says the server SHOULD reply with a single
     * application/json body for simple request-response patterns.
     * text/event-stream also works but VS Code's _doSSE loops on reader.read()
     * until EOF; with keep-alive that never comes, blocking sendRequest and
     * preventing notifications/initialized from being sent.
     *
     * The response is written synchronously (no async dispatch) so that the
     * mcp-session-id response header set before this call is guaranteed to
     * be flushed to the client in the same write as the status line.
     */
    private void writeSse(HttpServletResponse response, String json) throws Exception {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        response.setContentType("application/json;charset=UTF-8");
        response.setContentLength(bytes.length);
        response.getOutputStream().write(bytes);
        response.getOutputStream().flush();
    }

    // -------------------------------------------------------------------------
    // GET /sse  — optional SSE notification stream (MCP spec §6.2.2)
    // VS Code opens this after initialize for server-to-client push messages.
    // -------------------------------------------------------------------------

    @GetMapping(value = "/sse", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter openSseStream(
            @RequestHeader(value = "mcp-session-id", required = false) String sessionId,
            HttpServletResponse response) {

        log.info("[MCP] GET /sse — session={}", sessionId != null ? sessionId.substring(0, Math.min(8, sessionId.length())) + "…" : "null");

        if (sessionId == null || !sessions.containsKey(sessionId)) {
            // Return 405 (not 404) so VS Code's _attachStreamableBackchannel exits its
            // retry loop permanently on the first attempt.
            // VS Code source: "if (res.status >= 400) { ... return; }" — any 4xx stops it.
            // Using 405 (not 404) avoids triggering the MCP-Session-Id retry logic that
            // 404 can trigger in _sendStreamableHttp ("client MUST start a new session").
            log.warn("[MCP] GET /sse — unknown/missing session={} — returning 405 to stop backchannel", sessionId);
            response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            SseEmitter emitter = new SseEmitter(0L);
            emitter.complete();
            return emitter;
        }

        log.info("[MCP] GET /sse — SSE stream opened for session={}", sessionId);

        // Keep-alive emitter: never times out, no server-push needed for sync tool calls.
        // VS Code holds this open; it will be closed when VS Code disconnects.
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        emitter.onCompletion(() -> log.info("[MCP] SSE stream closed for session={}", sessionId));
        emitter.onTimeout(()    -> log.info("[MCP] SSE stream timed out for session={}", sessionId));

        // Send an initial ping comment so VS Code knows the stream is alive.
        // Without this, VS Code may time out waiting for the first byte.
        try {
            emitter.send(SseEmitter.event().comment("ping"));
        } catch (Exception e) {
            log.warn("[MCP] Could not send initial ping for session={}: {}", sessionId, e.getMessage());
        }

        return emitter;
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private String buildInitializeResponse(JsonNode id, String protocolVersion) throws Exception {
        ObjectNode capabilities = objectMapper.createObjectNode();
        capabilities.putObject("tools");

        ObjectNode serverInfo = objectMapper.createObjectNode();
        serverInfo.put("name", serverName);
        serverInfo.put("version", serverVersion);

        ObjectNode result = objectMapper.createObjectNode();
        result.put("protocolVersion", protocolVersion);
        result.set("capabilities", capabilities);
        result.set("serverInfo", serverInfo);

        log.info("[MCP] initialize → name={} version={} protocolVersion={}", serverName, serverVersion, protocolVersion);
        return buildResult(id, result);
    }

    private String buildToolsListResponse(JsonNode id) throws Exception {
        ArrayNode tools = objectMapper.createArrayNode();
        for (ToolCallback cb : toolCallbackProvider.getToolCallbacks()) {
            var def = cb.getToolDefinition();
            ObjectNode t = objectMapper.createObjectNode();
            t.put("name", def.name());
            t.put("description", def.description() != null ? def.description() : "");
            if (def.inputSchema() != null) {
                try {
                    t.set("inputSchema", objectMapper.readTree(def.inputSchema()));
                } catch (Exception ignored) {
                    t.putObject("inputSchema");
                }
            }
            tools.add(t);
        }
        ObjectNode result = objectMapper.createObjectNode();
        result.set("tools", tools);
        log.info("[MCP] tools/list → {} tools", tools.size());
        return buildResult(id, result);
    }

    private String buildToolsCallResponse(JsonNode id, JsonNode params) throws Exception {
        String toolName = params.path("name").asText("");
        JsonNode arguments = params.path("arguments");
        String argsJson = objectMapper.writeValueAsString(arguments.isMissingNode()
                ? objectMapper.createObjectNode() : arguments);

        log.info("[MCP] tools/call name={} args={}", toolName, argsJson);

        // Find matching ToolCallback by name
        for (ToolCallback cb : toolCallbackProvider.getToolCallbacks()) {
            if (cb.getToolDefinition().name().equals(toolName)) {
                String rawResult = cb.call(argsJson);
                // Wrap result in MCP CallToolResult format
                ObjectNode result = objectMapper.createObjectNode();
                ArrayNode content = result.putArray("content");
                ObjectNode textContent = content.addObject();
                textContent.put("type", "text");
                textContent.put("text", rawResult != null ? rawResult : "");
                result.put("isError", false);
                log.info("[MCP] tools/call {} → success", toolName);
                return buildResult(id, result);
            }
        }

        log.warn("[MCP] tools/call — unknown tool: {}", toolName);
        return buildErrorResponse(id, -32602, "Unknown tool: " + toolName);
    }

    private String buildResult(JsonNode id, ObjectNode result) throws Exception {
        ObjectNode response = objectMapper.createObjectNode();
        response.put("jsonrpc", "2.0");
        if (id != null) response.set("id", id);
        response.set("result", result);
        return objectMapper.writeValueAsString(response);
    }

    private String buildErrorResponse(JsonNode id, int code, String message) throws Exception {
        ObjectNode error = objectMapper.createObjectNode();
        error.put("code", code);
        error.put("message", message);
        ObjectNode response = objectMapper.createObjectNode();
        response.put("jsonrpc", "2.0");
        if (id != null) response.set("id", id);
        response.set("error", error);
        return objectMapper.writeValueAsString(response);
    }
}
