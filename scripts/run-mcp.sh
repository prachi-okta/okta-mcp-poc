#!/bin/sh
# Wrapper script for the Okta MCP Server (Java) — HTTP/OIDC mode.
#
# The server runs as a standard HTTP server on port 8080.
# MCP clients connect via HTTP and must present an Okta JWT on every request.
#
# Required env vars (server service account):
#   OKTA_ORG_URL, OKTA_CLIENT_ID, OKTA_PRIVATE_KEY, OKTA_KEY_ID, OKTA_SCOPES
#   OKTA_ISSUER_URI (e.g. https://okta-mcp-server.oktapreview.com/oauth2/default)
#
# MCP client config: { "type": "http", "url": "http://localhost:8080/mcp" }
#
JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null)"
if [ -z "$JAVA_HOME" ]; then
    echo "ERROR: Java 21 not found. Install Temurin 21 from https://adoptium.net" >&2
    exit 1
fi

JAR="$(dirname "$0")/../target/okta-mcp-poc-0.0.1-SNAPSHOT.jar"
if [ ! -f "$JAR" ]; then
    echo "ERROR: Fat jar not found at $JAR" >&2
    echo "Run the Build task first (Cmd+Shift+B)" >&2
    exit 1
fi

exec "$JAVA_HOME/bin/java" -jar "$JAR" "$@"
