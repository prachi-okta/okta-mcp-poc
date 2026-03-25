#!/bin/sh
# Wrapper script for the Okta MCP Server (Java).
# Mirrors the Python server's .venv/bin/okta-mcp-server pattern.
#
# Uses /usr/libexec/java_home to locate Java 21 regardless of what
# is on VS Code's restricted PATH when it spawns this process.

JAVA_HOME="$(/usr/libexec/java_home -v 21 2>/dev/null)"
if [ -z "$JAVA_HOME" ]; then
    echo "ERROR: Java 21 not found. Install Temurin 21 from https://adoptium.net" >&2
    exit 1
fi

JAR="$(dirname "$0")/../target/okta-mcp-poc-0.0.1-SNAPSHOT.jar"
if [ ! -f "$JAR" ]; then
    echo "ERROR: Fat jar not found at $JAR" >&2
    echo "Run the 'Build Okta MCP Server (fat jar)' task in VS Code first (Cmd+Shift+B)" >&2
    exit 1
fi

exec "$JAVA_HOME/bin/java" -jar "$JAR" "$@"