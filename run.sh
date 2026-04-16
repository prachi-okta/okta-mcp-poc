#!/bin/zsh
# Usage:
#   ./run.sh          → start server (skips rebuild if jar is up to date)
#   ./run.sh --build  → force rebuild first, then start

export JAVA_HOME=$(/usr/libexec/java_home -v 21)

if [[ "$1" == "--build" ]]; then
  echo "🔨 Building..."
  mvn package -DskipTests -q || { echo "❌ Build failed"; exit 1; }
  echo "✅ Build done"
fi

echo "🚀 Starting Okta MCP Server on http://localhost:8080 ..."
lsof -ti:8080 | xargs kill -9 2>/dev/null; sleep 1

OKTA_ORG_URL=https://prachipandey.oktapreview.com \
OKTA_ISSUER_URI=https://prachipandey.oktapreview.com/oauth2/default \
OKTA_UI_CLIENT_ID=0oax8iq4w87vVtjh01d7 \
OKTA_RESOURCE_URI=http://127.0.0.1:8081/sse \
$JAVA_HOME/bin/java -jar target/okta-mcp-poc-0.0.1-SNAPSHOT.jar --spring.profiles.active=local --server.port=8081
