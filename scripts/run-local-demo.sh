#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run-local-demo.sh  —  Start the Okta MCP Server locally with real auth
#
# Required environment variables:
#   OKTA_ORG_URL        Your Okta org, e.g. https://dev-123456.okta.com
#   OKTA_CLIENT_TOKEN   SSWS API token (Okta Admin → Security → API → Tokens)
#   OKTA_ISSUER_URI     Authorization server issuer, e.g.
#                         https://dev-123456.okta.com/oauth2/default
#   OKTA_UI_CLIENT_ID   Client ID of your Okta SPA app (for PKCE browser login)
#
# Optional:
#   OKTA_UI_SCOPES      Defaults to: openid profile email
#
# Usage:
#   export OKTA_ORG_URL=https://dev-123456.okta.com
#   export OKTA_CLIENT_TOKEN=00...
#   export OKTA_ISSUER_URI=https://dev-123456.okta.com/oauth2/default
#   export OKTA_UI_CLIENT_ID=0oa...
#   ./scripts/run-local-demo.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Resolve JAVA_HOME to Java 21 on macOS ─────────────────────────────────
if [[ "$(uname)" == "Darwin" ]]; then
  export JAVA_HOME=$(/usr/libexec/java_home -v 21 2>/dev/null || true)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
JAR="$PROJECT_DIR/target/okta-mcp-poc-0.0.1-SNAPSHOT.jar"

# ── Validate required vars ─────────────────────────────────────────────────
MISSING=()
[[ -z "${OKTA_ORG_URL:-}"       ]] && MISSING+=("OKTA_ORG_URL")
[[ -z "${OKTA_CLIENT_TOKEN:-}"  ]] && MISSING+=("OKTA_CLIENT_TOKEN")
[[ -z "${OKTA_ISSUER_URI:-}"    ]] && MISSING+=("OKTA_ISSUER_URI")
[[ -z "${OKTA_UI_CLIENT_ID:-}"  ]] && MISSING+=("OKTA_UI_CLIENT_ID")

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo ""
  echo "  ERROR: The following required environment variables are not set:"
  for v in "${MISSING[@]}"; do
    echo "    • $v"
  done
  echo ""
  echo "  See the header of this script for setup instructions."
  echo ""
  exit 1
fi

# ── Build if JAR is missing or source is newer ────────────────────────────
if [[ ! -f "$JAR" ]]; then
  echo ">>> JAR not found — building now..."
  cd "$PROJECT_DIR"
  mvn package -DskipTests -q
fi

# ── Launch ─────────────────────────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════════════════════════╗"
echo "  ║  Okta MCP Server                                            ║"
echo "  ║  JWT validation: ENABLED (real Okta tokens required)        ║"
echo "  ║                                                              ║"
echo "  ║  UI  → http://localhost:8080/                                ║"
echo "  ║  MCP → http://localhost:8080/mcp                             ║"
echo "  ║                                                              ║"
echo "  ║  Issuer:    $OKTA_ISSUER_URI"
echo "  ║  SPA Client: $OKTA_UI_CLIENT_ID"
echo "  ╚══════════════════════════════════════════════════════════════╝"
echo ""

exec java \
  -jar "$JAR" \
  --spring.profiles.active=local
