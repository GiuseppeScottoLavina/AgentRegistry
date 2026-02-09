#!/bin/bash
# AgentRegistry launchd Install Script
# Installs AgentRegistry as a macOS launchd service for auto-start on login

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTREGISTRY_DIR="$(dirname "$SCRIPT_DIR")"
PLIST_NAME="com.agentregistry.daemon.plist"
PLIST_SRC="$SCRIPT_DIR/$PLIST_NAME"
PLIST_DEST="$HOME/Library/LaunchAgents/$PLIST_NAME"
LOG_DIR="$HOME/.agentregistry/logs"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
   echo "❌ Error: Do not run this script as root/sudo."
   echo "   Launchd agents must be installed as the target user."
   exit 1
fi

# Check OS
if [ "$(uname)" != "Darwin" ]; then
    echo "❌ Error: This script is for macOS only."
    echo "   On Linux, use systemd or supervisord."
    exit 1
fi

echo "🚀 Installing AgentRegistry launchd service..."

# Check for bun
BUN_PATH=$(which bun 2>/dev/null || echo "")
if [ -z "$BUN_PATH" ]; then
    echo "❌ Error: bun not found in PATH"
    echo "   Install bun: curl -fsSL https://bun.sh/install | bash"
    exit 1
fi
echo "   Found bun: $BUN_PATH"

# Verify server.ts exists
SERVER_PATH="$AGENTREGISTRY_DIR/src/server.ts"
if [ ! -f "$SERVER_PATH" ]; then
    echo "❌ Error: server.ts not found at $SERVER_PATH"
    echo "   Make sure you are running install.sh from the scripts/ directory."
    exit 1
fi
echo "   Found server: $SERVER_PATH"

# Create directories
mkdir -p "$LOG_DIR"
mkdir -p "$HOME/.agentregistry/storage"
echo "   Created directories: $HOME/.agentregistry"

# Unload if already installed
if [ -f "$PLIST_DEST" ]; then
    echo "   Unloading existing service..."
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
    sleep 1
fi

# Generate plist from template with path substitution
echo "   Configuring plist..."
sed -e "s|__BUN_PATH__|$BUN_PATH|g" \
    -e "s|__AGENTREGISTRY_PATH__|$AGENTREGISTRY_DIR|g" \
    -e "s|__HOME__|$HOME|g" \
    "$PLIST_SRC" > "$PLIST_DEST"

# Set permissions
chmod 644 "$PLIST_DEST"

# Verify the generated plist doesn't have placeholder artifacts
if grep -q "__BUN_PATH__\|__AGENTREGISTRY_PATH__\|__HOME__" "$PLIST_DEST"; then
    echo "❌ Error: Plist template substitution failed"
    echo "   Placeholders still present in $PLIST_DEST"
    cat "$PLIST_DEST"
    exit 1
fi

# Verify the path in the plist is correct (no double src/src/)
if grep -q "src/src/" "$PLIST_DEST"; then
    echo "❌ Error: Double src/ path detected in plist — this is a known bug."
    exit 1
fi

echo "   Plist verified: $PLIST_DEST"

# Load the service
echo "   Loading service..."
launchctl load "$PLIST_DEST"

# Wait for startup
echo "   Waiting for server startup..."
sleep 3

# Health check
HEALTH_OK=false
for i in 1 2 3; do
    if curl -s http://localhost:4873/-/ping > /dev/null 2>&1; then
        HEALTH_OK=true
        break
    fi
    sleep 1
done

if [ "$HEALTH_OK" = true ]; then
    echo ""
    echo "✅ AgentRegistry installed and running!"
    echo ""
    echo "   Service:     com.agentregistry.daemon"
    echo "   Admin Panel: http://localhost:4873/-/admin"
    echo "   Logs:        $LOG_DIR"
    echo "   Plist:       $PLIST_DEST"
    echo ""
    echo "   The service will:"
    echo "   • Start automatically on login"
    echo "   • Restart automatically if it crashes"
    echo ""
    echo "   Manage with:"
    echo "   • launchctl stop com.agentregistry.daemon"
    echo "   • launchctl start com.agentregistry.daemon"
    echo "   • bun run cli -- status"
    echo "   • ./scripts/uninstall.sh"
else
    echo ""
    echo "⚠️  Service loaded but server not responding yet."
    echo "   Check logs: tail -f $LOG_DIR/launchd-stderr.log"
    echo ""
    echo "   Common fix: sudo launchctl limit maxfiles 524288 524288"
    exit 1
fi
