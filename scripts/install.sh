#!/bin/bash
# AgentRegistry launchd Install Script
# Installs AgentRegistry as a macOS launchd service for auto-start on boot

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENTREGISTRY_DIR="$(dirname "$SCRIPT_DIR")"
PLIST_NAME="com.agentregistry.daemon.plist"
PLIST_SRC="$SCRIPT_DIR/$PLIST_NAME"
PLIST_DEST="$HOME/Library/LaunchAgents/$PLIST_NAME"
LOG_DIR="$HOME/.agentregistry/logs"

LOG_DIR="$HOME/.agentregistry/logs"

# Check if running as root
if [ "$EUID" -eq 0 ]; then
   echo "❌ Error: Do not run this script as root/sudo."
   echo "   Launchd agents must be installed as the target user."
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

# Create log directory
mkdir -p "$LOG_DIR"
echo "   Created log directory: $LOG_DIR"

# Create .agentregistry directory
mkdir -p "$HOME/.agentregistry"

# Check if already installed
if [ -f "$PLIST_DEST" ]; then
    echo "   Unloading existing service..."
    launchctl unload "$PLIST_DEST" 2>/dev/null || true
fi

# Copy and configure plist
echo "   Configuring plist..."
sed -e "s|__BUN_PATH__|$BUN_PATH|g" \
    -e "s|__AGENTREGISTRY_PATH__|$AGENTREGISTRY_DIR|g" \
    -e "s|__HOME__|$HOME|g" \
    -e "s|__USER__|$USER|g" \
    "$PLIST_SRC" > "$PLIST_DEST"

# Set permissions
chmod 644 "$PLIST_DEST"

# Load the service
echo "   Loading service..."
launchctl load "$PLIST_DEST"

# Wait a moment for startup
sleep 2

# Check if running
if launchctl list | grep -q "com.agentregistry.daemon"; then
    echo ""
    echo "✅ AgentRegistry installed successfully!"
    echo ""
    echo "   Service: com.agentregistry.daemon"
    echo "   Plist: $PLIST_DEST"
    echo "   Logs: $LOG_DIR"
    echo ""
    echo "   The service will:"
    echo "   • Start automatically on login"
    echo "   • Restart automatically if it crashes"
    echo ""
    echo "   Manage with:"
    echo "   • launchctl stop com.agentregistry.daemon"
    echo "   • launchctl start com.agentregistry.daemon"
    echo "   • ./scripts/uninstall.sh"
    echo ""
    echo "   Or use the AgentRegistry CLI:"
    echo "   • bun run cli.ts status"
    echo "   • bun run cli.ts logs"
else
    echo "❌ Failed to start service"
    echo "   Check logs at: $LOG_DIR/launchd-stderr.log"
    exit 1
fi
