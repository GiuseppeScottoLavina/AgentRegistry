#!/bin/bash
# AgentRegistry launchd Uninstall Script
# Removes AgentRegistry launchd service

set -e

PLIST_NAME="com.agentregistry.daemon.plist"
PLIST_PATH="$HOME/Library/LaunchAgents/$PLIST_NAME"

echo "🛑 Uninstalling AgentRegistry launchd service..."

if [ ! -f "$PLIST_PATH" ]; then
    echo "⚠️  Service not installed (plist not found)"
    exit 0
fi

# Stop and unload the service
echo "   Stopping service..."
launchctl stop com.agentregistry.daemon 2>/dev/null || true
launchctl unload "$PLIST_PATH" 2>/dev/null || true

# Remove plist
echo "   Removing plist..."
rm -f "$PLIST_PATH"

echo ""
echo "✅ AgentRegistry service uninstalled successfully!"
echo ""
echo "   Note: Log files preserved at ~/.agentregistry/logs"
echo "   To remove all data: rm -rf ~/.agentregistry"
