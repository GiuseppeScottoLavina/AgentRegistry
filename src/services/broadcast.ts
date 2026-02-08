/* 
 * Copyright 2026 Giuseppe Scotto Lavina
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * AgentRegistry Broadcast Service
 * 
 * WebSocket-based real-time communication with admin panel.
 * Handles single-session enforcement and event broadcasting.
 * 
 * @module services/broadcast
 */

import type { ServerWebSocket } from "bun";

// ============================================================================
// WebSocket State
// ============================================================================

/** Currently connected admin WebSocket (single session only) */
let adminWs: ServerWebSocket<any> | null = null;

/** Server start time for uptime calculation */
export const SERVER_START_TIME = Date.now();

// ============================================================================
// Session Management
// ============================================================================

/**
 * Sets the active admin WebSocket connection.
 * Enforces single-session by closing previous connection.
 * 
 * @param ws - New WebSocket connection (or null to clear)
 */
export function setAdminWs(ws: ServerWebSocket<any> | null): void {
    if (adminWs && ws && adminWs !== ws) {
        // Close previous session
        try {
            adminWs.close(4001, "Session replaced");
        } catch { }
    }
    adminWs = ws;
}

// ============================================================================
// Broadcasting
// ============================================================================

/**
 * Broadcasts an event to the connected admin panel.
 * Used for real-time updates (package published, blocked, etc.)
 * 
 * @param eventType - Type of event (e.g., "package_published")
 * @param data - Event payload data
 * 
 * @example
 * broadcastToAdmin("package_blocked", { name: "malicious-pkg", issues: 5 });
 */
export function broadcastToAdmin(eventType: string, data: any): void {
    if (adminWs && adminWs.readyState === 1) {
        try {
            adminWs.send(JSON.stringify({
                type: "broadcast",
                event: eventType,
                data,
                timestamp: Date.now()
            }));
        } catch (error) {
            console.error("Failed to broadcast to admin:", error);
        }
    }
}

// ============================================================================
// Stats
// ============================================================================

/**
 * Gets server uptime in seconds.
 * 
 * @returns Uptime in seconds
 */
export function getUptimeSeconds(): number {
    return Math.floor((Date.now() - SERVER_START_TIME) / 1000);
}
