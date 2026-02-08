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
 * Desktop Notifications Helper
 * 
 * Provides cross-platform desktop notifications with macOS support.
 * On non-macOS platforms, notifications are silently skipped.
 * 
 * @module utils/notifications
 */

import { spawn } from "child_process";

/**
 * Send a desktop notification (macOS only).
 * 
 * On macOS: Uses osascript to display a native notification.
 * On other platforms: Silently does nothing.
 * 
 * This function is non-blocking and fire-and-forget.
 * Errors are silently ignored to prevent disrupting the main application.
 * 
 * @param title - The notification title
 * @param message - The notification body text
 */
export function notifyDesktop(title: string, message: string): void {
    // Only macOS is supported
    if (process.platform !== "darwin") {
        return;
    }

    try {
        // Escape quotes in title and message to prevent osascript injection
        const safeTitle = title.replace(/"/g, '\\"');
        const safeMessage = message.replace(/"/g, '\\"');

        // Non-blocking spawn, fire-and-forget
        const proc = spawn("osascript", [
            "-e",
            `display notification "${safeMessage}" with title "${safeTitle}"`
        ], {
            stdio: "ignore",
            detached: true
        });

        // Don't wait for the process to complete
        proc.unref();
    } catch {
        // Silent fail - notifications are optional and should never break the server
    }
}
