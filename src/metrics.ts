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
 * AgentRegistry Metrics Module
 * 
 * Time-series metrics collection for performance monitoring.
 * Tracks requests, cache hits, latency with rolling windows.
 * 
 * @module metrics
 */

// ============================================================================
// Circular Buffer for Time Series
// ============================================================================

interface MetricPoint {
    t: number;  // timestamp (ms)
    v: number;  // value
}

class CircularBuffer {
    private buffer: MetricPoint[];
    private size: number;
    private index: number = 0;
    private count: number = 0;

    constructor(size: number) {
        this.size = size;
        this.buffer = new Array(size);
    }

    push(value: number): void {
        this.buffer[this.index] = {
            t: Date.now(),
            v: value
        };
        this.index = (this.index + 1) % this.size;
        if (this.count < this.size) this.count++;
    }

    getAll(): MetricPoint[] {
        if (this.count === 0) return [];

        const result: MetricPoint[] = [];
        const start = this.count < this.size ? 0 : this.index;

        for (let i = 0; i < this.count; i++) {
            const idx = (start + i) % this.size;
            if (this.buffer[idx]) {
                result.push(this.buffer[idx]);
            }
        }

        return result;
    }

    getLast(): MetricPoint | null {
        if (this.count === 0) return null;
        const idx = (this.index - 1 + this.size) % this.size;
        return this.buffer[idx] || null;
    }

    clear(): void {
        this.buffer = new Array(this.size);
        this.index = 0;
        this.count = 0;
    }
}

// ============================================================================
// Metrics State
// ============================================================================

// Rolling windows for time-series data (60 points = 1 minute at 1/sec)
const requestsPerSecond = new CircularBuffer(60);
const avgLatency = new CircularBuffer(60);
const cacheHitRateHistory = new CircularBuffer(60);

// Counters (reset-able)
let totalRequests = 0;
let cacheHits = 0;
let cacheMisses = 0;
let totalLatencyMs = 0;
let requestsInCurrentSecond = 0;
let latencySumInCurrentSecond = 0;
let hitsInCurrentSecond = 0;
let missesInCurrentSecond = 0;

// Interval references
let aggregationInterval: Timer | null = null;

// ============================================================================
// Recording Functions
// ============================================================================

/**
 * Records a request with its latency and cache status.
 */
export function recordRequest(latencyMs: number, cacheHit: boolean): void {
    totalRequests++;
    totalLatencyMs += latencyMs;
    requestsInCurrentSecond++;
    latencySumInCurrentSecond += latencyMs;

    if (cacheHit) {
        cacheHits++;
        hitsInCurrentSecond++;
    } else {
        cacheMisses++;
        missesInCurrentSecond++;
    }
}

/**
 * Records a security event (blocked package, scan, etc.)
 */
export function recordSecurityEvent(type: "block" | "quarantine" | "scan"): void {
    // Future: track security events separately
}

// ============================================================================
// Aggregation (runs every second)
// ============================================================================

function aggregateSecond(): void {
    // Push requests/second
    requestsPerSecond.push(requestsInCurrentSecond);

    // Push average latency for this second
    if (requestsInCurrentSecond > 0) {
        avgLatency.push(latencySumInCurrentSecond / requestsInCurrentSecond);
    } else {
        avgLatency.push(0);
    }

    // Push cache hit rate for this second
    const totalInSecond = hitsInCurrentSecond + missesInCurrentSecond;
    if (totalInSecond > 0) {
        cacheHitRateHistory.push((hitsInCurrentSecond / totalInSecond) * 100);
    }

    // Reset per-second counters
    requestsInCurrentSecond = 0;
    latencySumInCurrentSecond = 0;
    hitsInCurrentSecond = 0;
    missesInCurrentSecond = 0;
}

// ============================================================================
// Metrics Snapshot
// ============================================================================

export interface MetricsSnapshot {
    requestsPerSecond: MetricPoint[];
    avgLatencyMs: MetricPoint[];
    cacheHitRateHistory: MetricPoint[];
    currentRps: number;
    currentLatencyMs: number;
    overallCacheHitRate: number;
    totalRequests: number;
    cacheHits: number;
    cacheMisses: number;
    uptimeSeconds: number;
}

const startTime = Date.now();

/**
 * Returns a complete snapshot of all metrics.
 */
export function getMetricsSnapshot(): MetricsSnapshot {
    const rpsData = requestsPerSecond.getAll();
    const latencyData = avgLatency.getAll();
    const hitRateData = cacheHitRateHistory.getAll();

    // Current values (last point or calculation)
    const lastRps = requestsPerSecond.getLast();
    const lastLatency = avgLatency.getLast();
    const overallHitRate = (cacheHits + cacheMisses) > 0
        ? (cacheHits / (cacheHits + cacheMisses)) * 100
        : 100;

    return {
        requestsPerSecond: rpsData,
        avgLatencyMs: latencyData,
        cacheHitRateHistory: hitRateData,
        currentRps: lastRps?.v ?? 0,
        currentLatencyMs: lastLatency?.v ?? 0,
        overallCacheHitRate: Math.round(overallHitRate * 10) / 10,
        totalRequests,
        cacheHits,
        cacheMisses,
        uptimeSeconds: Math.floor((Date.now() - startTime) / 1000)
    };
}

// ============================================================================
// Lifecycle
// ============================================================================

/**
 * Starts the metrics aggregation interval.
 */
export function startMetricsCollection(): void {
    if (aggregationInterval) return;
    aggregationInterval = setInterval(aggregateSecond, 1000);
}

/**
 * Stops the metrics aggregation interval.
 */
export function stopMetricsCollection(): void {
    if (aggregationInterval) {
        clearInterval(aggregationInterval);
        aggregationInterval = null;
    }
}

/**
 * Resets all metrics to zero.
 */
export function resetMetrics(): void {
    totalRequests = 0;
    cacheHits = 0;
    cacheMisses = 0;
    totalLatencyMs = 0;
    requestsInCurrentSecond = 0;
    latencySumInCurrentSecond = 0;
    hitsInCurrentSecond = 0;
    missesInCurrentSecond = 0;

    requestsPerSecond.clear();
    avgLatency.clear();
    cacheHitRateHistory.clear();
}

// Auto-start on import
startMetricsCollection();
