/**
 * AgentRegistry Type Definitions
 * 
 * Shared interfaces for package metadata and registry operations.
 */

/**
 * Represents a single version of a package with its metadata and distribution info.
 */
export interface PackageVersion {
    name: string;
    version: string;
    description?: string;
    main?: string;
    scripts?: Record<string, string>;
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
    dist: {
        tarball: string;
        shasum: string;
        integrity?: string;
    };
    [key: string]: unknown;
}

/**
 * Full package metadata as stored in the registry.
 */
export interface PackageMetadata {
    name: string;
    description?: string;
    "dist-tags": Record<string, string>;
    versions: Record<string, PackageVersion>;
    time: Record<string, string>;
    _id: string;
    _rev: string;
}

/**
 * WebSocket connection data for authentication state.
 */
export interface WebSocketData {
    authenticated: boolean;
}
