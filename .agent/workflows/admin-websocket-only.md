---
description: Admin panel uses WebSocket-only authentication - no HTTP endpoints for admin operations
---
# WebSocket-Only Admin Panel Rule

All admin panel operations SHOULD use authenticated WebSocket connections. HTTP endpoints require `X-Admin-Token` header.

## Why
- HTTP endpoints require `X-Admin-Token` header for authentication
- WebSocket requires ADMIN_SESSION_TOKEN before upgrade
- WebSocket is preferred for real-time updates

## Allowed HTTP Endpoints
- `GET /-/admin` - Serve HTML panel (injects token)
- `GET /assets/*` - Static files  
- `GET /health`, `GET /-/ping` - Public health checks

## All Other Admin Operations
Use WebSocket messages with format:
```json
{ "action": "actionName", "payload": { ... } }
```

Available actions:
- `getStats`, `getMetrics`, `getAuditLogs`, `getScanHistory`, `getRequestLogs`
- `getCache`, `getQuarantine`, `clearQuarantine`, `rescanQuarantine`
- `getAllowlist`, `updateAllowlistConfig`, `addAllowlistEntry`, `removeAllowlistEntry`, `toggleAllowlistEntry`, `checkIP`
- `getCVESummary`, `getAllCVEs`, `scanPackageCVE`, `scanAllCVEs`
- `exportAudit`, `exportAuditCSV`
- `getGraphRoots`, `getGraphNode`

## Frontend Implementation
Replace `fetch('/-/admin/...')` calls with:
```javascript
ws.send(JSON.stringify({ action: 'actionName', payload: { ... } }));
```
