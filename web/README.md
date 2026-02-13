# secrt web foundation

This is the Preact frontend foundation for the Rust server.

## Goals

- Same-origin browser app against `/api/v1/*`
- Reusable UI/domain modules for a future Tauri shell
- Keep server-side crypto responsibilities unchanged (all client-side encryption remains in app code)

## Commands

```sh
cd web
pnpm install
pnpm run dev
pnpm run build
```

## Serving with `secrt-server`

`secrt-server` already serves static files from `/static/*`.

- Build frontend to `web/dist`
- Set `SECRT_WEB_DIST_DIR=/absolute/path/to/web/dist`
- Run server and load assets from `/static`

Current API routes and static assets are same-origin, so no CORS middleware is required for this milestone.
