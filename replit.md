# AI Privacy & Security Reinforcement Dashboard

Sentinel is a lightweight security workspace for understanding account trust, privacy posture, network anomalies, and audit integrity.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server
- `pnpm --filter @workspace/privacy-security-dashboard run dev` — run the web dashboard
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — managed PostgreSQL connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `lib/api-spec/openapi.yaml` — source of truth for dashboard API contracts
- `lib/db/src/schema/security.ts` — users, sessions, privacy, intrusion, and audit tables
- `artifacts/api-server/src/routes/security.ts` — authentication and security API routes
- `artifacts/api-server/src/lib/security.ts` — PBKDF2, masking, privacy noise, sessions, and hash-chain helpers
- `artifacts/api-server/src/lib/isolation-forest.ts` — small dependency-free Isolation Forest scorer
- `artifacts/privacy-security-dashboard/src/` — responsive Sentinel web experience and pages

## Architecture decisions

- The dashboard uses the existing workspace Express/PostgreSQL runtime so it can share managed routing and database support while keeping the feature set low-resource.
- Authentication uses PBKDF2 password hashes and server-side, hashed session tokens in HTTP-only cookies.
- Intrusion scoring uses a small dependency-free Isolation Forest implementation to avoid heavyweight ML runtime dependencies.
- Audit records are tamper-evident through a SHA-256 hash chain; no blockchain or external service is required.
- Privacy demonstrations keep raw and noisy values side by side while masking email, username, and IP examples.

## Product

- Register and sign in with role-aware access control (Admin, Analyst, User)
- Review trust scores, account risk, privacy posture, suspicious traffic, and recent security activity
- Adjust privacy level and see Laplace-noised statistics
- Submit network features for anomaly detection and review historical traffic
- Verify and inspect SHA-256 chained audit records

## User preferences

No additional preferences recorded.

## Gotchas

- Run API codegen after changing `lib/api-spec/openapi.yaml`.
- The managed workflows provide `PORT` and `BASE_PATH`; do not run the Vite service directly without them.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
