import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import { drizzle as drizzlePglite } from "drizzle-orm/pglite";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import * as schema from "./schema";

import fs from "node:fs";

const { Pool } = pg;

export let db: any;
export let pool: any = null;

if (process.env.DATABASE_URL) {
  pool = new Pool({ connectionString: process.env.DATABASE_URL });
  db = drizzlePg(pool, { schema });
} else {
  const pglite = new PGlite("memory://");
  db = drizzlePglite(pglite, { schema });
  
  await pglite.exec(`
    CREATE TABLE IF NOT EXISTS security_users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'User',
      trust_score REAL NOT NULL DEFAULT 82,
      failed_logins INTEGER NOT NULL DEFAULT 0,
      known_device BOOLEAN NOT NULL DEFAULT true,
      last_login TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS security_sessions (
      id SERIAL PRIMARY KEY,
      token_hash TEXT NOT NULL UNIQUE,
      user_id INTEGER NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS security_privacy_settings (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL UNIQUE,
      level TEXT NOT NULL DEFAULT 'Medium',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS security_intrusion_events (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      duration REAL NOT NULL,
      src_bytes REAL NOT NULL,
      dst_bytes REAL NOT NULL,
      failed_logins INTEGER NOT NULL,
      packet_count INTEGER NOT NULL,
      connection_rate REAL NOT NULL,
      classification TEXT NOT NULL,
      anomaly_score REAL NOT NULL,
      risk_level TEXT NOT NULL,
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS security_audit_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      event_type TEXT NOT NULL,
      description TEXT NOT NULL,
      risk_score REAL NOT NULL,
      previous_hash TEXT NOT NULL,
      current_hash TEXT NOT NULL,
      actor TEXT NOT NULL
    );
  `);
}

export * from "./schema";
