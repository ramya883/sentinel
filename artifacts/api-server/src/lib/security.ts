import { createHash, randomBytes, pbkdf2Sync, timingSafeEqual } from "node:crypto";
import { and, asc, count, desc, eq, sql } from "drizzle-orm";
import {
  auditLogsTable,
  db,
  intrusionEventsTable,
  privacySettingsTable,
  usersTable,
  sessionsTable,
  type SecurityUser,
} from "@workspace/db";

import { broadcastRealtimeEvent } from "./sse";

export type Role = "Admin" | "Analyst" | "User";
export type RiskLevel = "Low" | "Medium" | "High";
export type PrivacyLevel = "Low" | "Medium" | "High";

const HASH_ITERATIONS = 120_000;
const HASH_KEY_LENGTH = 32;
const HASH_DIGEST = "sha256";
const SESSION_DAYS = 7;

export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const derived = pbkdf2Sync(
    password,
    salt,
    HASH_ITERATIONS,
    HASH_KEY_LENGTH,
    HASH_DIGEST,
  ).toString("hex");
  return `pbkdf2$${HASH_ITERATIONS}$${salt}$${derived}`;
}

export function verifyPassword(password: string, encoded: string): boolean {
  const [, iterations, salt, expected] = encoded.split("$");
  if (!iterations || !salt || !expected) return false;
  const actual = pbkdf2Sync(
    password,
    salt,
    Number(iterations),
    HASH_KEY_LENGTH,
    HASH_DIGEST,
  );
  const expectedBuffer = Buffer.from(expected, "hex");
  return (
    expectedBuffer.length === actual.length &&
    timingSafeEqual(expectedBuffer, actual)
  );
}

export function hashSessionToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!domain) return "••••••";
  const visible = local.length > 2 ? local.slice(0, 2) : local.slice(0, 1);
  return `${visible}${"•".repeat(Math.max(2, local.length - visible.length))}@${domain}`;
}

export function maskUsername(username: string): string {
  if (username.length <= 2) return `${username.slice(0, 1)}••`;
  return `${username.slice(0, 2)}${"•".repeat(Math.max(2, username.length - 2))}`;
}

export function maskIp(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4) return "•••.•••.•••.•••";
  return `${parts[0]}.•••.•••.${parts[3]}`;
}

export function riskFromTrust(trustScore: number): RiskLevel {
  if (trustScore < 55) return "High";
  if (trustScore < 78) return "Medium";
  return "Low";
}

export function trustScoreFor(user: Pick<SecurityUser, "failedLogins" | "knownDevice">): number {
  const score = 100 - user.failedLogins * 8 - (user.knownDevice ? 0 : 18);
  return Math.max(0, Math.min(100, Math.round(score)));
}

export async function getUserBySessionToken(token: string | undefined): Promise<SecurityUser | null> {
  if (!token) return null;
  const [session] = await db
    .select()
    .from(sessionsTable)
    .where(
      and(
        eq(sessionsTable.tokenHash, hashSessionToken(token)),
        sql`${sessionsTable.expiresAt} > now()`,
      ),
    )
    .limit(1);
  if (!session) return null;
  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, session.userId))
    .limit(1);
  return user ?? null;
}

export async function createSession(userId: number): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await db.insert(sessionsTable).values({
    tokenHash: hashSessionToken(token),
    userId,
    expiresAt,
  });
  return token;
}

export async function deleteSession(token: string | undefined): Promise<void> {
  if (!token) return;
  await db
    .delete(sessionsTable)
    .where(eq(sessionsTable.tokenHash, hashSessionToken(token)));
}

export function cookieOptions() {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: process.env.NODE_ENV === "production",
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
    path: "/",
  };
}

export async function appendAuditLog(input: {
  userId?: number | null;
  eventType: string;
  description: string;
  riskScore: number;
  actor: string;
}) {
  const [previous] = await db
    .select({ currentHash: auditLogsTable.currentHash })
    .from(auditLogsTable)
    .orderBy(desc(auditLogsTable.id))
    .limit(1);
  const timestamp = new Date();
  const previousHash = previous?.currentHash ?? "GENESIS";
  const payload = [
    timestamp.toISOString(),
    input.eventType,
    input.description,
    input.riskScore.toFixed(2),
    previousHash,
    input.actor,
  ].join("|");
  const currentHash = createHash("sha256").update(payload).digest("hex");
  const [row] = await db
    .insert(auditLogsTable)
    .values({
      userId: input.userId ?? null,
      timestamp,
      eventType: input.eventType,
      description: input.description,
      riskScore: input.riskScore,
      previousHash,
      currentHash,
      actor: input.actor,
    })
    .returning();
  broadcastRealtimeEvent("audit_log", {
    id: row.id,
    timestamp: row.timestamp.toISOString(),
    eventType: row.eventType,
    description: row.description,
    riskScore: row.riskScore,
    previousHash: row.previousHash,
    currentHash: row.currentHash,
    actor: row.actor,
  });
  return row;
}

export async function verifyAuditChain() {
  const rows = await db
    .select()
    .from(auditLogsTable)
    .orderBy(asc(auditLogsTable.id));
  let previousHash = "GENESIS";
  for (const row of rows) {
    const payload = [
      row.timestamp.toISOString(),
      row.eventType,
      row.description,
      row.riskScore.toFixed(2),
      row.previousHash,
      row.actor,
    ].join("|");
    const expected = createHash("sha256").update(payload).digest("hex");
    if (row.previousHash !== previousHash || row.currentHash !== expected) {
      return { valid: false, checked: rows.length, message: `Integrity check failed at event ${row.id}.` };
    }
    previousHash = row.currentHash;
  }
  return {
    valid: true,
    checked: rows.length,
    message: rows.length ? "All audit records match the SHA-256 chain." : "No audit records to verify yet.",
  };
}

export function epsilonFor(level: PrivacyLevel): number {
  return level === "Low" ? 2 : level === "Medium" ? 1 : 0.35;
}

export function laplaceNoise(scale: number): number {
  const uniform = Math.random() - 0.5;
  return -scale * Math.sign(uniform) * Math.log(1 - 2 * Math.abs(uniform));
}

export async function getPrivacyLevel(userId: number): Promise<PrivacyLevel> {
  const [settings] = await db
    .select()
    .from(privacySettingsTable)
    .where(eq(privacySettingsTable.userId, userId))
    .limit(1);
  return (settings?.level as PrivacyLevel | undefined) ?? "Medium";
}

let seedPromise: Promise<void> | null = null;

export async function ensureDefaultAdmin(): Promise<SecurityUser> {
  let [admin] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, "admin@sentinel.local"))
    .limit(1);
  if (!admin) {
    [admin] = await db
      .insert(usersTable)
      .values({
        username: "Admin",
        email: "admin@sentinel.local",
        passwordHash: hashPassword("password123"),
        role: "Admin",
        trustScore: 100,
        failedLogins: 0,
        knownDevice: true,
      })
      .returning();
    await db
      .insert(privacySettingsTable)
      .values({ userId: admin.id, level: "Medium" })
      .onConflictDoNothing();
  }
  return admin;
}

export function ensureDemoData(): Promise<void> {
  seedPromise ??= (async () => {
    const firstUser = await ensureDefaultAdmin();
    const [{ eventCount }] = await db
      .select({ eventCount: count() })
      .from(intrusionEventsTable);
    if (Number(eventCount) > 0) return;

    const samples = [
      [0.18, 1240, 2980, 0, 42, 3.2],
      [0.24, 1860, 3410, 0, 56, 4.1],
      [0.31, 2200, 4100, 1, 62, 5.2],
      [0.14, 980, 1920, 0, 35, 2.6],
      [0.42, 3100, 5200, 1, 88, 7.1],
      [0.27, 1560, 2860, 0, 48, 3.8],
      [0.22, 1320, 2560, 0, 44, 3.4],
      [0.36, 2480, 4300, 1, 71, 5.8],
      [0.19, 1120, 2300, 0, 38, 2.9],
      [8.4, 158000, 4200, 9, 1320, 86.5],
      [4.8, 89000, 6200, 6, 840, 62.1],
      [2.9, 45600, 9800, 4, 490, 44.7],
      [0.26, 1980, 3700, 0, 58, 4.7],
      [0.21, 1430, 2720, 0, 46, 3.5],
      [6.2, 124000, 3600, 8, 1100, 79.2],
      [0.34, 2600, 4900, 1, 76, 6.2],
      [0.17, 1010, 2040, 0, 36, 2.8],
      [3.7, 67800, 7400, 5, 610, 52.8],
    ] as const;
    await db.insert(intrusionEventsTable).values(
      samples.map(([duration, srcBytes, dstBytes, failedLogins, packetCount, connectionRate], index) => {
        const anomalyScore = index >= 9 && index !== 12 ? 0.84 - (index % 3) * 0.04 : 0.18 + (index % 4) * 0.07;
        return {
          userId: firstUser.id,
          duration,
          srcBytes,
          dstBytes,
          failedLogins,
          packetCount,
          connectionRate,
          classification: anomalyScore >= 0.62 ? "Suspicious" : "Normal",
          anomalyScore,
          riskLevel: anomalyScore >= 0.78 ? "High" : anomalyScore >= 0.62 ? "Medium" : "Low",
          timestamp: new Date(Date.now() - (samples.length - index) * 3_600_000),
        };
      }),
    );
  })();
  return seedPromise;
}