import {
  boolean,
  integer,
  pgTable,
  real,
  serial,
  text,
  timestamp,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const usersTable = pgTable("security_users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull(),
  email: text("email").notNull().unique(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("User"),
  trustScore: real("trust_score").notNull().default(82),
  failedLogins: integer("failed_logins").notNull().default(0),
  knownDevice: boolean("known_device").notNull().default(true),
  lastLogin: timestamp("last_login", { withTimezone: true }),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const sessionsTable = pgTable("security_sessions", {
  id: serial("id").primaryKey(),
  tokenHash: text("token_hash").notNull().unique(),
  userId: integer("user_id").notNull(),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const privacySettingsTable = pgTable("security_privacy_settings", {
  id: serial("id").primaryKey(),
  userId: integer("user_id").notNull().unique(),
  level: text("level").notNull().default("Medium"),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const intrusionEventsTable = pgTable("security_intrusion_events", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  duration: real("duration").notNull(),
  srcBytes: real("src_bytes").notNull(),
  dstBytes: real("dst_bytes").notNull(),
  failedLogins: integer("failed_logins").notNull(),
  packetCount: integer("packet_count").notNull(),
  connectionRate: real("connection_rate").notNull(),
  classification: text("classification").notNull(),
  anomalyScore: real("anomaly_score").notNull(),
  riskLevel: text("risk_level").notNull(),
  timestamp: timestamp("timestamp", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const auditLogsTable = pgTable("security_audit_logs", {
  id: serial("id").primaryKey(),
  userId: integer("user_id"),
  timestamp: timestamp("timestamp", { withTimezone: true })
    .notNull()
    .defaultNow(),
  eventType: text("event_type").notNull(),
  description: text("description").notNull(),
  riskScore: real("risk_score").notNull(),
  previousHash: text("previous_hash").notNull(),
  currentHash: text("current_hash").notNull(),
  actor: text("actor").notNull(),
});

export const insertUserSchema = createInsertSchema(usersTable).omit({
  id: true,
  createdAt: true,
});
export type InsertUser = z.infer<typeof insertUserSchema>;
export type SecurityUser = typeof usersTable.$inferSelect;
export type SecuritySession = typeof sessionsTable.$inferSelect;
export type PrivacySettings = typeof privacySettingsTable.$inferSelect;
export type IntrusionEvent = typeof intrusionEventsTable.$inferSelect;
export type AuditLog = typeof auditLogsTable.$inferSelect;