import { pgTable, integer, jsonb, text, timestamp } from "drizzle-orm/pg-core";

// Single-row table (id = 1) holding the shared settings pushed from the main device.
export const appConfig = pgTable("app_config", {
  id: integer().primaryKey(),
  settings: jsonb().notNull().default({}),
  version: integer().notNull().default(0),
  passwordHash: text("password_hash"),
  passwordVersion: integer("password_version").notNull().default(1),
  updatedAt: timestamp("updated_at").defaultNow(),
});
