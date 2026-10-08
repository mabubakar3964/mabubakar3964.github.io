CREATE TABLE "app_config" (
	"id" integer PRIMARY KEY,
	"settings" jsonb DEFAULT '{}' NOT NULL,
	"version" integer DEFAULT 0 NOT NULL,
	"password_hash" text,
	"password_version" integer DEFAULT 1 NOT NULL,
	"updated_at" timestamp DEFAULT now()
);
