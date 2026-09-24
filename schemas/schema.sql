-- Yorkwork backend D1 schema — replaces the old data/db.json file store.
-- Run locally with: npx wrangler d1 execute yorkwork-db --local --file=./schemas/schema.sql
-- Run in production with: npx wrangler d1 execute yorkwork-db --remote --file=./schemas/schema.sql

DROP TABLE IF EXISTS contacts;
DROP TABLE IF EXISTS pageviews;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS settings;

CREATE TABLE contacts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  subject TEXT,
  message TEXT NOT NULL,
  read INTEGER NOT NULL DEFAULT 0,
  email_sent INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE pageviews (
  id TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  referrer TEXT,
  utm_source TEXT,
  utm_medium TEXT,
  session_id TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_pageviews_created_at ON pageviews(created_at);

CREATE TABLE orders (
  session_id TEXT PRIMARY KEY,
  email TEXT,
  amount REAL NOT NULL,
  items_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  delivery TEXT DEFAULT ''
);

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
INSERT INTO settings (key, value) VALUES ('forwardEmails', '[]');
