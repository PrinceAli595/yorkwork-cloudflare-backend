# Yorkwork Backend — Cloudflare Workers

This is the Cloudflare Workers version of the backend, replacing the
original Node/Express server on Render. It does everything the old one
did — contact form, visitor analytics, Stripe checkout, the admin
dashboard, and Drive-backed product images — but runs at Cloudflare's
edge instead of a single Render instance.

## What changed from the Render/Express version, and why

| Old (Render/Express)         | New (Cloudflare Workers)            | Why                                                               |
|-------------------------------|--------------------------------------|--------------------------------------------------------------------|
| `data/db.json` on local disk  | D1 (SQL database)                    | Workers have no local filesystem — nothing persists between requests |
| Local `images-cache/` folder  | Workers Cache API (`caches.default`) | Same reason — edge-native caching instead                        |
| Nodemailer + SMTP             | Resend's REST API via `fetch()`      | Workers cannot open raw TCP sockets, so SMTP libraries don't work |
| Node's `crypto` module        | Web Crypto API (`crypto.subtle`)     | Full Workers compatibility for session signing                   |
| `express.static('/admin')`    | Workers Assets binding               | Static files are deployed as build-time assets, not served from disk |

Routes, admin dashboard behaviour, price validation logic, and the
Drive-based image proxy all work exactly the same as before from the
outside — this is an infrastructure swap, not a feature change.

## Current status

- ✅ D1 database `yorkwork-db` already created via the Cloudflare dashboard
  (database_id already filled into `wrangler.toml`)
- ✅ Database schema already run against the live database (all 4 tables exist)
- ⬜ Secrets not yet set
- ⬜ Not yet deployed

## One-time setup

You'll need a Cloudflare account (free tier is fine) and Node.js installed.

```bash
npm install
npx wrangler login          # opens a browser to authorize the CLI
```

The D1 database and schema are already set up (see above) — no need to
run `wrangler d1 create` or the migration commands again unless you want
to reset it.

### 3. Set your secrets

These are never written to any file — Wrangler stores them securely on
Cloudflare's side. You'll be prompted to paste each value:

```bash
npx wrangler secret put ADMIN_PASSWORD
npx wrangler secret put SESSION_SECRET
npx wrangler secret put STRIPE_SECRET_KEY
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put SMTP_FROM        # e.g. "Yorkwork <onboarding@resend.dev>"
```

### 4. Deploy

```bash
npm run deploy
```

Wrangler prints your live URL — something like
`https://yorkwork-backend.<your-subdomain>.workers.dev`.

## After deploying

- Update the frontend's `BACKEND_URL` constant in `index.html` to point
  at this new Workers URL instead of the old Render one.
- Update `FRONTEND_URL` and `ALLOWED_ORIGIN` in `wrangler.toml` if your
  Netlify/Cloudflare Pages URL differs from what's currently set.
- Test the same way as before: a Stripe test checkout with
  `4242 4242 4242 4242`, and a real contact-form submission to confirm
  Resend email delivery.

## Local development

```bash
npm run dev
```

This runs the Worker locally with a local D1 database (from the
`db:migrate:local` step). Secrets set via `wrangler secret put` are
production-only — for local dev, create a `.dev.vars` file (never
commit this) with the same variable names and real or test values.

## Known limitation: rate limiting

The in-memory rate limiter is best-effort — Workers isolates aren't
guaranteed to persist between requests the way a single long-running
Node process does. For stricter rate limiting later, Cloudflare's own
Rate Limiting rules (configured in the dashboard, no code needed) or a
Durable Object would be the natural upgrade path.
