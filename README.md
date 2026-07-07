# pulsefy.tools

Generic event monitoring & alerting SaaS. Wire any app event to Telegram / Slack / webhook via rule-based thresholds.

## Deployment

Runs on DigitalOcean droplet as systemd service `pulsefy` on `127.0.0.1:8093`, fronted by nginx on `pulsefy.tools`.

Reads events read-only from `searchads.tools` events database (`/root/.friday-asa/asa.db`) — production shares that ingestion pipeline for now. Own SQLite for users / sessions / apps: `/opt/pulsefy/state/pulsefy.db`.

## Structure

- `server.js` — HTTP + rule engine + SSE (dependency-free, node:http)
- `public/` — landing.html, auth.html, onboarding.html, app.html
- `config/` — rules.json, integrations.json (NOT tracked)
- `state/` — SQLite users/sessions/apps + alarms.jsonl (NOT tracked)

## Multi-tenancy

Each user claims apps via `application_token` (the same UUID indie-apps send to the events ingest). Cross-checked against `asa_accounts.app_token` in the events DB. Events queries filter by user's claimed `asa_account_id`s.

## Routes

- `/` — landing (public) or 302 → /app (auth)
- `/login` `/register` — auth form
- `/onboarding` — first-app claim (auth, no apps)
- `/app` — dashboard (auth, ≥1 app)
- `/api/auth/*` — register / login / logout / me
- `/api/apps` — CRUD
- `/api/events` — filtered feed
- `/api/events/live` — SSE (filtered)
- `/api/events/summary` — event count breakdown
- `/api/rules` — CRUD
- `/api/integrations` — telegram / slack / webhook config
- `/api/alarms` — fired alarm history

## Rule engine

Runs every 60s. Per rule:
- events + window + threshold + severity
- optional `filter_props.error_contains`
- cooldown per rule-signature (deduped by first ~60 chars of error message)
- fans out to configured channels
