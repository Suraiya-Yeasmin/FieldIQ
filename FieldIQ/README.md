# FieldIQ — Full-Stack PostgreSQL Upgrade (v1.2.1)

This package keeps the existing FieldIQ farmer-facing HTML interface and adds a Node.js/Express backend using PostgreSQL.

## Implemented in this package

- Real registration and database-backed email/password login.
- Password hashing with `bcryptjs` (cost factor 12); plaintext passwords are not stored.
- Unique case-insensitive email constraint in PostgreSQL.
- Opaque server-side sessions stored as SHA-256 token hashes in PostgreSQL.
- HttpOnly + SameSite=Strict session cookies; Secure cookies and `__Host-` prefix in production.
- Session rotation after login, server-side logout, expiry and periodic expired-session cleanup.
- CSRF token checks and strict same-origin checks for state-changing requests.
- Rate limiting on authentication endpoints; generic invalid-login response.
- Email verification and single-use 30-minute password reset tokens. Real SMTP is required; the app does not fake successful email delivery.
- Per-account JSONB data storage with a server-derived `user_id` for: calendar tasks, saved preferences, farms, fields, crop rotations, irrigation schedules, fertilizer reminders, harvest records, saved reports and preferences.
- Private farm and field forms (create/list/delete) connected to the account-owned data API; saved top crop-rotation strategies are also account-scoped.
- Guest Demo has separate local-storage keys for its farm, field and saved-strategy records; guest records are never sent to the account API.
- Read-only NASA POWER Daily API proxy for recent temperature, corrected precipitation and relative humidity at entered coordinates, with coordinate validation, 15-minute cache and request limits.
- Email verification now uses a confirmation page and a CSRF-protected POST, so automatic GET link previews do not consume verification tokens.
- API responses are marked no-store; user-data payload sizes and collection types are validated; writes have a rate limit.
- Guest mode remains separate and browser-local; it does not call private account-data endpoints.
- SQL parameterization, JSON request-size limits, Helmet security headers and database foreign-key constraints.

## Important honest limitations

1. The built-in Green Valley farm, A01/B02/C03 fields, crop traits, historical charts and risk indicators remain illustrative sample/reference data embedded in the HTML. The new private farm and field forms are separate account-owned records; they do not yet replace every sample analysis view.
2. Calendar tasks, saved preferences, private farms, private fields and saved crop-rotation strategy snapshots are connected to PostgreSQL. Irrigation, fertilizer, harvest and saved-report keys have owner-scoped storage support, but dedicated CRUD screens for each are not yet complete.
3. The NASA POWER card fetches live POWER meteorological time-series data when the server has internet access. The current crop-rotation engine still uses its clearly described demonstration dataset; it does not automatically feed NASA POWER values into recommendations. GPM/IMERG, SMAP and MODIS are not live-integrated in this package.
4. Email verification and password reset require working SMTP credentials and live testing. Registration is blocked before account creation if verification is required but SMTP is not configured.
5. The legacy HTML uses inline JavaScript and styles. Helmet security headers are enabled, but a strict Content-Security-Policy is intentionally not enabled in this compatibility pass. A nonce/hash-based CSP refactor is needed before production.
6. Rate limiting uses the process-local default store; multi-instance deployments should use a shared Redis store. This is not a penetration-tested or certified production system. Production deployment also needs HTTPS, backups, monitoring, secure secret management and an operational review.

## Requirements

- Node.js 22.13 or later (the current project runtime is compatible).
- npm.
- PostgreSQL 14 or later, running locally or hosted.

## Setup on Windows

### 1. Create a PostgreSQL database and user

Using pgAdmin or `psql`, create a database (for example `fieldiq`) and a dedicated database user. Grant that user access only to this database. Do not use the PostgreSQL superuser for the application.

Example SQL (change the password before running):

```sql
CREATE USER fieldiq_user WITH PASSWORD 'REPLACE_WITH_A_LONG_RANDOM_PASSWORD';
CREATE DATABASE fieldiq OWNER fieldiq_user;
```

### 2. Configure environment variables

- Open `backend/`.
- Copy `.env.example` to `.env`.
- Set `DATABASE_URL` to your PostgreSQL connection string.
- Generate a session secret:

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

- Paste that value into `SESSION_SECRET`.
- Keep `.env` private. Never upload it to GitHub.

### 3. Install and start

```bash
cd backend
npm install
npm run check
npm start
```

The backend creates the required tables/indexes automatically on startup. You can also inspect `backend/schema.sql`.

The complete project is split into `frontend/` and `backend/`. Express serves only the frontend directory, so backend source files are not exposed as static assets. Open **http://localhost:3000**. Do not open `frontend/FieldIQ.html` directly using `file://` because authentication requires the backend.

### 4. Configure real email

For real email verification and password reset, set `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, and `SMTP_FROM` in `.env`. Use credentials from an email provider you control. Restart the server after changing `.env`.

If SMTP is not configured, the app explicitly reports that verification/reset email delivery is unavailable. Do not turn off email verification for real farmer accounts just to bypass this requirement.

#### Gmail SMTP example

For a Gmail account with 2-Step Verification enabled, create a Google **App Password** (not your normal Gmail password), then configure these values in `backend/.env`:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=youraddress@gmail.com
SMTP_PASS=your-16-character-app-password
SMTP_FROM=FieldIQ <youraddress@gmail.com>
REQUIRE_EMAIL_VERIFICATION=true
```

Use your own verified sender address. Never paste the App Password into chat, source code, screenshots, or GitHub. Restart `npm.cmd start` after saving `.env`. A syntactically valid address is **not** proof that the mailbox exists: FieldIQ only marks it verified after the recipient receives the message and clicks the one-time verification link. If the message is not received, check Spam and the SMTP settings, then use **Resend verification email**.

## API overview

- `GET /api/health`
- `GET /api/auth/csrf`
- `GET /api/auth/me`
- `GET /api/nasa/power?lat=24.3745&lon=88.6042` (read-only NASA POWER daily point summary; recent ~45-day period)
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `POST /api/auth/resend-verification`
- `GET /api/auth/verify?token=...` (confirmation page only)
- `POST /api/auth/verify` (CSRF-protected token consumption)
- `POST /api/auth/forgot-password`
- `POST /api/auth/reset-password`
- `GET /api/user/data` (authenticated; returns only the current user's rows)
- `PUT /api/user/data` (authenticated + CSRF; server sets owner ID from session)

## Manual security test checklist

After configuring PostgreSQL and SMTP:

1. Open `/api/health`; expect `{ "ok": true, "database": "connected" }`.
2. Register a new email with a strong password.
3. Verify the email using the received one-time link.
4. Try registering the same email again; it must be rejected.
5. Sign in with the correct password; check that a session cookie is created.
6. Sign in with a wrong password; it must fail with a generic error.
7. Open `/api/user/data` while signed out; expect HTTP 401.
8. Add a private farm and field while signed in; refresh and sign in again; confirm they remain.
9. Save a crop-rotation strategy and calendar task; confirm both persist after re-login.
10. Create a second account; confirm it cannot read the first account's data.
11. Use Guest Demo; confirm its calendar, farms and fields remain browser-local and separate.
12. Repeatedly submit incorrect login attempts; expect rate limiting.
13. Request password reset; use the emailed link once; a second use must fail.
14. Open the NASA POWER card and request data for a known coordinate; confirm the latest date and units are shown and that the values are not labelled as a forecast.

## Production checklist

- Set `NODE_ENV=production`, `APP_ORIGIN=https://your-domain`, and use HTTPS end-to-end.
- Set `PGSSLMODE=require` for hosted PostgreSQL services that require TLS.
- Use a long random `SESSION_SECRET`; store it in the host's secret manager.
- Use a dedicated least-privilege PostgreSQL role, encrypted backups and tested restore procedures.
- Configure a shared rate-limit store for multiple backend instances.
- Add a nonce/hash-based Content-Security-Policy after refactoring inline scripts/styles.
- Complete dedicated irrigation/fertilizer/harvest/report forms and connect private records to field analytics before using real farmer data.
- Run dependency scanning, automated tests and an independent security review before public launch.

## v1.2 additions

- Account-owned private farm and field forms, plus saved crop-rotation strategy snapshots.
- Read-only NASA POWER daily point proxy with coordinate validation, timeout, request limiting and a 15-minute in-memory cache. Its results are displayed separately from the demo recommendation engine.
- Email verification uses a confirmation page and CSRF-protected POST; automatic GET link previews do not consume verification tokens.
- API responses are marked no-store; JSON collection types and payload sizes are validated; write requests are rate limited.

## Build verification performed for this handoff

- `npm run check` was run successfully: backend JavaScript syntax and both inline frontend JavaScript blocks parse.
- A live PostgreSQL/auth/SMTP integration test was **not** run in this environment because no PostgreSQL connection or SMTP credentials were provided. Run the setup and manual checklist above on your machine before demoing authentication.
