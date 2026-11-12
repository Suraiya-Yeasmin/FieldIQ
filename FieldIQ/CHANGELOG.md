# Changelog

## 1.2.1
- Clarified the real SMTP setup required for email verification and password reset, including Gmail App Password configuration.
- Documented that a syntactically valid email address is only verified after mailbox access is confirmed through the one-time link.
- Reconfirmed that email verification stays enabled by default and SMTP credentials must remain in the local `.env` file.


## 1.2.0
- Added account-owned private farm and field create/list/delete screens.
- Added account-owned saved crop-rotation strategy snapshots.
- Kept private account records separate from Guest Demo browser-local records.
- Added a read-only NASA POWER Daily Point proxy and a separate live-observation panel.
- Changed email verification so GET only renders a confirmation page; token consumption requires a CSRF-protected POST.
- Added no-store API response headers, bounded JSON payloads, collection-shape validation and write rate limiting.
- Kept the demo crop-rotation engine separate from NASA POWER observations until scientific validation is complete.

## 1.1.0
- Added PostgreSQL-backed registration, login and server-side sessions.
- Added password hashing, CSRF checks, session expiry, email verification and password-reset workflows.
