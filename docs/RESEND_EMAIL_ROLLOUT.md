# Resend email integration — staged rollout

## Current state
The Resend email adapter has been added but is **not yet wired to public registration, login, or workspace invitations**. Do not describe email verification or invitation acceptance as operational. Existing accounts and signup behavior are unchanged.

## Configuration (Ubuntu backend)
Create a Resend account, verify a domain you control, and create an API key with sending permission. Store credentials only in the backend service environment (never in Git, React/Vite environment variables, browser code, screenshots, or chat).

- `RESEND_API_KEY` — secret server-side API key
- `RESEND_FROM_EMAIL` — sender on your verified domain, e.g. `security@example.com`
- `APP_PUBLIC_URL` — browser-accessible frontend origin, e.g. `http://localhost:5173` for local testing; use HTTPS for production

The adapter uses Node's built-in fetch (Node 18+), Resend's POST /emails endpoint, a 10-second timeout, escaped HTML, and sanitized provider errors. Do not expose verification/invitation tokens in logs.

## Required before activation
1. Add Sequelize migrations for one-time, SHA-256-hashed tokens with purpose, user/email, workspace, role, expiry, consumption time and rate limits. Store **only token hashes**, not raw tokens.
2. New public registrations must start **unverified**, receive a verification email, and not receive an authenticated session or access workspace resources before verification. Existing accounts must remain usable; define explicit migration/backfill rules.
3. Add verify-email and resend-verification endpoints with expiry, single-use atomic consumption, throttling, generic responses to prevent account enumeration, and recovery for provider delivery failures.
4. Add ADMIN-only invitation issuance and acceptance endpoints. Existing accounts should authenticate before accepting; new accounts should set their own password. Verify the invitation email, target workspace and membership constraints transactionally. Never grant platform ADMIN.
5. Add frontend routes for verification and invitation acceptance; show delivery errors without exposing tokens.
6. Test successful and expired links, replay, cross-workspace access, duplicate email, role escalation, mail failure, and concurrency before enabling in production.

**Do not set any verification-enforcement feature flag until the complete flow and migrations are deployed and tested.**
