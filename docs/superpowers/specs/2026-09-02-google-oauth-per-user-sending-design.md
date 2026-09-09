# Per-User Google Sign-In and Sending — Design

**Date:** 2026-09-02
**Repo:** JoKage-LS/EmailApp (`lifeswitch-email`)
**Status:** Approved for planning

## Problem

The app is being handed over so any LifeSwitch staff member can use it. Two things block that today:

1. **No authentication.** All four API endpoints are open to the public internet.
2. **One hardcoded sender.** Every email goes out from the single account in `GMAIL_USER`, so the app is tied to one person's mailbox.

## Goals

- Any `@lifeswitch.org.nz` staff member can sign in and use the app.
- Email sends from the signed-in user's own account and lands in their own Sent folder.
- Nobody outside the domain can reach the app or its endpoints.
- No password — shared or personal — is created, stored, or transmitted.

## Non-Goals

- Per-user permissions or roles. Any authenticated domain user gets full access.
- Persistent sessions across days. Sessions last one Google access-token lifetime.
- Audit logging of who sent what.
- Changes to email templating, Planning Center integration, or the phone lookup feature.

## Findings That Shaped This Design

**A user's Gmail password cannot be used.** Google permanently disabled Less Secure App access on 30 May 2022. Passing a normal account password to `smtp.gmail.com` is rejected. Only App Passwords or OAuth 2.0 work. OAuth was chosen: it collects no credentials, and `lifeswitch.org.nz` is on Google Workspace, so the app registers as **Internal** and skips Google's verification review.

**Current exposure.** `api/send.js` sets `Access-Control-Allow-Origin: *` with no auth, making the deployment an open email relay backed by a Google App Password. `api/lookup.js`, `api/search.js` and `api/lookup-phones.js` are equally open and expose Planning Center member data — names, email addresses, phone numbers — to anyone with the URL. All four are closed by this work.

## Architecture

```
Browser  →  GET /api/auth/login     →  302 to Google (hd=lifeswitch.org.nz)
Google   →  GET /api/auth/callback  →  exchange code → verify hd → set signed cookie → 302 /
Browser  →  GET /api/auth/session   →  { email, name } or 401
Browser  →  POST /api/send          →  verify cookie → Gmail API as that user
```

### No token storage

The OAuth request uses `access_type=online`, so Google issues **no refresh token**. The access token is held only in a signed cookie and dies with it, roughly hourly. This removes the need for any database and means the app never holds long-lived access to anyone's mailbox. The accepted cost is that staff re-click sign-in about once an hour.

### Session cookie

Name `ls_session`. Value is `base64url(payload) + "." + HMAC-SHA256(payload, SESSION_SECRET)`.

Payload is kept minimal to stay well under the 4096-byte cookie limit:

```json
{ "email": "...", "name": "...", "accessToken": "...", "exp": 1234567890 }
```

Flags: `HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=<token lifetime>`.
Verification uses `crypto.timingSafeEqual`, and rejects when `exp` has passed.

### CSRF on the callback

`/api/auth/login` generates a random `state`, sets it in a short-lived signed `ls_oauth_state` cookie, and includes it in the Google URL. `/api/auth/callback` requires the returned `state` to match, then clears the cookie.

### Domain enforcement

The `hd=lifeswitch.org.nz` parameter on the auth URL is a UI hint only and is **not** treated as a control. The callback decodes the ID token payload and requires:

- `hd === ALLOWED_HD`
- `email_verified === true`

Anything else gets a 403 with a plain-language message. Because the ID token arrives directly from Google's token endpoint over TLS in a server-to-server call, signature re-verification is unnecessary and no JWT library is pulled in.

## Sending

Gmail API `POST https://gmail.googleapis.com/gmail/v1/users/me/messages/send`, authorised with `Bearer <accessToken>`, body `{ "raw": "<base64url MIME>" }`.

Scope is `https://www.googleapis.com/auth/gmail.send` — send-only. SMTP-over-OAuth is rejected because it would require `https://mail.google.com/`, a Google-restricted scope granting full mailbox access.

**All existing email construction is preserved.** `formatEmailBody`, `formatInline`, `escHtml`, the `{{first_name}}` / `{{last_name}}` / `{{full_name}}` substitution, the header colour validation, and attachment handling stay exactly as written. The only change is the final step: instead of `transporter.sendMail(mailOptions)`, the same `mailOptions` object goes through nodemailer's `MailComposer` to produce MIME, which is base64url-encoded and posted to the Gmail API.

```js
const MailComposer = require('nodemailer/lib/mail-composer');
// new MailComposer(mailOptions).compile().build(cb) — promisified
```

`from` is dropped from `mailOptions`; Gmail sets it from the authenticated account. The existing 150 ms inter-send delay and the per-recipient `results` array are unchanged.

**No new npm dependencies.** Node 18+ `fetch` handles Google's endpoints, built-in `crypto` handles signing, and nodemailer is already a dependency.

## Endpoint Protection

A shared `lib/session.js` exports `requireSession(req, res)`, returning the session or sending a 401. Every handler in `api/` calls it immediately after the method check. `Access-Control-Allow-Origin: *` is removed from all four handlers, since the frontend is same-origin and the wildcard only served to permit cross-site calls.

## Files

| File | Change |
|---|---|
| `lib/session.js` | new — sign, verify, `requireSession` |
| `api/auth/login.js` | new — build state, redirect to Google |
| `api/auth/callback.js` | new — verify state, exchange code, check `hd`, set cookie |
| `api/auth/session.js` | new — current user or 401 |
| `api/auth/logout.js` | new — clear cookie |
| `api/send.js` | Gmail API instead of SMTP; add `requireSession`; drop CORS wildcard |
| `api/lookup.js` | add `requireSession`; drop CORS wildcard |
| `api/search.js` | add `requireSession`; drop CORS wildcard |
| `api/lookup-phones.js` | add `requireSession`; drop CORS wildcard |
| `public/index.html` | sign-in screen, signed-in user chip, sign out |
| `public/phone-lookup.html` | same gate |
| `a` | delete — 2-byte stray file containing only `\r\n` |

`vercel.json` needs no change: the existing `/api/(.*)` rewrite precedes the catch-all, so `/api/auth/*` routes correctly.

## Frontend

On load, each page calls `/api/auth/session`. A 401 shows a full-screen sign-in panel with a single "Sign in with Google" button; a 200 reveals the app and puts the user's name and email in the existing `.header-nav`, alongside a "Sign out" link.

To avoid the app flashing before the check resolves, an inline `<head>` snippet sets `<html class="auth-pending">` and one CSS rule hides `body > *` until the session result arrives.

The panel reuses existing design tokens — `Syne` headings, `DM Sans` body, `#f7f5f0` ground, `.btn-dark`, `var(--radius)` — so it reads as part of the app.

If any API call returns 401 mid-session (token expired), the frontend shows an inline "Session expired — sign in again" prompt rather than silently failing a send.

## Environment Variables

Added in Vercel:

| Name | Value |
|---|---|
| `GOOGLE_CLIENT_ID` | from Google Cloud credentials |
| `GOOGLE_CLIENT_SECRET` | from Google Cloud credentials |
| `SESSION_SECRET` | 32+ random bytes, hex |
| `ALLOWED_HD` | `lifeswitch.org.nz` |

Unchanged: `PCO_APP_ID`, `PCO_SECRET`.

Removed **after** the change is verified in production: `GMAIL_USER`, `GMAIL_APP_PASSWORD`. The App Password must also be revoked in the Google account, or it remains a live credential.

## Manual Setup (Jono, in Google Cloud Console)

1. Create a project, e.g. `lifeswitch-email`.
2. APIs & Services → Library → enable **Gmail API**.
3. OAuth consent screen → User Type **Internal** → app name, support email, developer email.
4. Add scope `https://www.googleapis.com/auth/gmail.send`.
5. Credentials → Create → OAuth client ID → Web application.
6. Authorized redirect URIs — add all three:
   - `http://localhost:3000/api/auth/callback`
   - `https://<preview-url>/api/auth/callback`
   - `https://<production-url>/api/auth/callback`
7. Copy the client ID and secret into Vercel.

## Error Handling

| Case | Behaviour |
|---|---|
| Missing Google env vars | 500, explicit message naming the variable, matching the existing `send.js` style |
| `state` mismatch on callback | 400, no session set |
| Non-`lifeswitch.org.nz` account | 403, "This app is limited to LifeSwitch staff accounts." |
| Expired or tampered cookie | 401, frontend prompts re-sign-in |
| Gmail API 401 mid-send | Send loop stops, partial `results` returned, frontend prompts re-sign-in |
| Gmail API 4xx/5xx per recipient | Recorded as `sendStatus: 'failed'` with the API message, loop continues — matches current behaviour |

## Testing

**Local:** `vercel dev` with `.env.local`, against `http://localhost:3000/api/auth/callback`.

**Preview:** the PR's Vercel preview URL, added to authorized redirect URIs.

Manual test matrix:

1. Signed out → app hidden, sign-in panel shown.
2. Sign in with a `@lifeswitch.org.nz` account → app reveals, name in header.
3. Sign in with a personal Gmail → 403, no session.
4. Send a test email → arrives **from the signed-in user**, appears in **their** Sent folder.
5. `curl -X POST <preview>/api/send` with no cookie → 401.
6. `curl -X POST <preview>/api/lookup` with no cookie → 401.
7. Sign out → app hides, endpoints 401 again.
8. Phone lookup page → same gate, PCO lookup still works when signed in.

Test 4 is the one that proves the core requirement. Tests 5 and 6 prove the open relay and the Planning Center data exposure are closed.

## Rollout

1. Branch `feat/google-oauth-per-user-sending`, PR against `main`.
2. Vercel builds a preview; run the matrix there. `main` is untouched, so the live app keeps working throughout.
3. Merge only after test 4 passes on preview.
4. Merge deploys to production. Re-run tests 2, 4 and 5 against production.
5. Delete `GMAIL_USER` and `GMAIL_APP_PASSWORD` from Vercel; revoke the App Password in Google.

Staff need one instruction: go to the URL, click Sign in with Google. Nothing to install, no password to share.

## Risks

- **Hourly re-sign-in.** Deliberate, given no refresh token is stored. If it proves annoying, adding `access_type=offline` plus encrypted refresh-token storage is a contained follow-up.
- **Gmail send quotas.** Workspace allows ~2,000 recipients/day per account. Because sending is now spread across individual staff accounts rather than one shared mailbox, effective headroom increases.
- **Redirect URI drift.** Vercel preview URLs change per branch. Production and localhost are stable; a new preview URL must be added to the Google client when testing a fresh branch.
