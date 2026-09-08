# LifeSwitch Volunteer Emails

Sends templated emails to Planning Center contacts. Staff sign in with their
LifeSwitch Google account, and each email sends from that person's own Gmail
account and appears in their own Sent folder.

## Access

Restricted to verified `@lifeswitch.org.nz` Google Workspace accounts. There is
no shared password. Enforcement is server-side, on the `hd` claim of the Google
ID token.

## Environment Variables (Vercel)

| Name | Purpose |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth client ID from Google Cloud |
| `GOOGLE_CLIENT_SECRET` | OAuth client secret from Google Cloud |
| `SESSION_SECRET` | 32+ random bytes, hex. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `ALLOWED_HD` | `lifeswitch.org.nz` |
| `PCO_APP_ID` | Planning Center application ID |
| `PCO_SECRET` | Planning Center secret |

`GMAIL_USER` and `GMAIL_APP_PASSWORD` are no longer used. Delete them from
Vercel and revoke the App Password in the Google account that owned it.

## Google Cloud Setup

1. Create a project, e.g. `lifeswitch-email`, and select it in the console's top bar.
2. **APIs & Services → Library → enable Gmail API.** Do this before step 4 — until
   the API is enabled, its scopes do not appear in the scope picker at all.
3. **Google Auth Platform → Audience** → User Type **Internal**. Fill in app name,
   user support email, and developer contact email under **Branding**.
4. **Google Auth Platform → Data Access → Add or remove scopes.** Filter for
   `gmail.send`, or paste it into **Manually add scopes** at the bottom of the panel:
   ```
   https://www.googleapis.com/auth/gmail.send
   ```
   Tick it → **Update** → **Save**.
5. **Credentials → Create credentials → OAuth client ID → Web application.**
6. Authorized redirect URIs — paste these exactly. Google accepts only complete,
   literal URIs: no wildcards, no placeholders, and `http://` only for localhost.

   ```
   http://localhost:3000/api/auth/callback
   https://emailapp-roan.vercel.app/api/auth/callback
   https://emailapp-git-main-jono-chaplows-projects.vercel.app/api/auth/callback
   https://emailapp-jono-chaplows-projects.vercel.app/api/auth/callback
   https://emailapp-git-feat-oauth-jono-chaplows-projects.vercel.app/api/auth/callback
   ```

   `emailapp-roan.vercel.app` is the production domain. The last entry is the
   preview alias for the `feat/oauth` branch.
7. Copy the client ID and secret into Vercel.

### A note on preview URLs

Vercel names branch previews `emailapp-git-<branch>-jono-chaplows-projects.vercel.app`.
That hostname label cannot exceed 63 characters, and Vercel truncates longer ones
and appends an unpredictable hash. Since Google requires each redirect URI to be
registered in advance, an unpredictable preview host cannot be pre-registered.

Keep branch names short. `feat/oauth` yields a 46-character host and works; the
original `feat/google-oauth-per-user-sending` yielded 69 and would not have.
If you do deploy a long-named branch, read its real URL from the Vercel dashboard
and add that exact URI to the Google client before testing sign-in.

### Notes on scopes and verification

The console will show verification warnings for `gmail.send`, because Google
classifies it as a **sensitive** scope. Those warnings apply to **External** apps.
This app is **Internal** — every user is on the Workspace domain — so no
verification, review, or security assessment applies.

`gmail.send` is deliberately chosen over `https://mail.google.com/`. The latter is
a **restricted** scope granting full mailbox access, and it triggers a third-party
security assessment if the app is ever made External. Never widen the scope.

What actually grants permission at runtime is the `scope` parameter in the auth
URL, built in `api/auth/login.js`. The Data Access page governs what the consent
screen displays and what verification checks. Keep the two in agreement.

## Sessions

Sessions last one Google access-token lifetime (about an hour) and are held in
an `HttpOnly`, `Secure`, `SameSite=Lax`, HMAC-signed cookie. No refresh token is
requested and no tokens are stored server-side, so there is no database and no
long-lived access to anyone's mailbox. Staff re-click sign-in about hourly.

## Development

```bash
npm install
npm test        # node --test, no external test framework
vercel dev      # http://localhost:3000
```

`vercel dev` needs a `.env.local` with the variables above.

## Sending Limits

Google Workspace caps around 2,000 recipients per day per account. Because each
staff member now sends from their own account, that ceiling applies per person
rather than to one shared mailbox.
