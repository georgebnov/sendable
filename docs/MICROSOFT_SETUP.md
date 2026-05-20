# Microsoft Entra (Azure AD) app registration

One-time setup so emailAgent can offer "Sign in with Microsoft" + read
the user's Outlook mailbox via Graph. ~10 minutes. Free.

## 1. Open the portal

Go to <https://entra.microsoft.com>.

Sign in with any Microsoft account (work or personal). Free Azure
account creation if you don't already have one — they ask for a credit
card to verify, never bill on the Free tier we use.

## 2. Register the app

Left nav → **App registrations** → **+ New registration**.

| Field | Value |
|-------|-------|
| Name | `emailAgent` (anything, user-visible on consent screen) |
| Supported account types | **Accounts in any organizational directory (Any Microsoft Entra ID tenant — Multitenant) and personal Microsoft accounts (e.g. Skype, Xbox)** |
| Redirect URI | Platform: **Web**. URL: `http://localhost:8000/auth/microsoft/callback` |

Click **Register**.

## 3. Capture the IDs

After registration, the **Overview** page shows:

- **Application (client) ID** → copy
- **Directory (tenant) ID** → copy (we'll use `common` instead, see below, but save for reference)

## 4. Create a client secret

Left nav (inside the app) → **Certificates & secrets** → **+ New client secret**.

| Field | Value |
|-------|-------|
| Description | `dev` |
| Expires | `180 days` |

Click **Add**.

**Copy the `Value` column immediately.** It disappears after you leave
the page. Save it next to the client ID.

## 5. Grant Graph permissions

Left nav → **API permissions** → **+ Add a permission** → **Microsoft Graph** → **Delegated permissions**.

Search and check:

- `User.Read` (read user profile — needed to land the email on sign-in)
- `Mail.Read` (read mailbox — needed for the poller)
- `offline_access` (refresh-token issuance — needed so we don't re-prompt every hour)

Click **Add permissions**.

For personal Microsoft accounts and multitenant accounts these don't
need admin consent. The user sees the consent screen on first sign-in.

## 6. Drop the secrets into `.env`

At the project root, append to `.env`:

```
MICROSOFT_CLIENT_ID=<value from step 3>
MICROSOFT_CLIENT_SECRET=<value from step 4>
MICROSOFT_TENANT_ID=common
MICROSOFT_REDIRECT_URI=http://localhost:8000/auth/microsoft/callback
```

`MICROSOFT_TENANT_ID=common` lets both personal Microsoft accounts and
any work / school account sign in. If you want to restrict to a specific
org later, swap `common` for the Directory (tenant) ID from step 3.

## 7. Production redirect URI

When we deploy, add a second Redirect URI under **Authentication** →
**Web** → **+ Add URI**:

```
https://<your-domain>/auth/microsoft/callback
```

Don't remove the localhost one — keep both so dev still works.

## Done

Once `.env` has the four `MICROSOFT_*` values, the code is ready to
serve the sign-in flow.
