# Passkey Authentication

Users can enroll passkeys (WebAuthn credentials) on their accounts, sign in with them, and view them from the client. Zitadel stores the credentials and verifies every WebAuthn ceremony — it is the single source of truth. Mutations and reads are deliberately separated: enrollment and removal run as WebAuthn ceremonies directly against Zitadel, while the platform read path (Client → Milo → zitadel-provider → Zitadel) is read-only by construction, so a compromised read path cannot add or remove credentials.

## How it works

**Ceremony path (enrollment and login):**

1. The client requests a WebAuthn challenge from Zitadel — session/v2 for login, user/v2 passkey registration for enrollment.
2. The browser runs the ceremony (`navigator.credentials`) and the client returns the signed result to Zitadel for verification.
3. The passkey display name is set once at enrollment (Zitadel has no rename API).
4. Enroll and remove are sensitive operations: the client requires a fresh authentication factor on the session before either, and refuses to remove the user's last sign-in method.

**Read path (listing passkeys):**

1. The client lists the read-only `Passkey` kind (`identity.miloapis.com/v1alpha1`) with the user's own bearer token.
2. The Milo apiserver delegates the request to zitadel-provider's aggregated apiserver via `--passkeys-provider-url` — the same delegation pattern as `UserIdentity` and `Session`. Milo has no Zitadel knowledge.
3. zitadel-provider translates the request into a Zitadel user/v2 `ListPasskeys` call and maps the result into the kind.
4. Self-scoped lists resolve through the `X-Remote-Uid` header; cross-user reads require a SubjectAccessReview against the `status.userUID` field selector.

## Component roles

| Component | Role |
|---|---|
| Zitadel | Credential store and ceremony verifier; source of truth for all passkey state |
| Milo | Serves the `Passkey` kind — schema, read-only REST storage, OpenAPI — behind a feature gate; delegates data to the provider; enforces self-scope and SAR authorization; `UserStatus.LastLoginProvider` accepts `passkey` and `email` |
| zitadel-provider | The only platform component that speaks the Zitadel API: the aggregated-apiserver passkeys backend, and the actions server's login/passkey notification logic |
| Client | Runs WebAuthn ceremonies directly against Zitadel (mutations, behind step-up re-authentication) and lists the `Passkey` kind for display |

## Architecture

```
 ┌────────┐  WebAuthn ceremony (enroll/login)  ┌──────────┐
 │ Client │◄──────────────────────────────────►│ Zitadel  │
 └───┬────┘       session/v2 · user/v2         │ (source  │
     │                                         │ of truth)│
     │ list Passkey kind                       └──┬────▲──┘
     ▼                                  actions   │    │ user/v2
 ┌──────────────┐                       events    │    │ ListPasskeys
 │ Milo         │                                 ▼    │
 │ apiserver    │ --passkeys-provider-url ┌────────────┴────────────────┐
 │ (identity.   ├─────────────────────────►│ zitadel-provider            │
 │ miloapis.com)│                          │ • aggregated apiserver:     │
 └──────────────┘                          │   read-only passkeys backend│
                                           │ • actions server: login/    │
                                           │   passkey notification logic│
                                           └─────────────────────────────┘
```

## The Passkey kind

Milo serves a read-only `Passkey` kind, backed by zitadel-provider's aggregated apiserver:

- `metadata.name` — Zitadel passkey ID
- `status.displayName` — user-facing name, set once at enrollment
- `status.state` — `Active` | `Inactive` (mapped from Zitadel `AuthFactorState`)
- `status.userUID` — owner; registered as a field selector so self-scoped list and SAR-checked cross-user reads work identically to sessions

**No delete/create/update verbs exist** on this kind. Removal happens only through the ceremony path, behind step-up re-authentication.

## Suspicious-login exemption

Sessions whose WebAuthn factor is **user-verified** (a real passkey login) do not trigger the suspicious sign-in email. A passkey ceremony is phishing-resistant and proves user presence and verification — a passkey login from a new device is expected behavior (WebAuthn cross-device sign-in), not the credential-theft signal the suspicious-login email exists to catch. Password and IdP logins keep the existing detection unchanged (see [suspicious-login-detection.md](suspicious-login-detection.md)). Enrollment events get their own dedicated notification, which is the meaningful security signal for passkeys.

## Zitadel configuration

This component requires:

- **Login policy** — `passwordlessType: PASSWORDLESS_TYPE_ALLOWED` on the instance/org, per environment.
- **Actions v2** (for lifecycle notifications) — a `REST Webhook` target on the actions sidecar (`https://localhost:8888/v1/actions/...`) with event conditions for passkey add/remove, following the existing suspicious-login wiring.
- WebAuthn credentials bind to the RP ID of the login domain. Changing that domain invalidates every enrolled passkey — treat it as a one-way door.

## Dependencies

| Dependency | Purpose |
|---|---|
| Zitadel API (machine account) | `ListPasskeys` for the read backend; session listing for login notifications |
| Milo `identity.miloapis.com` | Serves the `Passkey` kind the client consumes |
| `notification.miloapis.com` Email CRD | Deliver passkey lifecycle notification emails (`user-passkey-added` template) |
| Zitadel Actions v2 (sidecar target) | Event delivery for the notification handlers |
