# Passkey Authentication

Datum supports passkeys (WebAuthn) as a first-class sign-in method: users can enroll passkeys on existing accounts, sign in with them instead of a social IdP, and manage them from the cloud portal. Zitadel is the credential store and the single source of truth; every other component either drives a WebAuthn ceremony against Zitadel or reads passkey state through the platform's identity API. This document covers the whole feature across the platform and where this repo fits.

Driving enhancement: [datum-cloud/enhancements#738](https://github.com/datum-cloud/enhancements/issues/738) — delivered in phases: **A** management + login for existing accounts (current), **B** email + passkey signup, **C** account recovery.

## Responsibility split

One rule shapes the whole design: **mutations and read paths are deliberately separated.**

- **auth-ui** owns every mutation (enroll, name, remove) and every WebAuthn ceremony. It holds the Zitadel service-user credential and can demand fresh re-authentication ("sudo mode") before sensitive operations.
- **The platform read path** (cloud-portal → Milo → this repo → Zitadel) is read-only by construction: the portal shows a display-only passkey list, exactly like linked SSO accounts, with a "manage" link out to auth-ui.

This mirrors how SSO account linking already works, keeps Zitadel credentials out of the portal entirely, and means a compromised read path cannot add or remove credentials.

## Architecture

```
            WebAuthn ceremony                      display-only read
 ┌─────────┐  (enroll/login)   ┌─────────┐        ┌──────────────┐
 │ Browser │◄─────────────────►│ auth-ui │        │ cloud-portal │
 └─────────┘                   └────┬────┘        └──────┬───────┘
                                    │ user/v2, session/v2│ list Passkey kind
                                    ▼                    ▼
                              ┌──────────┐        ┌──────────────┐
                              │ Zitadel  │◄───────┤ Milo         │
                              │ (source  │ user/v2│ apiserver    │
                              │ of truth)│ List-  │ (identity.   │
                              └────┬─────┘ Passkeys miloapis.com)│
                                   │        ▲     └──────┬───────┘
                     actions events│        │            │ passkeys
                                   ▼        │            ▼ provider URL
                              ┌─────────────┴────────────────────┐
                              │ this repo (auth-provider-zitadel)│
                              │ • aggregated apiserver: read-only│
                              │   passkeys backend               │
                              │ • actions server: login/passkey  │
                              │   notification logic             │
                              └──────────────────────────────────┘
```

## What lives in this repo

| Piece | Status | Notes |
|---|---|---|
| `SDKClient.ListPasskeys` (`pkg/zitadel`) | Shipped ([#122](https://github.com/milo-os/zitadel-provider/pull/122)) | Wraps Zitadel user/v2 `ListPasskeys`; returns `{ID, Name, State}` per credential |
| Suspicious-login exemption for passkey sessions | Shipped ([#122](https://github.com/milo-os/zitadel-provider/pull/122)) | See below and [suspicious-login-detection.md](suspicious-login-detection.md) |
| Read-only `passkeys` backend in the aggregated apiserver | Planned | Mirrors the `sessions` virtual resource: self-scoped via `X-Remote-Uid`, cross-user reads via SubjectAccessReview. Blocked on the Milo release that ships the `Passkey` types ([milo#727](https://github.com/milo-os/milo/pull/727)) |
| Passkey added/removed notification emails | Planned | New actions handlers mirroring `session_added.go`, creating `Email` resources against a `user-passkey-added` template. Blocked on verifying which Actions v2 events Zitadel delivers for passkey changes on the deployed version |

### Suspicious-login exemption

Sessions whose WebAuthn factor is **user-verified** (a real passkey login) do not trigger the suspicious sign-in email. Rationale: a passkey ceremony is phishing-resistant and proves user presence + verification — a passkey login from a new device is expected behavior (WebAuthn cross-device sign-in), not the credential-theft signal the suspicious-login email exists to catch. Password and IdP logins keep the existing detection unchanged. Enrollment events will get their own dedicated notification (see table above), which is the meaningful security signal for passkeys.

## The platform Passkey kind

Milo serves a read-only `Passkey` kind (`identity.miloapis.com/v1alpha1`), backed by this repo's aggregated apiserver via `--passkeys-provider-url` (the same pattern as `UserIdentity` and `Session`):

- `metadata.name` — Zitadel passkey ID
- `status.displayName` — user-facing name, set once at enrollment (Zitadel has no rename API)
- `status.state` — `Active` | `Inactive` (mapped from Zitadel `AuthFactorState`)
- `status.userUID` — owner; registered as a field selector so self-scoped list and SAR-checked cross-user reads work identically to sessions

**No delete/create/update verbs exist** on this kind. Removal happens only in auth-ui, which requires a fresh authentication factor (≤10 minutes) before enroll/remove and refuses to remove a user's last sign-in method.

## Cross-platform integration

| Repo | Responsibility |
|---|---|
| auth-ui | WebAuthn ceremonies (session/v2 challenge + user/v2 registration), `/passkeys` management page, step-up re-auth, enrollment naming (AAGUID-derived defaults) |
| Zitadel (infra) | Credential store; login policy `passwordlessType` gates the feature per environment (staging first, production after exit review) |
| milo | `Passkey` kind + REST storage behind an alpha feature gate (default off); `LastLoginProvider` now accepts `passkey`/`email` |
| this repo | Read backend for the kind; login-notification logic (exemption + planned passkey-added email) |
| cloud-portal | Display-only passkeys card on the account Security tab; links to auth-ui for management |
| email-templates → datum | `user-passkey-added` notification template (variables: `UserName`, `PasskeyName`, `AddedTime`, `Browser`, `Device`) |

## Zitadel configuration

- **Login policy**: `passwordlessType: PASSWORDLESS_TYPE_ALLOWED` (managed by the infra Pulumi program; per-environment config key `zitadel-setup:passwordless-type`).
- **Actions v2** (planned, for notifications): a `REST Webhook` target on the actions sidecar (`https://localhost:8888/v1/actions/...`) with event conditions for passkey add/remove, following the existing suspicious-login wiring.
- WebAuthn credentials bind to the RP ID of the auth domain (`auth.datum.net` / `auth.staging.env.datum.net`). Changing that domain invalidates every enrolled passkey — treat it as a one-way door.

## Dependencies

| Dependency | Purpose |
|---|---|
| Zitadel API (machine account) | `ListPasskeys` for the read backend; session listing for login notifications |
| Milo `identity.miloapis.com` | Serves the `Passkey` kind the portal consumes |
| `notification.miloapis.com` Email CRD | Deliver passkey lifecycle notification emails (planned) |
| Zitadel Actions v2 (sidecar target) | Event delivery for notification handlers (planned) |
