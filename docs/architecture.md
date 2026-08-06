# zitadel-provider Architecture

## Overview

zitadel-provider is the only platform component that speaks the Zitadel API. It ships as a
single binary, `auth-provider-zitadel`, but that binary contains **four independent runtimes**
selected by subcommand. They do not share process state, they are deployed separately, and
they fail separately.

Assuming this is one process is the most common source of confusion about this repo. Read
this section before anything else.

| Runtime | Subcommand | Deployed as | Direction |
|---|---|---|---|
| [Controllers](#1-controllers) | `controller` | Standalone deployment, leader-elected | Milo ⇄ Zitadel |
| [Aggregated apiserver](#2-aggregated-apiserver) | `apiserver` | Standalone deployment behind Milo | Milo → Zitadel |
| [Actions server](#3-actions-server) | `actions-server` | **Sidecar inside the Zitadel pod** | Zitadel → Milo |
| [Authentication webhook](#4-authentication-webhook) | `authn-webhook` | Standalone TLS webhook | Milo → Zitadel |

```
                          ┌──────────────────────────────┐
                          │           Zitadel            │
                          │   (source of truth for all   │
                          │       identity state)        │
                          │                              │
                          │  ┌────────────────────────┐  │
                          │  │ actions-server sidecar │  │
                          │  │     127.0.0.1:8888     │  │
                          │  └───────────┬────────────┘  │
                          └──────▲───────┼───────────────┘
                                 │       │ creates Email CRs,
              Zitadel API calls  │       │ reads User CRs
              (machine account)  │       │
        ┌────────────────────────┴───┐   │
        │                            │   │
 ┌──────┴───────┐  ┌──────────────┐  │   │  ┌──────────────────┐
 │ controller   │  │ apiserver    │──┘   │  │ authn-webhook    │
 │ (leader-     │  │ (aggregated) │      │  │ (TokenReview)    │
 │  elected)    │  │              │      │  │                  │
 └──────┬───────┘  └──────▲───────┘      │  └────────▲─────────┘
        │                 │              │           │
        ▼                 │ delegated    ▼           │ authn
 ┌──────────────────────────────────────────────────────────────┐
 │                     Milo control planes                      │
 │   core (platform-wide)  ·  project (per-tenant, discovered)  │
 └──────────────────────────────────────────────────────────────┘
```

---

## 1. Controllers

**Subcommand:** `controller` · **Leader-elected:** yes

Reconciles Milo resources into Zitadel state. Faces a topology problem: the resources it
manages live in *different* Milo control planes.

- **MachineAccount** resources live in project control planes — per-tenant, discovered
  dynamically as projects are created.
- **UserDeactivation** resources live in the core control plane — platform-wide.

Both need the same Zitadel instance. The solution is two coordinated managers in one process.

### Dual-manager architecture

```
┌─────────────────────────────────────────────────────────────────-┐
│                Auth Provider Zitadel Process                     │
├─────────────────────────────────────────────────────────────────-┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │              Main Multi-Tenant Manager                      │ │
│  │  • Leader Election: ✓ Enabled                               │ │
│  │  • Discovers: Project control planes (via Milo provider)    │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐    │ │
│  │  │         MachineAccountController                    │    │ │
│  │  │  • Watches: MachineAccount resources                │    │ │
│  │  │  • Reconciles across: All project control planes    │    │ │
│  │  │  • Zitadel: Creates/manages machine users           │    │ │
│  │  └─────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │            Core Control Plane Manager                       │ │
│  │  • Leader Election: Disabled (subordinate)                  │ │
│  │  • Target: Milo core control plane                          │ │
│  │  • Starts: Only when main manager is leader                 │ │
│  │                                                             │ │
│  │  ┌─────────────────────────────────────────────────────┐    │ │
│  │  │       UserDeactivationController                    │    │ │
│  │  │  • Watches: UserDeactivation resources              │    │ │
│  │  │  • Reconciles on: Core control plane only           │    │ │
│  │  │  • Zitadel: Deactivates/reactivates users           │    │ │
│  │  └─────────────────────────────────────────────────────┘    │ │
│  └─────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────-─┘
```

### Leadership coordination

The main multi-tenant manager participates in leader election and becomes the single active
instance across all deployments. Once it achieves leadership, it signals the core control
plane manager to start.

The core control plane manager is subordinate: it starts only after the main manager has
established leadership, and stops if leadership is lost. This prevents multiple instances from
simultaneously modifying user state in Zitadel.

### Resource synchronization

**MachineAccountController** (tenant level)

- Watches `MachineAccount` resources in project control planes
- Creates machine users in Zitadel on create; updates Active/Inactive state from spec; deletes
  machine users on delete
- Identity format: `{uid}@{namespace}.{project}.iam.miloapis.com`

**UserDeactivationController** (platform level)

- Watches `UserDeactivation` resources in the core control plane
- Deactivates users in Zitadel on create, reactivates on delete
- Updates the corresponding `User` resource status in Milo

### Discovery

Uses Milo's native discovery to find project control planes, supports Milo's internal service
discovery, and handles tenant onboarding/offboarding automatically.

---

## 2. Aggregated apiserver

**Subcommand:** `apiserver` · **Leader-elected:** no

A Kubernetes aggregated apiserver backing read-only `identity.miloapis.com` kinds. Milo serves
the kinds and owns schema, OpenAPI, and authorization; it delegates the actual data fetch here
via per-kind provider URLs (for example `--passkeys-provider-url`). **Milo holds no Zitadel
knowledge.**

Kinds backed by this runtime (`internal/apiserver/`):

| Kind | Backed by |
|---|---|
| `Passkey` | Zitadel user/v2 `ListPasskeys` |
| `Session` | Zitadel session listing |
| `UserIdentity` | Zitadel IdP link listing |
| `ServiceAccountKey` | Zitadel machine key listing |

Authorization follows one pattern across all of them: self-scoped lists resolve through the
`X-Remote-Uid` header, and cross-user reads require a SubjectAccessReview against the owner
field selector.

**This path is read-only by construction.** No create, update, or delete verbs are served, so
a compromised read path cannot mutate identity state.

---

## 3. Actions server

**Subcommand:** `actions-server` · **Deployed as a sidecar container inside the Zitadel pod**

Receives Zitadel Actions v2 webhooks and translates them into Milo resources. This is the only
runtime Zitadel calls outbound into.

It listens on `127.0.0.1:8888` and is reachable only from inside the Zitadel pod — which is
why every configured Actions target endpoint is `https://localhost:8888/v1/actions/...` rather
than a cluster service address.

Registered routes (`internal/httpactionsserver/server.go`):

| Route | Purpose |
|---|---|
| `/v1/actions/create-user-account` | User self-registration → Milo `User` CR |
| `/v1/actions/customize-jwt` | Token claim customization |
| `/v1/actions/idp-intent-succeeded` | External IdP link completion |
| `/v1/actions/session-added` | Suspicious-login detection ([doc](components/suspicious-login-detection.md)) |
| `/v1/actions/passkey-added` | Passkey enrollment notification ([doc](components/passkey-authentication.md)) |

Every handler validates an HMAC over the raw request body against the `Zitadel-Signature`
header before parsing anything. Notification handlers are deliberately fire-and-forget:
failures are logged rather than returned as HTTP errors, because Zitadel only needs the `200`
ack that its webhook was received.

**Subject vs creator — read this before adding a handler.** The event envelope's top-level
`userID` is the event *creator*, which is not always the user the event is *about*. Calls made
server-side on a user's behalf resolve `userID` to the calling service account and
`aggregateID` to the actual human. Handlers must pick the correct field for their event shape;
`passkey_added.go` records a live-fire case where getting this wrong silently produced zero
notifications for every real enrollment.

---

## 4. Authentication webhook

**Subcommand:** `authn-webhook` · **Default port:** 9443 (TLS)

A Kubernetes `TokenReview` webhook. Milo's apiserver calls it to authenticate bearer tokens; it
validates them against Zitadel via token introspection and returns the resolved user identity.

It also enforces deactivation at authentication time: a user with an active `UserDeactivation`
fails token review, so deactivation takes effect on the next request instead of waiting for a
token to expire.

Zitadel API access uses a service-account JWT with a configurable lifetime
(`--jwt-expiration`) and proactive refresh (`--jwt-refresh-before`), so introspection does not
stall on an expired credential.

---

## Component documentation

Runtime-level detail lives here. For how a user-facing capability works end to end across
several runtimes, see [components/](components/).
