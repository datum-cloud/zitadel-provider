# Passkey — Local End-to-End Testing

How to stand up the full passkey flow on a local Kubernetes stack and verify it
end to end: enroll a passkey in the browser, read it back through Milo, sign in
with it, and confirm the "passkey added" notification. This proves the whole
chain — `auth-ui → Zitadel → zitadel-provider → Milo → cloud-portal` — on one
machine, without staging.

See also: [components/passkey-authentication.md](../components/passkey-authentication.md)
for the architecture.

## Prerequisites

A local Datum-shaped stack:

- A Kind (or similar) cluster running Milo.
- Zitadel with the actions sidecar and an SMTP catcher (e.g. Mailpit).
- A reverse proxy serving auth-ui and Zitadel from **one https origin** — this
  is required so the WebAuthn RP ID matches the page origin.
- Login policy `passwordlessType: PASSWORDLESS_TYPE_ALLOWED` (must be set
  explicitly — the FirstInstance default is NOT_ALLOWED).
- A test user with no MFA factors.

Keep every `kubectl` command below pointed at the local cluster context. Never
point them at a staging/prod context.

## Passkey-specific deltas over a base stack

### 1. Milo — enable the feature gate and wire the provider URL

The `Passkey` kind is behind an alpha gate (off by default), and its data is
served by zitadel-provider's aggregated apiserver. Patch the Milo apiserver
deployment (mirrors how `SESSIONS_PROVIDER_URL` is wired):

```bash
kubectl -n milo-system set env deploy/milo-apiserver \
  PASSKEYS_PROVIDER_URL=https://<zitadel-provider-apiserver-service>.<namespace>.svc.cluster.local \
  PASSKEYS_PROVIDER_CA_FILE=/etc/kubernetes/pki/trust/control-plane/ca.crt \
  PASSKEYS_PROVIDER_CLIENT_CERT_FILE=/etc/kubernetes/pki/passkeys/tls.crt \
  PASSKEYS_PROVIDER_CLIENT_KEY_FILE=/etc/kubernetes/pki/passkeys/tls.key
```

The client cert is issued via a cert-manager CSI volume (same issuer/CN the
staging sessions provider uses). `FEATURE_GATES` must include `Passkeys=true`.

> These are live patches on a locally-built dev image; a Milo redeploy reverts
> them — re-apply afterwards. On staging this is done properly in `infra`
> (roadmap item A-I2: the gate + provider URL in one patch, applied only after
> zitadel-provider is deployed — never gate-on-without-URL, which panics).

### 2. zitadel-provider — build and deploy the identity apiserver

```bash
cd zitadel-provider   # branch with the passkeys backend
docker build -t ghcr.io/milo-os/zitadel-provider:dev .
kind load docker-image ghcr.io/milo-os/zitadel-provider:dev --name <cluster>
```

A minimal local overlay may omit the identity apiserver component
(sessions/useridentities don't need it locally). Passkeys is the first feature
that does — deploy it as a standalone Deployment+Service in the IAM namespace,
wired to the local Zitadel origin, an admin machine key, and the Milo
kubeconfig. Do **not** create an APIService — Milo's DynamicProvider proxies
directly (staging omits it too).

### 3. zitadel-provider — the passkey-added notification handler

The handler runs in the `zitadel-actions-receiver` sidecar. Patch the sidecar to
the dev image and add the template flag:

```
--passkey-added-email-template=emailtemplates.notification.miloapis.com-userpasskeyaddedemailtemplate
```

Apply the EmailTemplate CR (built from the `email-templates` repo:
`pnpm install && pnpm generate:all`, then apply the generated
`userpasskeyadded-emailtemplate.yaml`).

Bind the Zitadel Actions v2 execution — a **new** target (do not touch the
existing `user.human.added` binding), condition
**`user.human.passwordless.token.verified`**:

```bash
# using an admin JWT-bearer token:
# POST /v2beta/actions/targets  -> endpoint <sidecar>/v1/actions/passkey-added, interruptOnError:false
# PUT  /v2beta/actions/executions -> condition user.human.passwordless.token.verified
```

> Why `token.verified` and not `token.added`: `.added` fires when enrollment
> *starts* (no passkey name in its payload, fires even for abandoned attempts);
> `.verified` fires on ceremony completion and carries `webAuthNTokenName`.
> Confirmed bindable on Zitadel v4.12.2 (a bogus event name is rejected 404, so
> acceptance is real validation).

### 4. Frontends

- **auth-ui** (passkey branch): build and run against the stack — Zitadel API
  URL = the shared https origin, the service-user PAT, and your local CA cert
  via `NODE_EXTRA_CA_CERTS`.
- **cloud-portal** (passkeys-card branch): regenerate the client against local
  Milo (`bun run openapi`, select the identity resources), then run with the
  `.env` pointed at the local Milo API and Zitadel issuer.

## Verifying end to end

### The read path (no browser)

```bash
kubectl api-resources | grep passkeys
# admin list is caller-scoped -> empty for the "admin" identity; this is correct
kubectl get passkeys
```

### The WebAuthn ceremony

Real WebAuthn needs an authenticator. Two options:

- **Manual:** Chrome DevTools → WebAuthn tab → add a virtual authenticator (or
  a platform authenticator on a real device), then drive the UI.
- **Scripted:** Puppeteer/CDP with `WebAuthn.addVirtualAuthenticator`
  (`automaticPresenceSimulation:true, isUserVerified:true`) and Chrome launched
  with `--ignore-certificate-errors`. Use a **fresh** authenticator per enroll —
  a restored credential triggers `excludeCredentials` (`InvalidStateError`).

Flow: sign in as the test user at `https://<origin>/id/login` → `/id/passkeys`
→ add → name it → the authenticator satisfies the ceremony → the list shows the
passkey.

### Confirm it flows through Milo

The list is caller-scoped; query by owner (SAR-gated, allowed for admin). The
`userUID` selector takes the **Zitadel user ID** (= Milo User `.metadata.name`):

```bash
curl -sk -H "Authorization: Bearer <admin token>" \
  "https://<milo-api>/apis/identity.miloapis.com/v1alpha1/passkeys?fieldSelector=status.userUID=<zitadel-user-id>"
# -> the enrolled passkey: {displayName, state: Active, userUID}
```

The zitadel-provider apiserver log shows the SAR-authorized lookup →
`ListPasskeys ... found N` → 200.

### Confirm the notification

Enrollment fires `token.verified` → the sidecar handler creates an `Email` CR.
The CR lives in **Milo's aggregated apiserver** (namespaced), so a plain
`kubectl get emails` against the local cluster returns nothing — query the Milo
API instead. Verify the spec variables: `UserName` (the enrolled human, not the
service user), `PasskeyName`, `AddedTime`; `Browser`/`Device` are empty (not in
the event payload). **The SMTP catcher stays empty locally** — delivery needs
the Resend provider (staging only), so a created Email CR *is* the success
signal.

### Passkey sign-in

Log out, sign back in choosing the passkey method — the authenticator satisfies
the assertion. Proof: the new id_token carries `"amr":["user","mfa"]` (vs
`["pwd"]` for password).

## What this proves vs. what needs staging

Proven locally end to end: enrollment, read-through-chain (`Milo → provider →
Zitadel`), passkey sign-in, and the passkey-added `Email` CR with correct
variables.

Not verifiable locally:

- **Portal card render for a normal user.** The card code and its Milo read are
  correct (the same pattern the linked-accounts/sessions cards already use), and
  the admin-token read returns the data. But a **Zitadel user token** gets 401
  from Milo on a local stack (admin token → 200) — a local authn-wiring gap,
  not a passkey defect. On staging, where the sibling cards already render for
  users, the passkey card renders the same way.
- **Actual email delivery** — needs the Resend provider (staging).
- **Cross-device / hybrid transport** — needs two physical devices and a
  routable RP ID.

## Notes

- Bugs this local E2E caught that unit tests could not: the SDK appended a
  second port to a host that already carried one (every gRPC call would 503),
  and the notification handler resolved the target user from the event
  *creator* rather than the enrolled *subject* (`AggregateID`) — the latter
  silently produced no email for every real enrollment. Both fixed on the
  branch with regression tests.
- Live patches (Milo gate/URL, Zitadel sidecar) do not survive a redeploy /
  Helm upgrade — re-apply after redeploying.
