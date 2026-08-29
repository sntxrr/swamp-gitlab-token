# @sntxrr/gitlab-token

Create, rotate, revoke and inventory GitLab access tokens — personal, project
and group — through one model.

| | |
| --- | --- |
| Model | `@sntxrr/gitlab-token` |
| Methods | `sync`, `list`, `create`, `rotate`, `delete`, `update-ci-variable` |
| Workflow | `@sntxrr/gitlab-token-rotation` — daily check, threshold-gated rotation |
| Writes | `token` (metadata) per token, `secret` (vaulted value) on create/rotate, `ci-variable` (audit) on propagation |
| Auth | A GitLab token with `api` scope, sent as `PRIVATE-TOKEN` |

## Why one model and not three

GitLab documents personal, project and group access tokens as three APIs. They
are the same resource with three different parents: the same fields, the same
filters, the same `create` / `rotate` / `revoke` verbs, differing only in the
path prefix and in who is allowed to call them.

```
personal  ->  /personal_access_tokens
project   ->  /projects/:namespace/access_tokens
group     ->  /groups/:namespace/access_tokens
```

So `tokenScope` is a global argument, not a separate type. A rotation workflow
written against a project token works unchanged against a group token.

## What you can actually create

This is the part worth knowing before you plan around it, because GitLab returns
the same undifferentiated `403` for all three failure modes below.

| Scope | Who can `create` | Scopes available |
| --- | --- | --- |
| `project` | Maintainer (Owner for `owner` access level) | Any |
| `group` | Owner | Any |
| `personal`, `userId` set | **Instance administrator**, Self-Managed/Dedicated only | Any |
| `personal`, no `userId` | Any authenticated user | **Only `k8s_proxy`, `self_rotate`** |

A personal access token with `api` scope cannot be minted by its own owner
through the API — only by an instance administrator. `create` checks the
combination it was handed and refuses *before* spending an API call, naming both
ways forward rather than letting GitLab's 403 stand in for the explanation.

For automation, a **project or group access token is the answer**: Maintainer or
Owner is enough, and any scope is available.

**Except on a GitLab.com Free namespace, where neither exists.** Project and
group access tokens are a paid feature there; both endpoints answer

```
400 Bad request - User does not have permission to create project access token
```

to a group **Owner**, so the message names a permission that no role can grant.
Check the tier before designing around them — `glab api namespaces/<ns>` and read
`plan`. On Free, the substitute is a **fine-grained personal access token**,
which scopes to named projects and individual verbs; note it still carries the
`glpat-` prefix, so the prefix alone will not tell you which kind you hold.

## The token value exists exactly once

`create` and `rotate` are the only times GitLab ever discloses a token value.
There is no read path that returns it. So both methods write two resources:

- **`token`** — metadata: scopes, expiry, `daysRemaining`, last use, revoked
  state. Never contains a value.
- **`secret`** — the value itself, in a field marked
  `.meta({ sensitive: true })`. swamp stores it in a vault and persists only a
  reference, so the plaintext never lands in the datastore and never reaches a
  log.

The secret is written **twice**: once keyed by the new token ID, which is the
audit record, and once under the stable name `current`. Wire a consumer to the
alias:

```
${{ data.latest("gitlab-deploy-token", "current").attributes.token }}
```

The alias is not a convenience. `data.latest` takes a resource *instance* name,
and every instance of `secret` is keyed by a token ID that did not exist when the
consumer was written — rotation mints a new one each time. `findBySpec` reaches
the spec but hands back every generation with no way in CEL to ask for the
newest, so a consumer would be guessing, and guessing wrong means writing a
**revoked** value over a live one. `current` is always the value issued most
recently.

A rotation whose output is not wired somewhere is a self-inflicted outage, which
is why the secret is a first-class resource rather than a return value.

## Carrying a rotation through to its consumer

Rotating is half a handover. The other half is `update-ci-variable`, which writes
the new value into a GitLab CI/CD variable:

```bash
swamp model @sntxrr/gitlab-token method run update-ci-variable deploy-token \
  --input project=marsh-works/pipeline \
  --input key=GITLAB_PUSH_TOKEN \
  --input 'value=${{ data.latest("deploy-token", "current").attributes.token }}'
```

| Argument | Default | Notes |
| --- | --- | --- |
| `project` | — | Project owning the variable. Usually **not** the project that owns the token. |
| `key` | — | Variable name. Must already exist. |
| `value` | — | Sensitive. Wire from the `current` alias. |
| `masked` | `true` | Re-asserted on every write. |
| `protected` | `true` | Re-asserted on every write. |
| `environmentScope` | `*` | Disambiguates variables sharing a key across environments. |
| `tokenId` | — | Recorded on the audit resource for linkage. |
| `when` | `true` | Same gate convention as `rotate` and `delete`. |

**It updates and will not create.** A missing variable is an error naming both
the key and the project, not an upsert. Creating one would turn a mistyped key
into a variable nothing reads, while the real consumer went on reading the value
the rotation had just revoked — a silent outage reported as a green run.

**`masked` and `protected` are re-asserted, not inherited.** GitLab does not
carry them forward on an update, so omitting them can silently unmask a variable
that was masked before, and the next pipeline prints the secret. If GitLab
reports the value as unmasked after a write that asked for masking, the method
records the audit resource and *then* fails the run — the value is live and in a
log by that point, so it is an incident, not a warning.

It writes a `ci-variable` resource carrying the fact of the write and its safety
flags, never the value. That is what makes a closed loop distinguishable from an
open one: `secret` proves a value was issued, `ci-variable` proves something was
wired to receive it.

## Rotation is generational

GitLab's rotate revokes the current token immediately and issues a replacement
under a **new ID**. Re-presenting the old value triggers reuse detection, which
revokes the entire token family — not just the token you replayed.

Two consequences this model bakes in:

- The new snapshot is keyed by the **new** ID. Writing the successor under the
  old ID would erase the record of what was just retired.
- If a rotate returns no value, that is an **outage**, not a no-op: the previous
  token is already dead. It is logged as a warning rather than passed over.

## Usage

```bash
swamp extension pull @sntxrr/gitlab-token
```

### A project access token

```bash
swamp model create @sntxrr/gitlab-token deploy-token \
  --global-arg 'token=${{ vault.get("gitlab", "ADMIN_TOKEN") }}' \
  --global-arg baseUrl=https://gitlab.example.com \
  --global-arg tokenScope=project \
  --global-arg namespace=marsh-works/deploy-bot

# provision — the value lands in the vaulted `secret` resource
swamp model @sntxrr/gitlab-token method run create deploy-token \
  --input name=ci-deploy \
  --input 'scopes=["api"]' \
  --input expiresAt=2026-11-30 \
  --input accessLevel=maintainer

# read it back later
swamp model get deploy-token --json
```

### Rotate on a schedule

```bash
swamp model @sntxrr/gitlab-token method run rotate deploy-token \
  --input expiresAt=2027-02-28
```

Set `tokenId=self` to rotate the token doing the authenticating — the token
needs `api` or `self_rotate` scope to do that.

### Inventory what is about to lapse

`list` is a factory: one call writes one snapshot per token, rather than N model
runs contending on the same lock.

```bash
swamp model @sntxrr/gitlab-token method run list deploy-token \
  --input state=active \
  --input expiresBefore=2026-10-01

swamp data query deploy-token 'attributes.daysRemaining < 14'
```

### Revoke

```bash
swamp model @sntxrr/gitlab-token method run delete deploy-token
```

Already-revoked is treated as success. The desired state is "gone", and a
cleanup job that fails on its second run is one nobody schedules.

## The rotation workflow

The extension ships `@sntxrr/gitlab-token-rotation`, a two-job workflow that
checks the managed token daily and rotates it only when told to *and* only when
it is genuinely close to lapsing.

```bash
# scheduled path — read-only, keeps daysRemaining current
swamp workflow run @sntxrr/gitlab-token-rotation

# rotate, if the token is inside the threshold
swamp workflow run @sntxrr/gitlab-token-rotation --input rotate=true
```

| Input | Default | Effect |
| --- | --- | --- |
| `rotate` | `false` | Permit rotation at all. The default makes the scheduled run read-only. |
| `rotateWithinDays` | `7` | Rotate only at or below this many days remaining. |
| `expiresAt` | `""` | Expiry for the replacement, `YYYY-MM-DD`. Empty takes GitLab's default. |
| `ciVariableProject` | `""` | Project whose CI/CD variable consumes the token. Empty skips propagation. |
| `ciVariableKey` | `""` | Variable to update with the rotated value. Empty skips propagation. |

**Two independent gates, both of which must hold.** `rotate=true` alone does
nothing to a token with 60 days left, so re-running the workflow by hand cannot
mint a fresh token every invocation. That matters more than it sounds: rotation
is irreversible the instant it lands, and a workflow that rotates on every run
is one that quietly burns a token family.

Both conditions are evaluated in the model's `when` argument rather than a step
condition, because swamp step conditions are status-based and cannot express a
predicate over another step's output. A false `when` costs nothing — `rotate`
returns before it touches the API and writes no resource, so the existing
snapshot stays true instead of gaining a generation that was never issued.

The predicate uses `data.findBySpec` rather than `data.latest` because this
model keys each snapshot by the token's real GitLab ID, so the instance name is
not knowable when the workflow file is written.

**Wire the consumer before enabling rotation.** The replacement value lands in
the `secret` resource and nowhere else. A rotation whose output nothing reads is
an outage you scheduled.

## Global arguments

| Argument | Required | Default | Notes |
| --- | --- | --- | --- |
| `token` | yes | — | Sensitive. Sent as `PRIVATE-TOKEN`. Supply via `vault.get()`. |
| `baseUrl` | no | `https://gitlab.com` | Instance root, **without** `/api/v4`. |
| `tokenScope` | no | `personal` | `personal`, `project` or `group`. |
| `namespace` | for project/group | — | `group/repo` or a numeric ID. URL-encoded automatically. |
| `tokenId` | for all but `create` | — | Token ID, or the literal `self`. |
| `userId` | no | — | Admin PAT creation for that user. |
| `timeoutMs` | no | `15000` | Per-request timeout. |

## Pre-flight check

`valid-target` runs before `create` and `delete` and rejects, with a reason:

- a `project`/`group` scope with no `namespace`
- a `namespace` set on a `personal` scope
- a `baseUrl` that is not absolute, or that already contains `/api/v4`

## Notes

- Pagination follows GitLab's `x-next-page` header. GitLab signals "no more
  pages" with an empty header rather than a short page, so a short-page
  heuristic stops early on an exactly-full final page.
- `429` and `503` are retried up to three times, honouring `Retry-After`.
- `daysRemaining` is floored: a token with 0.9 days left reads as `0`, never
  `1`. Rounding up lets a token lapse on a day the inventory called safe.
- Expiry dates are anchored to UTC midnight so the count does not shift with the
  machine running the check.

## Related

[`@sntxrr/credential-expiry`](https://github.com/sntxrr/swamp-credential-expiry)
probes the credentials a fleet holds and reports how long each has left,
including GitLab tokens. This model manages their lifecycle; that one watches
the clock.

## License

MIT
