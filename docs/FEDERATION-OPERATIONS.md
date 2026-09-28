# Federation Operations

Operator guide for the simplified C03 federation.

Central `swiftstream/skills` polls accepted sources about every 15 minutes through `.github/workflows/federation-reconcile.yml`. A maintainer may dispatch the same workflow with no `repository_id` to reconcile all accepted sources, or with one accepted repository ID to reconcile one source.

## Normal flow

1. Trusted central code reads the exact accepted source registry from current `main`.
2. Sources are ordered deterministically and reconciled through the existing one-source operation.
3. `scripts/federate.py` remains the sole semantic federation engine.
4. Changed generated state is prepared in a machine PR.
5. Trusted validation checks candidate bytes but cannot independently publish green.
6. One globally serialized finalizer re-reads current main, PR head/base, source identity, App identity, generated scope, and exact App-owned check evidence before an expected-head merge.

The operation is current-state and idempotent. A source disappearing or moving during an all-source sweep becomes bounded stale/NOOP behavior; it cannot onboard a source. One polling sweep coalesces changed work into at most one finalizer dispatch.

## Source requirements

Accepted source repositories require no federation notifier workflow, secret, OIDC configuration, wake URL, signing key, or central credential. A source push may therefore take until the next successful poll to appear centrally. A maintainer can request earlier reconciliation manually.

The central administrator configures the GitHub App and branch/ruleset required-check settings once. Those settings are trusted administrative configuration; runtime federation does not audit them through a remote readiness ceremony.

There is no Ed25519 proof, keyring, signing, or key-rotation ceremony. There is no OIDC/JWT/JWKS relay, wake endpoint, source notifier deployment, or expected-App bootstrap ceremony. Manual source trust/configuration PRs remain human-merge decisions.

## Wave 1 policy

Default-branch HEAD is the distribution state. No tags, releases, or real `gh skill publish` execution is a maintainer policy until a later release policy is separately designed. This policy is not a runtime anti-admin scanner.

## Workflows

| Workflow | Purpose |
| --- | --- |
| `federation-reconcile.yml` | Scheduled / manual source reconciliation |
| `federation-interactive.yml` | ADD/UPDATE/REMOVE/RECONCILE request PRs + PATCH comments |
| `federation-trusted-validation.yml` | Independent candidate validation (non-green writer) |
| `federation-state-finalize.yml` | Globally serialized finalizer (single writer; queues pending runs) |
| `federation-main-advance.yml` | Open-request normalization when `main` advances |

## Troubleshooting

| Symptom | Cause | Action |
| --- | --- | --- |
| Empty accepted registry | No sources yet | All-source reconciliation is a clean bounded NOOP |
| Unknown targeted repository ID | Not in `federation.json` | Bounded NOOP; cannot onboard. Use add-source |
| Source changes not visible | Poll lag | Wait for the next successful poll or dispatch reconcile |
| Machine PR blocked or closed | Validation fail | Read the bounded controller comment; fix source/package state; next poll recomputes |
| Manual ADD/UPDATE/REMOVE PR stuck open | Trust decision pending | Correct the proposal; maintainer merges. Never auto-merges |
| `PROPOSAL_BLOCKED` | Interactive controller error | Reason is `TypeName:bounded-message`. Fix body/PATCH or source state |
| `InvalidResponseError` *issue comment REST authority changed during composite read* | Comment composite-read race | Automatically retried (bounded). If permanent, re-dispatch `federation-interactive.yml` |
| `Federation state finalizer` cancelled | Concurrency replace (legacy) | Pending runs now queue (`queue: max`). Re-dispatch finalize if still stuck |
| Marker-less maintenance PR check `failure`/`skipped` | Outside request state machine | Expected for privileged paths; use a one-shot App attestation or admin merge per policy |

## Validation and check evidence

- The App-owned check name is `federation/trusted-validation` (App `4834068`).
- A non-finalizer validation writer may create/update that check with **non-success** evidence only.
- The serialized finalizer may create a missing check and publish `success` only after final candidate revalidation against the exact PR head SHA and accepted central base SHA.
- Marker-less maintenance: `skipped` for non-privileged same-repo diffs, `failure` otherwise. Never `success`.

## Security boundaries

- PR heads, comments, source files, and source metadata are **untrusted data**.
- Privileged automation executes trusted central code only (`scripts/federate.py` + automation validators).
- Generic validation must not execute scripts/binaries from federated skill packages.

## Related

- [MECHANICS.md](MECHANICS.md) — canonical state machines
- [HOW-TO-ADD.md](HOW-TO-ADD.md) · [HOW-TO-UPDATE.md](HOW-TO-UPDATE.md) · [HOW-TO-REMOVE.md](HOW-TO-REMOVE.md)
