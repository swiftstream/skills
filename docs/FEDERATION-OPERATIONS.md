# Federation Operations

This is the current operator guide for the simplified C03 federation. Central `swiftstream/skills` polls accepted sources about every 15 minutes through `.github/workflows/federation-reconcile.yml`. A maintainer may dispatch the same workflow with no `repository_id` to reconcile all accepted sources, or with one accepted repository ID to reconcile one source.

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

## Troubleshooting

- Empty accepted registry: all-source reconciliation is a clean bounded NOOP.
- Unknown targeted repository ID: reconciliation is a bounded NOOP and cannot onboard anything.
- Source changes not visible: wait for the next successful poll or manually dispatch the workflow.
- Machine PR blocked or closed: inspect the bounded controller result and fix the current source/package state; the next poll recomputes from current authority.
- Manual ADD/UPDATE/REMOVE PR: correct the proposal and have a maintainer merge it; these trust decisions never auto-merge.

Do not run live publication, source onboarding, GitHub mutation, or release/tag operations as part of local validation.
