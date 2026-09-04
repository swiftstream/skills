# How to Update a Registered Repository

Use an **Update federation source** pull request for a registered source's description, branch, skills root, prefixes, or repository locator. Ordinary skill content changes do not need a registry PR.

The central App-writable request branch contains one `.federation-request` file whose complete content is `update-source`; fork heads fail closed. The bot resolves the URL and requires the same stable GitHub `repositoryId` for a rename or transfer. A different repository is not silently treated as the same source.

Structured comments beginning with the exact line `Federation PATCH` may refine fields before anchoring. The initial body and repository URL are immutable after anchoring. Every accepted proposal is revalidated against the exact current accepted central main and includes all deterministic trust/configuration consequences in one diff.

Prefix ownership is global by the first hyphen-delimited root namespace. A configured `foo-bar` publishes `foo-bar-*` but reserves `foo` against other `foo-*` prefixes.

An update PR never auto-merges. A maintainer manually merges the complete current-base transition, which may include:

```text
federation.json
federation.lock.json
skills/**
the generated README Skill Store section
```

Central polling then reconciles the current source. Source repositories require no notifier workflow, federation secret, OIDC setup, wake URL, signing key, or central credential. A normal source change may take until the next successful approximately 15-minute poll; a maintainer may manually dispatch reconciliation for all sources or one accepted repository ID.

For a configuration-independent refresh, use the technical **Reconcile federation source** request. An unknown repository ID is a bounded NOOP and cannot onboard a source. Outcomes are `NOOP`, `CHANGED`, or `FAIL`.

The current architecture remains: source and PR bytes are data, trusted central code executes the C02-backed `scripts/federate.py` engine, manual trust decisions remain human-merge decisions, and only the exact current-state/App/check/CAS-protected serialized finalizer may auto-merge machine publication.
