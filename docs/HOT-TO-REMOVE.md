# How to Remove a Registered Repository

Removal is an explicit trust/configuration decision and never auto-merges. Open a **Remove federation source** pull request with one central App-writable `.federation-request` file whose complete content is `remove-source`; fork heads fail closed.

The bot resolves the exact accepted repository identity and shows its source ID, repository ID, canonical ref, skills root, prefixes, and currently published skills. The proposal removes the source from `federation.json` and, in the same atomic transition, removes that source's `federation.lock.json` entries, generated `skills/**` packages, and generated README catalog content.

The finalizer re-reads current main, PR head/base, source identity, App-owned check evidence, and generated scope before the maintainer manually merges the complete transition. No later cleanup PR is required for trust revocation.

Central polling ignores a removed repository as an unknown source. If it should be federated again, use the normal add-source flow for a new explicit trust decision. Source repositories require no notifier workflow or federation credential.

To remove only one skill while keeping the repository registered, remove or rename that prefix-matching package in the source repository. The next successful approximately 15-minute poll, or an earlier manual reconcile, discovers the change.
