# How to Remove a Registered Repository

Revoke source trust and remove that source's generated skills from the collection.

Removal is an explicit **trust** decision and never auto-merges.

## Request

On a central branch in `swiftstream/skills`, add exactly one `.federation-request` file whose content is exactly `remove-source` plus a final newline (fork heads fail closed).

Open the [Remove federation source PR template](https://github.com/swiftstream/skills/compare/main...main?quick_pull=1&template=remove-source.md) with the exact body grammar:

```text
Repository URL:
https://github.com/SomeOrg/SomeRepo

Reason:
<optional value>
```

REMOVE does **not** accept mutable `Federation PATCH` fields.

## What the bot prepares

The bot resolves the accepted repository identity and shows its source ID, repository ID, canonical ref, skills root, prefixes, and currently published skills.

One atomic transition removes:

```text
federation.json source entry
federation.lock.json entries for that source
skills/** packages owned by that source
generated README catalog content for that source
```

A maintainer manually merges the complete transition after the finalizer revalidates current main, PR head/base, source identity, App-owned check evidence, and generated scope. **No later cleanup PR is required.**

## After merge

Central polling treats the repository as unknown and cannot re-onboard it. To federate again later, use the normal [add-source](HOW-TO-ADD.md) flow for a new explicit trust decision.

## Remove only one skill

To drop a single skill while keeping the repository registered, remove or rename that prefix-matching package **in the source repository**. The next successful ~15-minute poll (or an earlier manual reconcile) discovers the change. Do not use a remove-source request for partial skill removal.

## Related

- [HOW-TO-ADD.md](HOW-TO-ADD.md) · [HOW-TO-UPDATE.md](HOW-TO-UPDATE.md)
- [FEDERATION-OPERATIONS.md](FEDERATION-OPERATIONS.md)
- [MECHANICS.md](MECHANICS.md) — source removal (§20)
