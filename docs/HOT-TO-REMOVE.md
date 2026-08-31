# How to Remove a Registered Repository

Use this flow when a repository should no longer be trusted as a source in `swiftstream/skills`.

For the complete mechanics and trust model, see [MECHANICS.md](MECHANICS.md).

Removal is a trust/configuration operation and never auto-merges.

## 1. Open the Remove Source pull request template

Create a pull request in `swiftstream/skills` using the **Remove federation source** template.

Example:

```text
Repository URL:
https://github.com/SomeOrg/SomeRepo

Reason:
<optional>
```

The repository URL identifies the registered source to remove.

## 2. The bot verifies the registered identity

The bot resolves the request against accepted federation state and identifies the exact registered source.

Its response shows what is being removed, including at minimum:

```text
Repository
Repository ID
Source ID
Description
Canonical branch/ref
Skills root
Skill prefixes
Currently published skills
```

The bot updates the PR branch with the complete atomic removal diff. It removes the source from `federation.json` **and**, in the same proposal, removes every generated artifact whose publication authority comes from that source:

```text
its federation.lock.json entries
its generated skills/** packages
its generated README Skill Store entry/content
```

Review the complete diff carefully: it is the exact trust revocation and generated cleanup that one merge will make effective together.

## 3. Manual merge is required

The removal PR never auto-merges.

Before it can become merge-ready, the bot verifies that the PR is based on the latest accepted central state and that no lock/package/catalog ownership belonging to the removed source would remain after merge.

A maintainer manually merges the complete atomic removal transition.

The manual merge is the explicit decision that this repository is no longer trusted to publish through the federation, and the generated cleanup becomes effective in the same merge.

No later cleanup PR is required for correctness.

## 4. Post-merge verification

Central automation may run a post-merge verification reconciliation to prove the resulting state is internally consistent.

That verification is defense in depth; trust revocation does not depend on a later generated PR succeeding.

## 5. Future source notifications are ignored

Once the source entry has been removed from accepted `federation.json`, automatic push notifications from that repository no longer have authority.

Central ignores them as unknown-source notifications.

If the repository should be federated again later, use the normal add-source onboarding flow and receive a new explicit trust decision.

## Removal is not the same as removing one skill

Do not use this flow to remove a single public skill while keeping the repository registered.

To remove one public skill, remove or rename that prefix-matching skill in the source repository and push the canonical source branch. Normal automatic reconciliation will remove the corresponding generated central package.
