# How to Update a Registered Repository

Use this flow when the repository is already registered in `swiftstream/skills` and you need to change its federation configuration.

For the complete mechanics and trust model, see [MECHANICS.md](MECHANICS.md).

Ordinary skill additions, removals, and content changes do **not** require this flow. They are discovered automatically from the registered source after a normal source push.

## Use an update PR for configuration changes

Typical reasons include:

- change the stored catalog description;
- change the canonical source branch;
- change the skills root;
- add, remove, or replace owned skill prefixes;
- update the repository locator after a GitHub rename or transfer.

These are trust/configuration changes, so the PR never auto-merges.

## 1. Open the Update Source pull request template

Create a pull request in `swiftstream/skills` using the **Update federation source** template.

Example:

```text
Repository URL:
https://github.com/SomeOrg/SomeRepo

Description:
<optional new value>

Branch:
<optional new value>

Skills root:
<optional new value>

Skill prefixes:
<optional comma-separated new value>
```

The repository URL identifies the source being edited and is immutable for the lifetime of this PR.

If you entered the wrong URL, close the PR and create another one.

## 2. The bot resolves the accepted source

The bot resolves the URL to a GitHub repository ID and matches it against the accepted registry.

For a normal update, the ID must match the registered source.

For a repository rename or transfer, the new URL is accepted only when it still resolves to the same stable GitHub repository ID.

A different repository ID is not silently treated as the same source.

## 3. Refine the proposal through comments

Like onboarding, update PRs are interactive.

You may post structured PATCH comments containing only the fields you want to change.

Example:

```text
Description:
A new central catalog description.

Branch:
stable

Skills root:
.agent/skills

Skill prefixes:
foo, foo2
```

All fields except the initial repository URL can be refined repeatedly before merge.

After every accepted patch the bot:

1. recomputes the full source proposal;
2. revalidates repository identity, branch, root, prefixes, and discovered public skills;
3. recomputes the complete atomic central diff implied by that proposal, including `federation.json` and any required lock/package/catalog consequences;
4. updates the actual PR branch to that validated proposal;
5. comments with the complete effective source entry;
6. shows the public skills discovered under that proposal;
7. prints a hint/template for the next edit.

## 4. Invalid proposal changes do not close the PR

If a PATCH is invalid, the bot explains the exact failure and keeps the previous valid proposal diff unchanged.

The PR remains open so you can correct the configuration with another comment.

## 5. Prefix updates

A source may own multiple prefixes only when their **root namespaces** are different.

The root namespace is everything before the first `-` in the configured prefix.

For example:

```text
foo, foo2, fdb
```

uses the distinct roots `foo`, `foo2`, and `fdb`, so it is potentially valid.

These are invalid:

```text
foo, foo-db
foo-bar, foo-baz
foo-tools, foo2, foo-extra
```

because the conflicting entries reuse the root namespace `foo`.

This uniqueness rule is global across every registered source, not only within one repository.

A configured prefix such as `foo-bar` selects `foo-bar-*` skills, but it reserves the whole root namespace `foo` against any other configured prefix beginning with the `foo-` family.

Changing prefix/root-namespace ownership is a trust decision and therefore always requires the manual update flow.

## 6. Repository rename or transfer

Suppose the accepted source currently uses:

```text
OldOrg/SomeRepo
```

and GitHub transfers it to:

```text
NewOrg/SomeRepo
```

Open an update-source PR using the new URL.

The bot verifies that the new URL still resolves to the same registered `repositoryId`.

A valid transfer preserves stable federation identity such as:

```text
sourceId
repositoryId
accepted prefix ownership unless explicitly changed
```

while updating the mutable repository locator.

Redirects alone never silently rewrite the registry.

## 7. Manual merge is required — and the update is atomic

A configuration update does not auto-merge even when all checks are green.

Before the PR can become merge-ready, the bot computes the complete central state implied by the proposed configuration and places every deterministic consequence in the same PR.

The diff may therefore contain:

```text
federation.json
federation.lock.json
skills/** additions/updates/removals
the generated README Skill Store section
```

This prevents a trust/configuration change from becoming effective while stale generated packages remain published under the previous authorization.

A maintainer manually merges that complete atomic transition.

If the base branch changes while the proposal is open, the generated consequences must be revalidated/regenerated against the latest base before the PR is merge-ready again.

After merge, a verification reconciliation may check for any newer upstream content change, but no separate cleanup/publication PR is required to make the configuration change itself correct.

## Ordinary skill updates do not need this PR

If you only:

- edit a public skill;
- add a new valid prefix-matching skill;
- remove a public skill;
- change a skill description in `SKILL.md`;

then simply commit and push those changes to the registered canonical source branch.

The next source notification causes central reconciliation and the generated publication is handled automatically.

## Manual reconciliation without configuration changes

If the registry configuration is already correct but you want central to re-check the repository immediately, use the dedicated **Reconcile federation source** technical PR/request rather than an update-source PR.

That request identifies the registered repository URL and runs the same reconciliation used after source pushes.

Outcomes are:

```text
NOOP -> bot reports that central is current and closes the request
CHANGED + PASS -> generated publication may auto-merge
FAIL -> bot explains the error and closes the machine request/publication PR
```

An unknown repository cannot use reconciliation as a shortcut around onboarding.
