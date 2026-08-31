# How to Add a Repository

Use this flow when your repository is not yet registered in `swiftstream/skills`.

For the full trust, validation, naming, automation, and publication model, see [MECHANICS.md](MECHANICS.md).

Before opening the registration request, use [HOW-TO-PREPARE-SOURCE.md](HOW-TO-PREPARE-SOURCE.md) to migrate legacy flat skill files into canonical `<skill-name>/SKILL.md` packages, classify PUBLIC versus LOCAL skills, repair source routing references, and avoid inventing notifier values that belong to the later C03 contract.

## What you are requesting

Adding a repository is a trust/configuration operation.

You are asking Swift Stream Skills to trust one GitHub repository as a source of public Agent Skills under one or more reserved skill-prefix namespaces.

The onboarding PR does **not** auto-merge. A maintainer must review and merge it manually.

After that manual merge, the first skill publication is generated automatically in a separate machine PR.

## 1. Open the Add Source pull request template

Create a pull request in `swiftstream/skills` using the **Add federation source** template.

Fill in the request fields.

Example:

```text
Repository URL:
https://github.com/SomeOrg/SomeRepo

Description:
<optional>

Branch:
<optional>

Skills root:
.agents/skills

Skill prefixes:
somerepo, sr
```

### Repository URL

Required.

It identifies the repository being proposed.

Once the PR exists, this URL is immutable for that PR. If it is wrong, close the PR and create a new one.

### Description

Optional.

If omitted, the bot starts with the repository's GitHub description. If GitHub has no useful description, the bot may propose a deterministic fallback.

The accepted description is stored in `federation.json` and is used by the generated repository catalog in `README.md`.

### Branch

Optional.

If omitted, the bot proposes the repository's current default branch.

You may provide a short branch name such as:

```text
main
```

The registry stores the canonical full ref, for example:

```text
refs/heads/main
```

### Skills root

The repository-relative directory whose direct children may contain skills.

Common examples:

```text
.agents/skills
.agent/skills
```

Custom paths are allowed when valid.

### Skill prefixes

Optional.

Provide one or more comma-separated namespace prefixes, for example:

```text
foo, foo2, fdb
```

If omitted, the bot proposes a prefix derived from the repository name.

A configured prefix selects public skill names beginning with:

```text
<prefix>-
```

For ownership, however, the federation reserves the **first component before the first `-`**.

Examples:

```text
foo       -> root namespace foo
foo-bar   -> root namespace foo
foo-baz   -> root namespace foo
foo2      -> root namespace foo2
fdb-tools -> root namespace fdb
```

Every configured prefix must have a root namespace that is unique across the entire federation, including the prefixes of the same source.

Therefore all of these combinations are invalid:

```text
foo + foo-bar
foo-bar + foo-baz
foo-bar + foo-tools
```

while these are valid namespace combinations:

```text
foo + foo2
foo + fdb
foo-bar + fdb-tools
```

A source that owns only `foo-bar` publishes `foo-bar-*` skills, but it still reserves the root namespace `foo`, so nobody else may claim another `foo-*` prefix.

## 2. Wait for the bot's proposal

The bot resolves the repository and validates the proposed source configuration.

A GitHub `repositoryId` may belong to exactly one accepted federation source. If this repository ID is already registered, onboarding fails closed and you must use the existing-source update/reconciliation flow instead of creating a second source identity.

Its response shows the complete effective proposal, including:

```text
Repository
Repository ID
Source ID
Description
Canonical branch/ref
Skills root
Skill prefixes
Discovered public skills
Validation result
```

The bot also updates the PR branch so the real `federation.json` diff contains the exact entry currently proposed for merge.

Always review the actual file diff as well as the comment.

## 3. Refine the proposal with comments

You may change any proposal field except the original repository URL by posting a structured comment.

Comments work like a PATCH: include only the fields you want to change.

Example:

```text
Description:
A focused collection of database Agent Skills for Swift.

Skills root:
.agent/skills

Skill prefixes:
foo, fdb
```

After every accepted change the bot:

1. recomputes and revalidates the complete proposal;
2. updates the `federation.json` diff;
3. posts the complete effective entry again;
4. shows discovered public skills;
5. includes a hint/template for the next change.

You can repeat this as many times as needed before merge.

## 4. If a proposed change is invalid

The bot explains the exact problem and leaves the previous valid proposal intact.

The PR remains open so you can correct the proposal with another structured comment.

Typical failures include:

- prefix already owned;
- overlapping/redundant prefixes;
- invalid skills root;
- invalid branch;
- repository identity conflict;
- malformed public skill package;
- public skill name that does not satisfy the accepted prefix rules.

## 5. How public skills are discovered

You do not list individual skills in the federation request.

The bot inspects direct child directories beneath the configured `skillsRoot`.

A child whose name matches one of the source's owned prefixes is a public federation candidate.

For example, with:

```text
Skills root: .agent/skills
Skill prefixes: swifql
```

these are public candidates:

```text
swifql-query-building
swifql-custom-extensions
```

while these may remain local/contributor-only:

```text
adding-swifql-builder
extending-swifql-dialect
```

A prefix-matching public candidate must pass all package validation. Invalid public candidates block publication rather than being silently skipped.

## 6. Manual maintainer merge is required

Even when onboarding validation is fully green, the onboarding PR does not auto-merge.

Merge readiness is bound to both the exact current PR head and the exact current accepted `swiftstream/skills` default-branch base. If central `main` changes while your onboarding PR is open, the bot must re-read the newest registry and revalidate repository identity, source ID, root-namespace ownership, and the complete proposal before the PR becomes merge-ready again.

This prevents two independently valid onboarding proposals from racing to claim the same global identity/namespace. Git's textual merge behavior is not used as the trust-serialization mechanism.

The manual merge is the explicit trust decision that allows this repository and its namespace ownership into the federation.

## 7. First publication happens automatically after merge

Once the onboarding PR is manually merged, central automation immediately reconciles the newly accepted source.

It discovers the current public skills and creates the normal generated publication transition containing, as needed:

```text
skills/**
federation.lock.json
the generated README catalog section
```

If that generated publication validates successfully, it merges automatically.

If it fails, the bot posts the exact failure and closes the generated PR. Fix the source repository; a later reconciliation can retry from the last successfully published central state.

## 8. Install the source notifier workflow

After onboarding is accepted, the bot provides the standard Swift Stream Skills notifier workflow configured for the accepted branch and skills root.

Add that workflow to the source repository to enable automatic refreshes after future pushes.

The notifier does not need a central repository write token or a long-lived cross-repository secret. It uses GitHub Actions OIDC identity to authenticate a narrow wake request, while central independently resolves and validates the registered source.

The notifier may skip a wake request when the final skills-root tree did not change. Ambiguous cases such as force-push/missing-before history must wake central rather than guess that nothing changed.

If the notifier is not installed yet, the repository remains registered and can still be reconciled manually, but future pushes are not guaranteed to wake central automatically.

## Repository description and the README catalog

The description accepted during onboarding is stored in `federation.json`.

The root README's generated catalog lists every registered repository and its published skills. Skill names and descriptions come from validated skill package metadata, especially `SKILL.md`.

You do not maintain that catalog manually.
