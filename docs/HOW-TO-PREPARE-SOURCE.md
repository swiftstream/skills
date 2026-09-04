# How to Prepare a Source Repository

Use this guide before registering a repository in `swiftstream/skills`, before migrating legacy skill files, or whenever an agent needs to make a source repository structurally federation-ready without guessing the package format.

For federation trust/publication mechanics, see [MECHANICS.md](MECHANICS.md). For the registration flow itself, see [HOW-TO-ADD.md](HOW-TO-ADD.md).

This document is intentionally operational. An agent should be able to follow it directly instead of inferring package structure from the federation engine.

## 1. Choose one skills root

A registered source exposes one repository-relative `skillsRoot`.

Common examples are:

```text
.agent/skills
.agents/skills
```

Prefer the repository's existing canonical agent-governance location rather than moving between `.agent` and `.agents` without a separate reason.

The skills root must be a normal repository directory. Do not use an absolute path, `..`, backslashes, duplicate separators, or another non-canonical path spelling.

## 2. Every skill is a directory package

The canonical source layout is:

```text
<skillsRoot>/
  <skill-name>/
    SKILL.md
    LICENSE.txt        # optional
    references/        # optional package-local supporting material
    scripts/           # optional package-local tools; federation never executes them
    ...                # other regular package files when needed
```

Do **not** use a legacy flat layout such as:

```text
.agent/skills/view_composition_skill.md
.agent/skills/state_binding_skill.md
```

A file like `<name>_skill.md` is not a public Agent Skill package. Migrate it to a direct-child directory with `SKILL.md` inside it.

Example:

```text
before
.agent/skills/view_composition_skill.md

after, source-local
.agent/skills/view-composition/SKILL.md

after, intentionally public under prefix "uikitplus"
.agent/skills/uikitplus-view-composition/SKILL.md
```

## 3. Skill names use lower-hyphen form

Package directory names and `SKILL.md` frontmatter names must use:

```text
lowercase-words-separated-by-hyphens
```

Accepted shape:

```text
[a-z0-9]+(?:-[a-z0-9]+)*
```

Keep names at most 64 characters.

Good:

```text
view-composition
adding-query-builder
uikitplus-state-binding
swifql-query-building
```

Bad:

```text
view_composition
ViewComposition
view composition
_view-composition
view-composition-
```

## 4. Every package has a real `SKILL.md`

`SKILL.md` must be UTF-8 and begin with YAML-style frontmatter.

Use this minimal template unless the package needs an optional local license:

```markdown
---
name: <exact-package-directory-name>
description: <concise explanation of when an agent should use this skill and what scope it owns>
---

# <Human-readable title>

<Skill instructions...>
```

With a package-local license:

```markdown
---
name: <exact-package-directory-name>
description: <concise use/scope description>
license: LICENSE.txt
---
```

Rules:

- `name` is required and must exactly equal the package directory name;
- `description` is required and must be nonempty;
- `license` is optional;
- if `license` is present, it must be a canonical relative path **inside the skill package** and the referenced file must exist;
- do not point `license` at the source repository root with `../..` traversal;
- do not add committed `metadata.github-*` provenance/install fields; central federation owns publication provenance;
- prefer the minimal frontmatter above instead of adding fields an agent merely assumes are useful.

## 5. Decide PUBLIC versus LOCAL before renaming

A skills root may contain both public federation skills and source-local contributor skills.

The distinction is determined by the accepted source's configured `skillPrefixes`.

For a configured prefix:

```text
uikitplus
```

a public skill name must begin with exactly:

```text
uikitplus-
```

Examples:

```text
uikitplus-view-composition       -> public candidate
uikitplus-state-binding          -> public candidate
view-composition                 -> source-local/non-public
adding-uikitplus-view            -> source-local/non-public
```

Do not add a special `public: true` field. Public discovery is name/prefix based.

### PUBLIC package

Choose PUBLIC only when the skill is intentionally suitable for central distribution.

A public direct child that matches an accepted prefix is not optional: federation treats it as a publication candidate and validates it fail-closed.

A public package should therefore:

- have a prefix-matching package name;
- have valid `SKILL.md` frontmatter;
- remain useful when copied as its own package into central `skills/**`;
- keep essential instructions and required supporting material inside the package;
- avoid depending on unbundled repository-relative files for essential behavior;
- avoid symlinks and submodules/gitlinks anywhere in the package;
- preserve intentional executable bits on regular files;
- use normal UTF-8 POSIX package paths.

If a public skill needs reference material, copy or adapt the required material into package-local files such as:

```text
<skill-name>/references/...
```

Do not assume central publication will copy sibling `.agent/architecture/**`, repository docs, or another skill package. Federation copies the public skill package subtree, not the entire source repository.

A public skill may still tell an agent to inspect the consuming/source repository when that is semantically part of the workflow, but the skill's own indispensable contract must not exist only in an unbundled sibling file.

### LOCAL package

Choose LOCAL when the skill is repository-maintainer/contributor guidance that should not be centrally published under the source's public prefix.

A local skill should still use the canonical package form:

```text
<skillsRoot>/<local-skill-name>/SKILL.md
```

but its name must not accidentally match an accepted public prefix.

Local packages may intentionally refer to source-only governance or architecture files because federation ignores non-prefix-matching children.

This is the same model used by SwifQL: public `swifql-*` packages coexist with contributor/local packages such as `adding-swifql-builder` under the same `.agent/skills` root.

## 6. Public prefix ownership is stricter than matching

Matching uses the full configured prefix plus a hyphen:

```text
prefix "foo-bar" -> publishes foo-bar-*
```

Ownership reserves the first hyphen-delimited component:

```text
rootNamespace("foo-bar") = "foo"
rootNamespace("foo-baz") = "foo"
```

Therefore `foo-bar` and `foo-baz` cannot both be configured anywhere in the federation, even for the same source.

Before proposing a public prefix, check central accepted mechanics/registry rather than inventing a conflicting namespace.

For a project named UIKitPlus, a single `uikitplus` public prefix is structurally natural, but the source-registration decision remains explicit and must not be silently written into central `federation.json` by a source-migration task.

## 7. Package safety rules for PUBLIC skills

A public package may contain directories and regular files only.

Allowed Git object modes are effectively:

```text
040000  directory/tree
100644  regular non-executable file
100755  regular executable file
```

Forbidden in a public package:

```text
120000  symlink
160000  gitlink/submodule
unexpected Git modes
non-UTF-8 package paths
path traversal or non-canonical POSIX paths
```

Federation treats package content as data and does not execute scripts, hooks, binaries, or other source-package code during generic validation.

Do not rely on code execution as part of package discovery or package validity.

## 8. Migration checklist for legacy skill files

When migrating an existing repository, perform this in order.

### A. Inventory

List every existing skill file/package under the current skills root and every repository file that references it, especially:

```text
AGENTS.md
.agent/SKILL_INDEX.md
other .agent governance/index files
other skills
artifacts/plans that are still active authority
```

### B. Classify each skill

For every existing skill, write down one of:

```text
PUBLIC
LOCAL
```

Do not infer PUBLIC merely because the old file was called a "skill".

Ask:

```text
Should this package be centrally discoverable/installable under the source's public prefix?
Can its essential instructions survive as a standalone copied package?
```

If not, keep it LOCAL.

### C. Choose canonical names

Convert underscores/camel-case/legacy `_skill` suffixes to lower-hyphen package names.

For PUBLIC skills, prepend the exact intended public prefix.

For LOCAL skills, deliberately avoid the public prefix.

### D. Create package directories

Move/adapt each skill into:

```text
<skillsRoot>/<canonical-name>/SKILL.md
```

Preserve the semantic instructions unless adaptation is required by PUBLIC/LOCAL scope.

### E. Add frontmatter

Add exact `name` and useful `description` frontmatter to every package.

For a PUBLIC package, the description should tell an unfamiliar agent when to use the skill without requiring it to infer purpose from the title.

### F. Repair references after the depth change

Moving:

```text
.agent/skills/foo.md
```

to:

```text
.agent/skills/foo/SKILL.md
```

adds one directory level.

Update all inbound references and any relative links inside the skill.

Example:

```text
old index target:
.agent/skills/foo.md

new index target:
.agent/skills/foo/SKILL.md
```

A relative link that previously used `../architecture/...` may now require `../../architecture/...` for a LOCAL package.

For PUBLIC packages, prefer package-local reference material instead of repairing an essential link to an external sibling that will not be published with the package.

### G. Remove obsolete flat files

Do not leave old `*_skill.md` duplicates beside the canonical package directories unless they serve a separately documented non-skill purpose.

Duplicate old/new operational instructions create routing ambiguity for agents.

### H. Re-scan the real tree

The final intended shape should be obvious by inspection:

```text
.agent/skills/
  local-maintainer-skill/
    SKILL.md
  another-local-skill/
    SKILL.md
  <public-prefix>-consumer-skill/
    SKILL.md
    LICENSE.txt
    references/
      ...
```

No agent should need to guess which Markdown files are skills.

## 9. Keep source skill routing indexes synchronized

If the source repository maintains a `SKILL_INDEX.md`, `AGENTS.md`, task router, or other agent navigation file, update it in the same migration candidate.

Every route must point to the canonical package entrypoint:

```text
<skillsRoot>/<skill-name>/SKILL.md
```

Do not leave an index pointing at deleted flat files.

If PUBLIC and LOCAL skills coexist, the index may route both; federation publication status and source-repository routing are different concerns.

## 10. Federation readiness and polling

Source preparation is complete when the package layout and PUBLIC-versus-LOCAL
classification are correct. Accepted source repositories require no federation
workflow, notifier, secret, OIDC setup, wake URL, signing key, or central
credential.

After a maintainer accepts the source in central `federation.json`,
`swiftstream/skills` discovers current source state through scheduled polling
about every 15 minutes. A maintainer may manually reconcile all accepted
sources or target one accepted repository ID. A source change may therefore
take until the next successful poll to appear centrally.

Central reads accepted configuration as authority and uses
`scripts/federate.py` as the sole semantic federation engine. Source and PR
bytes are data; privileged central automation executes trusted central code
only. No source-side setup is needed for this polling path.

## 11. Do not mutate central registration from the source-migration task

Preparing a source repository does not itself authorize editing central:

```text
swiftstream/skills/federation.json
swiftstream/skills/federation.lock.json
swiftstream/skills/skills/**
```

The source migration prepares source-owned content only.

Registration/onboarding is a separate manual trust decision through the central add-source flow.

## 12. Agent completion checklist

A source-migration agent should not declare completion until it can answer all of these explicitly:

```text
[ ] One canonical skillsRoot is identified.
[ ] Every operational skill is a direct-child directory package with SKILL.md.
[ ] No legacy flat *_skill.md file remains as a competing skill entrypoint.
[ ] Every package name uses lower-hyphen syntax.
[ ] Every SKILL.md has exact name + nonempty description frontmatter.
[ ] Every optional license path stays inside its package.
[ ] PUBLIC versus LOCAL classification is explicit for every package.
[ ] Every PUBLIC name matches the intended accepted prefix exactly.
[ ] Every LOCAL name deliberately avoids the public prefix.
[ ] PUBLIC packages are standalone enough to survive package-only central copying.
[ ] PUBLIC packages contain no symlink/gitlink/non-canonical package path.
[ ] Source SKILL_INDEX/AGENTS/routing references point at */SKILL.md.
[ ] Relative links were repaired after directory-depth migration.
[ ] No source task guessed or mutated central sourceId/repositoryId/registry state.
[ ] No source-side federation workflow or credential was added; central polling is the refresh mechanism.
[ ] Existing unrelated source worktree changes were preserved.
[ ] Git staging/commit/push occurred only when separately authorized.
```

If any item is unknown, report the exact unknown instead of guessing.
