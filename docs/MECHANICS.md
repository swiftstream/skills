# Swift Stream Skills — Repository Mechanics

This document is the canonical human-readable specification for how the Swift Stream Skills federation repository works.

If implementation, workflow behavior, generated files, or another document disagrees with this file, the disagreement must be resolved explicitly before the conflicting behavior is considered accepted. This document describes the intended repository mechanics, trust boundaries, state transitions, publication rules, onboarding/update/removal flows, naming rules, provenance rules, and README catalog behavior.

## 1. Mission

`swiftstream/skills` is a public distribution collection for Agent Skills that are owned and maintained in their original product repositories.

The central repository is not the semantic authoring home for federated skills. A skill is authored in its source repository and is copied into this repository only through the federation machinery described here.

The central repository exists to provide:

- one public place to discover compatible skills;
- a stable trust registry describing which repositories are allowed to publish;
- byte-for-byte generated copies of accepted public skill packages;
- deterministic provenance for every published package;
- automatic publication of ordinary skill content changes;
- explicit human approval for changes to source trust/configuration;
- an App Store-like generated catalog in the root README;
- fail-closed validation without executing code bundled inside skills.

## 2. Core ownership model

There are three different kinds of state and they must not be conflated.

### 2.1 Source-owned semantic state

The source repository owns the meaning and content of its skills.

Examples:

```text
SwifQL/.agent/skills/**
SomeProject/.agents/skills/**
AnotherProject/tooling/agent-skills/**
```

A semantic edit to a skill belongs in the source repository, never directly in `swiftstream/skills/skills/**`.

### 2.2 Central trust/configuration state

`federation.json` declares which source repositories are trusted, where their skills live, which branch is canonical, which public naming namespaces they own, and the description displayed by the central catalog.

Trust/configuration changes require a manual maintainer merge.

### 2.3 Central generated publication state

The following are generated from accepted source state:

```text
federation.lock.json
skills/**
the generated repository/skill catalog section of README.md
```

Ordinary generated publication changes may merge automatically after all validation succeeds.

## 3. Repository layout

The intended central layout is:

```text
AGENTS.md
README.md
LICENSE
federation.json
federation.lock.json

docs/
  MECHANICS.md
  HOW-TO-ADD.md
  HOW-TO-UPDATE.md
  HOT-TO-REMOVE.md

skills/
  <generated-public-skill>/
    SKILL.md
    ...the rest of the exact upstream package...

scripts/
  federate.py
  validate.py
  ...other narrowly scoped repository automation...

.github/
  workflows/
  PULL_REQUEST_TEMPLATE/
  ...automation configuration...
```

`skills/**` must never become a second authoring surface.

## 4. Stable identities and mutable locators

A registered source has several distinct identities/attributes.

Conceptually:

```json
{
  "sourceId": "swifql",
  "repository": "SwifQL/SwifQL",
  "repositoryId": 123456789,
  "ref": "refs/heads/master",
  "skillsRoot": ".agent/skills",
  "skillPrefixes": [
    "swifql"
  ],
  "description": "SQL query builder and dialect toolkit for Swift."
}
```

The exact schema version is implementation-controlled, but the semantics below are canonical.

### 4.1 `sourceId`

`sourceId` is the stable central identity of one registered source.

It is assigned by the federation machinery during onboarding, must be globally unique, and should remain stable across repository renames or transfers.

It is not derived again on every run from the current GitHub owner/name.

### 4.2 `repositoryId`

`repositoryId` is the stable GitHub repository identity resolved from GitHub.

It protects the registry from treating a later repository that happens to reuse the same `OWNER/REPO` spelling as the previously trusted repository.

Accepted federation state requires a strict one-to-one binding between `sourceId` and `repositoryId`:

```text
sourceId is globally unique
repositoryId is globally unique
one sourceId -> exactly one repositoryId
one repositoryId -> exactly one sourceId
```

Onboarding fails closed if the resolved `repositoryId` is already present in accepted `federation.json`; an already registered repository must use the existing-source update/reconciliation paths instead of creating a second source identity.

Every lookup by `repositoryId` must resolve exactly one accepted source. Zero matches means unknown source/no-op where that flow permits it. More than one match means the accepted registry is invalid and all affected federation automation fails closed until the registry is corrected.

A repository transfer or rename may change the current locator while preserving the same `sourceId + repositoryId` binding.

### 4.3 `repository`

`repository` is the current canonical GitHub `OWNER/REPO` locator.

It may change after an explicitly reviewed repository transfer or rename.

A redirect alone is not sufficient authority to silently rewrite this field. A locator change is a trust/configuration update and therefore requires a manual registry PR.

### 4.4 `ref`

`ref` is the canonical source branch as a full branch ref, for example:

```text
refs/heads/master
refs/heads/main
```

Changing the canonical branch is a trust/configuration change and requires a manual registry PR.

### 4.5 `skillsRoot`

`skillsRoot` is the source-repository-relative directory whose direct children may contain skills.

Examples:

```text
.agent/skills
.agents/skills
tooling/agent-skills
```

It must be a canonical nonempty UTF-8 POSIX repository-relative path.

The following kinds of values are forbidden:

```text
/absolute/path
../skills
foo/../skills
foo//skills
foo\skills
.
<empty>
```

At the resolved source commit, the root must exist as a real Git tree.

Changing `skillsRoot` is a trust/configuration change and requires a manual registry PR.

### 4.6 `skillPrefixes`

A source may own one or more public skill prefixes.

Examples of meaningful multiple ownership:

```json
"skillPrefixes": [
  "swifql",
  "swql"
]
```

or:

```json
"skillPrefixes": [
  "swifql",
  "swifql2"
]
```

A configured prefix selects public skill names matching:

```text
<prefix>-...
```

For example, the configured prefix `swifql` selects:

```text
swifql-query-building
swifql-custom-extensions
swifql-duckdb-query
```

The configured prefix itself may contain hyphens. For example, `foo-bar` selects `foo-bar-*` skills.

#### Root namespace ownership rule

Prefix ownership is reserved by the **first hyphen-delimited component** of each configured prefix.

Define:

```text
rootNamespace(prefix) = everything before the first "-"
```

Examples:

```text
rootNamespace("swifql")       = swifql
rootNamespace("swifql2")      = swifql2
rootNamespace("foo-bar")      = foo
rootNamespace("foo-baz-extra") = foo
```

That root namespace must be globally unique across the entire federation, including within one source's own prefix list.

Therefore any two configured prefixes with the same first component conflict, even if their full strings would match different skill names.

Examples that are forbidden:

```text
swifql        + swifql-duckdb  -> conflict: root namespace `swifql`
foo           + foo-bar        -> conflict: root namespace `foo`
foo-bar       + foo-baz        -> conflict: root namespace `foo`
foo-bar       + foo-baz-extra  -> conflict: root namespace `foo`
```

Examples that are allowed:

```text
swifql        + swifql2        -> roots `swifql`, `swifql2`
swifql        + swql           -> roots `swifql`, `swql`
foo-bar       + fdb-baz        -> roots `foo`, `fdb`
foo           + foo2-bar       -> roots `foo`, `foo2`
```

This rule deliberately reserves the whole first-component namespace family. If one source owns a configured prefix whose first component is `foo`, no source may claim any other configured prefix whose first component is also `foo`.

For example, a source that owns only `foo-bar` publishes `foo-bar-*` skills, but it still reserves the root namespace `foo` so another source cannot claim `foo-baz`, `foo-tools`, or `foo`.

This is stricter than simple full-prefix overlap detection and is intentional.

A GitHub repository name does not itself grant ownership of a root namespace or prefix. Ownership exists only because accepted `federation.json` grants it.

### 4.7 `description`

Every registered source has a central catalog description stored in `federation.json`.

During onboarding, the default is the current GitHub repository description.

If the repository has no useful GitHub description, automation may propose a simple fallback such as:

```text
Agent Skills published from OWNER/REPO.
```

The requester may provide a custom description during onboarding or a later source update.

The stored value, not a live GitHub lookup, is the deterministic source for the generated README catalog.

Changing the description is a trust/configuration update and follows the manual source-update PR flow.

## 5. Public skill discovery

The registry does not enumerate individual skills.

That is intentional.

A registered source defines:

```text
repository + repositoryId + ref + skillsRoot + skillPrefixes
```

The federation engine discovers the current public skill set from the actual Git tree at the resolved source commit.

### 5.1 Discovery boundary

Only direct child names beneath `skillsRoot` are candidate skill directories.

For each direct child:

1. determine whether its directory name matches at least one owned prefix using `<prefix>-...` semantics;
2. if it does not match any owned prefix, treat it as source-local/non-public and ignore it for federation;
3. if it matches an owned prefix, it is a public federation candidate and must be a valid skill package;
4. a matching candidate that is malformed is a federation failure, not something to silently skip.

This means one root can safely contain both public and contributor/local skills.

For example, SwifQL may contain:

```text
.agent/skills/
  swifql-query-building
  swifql-custom-extensions
  adding-swifql-builder
  adding-swifql-sql-function
  extending-swifql-dialect
```

with:

```json
"skillPrefixes": ["swifql"]
```

The public set is automatically:

```text
swifql-query-building
swifql-custom-extensions
```

The nonmatching contributor skills remain source-local and are not published.

No separate federation-specific public/private marker is required inside `SKILL.md`.

### 5.2 Automatic additions and removals

Because individual skill names are not listed in `federation.json`:

- adding a new valid prefix-matching skill under `skillsRoot` automatically adds it to the next publication;
- changing an existing public skill automatically updates it;
- removing a public skill from the source automatically removes it from the central generated collection;
- renaming a public skill behaves as removal of the old name plus addition of the new name;
- local/contributor skills that do not match an owned prefix remain ignored.

This is a central design goal: normal evolution of a source's public skill set must not require a registry edit.

## 6. Public package validation

Every discovered public candidate is validated fail-closed before publication.

The federation engine must operate on Git tree/object state, not a permissive filesystem copy.

At minimum:

- source root is a Git tree;
- package contains a regular `SKILL.md`;
- package path names are strict UTF-8 POSIX paths;
- allowed Git modes are `040000`, `100644`, and `100755`;
- symlinks (`120000`) are forbidden;
- gitlinks/submodules (`160000`) are forbidden;
- unexpected modes are forbidden;
- executable state is preserved exactly;
- materialized files receive `lstat` defense-in-depth checks;
- `SKILL.md` name equals its package directory name;
- `SKILL.md` has a nonempty description;
- an optional referenced local license must stay inside the package and exist;
- central/provenance metadata must not be injected into source skill packages;
- generic validation must never execute bundled scripts, hooks, binaries, or package code.

## 7. Package identity and provenance

Package bytes and source provenance are separate concepts.

### 7.1 Content identity

A package content digest is computed using the accepted deterministic binary file-manifest algorithm.

It includes:

- relative path bytes;
- executable bit;
- file size;
- SHA-256 of raw file contents.

Therefore identical text with different executable state is a different package.

### 7.2 Provenance identity

The lock records which exact immutable source commit supplied the currently published package.

When a source declaration is unchanged and a later upstream commit leaves the package byte/mode-identical, unrelated upstream commits should not cause publication churn **while the previously locked commit remains retrievable from the canonical source repository**.

The no-churn rule must never preserve provenance that can no longer be independently verified.

If the source branch is force-pushed or history is otherwise rewritten so that the previously locked `resolvedCommit` is no longer retrievable, reconciliation must re-anchor provenance to the current canonical resolved commit even when package bytes/modes are unchanged. In that case:

```text
package bytes/modes unchanged
contentSha256 unchanged
resolvedCommit old -> current retrievable commit
```

This is a provenance-maintenance transition, not semantic package churn.

When the registered source declaration intentionally changes, for example `skillsRoot` or canonical `ref`, the new declaration must obtain new provenance even when package content happens to be byte-identical.

### 7.3 Lock ownership

Because individual skills are discovered dynamically rather than enumerated in `federation.json`, every lock entry must be unambiguously associated with its registered source identity.

Conceptually:

```json
{
  "skills": {
    "swifql-query-building": {
      "sourceId": "swifql",
      "resolvedCommit": "0123456789abcdef0123456789abcdef01234567",
      "contentSha256": "..."
    }
  }
}
```

The exact lock schema remains versioned and deterministic.

## 8. Central polling and authoritative reconciliation

Central polls accepted sources approximately every 15 minutes and also supports manual all-source or targeted reconciliation. Source repositories do not run a federation workflow and do not receive federation credentials.

The scheduled/manual workflow reads exact current accepted `federation.json` authority from central `main`, orders sources deterministically, and invokes the existing one-source reconciliation operation. It never treats workflow inputs, source bytes, or source metadata as trust authority. A missing or moved source during a sweep is bounded stale/current-state behavior; it cannot onboard a source. An empty registry is a clean NOOP and an unknown targeted repository ID is a bounded NOOP.

Central independently derives the accepted source ID, immutable repository ID, canonical locator/ref, skills root, and owned prefixes. Source and PR bytes remain data. `scripts/federate.py` is the sole semantic federation engine.

Polling is current-state and idempotent rather than an event queue. The controller may reconcile each accepted source once in deterministic order and emits at most one finalizer wake for changed work in an all-source sweep. A targeted manual run preserves the one-source operation and its existing finalizer wake behavior.

## 9. Global publication serialization

Generated `federation.lock.json`, `skills/**`, and the README catalog are global shared state. All central state-mutating federation transitions therefore use one serialized finalizer:

1. reconciliation computes deterministic machine work from current accepted authority;
2. a machine publication PR is validated against the exact current accepted base and generated scope;
3. the finalizer re-reads current main, PR head/base, source identity, App identity, and singular App-owned `federation/trusted-validation` evidence;
4. trusted candidate validation is confirmed again before the finalizer publishes green;
5. only the exact current head SHA is eligible for expected-head merge;
6. a main/head/base/source/App/check race makes the candidate stale and prevents merge.

Manual ADD/UPDATE/REMOVE trust/configuration PRs remain human-merge decisions. Their exact current base and deterministic consequences must be revalidated before a maintainer merges them.

## 10. Unknown and empty reconciliation inputs

An unknown targeted repository ID, an empty accepted registry, or a source that disappears during a poll produces bounded NOOP/current-state behavior. These paths must not alter `federation.json`, reserve prefixes, create onboarding trust, or create generated packages by themselves.

## 11. Scheduled/manual recovery

The scheduled poll is the normal recovery path for source changes. A source change may take until the next successful poll to appear centrally. A maintainer can manually dispatch reconciliation sooner for all accepted sources or one accepted repository ID.

## 12. Current-state publication, not event history

If a source advances through several commits between polls, central compares the last successfully published state with the source's current accepted state and publishes only the current deterministic result. It does not need to publish each intermediate commit. Global finalization still serializes shared generated outputs and retries from a fresh current base after races.

## 13. Automatic federation PR lifecycle

For an already registered source with a real publication change discovered by polling:

```text
scheduled/manual central poll
  -> central reconciliation
  -> generated federation PR
  -> independent PR validation
```

### PASS

If every required check passes **and the candidate has completed global single-writer finalization against the current default-branch base**:

```text
PASS -> automatic merge
```

No maintainer click is required for ordinary generated content publication.

A green source-specific check from an older base is not sufficient. The merge-eligible head must be the exact globally finalized candidate whose shared lock/catalog outputs were regenerated against the latest accepted central state.

### FAIL

If validation fails:

1. the bot posts a clear PR comment containing the source, resolved commit where useful, and the exact actionable failure;
2. no invalid central state is published;
3. the PR is automatically closed.

Failed machine-generated federation PRs must not accumulate as stale red PRs.

The source repository is fixed at the source. A later polling run retries reconciliation from the last successfully published central state.

### NOOP

If reconciliation determines that the accepted central publication is already current, no content PR is required.

## 14. Manual PR classes

Manual PRs are used for trust/configuration operations and manual recovery.

There are four conceptually distinct classes:

1. new source onboarding;
2. existing source configuration update;
3. source removal;
4. manual reconciliation of an already registered source.

Trust/configuration PRs and generated content PRs have different merge policies.

## 15. New source onboarding PR

A repository that is not registered can be proposed only through the dedicated add-source PR flow.

The initial PR body uses a structured template.

Conceptually:

```text
Repository URL:
https://github.com/OWNER/REPOSITORY

Description:
<optional; default from GitHub repository description>

Branch:
<optional; default to the GitHub default branch>

Skills root:
<optional if the template defines a conventional default such as .agents/skills>

Skill prefixes:
<optional; comma-separated; default proposed from repository name>
```

### 15.1 Immutable repository URL within one request PR

The repository URL supplied by the initial request is immutable for the lifetime of that PR.

If the requester used the wrong URL, close the PR and create a new request.

This prevents the identity under review from being swapped mid-conversation.

### 15.2 Bot-derived fields

The bot resolves and proposes fields that the requester should not forge directly, including:

- `repositoryId` from GitHub;
- current canonical `OWNER/REPO` spelling;
- a stable `sourceId`;
- default branch when not explicitly provided;
- default description when not explicitly provided;
- automatic candidate prefix(es) when not explicitly provided.

### 15.3 Automatic prefix proposal is only a proposal

For `SomeOrg/GreatDatabase`, the bot might initially propose:

```text
greatdatabase
```

The requester may instead request another available namespace before merge, for example:

```text
greatdb, gdb
```

The bot validates all requested prefixes against global ownership and overlap rules.

### 15.4 Interactive configuration through PR comments

Before the onboarding PR is merged, allowed configuration fields may be refined any number of times through structured comments.

All fields except the repository URL are mutable in this interactive proposal.

A comment acts as a PATCH, not necessarily a complete form.

For example:

```text
Skills root:
.agent/skills

Skill prefixes:
foo, fdb
```

changes only those fields; omitted values retain the current proposal.

Mutable fields include at least:

```text
Description
Branch
Skills root
Skill prefixes
```

The command parser accepts configuration PATCH commands only from the original PR author and designated `swiftstream/skills` maintainers. Arbitrary third-party commenters, source-repository collaborators who are not the PR author, and automation identities other than the federation bot must not be able to rewrite the proposal.

PATCH processing is serialized per PR. The bot must bind every accepted PATCH to the exact current PR head SHA and apply its file mutation with compare-and-swap semantics. If the head changes before the mutation is committed, the bot must abort that attempt and re-evaluate the latest head instead of applying a proposal computed from stale state.

### 15.5 Bot response after every accepted proposal change

After every initial request and every configuration PATCH, the bot posts the complete effective proposal, not merely the changed fields.

A successful response should show, at minimum:

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

It should also show the exact source entry that is currently proposed for `federation.json`.

Finally, every response includes a concise hint/template showing how to post the next update, for example:

```text
To refine this proposal, comment with any fields you want to change:

Description:
...

Branch:
...

Skills root:
...

Skill prefixes:
prefix-one, prefix-two
```

### 15.6 PR branch, diff, and race authority

When a proposal validates successfully, the bot edits the PR branch so the actual `federation.json` diff contains the exact proposed source entry.

The GitHub diff therefore remains the final auditable representation of what a manual merge would accept.

The bot must not rely on hidden comment-only state that disagrees with the file diff.

The request PR must be writable by the federation bot under the accepted GitHub permission model. If a contributor PR originates from a fork, processing is allowed only when the platform exposes an explicitly enabled maintainer-edit path that lets the bot update the current head branch safely. Otherwise the bot must explain that the request cannot be interactively maintained in-place and the request cannot advance to merge-ready state.

Every trust/configuration PR has a strict diff-scope check. The latest validated head may contain only the request/proposal files explicitly allowed for that PR class; unexpected user-supplied central code, workflows, generated packages, or unrelated repository changes make the proposal non-mergeable.

Every bot proposal commit is tied to the exact PR head SHA from which it was computed. Any subsequent requester push invalidates the previous proposal checks and requires a fresh full proposal validation. Manual merge is permitted only for the latest head SHA whose required checks all passed after the final bot mutation.

When accepted central `main` advances while an initial same-repository manual request is still based on an older accepted main, the trusted `Federation main advance` workflow may normalize that request entirely inside GitHub. This automatic normalization is allowed only before an immutable RequestAnchor exists and only after trusted code proves that the current request head differs from its own recorded historical PR base by exactly the valid initial `.federation-request` marker shape for ADD, UPDATE, or REMOVE. Fork heads, malformed or missing markers, anchored stale proposals, unrelated diffs, unexpected modes, or any request whose exact authority cannot be re-established remain fail-closed and are not updated automatically.

The normalization mutation uses GitHub's pull-request `update-branch` operation with the exact current PR head SHA as `expected_head_sha`. The GitHub App token is minted on the GitHub-hosted `Federation main advance` runner and is scoped to the central repository with the write permissions needed for that one cloud mutation. No maintainer workstation credential, private-key read, local JWT, installation token, or local REST controller participates.

A successful cloud update creates the ordinary GitHub `synchronize` event. That event, rather than a second manual dispatch, wakes `Federation interactive` and `Federation trusted validation`; those trusted workflows then re-read current authority, generate the proposal, and continue the normal finalizer path. Thus a main advance can recover a safe stale initial request without a maintainer click while preserving the same exact-head and exact-base race rules used by the interactive flow.

The bot must never merge or mark ready a proposal whose validated SHA differs from the current PR head.

### 15.7 Invalid interactive proposal

If a new PATCH is invalid:

- the bot explains the exact validation failure;
- the previous valid `federation.json` proposal remains unchanged;
- the bot shows the current effective proposal and the next-edit hint;
- the onboarding PR stays open so the requester can correct the proposal with another comment.

Interactive trust/configuration PRs are different from failed machine content PRs: they are intentionally editable conversations and must not be auto-closed merely because one proposed configuration is invalid.

### 15.8 Onboarding merge policy and accepted-base binding

A new-source onboarding PR is never auto-merged.

Every onboarding proposal is validated against two exact identities:

```text
current PR head SHA
current accepted central default-branch base SHA
```

The accepted-base SHA is part of proposal readiness, not merely informational evidence.

Before an onboarding PR can become merge-ready, a globally serialized trust finalizer must:

1. refresh the exact latest accepted central default-branch SHA;
2. reload the latest accepted `federation.json` from that base;
3. re-resolve the proposed GitHub repository identity;
4. revalidate global `sourceId`, `repositoryId`, root-namespace, repository locator, and all other registry constraints against that exact base;
5. update/regenerate the proposal if necessary;
6. bind the final validation result to both the exact current PR head SHA and exact current accepted base SHA;
7. rerun required checks after any head/base change.

If central `main` changes before manual merge, the onboarding proposal immediately becomes non-merge-ready even when its own PR head did not change. It must pass the trust finalizer again against the new accepted base.

Manual merge is allowed only when all three remain current simultaneously:

```text
exact validated PR head
exact validated accepted-base SHA
current PASS result
```

Do not rely on textual Git merge conflicts to serialize semantic source/repository/root-namespace ownership.

Even when all checks pass, the final current proposal waits for a manual merge by the designated maintainer.

The merge is the explicit trust decision:

```text
This repository is now allowed to publish through this federation configuration.
```

## 16. First federation after onboarding merge

The onboarding PR should primarily accept the trust/configuration entry in `federation.json`; it does not need to mix that human trust decision with generated package publication.

After the manual onboarding merge, the source is accepted and eligible for central reconciliation. Scheduled polling is the normal automatic trigger and may take until the next successful approximately 15-minute poll. A maintainer may manually dispatch all-source or targeted reconciliation sooner when immediate work is desired.

When reconciliation actually runs, it begins the normal generated publication transition:

```text
skills/**
federation.lock.json
generated README catalog section
```

It uses the normal machine publication policy:

```text
PASS -> auto-merge
FAIL -> bot comment + close
```

This keeps trust registration and content publication as separate responsibilities.

## 17. Existing source configuration update PR

An already registered source can be changed through a dedicated update-source PR template.

The interaction is intentionally analogous to onboarding.

The initial request identifies the source with an immutable repository URL. The bot resolves `repositoryId` and matches it to the accepted registry entry.

The requester may then refine mutable configuration through structured PATCH comments:

```text
Description
Branch
Skills root
Skill prefixes
```

After every accepted update the bot:

1. revalidates the complete proposed configuration;
2. updates the actual `federation.json` diff in the PR branch;
3. comments with the complete final proposed source entry;
4. lists discovered public skills under that proposal;
5. provides the next-edit hint.

Invalid proposed patches keep the previous valid diff and leave the PR open for correction.

### 17.1 Atomic update merge policy

A source configuration update is a trust/configuration change and is never auto-merged.

It requires a manual maintainer merge.

Unlike first-time onboarding, an update to an already published source must not rely on a later cleanup/publication PR to make the new trust decision effective. Before the update PR can become merge-ready, the federation bot must compute the **complete central state implied by the proposed configuration** and place all deterministic consequences in the same PR.

Depending on the proposal, that atomic diff may include:

```text
federation.json
federation.lock.json
skills/** additions/updates/removals
the generated README Skill Store section
```

This applies even when the configuration change appears administrative, because `ref`, `skillsRoot`, prefix ownership, repository relocation, or description changes can affect provenance, authorization, package selection, or generated catalog state.

The manual merge therefore atomically accepts both:

```text
the new trust/configuration decision
+
the exact generated publication state valid under that decision
```

If the proposed configuration cannot produce a fully validated generated state, the update PR is not merge-ready. It stays interactive so the requester can correct the proposal.

After the atomic merge, a reconciliation run may verify that current upstream still agrees with the just-merged state. If upstream advanced concurrently, that later ordinary content change is handled as a normal generated publication; the old configuration state is never left partially active.

## 18. Repository rename or transfer

Repository relocation is a special case of the existing-source configuration update flow.

For example:

```text
SwifQL/SwifQL
->
swiftstream/SwifQL
```

The new request URL is resolved through GitHub and must identify the same accepted `repositoryId`.

A valid relocation changes the mutable locator while preserving stable identity:

```text
sourceId       unchanged
repositoryId   unchanged
skillPrefixes  unchanged unless separately reviewed
repository     updated to current canonical OWNER/REPO
```

A different GitHub repository ID is not silently treated as a transfer. Replacing one trusted repository with an unrelated repository is a new trust decision and should use explicit removal/onboarding semantics rather than bypassing identity through an update.

## 19. Manual reconciliation PR

A registered source may be rechecked manually without changing federation configuration.

A dedicated technical PR/request contains its repository URL.

The bot resolves it to an already registered source and runs the same reconciliation used by central polling.

Outcomes:

```text
NOOP -> bot comments that central is current, then closes the request PR
CHANGED + PASS -> generated candidate is validated and may auto-merge
FAIL -> bot posts the exact failure and closes the machine publication PR/request
```

If the URL identifies an unknown source, manual reconciliation does not implicitly onboard it. The user is directed to the add-source flow.

## 20. Source removal PR

Removing a source is a trust/configuration operation and must be atomic with removal of the generated state that derives authority from that source.

A dedicated removal PR identifies the registered repository and may contain an optional human reason.

The bot verifies the accepted source identity and prepares one complete removal candidate containing, as applicable:

```text
federation.json source removal
federation.lock.json entries owned by that source removed
skills/** packages owned by that source removed
generated README Skill Store entry/content removed
```

The bot comments with the exact source entry being removed and the currently published skills that disappear in the same merge.

Removal is never auto-merged. It requires a manual maintainer merge.

The removal PR is merge-ready only when the full atomic diff validates against the accepted pre-removal state and no generated package/lock/catalog ownership belonging to the source would remain published after merge.

After the manual merge, no separate cleanup PR is required for correctness: trust revocation and generated cleanup became effective in the same commit/merge transition.

A post-merge reconciliation may verify the resulting central state, but it must not be required to revoke publication authority.

After removal, scheduled polling no longer enumerates the source from accepted `federation.json`. A later targeted reconcile using that removed/unknown repository ID is a bounded NOOP and cannot restore trust or onboard the source.

## 21. Manual trust/configuration PR behavior summary

Manual trust/configuration PRs include:

```text
new source onboarding
existing source configuration update
source removal
repository relocation
prefix ownership changes
canonical ref changes
skillsRoot changes
description changes
```

They are characterized by:

- human initiation;
- explicit visible `federation.json` diff;
- no auto-merge;
- manual maintainer merge required;
- interactive comment-based refinement for add/update flows;
- invalid intermediate configuration does not automatically close the PR.

## 22. Machine content PR behavior summary

Machine content PRs include:

```text
newly discovered public skill package
updated public skill package
removed public skill package
lock provenance/content changes
generated README catalog changes caused by accepted source/publication state
```

They are characterized by:

- generated changes only;
- independent source/provenance validation;
- automatic merge after all checks pass;
- bot error comment + automatic close on failure;
- no stale failed PR accumulation.

A useful governing rule is:

```text
Does the PR change who/where/under-which-namespace we trust?
  YES -> manual merge only
  NO, generated accepted content only -> eligible for auto-merge
```

## 23. README mission and generated catalog

The root README has two kinds of content.

### 23.1 Hand-authored stable introduction

The beginning of the README is concise and user-facing. It includes:

1. the repository mission;
2. a prominent link to this `docs/MECHANICS.md` document;
3. links to the human guides for adding, updating, and removing repositories;
4. basic installation/discovery information where appropriate.

Its writing style should remain concise, friendly, and practical, in the spirit of Swift Stream repositories such as UIKitPlus and CodyFire.

### 23.2 Generated App Store-like catalog

A clearly delimited section of README is generated from accepted federation state.

The generator owns everything between stable markers such as:

```text
<!-- BEGIN FEDERATED SKILLS CATALOG -->
...
<!-- END FEDERATED SKILLS CATALOG -->
```

Hand edits inside that section are forbidden because they will be replaced.

The two central-owned catalog markers are structural tokens, not source data. The renderer must find exactly one valid BEGIN marker and exactly one valid END marker in the expected order. Missing, duplicated, nested, reordered, or otherwise ambiguous marker structure is a fail-closed rendering error.

All source-derived display values are data, never raw README structure. This includes the stored source description, repository display text, skill names, and `SKILL.md` descriptions.

Before insertion into the generated catalog, every source-derived display value is passed through one deterministic Markdown-safe rendering function. At minimum it must:

- normalize line breaks/control whitespace to a deterministic single-line display form where the target position is a heading/table cell;
- escape or otherwise encode Markdown table delimiters and structural punctuation required to keep the value inside its intended cell/text position;
- prevent source-derived text from creating headings, HTML comments, generated BEGIN/END marker semantics, or additional table rows/cells;
- produce byte-identical output for identical input.

The renderer may preserve human wording semantically, but source metadata must never be able to alter the generated catalog's Markdown/marker structure.

For each registered source, the catalog displays a separate subsection containing:

- a human-readable repository title/current repository link;
- the stored federation `description`;
- the source's published skills in a table.

The skill table uses accepted `SKILL.md` metadata, at minimum:

```text
Skill | Description
```

The canonical skill name comes from validated `SKILL.md`/package identity, and the description comes from the validated `SKILL.md` description field.

Example shape:

```markdown
### SwifQL

SQL query builder and dialect toolkit for Swift.

| Skill | Description |
| --- | --- |
| `swifql-query-building` | Build and translate SwifQL queries safely. |
| `swifql-custom-extensions` | Extend SwifQL with custom functions and structural helpers. |
```

The exact wording comes from real accepted metadata rather than a manually maintained catalog.

### 23.3 Catalog regeneration

The generated catalog is recalculated whenever accepted state that affects it changes, including:

- a public skill is added;
- a public skill is removed;
- a public skill description/name changes validly;
- a source description changes;
- a repository locator changes;
- a source is added or removed;
- another accepted registry/publication change affects displayed catalog state.

For ordinary content publication under unchanged accepted trust, the generated catalog transition is included in the same generated publication PR as `skills/**` and `federation.lock.json` changes.

For an existing-source trust/configuration update or removal, the catalog consequences are included in the same manually merged atomic trust/configuration PR rather than deferred to a later machine cleanup PR.

A newly accepted source whose first package publication has not yet succeeded may temporarily exist in `federation.json` before its generated catalog/publication PR merges. Reconciliation is responsible for bringing that first-time generated state into alignment.

## 24. README generation must be deterministic

README catalog generation must not depend on timestamps or nondeterministic API ordering.

The source description is the value stored in `federation.json`, not a fresh GitHub description fetched every render.

Skill display data comes from the accepted generated skill package metadata.

Ordering must be deterministic, for example by a documented case-stable source/skill key.

Running the renderer twice on identical accepted state must produce byte-identical README output.

## 25. PR conversation state and file state

Comments are an interaction mechanism, not the final authority.

For onboarding/update:

```text
comments -> bot computes proposal -> validated PR file diff
```

For onboarding, that proposal may initially be only the accepted `federation.json` trust entry. For an existing-source update, the proposal also includes every required atomic generated consequence described above.

The proposed file diff is authoritative for what a merge will do.

The bot must always restate the complete effective proposal after a change so users do not have to reconstruct hidden state from a long comment history.

If a comment cannot be parsed safely, the bot reports that fact and leaves the last valid file proposal unchanged.

## 26. Suggested structured comment syntax

The exact parser may evolve, but a simple human-readable form is preferred.

Example:

```text
Description:
A better description for the central catalog.

Branch:
stable

Skills root:
.agent/skills

Skill prefixes:
foo, foo2, fdb
```

For branch input, the bot may accept a short human value such as `stable` while rendering/storing the canonical full ref:

```text
refs/heads/stable
```

Prefix input is comma-separated for convenience but stored as a deterministic JSON array.

## 27. Prefix matching and root-namespace details

A public skill matches a configured prefix only on the hyphen boundary:

```text
prefix = swifql
```

matches:

```text
swifql-query-building
swifql-custom-extensions
```

but not:

```text
swifql2-query
swifqlx-query
```

The public name must therefore satisfy:

```text
name starts with prefix + "-"
```

A configured prefix may itself contain hyphens. For example:

```text
prefix = foo-bar
```

matches:

```text
foo-bar-query
```

but not:

```text
foo-baz-query
```

Matching and ownership reservation are intentionally different checks.

For ownership reservation, only the first hyphen-delimited component matters:

```text
foo-bar -> root namespace foo
foo-baz -> root namespace foo
```

so those two configured prefixes cannot coexist anywhere in the federation even though their direct matching sets differ.

Every configured prefix in the accepted registry must have a root namespace that no other configured prefix uses.

Prefix arrays should be normalized/deterministically sorted only if doing so is part of the accepted registry rendering contract; user intent must not be silently rewritten into a semantically different prefix.

## 28. Description behavior in onboarding/update

On first onboarding:

```text
explicit Description supplied -> use it
otherwise GitHub repository description -> use it
otherwise deterministic fallback -> use it
```

The resulting description is stored in `federation.json`.

A later GitHub description change does not silently rewrite central catalog wording. The source owner/maintainer uses an update-source PR if they want the stored description changed.

## 29. Credentials and trust boundaries

Source repositories must not receive a broad credential that can directly write arbitrary central repository content.

Central automation owns generated central branches/PRs and uses its own narrowly scoped GitHub App or equivalent accepted automation identity. Source repositories require no federation credential.

The central PR validation workflow must independently verify generated state before auto-merge.

A source-side success claim is never sufficient publication evidence.

## 30. GitHub App / automation identity expectations

The central automation identity should be capable of:

- creating/updating generated central branches and PRs;
- posting bot comments;
- closing failed/no-op machine PRs;
- enabling/performing accepted auto-merge behavior;
- reading public source repositories as required.

Its permissions must be scoped to the operations actually needed.

Ordinary source repositories should not receive central contents-write authority.

### 30.1 Trusted-code boundary for privileged automation

Any automation that has central write capability, secrets, merge/comment/close authority, or equivalent privileged access executes only trusted automation code from the accepted central default branch or another separately audited trusted deployment.

PR heads, PR titles/bodies, comments, source metadata, source skill metadata, and downloaded request/source files are **untrusted data only**. Privileged automation must not execute code supplied by those inputs or let those inputs replace/alter the trusted validator implementation.

When request/source files must be inspected, trusted central validator code reads and validates their bytes as data. Privileged mutations are allowed only after that trusted code validates the exact current PR head SHA and the exact accepted central base SHA required by the flow.

Untrusted values passed to trusted validators/processes remain validated data arguments and must not become executable command syntax.

### 30.2 Wave 1 live-distribution invariant

Wave 1 uses the central repository's default-branch HEAD as the live distribution state.

Until a later separately researched and audited release-channel design explicitly replaces this rule:

```text
Git tag refs:       zero
GitHub releases:    zero
release workflow:   forbidden
real gh skill publish: forbidden
```

Validation may use `gh skill publish --dry-run` or equivalent non-publishing compatibility checks only.

Wave-1 zero-tags/zero-releases/no-real-publish is a trusted maintainer/operator policy. C03 runtime federation automation does not enumerate remote tags/releases merely to police the administrator; C03 runtime federation automation does not perform a channel-readiness/anti-admin gate. Maintainers must not create or use those publication channels until a later separately researched and audited release policy explicitly replaces this Wave-1 rule.

## 31. Fail-closed remote/source behavior

If central cannot establish required source identity, fetch provenance, package integrity, prefix ownership, or generated-state equivalence, it must not publish.

For a machine PR, the failure is explained and the PR is closed.

For an interactive trust/configuration PR, the invalid proposal is explained and the PR remains open so it can be corrected.

## 32. No stale federation PR invariant

The open PR list should not become a graveyard of failed automatic federation attempts.

Machine PR outcomes converge quickly to:

```text
PASS -> merged
FAIL -> commented + closed
NOOP -> stopped/closed as appropriate
SUPERSEDED -> updated or closed in favor of current state
```

An intentionally open trust/configuration PR means a human decision or interactive proposal is still pending.

A same-repository initial manual request must also not become permanently stranded merely because trusted central `main` advanced after the request was opened. On every `main` push, trusted main-advance automation re-enumerates open requests from current GitHub authority. A stale initial marker-only ADD/UPDATE/REMOVE request may be brought forward with GitHub's exact-head `update-branch` CAS after validation against its recorded historical base; the resulting `synchronize` event resumes the ordinary interactive pipeline. Stale requests that have already acquired an immutable anchor are not silently rebased by this recovery rule and remain subject to their normal exact-base revalidation/recovery semantics.

## 33. Eventual consistency model

The federation guarantees correctness of successfully accepted central state, not immediate publication of every source commit.

The desired convergence rule is:

```text
last accepted central publication
vs
current accepted source configuration + current canonical source tree
```

Intermediate source commits need not appear centrally.

A source change can be recovered by the next successful approximately 15-minute poll or manual reconciliation.

Scheduled polling is the normal recovery path; manual dispatch remains available for immediate work.

## 34. Source additions, updates, removals, and content publication are different operations

The following distinctions are intentional:

### Add source

```text
human proposes trust
-> interactive validation
-> federation.json diff
-> manual merge
-> source becomes eligible for central reconciliation
-> next scheduled poll or maintainer manual reconcile
-> generated publication PR when publication changes
```

### Update source configuration

```text
human proposes trust/config change
-> interactive validation
-> bot computes complete proposed central state
-> one atomic PR contains federation.json + every required generated consequence
-> manual merge
-> optional post-merge verification/reconciliation
```

### Remove source

```text
human proposes trust removal
-> bot computes complete atomic trust + generated cleanup diff
-> federation.json + owned lock/package/catalog removal in the same PR
-> manual merge
-> optional post-merge verification
```

### Publish source content

```text
registered source changes public skills
-> central generated PR
-> validation
-> auto-merge on PASS
-> comment + close on FAIL
```

## 35. State-machine summary

### 35.1 Scheduled/manual polling

```text
CENTRAL POLL
    |
    v
is each source accepted?
   / \
 NO   YES
 |     |
empty registry -> bounded NOOP
       |
       v
   reconcile each current accepted source
       |
       v
   publication changed?
      / \
    NO   YES
    |     |
   stop   v
       generated PR
           |
       validation
        /     \
      PASS    FAIL
       |       |
   auto-merge comment + close
```

### 35.2 Manual add/onboarding

```text
MANUAL ADD-SOURCE PR
        |
        v
structured initial template
        |
        v
bot resolves + validates proposal
        |
        +<-----------------------------+
        |                              |
        v                              |
actual federation.json proposal diff   |
        |                              |
        v                              |
bot prints complete proposal + hint    |
        |                              |
        +-- structured PATCH comment --+
        |
        v
manual maintainer merge only
        |
        v
source accepted for reconciliation
        |
        v
scheduled poll or maintainer manual reconcile
        |
        v
generated publication PR
        |
    PASS -> auto-merge
    FAIL -> comment + close
```

### 35.3 Manual existing-source update

```text
MANUAL UPDATE-SOURCE PR
        |
        v
interactive proposed configuration
        |
        v
bot computes complete central state under proposal
        |
        +<--------------------------------------+
        |                                       |
        v                                       |
federation.json + generated lock/skills/catalog|
        |                                       |
        v                                       |
bot prints complete proposal + hint             |
        |                                       |
        +-- structured PATCH comment -----------+
        |
        v
up-to-date-base + full validation
        |
        v
manual maintainer merge only
        |
        v
trust/config + generated consequences become effective atomically
```

### 35.4 Manual removal

```text
MANUAL REMOVE PR
    |
    v
verify registered identity
    |
    v
compute complete atomic removal
    |
    v
federation.json removal
+ lock/package/catalog removal
    |
    v
manual maintainer merge
    |
    v
trust revocation + cleanup effective atomically
```

## 36. Human guides

The concise user-facing procedures live in:

- [`HOW-TO-PREPARE-SOURCE.md`](HOW-TO-PREPARE-SOURCE.md)
- [`HOW-TO-ADD.md`](HOW-TO-ADD.md)
- [`HOW-TO-UPDATE.md`](HOW-TO-UPDATE.md)
- [`HOT-TO-REMOVE.md`](HOT-TO-REMOVE.md)

Those guides explain how to use the system. This document defines how the system itself works.

## 37. Implementation discipline

Changes to this mechanics specification are architecture changes.

They should be reviewed with the same care as changes to federation schema, trust boundaries, or package validation.

Implementation should not quietly invent mechanics that are absent from this document, and this document should not claim behavior that implementation has not yet been brought into conformance with.

### 37.1 Repository artifacts

This repository maintains transient engineering evidence under ignored `.artifacts/**`, following the same working discipline used by SwifQL.

Typical categories include:

```text
.artifacts/research/**
.artifacts/planning/**
.artifacts/implementation/**
.artifacts/corrections/**
.artifacts/reviews/**
.artifacts/handoff/**
.artifacts/NEW_CHAT.md
```

These artifacts record research, frozen entrypoints, runtime validation, architecture corrections, independent audits, and handoff state. They are working evidence only and must never be committed or published as repository content.

Historical federation artifacts that were created under SwifQL before this central repository adopted its own artifact discipline remain valid lineage evidence; new central-federation artifacts belong here.

### 37.2 Independent Sol audit execution model

Independent Sol architecture/plan/source audits are run by the maintainer in a separate ChatGPT session.

That Sol session uses CodexMCP2 for local repository/source/Git/`.artifacts` evidence and for the single canonical report write authorized by the frozen audit entrypoint.

Local coding agents such as Codex or Luna are not substitutes for the independent Sol auditor. They are used only when a frozen task requires an execution capability unavailable through CodexMCP2, such as shell/runtime/compiler probes.

### 37.3 Commit subject style

Every human or automated commit in `swiftstream/skills` follows the established UIKitPlus/CodyFire subject style:

```text
<single leading emoji> <concise action-oriented subject>
```

Examples:

```text
📖 Document federation mechanics
🛠 Harden federation validation
🤖 Refresh federated skills
```

Automated commits are subject to the same rule. Generic subjects such as `Update files`, `Automated changes`, or timestamp-only messages are forbidden.

When mechanics intentionally change:

1. update this document;
2. update the relevant user guides and README where needed;
3. update schema/scripts/workflows/tests;
4. independently validate the changed trust and failure boundaries;
5. only then treat the new behavior as accepted repository mechanics.

### 37.4 C03 simplified closure

C03 uses central scheduled/manual polling and the C02-backed
`scripts/federate.py` engine. Source repositories require no notifier,
credential, OIDC relay, signing key, proof, or remote readiness ceremony.
Manual trust/configuration PRs remain human decisions; machine publication is
eligible only through exact current-state/App/check/CAS validation and one
serialized finalizer. Wave 1 remains a default-branch HEAD policy with no
tags, releases, or real `gh skill publish` execution.
