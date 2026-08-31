# Swift Stream Skills Repository Rules

This repository is the public federation/distribution collection for Agent Skills maintained in source product repositories.

## Canonical mechanics

- `docs/MECHANICS.md` is the canonical human-readable specification for repository mechanics, trust boundaries, federation state transitions, naming/prefix ownership, interactive PR behavior, publication, failure handling, and generated catalog behavior.
- `docs/HOW-TO-PREPARE-SOURCE.md` is the canonical agent-facing operational guide for source-repository skill package structure, legacy-skill migration, PUBLIC-vs-LOCAL classification, and pre-C03 notifier readiness. Source-migration agents should read it instead of inferring package layout from `scripts/federate.py`.
- Implementation, workflows, schemas, and other documentation must not silently contradict `docs/MECHANICS.md`.
- Intentional mechanics changes must update `docs/MECHANICS.md` and all affected user guides/README behavior before the new mechanics are treated as accepted.

## Ownership

- `federation.json` is the hand-owned canonical source trust/configuration registry.
- `federation.lock.json` is machine-generated immutable publication provenance/content state once sources are published.
- `skills/**` is machine-generated federation output.
- The generated Skill Store section of `README.md` is machine-owned between its stable generation markers.
- Semantic skill edits belong in the owning source repository, never directly under generated `skills/**`.
- Individual public skills are discovered from each accepted source's configured skills root and prefix ownership; they are not manually enumerated in the federation registry.

## Trust versus generated publication

- Adding, removing, relocating, or reconfiguring a trusted source is a manual federation-registry decision and must never auto-merge.
- First-time onboarding may merge trust/configuration before first generated publication because no previously authorized central package state exists for that source yet.
- Updating or removing an already published source must be atomic with every deterministic generated consequence required by the new trust decision. The same manual PR must include the corresponding lock/package/catalog changes; correctness must not depend on a later cleanup PR.
- Ordinary generated skill/lock/catalog publication from an already trusted and unchanged source configuration may auto-merge only after all required checks and global single-writer finalization against current central `main` pass.
- Failed machine-generated federation PRs must receive an actionable bot comment and close automatically rather than remaining as stale red PRs.
- Invalid intermediate proposals in interactive manual add/update PRs remain open for correction; the last valid file proposal remains authoritative.
- Automatic notifications from repositories absent from accepted `federation.json` are ignored and cannot onboard a source.
- There is no scheduled/cron reconciliation. Recovery is through a later source push or an explicit manual reconciliation request.

## Validation and execution safety

- Generic central validation must not execute scripts, binaries, hooks, or other code bundled inside federated skill packages.
- Privileged central automation executes trusted central automation/validator code only. PR heads, comments, source files, and source metadata are untrusted data and must never replace or become executable privileged logic.
- Preserve package files and executable-bit state exactly when federation is implemented.
- Generated files must not be hand-edited after their generator exists.
- Generated README catalog values must be rendered through deterministic Markdown-safe containment; source metadata must never create catalog markers, headings, table structure, or other central-owned Markdown structure.
- Prefix ownership reserves the first hyphen-delimited component as a global root namespace. Every configured prefix must have a unique root namespace across the entire federation, including within one source. Thus `swifql` conflicts with `swifql-duckdb`, and `foo-bar` conflicts with `foo-baz`, because the reused roots are `swifql` and `foo` respectively. Matching still uses the full configured `<prefix>-...` string.
- Repository trust is bound to stable GitHub repository identity, not merely mutable `OWNER/REPO` spelling. Accepted `sourceId` and `repositoryId` bindings are globally one-to-one; an accepted repository ID cannot be onboarded as a second source.
- Every manual trust/configuration proposal, including trust-only onboarding, is merge-ready only when validated against both its exact current PR head SHA and the exact current accepted central base SHA.

## Wave 1 distribution policy

- Default-branch HEAD is the live distribution state.
- Git tags and GitHub releases are forbidden in Wave 1 until a later separately researched and audited release policy exists.
- Do not run a real `gh skill publish`; later validation may use `gh skill publish --dry-run` only.

## Artifact and audit discipline

- `.artifacts/**` is the transient, ignored planning/research/implementation/review/handoff evidence area for this repository, following the same working discipline used by SwifQL.
- `.artifacts/**` must never be committed or published as repository content.
- New central-federation planning, corrections, implementation reports, frozen audit entrypoints, audit reports, and handoffs belong under this repository's `.artifacts/**`. Historical SwifQL-hosted federation artifacts remain valid lineage evidence and are not rewritten retroactively.
- Independent Sol audits are executed by the maintainer in a separate ChatGPT session using CodexMCP2 for all required local repository evidence and the single authorized audit-report write.
- Local coding agents such as Codex/Luna are used only for execution capabilities that are unavailable through CodexMCP2, such as shell/runtime probes when a frozen validation entrypoint explicitly requires them.

## Commit style

- Every human or automated commit in this repository must follow the established UIKitPlus/CodyFire style: a single leading emoji followed by a concise imperative/verb-led subject.
- Examples: `📖 Document federation mechanics`, `🛠 Harden federation validation`, `🤖 Refresh federated skills`.
- Automated federation commits are not exempt from this rule and must use a stable, meaningful leading emoji; do not emit generic subjects such as `Update files` or `Automated changes`.

## Git safety

- Keep every mutation and commit scope explicit.
- Preserve unrelated staged, unstaged, and untracked work.
- Do not mix generated federation output with unrelated hand-authored changes.
- Do not stage, commit, amend, push, tag, release, reset, restore, clean, stash, rebase, merge, or otherwise rewrite repository state unless the maintainer explicitly authorizes that exact operation and scope.