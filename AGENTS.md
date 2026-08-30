# Swift Stream Skills Repository Rules

This repository is the public federation/distribution collection for Agent Skills maintained in Swift Stream ecosystem product repositories.

## Ownership

- `federation.json` is the hand-owned canonical source allowlist.
- `federation.lock.json` is machine-generated federation state once the generator exists.
- `skills/**` is machine-generated federation output once skills are seeded.
- Semantic skill edits belong in the owning product repository, never directly under generated `skills/**`.

## Validation and execution safety

- Generic central validation must not execute scripts, binaries, hooks, or other code bundled inside federated skill packages.
- Preserve package files and executable-bit state exactly when federation is implemented.
- Generated files must not be hand-edited after their generator exists.

## Wave 1 distribution policy

- Default-branch HEAD is the live distribution state.
- Git tags and GitHub releases are forbidden in Wave 1 until a later separately researched and audited release policy exists.
- Do not run a real `gh skill publish`; later validation may use `gh skill publish --dry-run` only.

## Git safety

- Keep every mutation and commit scope explicit.
- Preserve unrelated staged, unstaged, and untracked work.
- Do not mix generated federation output with unrelated hand-authored changes.
- Do not stage, commit, amend, push, tag, release, reset, restore, clean, stash, rebase, merge, or otherwise rewrite repository state unless the maintainer explicitly authorizes that exact operation and scope.
