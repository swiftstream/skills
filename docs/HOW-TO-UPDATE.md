# How to Update a Registered Repository

Change a registered source's **description, branch, skills root, prefixes, or GitHub locator** (same stable `repositoryId` after rename/transfer).

**Ordinary skill content changes do not need a registry PR.** Once registered, add/edit/remove public packages in the source repository and let polling publish them.

Updates are explicit **trust/configuration** decisions and never auto-merge.

## Request

On a central branch in `swiftstream/skills`, add exactly one `.federation-request` file whose content is exactly `update-source` plus a final newline (fork heads fail closed).

Open the [Update federation source PR template](https://github.com/swiftstream/skills/compare/main...main?quick_pull=1&template=update-source.md) with the exact body grammar:

```text
Repository URL:
https://github.com/SomeOrg/SomeRepo

Description:
<optional value>

Branch:
<optional value>

Skills root:
<optional value>

Skill prefixes:
<optional comma-separated value>
```

The repository URL must resolve to the **same** accepted `repositoryId`. A different repository is not silently treated as the same source.

## Publication lines

UPDATE may add, remove, or change publication lines. The proposed `Publication lines:` value is a **full replacement** of the accepted line set (not a merge).

### Dropped publication lines

When the proposal omits one or more accepted lines, the request must name each omitted ref in `Dropped publication lines:` (comma-separated full refs).

```text
Repository URL:
https://github.com/vapor/vapor

Description:
Server-side Swift web framework.

Skills root:
.agent/skills

Publication lines:
refs/heads/main=vapor5

Dropped publication lines:
refs/heads/release/4
```

Fail-closed drop rules:

- Only UPDATE may use `Dropped publication lines`. ADD with drops is invalid.
- Named drops must equal exactly `(accepted refs − proposed refs)`.
- A named drop that is still proposed is invalid.
- Dropping the last remaining line is invalid; use remove-source instead.
- Replacing ref A with ref B is a drop of A plus an add of B; name A.
- Changing a line's prefixes without changing its ref is not a drop.
- The drop set is evaluated on the final folded request after PATCH.

Generated lock/package/catalog consequences for dropped lines are removed in the same atomic UPDATE.

## Refining the proposal

Comments whose first non-empty line is exactly `Federation PATCH` may refine mutable fields before anchoring. After the RequestAnchor exists, the initial body and repository URL are immutable.

Every accepted proposal is revalidated against the exact current accepted central `main` and includes **all** deterministic consequences in one atomic diff:

```text
federation.json
federation.lock.json
skills/**
the generated README Skill Store section
```

A maintainer manually merges that complete transition. There is no later cleanup PR.

## Prefix reminder

Prefix ownership is global by the first hyphen-delimited root namespace. A configured `foo-bar` publishes `foo-bar-*` but reserves the root `foo` against other `foo-*` prefixes. Distinct major-line roots such as `vapor4` and `vapor5` are allowed; `vapor` and `vapor5` conflict.

## After merge

Central polling reconciles the current source. A normal change may wait until the next successful ~15-minute poll; a maintainer can dispatch reconciliation sooner for all sources or one accepted repository ID.

## Related

- [HOW-TO-ADD.md](HOW-TO-ADD.md) — first-time registration
- [HOW-TO-REMOVE.md](HOW-TO-REMOVE.md) — revoke trust
- [FEDERATION-OPERATIONS.md](FEDERATION-OPERATIONS.md) — operator view
- [MECHANICS.md](MECHANICS.md) — atomic update rules (§17)
