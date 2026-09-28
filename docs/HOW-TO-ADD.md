# How to Add a Repository

Register a source repository so its public Agent Skills appear in the Swift Stream Skills collection.

**Before you start:** package the skills in the source repo with [HOW-TO-PREPARE-SOURCE.md](HOW-TO-PREPARE-SOURCE.md). Each public skill must be a direct child package under your skills root with a valid `SKILL.md`.

Adding a repository is an explicit **trust** decision. The onboarding pull request never auto-merges — a maintainer reviews and merges it.

## 1. Prepare the request

Wave 1 accepts only a **central** request head in `swiftstream/skills` (fork heads fail closed). On a branch of this repository, add exactly one regular file:

```text
.federation-request
```

whose complete content is exactly `add-source` plus a final newline.

## 2. Open the PR with the exact body grammar

Use the [Add federation source PR template](https://github.com/swiftstream/skills/compare/main...main?quick_pull=1&template=add-source.md), or copy this grammar exactly:

```text
Repository URL:
https://github.com/SomeOrg/SomeRepo

Description:
<optional one-line description>

Branch:
<optional; defaults to the repository default branch>

Skills root:
.agent/skills

Skill prefixes:
foo, fdb
```

### Field notes

| Field | Meaning |
| --- | --- |
| **Repository URL** | Exact `https://github.com/OWNER/REPO` (no `.git`, no trailing slash, no query). Immutable after anchoring. Resolved to a stable `repositoryId` that can belong to only one accepted source. |
| **Description** | Optional. Shown in the generated Skill Store catalog. |
| **Branch** | Optional. Canonicalized to a full `refs/heads/...` ref. |
| **Skills root** | Directory in the source repo that holds public skill packages (for example `.agent/skills`). |
| **Skill prefixes** | Comma-separated public namespace prefixes. Matching uses the full `prefix-...` string. Ownership reserves the **first hyphen-delimited root** globally (`foo-bar` reserves `foo`, so `foo-baz` conflicts). |

You do **not** list individual skills. Federation discovers public packages under the skills root whose names match an accepted prefix.

### Optional multi-line form

For a source that publishes more than one major/maintenance line from one repository, use `Publication lines:` instead of `Branch:` + `Skill prefixes:` (the single-line form remains fully sufficient for one line).

```text
Publication lines:
refs/heads/release/4=vapor4; refs/heads/main=vapor5
```

Rules:

- Items are separated by `;`.
- Each item is `ref=prefix[,prefix...]` with a full `refs/heads/**` ref.
- Prefixes on different lines must be disjoint and must not share a root namespace (first hyphen component). Use `vapor4` / `vapor5`, not `vapor-4` / `vapor-5`.
- If `Branch:` and/or `Skill prefixes:` are also present, they must match exactly one listed line.
- Empty `Publication lines:` is invalid; omit the field and use the single-line form instead.

The source repository needs no federation notifier workflow, secret, OIDC setup, wake URL, signing key, or central credential.

## 3. Review and refine

The bot posts a proposal comment with the resolved repository identity, source ID, canonical ref, skills root, prefixes, discovered public skills, and the exact `federation.json` change. Review both the comment and the file diff.

To change mutable fields before the App creates the immutable RequestAnchor, reply with a comment whose first non-empty line is exactly:

```text
Federation PATCH
```

followed only by allowed field blocks (`Description`, `Branch`, `Skills root`, `Skill prefixes`). After anchoring, the initial body and repository URL are immutable. Invalid patches leave the last valid proposal in place.

## 4. Merge and first publication

A maintainer manually merges the onboarding PR. After merge, central polling (about every 15 minutes) reconciles the source and may open a generated publication PR containing `skills/**`, `federation.lock.json`, and the generated README catalog. That machine PR can auto-merge after validation and finalization.

You can also trigger reconciliation sooner from the Actions tab (`Federation reconcile`).

## Troubleshooting

| Symptom | What to do |
| --- | --- |
| `PROPOSAL_BLOCKED` on the PR | Read the bot comment reason (exception type + bounded message). Fix the request body or source package state, then re-run or PATCH. |
| `InvalidResponseError` … *issue comment REST authority changed during composite read* | Transient comment-read race. Re-dispatch `federation-interactive.yml` for that PR. Recent hardening retries this race automatically. |
| Fork head rejected | Wave 1 is central-repo request heads only. Open the branch in `swiftstream/skills`. |
| Skills not discovered | Check package layout in [HOW-TO-PREPARE-SOURCE.md](HOW-TO-PREPARE-SOURCE.md) and that names match your prefixes. |

## Related

- [HOW-TO-PREPARE-SOURCE.md](HOW-TO-PREPARE-SOURCE.md) — package layout and public vs local skills
- [HOW-TO-UPDATE.md](HOW-TO-UPDATE.md) — change a registered source
- [HOW-TO-REMOVE.md](HOW-TO-REMOVE.md) — revoke a source
- [MECHANICS.md](MECHANICS.md) — full trust and publication model
