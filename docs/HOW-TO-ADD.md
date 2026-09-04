# How to Add a Repository

Use this flow when a repository is not yet registered in `swiftstream/skills`.
Prepare its directory-package skills with [HOW-TO-PREPARE-SOURCE.md](HOW-TO-PREPARE-SOURCE.md), then open an **Add federation source** pull request.

Adding a repository is an explicit trust/configuration decision. The onboarding PR never auto-merges; a maintainer reviews and merges it manually.

## Request fields

The central App-writable request branch contains one `.federation-request` file whose complete content is `add-source`. Fork heads fail closed. The request body contains:

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
foo, fdb
```

The URL is immutable for the PR. The bot resolves it to a stable GitHub `repositoryId`; that identity can belong to only one accepted source. Branches become canonical `refs/heads/...` refs. Prefix ownership reserves the first hyphen-delimited root namespace globally, even though matching uses the full configured `<prefix>-` string.

The source repository requires no federation notifier workflow, secret, OIDC setup, wake URL, signing key, or central credential.

## Review and refine

The bot reports the repository, immutable identity, source ID, description, canonical ref, skills root, prefixes, discovered public skills, and the exact `federation.json` proposal. Review the file diff as well as the comment.

Before anchoring, fields may be refined with comments beginning on the exact line `Federation PATCH`. After anchoring, the initial body and repository URL are immutable; invalid patches leave the last valid proposal in place. The bot revalidates the complete proposal and current central base after every accepted patch.

Public skills are direct-child packages beneath `skillsRoot` whose names match an accepted prefix and whose `SKILL.md` and package tree pass validation. Individual skills are not listed in the request.

## Manual merge and first publication

The finalizer binds validation to the exact current PR head and accepted central base. It also preserves App-owned check identity, generated-scope, current-state, and CAS protections. A maintainer manually merges the onboarding PR; the trust decision is never auto-merged.

After that merge, central polling reconciles the source and may create the generated publication PR containing `skills/**`, `federation.lock.json`, and the generated README catalog. Normal source changes may appear after the next successful approximately 15-minute poll, or sooner after a maintainer manually dispatches reconciliation. Central uses `scripts/federate.py` as the sole semantic federation engine.

Wave 1 uses default-branch HEAD. No tags, releases, or real `gh skill publish` run is a maintainer policy, not a runtime anti-admin scanner.
