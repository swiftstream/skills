# Update federation source

Use a branch in the central `swiftstream/skills` repository. Wave 1 accepts
only a central-repository, App-writable request head. Fork heads fail closed;
there is no PAT or user-token workaround.

The branch must contain exactly one regular `.federation-request` file whose
complete content is exactly `update-source` (with a final newline). The PR
body uses the exact initial grammar:

```text
Repository URL:
<https://github.com/OWNER/REPO>

Description:
<optional value>

Branch:
<optional single-line value>

Skills root:
<optional value>

Skill prefixes:
<optional comma-separated value>

Publication lines:
<optional; full replacement of accepted lines; refs/heads/...=prefix[,prefix...]; ...>

Dropped publication lines:
<UPDATE only when omitting accepted lines; comma-separated full refs>
```

When the proposal omits one or more accepted publication lines, each omitted
ref must be named in `Dropped publication lines`. Dropping the last remaining
line is invalid (use remove-source).

The repository URL and initial body are immutable after the App creates its
single immutable RequestAnchor. Body edits are not PATCH operations. Refine
other fields only with a comment whose first non-empty line is exactly
`Federation PATCH`, followed only by allowed field blocks. The complete atomic
configuration consequence is reviewed and manually merged.
