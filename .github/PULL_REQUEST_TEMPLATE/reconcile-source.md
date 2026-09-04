# Reconcile federation source (R02 phase-gated)

Use a branch in the central `swiftstream/skills` repository. Wave 1 accepts
only a central-repository, App-writable request head. Fork heads fail closed;
there is no PAT or user-token workaround.

The branch must contain exactly one regular `.federation-request` file whose
complete content is exactly `reconcile-source` (with a final newline). The PR
body uses this exact initial grammar:

```text
Repository URL:
<https://github.com/OWNER/REPO>
```

The App creates one immutable RequestAnchor before removing the marker. The
body and repository URL are immutable, and RECONCILE has no mutable PATCH
fields. R02 recognizes and validates this technical request but leaves
reconciliation explicitly phase-gated: it never pretends reconciliation
occurred, never merges this request, and reports that R03 is required.
