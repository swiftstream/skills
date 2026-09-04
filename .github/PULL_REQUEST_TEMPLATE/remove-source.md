# Remove federation source

Use a branch in the central `swiftstream/skills` repository. Wave 1 accepts
only a central-repository, App-writable request head. Fork heads fail closed;
there is no PAT or user-token workaround.

The branch must contain exactly one regular `.federation-request` file whose
complete content is exactly `remove-source` (with a final newline). The PR
body uses this exact initial grammar:

```text
Repository URL:
<https://github.com/OWNER/REPO>

Reason:
<optional value>
```

The App creates one immutable RequestAnchor before removing the marker. The
body and repository URL remain immutable. REMOVE does not accept mutable
PATCH fields; comments beginning `Federation PATCH` do not change REMOVE
state. The complete C02-generated removal is reviewed and manually merged.
