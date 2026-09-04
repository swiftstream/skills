# Add federation source

Create the request branch in the central `swiftstream/skills` repository. Wave 1
accepts only a central-repository, App-writable request head. Fork heads fail
closed; there is no PAT or user-token workaround.

The branch must contain exactly one regular file named `.federation-request`
whose complete content is exactly `add-source` (with a final newline), and the
PR body must use this exact initial grammar:

```text
Repository URL:
<https://github.com/OWNER/REPO>

Description:
<optional value>

Branch:
<optional value>

Skills root:
<optional value>

Skill prefixes:
<optional comma-separated value>
```

The App creates one immutable RequestAnchor before removing the marker. After
anchoring, the body and repository URL are immutable. To refine ADD/UPDATE
fields, use a comment whose first non-empty line is exactly `Federation PATCH`,
followed only by allowed field blocks. The request is manually reviewed and
merged; this R02 flow does not authorize live publication.
