# Swift Stream Skills

Swift Stream Skills is a curated public collection of Agent Skills for Swift Stream ecosystem packages.

The semantic source for each skill remains in its owning product repository. This repository federates accepted source packages for public discovery and installation without duplicating their authoring authority.

The packages follow the open Agent Skills format. GitHub CLI's `gh skill` commands are currently a preview capability and are one supported installation route, not the semantic authority for the skill format.

## Install

Browse available skills interactively with:

```text
gh skill install swiftstream/skills
```

Install a specific skill with:

```text
gh skill install swiftstream/skills swifql-query-building
```

## Bootstrap status

This repository is currently in its empty federation bootstrap state. Public skills are not seeded until the subsequent federation seed task is completed and published, so the specific-skill example above describes the intended post-seed flow rather than claiming that the skill is already available from this repository.

Once skills are seeded, use your Agent Skills-compatible client or CLI discovery to see the current collection rather than relying on a hand-maintained catalog in this README.
