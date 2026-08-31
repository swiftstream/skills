<p align="center">
    <a href="LICENSE">
        <img src="https://img.shields.io/badge/license-MIT-brightgreen.svg" alt="MIT License">
    </a>
    <a href="https://agentskills.io">
        <img src="https://img.shields.io/badge/Agent%20Skills-open%20format-brightgreen.svg" alt="Agent Skills">
    </a>
    <a href="https://discord.gg/q5wCPYv">
        <img src="https://img.shields.io/discord/612561840765141005" alt="Swift.Stream">
    </a>
</p>

<br>

# Swift Stream Skills

Swift Stream Skills is a curated public collection of source-owned Agent Skills. Skills stay maintained in their original repositories while this repository provides one trusted place for discovery, validation, provenance, and installation.

The complete federation, trust, publication, naming, failure, and automation model is documented in **[Repository Mechanics](docs/MECHANICS.md)**.

## Publish your repository

- **[Add a repository](docs/HOW-TO-ADD.md)** — register a new source, choose its skills root and public namespace prefixes, then let federation discover its skills automatically.
- **[Update a registered repository](docs/HOW-TO-UPDATE.md)** — change its description, branch, skills root, prefixes, or verified GitHub location.
- **[Remove a repository](docs/HOT-TO-REMOVE.md)** — revoke source trust and automatically remove its generated skills from the collection.

Ordinary skill additions, edits, and removals do not require a registry PR. Once a source is registered, its current prefix-matching skills are discovered from the accepted source tree and published through validated automation.

## Installation

Browse the collection with GitHub CLI's Agent Skills support:

```text
gh skill install swiftstream/skills
```

Install a specific skill by name:

```text
gh skill install swiftstream/skills <skill-name>
```

`gh skill` is a preview installation route. It is not the semantic authority for the Agent Skills format or for this repository's federation mechanics.

## Skill Store

The catalog below is generated from accepted `federation.json` source metadata and the validated metadata of currently published skill packages. Do not edit the generated section by hand.

<!-- BEGIN FEDERATED SKILLS CATALOG -->

_No repositories have published skills through the federation yet._

<!-- END FEDERATED SKILLS CATALOG -->

## How it works

Source repositories own their skill content. `federation.json` owns central trust/configuration. Generated `skills/**`, `federation.lock.json`, and the Skill Store catalog record the accepted publication state.

Normal source content changes can publish automatically after validation. Adding, reconfiguring, relocating, or removing a trusted source always requires an explicit manual federation-registry merge.

See **[Repository Mechanics](docs/MECHANICS.md)** for the complete state machines and security boundaries.
