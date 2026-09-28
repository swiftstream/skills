import unittest

from scripts import federate as c02


def source_value(source_id="swifql-swifql", lines=None, repository_id=1):
    if lines is None:
        lines = [{"ref": "refs/heads/master", "skillPrefixes": ["swifql"]}]
    return {
        "sourceId": source_id,
        "repository": f"Owner/{source_id}",
        "repositoryId": repository_id,
        "skillsRoot": ".agent/skills",
        "description": "A source",
        "lines": lines,
    }


def manifest_value(sources=None, schema_version=3):
    return {"schemaVersion": schema_version, "sources": sources if sources is not None else [source_value()]}


def lock_value(skills=None, published=None, schema_version=3):
    return {
        "schemaVersion": schema_version,
        "contentDigestAlgorithm": "sha256-file-manifest-v1",
        "publishedSourceIds": published if published is not None else ["swifql-swifql"],
        "skills": skills
        if skills is not None
        else {
            "swifql-query-building": {
                "sourceId": "swifql-swifql",
                "lineRef": "refs/heads/master",
                "resolvedCommit": "a" * 40,
                "contentSha256": "b" * 64,
            }
        },
    }


class VersioningSchemaTests(unittest.TestCase):
    def test_schema_v3_single_line_source_round_trips(self):
        loaded = c02.load_manifest_from_value(manifest_value(), "federation.json")
        self.assertEqual(len(loaded.sources), 1)
        self.assertEqual(len(loaded.sources[0].lines), 1)
        self.assertEqual(loaded.sources[0].lines[0].ref, "refs/heads/master")
        self.assertEqual(loaded.sources[0].lines[0].skill_prefixes, ("swifql",))
        rendered = {
            "schemaVersion": 3,
            "sources": [
                {
                    "sourceId": s.source_id,
                    "repository": s.repository,
                    "repositoryId": s.repository_id,
                    "skillsRoot": s.skills_root,
                    "description": s.description,
                    "lines": [{"ref": line.ref, "skillPrefixes": list(line.skill_prefixes)} for line in s.lines],
                }
                for s in loaded.sources
            ],
        }
        again = c02.load_manifest_from_value(rendered, "federation.json")
        self.assertEqual(again, loaded)

    def test_schema_v3_multi_line_source_sorts_lines_by_ref(self):
        # Lexical order: refs/heads/main < refs/heads/release/4
        sorted_lines = [
            {"ref": "refs/heads/main", "skillPrefixes": ["vapor5"]},
            {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor4"]},
        ]
        unsorted_lines = list(reversed(sorted_lines))
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(
                manifest_value(sources=[source_value(lines=unsorted_lines)]), "federation.json"
            )
        loaded = c02.load_manifest_from_value(
            manifest_value(sources=[source_value(lines=sorted_lines)]), "federation.json"
        )
        self.assertEqual([line.ref for line in loaded.sources[0].lines], ["refs/heads/main", "refs/heads/release/4"])

    def test_schema_rejects_top_level_ref_or_skill_prefixes(self):
        value = source_value()
        value.pop("lines")
        value["ref"] = "refs/heads/master"
        value["skillPrefixes"] = ["swifql"]
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(manifest_value(sources=[value]), "federation.json")

    def test_schema_requires_nonempty_lines_and_exact_line_keys(self):
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(manifest_value(sources=[source_value(lines=[])]), "federation.json")
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(
                manifest_value(sources=[source_value(lines=[{}])]), "federation.json"
            )
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(
                manifest_value(sources=[source_value(lines=[{"ref": "refs/heads/main"}])]), "federation.json"
            )
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(
                manifest_value(
                    sources=[
                        source_value(
                            lines=[{"ref": "refs/heads/main", "skillPrefixes": ["vapor5"], "extra": 1}]
                        )
                    ]
                ),
                "federation.json",
            )

    def test_schema_rejects_duplicate_ref_within_source(self):
        lines = [
            {"ref": "refs/heads/main", "skillPrefixes": ["vapor5"]},
            {"ref": "refs/heads/main", "skillPrefixes": ["vapor6"]},
        ]
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(manifest_value(sources=[source_value(lines=lines)]), "federation.json")

    def test_schema_rejects_duplicate_prefix_across_lines(self):
        lines = [
            {"ref": "refs/heads/main", "skillPrefixes": ["vapor5"]},
            {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor5"]},
        ]
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(manifest_value(sources=[source_value(lines=lines)]), "federation.json")

    def test_schema_rejects_shared_root_across_lines(self):
        # R7: root namespace = first hyphen component. vapor-4 and vapor-5 share root "vapor".
        bad = [
            {"ref": "refs/heads/main", "skillPrefixes": ["vapor-5"]},
            {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor-4"]},
        ]
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(manifest_value(sources=[source_value(lines=bad)]), "federation.json")
        # Distinct single-token roots are allowed.
        good = [
            {"ref": "refs/heads/main", "skillPrefixes": ["vapor5"]},
            {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor4"]},
        ]
        loaded = c02.load_manifest_from_value(manifest_value(sources=[source_value(lines=good)]), "federation.json")
        self.assertEqual(len(loaded.sources[0].lines), 2)
        # Cross-source shared root also fails.
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(
                {
                    "schemaVersion": 3,
                    "sources": [
                        source_value(source_id="a-repo", lines=[{"ref": "refs/heads/main", "skillPrefixes": ["acme"]}], repository_id=1),
                        source_value(source_id="b-repo", lines=[{"ref": "refs/heads/main", "skillPrefixes": ["acme-tools"]}], repository_id=2),
                    ],
                },
                "federation.json",
            )

    def test_schema_rejects_tags_and_non_branch_refs(self):
        for ref in ("refs/tags/4.0.0", "main", "refs/heads/", "refs/heads/../x"):
            with self.subTest(ref=ref), self.assertRaises(c02.FederationError):
                c02.load_manifest_from_value(
                    manifest_value(sources=[source_value(lines=[{"ref": ref, "skillPrefixes": ["vapor5"]}])]),
                    "federation.json",
                )

    def test_lock_v3_requires_lineRef_and_binds_to_a_line(self):
        manifest = c02.load_manifest_from_value(manifest_value(), "federation.json")
        loaded = c02.load_lock_from_value(lock_value(), manifest, "federation.lock.json")
        self.assertEqual(loaded.skills["swifql-query-building"].line_ref, "refs/heads/master")
        rendered = c02.render_lock(loaded)
        again = c02.load_lock_from_value(c02.decode_json(rendered.decode()), manifest, "round-trip")
        self.assertEqual(again, loaded)

        missing = lock_value()
        missing["skills"]["swifql-query-building"].pop("lineRef")
        with self.assertRaises(c02.FederationError):
            c02.load_lock_from_value(missing, manifest, "federation.lock.json")

        unknown = lock_value()
        unknown["skills"]["swifql-query-building"]["lineRef"] = "refs/heads/other"
        with self.assertRaises(c02.FederationError):
            c02.load_lock_from_value(unknown, manifest, "federation.lock.json")

    def test_lock_lineRef_must_match_that_line_prefixes(self):
        manifest = c02.load_manifest_from_value(
            manifest_value(
                sources=[
                    source_value(
                        lines=[
                            {"ref": "refs/heads/master", "skillPrefixes": ["swifql"]},
                            {"ref": "refs/heads/release/2", "skillPrefixes": ["other"]},
                        ]
                    )
                ]
            ),
            "federation.json",
        )
        bad = lock_value(
            skills={
                "swifql-query-building": {
                    "sourceId": "swifql-swifql",
                    "lineRef": "refs/heads/release/2",
                    "resolvedCommit": "a" * 40,
                    "contentSha256": "b" * 64,
                }
            }
        )
        with self.assertRaises(c02.FederationError):
            c02.load_lock_from_value(bad, manifest, "federation.lock.json")

    def test_discovery_per_line_uses_only_that_line_prefixes(self):
        line = c02.LineDeclaration("refs/heads/main", ("vapor4",))
        self.assertTrue(c02.skill_matches_line_prefixes(line, "vapor4-routing"))
        self.assertFalse(c02.skill_matches_line_prefixes(line, "vapor5-routing"))
        source = c02.SourceDeclaration(
            "vapor-vapor",
            "vapor/vapor",
            1,
            ".agent/skills",
            "desc",
            (
                c02.LineDeclaration("refs/heads/main", ("vapor5",)),
                c02.LineDeclaration("refs/heads/release/4", ("vapor4",)),
            ),
        )
        self.assertTrue(c02.skill_matches_source_prefix(source, "vapor4-routing"))
        self.assertTrue(c02.skill_matches_source_prefix(source, "vapor5-routing"))
        self.assertFalse(c02.skill_matches_source_prefix(source, "other-skill"))

    def test_discovery_fails_on_cross_line_duplicate_skill_name(self):
        source = c02.SourceDeclaration(
            "vapor-vapor",
            "vapor/vapor",
            1,
            ".agent/skills",
            "desc",
            (
                c02.LineDeclaration("refs/heads/main", ("vapor",)),
                c02.LineDeclaration("refs/heads/release/4", ("vapor",)),
            ),
        )
        # Same full prefix cannot load; even if forced, name collision is fail-closed in discovery.
        with self.assertRaises(c02.FederationError):
            c02.load_manifest_from_value(
                {
                    "schemaVersion": 3,
                    "sources": [
                        {
                            "sourceId": "vapor-vapor",
                            "repository": "vapor/vapor",
                            "repositoryId": 1,
                            "skillsRoot": ".agent/skills",
                            "description": "desc",
                            "lines": [
                                {"ref": "refs/heads/main", "skillPrefixes": ["vapor"]},
                                {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor"]},
                            ],
                        }
                    ],
                },
                "federation.json",
            )
        self.assertEqual(len(source.lines), 2)

    def test_declaration_change_reanchors_only_changed_line(self):
        source = c02.SourceDeclaration(
            "demo",
            "Owner/Repo",
            99,
            "skills",
            "Demo",
            (
                c02.LineDeclaration("refs/heads/main", ("alpha",)),
                c02.LineDeclaration("refs/heads/release/1", ("beta",)),
            ),
        )
        main_line = source.lines[0]
        release_line = source.lines[1]
        identity_main = c02.declaration_identity(source, main_line, "alpha-one")
        identity_release = c02.declaration_identity(source, release_line, "beta-one")
        self.assertEqual(identity_main.ref, "refs/heads/main")
        self.assertEqual(identity_release.ref, "refs/heads/release/1")
        changed = c02.SourceDeclaration(
            source.source_id,
            source.repository,
            source.repository_id,
            source.skills_root,
            source.description,
            (
                c02.LineDeclaration("refs/heads/main", ("alpha", "gamma")),
                source.lines[1],
            ),
        )
        changed_main = c02.declaration_identity(changed, changed.lines[0], "alpha-one")
        self.assertNotEqual(identity_main, changed_main)
        self.assertEqual(identity_release, c02.declaration_identity(changed, changed.lines[1], "beta-one"))

    def test_migration_shape_maps_swifql_single_line_and_lineRef(self):
        # Migration map: v2 top-level ref/skillPrefixes -> one lines[] entry; lock lineRef = old ref.
        v2_source = {
            "sourceId": "swifql-swifql",
            "repository": "SwifQL/SwifQL",
            "repositoryId": 161410190,
            "ref": "refs/heads/master",
            "skillsRoot": ".agent/skills",
            "skillPrefixes": ["swifql"],
            "description": "A strongly typed, declarative, composable Swift SQL query-building library.",
        }
        migrated = source_value(
            source_id=v2_source["sourceId"],
            lines=[{"ref": v2_source["ref"], "skillPrefixes": v2_source["skillPrefixes"]}],
            repository_id=v2_source["repositoryId"],
        )
        migrated["repository"] = v2_source["repository"]
        migrated["skillsRoot"] = v2_source["skillsRoot"]
        migrated["description"] = v2_source["description"]
        loaded = c02.load_manifest_from_value({"schemaVersion": 3, "sources": [migrated]}, "federation.json")
        self.assertEqual(loaded.sources[0].lines[0].ref, "refs/heads/master")
        lock = c02.load_lock_from_value(
            {
                "schemaVersion": 3,
                "contentDigestAlgorithm": "sha256-file-manifest-v1",
                "publishedSourceIds": ["swifql-swifql"],
                "skills": {
                    "swifql-query-building": {
                        "sourceId": "swifql-swifql",
                        "lineRef": v2_source["ref"],
                        "resolvedCommit": "a" * 40,
                        "contentSha256": "b" * 64,
                    }
                },
            },
            loaded,
            "federation.lock.json",
        )
        self.assertEqual(lock.skills["swifql-query-building"].line_ref, "refs/heads/master")

    def test_validate_stable_identity_continuity_still_one_to_one(self):
        previous = c02.load_manifest_from_value(
            {
                "schemaVersion": 3,
                "sources": [
                    {
                        "sourceId": "demo",
                        "repository": "Owner/Repo",
                        "repositoryId": 99,
                        "skillsRoot": "skills",
                        "description": "Demo",
                        "lines": [{"ref": "refs/heads/main", "skillPrefixes": ["demo"]}],
                    }
                ],
            },
            "previous",
        )
        rebound_id = c02.load_manifest_from_value(
            {
                "schemaVersion": 3,
                "sources": [
                    {
                        "sourceId": "demo",
                        "repository": "Owner/Repo",
                        "repositoryId": 100,
                        "skillsRoot": "skills",
                        "description": "Demo",
                        "lines": [{"ref": "refs/heads/main", "skillPrefixes": ["demo"]}],
                    }
                ],
            },
            "candidate",
        )
        with self.assertRaises(c02.FederationError):
            c02.validate_stable_identity_continuity(previous, rebound_id)
        rebound_sid = c02.load_manifest_from_value(
            {
                "schemaVersion": 3,
                "sources": [
                    {
                        "sourceId": "other",
                        "repository": "Owner/Repo",
                        "repositoryId": 99,
                        "skillsRoot": "skills",
                        "description": "Demo",
                        "lines": [{"ref": "refs/heads/main", "skillPrefixes": ["other"]}],
                    }
                ],
            },
            "candidate",
        )
        with self.assertRaises(c02.FederationError):
            c02.validate_stable_identity_continuity(previous, rebound_sid)
        c02.validate_stable_identity_continuity(previous, previous)


if __name__ == "__main__":
    unittest.main()
