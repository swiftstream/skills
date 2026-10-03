import ast
from pathlib import Path
import unittest
from unittest.mock import patch

import automation.federation.controller as controller_module
from automation.federation.controller import (
    C02CandidateBuilder,
    IssueSourceAuthority,
    IssueSourceIdentityKind,
    PhaseNotImplementedError,
    PublicSourceMetadata,
    R01Controller,
    R02Error,
    classify_request,
    parse_c02_manifest,
    resolve_issue_source_authority,
)
from automation.federation.request_model import CommentEvent, RequestClass, RequestAnchor, parse_request_body, body_sha256
from scripts import federate as c02


class ControllerCoreTests(unittest.TestCase):
    @staticmethod
    def source_request(request_class, repository_url="https://github.com/Owner/Repo"):
        if request_class is RequestClass.REMOVE:
            body = f"Repository URL:\n{repository_url}\nReason:\nretire\n"
        else:
            body = f"Repository URL:\n{repository_url}\n"
        return parse_request_body(request_class, body)

    @staticmethod
    def accepted_manifest(source_id="accepted-source", repository="Owner/Repo", repository_id=41):
        return parse_c02_manifest(
            {
                "schemaVersion": 3,
                "sources": [
                    {
                        "sourceId": source_id,
                        "repository": repository,
                        "repositoryId": repository_id,
                        "skillsRoot": "skills",
                        "description": "Accepted source",
                        "lines": [{"ref": "refs/heads/main", "skillPrefixes": [source_id]}],
                    }
                ],
            }
        )

    def test_add_issue_source_authority_binds_proposed_source_identity(self):
        request = self.source_request(RequestClass.ADD)
        metadata = PublicSourceMetadata(99, "owner/repo", "main", "Source description")
        authority = resolve_issue_source_authority(request, RequestClass.ADD, c02.Manifest(()), metadata)
        self.assertEqual(authority, IssueSourceAuthority(
            RequestClass.ADD,
            "owner-repo",
            99,
            "owner/repo",
            IssueSourceIdentityKind.PROPOSED,
            "main",
            "Source description",
        ))
        with self.assertRaises(AttributeError):
            authority.source_id = "changed"

    def test_add_issue_source_authority_rejects_source_id_collision(self):
        accepted = self.accepted_manifest(source_id="owner-repo", repository="Elsewhere/Repo", repository_id=100)
        with self.assertRaises(R02Error):
            resolve_issue_source_authority(
                self.source_request(RequestClass.ADD),
                RequestClass.ADD,
                accepted,
                PublicSourceMetadata(99, "Owner/Repo", "main", None),
            )

    def test_add_issue_source_authority_rejects_repository_id_collision(self):
        accepted = self.accepted_manifest(source_id="other-source", repository="Elsewhere/Repo", repository_id=99)
        with self.assertRaises(R02Error):
            resolve_issue_source_authority(
                self.source_request(RequestClass.ADD),
                RequestClass.ADD,
                accepted,
                PublicSourceMetadata(99, "Owner/Repo", "main", None),
            )

    def test_update_issue_source_authority_selects_accepted_source_by_repository_id(self):
        accepted = self.accepted_manifest(source_id="accepted-source", repository_id=41)
        authority = resolve_issue_source_authority(
            self.source_request(RequestClass.UPDATE),
            RequestClass.UPDATE,
            accepted,
            PublicSourceMetadata(41, "owner/repo", "release", "Current metadata"),
        )
        self.assertEqual(authority.source_id, "accepted-source")
        self.assertEqual(authority.source_repository_id, 41)
        self.assertEqual(authority.source_identity_kind, IssueSourceIdentityKind.ACCEPTED)

    def test_remove_issue_source_authority_selects_accepted_source_by_repository_id(self):
        accepted = self.accepted_manifest(source_id="accepted-source", repository_id=41)
        authority = resolve_issue_source_authority(
            self.source_request(RequestClass.REMOVE),
            RequestClass.REMOVE,
            accepted,
            PublicSourceMetadata(41, "Owner/Repo", "main", None),
        )
        self.assertEqual(authority.source_id, "accepted-source")
        self.assertEqual(authority.source_identity_kind, IssueSourceIdentityKind.ACCEPTED)

    def test_update_and_remove_unknown_repository_id_are_blocked(self):
        accepted = self.accepted_manifest(repository_id=41)
        for request_class in (RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(request_class=request_class), self.assertRaises(R02Error):
                resolve_issue_source_authority(
                    self.source_request(request_class),
                    request_class,
                    accepted,
                    PublicSourceMetadata(42, "Owner/Repo", "main", None),
                )

    def test_issue_source_authority_rejects_canonical_name_mismatch(self):
        with self.assertRaises(R02Error):
            resolve_issue_source_authority(
                self.source_request(RequestClass.ADD),
                RequestClass.ADD,
                c02.Manifest(()),
                PublicSourceMetadata(99, "owner/different", "main", None),
            )

    def test_issue_source_authority_rejects_class_mismatch_and_unsupported_class(self):
        accepted = c02.Manifest(())
        add_request = self.source_request(RequestClass.ADD)
        with self.assertRaises(R02Error):
            resolve_issue_source_authority(
                add_request,
                RequestClass.UPDATE,
                accepted,
                PublicSourceMetadata(99, "Owner/Repo", "main", None),
            )
        reconcile = parse_request_body(RequestClass.RECONCILE, "Repository URL:\nhttps://github.com/Owner/Repo\n")
        with self.assertRaises(R02Error):
            resolve_issue_source_authority(
                reconcile,
                RequestClass.RECONCILE,
                accepted,
                PublicSourceMetadata(99, "Owner/Repo", "main", None),
            )
        with self.assertRaises(R02Error):
            IssueSourceAuthority(
                RequestClass.ADD,
                "owner-repo",
                99,
                "Owner/Repo",
                "proposed",
                "main",
                None,
            )

    def test_c02_candidate_planning_uses_shared_issue_source_resolver(self):
        request = parse_request_body(
            RequestClass.ADD,
            "Repository URL:\nhttps://github.com/Owner/Repo\n"
            "Description:\nA source\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n",
        )
        accepted = c02.Manifest(())
        metadata = PublicSourceMetadata(99, "owner/repo", "main", "Source description")
        builder = C02CandidateBuilder(object(), "swiftstream/skills", trusted_checkout_sha="a" * 40)
        builder._capsule_temp_root = Path(".")
        with (
            patch.object(builder, "_current_base", return_value=(None, "a" * 40)),
            patch.object(builder, "_central_state", return_value=(accepted, None, b"", {})),
            patch.object(builder, "_validate_add_source"),
            patch.object(controller_module, "read_public_source_metadata", return_value=metadata),
            patch.object(
                controller_module,
                "resolve_issue_source_authority",
                wraps=resolve_issue_source_authority,
            ) as shared_resolver,
        ):
            desired, _tree, source_id, repository_id = builder._plan(request, RequestClass.ADD, "a" * 40)
        shared_resolver.assert_called_once_with(request, RequestClass.ADD, accepted, metadata)
        self.assertEqual((source_id, repository_id), ("owner-repo", 99))
        self.assertEqual(set(desired), {"federation.json"})

    def test_authority_and_structural_classification(self):
        self.assertEqual(classify_request(marker_content="add-source"), RequestClass.ADD)
        self.assertEqual(classify_request(marker_content="unexpected", head_branch="bot/federation/swifql"), RequestClass.MACHINE_PUBLICATION)
        self.assertEqual(classify_request(head_branch="bot/federation/not valid"), RequestClass.UNRELATED)
        self.assertEqual(classify_request(title="add-source", head_branch="feature"), RequestClass.UNRELATED)
        body = "Repository URL:\nhttps://github.com/O/R\n"
        request = parse_request_body(RequestClass.RECONCILE, body)
        anchor = RequestAnchor(1, RequestClass.RECONCILE, "id", "login", body_sha256(body), request)
        self.assertEqual(classify_request(title="anything", anchor=anchor), RequestClass.RECONCILE)

    def test_c02_adapter_and_phase_boundary(self):
        manifest = parse_c02_manifest({"schemaVersion": 3, "sources": []})
        self.assertEqual(manifest.sources, ())
        controller = R01Controller()
        with self.assertRaises(PhaseNotImplementedError):
            controller.finalize_live_request()
        with self.assertRaises(PhaseNotImplementedError):
            controller.mutate_github()
        with self.assertRaises(PhaseNotImplementedError):
            controller.reconcile()

    def test_all_structural_classes_and_anchor_authority(self):
        bodies = {
            RequestClass.ADD: "Repository URL:\nhttps://github.com/O/R\nDescription:\nd\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n",
            RequestClass.UPDATE: "Repository URL:\nhttps://github.com/O/R\nDescription:\nd\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n",
            RequestClass.REMOVE: "Repository URL:\nhttps://github.com/O/R\nReason:\nwhy\n",
            RequestClass.RECONCILE: "Repository URL:\nhttps://github.com/O/R\n",
        }
        for index, (request_class, body) in enumerate(bodies.items(), 1):
            request = parse_request_body(request_class, body)
            anchor = RequestAnchor(index, request_class, "id", "login", body_sha256(body), request)
            self.assertEqual(classify_request(marker_content=None, title="remove-source", head_branch="main", anchor=anchor), request_class)
            self.assertEqual(classify_request(marker_content=request_class.value), request_class)
        self.assertEqual(classify_request(marker_content="machine-publication"), RequestClass.UNRELATED)
        self.assertEqual(classify_request(marker_content="unexpected", head_branch="bot/federation/swifql"), RequestClass.MACHINE_PUBLICATION)
        for branch in ("bot/federation/SwifQL", "bot/federation/not_valid", "bot/federation/foo/bar", "bot/federation/"):
            with self.subTest(branch=branch):
                self.assertEqual(classify_request(head_branch=branch), RequestClass.UNRELATED)
        self.assertEqual(classify_request(title="add-source", head_branch="feature"), RequestClass.UNRELATED)

    def test_complete_patch_reconstruction_uses_pure_fold(self):
        body = "Repository URL:\nhttps://github.com/O/R\nDescription:\nd\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n"
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(1, RequestClass.ADD, "id", "login", body_sha256(body), request)
        controller = R01Controller()
        result = controller.reconstruct(anchor, [CommentEvent(2, True, "Federation PATCH\n\nDescription:\nupdated\n")])
        self.assertEqual(result.request.description, "updated")

    def test_c02_adapter_is_reused_without_duplicate_semantics(self):
        with patch("automation.federation.controller.c02.load_manifest_from_value", return_value=object()) as loader:
            self.assertIs(parse_c02_manifest({"schemaVersion": 3, "sources": []}), loader.return_value)
            loader.assert_called_once_with({"schemaVersion": 3, "sources": []}, "candidate federation.json")

    def test_r02_plus_live_methods_are_explicitly_phase_blocked(self):
        controller = R01Controller()
        for method in (controller.finalize_live_request, controller.mutate_github, controller.reconcile):
            with self.subTest(method=method), self.assertRaises(PhaseNotImplementedError):
                method()

    def test_controller_has_no_live_network_or_mutation_seam(self):
        controller = R01Controller()
        self.assertEqual(controller.classify(marker_content="unrelated"), RequestClass.UNRELATED)
        with self.assertRaises(PhaseNotImplementedError):
            controller.mutate_github("would mutate")

    def test_module_entrypoint_guard_follows_all_top_level_definitions(self):
        path = Path(controller_module.__file__).resolve()
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        def is_main_guard(node):
            return (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"
            )

        guard_indices = [index for index, node in enumerate(module.body) if is_main_guard(node)]
        self.assertEqual(guard_indices, [len(module.body) - 1])
        guard_index = guard_indices[0]
        definitions = {
            node.name: index
            for index, node in enumerate(module.body)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        self.assertLess(definitions["main"], guard_index)
        self.assertLess(definitions["validate_candidate_diff"], guard_index)
        self.assertFalse(
            any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in module.body[guard_index + 1:])
        )

    def test_c02_source_candidate_builds_multi_line_source(self):
        from automation.federation.controller import c02_source_candidate
        from automation.federation.request_model import parse_request_body, RequestClass

        body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/release/4=vapor4; refs/heads/main=vapor5\n"
        )
        request = parse_request_body(RequestClass.ADD, body)
        empty = parse_c02_manifest({"schemaVersion": 3, "sources": []})
        candidate = c02_source_candidate(
            request,
            empty,
            source_id="vapor-vapor",
            repository_id=1,
            default_branch="main",
            default_description="Framework",
            default_prefixes=("vapor5",),
        )
        self.assertEqual(len(candidate.sources), 1)
        self.assertEqual([line.ref for line in candidate.sources[0].lines], ["refs/heads/main", "refs/heads/release/4"])
        self.assertEqual(candidate.sources[0].lines[0].skill_prefixes, ("vapor5",))
        self.assertEqual(candidate.sources[0].lines[1].skill_prefixes, ("vapor4",))

    def test_update_replaces_full_line_set(self):
        from automation.federation.controller import c02_source_candidate
        from automation.federation.request_model import parse_request_body, RequestClass

        accepted = parse_c02_manifest(
            {
                "schemaVersion": 3,
                "sources": [
                    {
                        "sourceId": "vapor-vapor",
                        "repository": "vapor/vapor",
                        "repositoryId": 1,
                        "skillsRoot": "skills",
                        "description": "Framework",
                        "lines": [
                            {"ref": "refs/heads/main", "skillPrefixes": ["vapor5"]},
                            {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor4"]},
                        ],
                    }
                ],
            }
        )
        body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/main=vapor5\n"
            "Dropped publication lines:\nrefs/heads/release/4\n"
        )
        request = parse_request_body(RequestClass.UPDATE, body)
        candidate = c02_source_candidate(
            request,
            accepted,
            source_id="vapor-vapor",
            repository_id=1,
            default_branch="main",
            default_description="Framework",
            default_prefixes=("vapor5",),
        )
        self.assertEqual(len(candidate.sources[0].lines), 1)
        self.assertEqual(candidate.sources[0].lines[0].ref, "refs/heads/main")
        self.assertEqual(candidate.sources[0].lines[0].skill_prefixes, ("vapor5",))

    def test_manifest_value_emits_schema_v3_lines(self):
        from automation.federation.controller import manifest_value
        from scripts import federate as c02

        source = c02.SourceDeclaration(
            "demo",
            "Owner/Repo",
            99,
            "skills",
            "Demo",
            (c02.LineDeclaration("refs/heads/main", ("demo",)),),
        )
        value = manifest_value(c02.Manifest((source,)))
        self.assertEqual(value["schemaVersion"], 3)
        self.assertEqual(value["sources"][0]["lines"], [{"ref": "refs/heads/main", "skillPrefixes": ["demo"]}])
        self.assertNotIn("ref", value["sources"][0])
        self.assertNotIn("skillPrefixes", value["sources"][0])

    def test_update_drop_one_line_is_atomic_with_generated_removal(self):
        from automation.federation.controller import c02_source_candidate
        from automation.federation.request_model import parse_request_body, RequestClass
        from scripts import federate as c02

        accepted = parse_c02_manifest(
            {
                "schemaVersion": 3,
                "sources": [
                    {
                        "sourceId": "vapor-vapor",
                        "repository": "vapor/vapor",
                        "repositoryId": 1,
                        "skillsRoot": "skills",
                        "description": "Framework",
                        "lines": [
                            {"ref": "refs/heads/main", "skillPrefixes": ["vapor5"]},
                            {"ref": "refs/heads/release/4", "skillPrefixes": ["vapor4"]},
                        ],
                    }
                ],
            }
        )
        body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/main=vapor5\n"
            "Dropped publication lines:\nrefs/heads/release/4\n"
        )
        request = parse_request_body(RequestClass.UPDATE, body)
        candidate = c02_source_candidate(
            request,
            accepted,
            source_id="vapor-vapor",
            repository_id=1,
            default_branch="main",
            default_description="Framework",
            default_prefixes=("vapor5",),
        )
        source = candidate.sources[0]
        proposed_refs = {line.ref for line in source.lines}
        self.assertEqual(proposed_refs, {"refs/heads/main"})
        # Dropped line packages cannot reappear: discovery is line-prefix filtered.
        remaining = source.lines[0]
        self.assertTrue(c02.skill_matches_line_prefixes(remaining, "vapor5-query"))
        self.assertFalse(c02.skill_matches_line_prefixes(remaining, "vapor4-query"))
        # Full candidate scope is only the proposed lines (generated removal is the
        # absence of dropped-line packages/lock/catalog in this same desired state).
        for line in source.lines:
            self.assertNotEqual(line.ref, "refs/heads/release/4")


if __name__ == "__main__":
    unittest.main()
