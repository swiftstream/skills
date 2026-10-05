import ast
import base64
import hashlib
import json
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

import automation.federation.controller as controller_module
from automation.federation.controller import (
    AppIdentity,
    C02CandidateBuilder,
    DuplicateAnchorError,
    IssueManagedNoSemanticChange,
    IssueAnchorComment,
    IssueBranchLeaseComment,
    IssuePRBindingState,
    IssueSourceAuthority,
    IssueSourceIdentityKind,
    PhaseNotImplementedError,
    PublicSourceMetadata,
    R01Controller,
    R02Error,
    StaleAuthorityError,
    classify_request,
    create_or_validate_issue_anchor,
    create_or_validate_issue_branch_lease,
    create_or_recover_issue_pr_binding,
    parse_c02_manifest,
    reconstruct_issue_from_github,
    resolve_issue_source_authority,
    validate_unique_issue_anchor,
)
from automation.federation.request_model import (
    ISSUE_REQUEST_ANCHOR_MARKER,
    ISSUE_BRANCH_LEASE_MARKER,
    ISSUE_HEAD_CLAIM_MARKER,
    ISSUE_INTERNAL_PR_BINDING_MARKER,
    PR_ISSUE_ORIGIN_BINDING_MARKER,
    PATCH_SENTINEL,
    CommentEvent,
    IssueRequestAnchor,
    IssueHeadClaim,
    IssuePRBinding,
    IssueBranchLease,
    RequestClass,
    RequestAnchor,
    body_sha256,
    classify_issue_head_claim_progression,
    parse_request_body,
    parse_issue_request_body,
    parse_issue_branch_lease,
    parse_issue_internal_pr_binding,
    parse_pr_issue_origin_binding,
    issue_branch_ref,
    issue_head_claim_authority_digest,
    effective_request_digest,
    proposal_target_evidence_digest,
    render_request_body,
)
from automation.federation.github_api import (
    GitHubAPIError,
    GitHubClient,
    GitCommitMetadata,
    GitObject,
    GitTreeEntry,
    HttpResponse,
    IssueComment,
    IssueMetadata,
    NotFoundError,
    PullRequestMetadata,
    RefCASConflict,
    RepositoryMetadata,
    REST_BASE_URL,
    ZERO_OID,
)
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

    def test_issue_managed_no_semantic_change_is_typed_before_transition_for_all_classes(self):
        accepted_base = "a" * 40
        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE):
            cases = [
                controller_module.ProposalCandidate(
                    "b" * 40, accepted_base, (), request_class, "owner-repo", 41, False,
                ),
                controller_module.ProposalCandidate(
                    accepted_base, accepted_base, ("federation.json",), request_class, "owner-repo", 41, False,
                ),
            ]
            if request_class in {RequestClass.UPDATE, RequestClass.REMOVE}:
                cases.append(controller_module.ProposalCandidate(
                    "b" * 40, accepted_base, ("README.md",), request_class, "owner-repo", 41, False,
                ))
            for candidate in cases:
                with self.subTest(request_class=request_class, candidate=candidate):
                    with self.assertRaises(IssueManagedNoSemanticChange) as caught:
                        controller_module._require_semantic_issue_candidate(candidate, request_class, accepted_base)
                    self.assertEqual(caught.exception.reason, "NO_SEMANTIC_CHANGE")
                    self.assertEqual(str(caught.exception), "NO_SEMANTIC_CHANGE")
                    self.assertIs(caught.exception.request_class, request_class)

    def test_shared_candidate_builder_preserves_legacy_noop_and_update_remove_errors(self):
        accepted_base = "a" * 40
        class ReadClient:
            def __init__(_self, blobs):
                _self.blobs = blobs

            def get_blob(_self, _repository, blob_sha):
                return _self.blobs[blob_sha]

            def get_commit_tree(_self, *_args):
                raise AssertionError("legacy no-diff/no-federation behavior must return before commit reads")

        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(empty_request_class=request_class):
                same_blob = "b" * 40
                same_bytes = b"same accepted bytes\n"
                builder = C02CandidateBuilder(ReadClient({same_blob: same_bytes}), "swiftstream/skills", trusted_checkout_sha=accepted_base)
                request = self.source_request(request_class)
                desired = {"federation.json": ("100644", same_bytes)}
                tree = {"federation.json": ("100644", "blob", same_blob)}
                with (
                    patch.object(controller_module, "trusted_c02_execution", return_value=nullcontext(Path("."))),
                    patch.object(builder, "_plan", return_value=(desired, tree, "owner-repo", 41)),
                ):
                    candidate = builder(request, request_class, accepted_base, "c" * 40)
                self.assertEqual(candidate, controller_module.ProposalCandidate(
                    accepted_base, accepted_base, (), request_class, "owner-repo", 41, False,
                ))

        for request_class in (RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(non_federation_request_class=request_class):
                old_blob = "d" * 40
                builder = C02CandidateBuilder(
                    ReadClient({old_blob: b"old README\n"}),
                    "swiftstream/skills",
                    trusted_checkout_sha=accepted_base,
                )
                request = self.source_request(request_class)
                desired = {"README.md": ("100644", b"new README\n")}
                tree = {"README.md": ("100644", "blob", old_blob)}
                with (
                    patch.object(controller_module, "trusted_c02_execution", return_value=nullcontext(Path("."))),
                    patch.object(builder, "_plan", return_value=(desired, tree, "owner-repo", 41)),
                    self.assertRaises(R02Error) as caught,
                ):
                    builder(request, request_class, accepted_base, "c" * 40)
                self.assertIs(type(caught.exception), R02Error)
                self.assertEqual(
                    str(caught.exception),
                    "UPDATE/REMOVE requires an actual federation.json trust/configuration change",
                )

    def test_issue_managed_candidate_planning_translates_only_exact_legacy_error(self):
        accepted_base = "a" * 40
        legacy_error = "UPDATE/REMOVE requires an actual federation.json trust/configuration change"
        for request_class in (RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(request_class=request_class):
                def legacy_builder(*_args):
                    raise R02Error(legacy_error)

                with self.assertRaises(IssueManagedNoSemanticChange) as caught:
                    controller_module._plan_issue_managed_candidate(
                        legacy_builder, self.source_request(request_class), request_class,
                        accepted_base, "b" * 40,
                    )
                self.assertIs(caught.exception.request_class, request_class)
                self.assertEqual(str(caught.exception), "NO_SEMANTIC_CHANGE")

        unrelated = R02Error("unrelated candidate planning failure")
        with self.assertRaises(R02Error) as caught:
            controller_module._plan_issue_managed_candidate(
                lambda *_args: (_ for _ in ()).throw(unrelated),
                self.source_request(RequestClass.UPDATE), RequestClass.UPDATE,
                accepted_base, "b" * 40,
            )
        self.assertIs(caught.exception, unrelated)

        same_text_subclass = StaleAuthorityError(legacy_error)
        with self.assertRaises(StaleAuthorityError) as caught:
            controller_module._plan_issue_managed_candidate(
                lambda *_args: (_ for _ in ()).throw(same_text_subclass),
                self.source_request(RequestClass.UPDATE), RequestClass.UPDATE,
                accepted_base, "b" * 40,
            )
        self.assertIs(caught.exception, same_text_subclass)

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


class IssueAnchorControllerTests(unittest.TestCase):
    APP = AppIdentity("swift-stream-federation", 10, "A_app", 11, "B_bot", "swift-stream-federation[bot]")

    @staticmethod
    def issue(request_class=RequestClass.ADD, **changes):
        request_body = f"### Federation request type\n\n{request_class.value}\n\n"
        request_body += "### Repository URL\n\nhttps://github.com/Owner/Repo\n"
        if request_class is RequestClass.REMOVE:
            request_body += "\n### Reason\n\nRetire source\n"
        else:
            request_body += (
                "\n### Description\n\nSource\n\n### Branch\n\nmain\n\n"
                "### Skills root\n\nskills\n\n### Skill prefixes\n\nowner\n\n"
                "### Publication lines\n\n_No response_\n"
            )
            if request_class is RequestClass.UPDATE:
                request_body += "\n### Dropped publication lines\n\n_No response_\n"
        value = dict(number=7, database_id=700, node_id="I_issue", body=request_body,
            state="open", author_id="U_requester",
            author_login="alice", last_edited_at=None, includes_created_edit=False, is_pull_request=False)
        value.update(changes)
        return IssueMetadata(**value)

    @staticmethod
    def authority(**changes):
        value = dict(request_class=RequestClass.ADD, source_id="owner-repo", source_repository_id=41,
                     source_canonical_full_name="Owner/Repo", source_identity_kind=IssueSourceIdentityKind.PROPOSED,
                     source_default_branch="main", source_description="Source")
        value.update(changes)
        return IssueSourceAuthority(**value)

    @staticmethod
    def comment(body, *, database_id=900, author_id="B_bot", author_login="swift-stream-federation[bot]",
                author_type="Bot", editor_id=None, editor_login=None, editor_type=None,
                last_edited_at=None, includes_created_edit=False):
        return IssueComment("IC_node", database_id, body, author_id, author_login, author_type,
                            editor_id, editor_login, editor_type, last_edited_at, includes_created_edit)

    @classmethod
    def persisted(cls, issue=None, request_class=RequestClass.ADD):
        issue = issue or cls.issue(request_class)
        request = parse_issue_request_body(issue.body)
        source_identity_kind = "proposed" if request.request_class is RequestClass.ADD else "accepted"
        anchor = IssueRequestAnchor(1, issue.number, issue.database_id, issue.node_id, request.request_class,
            issue.author_id, issue.author_login, body_sha256(issue.body), request, "owner-repo", 41,
            "Owner/Repo", source_identity_kind, issue.last_edited_at, issue.includes_created_edit)
        return cls.comment(anchor.render(), database_id=100), anchor

    class Client:
        def __init__(self, issue, comments=(), *, after_issue=None, permissions=None, permission_error=False):
            self.issue, self.comments, self.after_issue = issue, list(comments), after_issue
            self.permissions, self.permission_error = permissions or {}, permission_error
            self.create_calls, self.permission_calls = [], []

        def create_issue_comment(self, repository, number, body):
            self.create_calls.append((repository, number, body))
            self.comments.append(IssueAnchorControllerTests.comment(body, database_id=901))

        def get_issue_metadata(self, repository, number):
            return self.after_issue or self.issue

        def list_issue_comments(self, repository, number):
            return tuple(self.comments)

        def get_collaborator_permission(self, repository, login):
            self.permission_calls.append((repository, login))
            if self.permission_error:
                raise RuntimeError("permission lookup failed")
            return self.permissions.get(login, "none")

        def __getattr__(self, name):
            if name in {"update_refs", "create_machine_pull_request", "create_pull_request", "create_commit_status", "create_check_run", "dispatch_workflow"}:
                raise AssertionError(f"forbidden mutation unexpectedly called: {name}")
            raise AttributeError(name)

    @classmethod
    def resolver(cls, result=None):
        return lambda request, request_class: result or cls.authority()

    def test_anchor_app_authorship_edit_and_issue_identity(self):
        issue = self.issue()
        comment, _anchor = self.persisted(issue)
        self.assertEqual(validate_unique_issue_anchor([comment], issue, self.APP).comment, comment)
        for bad in (self.comment(comment.body, author_id="B_wrong"),
                    self.comment(comment.body, editor_login="editor"),
                    self.comment(comment.body, includes_created_edit=True)):
            with self.subTest(bad=bad), self.assertRaises(R02Error):
                validate_unique_issue_anchor([bad], issue, self.APP)
        for changed in (self.issue(node_id="I_other"), self.issue(author_id="U_other")):
            with self.assertRaises(R02Error):
                validate_unique_issue_anchor([comment], changed, self.APP)

    def test_malformed_source_drift_and_any_duplicate_anchor_block(self):
        issue = self.issue()
        comment, anchor = self.persisted(issue)
        client = self.Client(issue, [comment])
        with self.assertRaises(StaleAuthorityError):
            create_or_validate_issue_anchor(client, "swiftstream/skills", issue, [comment], self.APP, None,
                self.resolver(self.authority(source_repository_id=42)))
        malformed = self.comment(ISSUE_REQUEST_ANCHOR_MARKER + "\nnot-json\n")
        with self.assertRaises(R02Error):
            create_or_validate_issue_anchor(client, "swiftstream/skills", issue, [malformed], self.APP, None, self.resolver())
        with self.assertRaises(DuplicateAnchorError):
            validate_unique_issue_anchor([comment, self.comment(anchor.render(), database_id=902)], issue, self.APP)
        from dataclasses import replace
        conflicting = replace(anchor, issue_number=8)
        with self.assertRaises(DuplicateAnchorError):
            validate_unique_issue_anchor([comment, self.comment(conflicting.render(), database_id=903)], issue, self.APP)

    def test_existing_anchor_reused_and_later_login_presentation_drift_is_ignored(self):
        issue = self.issue()
        comment, anchor = self.persisted(issue)
        current = self.issue(author_login="alice-renamed")
        client = self.Client(current, [comment])
        result = create_or_validate_issue_anchor(client, "swiftstream/skills", current, [comment], self.APP, None, self.resolver())
        self.assertEqual(result.anchor, anchor)
        self.assertEqual(client.create_calls, [])


    def test_create_once_allows_preedited_issue_and_preserves_anchor_on_body_race(self):
        issue = self.issue(last_edited_at="2026-10-04T12:00:00Z", includes_created_edit=True)
        client = self.Client(issue)
        result = create_or_validate_issue_anchor(client, "swiftstream/skills", issue, [], self.APP,
            self.authority(), self.resolver())
        self.assertEqual(len(client.create_calls), 1)
        self.assertEqual(result.anchor.anchor_observed_last_edited_at, issue.last_edited_at)
        self.assertTrue(result.anchor.anchor_observed_includes_created_edit)
        changed = self.issue(body=self.issue().body + "edited\n", last_edited_at="2026-10-04T12:01:00Z")
        race = self.Client(self.issue(), after_issue=changed)
        with self.assertRaises(StaleAuthorityError):
            create_or_validate_issue_anchor(race, "swiftstream/skills", race.issue, [], self.APP,
                self.authority(), self.resolver())
        self.assertEqual(len(race.comments), 1)

    def test_fresh_source_drift_after_persist_keeps_anchor(self):
        issue = self.issue()
        client = self.Client(issue)
        with self.assertRaises(StaleAuthorityError):
            create_or_validate_issue_anchor(client, "swiftstream/skills", issue, [], self.APP,
                self.authority(), self.resolver(self.authority(source_repository_id=42)))
        self.assertEqual(len(client.comments), 1)

    def test_requester_admin_maintain_authorization_uses_stable_node_id(self):
        issue = self.issue()
        anchor_comment, anchor = self.persisted(issue)
        comments = [
            self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nrequester\n", database_id=101,
                author_id=anchor.original_author_id, author_login="alice", author_type="User"),
            self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nadmin\n", database_id=102,
                author_id="U_admin", author_login="admin", author_type="User"),
            self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nmaintain\n", database_id=103,
                author_id="U_maintain", author_login="maintainer", author_type="User"),
        ]
        client = self.Client(issue, comments, permissions={"admin": "admin", "maintainer": "maintain"})
        result = reconstruct_issue_from_github(client, "swiftstream/skills", IssueAnchorComment(anchor, anchor_comment), comments)
        self.assertEqual(result.request.description, "maintain")
        self.assertEqual(client.permission_calls, [("swiftstream/skills", "admin"), ("swiftstream/skills", "maintainer")])
        spoof = self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nspoof\n", database_id=104,
            author_id="U_other", author_login="alice", author_type="User")
        denied = reconstruct_issue_from_github(self.Client(issue, [spoof], permissions={"alice": "none"}),
            "swiftstream/skills", IssueAnchorComment(anchor, anchor_comment), [spoof])
        self.assertEqual(denied.evidence[0].kind, "unauthorized")

    def test_write_triage_read_none_bot_deleted_and_permission_errors_are_denied(self):
        issue = self.issue()
        anchor_comment, anchor = self.persisted(issue)
        comments = [self.comment(f"{PATCH_SENTINEL}\n\nDescription:\n{login}\n", database_id=index,
            author_id=f"U_{login}", author_login=login, author_type="User")
            for index, login in enumerate(("write", "triage", "read", "none"), 101)]
        comments += [self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nbot\n", database_id=110,
            author_id="B_bot2", author_login="other[bot]", author_type="Bot"),
            self.comment(f"{PATCH_SENTINEL}\n\nDescription:\ndeleted\n", database_id=111,
            author_id=None, author_login=None, author_type=None)]
        client = self.Client(issue, comments, permission_error=True)
        result = reconstruct_issue_from_github(client, "swiftstream/skills", IssueAnchorComment(anchor, anchor_comment), comments)
        self.assertEqual(result.request, anchor.initial_request)
        self.assertEqual([item.kind for item in result.evidence], ["unauthorized"] * 6)

    def test_after_anchor_only_edited_is_invalid_and_helper_has_no_mutation(self):
        issue = self.issue()
        anchor_comment, anchor = self.persisted(issue)
        early = self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nearly\n", database_id=anchor_comment.database_id - 1,
            author_id=anchor.original_author_id, author_login="alice", author_type="User")
        edited = self.comment(f"{PATCH_SENTINEL}\n\nDescription:\nedited\n", database_id=anchor_comment.database_id + 1,
            author_id=anchor.original_author_id, author_login="alice", author_type="User", editor_id="U_editor")
        client = self.Client(issue, [early, edited])
        result = reconstruct_issue_from_github(client, "swiftstream/skills", IssueAnchorComment(anchor, anchor_comment), [early, edited])
        self.assertEqual(result.request, anchor.initial_request)
        self.assertEqual([(item.comment_id, item.kind) for item in result.evidence], [(edited.database_id, "invalid")])
        self.assertEqual(client.create_calls, [])


class IssueBranchLeaseControllerTests(unittest.TestCase):
    APP = IssueAnchorControllerTests.APP
    BASE_SHA = "1" * 40
    BASE_TREE = "a" * 40
    HEAD_TREE = "b" * 40
    CENTRAL_NODE_ID = "R_central"
    CENTRAL_REPOSITORY = "swiftstream/skills"
    BASE_DATE = "2026-10-04T12:00:00Z"
    CLAIM_DATE = "2026-10-04T12:00:01Z"

    @staticmethod
    def setup_anchor(request_class=RequestClass.ADD):
        issue = IssueAnchorControllerTests.issue(request_class)
        comment, anchor = IssueAnchorControllerTests.persisted(issue)
        return issue, IssueAnchorComment(anchor, comment)

    class Client:
        def __init__(self, issue, anchor_comment, *, main_sequence=None, tree_corruption=None, wrong_readback=False):
            self.issue = issue
            self.comments = [anchor_comment.comment]
            self.repository = RepositoryMetadata(22, IssueBranchLeaseControllerTests.CENTRAL_NODE_ID,
                IssueBranchLeaseControllerTests.CENTRAL_REPOSITORY, "main")
            self.main_sequence = list(main_sequence or [IssueBranchLeaseControllerTests.BASE_SHA])
            self.main_reads = 0
            self.base_entries = (GitTreeEntry("README.md", "100644", "blob", "d" * 40),)
            self.head_entries = None
            self.tree_corruption = tree_corruption
            self.wrong_readback = wrong_readback
            self.blob_calls = []
            self.tree_calls = []
            self.commit_calls = []
            self.comment_writes = []
            self.readback_calls = []
            self.timestamp_calls = []
            self.forbidden_calls = []
            self.current_head = None
            self.commit_metadata = {
                IssueBranchLeaseControllerTests.BASE_SHA: GitCommitMetadata(
                    IssueBranchLeaseControllerTests.BASE_SHA,
                    IssueBranchLeaseControllerTests.BASE_TREE,
                    (),
                    IssueBranchLeaseControllerTests.BASE_DATE,
                )
            }

        def get_issue_metadata(self, repository, number):
            return self.issue

        def list_issue_comments(self, repository, number):
            return tuple(self.comments)

        def get_repository_metadata(self, repository):
            return self.repository

        def get_ref_oid(self, repository, branch):
            index = min(self.main_reads, len(self.main_sequence) - 1)
            self.main_reads += 1
            return self.main_sequence[index]

        def get_commit_metadata(self, repository, commit_sha):
            return self.commit_metadata[commit_sha]

        def get_commit_tree(self, repository, commit_sha):
            metadata = self.commit_metadata[commit_sha]
            entries = self.base_entries if commit_sha == IssueBranchLeaseControllerTests.BASE_SHA else self.head_entries
            return metadata.tree_sha, tuple(entries)

        def read_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
            self.readback_calls.append((commit_sha, path, expected_mode))
            if expected_mode != "100644":
                raise AssertionError("readback must require mode 100644")
            if self.wrong_readback:
                return b"update-source\n"
            request_class = parse_issue_request_body(self.issue.body).request_class
            return f"{request_class.value}\n".encode("utf-8")

        def create_blob(self, repository, content, *, encoding="base64"):
            self.blob_calls.append((repository, content, encoding))
            raw = base64.b64decode(content, validate=True)
            sha = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            return GitObject(sha)

        def create_tree(self, repository, base_tree, entries):
            items = list(entries)
            self.tree_calls.append((repository, base_tree, items))
            item = dict(items[0])
            if self.tree_corruption == "mode-100755":
                item["mode"] = "100755"
            elif self.tree_corruption == "mode-120000":
                item["mode"] = "120000"
            elif self.tree_corruption == "type-tree":
                item["type"] = "tree"
            elif self.tree_corruption == "type-commit":
                item["type"] = "commit"
            self.head_entries = (*self.base_entries, GitTreeEntry(item["path"], item["mode"], item["type"], item["sha"]))
            return GitObject(IssueBranchLeaseControllerTests.HEAD_TREE)

        def bot_commit_timestamp_after(self, repository, parent_sha):
            self.timestamp_calls.append((repository, parent_sha))
            return IssueBranchLeaseControllerTests.CLAIM_DATE

        def create_commit(self, repository, message, tree, parents, *, timestamp=None):
            parent_tuple = tuple(parents)
            self.commit_calls.append((repository, message, tree, parent_tuple, timestamp))
            sha = controller_module._expected_deterministic_commit_sha(tree, parent_tuple[0], message, timestamp)
            metadata_parents = ("2" * 40,) if self.tree_corruption == "wrong-parent" else parent_tuple
            self.commit_metadata[sha] = GitCommitMetadata(sha, tree, metadata_parents, timestamp)
            self.current_head = sha
            return GitObject(sha)

        def create_issue_comment(self, repository, number, body):
            if not self.readback_calls:
                raise AssertionError("lease persisted before commit readback")
            self.comment_writes.append((repository, number, body))
            comment = IssueComment(
                f"IC_lease_{len(self.comments)}", 901 + len(self.comment_writes), body,
                IssueBranchLeaseControllerTests.APP.bot_node_id,
                IssueBranchLeaseControllerTests.APP.bot_login, "Bot", None, None, None, None, False,
            )
            self.comments.append(comment)
            return comment

        def update_refs(self, *args, **kwargs):
            self.forbidden_calls.append("update_refs")
            raise AssertionError("lease producer may not update refs")

        def create_machine_pull_request(self, *args, **kwargs):
            self.forbidden_calls.append("create_machine_pull_request")
            raise AssertionError("lease producer may not create PRs")

        def create_pull_request(self, *args, **kwargs):
            self.forbidden_calls.append("create_pull_request")
            raise AssertionError("lease producer may not create PRs")

        def merge_machine_pull_request(self, *args, **kwargs):
            self.forbidden_calls.append("merge_machine_pull_request")
            raise AssertionError("lease producer may not merge PRs")

        def create_status(self, *args, **kwargs):
            self.forbidden_calls.append("create_status")
            raise AssertionError("lease producer may not write statuses")

        def create_check_run(self, *args, **kwargs):
            self.forbidden_calls.append("create_check_run")
            raise AssertionError("lease producer may not write checks")

        def dispatch_workflow(self, *args, **kwargs):
            self.forbidden_calls.append("dispatch_workflow")
            raise AssertionError("lease producer may not dispatch workflows")

    @staticmethod
    def resolver(**changes):
        fields = dict(
            request_class=RequestClass.ADD,
            source_id="owner-repo",
            source_repository_id=41,
            source_canonical_full_name="Owner/Repo",
            source_identity_kind=IssueSourceIdentityKind.PROPOSED,
            source_default_branch="main",
            source_description="Source",
        )
        fields.update(changes)
        return lambda request, request_class: IssueSourceAuthority(**fields)

    def create(self, client, anchor_comment, *, resolver=None, nonce_factory=None):
        return create_or_validate_issue_branch_lease(
            client,
            self.CENTRAL_REPOSITORY,
            anchor_comment,
            self.APP,
            self.CENTRAL_NODE_ID,
            resolver or self.resolver(),
            nonce_factory=nonce_factory,
        )

    def test_new_lease_uses_exact_base64_marker_only_commit_and_persists_after_readback(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        nonces = []
        result = self.create(client, anchor_comment, nonce_factory=lambda: nonces.append("called") or "c" * 64)
        self.assertIsInstance(result, IssueBranchLeaseComment)
        self.assertEqual(result.lease.carrier_nonce, "c" * 64)
        self.assertEqual(nonces, ["called"])
        raw = b"add-source\n"
        self.assertEqual(client.blob_calls, [(self.CENTRAL_REPOSITORY, base64.b64encode(raw).decode("ascii"), "base64")])
        self.assertEqual(client.tree_calls[0][1], "a" * 40)
        self.assertEqual(client.tree_calls[0][2], [{
            "path": ".federation-request", "mode": "100644", "type": "blob",
            "sha": client.blob_calls and hashlib.sha1(b"blob 11\0" + raw).hexdigest(),
        }])
        self.assertEqual(client.commit_calls[0][1], result.lease and controller_module.parse_claimed_head_marker(client.commit_calls[0][1]).render())
        self.assertEqual(client.commit_calls[0][2], "b" * 40)
        self.assertEqual(client.commit_calls[0][3], (self.BASE_SHA,))
        self.assertEqual(client.commit_calls[0][4], self.CLAIM_DATE)
        self.assertEqual(client.timestamp_calls, [(self.CENTRAL_REPOSITORY, self.BASE_SHA)])
        self.assertEqual(client.readback_calls[0][1:], (".federation-request", "100644"))
        self.assertEqual(len(client.comment_writes), 1)
        self.assertEqual(client.comment_writes[0][2], result.lease.render())
        self.assertEqual(client.forbidden_calls, [])
        self.assertEqual(client.main_reads, 2)

    def test_later_retry_reuses_historical_lease_after_main_advance_with_zero_writes(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        first = self.create(client, anchor_comment, nonce_factory=lambda: "d" * 64)
        before = (len(client.blob_calls), len(client.tree_calls), len(client.commit_calls), len(client.comment_writes))
        client.main_sequence = ["2" * 40]
        calls = []
        second = self.create(client, anchor_comment, nonce_factory=lambda: calls.append("called") or "e" * 64)
        after = (len(client.blob_calls), len(client.tree_calls), len(client.commit_calls), len(client.comment_writes))
        self.assertEqual(second, first)
        self.assertEqual(second.comment.database_id, first.comment.database_id)
        self.assertEqual(calls, [])
        self.assertEqual(after, before)
        self.assertEqual(client.forbidden_calls, [])
        self.assertEqual(client.main_sequence[0], "2" * 40)

    def test_default_nonce_is_fresh_lowercase_256_bit_hex(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        result = self.create(client, anchor_comment)
        self.assertRegex(result.lease.carrier_nonce, r"^[0-9a-f]{64}$")

    def test_same_invocation_main_advance_blocks_but_preserves_lease(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment, main_sequence=[self.BASE_SHA, "2" * 40])
        with self.assertRaises(StaleAuthorityError):
            self.create(client, anchor_comment, nonce_factory=lambda: "f" * 64)
        self.assertEqual(len(client.comment_writes), 1)
        self.assertTrue(any(comment.body.startswith(ISSUE_BRANCH_LEASE_MARKER) for comment in client.comments))
        self.assertEqual(client.forbidden_calls, [])

    def test_source_drift_after_lease_persistence_blocks_and_preserves_evidence(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        calls = [0]

        def drift(request, request_class):
            calls[0] += 1
            return IssueAnchorControllerTests.authority(source_id="changed-repo") if calls[0] == 2 else IssueAnchorControllerTests.authority()

        with self.assertRaises(StaleAuthorityError):
            self.create(client, anchor_comment, resolver=drift, nonce_factory=lambda: "7" * 64)
        self.assertEqual(len(client.comment_writes), 1)
        self.assertEqual(calls[0], 2)

    def test_readback_mode_type_bytes_and_parent_mismatches_block_before_lease_comment(self):
        issue, anchor_comment = self.setup_anchor()
        for corruption, wrong_readback in (("mode-100755", False), ("mode-120000", False),
                                           ("type-tree", False), ("type-commit", False),
                                           (None, True), ("wrong-parent", False)):
            client = self.Client(issue, anchor_comment, tree_corruption=corruption, wrong_readback=wrong_readback)
            with self.subTest(corruption=corruption, wrong_readback=wrong_readback), self.assertRaises(R02Error):
                self.create(client, anchor_comment, nonce_factory=lambda: "8" * 64)
            self.assertEqual(client.comment_writes, [])

    def test_existing_equivalent_comments_collapse_to_lowest_id_without_writes(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        first = self.create(client, anchor_comment, nonce_factory=lambda: "9" * 64)
        duplicate = IssueComment("IC_duplicate", 50, first.lease.render(), self.APP.bot_node_id,
            self.APP.bot_login, "Bot", None, None, None, None, False)
        client.comments.append(duplicate)
        before = (len(client.blob_calls), len(client.tree_calls), len(client.commit_calls), len(client.comment_writes))
        result = self.create(client, anchor_comment, nonce_factory=lambda: self.fail("nonce called on existing lease"))
        self.assertEqual(result.comment.database_id, 50)
        self.assertEqual(result.lease, first.lease)
        self.assertEqual((len(client.blob_calls), len(client.tree_calls), len(client.commit_calls), len(client.comment_writes)), before)

    def test_malformed_wrong_app_edited_and_anchor_mismatch_lease_comments_block(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        valid = self.create(client, anchor_comment, nonce_factory=lambda: "a" * 64)
        malformed = IssueComment("IC_bad", 999, ISSUE_BRANCH_LEASE_MARKER + "\n{}\n",
            self.APP.bot_node_id, self.APP.bot_login, "Bot", None, None, None, None, False)
        wrong_author = IssueComment("IC_wrong", 1000, valid.lease.render(), "B_other", "other[bot]", "Bot", None, None, None, None, False)
        edited = IssueComment("IC_edited", 1001, valid.lease.render(), self.APP.bot_node_id, self.APP.bot_login, "Bot",
            self.APP.bot_node_id, self.APP.bot_login, "Bot", "2026-10-04T12:01:00Z", False)
        changed = dict(valid.lease.__dict__)
        changed["source_id"] = "other-repo"
        changed.pop("lease_id")
        mismatch = IssueComment("IC_mismatch", 1002, IssueBranchLease.create(**changed).render(),
            self.APP.bot_node_id, self.APP.bot_login, "Bot", None, None, None, None, False)
        for bad in (malformed, wrong_author, edited, mismatch):
            client.comments = [anchor_comment.comment, valid.comment, bad]
            with self.subTest(comment=bad.node_id), self.assertRaises(R02Error):
                self.create(client, anchor_comment, nonce_factory=lambda: self.fail("nonce called on blocked evidence"))

    def test_conflicting_lease_payload_classes_fail_closed(self):
        issue, anchor_comment = self.setup_anchor()
        client = self.Client(issue, anchor_comment)
        valid = self.create(client, anchor_comment, nonce_factory=lambda: "b" * 64)
        second_client = self.Client(issue, anchor_comment)
        second = self.create(second_client, anchor_comment, nonce_factory=lambda: "c" * 64)
        client.commit_metadata.update(second_client.commit_metadata)
        conflicting = IssueComment("IC_conflict", 1002, second.lease.render(),
            self.APP.bot_node_id, self.APP.bot_login, "Bot", None, None, None, None, False)
        client.comments.append(conflicting)
        with self.assertRaises(R02Error):
            self.create(client, anchor_comment, nonce_factory=lambda: self.fail("nonce called on conflicting leases"))

    def test_historical_lease_cross_binding_generation_tree_delta_and_repository_are_revalidated(self):
        issue, anchor_comment = self.setup_anchor()
        for tamper in ("central", "generation", "nonce", "marker-digest", "tree", "delta", "repository"):
            client = self.Client(issue, anchor_comment)
            valid = self.create(client, anchor_comment, nonce_factory=lambda: "d" * 64)
            before = (len(client.blob_calls), len(client.tree_calls), len(client.commit_calls), len(client.comment_writes))
            if tamper == "repository":
                client.repository = RepositoryMetadata(22, "R_other", self.CENTRAL_REPOSITORY, "main")
            elif tamper == "delta":
                client.head_entries = (*client.head_entries, GitTreeEntry("extra.txt", "100644", "blob", "e" * 40))
            else:
                fields = dict(valid.lease.__dict__)
                if tamper == "central":
                    fields["central_repository_node_id"] = "R_other"
                elif tamper == "generation":
                    fields["claim_generation_id"] = "e" * 64
                elif tamper == "nonce":
                    fields["carrier_nonce"] = "f" * 64
                elif tamper == "marker-digest":
                    fields["initial_head_marker_digest"] = "0" * 64
                elif tamper == "tree":
                    fields["initial_head_tree_sha"] = "2" * 40
                fields.pop("lease_id")
                changed_lease = IssueBranchLease.create(**fields)
                existing = valid.comment
                changed_comment = IssueComment(existing.node_id, existing.database_id, changed_lease.render(),
                    existing.author_id, existing.author_login, existing.author_type, None, None, None, None, False)
                client.comments = [anchor_comment.comment, changed_comment]
            with self.subTest(tamper=tamper), self.assertRaises(R02Error):
                self.create(client, anchor_comment, nonce_factory=lambda: self.fail("nonce called on invalid historical evidence"))
            self.assertEqual(
                (len(client.blob_calls), len(client.tree_calls), len(client.commit_calls), len(client.comment_writes)),
                before,
            )

    def test_fresh_source_authority_drift_blocks_add_update_remove_authorities(self):
        cases = (
            (RequestClass.ADD, IssueSourceIdentityKind.PROPOSED, {"source_id": "changed-source"}),
            (RequestClass.ADD, IssueSourceIdentityKind.PROPOSED, {"source_repository_id": 42}),
            (RequestClass.ADD, IssueSourceIdentityKind.PROPOSED, {"source_canonical_full_name": "Other/Repo"}),
            (RequestClass.UPDATE, IssueSourceIdentityKind.ACCEPTED, {"source_id": "changed-source"}),
            (RequestClass.UPDATE, IssueSourceIdentityKind.ACCEPTED, {"source_repository_id": 42}),
            (RequestClass.UPDATE, IssueSourceIdentityKind.ACCEPTED, {"source_canonical_full_name": "Other/Repo"}),
            (RequestClass.REMOVE, IssueSourceIdentityKind.ACCEPTED, {"source_id": "changed-source"}),
            (RequestClass.REMOVE, IssueSourceIdentityKind.ACCEPTED, {"source_repository_id": 42}),
            (RequestClass.REMOVE, IssueSourceIdentityKind.ACCEPTED, {"source_canonical_full_name": "Other/Repo"}),
        )
        for request_class, kind, drift in cases:
            with self.subTest(request_class=request_class, drift=drift):
                issue, anchor_comment = self.setup_anchor(request_class)
                client = self.Client(issue, anchor_comment)
                resolver_calls = []
                nonce_calls = []

                def fresh_resolver(request, resolved_class):
                    resolver_calls.append((request, resolved_class))
                    self.assertIs(resolved_class, request_class)
                    self.assertIs(request.request_class, request_class)
                    return self.resolver(
                        request_class=request_class,
                        source_identity_kind=kind,
                        **drift,
                    )(request, resolved_class)

                def nonce_factory():
                    nonce_calls.append("called")
                    return "c" * 64

                with self.assertRaises(StaleAuthorityError):
                    self.create(client, anchor_comment, resolver=fresh_resolver, nonce_factory=nonce_factory)
                self.assertEqual(len(resolver_calls), 1)
                self.assertIs(resolver_calls[0][1], anchor_comment.anchor.request_class)
                self.assertEqual(nonce_calls, [])
                self.assertEqual(client.blob_calls, [])
                self.assertEqual(client.tree_calls, [])
                self.assertEqual(client.commit_calls, [])
                self.assertEqual(client.comment_writes, [])
                self.assertEqual(client.forbidden_calls, [])

class IssuePRBindingControllerTests(unittest.TestCase):
    APP = IssueBranchLeaseControllerTests.APP
    CENTRAL_REPOSITORY = IssueBranchLeaseControllerTests.CENTRAL_REPOSITORY
    CENTRAL_NODE_ID = IssueBranchLeaseControllerTests.CENTRAL_NODE_ID

    class Client(IssueBranchLeaseControllerTests.Client):
        APP = IssueBranchLeaseControllerTests.APP
        CENTRAL_REPOSITORY = IssueBranchLeaseControllerTests.CENTRAL_REPOSITORY
        CENTRAL_NODE_ID = IssueBranchLeaseControllerTests.CENTRAL_NODE_ID

        def __init__(
            self,
            issue,
            anchor_comment,
            *,
            ref_write_error=None,
            persist_ref_on_error=True,
            pr_create_error_after_persist=None,
            persist_pr_on_error=True,
            ambiguous_binding_side=None,
            persist_ambiguous_binding=True,
            **kwargs,
        ):
            super().__init__(issue, anchor_comment, **kwargs)
            self.current_ref = None
            self.ref_reads = []
            self.ref_writes = []
            self.ref_write_error = ref_write_error
            self.persist_ref_on_error = persist_ref_on_error
            self.pull_requests = {}
            self.pull_request_issues = {}
            self.pr_comments = {}
            self.pr_create_calls = []
            self.pr_create_error_after_persist = pr_create_error_after_persist
            self.persist_pr_on_error = persist_pr_on_error
            self.pr_create_number = 81
            self.binding_posts = []
            self.ambiguous_binding_side = ambiguous_binding_side
            self.persist_ambiguous_binding = persist_ambiguous_binding
            self.next_comment_database_id = 2000
            self.after_binding_callback = None
            self.current_main_sha = IssueBranchLeaseControllerTests.BASE_SHA
            self.binding_anchor = None
            self.binding_lease = None
            self.update_branch_calls = []
            self.state_updates = []

        def get_ref_oid(self, repository, branch):
            self.ref_reads.append(branch)
            if branch == "main":
                return self.current_main_sha
            expected_short = issue_branch_ref(self.issue.number).removeprefix("refs/heads/")
            if branch != expected_short:
                raise AssertionError(f"unexpected ref read: {branch}")
            if self.current_ref is None:
                raise NotFoundError("ref not found")
            return self.current_ref

        def update_refs(self, repository_id, updates):
            self.ref_writes.append((repository_id, tuple(updates)))
            update = updates[0]
            if (
                repository_id != self.CENTRAL_NODE_ID
                or len(updates) != 1
                or update.name != issue_branch_ref(self.issue.number)
                or update.before_oid != ZERO_OID
                or update.after_oid != self.current_head
                or update.force is not False
            ):
                raise AssertionError("Wave 03 requires exact ZERO_OID -> lease.initialHeadSha force=false CAS")
            if self.ref_write_error is not None:
                if self.persist_ref_on_error:
                    self.current_ref = update.after_oid
                raise self.ref_write_error
            if self.current_ref is not None:
                raise RefCASConflict("branch already exists")
            self.current_ref = update.after_oid

        def get_issue_metadata(self, repository, number):
            if number == self.issue.number:
                return self.issue
            return self.pull_request_issues[number]

        def list_issue_comments(self, repository, number):
            if number == self.issue.number:
                return tuple(self.comments)
            return tuple(self.pr_comments.get(number, ()))

        def list_pull_requests(self, repository, *, state="open", max_pages=100):
            if state != "all":
                raise AssertionError("Wave 03 candidate recovery must enumerate all PR states")
            return tuple({"number": number} for number in sorted(self.pull_requests))

        def get_pull_request_metadata(self, repository, number):
            return self.pull_requests[number]

        def add_candidate(self, *, number=81, **changes):
            anchor = self.binding_anchor
            lease = self.binding_lease
            body = render_request_body(anchor.anchor.initial_request)
            defaults = dict(
                number=number,
                body=body,
                author_id=self.APP.bot_node_id,
                author_login=self.APP.bot_login,
                head_oid=lease.lease.initial_head_sha,
                base_oid=self.current_main_sha,
                head_ref=lease.lease.branch_ref.removeprefix("refs/heads/"),
                base_ref="main",
                head_repository_id=self.CENTRAL_NODE_ID,
                head_repository=self.CENTRAL_REPOSITORY,
                base_repository_id=self.CENTRAL_NODE_ID,
                base_repository=self.CENTRAL_REPOSITORY,
                last_edited_at=None,
                includes_created_edit=False,
                draft=False,
            )
            issue_overrides = changes.pop("issue_overrides", {})
            defaults.update(changes)
            self.pull_requests[number] = PullRequestMetadata(**defaults)
            issue_values = dict(
                number=number,
                database_id=number * 10,
                node_id=f"PR_node_{number}",
                body=defaults["body"],
                state="open",
                author_id=defaults["author_id"],
                author_login=defaults["author_login"],
                last_edited_at=None,
                includes_created_edit=False,
                is_pull_request=True,
            )
            issue_values.update(issue_overrides)
            self.pull_request_issues[number] = IssueMetadata(**issue_values)
            self.pr_comments.setdefault(number, [])

        def create_issue_pull_request(self, repository, *, head, base, title, body):
            self.pr_create_calls.append((repository, head, base, title, body))
            if self.pr_create_error_after_persist is None or self.persist_pr_on_error:
                self.add_candidate(body=body, base_ref=base, number=self.pr_create_number)
            if self.pr_create_error_after_persist is not None:
                raise self.pr_create_error_after_persist
            return self.pr_create_number

        def create_issue_comment(self, repository, number, body):
            if body.startswith(ISSUE_BRANCH_LEASE_MARKER):
                return super().create_issue_comment(repository, number, body)
            self.binding_posts.append((number, body))
            issue_side = number == self.issue.number
            side_name = "issue" if issue_side else "pr"
            if self.ambiguous_binding_side == side_name:
                if self.persist_ambiguous_binding:
                    self._append_binding_comment(number, body, issue_side)
                raise GitHubAPIError("simulated accepted/lost binding comment response")
            return self._append_binding_comment(number, body, issue_side)

        def _append_binding_comment(self, number, body, issue_side):
            self.next_comment_database_id += 1
            comment = IssueComment(
                f"IC_binding_{self.next_comment_database_id}", self.next_comment_database_id,
                body, self.APP.bot_node_id, self.APP.bot_login, "Bot", None, None, None, None, False,
            )
            if issue_side:
                self.comments.append(comment)
            else:
                self.pr_comments.setdefault(number, []).append(comment)
            if self.after_binding_callback is not None:
                self.after_binding_callback(number, body, issue_side)
            return comment

        def update_pull_request_branch(self, *args, **kwargs):
            self.update_branch_calls.append((args, kwargs))
            self.forbidden_calls.append("update_pull_request_branch")
            raise AssertionError("Wave 03 must not normalize or update a PR branch")

        def update_pull_request_state(self, *args, **kwargs):
            self.state_updates.append((args, kwargs))
            self.forbidden_calls.append("update_pull_request_state")
            raise AssertionError("Wave 03 must not close or reopen a PR")

    def prepare(self, *, nonce="c" * 64, **client_kwargs):
        issue, anchor_comment = IssueBranchLeaseControllerTests.setup_anchor()
        client = self.Client(issue, anchor_comment, **client_kwargs)
        lease = IssueBranchLeaseControllerTests().create(
            client, anchor_comment, nonce_factory=lambda: nonce,
        )
        client.binding_anchor = anchor_comment
        client.binding_lease = lease
        return client, issue, anchor_comment, lease

    def run_binding(self, client, issue_number=7, resolver=None):
        return create_or_recover_issue_pr_binding(
            client, self.CENTRAL_REPOSITORY, issue_number, self.APP, self.CENTRAL_NODE_ID,
            resolver or IssueBranchLeaseControllerTests.resolver(),
        )

    def prepare_existing(self, **client_kwargs):
        client, issue, anchor_comment, lease = self.prepare(**client_kwargs)
        client.current_ref = lease.lease.initial_head_sha
        client.add_candidate()
        return client, issue, anchor_comment, lease

    def expected_binding(self, anchor_comment, lease, *, number=81, issue_database_id=None, issue_node_id=None):
        return IssuePRBinding.create(
            issue_number=anchor_comment.anchor.issue_number,
            issue_database_id=anchor_comment.anchor.issue_database_id,
            issue_node_id=anchor_comment.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=anchor_comment.comment.database_id,
            issue_request_anchor_sha256=anchor_comment.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(lease.comment.body.encode("utf-8")).hexdigest(),
            source_id=anchor_comment.anchor.source_id,
            source_repository_id=anchor_comment.anchor.source_repository_id,
            branch_ref=lease.lease.branch_ref,
            pull_request_number=number,
            pull_request_database_id=issue_database_id if issue_database_id is not None else number * 10,
            pull_request_node_id=issue_node_id if issue_node_id is not None else f"PR_node_{number}",
            initial_head_sha=lease.lease.initial_head_sha,
            base_ref="main",
            central_repository_node_id=self.CENTRAL_NODE_ID,
        )

    def add_binding_side(
        self, client, binding, *, issue_side, number=81, body=None,
        author_id=None, author_login=None, edited=False,
    ):
        marker_body = (
            binding.render_issue_binding() if issue_side else binding.render_pr_origin_binding()
        ) if body is None else body
        comment = IssueAnchorControllerTests.comment(
            marker_body,
            database_id=client.next_comment_database_id + 1,
            author_id=self.APP.bot_node_id if author_id is None else author_id,
            author_login=self.APP.bot_login if author_login is None else author_login,
            author_type="Bot",
        )
        if edited:
            comment = IssueComment(
                comment.node_id, comment.database_id, comment.body, comment.author_id,
                comment.author_login, comment.author_type, "U_editor", "editor", "User",
                "2026-10-04T12:01:00Z", True,
            )
        if issue_side:
            client.comments.append(comment)
        else:
            client.pr_comments.setdefault(number, []).append(comment)
        client.next_comment_database_id += 1
        return comment

    def test_no_candidate_creates_exact_lease_ref_and_nondraft_canonical_pr_then_two_bindings(self):
        client, _issue, anchor_comment, lease = self.prepare()
        state = self.run_binding(client)
        self.assertIsInstance(state, IssuePRBindingState)
        self.assertEqual(client.current_ref, lease.lease.initial_head_sha)
        self.assertEqual(len(client.ref_writes), 1)
        repository_id, updates = client.ref_writes[0]
        self.assertEqual(repository_id, self.CENTRAL_NODE_ID)
        self.assertEqual(updates, (controller_module.RefUpdate(
            issue_branch_ref(7), ZERO_OID, lease.lease.initial_head_sha, force=False,
        ),))
        self.assertEqual(len(client.pr_create_calls), 1)
        self.assertEqual(client.pr_create_calls[0], (
            self.CENTRAL_REPOSITORY,
            issue_branch_ref(7).removeprefix("refs/heads/"),
            "main",
            "Federation request #7: add-source",
            render_request_body(anchor_comment.anchor.initial_request),
        ))
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [
            ISSUE_INTERNAL_PR_BINDING_MARKER,
            PR_ISSUE_ORIGIN_BINDING_MARKER,
        ])
        self.assertEqual(state.binding, parse_issue_internal_pr_binding(client.comments[-1].body))
        self.assertEqual(state.binding, parse_pr_issue_origin_binding(client.pr_comments[state.pr.number][-1].body))
        self.assertFalse(state.pr.draft)
        self.assertEqual(client.update_branch_calls, [])
        self.assertEqual(client.state_updates, [])
        self.assertEqual(client.forbidden_calls, [])

    def test_missing_ref_with_open_or_closed_pr_candidate_never_recreates_ref(self):
        for state in ("open", "closed"):
            with self.subTest(state=state):
                client, _issue, _anchor, _lease = self.prepare()
                overrides = {"issue_overrides": {"state": state}}
                client.add_candidate(**overrides)
                with self.assertRaises(R02Error):
                    self.run_binding(client)
                self.assertEqual(client.ref_writes, [])
                self.assertEqual(client.pr_create_calls, [])

    def test_missing_ref_with_pr_side_binding_evidence_never_creates_ref(self):
        client, _issue, anchor_comment, lease = self.prepare()
        client.add_candidate()
        binding = self.expected_binding(anchor_comment, lease)
        self.add_binding_side(client, binding, issue_side=False)
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.ref_writes, [])
        self.assertEqual(client.pr_create_calls, [])

    def test_exact_preexisting_ref_and_one_open_candidate_are_recovered_without_ref_or_pr_create(self):
        client, _issue, _anchor, lease = self.prepare_existing()
        state = self.run_binding(client)
        self.assertEqual(state.pr.number, 81)
        self.assertEqual(client.current_ref, lease.lease.initial_head_sha)
        self.assertEqual(client.ref_writes, [])
        self.assertEqual(client.pr_create_calls, [])

    def test_foreign_ref_head_blocks_without_overwrite_or_delete(self):
        client, _issue, _anchor, _lease = self.prepare()
        client.current_ref = "f" * 40
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.current_ref, "f" * 40)
        self.assertEqual(client.ref_writes, [])
        self.assertEqual(client.pr_create_calls, [])

    def test_ref_cas_conflict_and_ambiguous_exact_readback_recover_once(self):
        for error in (RefCASConflict("CAS conflict"), GitHubAPIError("accepted create response lost")):
            with self.subTest(error=type(error).__name__):
                client, _issue, _anchor, lease = self.prepare(ref_write_error=error)
                state = self.run_binding(client)
                self.assertEqual(state.binding.initial_head_sha, lease.lease.initial_head_sha)
                self.assertEqual(len(client.ref_writes), 1)
                self.assertEqual(client.current_ref, lease.lease.initial_head_sha)

    def test_ambiguous_ref_cas_without_exact_readback_never_retries_in_invocation(self):
        client, _issue, _anchor, _lease = self.prepare(
            ref_write_error=GitHubAPIError("ref create response lost"),
            persist_ref_on_error=False,
        )
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertEqual(len(client.ref_writes), 1)
        self.assertIsNone(client.current_ref)
        self.assertEqual(client.pr_create_calls, [])

    def test_main_advance_does_not_normalize_or_invalidate_historical_lease(self):
        client, _issue, _anchor, lease = self.prepare()
        client.current_main_sha = "2" * 40
        state = self.run_binding(client)
        self.assertEqual(state.binding.initial_head_sha, lease.lease.initial_head_sha)
        self.assertEqual(state.pr.head_oid, lease.lease.initial_head_sha)
        self.assertEqual(state.pr.base_oid, "2" * 40)
        self.assertEqual(client.current_ref, lease.lease.initial_head_sha)
        self.assertEqual(client.ref_writes[0][1][0].after_oid, lease.lease.initial_head_sha)
        self.assertEqual(client.pr_create_calls[0][2], "main")

    def test_issue_closed_or_source_drift_blocks_before_ref_cas(self):
        client, issue, _anchor, _lease = self.prepare()
        client.issue = IssueMetadata(**dict(issue.__dict__, state="closed"))
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.ref_writes, [])

        client, _issue, _anchor, _lease = self.prepare()
        wrong = IssueBranchLeaseControllerTests.resolver(source_id="changed-source")
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client, resolver=wrong)
        self.assertEqual(client.ref_writes, [])

    def test_duplicate_and_closed_reserved_head_candidates_block_without_replacement(self):
        client, _issue, _anchor, _lease = self.prepare_existing()
        client.add_candidate(number=82)
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.pr_create_calls, [])
        self.assertEqual(client.ref_writes, [])

        client, _issue, _anchor, _lease = self.prepare_existing()
        client.add_candidate(issue_overrides={"state": "closed"})
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.pr_create_calls, [])
        self.assertEqual(client.ref_writes, [])

    def test_foreign_same_name_head_candidate_blocks_instead_of_being_ignored(self):
        client, _issue, _anchor, _lease = self.prepare()
        client.add_candidate(head_repository_id="R_fork", head_repository="someone/fork")
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.ref_writes, [])
        self.assertEqual(client.pr_create_calls, [])

    def test_reserved_head_pr_topology_body_author_draft_and_edit_drift_block(self):
        variants = (
            {"author_id": "U_other"},
            {"author_login": "someone[bot]"},
            {"head_repository": "someone/fork"},
            {"base_repository_id": "R_other"},
            {"base_repository": "someone/fork"},
            {"base_ref": "trunk"},
            {"head_oid": "e" * 40},
            {"draft": True},
            {"body": "different body"},
            {"last_edited_at": "2026-10-04T12:10:00Z"},
            {"includes_created_edit": True},
        )
        for changes in variants:
            with self.subTest(changes=changes):
                client, _issue, _anchor, _lease = self.prepare_existing()
                client.add_candidate(**changes)
                with self.assertRaises(R02Error):
                    self.run_binding(client)
                self.assertEqual(client.pr_create_calls, [])
                self.assertEqual(client.ref_writes, [])

    def test_pull_request_issue_identity_state_and_body_must_match_pr(self):
        variants = (
            {"is_pull_request": False},
            {"number": 82},
            {"database_id": True},
            {"node_id": ""},
            {"author_id": "U_other"},
            {"author_login": "other"},
            {"state": "closed"},
            {"body": "different Issue body"},
        )
        for changes in variants:
            with self.subTest(changes=changes):
                client, _issue, _anchor, _lease = self.prepare_existing()
                client.add_candidate(issue_overrides=changes)
                with self.assertRaises(R02Error):
                    self.run_binding(client)
                self.assertEqual(client.pr_create_calls, [])

    def test_lost_pr_create_response_recovers_one_exact_candidate_and_absence_blocks_retry(self):
        client, _issue, _anchor, _lease = self.prepare(
            pr_create_error_after_persist=GitHubAPIError("accepted PR create response lost"),
        )
        state = self.run_binding(client)
        self.assertEqual(state.pr.number, client.pr_create_number)
        self.assertEqual(len(client.pr_create_calls), 1)

        client, _issue, _anchor, _lease = self.prepare(
            pr_create_error_after_persist=GitHubAPIError("PR create response lost"),
            persist_pr_on_error=False,
        )
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertEqual(len(client.pr_create_calls), 1)
        self.assertEqual(client.pull_requests, {})
        self.assertEqual(len(client.ref_writes), 1)

    def test_one_sided_and_complete_bindings_repair_only_the_missing_side(self):
        client, _issue, anchor_comment, lease = self.prepare_existing()
        binding = self.expected_binding(anchor_comment, lease)
        self.add_binding_side(client, binding, issue_side=True)
        state = self.run_binding(client)
        self.assertEqual(state.binding, binding)
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [PR_ISSUE_ORIGIN_BINDING_MARKER])

        client, _issue, anchor_comment, lease = self.prepare_existing()
        binding = self.expected_binding(anchor_comment, lease)
        self.add_binding_side(client, binding, issue_side=False)
        state = self.run_binding(client)
        self.assertEqual(state.binding, binding)
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [ISSUE_INTERNAL_PR_BINDING_MARKER])

        client, _issue, anchor_comment, lease = self.prepare_existing()
        binding = self.expected_binding(anchor_comment, lease)
        self.add_binding_side(client, binding, issue_side=True)
        self.add_binding_side(client, binding, issue_side=False)
        state = self.run_binding(client)
        self.assertEqual(state.binding, binding)
        self.assertEqual(client.binding_posts, [])
        self.assertEqual(client.ref_writes, [])
        self.assertEqual(client.pr_create_calls, [])

    def test_malformed_wrong_app_edited_and_duplicate_binding_markers_fail_closed(self):
        valid_body = ISSUE_INTERNAL_PR_BINDING_MARKER + "\n{}\n"
        scenarios = ("malformed-issue", "wrong-app-issue", "edited-issue", "duplicate-issue",
                     "malformed-pr", "wrong-app-pr", "edited-pr", "duplicate-pr")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                client, _issue, anchor_comment, lease = self.prepare_existing()
                binding = self.expected_binding(anchor_comment, lease)
                issue_side = scenario.endswith("issue")
                if scenario.startswith("malformed"):
                    marker = ISSUE_INTERNAL_PR_BINDING_MARKER if issue_side else PR_ISSUE_ORIGIN_BINDING_MARKER
                    self.add_binding_side(client, binding, issue_side=issue_side, body=marker + "\n{}\n")
                elif scenario.startswith("wrong-app"):
                    self.add_binding_side(client, binding, issue_side=issue_side, author_id="B_other", author_login="other[bot]")
                elif scenario.startswith("edited"):
                    self.add_binding_side(client, binding, issue_side=issue_side, edited=True)
                else:
                    self.add_binding_side(client, binding, issue_side=issue_side)
                    self.add_binding_side(client, binding, issue_side=issue_side)
                with self.assertRaises(R02Error):
                    self.run_binding(client)
                self.assertEqual(client.binding_posts, [])

    def test_conflicting_and_opposite_side_binding_payloads_block_without_repair(self):
        client, _issue, anchor_comment, lease = self.prepare_existing()
        conflicting = self.expected_binding(anchor_comment, lease, number=82)
        self.add_binding_side(client, conflicting, issue_side=True)
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.binding_posts, [])

        client, _issue, anchor_comment, lease = self.prepare_existing()
        intended = self.expected_binding(anchor_comment, lease)
        self.add_binding_side(client, intended, issue_side=True)
        mismatched_pr_side = self.expected_binding(anchor_comment, lease, issue_database_id=811, issue_node_id="PR_node_wrong")
        self.add_binding_side(client, mismatched_pr_side, issue_side=False)
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.binding_posts, [])

    def test_reserved_unknown_issue_authority_marker_fences_ref_progression(self):
        client, _issue, _anchor, _lease = self.prepare()
        comment = IssueAnchorControllerTests.comment(
            "<!-- swiftstream-federation-issue-cancellation-fence:v1 -->\n{}\n",
            database_id=1999,
            author_id=self.APP.bot_node_id,
            author_login=self.APP.bot_login,
        )
        client.comments.append(comment)
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(client.ref_writes, [])
        self.assertEqual(client.pr_create_calls, [])

    def test_ambiguous_issue_binding_post_never_posts_again_or_writes_opposite_side_same_invocation(self):
        client, _issue, _anchor, _lease = self.prepare_existing(ambiguous_binding_side="issue")
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertEqual(len(client.binding_posts), 1)
        self.assertEqual(client.binding_posts[0][0], 7)
        self.assertTrue(client.binding_posts[0][1].startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))
        self.assertFalse(any(body.startswith(PR_ISSUE_ORIGIN_BINDING_MARKER) for _number, body in client.binding_posts))

        client.ambiguous_binding_side = None
        state = self.run_binding(client)
        self.assertEqual(state.binding, parse_issue_internal_pr_binding(client.comments[-1].body))
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [
            ISSUE_INTERNAL_PR_BINDING_MARKER, PR_ISSUE_ORIGIN_BINDING_MARKER,
        ])

    def test_ambiguous_pr_binding_post_never_reposts_same_side_and_later_complete_recovery_is_zero_write(self):
        client, _issue, _anchor, _lease = self.prepare_existing(ambiguous_binding_side="pr")
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [
            ISSUE_INTERNAL_PR_BINDING_MARKER, PR_ISSUE_ORIGIN_BINDING_MARKER,
        ])
        before = list(client.binding_posts)
        state = self.run_binding(client)
        self.assertIsInstance(state, IssuePRBindingState)
        self.assertEqual(client.binding_posts, before)

    def test_nonpersisted_ambiguous_binding_posts_retry_only_in_later_fresh_invocation(self):
        client, _issue, _anchor, _lease = self.prepare_existing(
            ambiguous_binding_side="issue", persist_ambiguous_binding=False,
        )
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertEqual(len(client.binding_posts), 1)
        self.assertEqual(len(client.comments), 2)
        client.ambiguous_binding_side = None
        self.run_binding(client)
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [
            ISSUE_INTERNAL_PR_BINDING_MARKER,
            ISSUE_INTERNAL_PR_BINDING_MARKER,
            PR_ISSUE_ORIGIN_BINDING_MARKER,
        ])

        client, _issue, _anchor, _lease = self.prepare_existing(
            ambiguous_binding_side="pr", persist_ambiguous_binding=False,
        )
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [
            ISSUE_INTERNAL_PR_BINDING_MARKER, PR_ISSUE_ORIGIN_BINDING_MARKER,
        ])
        client.ambiguous_binding_side = None
        self.run_binding(client)
        self.assertEqual([body.splitlines()[0] for _number, body in client.binding_posts], [
            ISSUE_INTERNAL_PR_BINDING_MARKER,
            PR_ISSUE_ORIGIN_BINDING_MARKER,
            PR_ISSUE_ORIGIN_BINDING_MARKER,
        ])

    def test_head_source_issue_and_final_pr_drift_preserve_binding_evidence_and_block(self):
        client, _issue, _anchor, _lease = self.prepare_existing()
        client.after_binding_callback = lambda number, body, issue_side: setattr(client, "current_ref", "e" * 40) if issue_side else None
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client)
        self.assertTrue(client.comments[-1].body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))
        self.assertEqual(len(client.binding_posts), 1)

        client, _issue, _anchor, _lease = self.prepare_existing()
        client.source_drift = False
        def dynamic_resolver(request, request_class):
            source_id = "changed-source" if client.source_drift else "owner-repo"
            return IssueBranchLeaseControllerTests.resolver(source_id=source_id)(request, request_class)
        client.after_binding_callback = lambda number, body, issue_side: setattr(client, "source_drift", True) if issue_side else None
        with self.assertRaises(StaleAuthorityError):
            self.run_binding(client, resolver=dynamic_resolver)
        self.assertEqual(len(client.binding_posts), 1)
        self.assertTrue(client.comments[-1].body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))

        client, issue, _anchor, _lease = self.prepare_existing()
        client.after_binding_callback = lambda number, body, issue_side: setattr(
            client, "issue", IssueMetadata(**dict(issue.__dict__, state="closed")),
        ) if issue_side else None
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(len(client.binding_posts), 1)

        client, _issue, _anchor, _lease = self.prepare_existing()
        def drift_after_pr_binding(number, body, issue_side):
            if not issue_side:
                pr = client.pull_requests[number]
                client.pull_requests[number] = PullRequestMetadata(**dict(pr.__dict__, body="post-binding drift"))
        client.after_binding_callback = drift_after_pr_binding
        with self.assertRaises(R02Error):
            self.run_binding(client)
        self.assertEqual(len(client.binding_posts), 2)
        self.assertTrue(client.comments[-1].body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))
        self.assertTrue(client.pr_comments[81][-1].body.startswith(PR_ISSUE_ORIGIN_BINDING_MARKER))


class IssueHeadClaimControllerTests(unittest.TestCase):
    APP = IssueAnchorControllerTests.APP
    CENTRAL = IssuePRBindingControllerTests.CENTRAL_REPOSITORY
    CENTRAL_NODE_ID = IssuePRBindingControllerTests.CENTRAL_NODE_ID
    BASE_SHA = "a" * 40
    INITIAL_HEAD_SHA = "b" * 40
    BASE_TREE_SHA = "d" * 40
    FROM_TREE_SHA = "c" * 40
    TARGET_TREE_SHA = "e" * 40
    AUTHOR_DATE = "2026-10-04T00:00:00Z"

    @staticmethod
    def _git_blob_sha(data):
        return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()

    def make_state(self, request_class=RequestClass.ADD):
        issue = IssueAnchorControllerTests.issue(request_class)
        anchor_comment, anchor = IssueAnchorControllerTests.persisted(issue, request_class)
        lease = IssueBranchLease.create(
            schema_version=1,
            issue_number=issue.number,
            issue_database_id=issue.database_id,
            issue_node_id=issue.node_id,
            issue_request_anchor_comment_database_id=anchor_comment.database_id,
            issue_request_anchor_sha256=anchor.canonical_sha256(),
            source_id=anchor.source_id,
            source_repository_id=anchor.source_repository_id,
            central_repository_node_id=self.CENTRAL_NODE_ID,
            branch_ref=issue_branch_ref(issue.number),
            accepted_base_sha=self.BASE_SHA,
            carrier_role="ISSUE_ACTIVE",
            claim_kind="ISSUE_BRANCH_LEASE",
            claim_generation_id="1" * 64,
            carrier_nonce="2" * 64,
            authority_preimage_digest="3" * 64,
            initial_head_sha=self.INITIAL_HEAD_SHA,
            initial_head_tree_sha=self.FROM_TREE_SHA,
            initial_head_parent_sha=self.BASE_SHA,
            initial_head_marker_digest="4" * 64,
            request_class=request_class,
        )
        lease_comment = IssueAnchorControllerTests.comment(lease.render(), database_id=101)
        lease_comment_wrap = IssueBranchLeaseComment(lease, lease_comment)
        binding = IssuePRBinding.create(
            schema_version=1,
            issue_number=issue.number,
            issue_database_id=issue.database_id,
            issue_node_id=issue.node_id,
            issue_request_anchor_comment_database_id=anchor_comment.database_id,
            issue_request_anchor_sha256=anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=lease_comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(lease_comment.body.encode()).hexdigest(),
            source_id=anchor.source_id,
            source_repository_id=anchor.source_repository_id,
            branch_ref=lease.branch_ref,
            pull_request_number=81,
            pull_request_database_id=810,
            pull_request_node_id="PR_node_81",
            initial_head_sha=lease.initial_head_sha,
            base_ref="main",
            central_repository_node_id=self.CENTRAL_NODE_ID,
        )
        issue_binding_comment = IssueAnchorControllerTests.comment(
            binding.render_issue_binding(), database_id=102,
        )
        pr_binding_comment = IssueAnchorControllerTests.comment(
            binding.render_pr_origin_binding(), database_id=103,
        )
        body = render_request_body(anchor.initial_request)
        pr = PullRequestMetadata(
            81, body, self.APP.bot_node_id, self.APP.bot_login,
            self.INITIAL_HEAD_SHA, self.BASE_SHA,
            lease.branch_ref.removeprefix("refs/heads/"), "main",
            self.CENTRAL_NODE_ID, self.CENTRAL, self.CENTRAL_NODE_ID, self.CENTRAL,
            None, False, False,
        )
        pr_issue = IssueMetadata(
            81, 810, "PR_node_81", body, "open", self.APP.bot_node_id,
            self.APP.bot_login, None, False, True,
        )
        state = IssuePRBindingState(
            IssueAnchorComment(anchor, anchor_comment), lease_comment_wrap, binding,
            issue_binding_comment, pr_binding_comment, pr, pr_issue,
        )
        return issue, anchor_comment, anchor, state

    def make_proposal_claim(self, state):
        old_bytes = b"old federation state\n"
        new_bytes = b"new federation state\n"
        old_blob = self._git_blob_sha(old_bytes)
        new_blob = self._git_blob_sha(new_bytes)
        evidence = [{
            "path": "federation.json",
            "state": "PRESENT",
            "mode": "100644",
            "objectType": "blob",
            "blobSha": new_blob,
            "contentSha256": hashlib.sha256(new_bytes).hexdigest(),
        }]
        target_digest = proposal_target_evidence_digest(
            candidate_tree_sha=self.TARGET_TREE_SHA,
            changed=evidence,
            candidate_changed_paths=("federation.json",),
        )
        common = dict(
            schema_version=1,
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(state.lease.comment.body.encode()).hexdigest(),
            binding_id=state.binding.binding_id,
            source_id=state.binding.source_id,
            source_repository_id=state.binding.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=RequestClass.ADD,
            accepted_base_sha=self.BASE_SHA,
            accepted_base_tree_sha=self.BASE_TREE_SHA,
            from_head_sha=self.INITIAL_HEAD_SHA,
            from_tree_sha=self.FROM_TREE_SHA,
            to_head_sha="0" * 40,
            to_tree_sha=self.TARGET_TREE_SHA,
            transition_kind="PROPOSAL",
            carrier_nonce="5" * 64,
            effective_request_digest="6" * 64,
            patch_projection_evidence_digest="7" * 64,
            target_evidence_digest=target_digest,
        )
        prepared = IssueHeadClaim.create(**common)
        marker = controller_module._issue_head_claim_marker(prepared).render()
        to_head = controller_module._expected_deterministic_commit_sha(
            self.TARGET_TREE_SHA, self.INITIAL_HEAD_SHA, marker, self.AUTHOR_DATE,
        )
        claim = IssueHeadClaim.create(**{**common, "to_head_sha": to_head})
        trees = {
            self.BASE_SHA: (self.BASE_TREE_SHA, (GitTreeEntry("federation.json", "100644", "blob", old_blob),)),
            self.INITIAL_HEAD_SHA: (self.FROM_TREE_SHA, (GitTreeEntry("federation.json", "100644", "blob", old_blob),)),
            to_head: (self.TARGET_TREE_SHA, (GitTreeEntry("federation.json", "100644", "blob", new_blob),)),
        }
        commits = {
            self.BASE_SHA: GitCommitMetadata(self.BASE_SHA, self.BASE_TREE_SHA, (), self.AUTHOR_DATE),
            self.INITIAL_HEAD_SHA: GitCommitMetadata(self.INITIAL_HEAD_SHA, self.FROM_TREE_SHA, (self.BASE_SHA,), self.AUTHOR_DATE),
            to_head: GitCommitMetadata(to_head, self.TARGET_TREE_SHA, (self.INITIAL_HEAD_SHA,), self.AUTHOR_DATE),
        }
        return claim, commits, trees, {old_blob: old_bytes, new_blob: new_bytes}

    def test_managed_normalize_reads_created_tree_and_claims_wrapper_before_cas(self):
        issue, _anchor_comment, _anchor, original_state = self.make_state()
        current_main = "f" * 40
        current_main_tree = "9" * 40
        raw_candidate_sha = "4" * 40
        raw_candidate_tree = "5" * 40
        normalized_tree_sha = "7" * 40
        state = replace(original_state, pr=replace(original_state.pr, base_oid=current_main))
        request = parse_issue_request_body(issue.body)
        fold = type("Fold", (), {"request": request})()
        repository = RepositoryMetadata(1, self.CENTRAL_NODE_ID, self.CENTRAL, "main")

        base_bytes = b"fresh accepted federation state\n"
        candidate_bytes = b"raw C02 candidate federation state\n"
        base_blob = self._git_blob_sha(base_bytes)
        candidate_blob = self._git_blob_sha(candidate_bytes)
        marker_bytes = (RequestClass.ADD.value + "\n").encode("utf-8")
        marker_blob = self._git_blob_sha(marker_bytes)
        main_entries = (GitTreeEntry("federation.json", "100644", "blob", base_blob),)
        candidate_entries = (GitTreeEntry("federation.json", "100644", "blob", candidate_blob),)
        from_entries = (
            GitTreeEntry(".federation-request", "100644", "blob", marker_blob),
            GitTreeEntry("federation.json", "100644", "blob", "6" * 40),
        )
        target_entries = tuple(sorted(
            (*main_entries, GitTreeEntry(".federation-request", "100644", "blob", marker_blob)),
            key=lambda item: item.path.encode("utf-8"),
        ))
        tree_entries = {
            current_main_tree: main_entries,
            self.FROM_TREE_SHA: from_entries,
            normalized_tree_sha: target_entries,
        }
        events = []

        class TreeTransport:
            def request(_self, method, url, headers, body, timeout):
                expected_prefix = REST_BASE_URL + f"/repos/{self.CENTRAL}/git/trees/"
                if method != "GET" or not url.startswith(expected_prefix) or not url.endswith("?recursive=1"):
                    raise AssertionError((method, url))
                requested_tree = url[len(expected_prefix):-len("?recursive=1")]
                events.append(("get-tree", requested_tree))
                entries = tree_entries[requested_tree]
                payload = {
                    "sha": requested_tree,
                    "tree": [
                        {"path": entry.path, "mode": entry.mode, "type": entry.object_type, "sha": entry.sha}
                        for entry in entries
                    ],
                    "truncated": False,
                }
                return HttpResponse(200, url, json.dumps(payload).encode("utf-8"))

        class ManagedNormalizeClient(GitHubClient):
            def __init__(_self):
                super().__init__(None, TreeTransport())
                _self.current_ref = self.INITIAL_HEAD_SHA
                _self.commit_reads = []
                _self.commit_metadata = {
                    current_main: GitCommitMetadata(current_main, current_main_tree, (), self.AUTHOR_DATE),
                    self.INITIAL_HEAD_SHA: GitCommitMetadata(
                        self.INITIAL_HEAD_SHA, self.FROM_TREE_SHA, (self.BASE_SHA,), self.AUTHOR_DATE,
                    ),
                }
                _self.blobs = {
                    base_blob: base_bytes,
                    candidate_blob: candidate_bytes,
                    marker_blob: marker_bytes,
                }
                _self.pull_comments = []
                _self.ref_updates = []
                _self.created_tree = None
                _self.created_commit = None

            def get_commit_metadata(_self, _repository, commit_sha):
                _self.commit_reads.append(commit_sha)
                if commit_sha not in _self.commit_metadata:
                    raise AssertionError(f"unexpected commit metadata read: {commit_sha}")
                return _self.commit_metadata[commit_sha]

            def get_blob(_self, _repository, blob_sha):
                return _self.blobs[blob_sha]

            def create_blob(_self, _repository, content, *, encoding="base64"):
                self.assertEqual(encoding, "base64")
                data = base64.b64decode(content, validate=True)
                self.assertEqual(data, marker_bytes)
                events.append(("create-blob", data))
                return GitObject(marker_blob)

            def create_tree(_self, _repository, base_tree, entries):
                entry_list = list(entries)
                self.assertEqual(base_tree, current_main_tree)
                self.assertEqual(entry_list, [{
                    "path": ".federation-request", "mode": "100644", "type": "blob", "sha": marker_blob,
                }])
                events.append(("create-tree", base_tree))
                _self.created_tree = (base_tree, entry_list)
                return GitObject(normalized_tree_sha)

            def create_commit(_self, _repository, message, tree, parents, *, timestamp=None):
                parent_list = list(parents)
                self.assertEqual(tree, normalized_tree_sha)
                self.assertEqual(parent_list, [self.INITIAL_HEAD_SHA])
                wrapper_sha = controller_module._expected_deterministic_commit_sha(
                    tree, parent_list[0], message, timestamp,
                )
                events.append(("create-commit", tree, tuple(parent_list)))
                _self.created_commit = (message, tree, tuple(parent_list), timestamp, wrapper_sha)
                _self.commit_metadata[wrapper_sha] = GitCommitMetadata(
                    wrapper_sha, tree, tuple(parent_list), timestamp,
                )
                return GitObject(wrapper_sha)

            def create_issue_comment(_self, _repository, number, body):
                self.assertEqual(number, state.binding.pull_request_number)
                events.append(("claim-post", body))
                comment = IssueAnchorControllerTests.comment(body, database_id=501)
                _self.pull_comments.append(comment)
                return comment

            def list_issue_comments(_self, _repository, number):
                if number == state.binding.pull_request_number:
                    if _self.pull_comments:
                        events.append(("claim-readback", _self.pull_comments[-1].body))
                    return tuple(_self.pull_comments)
                return ()

            def get_issue_metadata(_self, _repository, number):
                self.assertEqual(number, issue.number)
                return issue

            def get_pull_request_metadata(_self, _repository, number):
                self.assertEqual(number, state.binding.pull_request_number)
                return state.pr

            def get_ref_oid(_self, _repository, _branch):
                return _self.current_ref

            def update_refs(_self, repository_id, updates):
                update_list = tuple(updates)
                events.append(("ref-cas", repository_id, update_list))
                _self.ref_updates.append((repository_id, update_list))
                _self.current_ref = update_list[0].after_oid
                return {}

        client = ManagedNormalizeClient()
        candidate = controller_module.ProposalCandidate(
            raw_candidate_sha,
            current_main,
            ("federation.json",),
            RequestClass.ADD,
            "owner-repo",
            41,
            False,
        )
        snapshots = {
            current_main: (
                client.commit_metadata[current_main], current_main_tree, main_entries,
            ),
            raw_candidate_sha: (
                GitCommitMetadata(raw_candidate_sha, raw_candidate_tree, (current_main,), self.AUTHOR_DATE),
                raw_candidate_tree,
                candidate_entries,
            ),
            self.INITIAL_HEAD_SHA: (
                client.commit_metadata[self.INITIAL_HEAD_SHA], self.FROM_TREE_SHA, from_entries,
            ),
        }
        lease_snapshot_calls = []
        real_lease_snapshot = controller_module._lease_tree_snapshot

        def lease_snapshot(_client, repository_name, commit_sha):
            self.assertNotEqual(commit_sha, normalized_tree_sha)
            lease_snapshot_calls.append(commit_sha)
            if commit_sha in snapshots:
                return snapshots[commit_sha]
            return real_lease_snapshot(_client, repository_name, commit_sha)

        claim_readbacks = []

        def read_claims(_client, _repository, comments, _app, _state, current_ref):
            claims = []
            for comment in comments:
                if comment.body.startswith(ISSUE_HEAD_CLAIM_MARKER):
                    claim = controller_module.parse_issue_head_claim(comment.body)
                    claim_readbacks.append((claim, current_ref))
                    claims.append(controller_module.IssueHeadClaimComment(
                        claim, comment, claim.to_head_sha == current_ref,
                    ))
            return tuple(claims)

        controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
        controller.client = client
        controller.central_repository = self.CENTRAL
        controller.app = self.APP
        controller.candidate_builder = lambda *_args: candidate
        with (
            patch.object(
                controller_module, "_validate_managed_issue_head_history",
                return_value=(state, self.INITIAL_HEAD_SHA, (), ()),
            ),
            patch.object(controller_module, "_ensure_managed_issue_pr_request_anchor"),
            patch.object(controller_module, "_read_managed_issue_pr_binding_state", return_value=state),
            patch.object(controller_module, "_fresh_issue_projection_set", return_value=(fold, ())),
            patch.object(controller_module, "_synchronize_issue_patch_projections", return_value=(fold, (), (), ())),
            patch.object(controller_module, "_validate_issue_source_authority"),
            patch.object(controller_module, "_issue_pr_authority_fence"),
            patch.object(controller_module, "_issue_head_claim_comments", side_effect=read_claims),
            patch.object(controller_module, "_lease_tree_snapshot", side_effect=lease_snapshot),
            patch.object(controller, "current_accepted_main", return_value=(repository, current_main)),
        ):
            final_claim = controller.interactive_issue_managed_proposal(
                issue.number, lambda *_args: IssueAnchorControllerTests.authority(), nonce_factory=lambda: "8" * 64,
            )

        self.assertEqual(final_claim.transition_kind, "NORMALIZE")
        self.assertEqual(final_claim.accepted_base_sha, current_main)
        self.assertEqual(final_claim.accepted_base_tree_sha, current_main_tree)
        self.assertEqual(final_claim.to_tree_sha, normalized_tree_sha)
        self.assertEqual(client.created_tree[0], current_main_tree)
        self.assertEqual(client.created_commit[1:3], (normalized_tree_sha, (self.INITIAL_HEAD_SHA,)))
        self.assertIn(("get-tree", normalized_tree_sha), events)
        self.assertLess(events.index(("create-tree", current_main_tree)), events.index(("get-tree", normalized_tree_sha)))
        self.assertLess(events.index(("get-tree", normalized_tree_sha)), next(i for i, event in enumerate(events) if event[0] == "create-commit"))
        self.assertNotIn(normalized_tree_sha, client.commit_reads)
        self.assertNotIn(normalized_tree_sha, lease_snapshot_calls)
        self.assertEqual(len(claim_readbacks), 1)
        self.assertEqual(claim_readbacks[0][0], final_claim)
        self.assertEqual(claim_readbacks[0][1], self.INITIAL_HEAD_SHA)
        event_names = [event[0] for event in events]
        self.assertLess(event_names.index("claim-post"), event_names.index("claim-readback"))
        self.assertLess(event_names.index("claim-readback"), event_names.index("ref-cas"))
        self.assertEqual(len(client.ref_updates), 1)
        repository_id, updates = client.ref_updates[0]
        self.assertEqual(repository_id, self.CENTRAL_NODE_ID)
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0].before_oid, self.INITIAL_HEAD_SHA)
        self.assertEqual(updates[0].after_oid, final_claim.to_head_sha)
        self.assertIs(updates[0].force, False)
        self.assertNotEqual(updates[0].after_oid, normalized_tree_sha)
        self.assertEqual(client.current_ref, final_claim.to_head_sha)

    def test_f1_proposal_remains_historically_valid_after_f2_and_losing_cas_is_nonactive(self):
        _issue, _anchor_comment, _anchor, state = self.make_state()
        claim, commits, trees, blobs = self.make_proposal_claim(state)
        claim_comment = IssueAnchorControllerTests.comment(claim.render(), database_id=300)

        class HistoricalClient:
            current_issue_comments = ()

            def get_commit_metadata(_self, _repository, sha):
                return commits[sha]

            def get_commit_tree(_self, _repository, sha):
                return trees[sha]

            def get_blob(_self, _repository, sha):
                return blobs[sha]

        # F2 exists only in the mutable source Issue comments. Historical claim
        # validation must prove F1 from its stored evidence and Git target alone.
        f2 = IssueAnchorControllerTests.comment(
            f"{PATCH_SENTINEL}\n\nDescription:\nF2\n", database_id=400,
            author_id="U_requester", author_login="alice", author_type="User",
        )
        historical_client = HistoricalClient()
        historical_client.current_issue_comments = (f2,)
        with patch.object(controller_module, "reconstruct_issue_from_github", side_effect=AssertionError("historical path must not fold current Issue comments")):
            validated = controller_module._issue_head_claim_comments(
                historical_client, self.CENTRAL, [claim_comment], self.APP, state, "9" * 40,
            )
        self.assertEqual(len(validated), 1)
        self.assertEqual(validated[0].claim, claim)
        self.assertFalse(validated[0].active)
        active = controller_module._issue_head_claim_comments(
            historical_client, self.CENTRAL, [claim_comment], self.APP, state, claim.to_head_sha,
        )
        self.assertTrue(active[0].active)
        self.assertEqual(
            classify_issue_head_claim_progression(
                claim,
                fresh_effective_request_digest="8" * 64,
                fresh_patch_projection_evidence_digest="7" * 64,
                fresh_accepted_base_sha="a" * 40,
                fresh_accepted_base_tree_sha=self.BASE_TREE_SHA,
                proposal_exists=True,
            ),
            "PATCH_REGENERATION",
        )
        self.assertEqual(
            classify_issue_head_claim_progression(
                claim,
                fresh_effective_request_digest=claim.effective_request_digest,
                fresh_patch_projection_evidence_digest=claim.patch_projection_evidence_digest,
                fresh_accepted_base_sha="8" * 40,
                fresh_accepted_base_tree_sha="9" * 40,
                proposal_exists=True,
            ),
            "MAIN_ADVANCE",
        )
        self.assertEqual(
            classify_issue_head_claim_progression(
                claim,
                fresh_effective_request_digest="8" * 64,
                fresh_patch_projection_evidence_digest="9" * 64,
                fresh_accepted_base_sha="8" * 40,
                fresh_accepted_base_tree_sha="9" * 40,
                proposal_exists=True,
            ),
            "PATCH_REGENERATION",
        )

    def test_f2_racing_claim_post_keeps_persisted_f1_fields_unchanged(self):
        _issue, _anchor_comment, _anchor, state = self.make_state()
        claim, _commits, _trees, _blobs = self.make_proposal_claim(state)

        class PersistClient:
            def __init__(_self):
                _self.pr_comments = [state.pr_binding_comment]
                _self.issue_comments = []

            def create_issue_comment(_self, _repository, number, body):
                self.assertEqual(number, state.binding.pull_request_number)
                _self.pr_comments.append(IssueAnchorControllerTests.comment(body, database_id=301))
                _self.issue_comments.append(IssueAnchorControllerTests.comment(
                    f"{PATCH_SENTINEL}\n\nDescription:\nF2\n", database_id=400,
                    author_id="U_requester", author_login="alice", author_type="User",
                ))

            def list_issue_comments(_self, _repository, number):
                return tuple(_self.pr_comments)

            def get_ref_oid(_self, _repository, _branch):
                return self.INITIAL_HEAD_SHA

        client = PersistClient()
        with (
            patch.object(controller_module, "_validate_issue_head_claim_target"),
            patch.object(controller_module, "reconstruct_issue_from_github", side_effect=AssertionError("claim persistence must not refold F2")),
        ):
            controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
            controller.client = client
            controller.central_repository = self.CENTRAL
            controller.app = self.APP
            persisted = controller._persist_issue_head_claim(state, claim)
        self.assertEqual(persisted.claim, claim)
        self.assertEqual(persisted.claim.carrier_nonce, claim.carrier_nonce)
        self.assertEqual(persisted.claim.target_evidence_digest, claim.target_evidence_digest)
        self.assertEqual(persisted.claim.to_head_sha, claim.to_head_sha)
        self.assertEqual(len(client.issue_comments), 1)

    def test_crash_replay_uses_persisted_claim_target_and_single_force_false_cas(self):
        _issue, _anchor_comment, _anchor, state = self.make_state()
        claim, _commits, _trees, _blobs = self.make_proposal_claim(state)

        class CASClient:
            def __init__(_self):
                _self.ref = claim.from_head_sha
                _self.updates = []
                _self.comment_posts = []

            def get_ref_oid(_self, _repository, _branch):
                return _self.ref

            def update_refs(_self, _repository_id, updates):
                _self.updates.append(tuple(updates))
                update = updates[0]
                _self.ref = update.after_oid

        client = CASClient()
        controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
        controller.client = client
        controller.central_repository = self.CENTRAL
        controller._apply_persisted_issue_head_claim(state, claim, claim.from_head_sha)
        self.assertEqual(len(client.updates), 1)
        update = client.updates[0][0]
        self.assertEqual(update.before_oid, claim.from_head_sha)
        self.assertEqual(update.after_oid, claim.to_head_sha)
        self.assertIs(update.force, False)
        self.assertEqual(client.ref, claim.to_head_sha)
        self.assertEqual(client.comment_posts, [])

    def test_accepted_patch_projection_is_persisted_on_bound_pr_and_complete_before_transition(self):
        issue, _anchor_comment, _anchor, state = self.make_state()
        patch_comment = IssueAnchorControllerTests.comment(
            f"{PATCH_SENTINEL}\n\nDescription:\nProjected description\n",
            database_id=104,
            author_id="U_requester",
            author_login="alice",
            author_type="User",
        )
        source_comments = (
            state.issue_anchor.comment,
            state.lease.comment,
            patch_comment,
            state.issue_binding_comment,
        )

        class ProjectionClient:
            def __init__(_self):
                _self.source_comments = list(source_comments)
                _self.pr_comments = [state.pr_binding_comment]
                _self.posts = []

            def get_collaborator_permission(_self, _repository, _login):
                raise AssertionError("original requester authorization needs no permission read")

            def create_issue_patch_projection_comment(_self, _repository, number, body):
                _self.posts.append((number, body))
                _self.pr_comments.append(IssueAnchorControllerTests.comment(body, database_id=302))

            def list_issue_comments(_self, _repository, number):
                return tuple(_self.source_comments if number == issue.number else _self.pr_comments)

            def get_issue_metadata(_self, _repository, number):
                if number != issue.number:
                    raise AssertionError("projection refresh must reread the source Issue")
                return issue

        client = ProjectionClient()
        fold, projections, _fresh_source_comments, fresh_pr_comments = controller_module._synchronize_issue_patch_projections(
            client,
            self.CENTRAL,
            issue,
            state.issue_anchor,
            state.binding,
            source_comments,
            [state.pr_binding_comment],
            self.APP,
            None,
        )
        self.assertEqual(fold.request.description, "Projected description")
        self.assertEqual(len(projections), 1)
        self.assertEqual(client.posts[0][0], state.binding.pull_request_number)
        self.assertTrue(any(comment.body.startswith("<!-- swiftstream-federation-issue-patch-projection:v1 -->") for comment in fresh_pr_comments))
        with self.assertRaises(R02Error):
            controller_module._fresh_issue_projection_set(
                client, self.CENTRAL, issue, state.issue_anchor, state.binding,
                tuple(source_comments) + (fresh_pr_comments[-1],), fresh_pr_comments,
                self.APP, None, require_complete=True,
            )

    def test_managed_issue_pr_hands_off_one_exact_reusable_request_anchor(self):
        _issue, _anchor_comment, _anchor, state = self.make_state()

        class AnchorClient:
            def __init__(_self):
                _self.comments = [state.pr_binding_comment]
                _self.posts = []

            def get_pull_request_metadata(_self, _repository, number):
                self.assertEqual(number, state.binding.pull_request_number)
                return state.pr

            def list_issue_comments(_self, _repository, number):
                self.assertEqual(number, state.binding.pull_request_number)
                return tuple(_self.comments)

            def create_issue_comment(_self, _repository, number, body):
                _self.posts.append((number, body))
                _self.comments.append(IssueAnchorControllerTests.comment(body, database_id=304))

        client = AnchorClient()
        first = controller_module._ensure_managed_issue_pr_request_anchor(
            client, self.CENTRAL, state, RequestClass.ADD, self.APP,
        )
        replay = controller_module._ensure_managed_issue_pr_request_anchor(
            client, self.CENTRAL, state, RequestClass.ADD, self.APP,
        )
        self.assertEqual(first, replay)
        self.assertEqual(first.anchor.initial_request, state.issue_anchor.anchor.initial_request)
        self.assertEqual(len(client.posts), 1)
        self.assertEqual(client.posts[0][0], state.binding.pull_request_number)

    def test_no_semantic_change_stops_each_request_class_before_claim_or_status_mutation(self):
        repository = RepositoryMetadata(1, self.CENTRAL_NODE_ID, self.CENTRAL, "main")

        class ReadOnlyClient:
            def __init__(_self):
                _self.writes = []

            def get_repository_metadata(_self, _repository):
                return repository

            def list_issue_comments(_self, _repository, _number):
                return ()

            def get_issue_metadata(_self, _repository, number):
                self.assertEqual(number, issue.number)
                return issue

            def get_pull_request_metadata(_self, _repository, number):
                self.assertEqual(number, state.binding.pull_request_number)
                return state.pr

            def __getattr__(_self, name):
                if name.startswith(("create_", "update_", "dispatch_", "merge_", "close_")):
                    return lambda *_args, **_kwargs: _self.writes.append(name)
                raise AttributeError(name)

        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(request_class=request_class):
                issue, _anchor_comment, _anchor, state = self.make_state(request_class)
                request = parse_issue_request_body(issue.body)
                fold = type("Fold", (), {"request": request})()
                main_meta = GitCommitMetadata(self.BASE_SHA, self.BASE_TREE_SHA, (), self.AUTHOR_DATE)
                client = ReadOnlyClient()

                def no_semantic_candidate(*_args):
                    raise IssueManagedNoSemanticChange(request_class)

                controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
                controller.client = client
                controller.central_repository = self.CENTRAL
                controller.app = self.APP
                controller.candidate_builder = no_semantic_candidate
                with (
                    patch.object(
                        controller_module,
                        "_validate_managed_issue_head_history",
                        return_value=(state, self.INITIAL_HEAD_SHA, (), ()),
                    ),
                    patch.object(controller_module, "_ensure_managed_issue_pr_request_anchor", return_value=object()),
                    patch.object(controller_module, "_read_managed_issue_pr_binding_state", return_value=state),
                    patch.object(controller_module, "_fresh_issue_projection_set", return_value=(fold, ())),
                    patch.object(controller_module, "_synchronize_issue_patch_projections", return_value=(fold, (), (), ())),
                    patch.object(controller_module, "_validate_issue_source_authority"),
                    patch.object(controller_module, "_issue_pr_authority_fence"),
                    patch.object(controller_module, "_issue_head_claim_comments", return_value=()),
                    patch.object(
                        controller_module,
                        "_lease_tree_snapshot",
                        return_value=(main_meta, self.BASE_TREE_SHA, ()),
                    ),
                    patch.object(controller_module, "_read_issue_branch_ref", return_value=self.INITIAL_HEAD_SHA),
                    patch.object(controller, "current_accepted_main", return_value=(repository, self.BASE_SHA)),
                ):
                    first = controller.interactive_issue_managed_route(
                        issue.number,
                        lambda *_args: object(),
                    )
                    replay = controller.interactive_issue_managed_route(
                        issue.number,
                        lambda *_args: object(),
                    )
                self.assertEqual(first.outcome, "NOOP")
                self.assertEqual(first.reason, "NO_SEMANTIC_CHANGE")
                self.assertIs(first.request_class, request_class)
                self.assertEqual(replay, first)
                self.assertEqual(client.writes, [])

    def test_claim_ready_route_result_includes_exact_request_class(self):
        _issue, _anchor_comment, _anchor, state = self.make_state(RequestClass.ADD)
        claim, _commits, _trees, _blobs = self.make_proposal_claim(state)
        controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
        with patch.object(controller, "interactive_issue_managed_proposal", return_value=claim):
            result = controller.interactive_issue_managed_route(7, lambda *_args: object())
        self.assertEqual(result, controller_module.IssueManagedRouteResult(
            "CLAIM_READY", claim.transition_kind, RequestClass.ADD,
        ))
        self.assertIs(result.request_class, claim.request_class)

    def test_patch_and_main_advance_uses_patch_regeneration_from_fresh_main(self):
        issue, _anchor_comment, _anchor, original_state = self.make_state()
        claim, _commits, _trees, _blobs = self.make_proposal_claim(original_state)
        fresh_main = "8" * 40
        fresh_main_tree = "9" * 40
        fresh_main_meta = GitCommitMetadata(fresh_main, fresh_main_tree, (), self.AUTHOR_DATE)
        state = replace(
            original_state,
            pr=replace(original_state.pr, head_oid=claim.to_head_sha, base_oid=fresh_main),
        )
        request = parse_issue_request_body(issue.body)
        fold = type("Fold", (), {"request": request})()
        repository = RepositoryMetadata(1, self.CENTRAL_NODE_ID, self.CENTRAL, "main")
        active = controller_module.IssueHeadClaimComment(
            claim,
            IssueAnchorControllerTests.comment(claim.render(), database_id=300),
            True,
        )

        class ReadOnlyClient:
            def __init__(_self):
                _self.writes = []

            def get_repository_metadata(_self, _repository):
                return repository

            def list_issue_comments(_self, _repository, _number):
                return ()

            def get_issue_metadata(_self, _repository, number):
                self.assertEqual(number, issue.number)
                return issue

            def get_pull_request_metadata(_self, _repository, number):
                self.assertEqual(number, state.binding.pull_request_number)
                return state.pr

            def __getattr__(_self, name):
                if name.startswith(("create_", "update_", "dispatch_", "merge_", "close_")):
                    return lambda *_args, **_kwargs: _self.writes.append(name)
                raise AttributeError(name)

        client = ReadOnlyClient()
        candidate_inputs = []
        classified_transitions = []

        def candidate_from_fresh_snapshot(request_value, request_class, accepted_base_sha, head_sha):
            candidate_inputs.append((request_value, request_class, accepted_base_sha, head_sha))
            raise IssueManagedNoSemanticChange(request_class)

        def classify_transition(*args, **kwargs):
            result = classify_issue_head_claim_progression(*args, **kwargs)
            classified_transitions.append(result)
            return result

        controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
        controller.client = client
        controller.central_repository = self.CENTRAL
        controller.app = self.APP
        controller.candidate_builder = candidate_from_fresh_snapshot
        with (
            patch.object(
                controller_module,
                "_validate_managed_issue_head_history",
                return_value=(state, claim.to_head_sha, (), (active,)),
            ),
            patch.object(controller_module, "_ensure_managed_issue_pr_request_anchor", return_value=object()),
            patch.object(controller_module, "_read_managed_issue_pr_binding_state", return_value=state),
            patch.object(controller_module, "_fresh_issue_projection_set", return_value=(fold, ())),
            patch.object(controller_module, "_synchronize_issue_patch_projections", return_value=(fold, (), (), ())),
            patch.object(controller_module, "_validate_issue_source_authority"),
            patch.object(controller_module, "_issue_pr_authority_fence"),
            patch.object(controller_module, "_issue_head_claim_comments", return_value=(active,)),
            patch.object(
                controller_module,
                "_lease_tree_snapshot",
                side_effect=[
                    (fresh_main_meta, fresh_main_tree, ()),
                    (fresh_main_meta, fresh_main_tree, ()),
                ],
            ),
            patch.object(controller_module, "_read_issue_branch_ref", return_value=claim.to_head_sha),
            patch.object(controller, "current_accepted_main", return_value=(repository, fresh_main)),
            patch.object(
                controller_module,
                "classify_issue_head_claim_progression",
                side_effect=classify_transition,
            ),
        ):
            with self.assertRaises(IssueManagedNoSemanticChange):
                controller.interactive_issue_managed_proposal(issue.number, lambda *_args: object())

        self.assertEqual(classified_transitions, ["PATCH_REGENERATION"])
        self.assertEqual(candidate_inputs, [(request, RequestClass.ADD, fresh_main, claim.to_head_sha)])
        self.assertEqual(client.writes, [])


if __name__ == "__main__":
    unittest.main()
