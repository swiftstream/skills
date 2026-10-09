import ast
import base64
import hashlib
import inspect
from io import StringIO
import json
from contextlib import nullcontext
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import automation.federation.controller as controller_module
from automation.federation.controller import (
    _legacy_payload_digest,
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
    R02Controller,
    R01Controller,
    R02Error,
    StaleAuthorityError,
    classify_request,
    resolve_sha_carrier_role,
    legacy_classification_disposition,
    publish_unclaimed_external_success,
    create_or_validate_issue_anchor,
    create_or_validate_issue_branch_lease,
    create_or_recover_issue_pr_binding,
    parse_c02_manifest,
    reconstruct_issue_from_github,
    resolve_issue_source_authority,
    validate_unique_issue_anchor,
)
from automation.federation.github_api import MergedPullRequestMetadata, RepositoryMetadata, GitTreeEntry
from automation.federation.request_model import (
    ISSUE_REQUEST_ANCHOR_MARKER,
    ISSUE_BRANCH_LEASE_MARKER,
    ISSUE_HEAD_CLAIM_MARKER,
    REQUIRED_STATUS_EPOCH_MARKER,
    ISSUE_FINALIZATION_EPOCH_MARKER,
    ISSUE_CANCELLATION_FENCE_MARKER,
    ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER,
    ISSUE_TERMINAL_CANCELLED_RESULT_MARKER,
    ISSUE_INTERNAL_PR_BINDING_MARKER,
    PR_ISSUE_ORIGIN_BINDING_MARKER,
    PATCH_SENTINEL,
    CommentEvent,
    IssueRequestAnchor,
    IssueHeadClaim,
    RequiredStatusEpoch,
    RequiredStatusEpochReason,
    IssueFinalizationEpoch,
    IssueCancellationFence,
    IssueCancellationDraftWitness,
    IssueTerminalCancelledResult,
    IssueNoPRCancelledProofKind,
    ExactAppRequiredStatusSnapshot,
    IssuePRBinding,
    IssueBranchLease,
    ClaimedHeadMarker,
    ActivationBoundaryEvidence,
    CarrierActivation,
    CarrierRole,
    LegacyEvidenceDisposition,
    LegacyQuarantineClass,
    LegacyClassificationOutcome,
    LegacyQuarantineEvidence,
    LegacyClassificationResult,
    LegacyRecoveryAction,
    legacy_status_evidence_digest,
    ShaCarrierResolution,
    StatusClass,
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
    issue_final_status_evidence_digest,
    external_status_evidence_digest,
    effective_request_digest,
    proposal_target_evidence_digest,
    normalize_target_evidence_digest,
    render_request_body,
    render_status_description,
    parse_required_status_epoch,
    parse_issue_finalization_epoch,
    parse_issue_cancellation_fence,
    parse_issue_cancellation_draft_witness,
    parse_issue_terminal_cancelled_result,
    cancel_status_evidence_digest,
    claim_generation_id,
    activation_boundary_id_digest,
    machine_ref_claim_authority_digest,
)
from automation.federation.github_api import (
    CheckRun,
    GitHubAPIError,
    GitHubClient,
    GitCommitMetadata,
    GitCommitIdentity,
    GitCommitObject,
    GitCommitIdentity,
    GitObject,
    GitTreeEntry,
    HttpResponse,
    IssueComment,
    IssueMetadata,
    NotFoundError,
    PullRequestMetadata,
    PullRequestStageMutationReceipt,
    RefCASConflict,
    RepositoryMetadata,
    AppMetadata,
    BotMetadata,
    CommitStatus,
    StatusWriteReceipt,
    REST_BASE_URL,
    ZERO_OID,
    UnexpectedStatusError,
    UnprocessableError,
    TransportError,
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
            issue_binding_comment, pr_binding_comment, pr, pr_issue, issue,
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

            def list_issue_comments(_self, _repository, _number):
                return ()

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


class Wave05ShaCarrierResolverTests(unittest.TestCase):
    CENTRAL = IssuePRBindingControllerTests.CENTRAL_REPOSITORY
    CENTRAL_NODE_ID = IssuePRBindingControllerTests.CENTRAL_NODE_ID
    APP = IssueAnchorControllerTests.APP

    class CarrierClient(IssuePRBindingControllerTests.Client):
        def __init__(self, issue, anchor_comment):
            super().__init__(issue, anchor_comment)
            self.commit_trees = {
                IssueBranchLeaseControllerTests.BASE_SHA: (
                    IssueBranchLeaseControllerTests.BASE_TREE,
                    tuple(self.base_entries),
                ),
            }
            self.commit_messages = {}
            self.blobs = {}
            self.commit_object_reads = []
            self.authority_reads = []
            self.pr_inventory_reads = 0
            self.status_calls = []
            self.issue_metadata_sequences = {}
            self.issue_metadata_reads = []
            self.pull_request_metadata_sequences = {}
            self.pull_request_metadata_reads = []
            self.issue_comment_sequences = {}
            self.issue_comment_reads = []
            self.generated_ref_sequence = None
            self.generated_ref_reads = []

        def create_tree(self, repository, base_tree, entries):
            result = super().create_tree(repository, base_tree, entries)
            self.commit_trees[IssueBranchLeaseControllerTests.HEAD_TREE] = (
                IssueBranchLeaseControllerTests.HEAD_TREE, tuple(self.head_entries),
            )
            return result

        def create_commit(self, repository, message, tree, parents, *, timestamp=None):
            result = super().create_commit(repository, message, tree, parents, timestamp=timestamp)
            self.commit_messages[result.sha] = message
            self.commit_trees[result.sha] = (tree, tuple(self.head_entries))
            return result

        def get_commit_tree(self, repository, commit_sha):
            if commit_sha in self.commit_trees:
                return self.commit_trees[commit_sha]
            return super().get_commit_tree(repository, commit_sha)

        def get_git_commit_object(self, repository, sha):
            self.commit_object_reads.append((repository, sha))
            self.authority_reads.append("commit")
            metadata = self.commit_metadata[sha]
            identity = GitCommitIdentity(
                "Swift Stream Federation", "automation@swiftstream.invalid", metadata.author_date,
            )
            return GitCommitObject(
                sha, self.commit_messages[sha], metadata.tree_sha, metadata.parents, identity, identity,
            )

        def get_app_metadata(self, slug):
            self.authority_reads.append("app")
            return AppMetadata(self.APP.app_id, slug, self.APP.app_node_id)

        def get_bot_metadata(self, slug):
            self.authority_reads.append("bot")
            return BotMetadata(self.APP.bot_id, self.APP.bot_login, self.APP.bot_node_id, "Bot")

        def get_repository_metadata(self, repository):
            self.authority_reads.append("repository")
            return super().get_repository_metadata(repository)

        def get_issue_metadata(self, repository, number):
            self.authority_reads.append("issue")
            sequence = self.issue_metadata_sequences.get(number)
            if sequence:
                value = sequence.pop(0)
                if isinstance(value, BaseException):
                    self.issue_metadata_reads.append((number, "ERROR"))
                    raise value
            else:
                value = super().get_issue_metadata(repository, number)
            self.issue_metadata_reads.append((number, getattr(value, "state", "MALFORMED")))
            return value

        def list_issue_comments(self, repository, number):
            sequence = self.issue_comment_sequences.get(number)
            if sequence:
                value = sequence.pop(0)
                if isinstance(value, BaseException):
                    self.issue_comment_reads.append((number, "ERROR"))
                    raise value
            else:
                value = super().list_issue_comments(repository, number)
            result = tuple(value)
            self.issue_comment_reads.append((number, len(result)))
            return result

        def get_pull_request_metadata(self, repository, number):
            self.authority_reads.append("pull")
            sequence = self.pull_request_metadata_sequences.get(number)
            if sequence:
                value = sequence.pop(0)
                if isinstance(value, BaseException):
                    self.pull_request_metadata_reads.append((number, "ERROR"))
                    raise value
            else:
                value = super().get_pull_request_metadata(repository, number)
            self.pull_request_metadata_reads.append((number, getattr(value, "head_oid", "MALFORMED")))
            return value

        def get_ref_oid(self, repository, branch):
            if branch != "main" and self.generated_ref_sequence is not None:
                self.ref_reads.append(branch)
                if not self.generated_ref_sequence:
                    raise AssertionError("generated-ref sequence was exhausted")
                value = self.generated_ref_sequence.pop(0)
                self.generated_ref_reads.append((branch, "ERROR" if isinstance(value, BaseException) else value))
                if isinstance(value, BaseException):
                    raise value
                if value is None:
                    raise NotFoundError("generated ref not found")
                return value
            return super().get_ref_oid(repository, branch)

        def get_blob(self, repository, blob_sha):
            return self.blobs[blob_sha]

        def list_pull_requests(self, repository, *, state="open", max_pages=100):
            self.pr_inventory_reads += 1
            return tuple(
                {
                    "number": item["number"],
                    "state": getattr(self, "raw_pr_state", "open"),
                    "merged": getattr(self, "raw_pr_merged", False),
                    "merged_at": getattr(self, "raw_pr_merged_at", None),
                }
                for item in super().list_pull_requests(repository, state=state, max_pages=max_pages)
            )

    @staticmethod
    def make_client(nonce="c" * 64):
        issue, anchor_comment = IssueBranchLeaseControllerTests.setup_anchor()
        client = Wave05ShaCarrierResolverTests.CarrierClient(issue, anchor_comment)
        lease = IssueBranchLeaseControllerTests().create(
            client, anchor_comment, nonce_factory=lambda: nonce,
        )
        client.binding_anchor = anchor_comment
        client.binding_lease = lease
        client.current_ref = lease.lease.initial_head_sha
        client.add_candidate()
        return client, issue, anchor_comment, lease

    @staticmethod
    def resolve(client, sha, legacy=LegacyEvidenceDisposition.ABSENT):
        return resolve_sha_carrier_role(
            client,
            Wave05ShaCarrierResolverTests.CENTRAL,
            sha,
            Wave05ShaCarrierResolverTests.APP.slug,
            legacy,
        )

    def make_claim_client(self):
        binder = IssuePRBindingControllerTests()
        client, issue, anchor_comment, lease = self.make_client()
        state = binder.run_binding(client)

        data = b"Wave 05 resolver proposal evidence\n"
        blob_sha = hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()
        target_tree = "e" * 40
        target_entries = tuple(sorted(
            (*client.base_entries, GitTreeEntry("federation.json", "100644", "blob", blob_sha)),
            key=lambda entry: entry.path.encode("utf-8"),
        ))
        target_digest = proposal_target_evidence_digest(
            candidate_tree_sha=target_tree,
            changed=({
                "path": "federation.json",
                "state": "PRESENT",
                "mode": "100644",
                "objectType": "blob",
                "blobSha": blob_sha,
                "contentSha256": hashlib.sha256(data).hexdigest(),
            },),
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
            issue_branch_lease_sha256=hashlib.sha256(state.lease.comment.body.encode("utf-8")).hexdigest(),
            binding_id=state.binding.binding_id,
            source_id=state.binding.source_id,
            source_repository_id=state.binding.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=state.issue_anchor.anchor.request_class,
            accepted_base_sha=lease.lease.accepted_base_sha,
            accepted_base_tree_sha=IssueBranchLeaseControllerTests.BASE_TREE,
            from_head_sha=lease.lease.initial_head_sha,
            from_tree_sha=lease.lease.initial_head_tree_sha,
            to_head_sha="0" * 40,
            to_tree_sha=target_tree,
            transition_kind="PROPOSAL",
            carrier_nonce="5" * 64,
            effective_request_digest=effective_request_digest(state.issue_anchor.anchor.initial_request),
            patch_projection_evidence_digest="7" * 64,
            target_evidence_digest=target_digest,
        )
        prepared = IssueHeadClaim.create(**common)
        marker_text = controller_module._issue_head_claim_marker(prepared).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target_sha = controller_module._expected_deterministic_commit_sha(
            target_tree, lease.lease.initial_head_sha, marker_text, timestamp,
        )
        claim = IssueHeadClaim.create(**{**common, "to_head_sha": target_sha})
        client.commit_metadata[target_sha] = GitCommitMetadata(
            target_sha, target_tree, (lease.lease.initial_head_sha,), timestamp,
        )
        client.commit_messages[target_sha] = marker_text
        client.commit_trees[target_sha] = (target_tree, target_entries)
        client.blobs[blob_sha] = data
        client.current_ref = target_sha
        client.pull_requests[state.binding.pull_request_number] = replace(
            client.pull_requests[state.binding.pull_request_number], head_oid=target_sha,
        )
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(claim.render(), database_id=3_001),
        )
        client.authority_reads = []
        client.pr_inventory_reads = 0
        client.issue_metadata_reads = []
        client.pull_request_metadata_reads = []
        client.issue_comment_reads = []
        client.ref_reads = []
        client.generated_ref_reads = []
        return client, issue, anchor_comment, lease, state, claim

    @staticmethod
    def _persist_test_epoch_target(client, sha, parent_sha, tree_sha, marker_text, timestamp=None):
        timestamp = timestamp or IssueBranchLeaseControllerTests.CLAIM_DATE
        parent_tree, entries = client.commit_trees[parent_sha]
        if parent_tree != tree_sha:
            raise AssertionError("epoch target fixture must preserve its parent tree")
        client.commit_metadata[sha] = GitCommitMetadata(sha, tree_sha, (parent_sha,), timestamp)
        client.commit_messages[sha] = marker_text
        client.commit_trees[sha] = (tree_sha, entries)

    @staticmethod
    def _activate_fixture_head(client, state, head_sha):
        client.current_ref = head_sha
        client.pull_requests[state.binding.pull_request_number] = replace(
            client.pull_requests[state.binding.pull_request_number], head_oid=head_sha,
        )

    def make_required_status_epoch_client(self, *, prior_required_status=None, nonce="9" * 64):
        client, issue, anchor_comment, lease, state, claim = self.make_claim_client()
        claim_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        common = dict(
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(state.lease.comment.body.encode("utf-8")).hexdigest(),
            binding_id=state.binding.binding_id,
            source_id=state.binding.source_id,
            source_repository_id=state.binding.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=state.issue_anchor.anchor.request_class,
            accepted_base_sha=claim.accepted_base_sha,
            accepted_base_tree_sha=claim.accepted_base_tree_sha,
            base_ref="main",
            from_head_sha=claim.to_head_sha,
            from_tree_sha=claim.to_tree_sha,
            to_head_sha="0" * 40,
            to_tree_sha=claim.to_tree_sha,
            carrier_nonce=nonce,
            reason_class=RequiredStatusEpochReason.ACTIVE_REVALIDATION,
            from_provenance_kind="ISSUE_HEAD_CLAIM",
            from_provenance_id=claim.claim_id,
            from_provenance_sha256=hashlib.sha256(claim_comment.body.encode("utf-8")).hexdigest(),
            from_carrier_role="ISSUE_ACTIVE",
            prior_required_status=prior_required_status,
        )
        prepared = RequiredStatusEpoch.create(**common)
        marker_text = controller_module._required_status_epoch_marker(prepared).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target_sha = controller_module._expected_deterministic_commit_sha(
            claim.to_tree_sha, claim.to_head_sha, marker_text, timestamp,
        )
        epoch = RequiredStatusEpoch.create(**{**common, "to_head_sha": target_sha})
        self._persist_test_epoch_target(client, target_sha, claim.to_head_sha, claim.to_tree_sha, marker_text)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(epoch.render(), database_id=3_101),
        )
        self._activate_fixture_head(client, state, target_sha)
        client.authority_reads = []
        client.issue_metadata_reads = []
        client.pull_request_metadata_reads = []
        client.issue_comment_reads = []
        client.generated_ref_reads = []
        client.ref_reads = []
        return client, issue, anchor_comment, lease, state, claim, epoch

    def make_finalization_epoch_client(self, *, through_required_status=False):
        if through_required_status:
            client, issue, anchor_comment, lease, state, claim, immediate = self.make_required_status_epoch_client()
            immediate_kind = "REQUIRED_STATUS_EPOCH"
            immediate_comment = next(
                item for item in client.pr_comments[state.binding.pull_request_number]
                if item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
            )
            from_head = immediate.to_head_sha
            from_tree = immediate.to_tree_sha
        else:
            client, issue, anchor_comment, lease, state, claim = self.make_claim_client()
            immediate = claim
            immediate_kind = "ISSUE_HEAD_CLAIM"
            immediate_comment = next(
                item for item in client.pr_comments[state.binding.pull_request_number]
                if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
            )
            from_head = claim.to_head_sha
            from_tree = claim.to_tree_sha
        origin_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        common = dict(
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(state.lease.comment.body.encode("utf-8")).hexdigest(),
            binding_id=state.binding.binding_id,
            source_id=state.binding.source_id,
            source_repository_id=state.binding.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=state.issue_anchor.anchor.request_class,
            accepted_base_sha=claim.accepted_base_sha,
            accepted_base_tree_sha=claim.accepted_base_tree_sha,
            base_ref="main",
            from_head_sha=from_head,
            from_tree_sha=from_tree,
            final_head_sha="0" * 40,
            final_tree_sha=from_tree,
            carrier_nonce="a" * 64,
            from_authority_kind=immediate_kind,
            from_authority_comment_database_id=immediate_comment.database_id,
            from_authority_artifact_id=immediate.epoch_id if through_required_status else immediate.claim_id,
            from_authority_artifact_sha256=hashlib.sha256(immediate_comment.body.encode("utf-8")).hexdigest(),
            from_authority_role="ISSUE_ACTIVE",
            proposal_origin_claim_comment_database_id=origin_comment.database_id,
            proposal_origin_claim_id=claim.claim_id,
            proposal_origin_claim_sha256=hashlib.sha256(origin_comment.body.encode("utf-8")).hexdigest(),
            effective_request_digest=claim.effective_request_digest,
            patch_projection_evidence_digest=claim.patch_projection_evidence_digest,
            claimed_target_evidence_digest=claim.target_evidence_digest,
            fresh_proposal_scope_evidence_digest=claim.target_evidence_digest,
        )
        prepared = IssueFinalizationEpoch.create(**common)
        marker_text = controller_module._issue_finalization_epoch_marker(prepared).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target_sha = controller_module._expected_deterministic_commit_sha(
            from_tree, from_head, marker_text, timestamp,
        )
        epoch = IssueFinalizationEpoch.create(**{**common, "final_head_sha": target_sha})
        self._persist_test_epoch_target(client, target_sha, from_head, from_tree, marker_text)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(epoch.render(), database_id=3_102),
        )
        self._activate_fixture_head(client, state, target_sha)
        client.authority_reads = []
        client.issue_metadata_reads = []
        client.pull_request_metadata_reads = []
        client.issue_comment_reads = []
        client.generated_ref_reads = []
        client.ref_reads = []
        return client, issue, anchor_comment, lease, state, claim, immediate, epoch

    def make_finalization_invalidation_chain(self):
        client, issue, anchor_comment, lease, state, claim, _claim_authority, first_final = self.make_finalization_epoch_client()
        final_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER)
        )
        revoke_fields = dict(
            issue_number=first_final.issue_number,
            issue_database_id=first_final.issue_database_id,
            issue_node_id=first_final.issue_node_id,
            issue_request_anchor_comment_database_id=first_final.issue_request_anchor_comment_database_id,
            issue_request_anchor_sha256=first_final.issue_request_anchor_sha256,
            issue_branch_lease_comment_database_id=first_final.issue_branch_lease_comment_database_id,
            issue_branch_lease_sha256=first_final.issue_branch_lease_sha256,
            binding_id=first_final.binding_id,
            source_id=first_final.source_id,
            source_repository_id=first_final.source_repository_id,
            pull_request_number=first_final.pull_request_number,
            pull_request_database_id=first_final.pull_request_database_id,
            pull_request_node_id=first_final.pull_request_node_id,
            central_repository_node_id=first_final.central_repository_node_id,
            branch_ref=first_final.branch_ref,
            request_class=first_final.request_class,
            accepted_base_sha=first_final.accepted_base_sha,
            accepted_base_tree_sha=first_final.accepted_base_tree_sha,
            base_ref="main",
            from_head_sha=first_final.final_head_sha,
            from_tree_sha=first_final.final_tree_sha,
            to_head_sha="0" * 40,
            to_tree_sha=first_final.final_tree_sha,
            carrier_nonce="b" * 64,
            reason_class=RequiredStatusEpochReason.FINALIZATION_INVALIDATED,
            from_provenance_kind="ISSUE_FINALIZATION_EPOCH",
            from_provenance_id=first_final.epoch_id,
            from_provenance_sha256=hashlib.sha256(final_comment.body.encode("utf-8")).hexdigest(),
            from_carrier_role="ISSUE_FINALIZING",
            prior_required_status=None,
        )
        prepared_revoke = RequiredStatusEpoch.create(**revoke_fields)
        revoke_marker = controller_module._required_status_epoch_marker(prepared_revoke).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        hv = controller_module._expected_deterministic_commit_sha(
            first_final.final_tree_sha, first_final.final_head_sha, revoke_marker, timestamp,
        )
        revoke = RequiredStatusEpoch.create(**{**revoke_fields, "to_head_sha": hv})
        self._persist_test_epoch_target(client, hv, first_final.final_head_sha, first_final.final_tree_sha, revoke_marker)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(revoke.render(), database_id=3_103),
        )
        self._activate_fixture_head(client, state, hv)
        revoke_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
        )
        claim_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        final_fields = dict(
            issue_number=claim.issue_number,
            issue_database_id=claim.issue_database_id,
            issue_node_id=claim.issue_node_id,
            issue_request_anchor_comment_database_id=claim.issue_request_anchor_comment_database_id,
            issue_request_anchor_sha256=claim.issue_request_anchor_sha256,
            issue_branch_lease_comment_database_id=claim.issue_branch_lease_comment_database_id,
            issue_branch_lease_sha256=claim.issue_branch_lease_sha256,
            binding_id=claim.binding_id,
            source_id=claim.source_id,
            source_repository_id=claim.source_repository_id,
            pull_request_number=claim.pull_request_number,
            pull_request_database_id=claim.pull_request_database_id,
            pull_request_node_id=claim.pull_request_node_id,
            central_repository_node_id=claim.central_repository_node_id,
            branch_ref=claim.branch_ref,
            request_class=claim.request_class,
            accepted_base_sha=claim.accepted_base_sha,
            accepted_base_tree_sha=claim.accepted_base_tree_sha,
            base_ref="main",
            from_head_sha=hv,
            from_tree_sha=revoke.to_tree_sha,
            final_head_sha="0" * 40,
            final_tree_sha=revoke.to_tree_sha,
            carrier_nonce="d" * 64,
            from_authority_kind="REQUIRED_STATUS_EPOCH",
            from_authority_comment_database_id=revoke_comment.database_id,
            from_authority_artifact_id=revoke.epoch_id,
            from_authority_artifact_sha256=hashlib.sha256(revoke_comment.body.encode("utf-8")).hexdigest(),
            from_authority_role="ISSUE_ACTIVE",
            proposal_origin_claim_comment_database_id=claim_comment.database_id,
            proposal_origin_claim_id=claim.claim_id,
            proposal_origin_claim_sha256=hashlib.sha256(claim_comment.body.encode("utf-8")).hexdigest(),
            effective_request_digest=claim.effective_request_digest,
            patch_projection_evidence_digest=claim.patch_projection_evidence_digest,
            claimed_target_evidence_digest=claim.target_evidence_digest,
            fresh_proposal_scope_evidence_digest=claim.target_evidence_digest,
        )
        prepared_final = IssueFinalizationEpoch.create(**final_fields)
        final_marker = controller_module._issue_finalization_epoch_marker(prepared_final).render()
        hf2 = controller_module._expected_deterministic_commit_sha(
            revoke.to_tree_sha, hv, final_marker, timestamp,
        )
        final2 = IssueFinalizationEpoch.create(**{**final_fields, "final_head_sha": hf2})
        self._persist_test_epoch_target(client, hf2, hv, revoke.to_tree_sha, final_marker)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(final2.render(), database_id=3_104),
        )
        self._activate_fixture_head(client, state, hf2)
        return client, issue, anchor_comment, lease, state, claim, first_final, revoke, final2

    def make_claim_from_epoch(self, client, state, parent_epoch, base_claim, *, transition="PROPOSAL", nonce="e" * 64):
        common = dict(
            schema_version=1,
            issue_number=base_claim.issue_number,
            issue_database_id=base_claim.issue_database_id,
            issue_node_id=base_claim.issue_node_id,
            issue_request_anchor_comment_database_id=base_claim.issue_request_anchor_comment_database_id,
            issue_request_anchor_sha256=base_claim.issue_request_anchor_sha256,
            issue_branch_lease_comment_database_id=base_claim.issue_branch_lease_comment_database_id,
            issue_branch_lease_sha256=base_claim.issue_branch_lease_sha256,
            binding_id=base_claim.binding_id,
            source_id=base_claim.source_id,
            source_repository_id=base_claim.source_repository_id,
            pull_request_number=base_claim.pull_request_number,
            pull_request_database_id=base_claim.pull_request_database_id,
            pull_request_node_id=base_claim.pull_request_node_id,
            central_repository_node_id=base_claim.central_repository_node_id,
            branch_ref=base_claim.branch_ref,
            request_class=base_claim.request_class,
            accepted_base_sha=base_claim.accepted_base_sha,
            accepted_base_tree_sha=base_claim.accepted_base_tree_sha,
            from_head_sha=parent_epoch.to_head_sha if type(parent_epoch) is RequiredStatusEpoch else parent_epoch.final_head_sha,
            from_tree_sha=parent_epoch.to_tree_sha if type(parent_epoch) is RequiredStatusEpoch else parent_epoch.final_tree_sha,
            to_head_sha="0" * 40,
            to_tree_sha=base_claim.to_tree_sha,
            transition_kind=transition,
            carrier_nonce=nonce,
            effective_request_digest=base_claim.effective_request_digest,
            patch_projection_evidence_digest=base_claim.patch_projection_evidence_digest,
            target_evidence_digest=base_claim.target_evidence_digest,
        )
        prepared = IssueHeadClaim.create(**common)
        marker_text = controller_module._issue_head_claim_marker(prepared).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target_sha = controller_module._expected_deterministic_commit_sha(
            prepared.to_tree_sha, prepared.from_head_sha, marker_text, timestamp,
        )
        claim = IssueHeadClaim.create(**{**common, "to_head_sha": target_sha})
        self._persist_test_epoch_target(client, target_sha, prepared.from_head_sha, prepared.to_tree_sha, marker_text)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(claim.render(), database_id=3_105),
        )
        return claim

    def make_normalize_origin_finalization_client(self):
        issue, anchor_comment = IssueBranchLeaseControllerTests.setup_anchor()
        client = self.CarrierClient(issue, anchor_comment)
        lease = IssueBranchLeaseControllerTests().create(client, anchor_comment, nonce_factory=lambda: "c" * 64)
        client.binding_anchor = anchor_comment
        client.binding_lease = lease
        client.current_ref = lease.lease.initial_head_sha
        binder = IssuePRBindingControllerTests()
        state = binder.run_binding(client)
        marker_content = (state.issue_anchor.anchor.request_class.value + "\n").encode("utf-8")
        marker_blob_sha = hashlib.sha1(
            b"blob " + str(len(marker_content)).encode("ascii") + b"\0" + marker_content,
        ).hexdigest()
        normalize_target = normalize_target_evidence_digest(
            request_class=state.issue_anchor.anchor.request_class,
            request_marker_blob_sha=marker_blob_sha,
            target_tree_sha=lease.lease.initial_head_tree_sha,
        )
        claim_fields = dict(
            schema_version=1,
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(state.lease.comment.body.encode("utf-8")).hexdigest(),
            binding_id=state.binding.binding_id,
            source_id=state.binding.source_id,
            source_repository_id=state.binding.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=state.issue_anchor.anchor.request_class,
            accepted_base_sha=lease.lease.accepted_base_sha,
            accepted_base_tree_sha=IssueBranchLeaseControllerTests.BASE_TREE,
            from_head_sha=lease.lease.initial_head_sha,
            from_tree_sha=lease.lease.initial_head_tree_sha,
            to_head_sha="0" * 40,
            to_tree_sha=lease.lease.initial_head_tree_sha,
            transition_kind="NORMALIZE",
            carrier_nonce="d" * 64,
            effective_request_digest=effective_request_digest(state.issue_anchor.anchor.initial_request),
            patch_projection_evidence_digest="7" * 64,
            target_evidence_digest=normalize_target,
        )
        prepared = IssueHeadClaim.create(**claim_fields)
        marker_text = controller_module._issue_head_claim_marker(prepared).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target_sha = controller_module._expected_deterministic_commit_sha(
            prepared.to_tree_sha, prepared.from_head_sha, marker_text, timestamp,
        )
        normalize_claim = IssueHeadClaim.create(**{**claim_fields, "to_head_sha": target_sha})
        self._persist_test_epoch_target(
            client, target_sha, lease.lease.initial_head_sha,
            lease.lease.initial_head_tree_sha, marker_text,
        )
        client.blobs[marker_blob_sha] = marker_content
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(normalize_claim.render(), database_id=3_107),
        )
        # Persist a finalization artifact that is structurally exact but whose
        # only IssueHeadClaim origin is normalization-only.
        common = dict(
            issue_number=normalize_claim.issue_number,
            issue_database_id=normalize_claim.issue_database_id,
            issue_node_id=normalize_claim.issue_node_id,
            issue_request_anchor_comment_database_id=normalize_claim.issue_request_anchor_comment_database_id,
            issue_request_anchor_sha256=normalize_claim.issue_request_anchor_sha256,
            issue_branch_lease_comment_database_id=normalize_claim.issue_branch_lease_comment_database_id,
            issue_branch_lease_sha256=normalize_claim.issue_branch_lease_sha256,
            binding_id=normalize_claim.binding_id,
            source_id=normalize_claim.source_id,
            source_repository_id=normalize_claim.source_repository_id,
            pull_request_number=normalize_claim.pull_request_number,
            pull_request_database_id=normalize_claim.pull_request_database_id,
            pull_request_node_id=normalize_claim.pull_request_node_id,
            central_repository_node_id=normalize_claim.central_repository_node_id,
            branch_ref=normalize_claim.branch_ref,
            request_class=normalize_claim.request_class,
            accepted_base_sha=normalize_claim.accepted_base_sha,
            accepted_base_tree_sha=normalize_claim.accepted_base_tree_sha,
            base_ref="main",
            from_head_sha=normalize_claim.to_head_sha,
            from_tree_sha=normalize_claim.to_tree_sha,
            final_head_sha="0" * 40,
            final_tree_sha=normalize_claim.to_tree_sha,
            carrier_nonce="f" * 64,
            from_authority_kind="ISSUE_HEAD_CLAIM",
            from_authority_comment_database_id=3_107,
            from_authority_artifact_id=normalize_claim.claim_id,
            from_authority_artifact_sha256=hashlib.sha256(normalize_claim.render().encode("utf-8")).hexdigest(),
            from_authority_role="ISSUE_ACTIVE",
            proposal_origin_claim_comment_database_id=3_107,
            proposal_origin_claim_id=normalize_claim.claim_id,
            proposal_origin_claim_sha256=hashlib.sha256(normalize_claim.render().encode("utf-8")).hexdigest(),
            effective_request_digest=normalize_claim.effective_request_digest,
            patch_projection_evidence_digest=normalize_claim.patch_projection_evidence_digest,
            claimed_target_evidence_digest=normalize_claim.target_evidence_digest,
            fresh_proposal_scope_evidence_digest=normalize_claim.target_evidence_digest,
        )
        prepared_final = IssueFinalizationEpoch.create(**common)
        final_marker = controller_module._issue_finalization_epoch_marker(prepared_final).render()
        final_sha = controller_module._expected_deterministic_commit_sha(
            normalize_claim.to_tree_sha, normalize_claim.to_head_sha, final_marker, timestamp,
        )
        final_epoch = IssueFinalizationEpoch.create(**{**common, "final_head_sha": final_sha})
        self._persist_test_epoch_target(client, final_sha, normalize_claim.to_head_sha, normalize_claim.to_tree_sha, final_marker)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(final_epoch.render(), database_id=3_108),
        )
        self._activate_fixture_head(client, state, final_sha)
        return client, state, normalize_claim, final_epoch

    def append_finalization_variant(self, client, state, fields, *, comment_id, timestamp=None):
        for key in (
            "claim_generation_id", "authority_preimage_digest", "finalizer_evidence_digest",
            "required_status_context", "required_status_class", "required_status_state",
            "required_status_target_url", "required_status_evidence_digest",
            "required_status_description", "marker_digest", "epoch_id",
        ):
            fields.pop(key, None)
        fields["final_head_sha"] = "0" * 40
        prepared = IssueFinalizationEpoch.create(**fields)
        marker_text = controller_module._issue_finalization_epoch_marker(prepared).render()
        commit_time = timestamp or IssueBranchLeaseControllerTests.CLAIM_DATE
        head_sha = controller_module._expected_deterministic_commit_sha(
            prepared.final_tree_sha, prepared.from_head_sha, marker_text, commit_time,
        )
        epoch = IssueFinalizationEpoch.create(**{**fields, "final_head_sha": head_sha})
        self._persist_test_epoch_target(
            client, head_sha, epoch.from_head_sha, epoch.final_tree_sha, marker_text, commit_time,
        )
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(epoch.render(), database_id=comment_id),
        )
        return epoch

    @staticmethod
    def commit_message_client(sha, message):
        class MarkerClient:
            def __init__(self):
                self.reads = []

            def get_git_commit_object(self, repository, requested_sha):
                self.reads.append((repository, requested_sha))
                identity = GitCommitIdentity("Author", "author@example.test", "2026-10-05T00:00:00Z")
                return GitCommitObject(requested_sha, message, "b" * 40, (), identity, identity)

        return MarkerClient()

    @staticmethod
    def marker(**changes):
        fields = dict(
            claim_kind="ISSUE_BRANCH_LEASE",
            role="ISSUE_ACTIVE",
            owner_kind="ISSUE",
            owner_key="R_central:700:I_issue:7",
            claim_generation_id="1" * 64,
            carrier_nonce="2" * 64,
            transition_kind="INITIAL",
        )
        fields.update(changes)
        return ClaimedHeadMarker(**fields)

    def test_active_and_historical_issue_branch_lease_use_real_provenance_path(self):
        client, _issue, _anchor_comment, lease = self.make_client()
        client.authority_reads = []
        legacy_reads = []
        self.assertEqual(
            self.resolve(client, lease.lease.initial_head_sha,
                         lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT),
            ShaCarrierResolution(CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE,
                                 controller_module._lease_marker_for(lease.lease)),
        )
        self.assertEqual(legacy_reads, [])
        self.assertEqual(client.commit_object_reads[0], (self.CENTRAL, lease.lease.initial_head_sha))
        self.assertEqual(client.authority_reads[0], "commit")
        self.assertEqual(client.pr_inventory_reads, 0)

        client.current_ref = "f" * 40
        historical = self.resolve(client, lease.lease.initial_head_sha,
                                  lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(historical.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(historical.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(legacy_reads, [])

    def test_active_and_historical_issue_head_claim_use_real_production_validators(self):
        client, _issue, _anchor_comment, _lease, state, claim = self.make_claim_client()
        client.pr_inventory_reads = 0
        legacy_reads = []
        active = self.resolve(
            client, claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(active.activation, CarrierActivation.ACTIVE)
        self.assertEqual(active.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(active.marker, controller_module._issue_head_claim_marker(claim))
        self.assertEqual(client.authority_reads[0], "commit")
        self.assertEqual(legacy_reads, [])
        self.assertEqual(client.pr_inventory_reads, 0)

        # An unrelated PR topology that mentions H cannot alter the exact bound claim.
        client.pull_requests[82] = replace(client.pull_requests[state.binding.pull_request_number], number=82)
        same_head = self.resolve(client, claim.to_head_sha, LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(same_head, active)
        client.current_ref = claim.from_head_sha
        reserved = self.resolve(client, claim.to_head_sha, LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(reserved.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(reserved.role, CarrierRole.ISSUE_ACTIVE)

    def test_race1_owning_issue_closes_after_exact_claim_provenance(self):
        client, issue, _anchor, _lease, _state, claim = self.make_claim_client()
        client.issue_metadata_sequences[issue.number] = [
            issue,
            issue,
            replace(issue, state="closed"),
        ]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        owning_issue_reads = [
            state for number, state in client.issue_metadata_reads if number == issue.number
        ]
        self.assertEqual(owning_issue_reads, ["open", "open", "closed"])
        self.assertEqual(client.issue_metadata_sequences[issue.number], [])
        self.assertEqual(
            result,
            ShaCarrierResolution(
                CarrierActivation.RESERVED_INACTIVE,
                CarrierRole.ISSUE_ACTIVE,
                controller_module._issue_head_claim_marker(claim),
            ),
        )
        self.assertNotEqual(result.activation, CarrierActivation.ACTIVE)
        self.assertEqual(legacy_reads, [])

    def test_race2_bound_pr_closes_before_final_activation_read(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        pr_number = state.binding.pull_request_number
        open_pr_issue = client.pull_request_issues[pr_number]
        client.issue_metadata_sequences[pr_number] = [
            open_pr_issue,
            replace(open_pr_issue, state="closed"),
        ]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        pr_lifecycle_reads = [
            lifecycle for number, lifecycle in client.issue_metadata_reads if number == pr_number
        ]
        self.assertEqual(pr_lifecycle_reads, ["open", "closed"])
        self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(result.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(legacy_reads, [])

    def test_race3_bound_pr_head_moves_before_final_activation_read(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        pr_number = state.binding.pull_request_number
        initial_pr = client.pull_requests[pr_number]
        moved_pr = replace(initial_pr, head_oid="f" * 40)
        client.pull_request_metadata_sequences[pr_number] = [initial_pr, moved_pr]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        self.assertEqual(
            [head for number, head in client.pull_request_metadata_reads if number == pr_number],
            [claim.to_head_sha, "f" * 40],
        )
        self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(result.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(legacy_reads, [])

    def test_race4_generated_ref_moves_before_final_activation_read(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        branch = state.lease.lease.branch_ref.removeprefix("refs/heads/")
        client.generated_ref_sequence = [claim.to_head_sha, claim.from_head_sha]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        self.assertEqual(client.ref_reads, [branch, branch])
        self.assertEqual(
            client.generated_ref_reads,
            [(branch, claim.to_head_sha), (branch, claim.from_head_sha)],
        )
        self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(result.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(legacy_reads, [])

    def test_race5_immutable_binding_drift_is_conflicting(self):
        client, issue, _anchor, _lease, state, claim = self.make_claim_client()
        original_comments = tuple(client.comments)
        drifted_comments = list(original_comments)
        binding_index = next(
            index for index, item in enumerate(drifted_comments)
            if item.body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER)
        )
        changed_binding_fields = {
            name: value for name, value in state.binding.__dict__.items()
            if name != "binding_id"
        }
        changed_binding_fields["pull_request_number"] += 1
        changed_binding = IssuePRBinding.create(**changed_binding_fields)
        drifted_comments[binding_index] = replace(
            drifted_comments[binding_index],
            body=changed_binding.render_issue_binding(),
        )
        client.issue_comment_sequences[issue.number] = [
            original_comments,
            original_comments,
            tuple(drifted_comments),
        ]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        self.assertEqual(
            [count for number, count in client.issue_comment_reads if number == issue.number],
            [len(original_comments), len(original_comments), len(drifted_comments)],
        )
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(legacy_reads, [])

    def test_race6_final_activation_ref_failure_is_conflicting(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        branch = state.lease.lease.branch_ref.removeprefix("refs/heads/")
        client.generated_ref_sequence = [claim.to_head_sha, RuntimeError("final ref unavailable")]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        self.assertEqual(client.ref_reads, [branch, branch])
        self.assertEqual(
            client.generated_ref_reads,
            [(branch, claim.to_head_sha), (branch, "ERROR")],
        )
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(legacy_reads, [])

    def test_race7_stable_exact_post_provenance_state_remains_active(self):
        client, issue, _anchor, _lease, state, claim = self.make_claim_client()
        pr_number = state.binding.pull_request_number
        client.issue_metadata_sequences[issue.number] = [issue, issue, issue]
        client.issue_metadata_sequences[pr_number] = [
            client.pull_request_issues[pr_number],
            client.pull_request_issues[pr_number],
        ]
        current_pr = client.pull_requests[pr_number]
        client.pull_request_metadata_sequences[pr_number] = [current_pr, current_pr]
        client.generated_ref_sequence = [claim.to_head_sha, claim.to_head_sha]
        legacy_reads = []
        result = self.resolve(
            client,
            claim.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )

        self.assertEqual(
            [lifecycle for number, lifecycle in client.issue_metadata_reads if number == issue.number],
            ["open", "open", "open"],
        )
        self.assertEqual(
            [lifecycle for number, lifecycle in client.issue_metadata_reads if number == pr_number],
            ["open", "open"],
        )
        self.assertEqual(
            [head for number, head in client.pull_request_metadata_reads if number == pr_number],
            [claim.to_head_sha, claim.to_head_sha],
        )
        self.assertEqual(
            client.generated_ref_reads,
            [(state.lease.lease.branch_ref.removeprefix("refs/heads/"), claim.to_head_sha)] * 2,
        )
        self.assertEqual(result.activation, CarrierActivation.ACTIVE)
        self.assertEqual(result.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(legacy_reads, [])

    def test_race8_correction_01_static_historical_cases_remain_reserved(self):
        scenarios = (
            "issue-closed",
            "pr-closed",
            "issue-and-pr-closed",
            "issue-closed-ref-moved",
            "pr-closed-head-moved",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                client, issue, _anchor, _lease, state, claim = self.make_claim_client()
                if scenario in {"issue-closed", "issue-and-pr-closed", "issue-closed-ref-moved"}:
                    client.issue = replace(issue, state="closed")
                if scenario in {"pr-closed", "issue-and-pr-closed", "pr-closed-head-moved"}:
                    client.pull_request_issues[state.binding.pull_request_number] = replace(
                        client.pull_request_issues[state.binding.pull_request_number],
                        state="closed",
                    )
                if scenario == "issue-closed-ref-moved":
                    client.current_ref = claim.from_head_sha
                if scenario == "pr-closed-head-moved":
                    client.pull_requests[state.binding.pull_request_number] = replace(
                        client.pull_requests[state.binding.pull_request_number],
                        head_oid="f" * 40,
                    )

                legacy_reads = []
                result = self.resolve(
                    client,
                    claim.to_head_sha,
                    lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
                )
                self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
                self.assertEqual(result.role, CarrierRole.ISSUE_ACTIVE)
                self.assertEqual(result.marker, controller_module._issue_head_claim_marker(claim))
                self.assertNotEqual(result.activation, CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
                self.assertEqual(legacy_reads, [])

    def test_race8_broken_claim_provenance_remains_conflicting(self):
        for corruption in ("missing", "edited"):
            with self.subTest(corruption=corruption):
                client, issue, _anchor, _lease, state, claim = self.make_claim_client()
                client.issue = replace(issue, state="closed")
                client.pull_request_issues[state.binding.pull_request_number] = replace(
                    client.pull_request_issues[state.binding.pull_request_number],
                    state="closed",
                )
                comments = client.pr_comments[state.binding.pull_request_number]
                if corruption == "missing":
                    client.pr_comments[state.binding.pull_request_number] = [
                        item for item in comments
                        if not item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
                    ]
                else:
                    client.pr_comments[state.binding.pull_request_number] = [
                        replace(item, editor_id=self.APP.bot_node_id)
                        if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER) else item
                        for item in comments
                    ]

                legacy_reads = []
                result = self.resolve(
                    client,
                    claim.to_head_sha,
                    lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
                )
                self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
                self.assertEqual(legacy_reads, [])

    def test_race9_managed_issue_pr_binding_default_still_requires_open_lifecycle(self):
        client, issue, _anchor, _lease, state, _claim = self.make_claim_client()
        client.issue = replace(issue, state="closed")
        with self.assertRaises(R02Error):
            controller_module._read_managed_issue_pr_binding_state(
                client,
                self.CENTRAL,
                issue.number,
                self.APP,
                self.CENTRAL_NODE_ID,
                lambda _request, _request_class: None,
                validate_fresh_source_authority=False,
            )

        client, _issue, _anchor, _lease, state, _claim = self.make_claim_client()
        client.pull_request_issues[state.binding.pull_request_number] = replace(
            client.pull_request_issues[state.binding.pull_request_number],
            state="closed",
        )
        with self.assertRaises(R02Error):
            controller_module._read_managed_issue_pr_binding_state(
                client,
                self.CENTRAL,
                state.issue_anchor.anchor.issue_number,
                self.APP,
                self.CENTRAL_NODE_ID,
                lambda _request, _request_class: None,
                validate_fresh_source_authority=False,
            )

    def test_race10_false_lifecycle_override_is_resolver_only(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        module_ast = ast.parse(source)

        class FalseLifecycleCallCollector(ast.NodeVisitor):
            def __init__(self):
                self.functions = []
                self.call_owners = []

            def visit_FunctionDef(self, node):
                self.functions.append(node.name)
                self.generic_visit(node)
                self.functions.pop()

            visit_AsyncFunctionDef = visit_FunctionDef

            def visit_Call(self, node):
                if any(
                    keyword.arg == "require_open_lifecycle"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                    for keyword in node.keywords
                ):
                    self.call_owners.append(self.functions[-1] if self.functions else None)
                self.generic_visit(node)

        collector = FalseLifecycleCallCollector()
        collector.visit(module_ast)
        self.assertEqual(len(collector.call_owners), 3)
        self.assertEqual(set(collector.call_owners), {"resolve_sha_carrier_role", "derive_issue_owner_pr"})

    def test_reserved_namespace_versions_and_malformed_markers_never_consult_legacy(self):
        valid = self.marker().render()
        unknown_messages = (
            "swiftstream-federation-head:v0\n",
            "swiftstream-federation-head:v1\n",
            "swiftstream-federation-head:v3\n",
            "swiftstream-federation-head:v999\n",
            "swiftstream-federation-head:future\n",
            "swiftstream-federation-head:\n",
            "swiftstream-federation-head:v2x\n",
            "swiftstream-federation-head:v2\n" + valid,
            valid.replace("claim-kind=ISSUE_BRANCH_LEASE", "claim-kind=FUTURE"),
            valid.replace("role=ISSUE_ACTIVE", "role=FUTURE"),
            valid.replace("role=ISSUE_ACTIVE\n", "owner-kind=ISSUE\nrole=ISSUE_ACTIVE\n"),
        )
        for message in unknown_messages:
            with self.subTest(message=message[:48]):
                client = self.commit_message_client("a" * 40, message)
                legacy_reads = []
                result = self.resolve(
                    client, "a" * 40,
                    lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
                )
                self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
                self.assertEqual(legacy_reads, [])
                self.assertEqual(client.reads, [(self.CENTRAL, "a" * 40)])

    def test_copied_v2_marker_and_missing_or_edited_issue_provenance_conflict(self):
        client, issue, anchor_comment, lease = self.make_client()
        head_sha = lease.lease.initial_head_sha
        legacy_reads = []

        missing_lease = list(client.comments)
        missing_lease.pop()
        client.comments = missing_lease
        copied = self.resolve(
            client, head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(copied.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(legacy_reads, [])

        client, _issue, anchor_comment, lease = self.make_client()
        client.comments = [lease.comment]
        missing_anchor = self.resolve(client, lease.lease.initial_head_sha)
        self.assertEqual(missing_anchor.activation, CarrierActivation.CONFLICTING)

        client, _issue, anchor_comment, lease = self.make_client()
        client.comments[0] = replace(client.comments[0], editor_id=self.APP.bot_node_id)
        edited_anchor = self.resolve(client, lease.lease.initial_head_sha)
        self.assertEqual(edited_anchor.activation, CarrierActivation.CONFLICTING)

        client, _issue, anchor_comment, lease = self.make_client()
        client.comments[-1] = replace(client.comments[-1], editor_id=self.APP.bot_node_id)
        edited_lease = self.resolve(client, lease.lease.initial_head_sha)
        self.assertEqual(edited_lease.activation, CarrierActivation.CONFLICTING)

    def test_conflicting_duplicate_lease_provenance_fails_real_history_validation(self):
        first, _issue, anchor_comment, first_lease = self.make_client("c" * 64)
        second, _issue2, _anchor2, second_lease = self.make_client("d" * 64)
        second_head = second_lease.lease.initial_head_sha
        first.commit_metadata[second_head] = second.commit_metadata[second_head]
        first.commit_messages[second_head] = second.commit_messages[second_head]
        first.commit_trees[second_head] = second.commit_trees[second_head]
        first.comments.append(replace(second_lease.comment, database_id=999))
        result = self.resolve(first, first_lease.lease.initial_head_sha)
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)

    def test_missing_and_edited_head_claim_comments_fail_through_real_validators(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        comments = client.pr_comments[state.binding.pull_request_number]
        client.pr_comments[state.binding.pull_request_number] = [
            item for item in comments if not item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        ]
        missing = self.resolve(client, claim.to_head_sha)
        self.assertEqual(missing.activation, CarrierActivation.CONFLICTING)

        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        comments = client.pr_comments[state.binding.pull_request_number]
        client.pr_comments[state.binding.pull_request_number] = [
            replace(item, editor_id=self.APP.bot_node_id)
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER) else item
            for item in comments
        ]
        edited = self.resolve(client, claim.to_head_sha)
        self.assertEqual(edited.activation, CarrierActivation.CONFLICTING)

    def test_future_reserved_claim_kinds_fail_closed_and_legacy_dispositions_are_explicit(self):
        legacy_reads = []
        for claim_kind, role in (
            ("REQUIRED_STATUS_EPOCH", "ISSUE_FINALIZING"),
            ("ISSUE_FINALIZATION_EPOCH", "ISSUE_FINALIZING"),
            ("ISSUE_CANCELLATION_FENCE", "ISSUE_CANCEL"),
            ("MACHINE_REF_CLAIM", "MACHINE_PUBLICATION"),
        ):
            marker = self.marker(claim_kind=claim_kind, role=role).render()
            client = self.commit_message_client("a" * 40, marker)
            result = self.resolve(
                client, "a" * 40,
                lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
            )
            self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(legacy_reads, [])

        client = self.commit_message_client("a" * 40, "ordinary commit\n")
        for disposition, expected in (
            (LegacyEvidenceDisposition.QUARANTINE, CarrierActivation.LEGACY_CUTOVER_QUARANTINE),
            (LegacyEvidenceDisposition.CONFLICTING, CarrierActivation.CONFLICTING),
            (LegacyEvidenceDisposition.ABSENT, CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION),
        ):
            with self.subTest(disposition=disposition):
                self.assertEqual(self.resolve(client, "a" * 40, disposition).activation, expected)

        callback_client = self.commit_message_client("a" * 40, "no reserved family\n")
        reads = []
        result = self.resolve(
            callback_client, "a" * 40,
            lambda: reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(result.activation, CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
        self.assertEqual(reads, ["called"])
        with self.assertRaises(TypeError):
            resolve_sha_carrier_role(callback_client, self.CENTRAL, "a" * 40, self.APP.slug)
        with self.assertRaises(R02Error):
            self.resolve(callback_client, "a" * 40, None)

    def test_external_writer_emits_only_exact_201_pr_independent_tuple(self):
        sha = "a" * 40
        repo = RepositoryMetadata(22, self.CENTRAL_NODE_ID, self.CENTRAL, "main")
        unclaimed = ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
        digest = external_status_evidence_digest(repo.id, repo.node_id, repo.full_name, sha)
        description = render_status_description(StatusClass.EXTERNAL, digest)
        route = f"/repos/{self.CENTRAL}/statuses/{sha}"

        def payload(status_id=1, *, creator=None):
            return {
                "id": status_id,
                "node_id": f"STATUS_{status_id}",
                "state": "success",
                "context": "federation/trusted-validation",
                "description": description,
                "target_url": None,
                "creator": creator or {
                    "id": self.APP.bot_id,
                    "node_id": self.APP.bot_node_id,
                    "login": self.APP.bot_login,
                    "type": "Bot",
                },
                "created_at": "2026-10-05T12:00:00Z",
                "updated_at": "2026-10-05T12:00:01Z",
            }

        class StatusTransport:
            def __init__(inner_self, codes=(201,), values=None):
                inner_self.codes = list(codes)
                inner_self.values = list(values or [payload(index + 1) for index in range(len(codes))])
                inner_self.calls = []

            def request(inner_self, method, url, headers, body, timeout):
                inner_self.calls.append((method, url, body))
                code = inner_self.codes.pop(0)
                value = inner_self.values.pop(0)
                return HttpResponse(code, url, json.dumps(value).encode("utf-8"))

        transport = StatusTransport(codes=(201, 201), values=(payload(1), payload(2)))
        client = GitHubClient(None, transport)
        first = publish_unclaimed_external_success(client, repo, sha, unclaimed, self.APP)
        second = publish_unclaimed_external_success(client, repo, sha, unclaimed, self.APP)
        self.assertEqual(first.requested_description, description)
        self.assertEqual(first.requested_target_url, None)
        self.assertEqual(first.returned_status.creator_type, "Bot")
        self.assertEqual(len(transport.calls), 2)
        self.assertEqual([call[0:2] for call in transport.calls], [
            ("POST", REST_BASE_URL + route), ("POST", REST_BASE_URL + route),
        ])
        self.assertEqual(json.loads(transport.calls[0][2]), json.loads(transport.calls[1][2]))
        self.assertEqual(first.requested_context, second.requested_context)
        self.assertEqual(first.requested_description, second.requested_description)
        self.assertTrue(all(set(json.loads(call[2])) == {"state", "context", "description", "target_url"} for call in transport.calls))

        for activation in (
            CarrierActivation.ACTIVE,
            CarrierActivation.RESERVED_INACTIVE,
            CarrierActivation.LEGACY_CUTOVER_QUARANTINE,
            CarrierActivation.CONFLICTING,
        ):
            resolution = ShaCarrierResolution(
                activation,
                CarrierRole.ISSUE_ACTIVE if activation in {CarrierActivation.ACTIVE, CarrierActivation.RESERVED_INACTIVE} else None,
            )
            with self.subTest(activation=activation), self.assertRaises(R02Error):
                publish_unclaimed_external_success(client, repo, sha, resolution, self.APP)

    def test_external_writer_rejects_creator_receipt_mismatch_and_non_201_without_reads(self):
        sha = "a" * 40
        repo = RepositoryMetadata(22, self.CENTRAL_NODE_ID, self.CENTRAL, "main")
        resolution = ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
        description = render_status_description(
            StatusClass.EXTERNAL,
            external_status_evidence_digest(repo.id, repo.node_id, repo.full_name, sha),
        )
        route = f"/repos/{self.CENTRAL}/statuses/{sha}"
        payload = {
            "id": 1, "node_id": "S_1", "state": "success",
            "context": "federation/trusted-validation", "description": description,
            "target_url": None,
            "creator": {"id": 99, "node_id": "other", "login": "other[bot]", "type": "Bot"},
            "created_at": "2026-10-05T12:00:00Z", "updated_at": "2026-10-05T12:00:01Z",
        }

        class OneResponse:
            def __init__(inner_self, response):
                inner_self.response = response
                inner_self.calls = []

            def request(inner_self, method, url, headers, body, timeout):
                inner_self.calls.append((method, url, body))
                return HttpResponse(inner_self.response, url, json.dumps(payload).encode())

        for code in (200, 202, 204):
            transport = OneResponse(code)
            with self.subTest(status=code), self.assertRaises(UnexpectedStatusError):
                publish_unclaimed_external_success(GitHubClient(None, transport), repo, sha, resolution, self.APP)
            self.assertEqual(len(transport.calls), 1)
            self.assertEqual(transport.calls[0][0], "POST")

        rejected = OneResponse(422)
        with self.assertRaises(UnprocessableError):
            publish_unclaimed_external_success(GitHubClient(None, rejected), repo, sha, resolution, self.APP)
        self.assertEqual(len(rejected.calls), 1)

        transport = OneResponse(201)
        with self.assertRaises(R02Error):
            publish_unclaimed_external_success(GitHubClient(None, transport), repo, sha, resolution, self.APP)
        self.assertEqual(len(transport.calls), 1)

        valid_status = CommitStatus(
            1, "S_1", "success", "federation/trusted-validation", description, None,
            self.APP.bot_id, self.APP.bot_node_id, self.APP.bot_login, "Bot",
            "2026-10-05T12:00:00Z", "2026-10-05T12:00:01Z",
        )
        wrong_repo_receipt = StatusWriteReceipt(
            "other/repository", sha, "POST", f"/repos/other/repository/statuses/{sha}",
            "success", "federation/trusted-validation", description, None, valid_status,
        )
        wrong_sha = "b" * 40
        wrong_sha_receipt = StatusWriteReceipt(
            self.CENTRAL, wrong_sha, "POST", f"/repos/{self.CENTRAL}/statuses/{wrong_sha}",
            "success", "federation/trusted-validation", description, None, valid_status,
        )

        class WrongReceiptClient:
            def __init__(inner_self, receipt):
                inner_self.receipt = receipt
                inner_self.calls = []

            def create_commit_status(inner_self, *args):
                inner_self.calls.append(args)
                return inner_self.receipt

        for wrong_receipt in (wrong_repo_receipt, wrong_sha_receipt):
            fake = WrongReceiptClient(wrong_receipt)
            with self.subTest(receipt=wrong_receipt), self.assertRaises(R02Error):
                publish_unclaimed_external_success(fake, repo, sha, resolution, self.APP)
            self.assertEqual(len(fake.calls), 1)

        class FailedTransport:
            def __init__(inner_self):
                inner_self.calls = []

            def request(inner_self, method, url, headers, body, timeout):
                inner_self.calls.append((method, url, body))
                raise TransportError("ambiguous write")

        failed = FailedTransport()
        with self.assertRaises(TransportError):
            publish_unclaimed_external_success(GitHubClient(None, failed), repo, sha, resolution, self.APP)
        self.assertEqual(len(failed.calls), 1)
        self.assertEqual(failed.calls[0][0], "POST")

    def test_required_status_epoch_active_and_moved_ref_use_real_provenance_graph(self):
        client, _issue, _anchor, _lease, state, _claim, epoch = self.make_required_status_epoch_client()
        legacy_reads = []
        active = self.resolve(
            client, epoch.to_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(active, ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE,
            controller_module._required_status_epoch_marker(epoch),
        ))
        self.assertEqual(legacy_reads, [])
        client.current_ref = epoch.from_head_sha
        reserved = self.resolve(client, epoch.to_head_sha, LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(reserved.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(reserved.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(client.pr_inventory_reads, 0)

    def test_required_status_epoch_post_provenance_lifecycle_head_and_ref_drift_are_reserved(self):
        scenarios = ("ref-moved", "pr-head-moved", "issue-closed", "pr-closed")
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                client, issue, _anchor, _lease, state, _claim, epoch = self.make_required_status_epoch_client()
                branch = state.binding.branch_ref.removeprefix("refs/heads/")
                if scenario == "ref-moved":
                    client.current_ref = epoch.from_head_sha
                elif scenario == "pr-head-moved":
                    client.pull_requests[state.binding.pull_request_number] = replace(
                        client.pull_requests[state.binding.pull_request_number], head_oid=epoch.from_head_sha,
                    )
                elif scenario == "issue-closed":
                    client.issue = replace(issue, state="closed")
                else:
                    pr_number = state.binding.pull_request_number
                    client.pull_request_issues[pr_number] = replace(
                        client.pull_request_issues[pr_number], state="closed",
                    )
                result = self.resolve(client, epoch.to_head_sha, LegacyEvidenceDisposition.ABSENT)
                self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
                self.assertEqual(result.role, CarrierRole.ISSUE_ACTIVE)
                self.assertEqual(result.marker, controller_module._required_status_epoch_marker(epoch))
                self.assertEqual(client.ref_reads, [branch, branch])

    def test_required_status_epoch_missing_wrong_app_edited_and_conflicting_comments_fail_closed(self):
        for corruption in ("missing", "wrong-app", "edited"):
            with self.subTest(corruption=corruption):
                client, _issue, _anchor, _lease, state, _claim, epoch = self.make_required_status_epoch_client()
                comments = list(client.pr_comments[state.binding.pull_request_number])
                if corruption == "missing":
                    comments = [item for item in comments if not item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)]
                else:
                    comments = [
                        replace(item, author_id="wrong") if corruption == "wrong-app" and item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
                        else replace(item, editor_id=self.APP.bot_node_id) if corruption == "edited" and item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
                        else item
                        for item in comments
                    ]
                client.pr_comments[state.binding.pull_request_number] = comments
                legacy_reads = []
                result = self.resolve(
                    client, epoch.to_head_sha,
                    lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
                )
                self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
                self.assertEqual(legacy_reads, [])

    def test_required_status_epoch_conflicting_duplicate_and_target_corruption_block(self):
        client, _issue, _anchor, _lease, state, claim, epoch = self.make_required_status_epoch_client()
        fields = epoch._fields()
        for name in ("claim_generation_id", "authority_preimage_digest", "marker_digest", "epoch_id"):
            fields.pop(name)
        alternate_time = "2026-10-05T00:00:01Z"
        prepared = RequiredStatusEpoch.create(**{**fields, "to_head_sha": "0" * 40})
        marker_text = controller_module._required_status_epoch_marker(prepared).render()
        alternate_sha = controller_module._expected_deterministic_commit_sha(
            epoch.to_tree_sha, epoch.from_head_sha, marker_text, alternate_time,
        )
        duplicate = RequiredStatusEpoch.create(**{**fields, "to_head_sha": alternate_sha})
        client.commit_metadata[alternate_sha] = GitCommitMetadata(
            alternate_sha, epoch.to_tree_sha, (epoch.from_head_sha,), alternate_time,
        )
        parent_tree, entries = client.commit_trees[epoch.from_head_sha]
        self.assertEqual(parent_tree, epoch.to_tree_sha)
        client.commit_messages[alternate_sha] = marker_text
        client.commit_trees[alternate_sha] = (epoch.to_tree_sha, entries)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(duplicate.render(), database_id=3_106),
        )
        result = self.resolve(client, epoch.to_head_sha, LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)

        for corruption in ("parent", "tree", "marker"):
            with self.subTest(corruption=corruption):
                fresh, _issue, _anchor, _lease, _state, _claim, fresh_epoch = self.make_required_status_epoch_client()
                sha = fresh_epoch.to_head_sha
                metadata = fresh.commit_metadata[sha]
                if corruption == "parent":
                    fresh.commit_metadata[sha] = replace(metadata, parents=("f" * 40,))
                elif corruption == "tree":
                    fresh.commit_metadata[sha] = replace(metadata, tree_sha="f" * 40)
                else:
                    fresh.commit_messages[sha] += "forged\n"
                self.assertEqual(
                    self.resolve(fresh, sha, LegacyEvidenceDisposition.ABSENT).activation,
                    CarrierActivation.CONFLICTING,
                )

    def test_required_status_epoch_finalization_invalidated_requires_exact_finalizer_parent(self):
        client, issue, anchor_comment, lease, state, claim, first_final, revoke, final2 = self.make_finalization_invalidation_chain()
        self.assertEqual(revoke.reason_class, RequiredStatusEpochReason.FINALIZATION_INVALIDATED)
        active = self.resolve(client, final2.final_head_sha, LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(active.activation, CarrierActivation.ACTIVE)
        self.assertEqual(active.role, CarrierRole.ISSUE_FINALIZING)
        self.assertEqual(active.marker, controller_module._issue_finalization_epoch_marker(final2))
        self.assertEqual(
            [item.body.splitlines()[0] for item in client.pr_comments[state.binding.pull_request_number]
             if item.body.startswith((ISSUE_HEAD_CLAIM_MARKER, REQUIRED_STATUS_EPOCH_MARKER, ISSUE_FINALIZATION_EPOCH_MARKER))],
            [ISSUE_HEAD_CLAIM_MARKER, ISSUE_FINALIZATION_EPOCH_MARKER, REQUIRED_STATUS_EPOCH_MARKER, ISSUE_FINALIZATION_EPOCH_MARKER],
        )

    def test_issue_finalization_epoch_active_direct_and_after_required_status_chain(self):
        for through_required in (False, True):
            with self.subTest(through_required=through_required):
                client, _issue, _anchor, _lease, _state, _claim, _immediate, epoch = self.make_finalization_epoch_client(
                    through_required_status=through_required,
                )
                legacy_reads = []
                result = self.resolve(
                    client, epoch.final_head_sha,
                    lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
                )
                self.assertEqual(result.activation, CarrierActivation.ACTIVE)
                self.assertEqual(result.role, CarrierRole.ISSUE_FINALIZING)
                self.assertEqual(result.marker, controller_module._issue_finalization_epoch_marker(epoch))
                self.assertEqual(legacy_reads, [])

    def test_issue_finalization_epoch_moved_head_and_lifecycle_are_reserved(self):
        for moved in ("ref", "pr-head", "issue-closed", "pr-closed"):
            with self.subTest(moved=moved):
                client, issue, _anchor, _lease, state, _claim, _immediate, epoch = self.make_finalization_epoch_client()
                if moved == "ref":
                    client.current_ref = epoch.from_head_sha
                elif moved == "pr-head":
                    client.pull_requests[state.binding.pull_request_number] = replace(
                        client.pull_requests[state.binding.pull_request_number], head_oid=epoch.from_head_sha,
                    )
                elif moved == "issue-closed":
                    client.issue = replace(issue, state="closed")
                else:
                    number = state.binding.pull_request_number
                    client.pull_request_issues[number] = replace(client.pull_request_issues[number], state="closed")
                result = self.resolve(client, epoch.final_head_sha, LegacyEvidenceDisposition.ABSENT)
                self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
                self.assertEqual(result.role, CarrierRole.ISSUE_FINALIZING)

    def test_issue_finalization_epoch_missing_edited_wrong_app_and_status_digest_tamper_conflict(self):
        for corruption in ("missing", "edited", "wrong-app", "status-digest"):
            with self.subTest(corruption=corruption):
                client, _issue, _anchor, _lease, state, _claim, _immediate, epoch = self.make_finalization_epoch_client()
                comments = list(client.pr_comments[state.binding.pull_request_number])
                index = next(i for i, item in enumerate(comments) if item.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER))
                if corruption == "missing":
                    comments.pop(index)
                elif corruption == "edited":
                    comments[index] = replace(comments[index], editor_id=self.APP.bot_node_id)
                elif corruption == "wrong-app":
                    comments[index] = replace(comments[index], author_login="wrong[bot]")
                else:
                    value = json.loads(comments[index].body.splitlines()[1])
                    value["requiredStatusEvidenceDigest"] = "f" * 64
                    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                    comments[index] = replace(comments[index], body=ISSUE_FINALIZATION_EPOCH_MARKER + "\n" + payload + "\n")
                client.pr_comments[state.binding.pull_request_number] = comments
                result = self.resolve(client, epoch.final_head_sha, LegacyEvidenceDisposition.ABSENT)
                self.assertEqual(result.activation, CarrierActivation.CONFLICTING)

    def test_issue_finalization_epoch_target_parent_tree_and_marker_mismatch_conflict(self):
        for corruption in ("parent", "tree", "marker"):
            with self.subTest(corruption=corruption):
                client, _issue, _anchor, _lease, _state, _claim, _immediate, epoch = self.make_finalization_epoch_client()
                sha = epoch.final_head_sha
                metadata = client.commit_metadata[sha]
                if corruption == "parent":
                    client.commit_metadata[sha] = replace(metadata, parents=("f" * 40,))
                elif corruption == "tree":
                    client.commit_metadata[sha] = replace(metadata, tree_sha="f" * 40)
                else:
                    client.commit_messages[sha] += "forged\n"
                self.assertEqual(
                    self.resolve(client, sha, LegacyEvidenceDisposition.ABSENT).activation,
                    CarrierActivation.CONFLICTING,
                )

    def test_unified_history_accepts_issue_head_claim_from_active_required_status_head(self):
        client, _issue, _anchor, _lease, state, base_claim, epoch = self.make_required_status_epoch_client()
        successor = self.make_claim_from_epoch(client, state, epoch, base_claim)
        history = controller_module._issue_authority_history(
            client, self.CENTRAL, client.pr_comments[state.binding.pull_request_number],
            self.APP, state, epoch.to_head_sha,
        )
        self.assertTrue(any(node.target_head_sha == successor.to_head_sha and node.claim_kind == "ISSUE_HEAD_CLAIM" for node in history))
        self.assertEqual(
            controller_module._issue_head_claim_comments(
                client, self.CENTRAL, client.pr_comments[state.binding.pull_request_number],
                self.APP, state, epoch.to_head_sha,
            )[-1].claim,
            successor,
        )

    def test_issue_head_claim_from_finalizing_and_normalize_from_epoch_are_rejected(self):
        client, _issue, _anchor, _lease, state, claim, _immediate, final = self.make_finalization_epoch_client()
        direct_successor = self.make_claim_from_epoch(client, state, final, claim)
        self.assertEqual(
            self.resolve(client, direct_successor.to_head_sha, LegacyEvidenceDisposition.ABSENT).activation,
            CarrierActivation.CONFLICTING,
        )

        client, _issue, _anchor, _lease, state, claim, epoch = self.make_required_status_epoch_client()
        normalize = self.make_claim_from_epoch(client, state, epoch, claim, transition="NORMALIZE")
        self.assertEqual(
            self.resolve(client, normalize.to_head_sha, LegacyEvidenceDisposition.ABSENT).activation,
            CarrierActivation.CONFLICTING,
        )

    def test_issue_finalization_rejects_required_authority_and_proposal_origin_mismatches(self):
        client, _issue, _anchor, _lease, state, _claim, _immediate, epoch = self.make_finalization_epoch_client()
        wrong_immediate = epoch._fields()
        wrong_immediate.update({
            "from_authority_kind": "REQUIRED_STATUS_EPOCH",
            "from_authority_comment_database_id": 999,
            "from_authority_artifact_id": "c" * 64,
            "from_authority_artifact_sha256": "d" * 64,
        })
        variant = self.append_finalization_variant(client, state, wrong_immediate, comment_id=3_109)
        self.assertEqual(
            self.resolve(client, variant.final_head_sha, LegacyEvidenceDisposition.ABSENT).activation,
            CarrierActivation.CONFLICTING,
        )

        client, _issue, _anchor, _lease, state, _claim, _immediate, epoch = self.make_finalization_epoch_client(
            through_required_status=True,
        )
        wrong_origin = epoch._fields()
        wrong_origin.update({
            "proposal_origin_claim_comment_database_id": 999,
            "proposal_origin_claim_id": "c" * 64,
            "proposal_origin_claim_sha256": "d" * 64,
        })
        variant = self.append_finalization_variant(client, state, wrong_origin, comment_id=3_110)
        self.assertEqual(
            self.resolve(client, variant.final_head_sha, LegacyEvidenceDisposition.ABSENT).activation,
            CarrierActivation.CONFLICTING,
        )

    def test_issue_finalization_conflicting_duplicate_and_normalization_only_origin_block(self):
        client, _issue, _anchor, _lease, state, _claim, _immediate, epoch = self.make_finalization_epoch_client()
        duplicate_fields = epoch._fields()
        duplicate = self.append_finalization_variant(
            client, state, duplicate_fields, comment_id=3_111,
            timestamp="2026-10-05T00:00:01Z",
        )
        self.assertEqual(duplicate.claim_generation_id, epoch.claim_generation_id)
        self.assertEqual(
            self.resolve(client, epoch.final_head_sha, LegacyEvidenceDisposition.ABSENT).activation,
            CarrierActivation.CONFLICTING,
        )

        client, state, _normalize_claim, normalize_origin_epoch = self.make_normalize_origin_finalization_client()
        self.assertEqual(
            self.resolve(client, normalize_origin_epoch.final_head_sha, LegacyEvidenceDisposition.ABSENT).activation,
            CarrierActivation.CONFLICTING,
        )

    def test_missing_mixed_epoch_predecessor_fails_closed_without_fallback(self):
        client, issue, _anchor, _lease, state, claim, _active_epoch = self.make_required_status_epoch_client()
        missing_parent = "f" * 40
        client.commit_metadata[missing_parent] = GitCommitMetadata(
            missing_parent, claim.to_tree_sha, (), IssueBranchLeaseControllerTests.CLAIM_DATE,
        )
        client.commit_trees[missing_parent] = (claim.to_tree_sha, client.commit_trees[claim.to_head_sha][1])
        fields = dict(
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(state.lease.comment.body.encode("utf-8")).hexdigest(),
            binding_id=state.binding.binding_id,
            source_id=state.binding.source_id,
            source_repository_id=state.binding.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=state.issue_anchor.anchor.request_class,
            accepted_base_sha=claim.accepted_base_sha,
            accepted_base_tree_sha=claim.accepted_base_tree_sha,
            base_ref="main",
            from_head_sha=missing_parent,
            from_tree_sha=claim.to_tree_sha,
            to_head_sha="0" * 40,
            to_tree_sha=claim.to_tree_sha,
            carrier_nonce="8" * 64,
            reason_class=RequiredStatusEpochReason.ACTIVE_REVALIDATION,
            from_provenance_kind="ISSUE_HEAD_CLAIM",
            from_provenance_id="9" * 64,
            from_provenance_sha256="a" * 64,
            from_carrier_role="ISSUE_ACTIVE",
            prior_required_status=None,
        )
        prepared = RequiredStatusEpoch.create(**fields)
        marker_text = controller_module._required_status_epoch_marker(prepared).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target = controller_module._expected_deterministic_commit_sha(
            claim.to_tree_sha, missing_parent, marker_text, timestamp,
        )
        epoch = RequiredStatusEpoch.create(**{**fields, "to_head_sha": target})
        self._persist_test_epoch_target(client, target, missing_parent, claim.to_tree_sha, marker_text)
        client.pr_comments[state.binding.pull_request_number].append(
            IssueAnchorControllerTests.comment(epoch.render(), database_id=3_112),
        )
        legacy_reads = []
        result = self.resolve(
            client, target,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(legacy_reads, [])

    def test_unified_issue_authority_history_rejects_genuine_mixed_cycle(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()

        def validated_shape(target_sha, parent_sha, epoch_id):
            epoch = object.__new__(RequiredStatusEpoch)
            object.__setattr__(epoch, "claim_kind", "REQUIRED_STATUS_EPOCH")
            object.__setattr__(epoch, "to_head_sha", target_sha)
            object.__setattr__(epoch, "from_head_sha", parent_sha)
            object.__setattr__(epoch, "to_tree_sha", claim.to_tree_sha)
            object.__setattr__(epoch, "transition_kind", "ACTIVE_REVALIDATION")
            object.__setattr__(epoch, "epoch_id", epoch_id)
            comment = IssueAnchorControllerTests.comment(
                f"validated Phase-1 wrapper {epoch_id}", database_id=3_120 + int(epoch_id[0], 16),
            )
            return controller_module.RequiredStatusEpochComment(epoch, comment, False)

        target_a, target_b = "d" * 40, "e" * 40
        self.assertNotIn(target_a, {state.lease.lease.initial_head_sha, claim.to_head_sha})
        self.assertNotIn(target_b, {state.lease.lease.initial_head_sha, claim.to_head_sha})
        cycle = (
            validated_shape(target_a, target_b, "1" * 64),
            validated_shape(target_b, target_a, "2" * 64),
        )
        comments = client.pr_comments[state.binding.pull_request_number]
        with patch.object(controller_module, "_required_status_epoch_comments", return_value=cycle):
            with self.assertRaises(R02Error) as caught:
                controller_module._issue_authority_history(
                    client, self.CENTRAL, comments, self.APP, state, claim.to_head_sha,
                )
        self.assertEqual(
            str(caught.exception),
            "unified Issue-owned history has missing or cyclic predecessor provenance",
        )

    def test_unified_issue_authority_history_rejects_conflicting_role_provenance_for_same_target(self):
        client, _issue, _anchor, _lease, state, claim = self.make_claim_client()
        target_sha = "f" * 40
        self.assertNotIn(target_sha, {state.lease.lease.initial_head_sha, claim.to_head_sha})

        required = object.__new__(RequiredStatusEpoch)
        for name, value in {
            "claim_kind": "REQUIRED_STATUS_EPOCH",
            "epoch_id": "3" * 64,
            "from_head_sha": claim.to_head_sha,
            "to_head_sha": target_sha,
            "to_tree_sha": claim.to_tree_sha,
            "transition_kind": "ACTIVE_REVALIDATION",
        }.items():
            object.__setattr__(required, name, value)
        finalization = object.__new__(IssueFinalizationEpoch)
        for name, value in {
            "claim_kind": "ISSUE_FINALIZATION_EPOCH",
            "epoch_id": "4" * 64,
            "from_head_sha": claim.to_head_sha,
            "final_head_sha": target_sha,
            "final_tree_sha": claim.to_tree_sha,
            "transition_kind": "FINALIZE",
        }.items():
            object.__setattr__(finalization, name, value)
        required_wrapper = controller_module.RequiredStatusEpochComment(
            required,
            IssueAnchorControllerTests.comment("validated RSE wrapper", database_id=3_123),
            False,
        )
        finalization_wrapper = controller_module.IssueFinalizationEpochComment(
            finalization,
            IssueAnchorControllerTests.comment("validated IFE wrapper", database_id=3_124),
            False,
        )
        comments = client.pr_comments[state.binding.pull_request_number]
        with (
            patch.object(controller_module, "_required_status_epoch_comments", return_value=(required_wrapper,)),
            patch.object(controller_module, "_issue_finalization_epoch_comments", return_value=(finalization_wrapper,)),
        ):
            with self.assertRaises(R02Error) as caught:
                controller_module._issue_authority_history(
                    client, self.CENTRAL, comments, self.APP, state, claim.to_head_sha,
                )
        self.assertEqual(
            str(caught.exception),
            "conflicting Issue-owned role/provenance for one claimed SHA",
        )

    def test_finalization_from_required_epoch_rejects_stale_older_proposal_origin(self):
        client, _issue, _anchor, _lease, state, proposal_one, _epoch_one, final_one = (
            self.make_finalization_epoch_client(through_required_status=True)
        )
        proposal_two = self.make_claim_from_epoch(client, state, _epoch_one, proposal_one)
        proposal_two_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER) and item.database_id == 3_105
        )

        epoch_fields = _epoch_one._fields()
        for key in ("claim_generation_id", "authority_preimage_digest", "marker_digest", "epoch_id"):
            epoch_fields.pop(key)
        epoch_fields.update({
            "from_head_sha": proposal_two.to_head_sha,
            "from_tree_sha": proposal_two.to_tree_sha,
            "to_head_sha": "0" * 40,
            "to_tree_sha": proposal_two.to_tree_sha,
            "carrier_nonce": "b" * 64,
            "from_provenance_kind": "ISSUE_HEAD_CLAIM",
            "from_provenance_id": proposal_two.claim_id,
            "from_provenance_sha256": hashlib.sha256(proposal_two_comment.body.encode("utf-8")).hexdigest(),
            "from_carrier_role": "ISSUE_ACTIVE",
        })
        prepared_epoch_two = RequiredStatusEpoch.create(**epoch_fields)
        epoch_two_marker = controller_module._required_status_epoch_marker(prepared_epoch_two).render()
        epoch_two_sha = controller_module._expected_deterministic_commit_sha(
            proposal_two.to_tree_sha, proposal_two.to_head_sha, epoch_two_marker,
            IssueBranchLeaseControllerTests.CLAIM_DATE,
        )
        epoch_two = RequiredStatusEpoch.create(**{**epoch_fields, "to_head_sha": epoch_two_sha})
        self._persist_test_epoch_target(
            client, epoch_two_sha, proposal_two.to_head_sha, proposal_two.to_tree_sha, epoch_two_marker,
        )
        epoch_two_comment = IssueAnchorControllerTests.comment(epoch_two.render(), database_id=3_125)
        client.pr_comments[state.binding.pull_request_number].append(epoch_two_comment)

        stale_final_fields = final_one._fields()
        stale_final_fields.update({
            "from_head_sha": epoch_two.to_head_sha,
            "from_tree_sha": epoch_two.to_tree_sha,
            "final_head_sha": "0" * 40,
            "final_tree_sha": epoch_two.to_tree_sha,
            "from_authority_kind": "REQUIRED_STATUS_EPOCH",
            "from_authority_comment_database_id": epoch_two_comment.database_id,
            "from_authority_artifact_id": epoch_two.epoch_id,
            "from_authority_artifact_sha256": hashlib.sha256(epoch_two_comment.body.encode("utf-8")).hexdigest(),
        })
        stale_final = self.append_finalization_variant(
            client, state, stale_final_fields, comment_id=3_126,
        )
        self._activate_fixture_head(client, state, stale_final.final_head_sha)

        self.assertNotEqual(proposal_one.claim_id, proposal_two.claim_id)
        self.assertEqual(epoch_two.from_provenance_id, proposal_two.claim_id)
        self.assertEqual(stale_final.from_head_sha, epoch_two.to_head_sha)
        self.assertEqual(stale_final.proposal_origin_claim_id, proposal_one.claim_id)
        legacy_reads = []
        result = self.resolve(
            client, stale_final.final_head_sha,
            lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertIsNone(result.role)
        self.assertEqual(legacy_reads, [])

    def test_required_status_epoch_post_provenance_races_and_binding_drift(self):
        for race in ("issue-close", "pr-close", "pr-head", "ref", "final-ref-error", "binding"):
            with self.subTest(race=race):
                client, issue, _anchor, _lease, state, _claim, epoch = self.make_required_status_epoch_client()
                pr_number = state.binding.pull_request_number
                branch = state.binding.branch_ref.removeprefix("refs/heads/")
                if race == "issue-close":
                    client.issue_metadata_sequences[issue.number] = [issue, issue, replace(issue, state="closed")]
                elif race == "pr-close":
                    pr_issue = client.pull_request_issues[pr_number]
                    client.issue_metadata_sequences[pr_number] = [pr_issue, replace(pr_issue, state="closed")]
                elif race == "pr-head":
                    pr = client.pull_requests[pr_number]
                    client.pull_request_metadata_sequences[pr_number] = [pr, replace(pr, head_oid=epoch.from_head_sha)]
                elif race == "ref":
                    client.generated_ref_sequence = [epoch.to_head_sha, epoch.from_head_sha]
                elif race == "final-ref-error":
                    client.generated_ref_sequence = [epoch.to_head_sha, RuntimeError("final ref unavailable")]
                else:
                    original = tuple(client.comments)
                    drifted = list(original)
                    index = next(i for i, comment in enumerate(drifted) if comment.body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))
                    drifted[index] = replace(drifted[index], body=drifted[index].body + "\n")
                    client.issue_comment_sequences[issue.number] = [original, original, drifted]
                result = self.resolve(client, epoch.to_head_sha, LegacyEvidenceDisposition.ABSENT)
                if race == "final-ref-error" or race == "binding":
                    self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
                else:
                    self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
                if race in {"ref", "final-ref-error"}:
                    self.assertEqual(client.ref_reads, [branch, branch])

    def test_finalization_epoch_post_provenance_issue_close_ref_and_binding_races_fail_closed(self):
        for race in ("issue-close", "ref", "final-ref-error", "binding"):
            with self.subTest(race=race):
                client, issue, _anchor, _lease, state, _claim, _immediate, epoch = self.make_finalization_epoch_client()
                branch = state.binding.branch_ref.removeprefix("refs/heads/")
                if race == "issue-close":
                    client.issue_metadata_sequences[issue.number] = [issue, issue, replace(issue, state="closed")]
                elif race == "ref":
                    client.generated_ref_sequence = [epoch.final_head_sha, epoch.from_head_sha]
                elif race == "final-ref-error":
                    client.generated_ref_sequence = [epoch.final_head_sha, RuntimeError("final ref unavailable")]
                else:
                    original = tuple(client.comments)
                    drifted = list(original)
                    index = next(i for i, comment in enumerate(drifted) if comment.body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))
                    drifted[index] = replace(drifted[index], body=drifted[index].body + "\n")
                    client.issue_comment_sequences[issue.number] = [original, original, drifted]
                result = self.resolve(client, epoch.final_head_sha, LegacyEvidenceDisposition.ABSENT)
                if race in {"final-ref-error", "binding"}:
                    self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
                else:
                    self.assertEqual(result.activation, CarrierActivation.RESERVED_INACTIVE)
                if race in {"ref", "final-ref-error"}:
                    self.assertEqual(client.ref_reads, [branch, branch])

    def test_epoch_reserved_markers_never_use_legacy_and_future_wave_roles_remain_conflicting(self):
        markers = (
            self.marker(claim_kind="REQUIRED_STATUS_EPOCH", role="ISSUE_ACTIVE").render(),
            self.marker(claim_kind="ISSUE_FINALIZATION_EPOCH", role="ISSUE_FINALIZING").render(),
            self.marker(claim_kind="ISSUE_CANCELLATION_FENCE", role="ISSUE_CANCEL").render(),
            self.marker(claim_kind="MACHINE_REF_CLAIM", role="MACHINE_PUBLICATION", owner_kind="MACHINE_SOURCE").render(),
        )
        for marker_text in markers:
            legacy_reads = []
            fake = self.commit_message_client("a" * 40, marker_text)
            result = self.resolve(
                fake, "a" * 40,
                lambda: legacy_reads.append("called") or LegacyEvidenceDisposition.ABSENT,
            )
            self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
            self.assertEqual(legacy_reads, [])

    def test_wave05_resolver_and_external_writer_are_not_runtime_activated(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        module_ast = ast.parse(source)
        main = next(node for node in module_ast.body if isinstance(node, ast.FunctionDef) and node.name == "main")
        main_names = {node.id for node in ast.walk(main) if isinstance(node, ast.Name)}
        self.assertNotIn("resolve_sha_carrier_role", main_names)
        self.assertNotIn("publish_unclaimed_external_success", main_names)
        self.assertIn("def upsert_trusted_validation_check(", source)
        self.assertIn("allow_create=True, allow_green=False", source)
        self.assertIn("allow_create=True, allow_green=True", source)


class IssueEpochControllerComponentTests(unittest.TestCase):
    APP = IssueAnchorControllerTests.APP
    CENTRAL = Wave05ShaCarrierResolverTests.CENTRAL
    CENTRAL_NODE_ID = Wave05ShaCarrierResolverTests.CENTRAL_NODE_ID

    class MutationClient:
        def __init__(self):
            self.commit_calls = []
            self.status_calls = []
            self.status_reads = 0
            self.check_calls = []
            self.timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
            self.status_receipt = None
            self.status_error = None

        def bot_commit_timestamp_after(self, repository, parent_sha):
            return self.timestamp

        def create_commit(self, repository, message, tree, parents, *, timestamp=None):
            parent_list = tuple(parents)
            sha = controller_module._expected_deterministic_commit_sha(
                tree, parent_list[0], message, timestamp or self.timestamp,
            )
            self.commit_calls.append((repository, message, tree, parent_list, timestamp, sha))
            return GitObject(sha)

        def create_commit_status(self, repository, sha, state, context, description, target_url=None):
            self.status_calls.append((repository, sha, state, context, description, target_url))
            if self.status_error is not None:
                raise self.status_error
            return self.status_receipt

        def list_commit_statuses(self, repository, sha):
            self.status_reads += 1
            return ()

        def create_check_run(self, *args, **kwargs):
            self.check_calls.append((args, kwargs))
            raise AssertionError("Issue finalization must not fall back to Check Runs")

    @staticmethod
    def _node_for_claim(claim, comment, *, origin=None, active=True):
        base = controller_module._IssueAuthorityNode(
            "ISSUE_HEAD_CLAIM", CarrierRole.ISSUE_ACTIVE, claim.to_head_sha,
            claim.from_head_sha, claim.to_tree_sha, claim.transition_kind,
            claim.claim_id, hashlib.sha256(comment.body.encode()).hexdigest(),
            comment, claim, active=active,
        )
        if origin is None and claim.transition_kind != "NORMALIZE":
            origin = base
        return controller_module._IssueAuthorityNode(
            base.claim_kind, base.role, base.target_head_sha, base.from_head_sha,
            base.tree_sha, base.transition_kind, base.artifact_id,
            base.artifact_sha256, base.comment, base.artifact, active=active,
            proposal_origin=origin,
        )

    @classmethod
    def _snapshot(
        cls,
        *,
        client,
        issue,
        state,
        claim,
        current_authority,
        current_ref,
        history=None,
        source_error=None,
        accepted_main=None,
    ):
        main_sha = accepted_main or claim.accepted_base_sha
        main_meta = client.commit_metadata[main_sha]
        _main_tree, main_entries = client.commit_trees[main_sha]
        state = replace(
            state,
            pr=replace(state.pr, head_oid=current_ref, base_oid=main_sha),
        )
        request = parse_issue_request_body(issue.body)
        fold = type("Fold", (), {"request": request})()
        role = current_authority.role
        if current_authority.claim_kind == "ISSUE_HEAD_CLAIM":
            marker = controller_module._issue_head_claim_marker(current_authority.artifact)
        elif current_authority.claim_kind == "REQUIRED_STATUS_EPOCH":
            marker = controller_module._required_status_epoch_marker(current_authority.artifact)
        else:
            marker = controller_module._issue_finalization_epoch_marker(current_authority.artifact)
        resolution = ShaCarrierResolution(CarrierActivation.ACTIVE, role, marker)
        return controller_module._IssueEpochSnapshot(
            state,
            RepositoryMetadata(1, cls.CENTRAL_NODE_ID, cls.CENTRAL, "main"),
            main_sha,
            main_meta.tree_sha,
            tuple(main_entries),
            current_ref,
            issue,
            (),
            tuple(client.pr_comments.get(state.binding.pull_request_number, ())),
            fold,
            (),
            IssueAnchorControllerTests.authority(),
            source_error,
            tuple(history if history is not None else (current_authority,)),
            current_authority,
            resolution,
        )

    @classmethod
    def _finalization_node(cls, epoch, comment, origin, *, active=True):
        return controller_module._IssueAuthorityNode(
            "ISSUE_FINALIZATION_EPOCH", CarrierRole.ISSUE_FINALIZING,
            epoch.final_head_sha, epoch.from_head_sha, epoch.final_tree_sha,
            epoch.transition_kind, epoch.epoch_id,
            hashlib.sha256(comment.body.encode()).hexdigest(), comment, epoch,
            active=active, proposal_origin=origin,
        )

    @classmethod
    def _required_status_node(cls, epoch, comment, origin, *, active=True):
        return controller_module._IssueAuthorityNode(
            "REQUIRED_STATUS_EPOCH", CarrierRole.ISSUE_ACTIVE,
            epoch.to_head_sha, epoch.from_head_sha, epoch.to_tree_sha,
            epoch.transition_kind, epoch.epoch_id,
            hashlib.sha256(comment.body.encode()).hexdigest(), comment, epoch,
            active=active, proposal_origin=origin,
        )

    @classmethod
    def _controller(cls, client):
        result = controller_module.R02Controller.__new__(controller_module.R02Controller)
        result.client = client
        result.central_repository = cls.CENTRAL
        result.app = cls.APP
        result.candidate_builder = None
        result.environ = {}
        return result

    @staticmethod
    def _install_created_commit(client):
        client.commit_calls = []
        client.bot_commit_timestamp_after = lambda _repo, _parent: client.timestamp

    def _active_claim_fixture(self):
        client, issue, _anchor_comment, _lease, state, claim = Wave05ShaCarrierResolverTests().make_claim_client()
        claim_comment = next(
            comment for comment in client.pr_comments[state.binding.pull_request_number]
            if comment.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        node = self._node_for_claim(claim, claim_comment)
        snapshot = self._snapshot(
            client=client, issue=issue, state=state, claim=claim,
            current_authority=node, current_ref=claim.to_head_sha,
        )
        mutation = self.MutationClient()
        self._install_created_commit(mutation)
        controller = self._controller(mutation)
        return client, issue, state, claim, node, snapshot, controller, mutation

    def _active_finalization_fixture(self):
        client, issue, _anchor_comment, _lease, state, claim, _immediate, epoch = (
            Wave05ShaCarrierResolverTests().make_finalization_epoch_client()
        )
        claim_comment = next(
            comment for comment in client.pr_comments[state.binding.pull_request_number]
            if comment.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        final_comment = next(
            comment for comment in client.pr_comments[state.binding.pull_request_number]
            if comment.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER)
        )
        origin = self._node_for_claim(claim, claim_comment)
        final_node = self._finalization_node(epoch, final_comment, origin)
        snapshot = self._snapshot(
            client=client, issue=issue, state=state, claim=claim,
            current_authority=final_node, current_ref=epoch.final_head_sha,
        )
        mutation = self.MutationClient()
        self._install_created_commit(mutation)
        controller = self._controller(mutation)
        return client, issue, state, claim, epoch, final_node, origin, snapshot, controller, mutation

    def test_prepare_finalization_persists_before_nonforce_cas_and_creates_exact_no_tree_child(self):
        _client, issue, state, claim, _node, snapshot, controller, mutation = self._active_claim_fixture()
        events = []
        captured = {}

        def persist(_state, epoch, _head):
            events.append("persist")
            captured["epoch"] = epoch

        def cas(_state, parent, target, _expected):
            events.append(("cas", parent, target))

        calls = 0

        def read_snapshot(*_args, **_kwargs):
            nonlocal calls
            calls += 1
            if calls < 3:
                return snapshot
            epoch = captured["epoch"]
            comment = IssueAnchorControllerTests.comment(epoch.render(), database_id=3_901)
            origin = snapshot.current_authority
            final_node = self._finalization_node(epoch, comment, origin)
            return self._snapshot(
                client=_client, issue=issue, state=state, claim=claim,
                current_authority=final_node, current_ref=epoch.final_head_sha,
            )

        target_digest = claim.target_evidence_digest
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", side_effect=read_snapshot),
            patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                target_digest, claim.effective_request_digest, claim.patch_projection_evidence_digest,
            )),
            patch.object(controller, "_persist_issue_epoch_artifact", side_effect=persist),
            patch.object(controller, "_apply_persisted_issue_epoch_target", side_effect=cas),
            patch.object(controller_module, "_validate_issue_finalization_epoch_target"),
        ):
            result = controller.prepare_issue_finalization_epoch(
                issue.number, IssueAnchorControllerTests.resolver(), nonce_factory=lambda: "f" * 64,
            )
        self.assertEqual(result, captured["epoch"])
        self.assertEqual([event if isinstance(event, str) else event[0] for event in events], ["persist", "cas"])
        self.assertEqual(events[1][1:], (claim.to_head_sha, result.final_head_sha))
        self.assertEqual(mutation.commit_calls[0][2:4], (claim.to_tree_sha, (claim.to_head_sha,)))
        self.assertEqual(mutation.commit_calls[0][1], controller_module._issue_finalization_epoch_marker(result).render())
        self.assertEqual(result.final_tree_sha, claim.to_tree_sha)
        self.assertEqual(mutation.status_calls, [])

    def test_prepare_from_required_status_head_binds_immediate_epoch_and_earlier_proposal_origin(self):
        client, issue, _anchor, _lease, state, claim, required = (
            Wave05ShaCarrierResolverTests().make_required_status_epoch_client()
        )
        claim_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        required_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
        )
        origin = self._node_for_claim(claim, claim_comment)
        immediate = self._required_status_node(required, required_comment, origin)
        snapshot = self._snapshot(
            client=client, issue=issue, state=state, claim=claim,
            current_authority=immediate, current_ref=required.to_head_sha,
        )
        mutation = self.MutationClient()
        self._install_created_commit(mutation)
        controller = self._controller(mutation)
        events, captured = [], {}
        def persist(_state, epoch, _head):
            events.append("persist")
            captured["epoch"] = epoch
        def cas(_state, parent, target, _expected):
            events.append(("cas", parent, target))
        reads = 0
        def read_snapshot(*_args, **_kwargs):
            nonlocal reads
            reads += 1
            if reads < 3:
                return snapshot
            epoch = captured["epoch"]
            final_comment = IssueAnchorControllerTests.comment(epoch.render(), database_id=3_902)
            final_node = self._finalization_node(epoch, final_comment, origin)
            return self._snapshot(
                client=client, issue=issue, state=state, claim=claim,
                current_authority=final_node, current_ref=epoch.final_head_sha,
            )
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", side_effect=read_snapshot),
            patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                claim.target_evidence_digest, claim.effective_request_digest,
                claim.patch_projection_evidence_digest,
            )),
            patch.object(controller, "_persist_issue_epoch_artifact", side_effect=persist),
            patch.object(controller, "_apply_persisted_issue_epoch_target", side_effect=cas),
            patch.object(controller_module, "_validate_issue_finalization_epoch_target"),
        ):
            result = controller.prepare_issue_finalization_epoch(
                issue.number, IssueAnchorControllerTests.resolver(), nonce_factory=lambda: "b" * 64,
            )
        self.assertEqual(result.from_head_sha, required.to_head_sha)
        self.assertEqual(result.from_authority_kind, "REQUIRED_STATUS_EPOCH")
        self.assertEqual(result.from_authority_artifact_id, required.epoch_id)
        self.assertEqual(result.proposal_origin_claim_id, claim.claim_id)
        self.assertNotEqual(required.to_head_sha, claim.to_head_sha)
        self.assertEqual(events[0], "persist")

    def test_pending_finalization_replay_reuses_exact_epoch_without_reposting_or_new_target(self):
        client, issue, state, claim, epoch, _final, origin, _old_snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        claim_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        immediate = self._node_for_claim(claim, claim_comment)
        pending_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER)
        )
        pending = self._finalization_node(epoch, pending_comment, origin, active=False)
        initial = self._snapshot(
            client=client, issue=issue, state=state, claim=claim,
            current_authority=immediate, current_ref=claim.to_head_sha,
            history=(immediate, pending),
        )
        captured, events = {}, []
        reads = 0
        def read_snapshot(*_args, **_kwargs):
            nonlocal reads
            reads += 1
            if reads < 3:
                return initial
            comment = IssueAnchorControllerTests.comment(epoch.render(), database_id=pending_comment.database_id)
            final_node = self._finalization_node(epoch, comment, origin)
            return self._snapshot(
                client=client, issue=issue, state=state, claim=claim,
                current_authority=final_node, current_ref=epoch.final_head_sha,
            )
        def cas(_state, parent, target, _expected):
            events.append((parent, target))
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", side_effect=read_snapshot),
            patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                claim.target_evidence_digest, claim.effective_request_digest,
                claim.patch_projection_evidence_digest,
            )),
            patch.object(controller, "_persist_issue_epoch_artifact", side_effect=AssertionError("replay must not repost")),
            patch.object(controller, "_apply_persisted_issue_epoch_target", side_effect=cas),
        ):
            replay = controller.prepare_issue_finalization_epoch(
                issue.number, IssueAnchorControllerTests.resolver(), nonce_factory=lambda: "c" * 64,
            )
        self.assertEqual(replay, epoch)
        self.assertEqual(mutation.commit_calls, [])
        self.assertEqual(events, [(epoch.from_head_sha, epoch.final_head_sha)])

    def test_conflicting_pending_finalizations_block_without_creating_a_target(self):
        client, issue, state, claim, epoch, _final, origin, _snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        claim_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        current = self._node_for_claim(claim, claim_comment)
        pending_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER)
        )
        pending = self._finalization_node(epoch, pending_comment, origin, active=False)
        variant_fields = epoch._fields()
        for derived in (
            "claim_generation_id", "authority_preimage_digest", "finalizer_evidence_digest",
            "required_status_context", "required_status_class", "required_status_state",
            "required_status_target_url", "required_status_evidence_digest",
            "required_status_description", "marker_digest", "epoch_id",
        ):
            variant_fields.pop(derived)
        variant_fields["carrier_nonce"] = "9" * 64
        variant_fields["final_head_sha"] = "0" * 40
        variant_prepared = IssueFinalizationEpoch.create(**variant_fields)
        variant_marker = controller_module._issue_finalization_epoch_marker(variant_prepared).render()
        variant_sha = controller_module._expected_deterministic_commit_sha(
            variant_prepared.final_tree_sha, variant_prepared.from_head_sha,
            variant_marker, IssueBranchLeaseControllerTests.CLAIM_DATE,
        )
        variant = IssueFinalizationEpoch.create(**{**variant_fields, "final_head_sha": variant_sha})
        variant_comment = IssueAnchorControllerTests.comment(variant.render(), database_id=3_899)
        variant_node = self._finalization_node(variant, variant_comment, origin, active=False)
        snapshot = self._snapshot(
            client=client, issue=issue, state=state, claim=claim,
            current_authority=current, current_ref=claim.to_head_sha,
            history=(current, pending, variant_node),
        )
        with patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot), patch.object(
            controller, "_derive_issue_proposal_scope", return_value=(
                claim.target_evidence_digest, claim.effective_request_digest,
                claim.patch_projection_evidence_digest,
            ),
        ), self.assertRaises(R02Error):
            controller.prepare_issue_finalization_epoch(issue.number, IssueAnchorControllerTests.resolver())
        self.assertEqual(mutation.commit_calls, [])

    def test_finalization_pre_cas_main_drift_leaves_persisted_epoch_historical(self):
        _client, issue, state, claim, _node, initial, controller, mutation = self._active_claim_fixture()
        events, captured = [], {}
        changed = replace(initial, accepted_main_sha="8" * 40)
        reads = 0
        def read_snapshot(*_args, **_kwargs):
            nonlocal reads
            reads += 1
            return initial if reads == 1 else changed
        def persist(_state, epoch, _head):
            events.append("persist")
            captured["epoch"] = epoch
        with patch.object(controller, "_read_issue_epoch_snapshot", side_effect=read_snapshot), patch.object(
            controller, "_derive_issue_proposal_scope", return_value=(
                claim.target_evidence_digest, claim.effective_request_digest,
                claim.patch_projection_evidence_digest,
            ),
        ), patch.object(controller, "_persist_issue_epoch_artifact", side_effect=persist), patch.object(
            controller, "_apply_persisted_issue_epoch_target", side_effect=lambda *_: events.append("cas"),
        ), patch.object(controller_module, "_validate_issue_finalization_epoch_target"), self.assertRaises(StaleAuthorityError):
            controller.prepare_issue_finalization_epoch(
                issue.number, IssueAnchorControllerTests.resolver(), nonce_factory=lambda: "d" * 64,
            )
        self.assertEqual(events, ["persist"])
        self.assertEqual(len(mutation.commit_calls), 1)

    def test_finalization_cas_loss_does_not_create_a_second_target(self):
        _client, issue, _state, claim, _node, snapshot, controller, mutation = self._active_claim_fixture()
        events = []
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot),
            patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                claim.target_evidence_digest, claim.effective_request_digest,
                claim.patch_projection_evidence_digest,
            )),
            patch.object(controller, "_persist_issue_epoch_artifact", side_effect=lambda *_: events.append("persist")),
            patch.object(
                controller, "_apply_persisted_issue_epoch_target",
                side_effect=StaleAuthorityError("ref CAS lost"),
            ),
            patch.object(controller_module, "_validate_issue_finalization_epoch_target"),
            self.assertRaises(StaleAuthorityError),
        ):
            controller.prepare_issue_finalization_epoch(
                issue.number, IssueAnchorControllerTests.resolver(), nonce_factory=lambda: "1" * 64,
            )
        self.assertEqual(events, ["persist"])
        self.assertEqual(len(mutation.commit_calls), 1)

    def test_prepare_normalization_only_chain_is_not_finalizable(self):
        _client, issue, state, _claim, _node, snapshot, controller, mutation = self._active_claim_fixture()
        normalize = replace(snapshot.current_authority, transition_kind="NORMALIZE", proposal_origin=None)
        snapshot = replace(snapshot, current_authority=normalize)
        with patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot), self.assertRaises(StaleAuthorityError):
            controller.prepare_issue_finalization_epoch(issue.number, IssueAnchorControllerTests.resolver())
        self.assertEqual(mutation.commit_calls, [])

    def test_publish_issue_final_status_uses_exact_hf_tuple_and_never_check_run(self):
        _client, issue, state, claim, epoch, final_node, _origin, snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        status = CommitStatus(
            9, "S_status", "success", epoch.required_status_context,
            epoch.required_status_description, None, self.APP.bot_id, self.APP.bot_node_id,
            self.APP.bot_login, "Bot", "2026-10-05T00:00:00Z", "2026-10-05T00:00:00Z",
        )
        mutation.status_receipt = StatusWriteReceipt(
            self.CENTRAL, epoch.final_head_sha, "POST",
            f"/repos/{self.CENTRAL}/statuses/{epoch.final_head_sha}",
            "success", epoch.required_status_context, epoch.required_status_description, None, status,
        )
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot),
            patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                epoch.fresh_proposal_scope_evidence_digest,
                epoch.effective_request_digest, epoch.patch_projection_evidence_digest,
            )),
        ):
            receipt = controller.publish_issue_final_success(
                issue.number, epoch, IssueAnchorControllerTests.resolver(),
            )
        self.assertIs(receipt, mutation.status_receipt)
        self.assertEqual(mutation.status_calls, [(
            self.CENTRAL, epoch.final_head_sha, "success", "federation/trusted-validation",
            epoch.required_status_description, None,
        )])
        self.assertEqual(mutation.check_calls, [])
        self.assertEqual(mutation.status_reads, 0)

    def test_publish_rejects_wrong_receipt_sha_or_creator_without_fallback(self):
        _client, issue, _state, _claim, epoch, _node, _origin, snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        wrong_sha = "8" * 40
        for wrong_creator in (False, True):
            status = CommitStatus(
                10, "S_wrong", "success", epoch.required_status_context,
                epoch.required_status_description, None,
                self.APP.bot_id if not wrong_creator else 99,
                self.APP.bot_node_id if not wrong_creator else "B_other",
                self.APP.bot_login if not wrong_creator else "other[bot]", "Bot",
                "2026-10-05T00:00:00Z", "2026-10-05T00:00:00Z",
            )
            requested_sha = epoch.final_head_sha if wrong_creator else wrong_sha
            mutation.status_receipt = StatusWriteReceipt(
                self.CENTRAL, requested_sha, "POST",
                f"/repos/{self.CENTRAL}/statuses/{requested_sha}",
                "success", epoch.required_status_context,
                epoch.required_status_description, None, status,
            )
            with (
                patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot),
                patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                    epoch.fresh_proposal_scope_evidence_digest,
                    epoch.effective_request_digest, epoch.patch_projection_evidence_digest,
                )),
                self.assertRaises(R02Error),
            ):
                controller.publish_issue_final_success(issue.number, epoch, IssueAnchorControllerTests.resolver())
        self.assertEqual(len(mutation.status_calls), 2)
        self.assertEqual(mutation.check_calls, [])

    def test_issue_final_status_never_posts_on_active_or_reserved_issue_active_authority(self):
        _client, issue, _state, claim, epoch, _node, _origin, snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        active_claim_comment = IssueAnchorControllerTests.comment(claim.render(), database_id=3_911)
        active_claim = self._node_for_claim(claim, active_claim_comment)
        issue_snapshot = replace(
            snapshot, current_ref=claim.to_head_sha, current_authority=active_claim,
            resolution=ShaCarrierResolution(
                CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE,
                controller_module._issue_head_claim_marker(claim),
            ),
        )
        with patch.object(controller, "_read_issue_epoch_snapshot", return_value=issue_snapshot), self.assertRaises(StaleAuthorityError):
            controller.publish_issue_final_success(issue.number, epoch, IssueAnchorControllerTests.resolver())
        inactive = replace(
            snapshot,
            resolution=ShaCarrierResolution(
                CarrierActivation.RESERVED_INACTIVE, CarrierRole.ISSUE_FINALIZING,
                controller_module._issue_finalization_epoch_marker(epoch),
            ),
        )
        with patch.object(controller, "_read_issue_epoch_snapshot", return_value=inactive), self.assertRaises(StaleAuthorityError):
            controller.publish_issue_final_success(issue.number, epoch, IssueAnchorControllerTests.resolver())
        self.assertEqual(mutation.status_calls, [])

    def test_status_transport_error_is_ambiguous_and_does_not_read_or_fallback(self):
        _client, issue, _state, _claim, epoch, _node, _origin, snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        mutation.status_error = TransportError("network unavailable")
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot),
            patch.object(controller, "_derive_issue_proposal_scope", return_value=(
                epoch.fresh_proposal_scope_evidence_digest,
                epoch.effective_request_digest, epoch.patch_projection_evidence_digest,
            )),
            self.assertRaises(TransportError),
        ):
            controller.publish_issue_final_success(issue.number, epoch, IssueAnchorControllerTests.resolver())
        self.assertEqual(len(mutation.status_calls), 1)
        self.assertEqual(mutation.status_reads, 0)
        self.assertEqual(mutation.check_calls, [])

    def test_revoke_invalid_active_finalization_even_without_visible_status_and_never_writes_hv_status(self):
        client, issue, state, claim, epoch, final_node, origin, snapshot, controller, mutation = (
            self._active_finalization_fixture()
        )
        events, captured = [], {}
        def persist(_state, required, _head):
            events.append("persist")
            captured["epoch"] = required
        def cas(_state, parent, target, _expected):
            events.append(("cas", parent, target))
        reads = 0
        def read_snapshot(*_args, **_kwargs):
            nonlocal reads
            reads += 1
            if reads < 3:
                return snapshot
            required = captured["epoch"]
            comment = IssueAnchorControllerTests.comment(required.render(), database_id=3_920)
            required_node = self._required_status_node(required, comment, origin)
            return self._snapshot(
                client=client, issue=issue, state=state, claim=claim,
                current_authority=required_node, current_ref=required.to_head_sha,
            )
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", side_effect=read_snapshot),
            patch.object(controller, "_persist_issue_epoch_artifact", side_effect=persist),
            patch.object(controller, "_apply_persisted_issue_epoch_target", side_effect=cas),
            patch.object(controller_module, "_latest_exact_issue_final_status_evidence", return_value=None),
            patch.object(controller_module, "_validate_required_status_epoch_target"),
        ):
            required = controller.revoke_required_status_epoch(
                issue.number, RequiredStatusEpochReason.FINALIZATION_INVALIDATED,
                IssueAnchorControllerTests.resolver(), nonce_factory=lambda: "e" * 64,
            )
        self.assertIsNone(required.prior_required_status)
        self.assertEqual(required.from_head_sha, epoch.final_head_sha)
        self.assertEqual(required.from_provenance_kind, "ISSUE_FINALIZATION_EPOCH")
        self.assertEqual(events[0], "persist")
        self.assertEqual(events[1][1:], (epoch.final_head_sha, required.to_head_sha))
        self.assertEqual(mutation.commit_calls[0][2:4], (epoch.final_tree_sha, (epoch.final_head_sha,)))
        self.assertEqual(mutation.status_calls, [])

    def test_finalization_invalidated_is_rejected_for_issue_active_head(self):
        _client, issue, _state, _claim, _node, snapshot, controller, mutation = self._active_claim_fixture()
        with patch.object(controller, "_read_issue_epoch_snapshot", return_value=snapshot), self.assertRaises(R02Error):
            controller.revoke_required_status_epoch(
                issue.number, RequiredStatusEpochReason.FINALIZATION_INVALIDATED,
                IssueAnchorControllerTests.resolver(),
            )
        self.assertEqual(mutation.commit_calls, [])

    def test_required_status_pending_replay_reuses_exact_hv_without_second_target(self):
        client, issue, _anchor, _lease, state, claim, first_final, revoke, _final2 = (
            Wave05ShaCarrierResolverTests().make_finalization_invalidation_chain()
        )
        final_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER)
        )
        origin_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(ISSUE_HEAD_CLAIM_MARKER)
        )
        origin = self._node_for_claim(claim, origin_comment)
        final_node = self._finalization_node(first_final, final_comment, origin)
        revoke_comment = next(
            item for item in client.pr_comments[state.binding.pull_request_number]
            if item.body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
        )
        pending = self._required_status_node(revoke, revoke_comment, origin, active=False)
        snapshot = self._snapshot(
            client=client, issue=issue, state=state, claim=claim,
            current_authority=final_node, current_ref=first_final.final_head_sha,
            history=(origin, final_node, pending),
        )
        mutation = self.MutationClient()
        self._install_created_commit(mutation)
        controller = self._controller(mutation)
        reads = 0
        def read_snapshot(*_args, **_kwargs):
            nonlocal reads
            reads += 1
            if reads < 3:
                return snapshot
            active_revoke = self._required_status_node(revoke, revoke_comment, origin)
            return self._snapshot(
                client=client, issue=issue, state=state, claim=claim,
                current_authority=active_revoke, current_ref=revoke.to_head_sha,
            )
        def cas(_state, parent, target, _expected):
            self.assertEqual((parent, target), (first_final.final_head_sha, revoke.to_head_sha))
        with (
            patch.object(controller, "_read_issue_epoch_snapshot", side_effect=read_snapshot),
            patch.object(controller, "_persist_issue_epoch_artifact", side_effect=AssertionError("pending HV must not repost")),
            patch.object(controller, "_apply_persisted_issue_epoch_target", side_effect=cas),
            patch.object(controller_module, "_latest_exact_issue_final_status_evidence", return_value=None),
        ):
            replay = controller.revoke_required_status_epoch(
                issue.number, RequiredStatusEpochReason.FINALIZATION_INVALIDATED,
                IssueAnchorControllerTests.resolver(),
            )
        self.assertEqual(replay, revoke)
        self.assertEqual(mutation.commit_calls, [])
        self.assertEqual(mutation.status_calls, [])

    def test_revoke_captures_exact_app_status_and_ignores_foreign_bot_status(self):
        client, issue, state, claim, epoch, _node, _origin, _snapshot, _controller, _mutation = (
            self._active_finalization_fixture()
        )
        def status(status_id, *, creator_id, creator_node, creator_login, creator_type, updated):
            return CommitStatus(
                status_id, f"S{status_id}", "success", epoch.required_status_context,
                epoch.required_status_description, None, creator_id, creator_node,
                creator_login, creator_type, "2026-10-05T00:00:00Z", updated,
            )
        foreign = status(99, creator_id=99, creator_node="B_other", creator_login="other[bot]", creator_type="Bot", updated="2026-10-06T00:00:00Z")
        exact = status(11, creator_id=self.APP.bot_id, creator_node=self.APP.bot_node_id, creator_login=self.APP.bot_login, creator_type="Bot", updated="2026-10-05T01:00:00Z")
        class StatusReader:
            def list_commit_statuses(self, _repository, sha):
                self_sha.append(sha)
                return (exact, foreign)
        self_sha = []
        evidence = controller_module._latest_exact_issue_final_status_evidence(
            StatusReader(), self.CENTRAL, epoch.final_head_sha, self.APP,
        )
        self.assertEqual(evidence.status_id, exact.id)
        self.assertEqual(self_sha, [epoch.final_head_sha])

    def test_nonactivation_ast_keeps_wave06_callables_out_of_main(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        main = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "main")
        called = {
            item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
            for item in ast.walk(main)
            if isinstance(item, ast.Call)
            and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
        }
        self.assertNotIn("prepare_issue_finalization_epoch", called)
        self.assertNotIn("publish_issue_final_success", called)
        self.assertNotIn("revoke_required_status_epoch", called)
        self.assertIn("def finalize_one_manual_pr(", source)


class Wave07CancellationControllerTests(unittest.TestCase):
    APP = Wave05ShaCarrierResolverTests.APP
    CENTRAL = Wave05ShaCarrierResolverTests.CENTRAL
    CENTRAL_NODE_ID = Wave05ShaCarrierResolverTests.CENTRAL_NODE_ID

    def _fixture(self, *, binding="FULL_BINDING", predecessor="CLAIM"):
        if binding == "PRE_BINDING":
            client, issue, anchor, lease = Wave05ShaCarrierResolverTests.make_client()
            state = None
        elif predecessor == "FINALIZING":
            client, issue, anchor, lease, state, _claim, _immediate, _epoch = (
                Wave05ShaCarrierResolverTests().make_finalization_epoch_client()
            )
        else:
            client, issue, anchor, lease, state, _claim = (
                Wave05ShaCarrierResolverTests().make_claim_client()
            )
        client.issue = replace(issue, state="closed")
        client.raw_pr_state = "open"
        client.raw_pr_merged = False
        client.status_rows = {}
        client.status_reads = []
        client.status_posts = []
        client.stage_calls = []
        client.stage_errors = {}
        client.stage_receipt_overrides = {}
        client.stage_accepts_before_error = set()
        client.events = []
        client.cas_outcomes = []
        client.cancel_comment_ids = []
        client.list_commit_statuses = lambda _repository, sha: (
            client.status_reads.append(sha) or tuple(client.status_rows.get(sha, ()))
        )

        original_create_comment = client.create_issue_comment

        def create_comment(repository, number, body):
            if body.startswith(ISSUE_CANCELLATION_FENCE_MARKER):
                client.events.append(("fence-comment", number, body))
                result = original_create_comment(repository, number, body)
                client.cancel_comment_ids.append(result.database_id)
                return result
            return original_create_comment(repository, number, body)

        client.create_issue_comment = create_comment

        def update_refs(repository_id, updates):
            update = tuple(updates)[0]
            client.events.append(("cas", repository_id, update))
            outcome = client.cas_outcomes.pop(0) if client.cas_outcomes else "success"
            if outcome == "other-head":
                client.current_ref = "3" * 40
                if client.pull_requests:
                    number = next(iter(client.pull_requests))
                    client.pull_requests[number] = replace(client.pull_requests[number], head_oid=client.current_ref)
                raise RefCASConflict("simulated competing writer")
            if outcome == "raise-nochange":
                raise RefCASConflict("simulated lost response without ref update")
            if (
                repository_id != self.CENTRAL_NODE_ID
                or update.name != issue_branch_ref(issue.number)
                or update.before_oid != client.current_ref
                or update.force is not False
            ):
                raise AssertionError("cancellation CAS must be exact and non-force")
            client.current_ref = None if update.after_oid == ZERO_OID else update.after_oid
            if client.pull_requests and update.after_oid != ZERO_OID:
                number = next(iter(client.pull_requests))
                client.pull_requests[number] = replace(client.pull_requests[number], head_oid=update.after_oid)
            return {}

        client.update_refs = update_refs

        def create_status(repository, sha, state, context, description, target_url=None):
            client.status_posts.append((repository, sha, state, context, description, target_url))
            if getattr(client, "status_write_error", None) is not None:
                raise client.status_write_error
            status = CommitStatus(
                201, "S201", state,
                context, description, target_url, self.APP.bot_id, self.APP.bot_node_id,
                self.APP.bot_login, "Bot", "2026-10-06T00:00:00Z", "2026-10-06T00:00:00Z",
            )
            if getattr(client, "status_receipt_override", None) is not None:
                return client.status_receipt_override
            client.status_rows[sha] = tuple(client.status_rows.get(sha, ())) + (status,)
            receipt = StatusWriteReceipt(
                repository, sha, "POST", f"/repos/{repository}/statuses/{sha}",
                state, context, description, target_url, status,
            )
            return receipt

        client.create_commit_status = create_status

        def stage_mutation(operation, pull_request_node_id, client_mutation_id):
            client.stage_calls.append((operation, pull_request_node_id, client_mutation_id))
            if operation in client.stage_errors and operation not in client.stage_accepts_before_error:
                raise client.stage_errors[operation]
            number = next(iter(client.pull_requests))
            current_pr = client.pull_requests[number]
            current_issue = client.pull_request_issues[number]
            if operation == "REOPEN":
                state, draft = "open", current_pr.draft
            elif operation == "READY_FOR_REVIEW":
                state, draft = "open", False
            elif operation == "CONVERT_TO_DRAFT":
                state, draft = "open", True
            elif operation == "CLOSE":
                state, draft = "closed", current_pr.draft
            else:
                raise AssertionError(f"unexpected PR-stage operation: {operation}")
            client.raw_pr_state = state
            client.pull_request_issues[number] = replace(current_issue, state=state)
            client.pull_requests[number] = replace(current_pr, draft=draft)
            database_id = client.pull_request_issues[number].database_id
            receipt = PullRequestStageMutationReceipt(
                operation,
                pull_request_node_id,
                client_mutation_id,
                client_mutation_id,
                current_issue.node_id,
                database_id,
                number,
                state.upper(),
                draft,
                False,
                None,
                current_pr.head_oid,
                current_pr.base_oid,
                current_pr.head_ref,
                current_pr.base_ref,
                current_pr.head_repository_id,
                current_pr.base_repository_id,
            )
            override = client.stage_receipt_overrides.get(operation)
            if override is not None:
                if callable(override):
                    return override(receipt)
                return override
            if operation in client.stage_errors:
                raise client.stage_errors[operation]
            return receipt

        client.reopen_pull_request = lambda node_id, mutation_id: stage_mutation(
            "REOPEN", node_id, mutation_id,
        )
        client.mark_pull_request_ready_for_review = lambda node_id, mutation_id: stage_mutation(
            "READY_FOR_REVIEW", node_id, mutation_id,
        )
        client.convert_pull_request_to_draft = lambda node_id, mutation_id: stage_mutation(
            "CONVERT_TO_DRAFT", node_id, mutation_id,
        )
        client.close_pull_request = lambda node_id, mutation_id: stage_mutation(
            "CLOSE", node_id, mutation_id,
        )
        controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
        controller.client = client
        controller.central_repository = self.CENTRAL
        controller.app = self.APP
        controller.candidate_builder = None
        controller.environ = {}
        return client, issue, anchor, lease, state, controller

    def _no_pr_fixture(self, *, with_lease=True, ref_state="absent", issue_state="closed"):
        client, issue, anchor, lease = Wave05ShaCarrierResolverTests.make_client()
        client.issue = replace(issue, state=issue_state)
        client.pull_requests.clear()
        client.pull_request_issues.clear()
        client.pr_comments.clear()
        if not with_lease:
            client.comments = [
                item for item in client.comments
                if not item.body.startswith(ISSUE_BRANCH_LEASE_MARKER)
            ]
            client.current_ref = None
            lease = None
        elif ref_state == "absent":
            client.current_ref = None
        elif ref_state == "root":
            client.current_ref = lease.lease.initial_head_sha
        elif ref_state == "drift":
            client.current_ref = "f" * 40
        else:
            raise AssertionError(ref_state)
        client.status_rows = {}
        client.status_reads = []
        client.check_rows = []
        client.list_commit_statuses = lambda _repository, sha: (
            client.status_reads.append(sha) or tuple(client.status_rows.get(sha, ()))
        )
        client.list_check_runs = lambda _repository, sha: tuple(
            check for check in client.check_rows if check.head_sha == sha
        )
        client.no_pr_ref_updates = []
        client.no_pr_cas_error = None

        def delete_lease_ref(repository_id, updates):
            updates = tuple(updates)
            client.no_pr_ref_updates.append((repository_id, updates))
            if (
                repository_id != self.CENTRAL_NODE_ID
                or len(updates) != 1
                or updates[0].name != issue_branch_ref(issue.number)
                or updates[0].before_oid != client.current_ref
                or updates[0].after_oid != ZERO_OID
                or updates[0].force is not False
            ):
                raise AssertionError("no-PR cleanup must use the exact non-force lease-ref CAS")
            if client.no_pr_cas_error is not None:
                raise client.no_pr_cas_error
            client.current_ref = None

        client.update_refs = delete_lease_ref
        controller = controller_module.R02Controller.__new__(controller_module.R02Controller)
        controller.client = client
        controller.central_repository = self.CENTRAL
        controller.app = self.APP
        controller.candidate_builder = None
        controller.environ = {}
        return client, issue, anchor, lease, controller

    def _prepare(self, *, binding="FULL_BINDING", predecessor="CLAIM", nonce="a" * 64):
        client, issue, anchor, lease, state, controller = self._fixture(
            binding=binding, predecessor=predecessor,
        )
        fence = controller.prepare_issue_cancellation_fence(
            issue.number,
            classification="D" if binding == "PRE_BINDING" else "E",
            nonce_factory=lambda: nonce,
        )
        return client, issue, anchor, lease, state, controller, fence

    @staticmethod
    def _exact_app_status(sha, *, state="success", status_class=StatusClass.ISSUE_FINAL, digest="a" * 64, status_id=10):
        return CommitStatus(
            status_id, f"S{status_id}", state, "federation/trusted-validation",
            render_status_description(status_class, digest), None,
            Wave07CancellationControllerTests.APP.bot_id,
            Wave07CancellationControllerTests.APP.bot_node_id,
            Wave07CancellationControllerTests.APP.bot_login,
            "Bot", "2026-10-06T00:00:00Z", "2026-10-06T00:00:00Z",
        )

    def _publish_cancel_failure(self, binding="FULL_BINDING", nonce="a" * 64):
        client, issue, anchor, lease, state, controller, fence = self._prepare(
            binding=binding, nonce=nonce,
        )
        status = controller.publish_issue_cancel_failure(issue.number, fence)
        return client, issue, anchor, lease, state, controller, fence, status

    @staticmethod
    def _set_pr_stage(client, *, state="open", draft=False, merged=False):
        number = next(iter(client.pull_requests))
        client.raw_pr_state = state
        client.raw_pr_merged = merged
        client.pull_request_issues[number] = replace(
            client.pull_request_issues[number], state=state,
        )
        client.pull_requests[number] = replace(
            client.pull_requests[number], draft=draft,
        )

    def test_full_and_prebinding_fence_creation_persists_before_nonforce_cas(self):
        for binding in ("FULL_BINDING", "PRE_BINDING"):
            with self.subTest(binding=binding):
                client, issue, _anchor, _lease, _state, _controller, fence = self._prepare(binding=binding)
                if binding == "PRE_BINDING":
                    self.assertEqual(fence.binding_authority, "PRE_BINDING")
                else:
                    self.assertEqual(fence.binding_authority, _state.binding.binding_id)
                self.assertEqual(fence.pre_fence_required_status.disposition, "ABSENT")
                self.assertEqual(fence.original_head_sha, fence.pre_fence_required_status.queried_sha)
                self.assertEqual(fence.original_head_tree_sha, fence.cancellation_head_tree_sha)
                self.assertEqual(client.current_ref, fence.cancellation_head_sha)
                self.assertEqual([event[0] for event in client.events], ["fence-comment", "cas"])
                resolution = Wave05ShaCarrierResolverTests.resolve(client, fence.cancellation_head_sha)
                self.assertEqual(
                    resolution,
                    ShaCarrierResolution(
                        CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL,
                        controller_module._issue_cancellation_fence_marker(fence),
                    ),
                )
                self.assertEqual(client.status_posts, [])

    def test_prebinding_never_fabricates_binding_and_crosschecks_central_pr_identity(self):
        client, issue, _anchor, _lease, _state, controller, fence = self._prepare(binding="PRE_BINDING")
        authority = controller_module._fresh_issue_cancellation_authority(
            client, self.CENTRAL, issue.number, self.APP,
        )
        self.assertIsNone(authority.binding)
        self.assertIsNone(authority.binding_state)
        self.assertEqual(
            (fence.pull_request_node_id, fence.pull_request_database_id, fence.pull_request_number),
            (authority.pr_issue.node_id, authority.pr_issue.database_id, authority.pr_issue.number),
        )
        changed_pr_issue = replace(authority.pr_issue, database_id=authority.pr_issue.database_id + 1)
        bad_authority = replace(authority, pr_issue=changed_pr_issue)
        with self.assertRaises(R02Error):
            controller_module._validate_issue_cancellation_fence_context(fence, bad_authority)

    def test_fence_comment_reader_accepts_exact_duplicates_and_rejects_foreign_edited_or_conflicting(self):
        client, issue, _anchor, _lease, _state, controller, fence = self._prepare()
        authority = controller_module._fresh_issue_cancellation_authority(
            client, self.CENTRAL, issue.number, self.APP,
        )
        comments = client.list_issue_comments(self.CENTRAL, fence.pull_request_number)
        duplicate = IssueAnchorControllerTests.comment(fence.render(), database_id=max(c.database_id for c in comments) + 1)
        client.pr_comments[fence.pull_request_number].append(duplicate)
        found = controller_module._issue_cancellation_fence_comments(
            client, self.CENTRAL, client.list_issue_comments(self.CENTRAL, fence.pull_request_number),
            self.APP, authority, fence.cancellation_head_sha,
        )
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].comment.database_id, client.cancel_comment_ids[0])

        human = IssueAnchorControllerTests.comment(
            fence.render(), database_id=20_001, author_id="U_human", author_login="human", author_type="User",
        )
        with self.assertRaises(R02Error):
            controller_module._issue_cancellation_fence_comments(
                client, self.CENTRAL, (*client.list_issue_comments(self.CENTRAL, fence.pull_request_number), human),
                self.APP, authority, fence.cancellation_head_sha,
            )
        edited = replace(duplicate, editor_id="B_editor", editor_login=self.APP.bot_login, editor_type="Bot")
        with self.assertRaises(R02Error):
            controller_module._issue_cancellation_fence_comments(
                client, self.CENTRAL, (edited,), self.APP, authority, fence.cancellation_head_sha,
            )

        fields = fence._fields()
        fields["cancellation_carrier_nonce"] = "d" * 64
        fields["cancellation_head_sha"] = "f" * 40 if fence.original_head_sha != "f" * 40 else "e" * 40
        seed = IssueCancellationFence.create(**fields)
        message = controller_module._issue_cancellation_fence_marker(seed).render()
        timestamp = IssueBranchLeaseControllerTests.CLAIM_DATE
        target = client.create_commit(
            self.CENTRAL, message, fence.original_head_tree_sha,
            [fence.original_head_sha], timestamp=timestamp,
        )
        alternate = IssueCancellationFence.create(**{**fields, "cancellation_head_sha": target.sha})
        controller_module._validate_issue_cancellation_fence_target(client, self.CENTRAL, alternate)
        conflict_comment = IssueAnchorControllerTests.comment(alternate.render(), database_id=20_002)
        with self.assertRaises(R02Error):
            controller_module._issue_cancellation_fence_comments(
                client, self.CENTRAL,
                (*client.list_issue_comments(self.CENTRAL, fence.pull_request_number), conflict_comment),
                self.APP, authority, fence.cancellation_head_sha,
            )

    def test_fence_target_parent_tree_and_marker_are_exact(self):
        client, _issue, _anchor, _lease, _state, _controller, fence = self._prepare()
        target = fence.cancellation_head_sha
        original = client.commit_metadata[target]
        for changed in (
            replace(original, parents=("5" * 40,)),
            replace(original, tree_sha="6" * 40),
        ):
            client.commit_metadata[target] = changed
            with self.assertRaises(R02Error):
                controller_module._validate_issue_cancellation_fence_target(client, self.CENTRAL, fence)
        client.commit_metadata[target] = original
        old_message = client.commit_messages[target]
        client.commit_messages[target] = old_message.replace(fence.cancellation_carrier_nonce, "b" * 64)
        with self.assertRaises(R02Error):
            controller_module._validate_issue_cancellation_fence_target(client, self.CENTRAL, fence)
        client.commit_messages[target] = old_message
        changed_fields = fence.as_value()
        changed_fields["claimGenerationId"] = "0" * 64
        # A copied marker cannot become a fence merely by retaining the target SHA.
        with self.assertRaises(Exception):
            parse_issue_cancellation_fence(
                ISSUE_CANCELLATION_FENCE_MARKER + "\n" + json.dumps(changed_fields, separators=(",", ":"), sort_keys=True) + "\n",
            )

    def test_pre_fence_success_snapshot_and_finalizing_predecessor_semantics(self):
        client, issue, _anchor, _lease, _state, controller = self._fixture()
        claim_head = client.current_ref
        client.status_rows[claim_head] = (
            self._exact_app_status(claim_head, status_id=80),
        )
        fence = controller.prepare_issue_cancellation_fence(
            issue.number, classification="E", nonce_factory=lambda: "b" * 64,
        )
        self.assertTrue(fence.pre_fence_success_may_exist)
        self.assertEqual(fence.pre_fence_required_status.status_class, StatusClass.ISSUE_FINAL)

        final_client, final_issue, _a, _l, _s, final_controller = self._fixture(predecessor="FINALIZING")
        final_fence = final_controller.prepare_issue_cancellation_fence(
            final_issue.number, classification="E", nonce_factory=lambda: "c" * 64,
        )
        self.assertEqual(final_fence.original_head_claim_kind, "ISSUE_FINALIZATION_EPOCH")
        self.assertEqual(final_fence.original_head_claim_role, "ISSUE_FINALIZING")
        self.assertTrue(final_fence.pre_fence_success_may_exist)
        self.assertEqual(final_fence.pre_fence_required_status.disposition, "ABSENT")

    def test_merge_observed_blocks_without_fence_nonce_comment_or_cas(self):
        client, issue, _anchor, _lease, _state, controller = self._fixture()
        client.raw_pr_merged = True
        nonce_calls = []
        with self.assertRaisesRegex(StaleAuthorityError, "CANCELLATION_MERGED_OBSERVED"):
            controller.prepare_issue_cancellation_fence(
                issue.number, classification="E",
                nonce_factory=lambda: nonce_calls.append("called") or "d" * 64,
            )
        self.assertEqual(nonce_calls, [])
        self.assertEqual(client.cancel_comment_ids, [])
        self.assertFalse(any(event[0] == "cas" for event in client.events))

    def test_crash_after_fence_post_reuses_exact_snapshot_nonce_and_target(self):
        client, issue, _anchor, _lease, state, controller = self._fixture()
        client.cas_outcomes = ["raise-nochange", "raise-nochange"]
        with self.assertRaises(StaleAuthorityError):
            controller.prepare_issue_cancellation_fence(
                issue.number, classification="E", nonce_factory=lambda: "e" * 64,
            )
        first_fence = parse_issue_cancellation_fence(
            next(item.body for item in client.pr_comments[81] if item.body.startswith(ISSUE_CANCELLATION_FENCE_MARKER)),
        )
        self.assertEqual(len(client.status_reads), 1)
        client.cas_outcomes = []
        replay = controller.prepare_issue_cancellation_fence(
            issue.number, classification="E",
            nonce_factory=lambda: self.fail("replay must not request a new nonce"),
        )
        self.assertEqual(replay, first_fence)
        self.assertEqual(client.status_reads, [first_fence.original_head_sha])
        self.assertEqual(client.cancel_comment_ids, [client.cancel_comment_ids[0]])
        self.assertEqual(client.current_ref, first_fence.cancellation_head_sha)

    def test_losing_cas_to_other_head_leaves_only_historical_fence_and_blocks_progression(self):
        client, issue, _anchor, _lease, state, controller = self._fixture()
        client.cas_outcomes = ["other-head"]
        with self.assertRaises(StaleAuthorityError):
            controller.prepare_issue_cancellation_fence(
                issue.number, classification="E", nonce_factory=lambda: "f" * 64,
            )
        self.assertEqual(len(client.cancel_comment_ids), 1)
        self.assertEqual(client.status_posts, [])
        self.assertEqual(client.current_ref, "3" * 40)
        # The persisted fence blocks after the owner Issue is reopened as well.
        client.issue = replace(client.issue, state="open")
        with self.assertRaises(StaleAuthorityError):
            controller._require_no_issue_cancellation_fence(state, state.pr.head_oid)
        self.assertEqual(client.status_posts, [])

    def test_pending_fence_is_one_way_gate_for_proposal_finalization_and_revocation(self):
        client, issue, _anchor, _lease, state, controller = self._fixture()
        original_ref = client.current_ref
        client.cas_outcomes = ["raise-nochange", "raise-nochange"]
        with self.assertRaises(StaleAuthorityError):
            controller.prepare_issue_cancellation_fence(
                issue.number, classification="E", nonce_factory=lambda: "9" * 64,
            )
        client.issue = replace(client.issue, state="open")
        controller.candidate_builder = object()
        with self.assertRaises(StaleAuthorityError):
            controller.interactive_issue_managed_proposal(issue.number, IssueAnchorControllerTests.resolver())
        with self.assertRaises(StaleAuthorityError):
            controller.prepare_issue_finalization_epoch(issue.number, IssueAnchorControllerTests.resolver())
        with self.assertRaises(StaleAuthorityError):
            controller.revoke_required_status_epoch(
                issue.number, RequiredStatusEpochReason.ACTIVE_REVALIDATION,
                IssueAnchorControllerTests.resolver(),
            )
        self.assertEqual(client.current_ref, original_ref)
        self.assertEqual(client.status_posts, [])

    def test_exact_cancel_failure_receipt_and_idempotent_status_recovery(self):
        client, issue, _anchor, _lease, _state, controller, fence = self._prepare()
        evidence = controller.publish_issue_cancel_failure(issue.number, fence)
        self.assertEqual(evidence.queried_sha, fence.cancellation_head_sha)
        self.assertEqual(evidence.state, "failure")
        self.assertEqual(evidence.status_class, StatusClass.CANCEL)
        self.assertEqual(len(evidence.description.encode("ascii")), 81)
        self.assertEqual(
            client.status_posts,
            [(self.CENTRAL, fence.cancellation_head_sha, "failure", "federation/trusted-validation", evidence.description, None)],
        )
        row = self._exact_app_status(
            fence.cancellation_head_sha, state="failure", status_class=StatusClass.CANCEL,
            digest=evidence.evidence_digest, status_id=201,
        )
        client.status_rows[fence.cancellation_head_sha] = (row, row)
        reused = controller.publish_issue_cancel_failure(issue.number, fence)
        self.assertEqual(reused, evidence)
        self.assertEqual(len(client.status_posts), 1)

    def test_cancel_status_blocks_success_and_wrong_digest_and_never_reads_after_transport_error(self):
        for current in (
            self._exact_app_status("a" * 40, state="success", status_class=StatusClass.ISSUE_FINAL),
            self._exact_app_status("a" * 40, state="failure", status_class=StatusClass.CANCEL, digest="0" * 64),
        ):
            client, issue, _anchor, _lease, _state, controller, fence = self._prepare(nonce="7" * 64)
            client.status_rows[fence.cancellation_head_sha] = (replace(current, id=401, node_id="S401"),)
            with self.assertRaises(StaleAuthorityError):
                controller.publish_issue_cancel_failure(issue.number, fence)
            self.assertEqual(client.status_posts, [])

        client, issue, _anchor, _lease, _state, controller, fence = self._prepare(nonce="8" * 64)
        client.status_reads.clear()
        client.status_write_error = TransportError("response lost")
        with self.assertRaises(TransportError):
            controller.publish_issue_cancel_failure(issue.number, fence)
        self.assertEqual(client.status_reads, [fence.cancellation_head_sha])
        self.assertEqual(len(client.status_posts), 1)

    def test_stage_mutation_receipts_crosscheck_node_database_and_number_in_both_authorities(self):
        for binding in ("PRE_BINDING", "FULL_BINDING"):
            with self.subTest(binding=binding):
                client, issue, _anchor, _lease, _state, controller, fence = self._prepare(binding=binding)
                authority = controller_module._fresh_issue_cancellation_authority(
                    client, self.CENTRAL, issue.number, self.APP,
                )
                receipt = PullRequestStageMutationReceipt(
                    "CLOSE", fence.pull_request_node_id, "mutation-1", "mutation-1",
                    fence.pull_request_node_id, fence.pull_request_database_id, fence.pull_request_number,
                    "CLOSED", False, False, None, fence.cancellation_head_sha,
                    authority.pr.base_oid, authority.pr.head_ref, authority.pr.base_ref,
                    authority.central_repository_node_id, authority.central_repository_node_id,
                )
                self.assertIs(
                    controller_module._require_exact_cancellation_stage_receipt_identity(receipt, authority, fence),
                    receipt,
                )
                for bad in (
                    replace(receipt, pull_request_database_id=receipt.pull_request_database_id + 1),
                    replace(receipt, pull_request_number=receipt.pull_request_number + 1),
                    replace(
                        receipt,
                        requested_pull_request_node_id="PR_wrong",
                        pull_request_node_id="PR_wrong",
                    ),
                ):
                    with self.assertRaises(R02Error):
                        controller_module._require_exact_cancellation_stage_receipt_identity(bad, authority, fence)

    def test_draft_witness_normalizes_open_ready_pr_from_exact_convert_receipt(self):
        client, issue, _anchor, _lease, state, controller, fence, status = self._publish_cancel_failure()
        witness = controller.establish_issue_cancellation_draft_witness(issue.number)
        self.assertEqual([row[0] for row in client.stage_calls], ["CONVERT_TO_DRAFT"])
        self.assertEqual(witness.binding_authority, state.binding.binding_id)
        self.assertEqual(witness.current_required_status.status_id, status.status_id)
        self.assertEqual(witness.draft_evidence.pull_request_database_id, fence.pull_request_database_id)
        self.assertEqual(witness.draft_evidence.pull_request_node_id, fence.pull_request_node_id)
        self.assertEqual(witness.draft_evidence.state, "OPEN")
        self.assertTrue(witness.draft_evidence.is_draft)
        persisted = [
            parse_issue_cancellation_draft_witness(item.body)
            for item in client.pr_comments[fence.pull_request_number]
            if item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
        ]
        self.assertEqual(persisted, [witness])

    def test_draft_witness_ready_reopen_and_prebinding_stage_sequences(self):
        scenarios = (
            ("open", True, "FULL_BINDING", ["READY_FOR_REVIEW", "CONVERT_TO_DRAFT"]),
            ("closed", False, "FULL_BINDING", ["REOPEN", "CONVERT_TO_DRAFT"]),
            ("closed", True, "FULL_BINDING", ["REOPEN", "READY_FOR_REVIEW", "CONVERT_TO_DRAFT"]),
            ("open", False, "PRE_BINDING", ["CONVERT_TO_DRAFT"]),
        )
        for state_name, draft, binding, operations in scenarios:
            with self.subTest(state=state_name, draft=draft, binding=binding):
                nonce = ("b" if state_name == "open" and draft else "c") * 64
                client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(
                    binding=binding, nonce=nonce,
                )
                self._set_pr_stage(client, state=state_name, draft=draft)
                witness = controller.establish_issue_cancellation_draft_witness(issue.number)
                self.assertEqual([row[0] for row in client.stage_calls], operations)
                self.assertEqual(witness.binding_authority, binding if binding == "PRE_BINDING" else _s.binding.binding_id)
                self.assertEqual(witness.reopen_evidence is not None, state_name == "closed")
                self.assertEqual(witness.ready_evidence is not None, draft)
                self.assertEqual(witness.draft_evidence.pull_request_database_id, fence.pull_request_database_id)

    def test_terminal_cancelled_result_closes_exact_witnessed_pr_and_replays_without_mutation(self):
        for binding in ("FULL_BINDING", "PRE_BINDING"):
            with self.subTest(binding=binding):
                nonce = "d" * 64 if binding == "FULL_BINDING" else "e" * 64
                client, issue, _a, _l, _state, controller, fence, _status = self._publish_cancel_failure(
                    binding=binding, nonce=nonce,
                )
                controller.establish_issue_cancellation_draft_witness(issue.number)
                result = controller.establish_issue_terminal_cancelled_result(issue.number)
                self.assertEqual([row[0] for row in client.stage_calls], ["CONVERT_TO_DRAFT", "CLOSE"])
                self.assertEqual(result.binding_authority, binding if binding == "PRE_BINDING" else _state.binding.binding_id)
                self.assertEqual(result.close_evidence.pull_request_database_id, fence.pull_request_database_id)
                self.assertEqual(result.close_evidence.pull_request_node_id, fence.pull_request_node_id)
                self.assertEqual(result.close_evidence.state, "CLOSED")
                self.assertFalse(result.close_evidence.merged)
                self.assertEqual(result.proof_kind.value, "PR_BACKED_PRE_BINDING" if binding == "PRE_BINDING" else "PR_BACKED_FULL_BINDING")
                replay = controller.establish_issue_terminal_cancelled_result(issue.number)
                self.assertEqual(replay, result)
                self.assertEqual([row[0] for row in client.stage_calls], ["CONVERT_TO_DRAFT", "CLOSE"])

    def test_terminal_result_reopens_closed_pr_and_closes_with_same_response_evidence(self):
        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce="f" * 64)
        controller.establish_issue_cancellation_draft_witness(issue.number)
        self._set_pr_stage(client, state="closed", draft=True)
        result = controller.establish_issue_terminal_cancelled_result(issue.number)
        self.assertEqual([row[0] for row in client.stage_calls], ["CONVERT_TO_DRAFT", "REOPEN", "CLOSE"])
        self.assertEqual(result.close_evidence.pull_request_number, fence.pull_request_number)
        self.assertEqual(result.close_evidence.pull_request_database_id, fence.pull_request_database_id)
        self.assertEqual(result.close_evidence.state, "CLOSED")

    def test_draft_witness_requires_current_failure_and_active_unmerged_authority(self):
        client, issue, _a, _l, _s, controller, fence = self._prepare(nonce="1" * 64)
        self._set_pr_stage(client, draft=True)
        with self.assertRaises(StaleAuthorityError):
            controller.establish_issue_cancellation_draft_witness(issue.number)
        self.assertEqual(client.stage_calls, [])
        self.assertFalse(any(
            item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
            for item in client.pr_comments[fence.pull_request_number]
        ))

        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce="2" * 64)
        self._set_pr_stage(client, merged=True)
        with self.assertRaises(StaleAuthorityError):
            controller.establish_issue_cancellation_draft_witness(issue.number)
        self.assertEqual(client.stage_calls, [])
        self.assertFalse(any(
            item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
            for item in client.pr_comments[fence.pull_request_number]
        ))

    def test_draft_witness_mutation_errors_and_wrong_same_response_are_never_inferred_from_get(self):
        cases = (
            ("REOPEN", "closed", False, None),
            ("READY_FOR_REVIEW", "open", True, None),
            ("CONVERT_TO_DRAFT", "open", False, None),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-head"),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-database-id"),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-node-id"),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-number"),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-base"),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-repository"),
            ("CONVERT_TO_DRAFT", "open", False, "wrong-stage-state"),
            ("CONVERT_TO_DRAFT", "open", False, "merged"),
        )
        for index, (operation, pr_state, is_draft, response_fault) in enumerate(cases, 1):
            with self.subTest(operation=operation, fault=response_fault):
                nonce = f"{index:064x}"
                client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce=nonce)
                self._set_pr_stage(client, state=pr_state, draft=is_draft)
                error = TransportError("mutation response unavailable")
                client.stage_errors[operation] = error
                if response_fault is not None:
                    client.stage_errors.pop(operation, None)

                    def corrupt(receipt, fault=response_fault):
                        if fault == "wrong-head":
                            return replace(receipt, head_oid="f" * 40 if receipt.head_oid != "f" * 40 else "e" * 40)
                        if fault == "wrong-database-id":
                            return replace(receipt, pull_request_database_id=receipt.pull_request_database_id + 1)
                        if fault == "wrong-node-id":
                            return replace(
                                receipt, requested_pull_request_node_id="PR_wrong",
                                pull_request_node_id="PR_wrong",
                            )
                        if fault == "wrong-number":
                            return replace(receipt, pull_request_number=receipt.pull_request_number + 1)
                        if fault == "wrong-base":
                            return replace(receipt, base_ref="release")
                        if fault == "wrong-repository":
                            return replace(receipt, head_repository_node_id="R_other")
                        if fault == "wrong-stage-state":
                            return replace(receipt, is_draft=False)
                        if fault == "merged":
                            return replace(receipt, merged=True, merged_at="2026-10-06T01:00:00Z")
                        raise AssertionError(fault)

                    client.stage_receipt_overrides[operation] = corrupt
                with self.assertRaises((R02Error, StaleAuthorityError)):
                    controller.establish_issue_cancellation_draft_witness(issue.number)
                self.assertFalse(any(
                    item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
                    for item in client.pr_comments[fence.pull_request_number]
                ))

    def test_draft_witness_rechecks_failure_after_ready_and_lost_convert_requires_real_retry(self):
        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce="3" * 64)
        self._set_pr_stage(client, draft=True)
        original_ready = client.mark_pull_request_ready_for_review

        def ready_then_success(node_id, mutation_id):
            receipt = original_ready(node_id, mutation_id)
            client.status_rows[fence.cancellation_head_sha] = (
                self._exact_app_status(
                    fence.cancellation_head_sha, state="success", status_class=StatusClass.CANCEL,
                    digest=controller_module.cancel_status_evidence_digest(
                        central_repository_node_id=fence.central_repository_node_id,
                        issue_number=fence.issue_number, issue_database_id=fence.issue_database_id,
                        issue_node_id=fence.issue_node_id, fence_id=fence.fence_id,
                        cancellation_head_sha=fence.cancellation_head_sha,
                        binding_authority=fence.binding_authority,
                        pull_request_number=fence.pull_request_number,
                        pull_request_database_id=fence.pull_request_database_id,
                        pull_request_node_id=fence.pull_request_node_id,
                    ), status_id=902,
                ),
            )
            return receipt

        client.mark_pull_request_ready_for_review = ready_then_success
        with self.assertRaises(StaleAuthorityError):
            controller.establish_issue_cancellation_draft_witness(issue.number)
        self.assertEqual([row[0] for row in client.stage_calls], ["READY_FOR_REVIEW"])
        self.assertFalse(any(
            item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
            for item in client.pr_comments[fence.pull_request_number]
        ))

        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce="4" * 64)
        client.stage_errors["CONVERT_TO_DRAFT"] = TransportError("accepted response lost")
        client.stage_accepts_before_error.add("CONVERT_TO_DRAFT")
        with self.assertRaises(StaleAuthorityError):
            controller.establish_issue_cancellation_draft_witness(issue.number)
        self.assertTrue(client.pull_requests[fence.pull_request_number].draft)
        self.assertFalse(any(
            item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
            for item in client.pr_comments[fence.pull_request_number]
        ))
        client.stage_errors.clear()
        client.stage_accepts_before_error.clear()
        witness = controller.establish_issue_cancellation_draft_witness(issue.number)
        self.assertEqual([row[0] for row in client.stage_calls], [
            "CONVERT_TO_DRAFT", "READY_FOR_REVIEW", "CONVERT_TO_DRAFT",
        ])
        self.assertTrue(witness.draft_evidence.is_draft)

    def test_existing_witness_is_immutable_across_pr_state_and_duplicate_exact_comments(self):
        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce="5" * 64)
        witness = controller.establish_issue_cancellation_draft_witness(issue.number)
        original_calls = list(client.stage_calls)
        witness_comment = next(
            item for item in client.pr_comments[fence.pull_request_number]
            if item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
        )
        client.pr_comments[fence.pull_request_number].append(
            replace(witness_comment, database_id=witness_comment.database_id + 50_000),
        )
        self._set_pr_stage(client, state="closed", draft=False)
        self.assertEqual(controller.establish_issue_cancellation_draft_witness(issue.number), witness)
        self.assertEqual(client.stage_calls, original_calls)

        conflicting_base_oid = "8" * 40 if witness.returned_base_ref_oid != "8" * 40 else "9" * 40
        conflicting = IssueCancellationDraftWitness.create(
            **{
                **witness._fields(),
                "witness_id": "0" * 64,
                "returned_base_ref_oid": conflicting_base_oid,
                "draft_evidence": replace(witness.draft_evidence, base_ref_oid=conflicting_base_oid),
            },
        )
        client.pr_comments[fence.pull_request_number].append(
            IssueAnchorControllerTests.comment(
                conflicting.render(), database_id=witness_comment.database_id + 60_000,
            ),
        )
        with self.assertRaises(R02Error):
            controller.establish_issue_cancellation_draft_witness(issue.number)

    def test_terminal_result_rejects_wrong_close_receipt_status_change_and_merge_race(self):
        for index, fault in enumerate(("wrong-head", "wrong-base", "wrong-repository", "wrong-db", "merged", "status-before", "status-after", "merged-after", "close-response-lost"), 1):
            with self.subTest(fault=fault):
                client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(
                    nonce=f"{index + 10:064x}",
                )
                controller.establish_issue_cancellation_draft_witness(issue.number)
                if fault == "status-before":
                    self._set_pr_stage(client, state="closed", draft=True)
                    original_reopen = client.reopen_pull_request

                    def reopen_then_success(node_id, mutation_id):
                        receipt = original_reopen(node_id, mutation_id)
                        client.status_rows[fence.cancellation_head_sha] = (
                            self._exact_app_status(
                                fence.cancellation_head_sha, state="success", status_class=StatusClass.CANCEL,
                                digest="0" * 64, status_id=950,
                            ),
                        )
                        return receipt

                    client.reopen_pull_request = reopen_then_success
                elif fault == "status-after":
                    original_close = client.close_pull_request

                    def close_then_success(node_id, mutation_id):
                        receipt = original_close(node_id, mutation_id)
                        client.status_rows[fence.cancellation_head_sha] = (
                            self._exact_app_status(
                                fence.cancellation_head_sha, state="failure", status_class=StatusClass.CANCEL,
                                digest="0" * 64, status_id=951,
                            ),
                        )
                        return receipt

                    client.close_pull_request = close_then_success
                elif fault == "merged-after":
                    original_close = client.close_pull_request

                    def close_then_merge(node_id, mutation_id):
                        receipt = original_close(node_id, mutation_id)
                        client.raw_pr_merged = True
                        return receipt

                    client.close_pull_request = close_then_merge
                elif fault == "close-response-lost":
                    client.stage_errors["CLOSE"] = TransportError("close accepted but response lost")
                    client.stage_accepts_before_error.add("CLOSE")
                else:
                    def corrupt_close(receipt):
                        if fault == "wrong-head":
                            return replace(receipt, head_oid="f" * 40 if receipt.head_oid != "f" * 40 else "e" * 40)
                        if fault == "wrong-base":
                            return replace(receipt, base_ref="release")
                        if fault == "wrong-repository":
                            return replace(receipt, base_repository_node_id="R_other")
                        if fault == "wrong-db":
                            return replace(receipt, pull_request_database_id=receipt.pull_request_database_id + 1)
                        if fault == "merged":
                            return replace(receipt, merged=True, merged_at="2026-10-06T01:00:00Z")
                        raise AssertionError(fault)

                    client.stage_receipt_overrides["CLOSE"] = corrupt_close
                with self.assertRaises((R02Error, StaleAuthorityError)):
                    controller.establish_issue_terminal_cancelled_result(issue.number)
                self.assertFalse(any(
                    item.body.startswith(ISSUE_TERMINAL_CANCELLED_RESULT_MARKER)
                    for item in client.pr_comments[fence.pull_request_number]
                ))

    def test_cancellation_stage_mutation_ids_are_exactly_replayable_and_stage_specific(self):
        _client, _issue, _a, _l, _s, _controller, fence = self._prepare(nonce="7" * 64)
        convert_id = controller_module._cancellation_stage_client_mutation_id(fence, "DRAFT_CONVERT")
        self.assertEqual(
            controller_module._cancellation_stage_client_mutation_id(fence, "DRAFT_CONVERT"),
            convert_id,
        )
        self.assertNotEqual(
            convert_id,
            controller_module._cancellation_stage_client_mutation_id(fence, "TERMINAL_CLOSE"),
        )
        other_fence = IssueCancellationFence.create(
            **{**fence._fields(), "fence_id": "0" * 64, "cancellation_carrier_nonce": "8" * 64},
        )
        self.assertNotEqual(
            convert_id,
            controller_module._cancellation_stage_client_mutation_id(other_fence, "DRAFT_CONVERT"),
        )

    def test_terminal_result_conflicts_replay_and_human_ready_do_not_reacquire_witness_or_close(self):
        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce="6" * 64)
        witness = controller.establish_issue_cancellation_draft_witness(issue.number)
        self._set_pr_stage(client, draft=False)
        result = controller.establish_issue_terminal_cancelled_result(issue.number)
        calls_after_close = list(client.stage_calls)
        self.assertEqual([row[0] for row in calls_after_close], ["CONVERT_TO_DRAFT", "CLOSE"])
        self.assertEqual(result.witness_id, witness.witness_id)
        self.assertEqual(controller.establish_issue_terminal_cancelled_result(issue.number), result)
        self.assertEqual(client.stage_calls, calls_after_close)

        result_comment = next(
            item for item in client.pr_comments[fence.pull_request_number]
            if item.body.startswith(ISSUE_TERMINAL_CANCELLED_RESULT_MARKER)
        )
        client.pr_comments[fence.pull_request_number].append(
            replace(result_comment, database_id=result_comment.database_id + 70_000),
        )
        self.assertEqual(controller.establish_issue_terminal_cancelled_result(issue.number), result)

        bad = parse_issue_terminal_cancelled_result(result_comment.body)
        changed_fields = {**bad._fields(), "terminal_result_id": "0" * 64, "outcome": "CANCELLED"}
        # A canonical but conflicting terminal claim cannot replace the first.
        changed_fields["draft_witness_comment_database_id"] = bad.draft_witness_comment_database_id + 1
        conflicting = IssueTerminalCancelledResult.create(**changed_fields)
        client.pr_comments[fence.pull_request_number].append(
            IssueAnchorControllerTests.comment(
                conflicting.render(), database_id=result_comment.database_id + 80_000,
            ),
        )
        with self.assertRaises(R02Error):
            controller.establish_issue_terminal_cancelled_result(issue.number)

    def test_task04_components_do_not_delete_branches(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        names = {item.name: item for item in tree.body if isinstance(item, ast.ClassDef)}
        controller = names["R02Controller"]
        methods = {
            node.name: node for node in controller.body
            if isinstance(node, ast.FunctionDef)
        }
        selected = (
            "establish_issue_cancellation_draft_witness",
            "establish_issue_terminal_cancelled_result",
            "_persist_issue_cancellation_draft_witness",
            "_persist_issue_terminal_cancelled_result",
        )
        for name in selected:
            with self.subTest(method=name):
                called = {
                    item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
                    for item in ast.walk(methods[name])
                    if isinstance(item, ast.Call)
                    and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
                }
                self.assertFalse(called & {"delete_ref", "delete_branch", "delete_git_ref"})

    def test_cancellation_callables_are_not_activated_by_main_or_workflows(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        main = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "main")
        called = {
            item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
            for item in ast.walk(main)
            if isinstance(item, ast.Call)
            and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
        }
        self.assertNotIn("prepare_issue_cancellation_fence", called)
        self.assertNotIn("publish_issue_cancel_failure", called)
        self.assertNotIn("establish_issue_cancellation_draft_witness", called)
        self.assertNotIn("establish_issue_terminal_cancelled_result", called)

    def test_terminal_classifier_classifies_A_through_E_without_source_eligibility(self):
        cases = (
            (*self._no_pr_fixture(with_lease=False), controller_module.IssueCancellationClass.A_ANCHOR_ONLY),
            (*self._no_pr_fixture(with_lease=True, ref_state="absent"), controller_module.IssueCancellationClass.B_LEASE_REF_ABSENT),
            (*self._no_pr_fixture(with_lease=True, ref_state="root"), controller_module.IssueCancellationClass.C_LEASE_ZERO_PR),
        )
        for client, _issue, _anchor, _lease, controller, expected in cases:
            with self.subTest(expected=expected):
                with patch.object(controller_module, "resolve_issue_source_authority", side_effect=AssertionError("source lookup forbidden")):
                    state = controller._read_issue_cancellation_state(7)
                self.assertIs(state.classification, expected)
                self.assertFalse(state.pr_candidates)

        for binding, expected in (
            ("PRE_BINDING", controller_module.IssueCancellationClass.D_PRE_BINDING_ONE_PR),
            ("FULL_BINDING", controller_module.IssueCancellationClass.E_FULL_BINDING),
        ):
            with self.subTest(binding=binding):
                client, issue, _a, _l, _s, controller, _fence = self._prepare(binding=binding)
                with patch.object(controller_module, "resolve_issue_source_authority", side_effect=AssertionError("source lookup forbidden")):
                    state = controller._read_issue_cancellation_state(issue.number)
                self.assertIs(state.classification, expected)
                self.assertEqual(len(state.pr_candidates), 1)
                client.raw_pr_merged = True
                client.raw_pr_merged_at = "2026-10-06T01:00:00Z"
                merged = controller._read_issue_cancellation_state(issue.number)
                self.assertTrue(merged.merge_observed)
                self.assertIs(merged.classification, expected)

    def test_terminal_classifier_rejects_hidden_pr_ref_drift_multiple_and_inconsistent_binding(self):
        client, _issue, _anchor, _lease, controller = self._no_pr_fixture(with_lease=False)
        client.add_candidate()
        self.assertIs(
            controller._read_issue_cancellation_state(7).classification,
            controller_module.IssueCancellationClass.F_CONFLICTING,
        )

        client, _issue, _anchor, _lease, controller = self._no_pr_fixture(ref_state="drift")
        self.assertIs(
            controller._read_issue_cancellation_state(7).classification,
            controller_module.IssueCancellationClass.F_CONFLICTING,
        )

        client, _issue, _anchor, _lease, _state, controller, _fence = self._prepare(binding="PRE_BINDING")
        client.add_candidate(number=82)
        self.assertIs(
            controller._read_issue_cancellation_state(7).classification,
            controller_module.IssueCancellationClass.F_CONFLICTING,
        )

        client, _issue, _anchor, _lease, _state, controller, _fence = self._prepare(binding="PRE_BINDING")
        number = next(iter(client.pull_requests))
        client.pull_requests[number] = replace(client.pull_requests[number], head_repository_id="R_foreign")
        self.assertIs(
            controller._read_issue_cancellation_state(7).classification,
            controller_module.IssueCancellationClass.F_CONFLICTING,
        )

        client, _issue, _anchor, _lease, _state, controller, _fence = self._prepare(binding="FULL_BINDING")
        original = next(item for item in client.comments if item.body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER))
        binding = parse_issue_internal_pr_binding(original.body)
        binding_fields = binding.as_value(include_binding_id=False)
        inconsistent = IssuePRBinding.create(**{
            "schema_version": binding_fields["schemaVersion"],
            "issue_number": binding_fields["issueNumber"],
            "issue_database_id": binding_fields["issueDatabaseId"],
            "issue_node_id": binding_fields["issueNodeId"],
            "issue_request_anchor_comment_database_id": binding_fields["issueRequestAnchorCommentDatabaseId"],
            "issue_request_anchor_sha256": binding_fields["issueRequestAnchorSha256"],
            "issue_branch_lease_comment_database_id": binding_fields["issueBranchLeaseCommentDatabaseId"],
            "issue_branch_lease_sha256": binding_fields["issueBranchLeaseSha256"],
            "source_id": binding_fields["sourceId"],
            "source_repository_id": binding_fields["sourceRepositoryId"],
            "branch_ref": binding_fields["branchRef"],
            "pull_request_number": binding_fields["pullRequestNumber"],
            "pull_request_database_id": binding_fields["pullRequestDatabaseId"] + 1,
            "pull_request_node_id": binding_fields["pullRequestNodeId"],
            "initial_head_sha": binding_fields["initialHeadSha"],
            "base_ref": binding_fields["baseRef"],
            "central_repository_node_id": binding_fields["centralRepositoryNodeId"],
        })
        client.comments[client.comments.index(original)] = replace(
            original, body=inconsistent.render_issue_binding(),
        )
        self.assertIs(
            controller._read_issue_cancellation_state(7).classification,
            controller_module.IssueCancellationClass.F_CONFLICTING,
        )

    def test_no_pr_A_B_results_are_exact_idempotent_and_do_not_mutate_refs(self):
        client, issue, _anchor, _lease, controller = self._no_pr_fixture(with_lease=False)
        result = controller.cancel_issue_without_pr(issue.number)
        self.assertIs(result.proof_kind, IssueNoPRCancelledProofKind.ANCHOR_ONLY)
        self.assertEqual(controller.cancel_issue_without_pr(issue.number), result)
        self.assertEqual(client.no_pr_ref_updates, [])
        client.issue = replace(client.issue, state="open")
        self.assertEqual(controller.cancel_issue_without_pr(issue.number), result)

        client, issue, _anchor, _lease, controller = self._no_pr_fixture(ref_state="absent")
        result = controller.cancel_issue_without_pr(issue.number)
        self.assertIs(result.proof_kind, IssueNoPRCancelledProofKind.LEASE_REF_ABSENT)
        self.assertIsNone(client.current_ref)
        self.assertEqual(client.no_pr_ref_updates, [])
        self.assertEqual(controller.cancel_issue_without_pr(issue.number), result)

    def test_no_pr_C_uses_exact_zero_pr_status_check_and_nonforce_cas_proof(self):
        for status_state in (None, "pending", "failure", "error"):
            with self.subTest(status_state=status_state):
                client, issue, _anchor, lease, controller = self._no_pr_fixture(ref_state="root")
                if status_state is not None:
                    client.status_rows[lease.lease.initial_head_sha] = (
                        self._exact_app_status(
                            lease.lease.initial_head_sha, state=status_state,
                            status_class=StatusClass.ISSUE_FINAL, status_id=301,
                        ),
                    )
                inventory_reads = []
                original_inventory = client.list_pull_requests

                def count_inventory(repository, *, state="all", max_pages=100):
                    inventory_reads.append(state)
                    return original_inventory(repository, state=state, max_pages=max_pages)

                client.list_pull_requests = count_inventory
                result = controller.cancel_issue_without_pr(issue.number)
                self.assertIs(result.proof_kind, IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS)
                self.assertEqual(result.cleanup_before_oid, lease.lease.initial_head_sha)
                self.assertTrue(result.cleanup_ref_absent_after)
                self.assertEqual(result.required_status.queried_sha, lease.lease.initial_head_sha)
                self.assertGreaterEqual(len(inventory_reads), 2)
                self.assertTrue(all(item == "all" for item in inventory_reads))
                self.assertIsNone(client.current_ref)
                repository_id, updates = client.no_pr_ref_updates[0]
                self.assertEqual(repository_id, self.CENTRAL_NODE_ID)
                self.assertEqual(len(updates), 1)
                self.assertEqual(updates[0].before_oid, lease.lease.initial_head_sha)
                self.assertEqual(updates[0].after_oid, ZERO_OID)
                self.assertFalse(updates[0].force)
                self.assertEqual(controller.cancel_issue_without_pr(issue.number), result)

    def test_no_pr_C_success_check_mixed_carrier_and_cas_conflict_never_persist_result(self):
        cases = ("status-success", "check-success", "mixed", "cas-conflict")
        for case in cases:
            with self.subTest(case=case):
                client, issue, _anchor, lease, controller = self._no_pr_fixture(ref_state="root")
                if case in {"status-success", "mixed"}:
                    client.status_rows[lease.lease.initial_head_sha] = (
                        self._exact_app_status(
                            lease.lease.initial_head_sha, state="success",
                            status_class=StatusClass.ISSUE_FINAL, status_id=401,
                        ),
                    )
                if case in {"check-success", "mixed"}:
                    client.check_rows = [CheckRun(
                        11, "federation/trusted-validation", lease.lease.initial_head_sha,
                        "completed", "success", self.APP.app_id,
                    )]
                if case == "cas-conflict":
                    client.no_pr_cas_error = RefCASConflict("competing lease-ref deletion")
                with self.assertRaises((R02Error, StaleAuthorityError)):
                    controller.cancel_issue_without_pr(issue.number)
                self.assertEqual(client.current_ref, lease.lease.initial_head_sha if case == "cas-conflict" else lease.lease.initial_head_sha)
                self.assertFalse(any(item.body.startswith(controller_module.ISSUE_NO_PR_CANCELLED_RESULT_MARKER) for item in client.comments))

    def test_no_pr_C_reclassifies_when_pr_appears_and_rejects_bad_lease_marker(self):
        client, issue, _anchor, lease, controller = self._no_pr_fixture(ref_state="root")
        original_inventory = client.list_pull_requests
        calls = []

        def add_pr_on_recheck(repository, *, state="all", max_pages=100):
            calls.append(state)
            if len(calls) == 2:
                client.add_candidate()
            return original_inventory(repository, state=state, max_pages=max_pages)

        client.list_pull_requests = add_pr_on_recheck
        with self.assertRaises((R02Error, StaleAuthorityError)):
            controller.cancel_issue_without_pr(issue.number)
        self.assertEqual(client.no_pr_ref_updates, [])
        self.assertEqual(client.current_ref, lease.lease.initial_head_sha)
        self.assertFalse(any(item.body.startswith(controller_module.ISSUE_NO_PR_CANCELLED_RESULT_MARKER) for item in client.comments))

        client, issue, _anchor, lease, controller = self._no_pr_fixture(ref_state="root")
        client.commit_messages[lease.lease.initial_head_sha] += " altered"
        with self.assertRaises((R02Error, StaleAuthorityError)):
            controller.cancel_issue_without_pr(issue.number)
        self.assertEqual(client.no_pr_ref_updates, [])

    def test_pr_backed_cleanup_deletes_exact_D_E_HC_and_replays_without_stage_mutations(self):
        for binding in ("PRE_BINDING", "FULL_BINDING"):
            with self.subTest(binding=binding):
                client, issue, _a, lease, _state, controller, fence, _status = self._publish_cancel_failure(
                    binding=binding, nonce=("b" if binding == "PRE_BINDING" else "c") * 64,
                )
                controller.establish_issue_cancellation_draft_witness(issue.number)
                terminal = controller.establish_issue_terminal_cancelled_result(issue.number)
                prior_stages = list(client.stage_calls)
                with patch.object(controller_module, "resolve_issue_source_authority", side_effect=AssertionError("source lookup forbidden")):
                    cleaned = controller.cleanup_issue_cancelled_branch(issue.number)
                self.assertEqual(cleaned, terminal)
                self.assertIsNone(client.current_ref)
                self.assertEqual(client.stage_calls, prior_stages)
                update = next(
                    event[2] for event in client.events
                    if event[0] == "cas" and event[2].after_oid == ZERO_OID
                )
                self.assertEqual(update.name, lease.lease.branch_ref)
                self.assertEqual(update.before_oid, fence.cancellation_head_sha)
                self.assertEqual(update.after_oid, ZERO_OID)
                self.assertFalse(update.force)
                with patch.object(controller_module, "resolve_issue_source_authority", side_effect=AssertionError("source lookup forbidden")):
                    self.assertEqual(controller.cleanup_issue_cancelled_branch(issue.number), terminal)
                self.assertEqual(client.stage_calls, prior_stages)
                if binding == "PRE_BINDING":
                    self.assertFalse(any(item.body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER) for item in client.comments))

    def test_pr_backed_cleanup_blocks_missing_proof_wrong_status_drift_merge_and_cas_conflict(self):
        for case in ("missing-result", "success-status", "drift", "merge", "cas-conflict"):
            with self.subTest(case=case):
                client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(nonce=f"{len(case):064x}")
                controller.establish_issue_cancellation_draft_witness(issue.number)
                terminal = controller.establish_issue_terminal_cancelled_result(issue.number)
                if case == "missing-result":
                    client.pr_comments[fence.pull_request_number] = [
                        item for item in client.pr_comments[fence.pull_request_number]
                        if not item.body.startswith(ISSUE_TERMINAL_CANCELLED_RESULT_MARKER)
                    ]
                elif case == "success-status":
                    client.status_rows[fence.cancellation_head_sha] = (
                        self._exact_app_status(
                            fence.cancellation_head_sha, state="success",
                            status_class=StatusClass.CANCEL, digest=terminal.current_failure_status.evidence_digest,
                            status_id=701,
                        ),
                    )
                elif case == "drift":
                    client.current_ref = "3" * 40
                    number = fence.pull_request_number
                    client.pull_requests[number] = replace(client.pull_requests[number], head_oid=client.current_ref)
                elif case == "merge":
                    client.raw_pr_merged = True
                    client.raw_pr_merged_at = "2026-10-06T01:00:00Z"
                else:
                    client.cas_outcomes = ["raise-nochange"]
                deletion_cas_count = len([
                    event for event in client.events
                    if event[0] == "cas" and event[2].after_oid == ZERO_OID
                ])
                if case == "merge":
                    self.assertEqual(
                        controller.cleanup_issue_cancelled_branch(issue.number),
                        "MERGE_OBSERVED_POST_MERGE_REQUIRED",
                    )
                else:
                    with self.assertRaises((R02Error, StaleAuthorityError)):
                        controller.cleanup_issue_cancelled_branch(issue.number)
                self.assertEqual(
                    len([event for event in client.events if event[0] == "cas" and event[2].after_oid == ZERO_OID])
                    - deletion_cas_count,
                    0 if case in {"missing-result", "success-status", "drift", "merge"} else 1,
                )

    def test_terminal_cleanup_reclassifies_binding_and_preserves_merged_E(self):
        client, issue, _a, _l, _s, controller, fence, _status = self._publish_cancel_failure(
            binding="PRE_BINDING", nonce="d" * 64,
        )
        controller.establish_issue_cancellation_draft_witness(issue.number)
        controller.establish_issue_terminal_cancelled_result(issue.number)
        pr = client.pull_requests[fence.pull_request_number]
        full_binding = IssuePRBinding.create(
            issue_number=issue.number,
            issue_database_id=client.binding_anchor.anchor.issue_database_id,
            issue_node_id=client.binding_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=client.binding_anchor.comment.database_id,
            issue_request_anchor_sha256=client.binding_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=client.binding_lease.comment.database_id,
            issue_branch_lease_sha256=hashlib.sha256(client.binding_lease.comment.body.encode("utf-8")).hexdigest(),
            source_id=client.binding_anchor.anchor.source_id,
            source_repository_id=client.binding_anchor.anchor.source_repository_id,
            branch_ref=client.binding_lease.lease.branch_ref,
            pull_request_number=pr.number,
            pull_request_database_id=client.pull_request_issues[pr.number].database_id,
            pull_request_node_id=client.pull_request_issues[pr.number].node_id,
            initial_head_sha=client.binding_lease.lease.initial_head_sha,
            base_ref="main",
            central_repository_node_id=self.CENTRAL_NODE_ID,
        )
        client.comments.append(IssueAnchorControllerTests.comment(
            full_binding.render_issue_binding(), database_id=90_001,
        ))
        client.pr_comments[pr.number].append(IssueAnchorControllerTests.comment(
            full_binding.render_pr_origin_binding(), database_id=90_002,
        ))
        with self.assertRaises((R02Error, StaleAuthorityError)):
            controller.cleanup_issue_cancelled_branch(issue.number)
        self.assertEqual(client.current_ref, fence.cancellation_head_sha)
        self.assertFalse(any(event[0] == "cas" and event[2].after_oid == ZERO_OID for event in client.events))

        client, issue, _a, _l, _s, controller, _fence, _status = self._publish_cancel_failure(
            binding="FULL_BINDING", nonce="e" * 64,
        )
        controller.establish_issue_cancellation_draft_witness(issue.number)
        controller.establish_issue_terminal_cancelled_result(issue.number)
        client.raw_pr_merged = True
        client.raw_pr_merged_at = "2026-10-06T01:00:00Z"
        self.assertEqual(
            controller.cleanup_issue_cancelled_branch(issue.number),
            "MERGE_OBSERVED_POST_MERGE_REQUIRED",
        )
        self.assertFalse(any(event[0] == "cas" and event[2].after_oid == ZERO_OID for event in client.events))

        client, issue, _a, _l, _s, controller, _fence, _status = self._publish_cancel_failure(
            binding="PRE_BINDING", nonce="f" * 64,
        )
        controller.establish_issue_cancellation_draft_witness(issue.number)
        controller.establish_issue_terminal_cancelled_result(issue.number)
        client.raw_pr_merged = True
        client.raw_pr_merged_at = "2026-10-06T01:00:00Z"
        with self.assertRaisesRegex(StaleAuthorityError, "MERGED_PRE_BINDING_PRESERVE"):
            controller.cleanup_issue_cancelled_branch(issue.number)
        self.assertFalse(any(event[0] == "cas" and event[2].after_oid == ZERO_OID for event in client.events))

    def test_new_cancellation_cleanup_callables_remain_inert_and_source_free(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        main = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "main")
        called = {
            item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
            for item in ast.walk(main)
            if isinstance(item, ast.Call)
            and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
        }
        for name in (
            "prepare_issue_cancellation_fence",
            "publish_issue_cancel_failure",
            "establish_issue_cancellation_draft_witness",
            "establish_issue_terminal_cancelled_result",
            "cleanup_issue_cancelled_branch",
            "cancel_issue_without_pr",
        ):
            self.assertNotIn(name, called)
        controller_class = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "R02Controller")
        methods = {item.name: item for item in controller_class.body if isinstance(item, ast.FunctionDef)}
        for name in ("cleanup_issue_cancelled_branch", "cancel_issue_without_pr", "_read_issue_cancellation_state"):
            source_calls = {
                item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
                for item in ast.walk(methods[name])
                if isinstance(item, ast.Call)
                and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
            }
            self.assertFalse(source_calls & {
                "resolve_issue_source_authority", "_fresh_issue_source_authority",
                "current_issue_source_authority", "source_authority_resolver",
            })
        for client, issue, _anchor, _lease, controller in (
            self._no_pr_fixture(with_lease=False),
            self._no_pr_fixture(ref_state="absent"),
        ):
            with patch.object(controller_module, "resolve_issue_source_authority", side_effect=AssertionError("source lookup forbidden")):
                state = controller._read_issue_cancellation_state(issue.number)
                if state.issue.state == "closed":
                    controller.cancel_issue_without_pr(issue.number)


class Wave08RoleDecisionContractTests(unittest.TestCase):
    HEAD = "a" * 40

    @staticmethod
    def marker(role, claim_kind, *, owner_kind="ISSUE", owner_key="R_central:700:I_issue:7"):
        return ClaimedHeadMarker(
            claim_kind=claim_kind, role=role.value, owner_kind=owner_kind, owner_key=owner_key,
            claim_generation_id="1" * 64, carrier_nonce="2" * 64, transition_kind="INITIAL",
        )

    def test_closed_decision_mapping_covers_issue_machine_external_and_fail_closed_roles(self):
        decide = controller_module.wave08_decision_for_resolution
        kind = controller_module.Wave08DecisionKind
        target = controller_module.Wave08DispatchTarget
        issue_active = ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE,
            self.marker(CarrierRole.ISSUE_ACTIVE, "ISSUE_HEAD_CLAIM"),
        )
        finalizing = ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_FINALIZING,
            self.marker(CarrierRole.ISSUE_FINALIZING, "ISSUE_FINALIZATION_EPOCH"),
        )
        cancelling = ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL,
            self.marker(CarrierRole.ISSUE_CANCEL, "ISSUE_CANCELLATION_FENCE"),
        )
        machine = ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION,
            self.marker(CarrierRole.MACHINE_PUBLICATION, "MACHINE_REF_CLAIM", owner_kind="MACHINE_SOURCE", owner_key="orphan-source"),
        )
        for resolution in (issue_active, finalizing):
            with self.subTest(role=resolution.role):
                action = decide(self.HEAD, resolution, (12, 7), owner_pr_number=7)
                self.assertEqual(action.kind, kind.ISSUE_OWNER_FINALIZER_RECOVERY)
                self.assertEqual(action.dispatch_target, target.ISSUE_FINALIZER)
                self.assertEqual(action.pull_request_numbers, (7, 12))
                self.assertEqual(action.owning_pr_number, 7)
        action = decide(self.HEAD, cancelling, (7,), owner_pr_number=7)
        self.assertEqual(action.kind, kind.ISSUE_OWNER_CANCELLATION_RECOVERY)
        self.assertEqual(action.dispatch_target, target.ISSUE_CANCELLATION_RECOVERY)
        for lane, expected in (
            (target.MACHINE_VALIDATION, kind.MACHINE_VALIDATION_DISPATCH),
            (target.MACHINE_FINALIZER, kind.MACHINE_FINALIZER_DISPATCH),
        ):
            action = decide(self.HEAD, machine, (7, 12), owner_pr_number=7, machine_target=lane)
            self.assertEqual((action.kind, action.dispatch_target), (expected, lane))

        reserved_issue = ShaCarrierResolution(CarrierActivation.RESERVED_INACTIVE, CarrierRole.ISSUE_ACTIVE, issue_active.marker)
        self.assertEqual(decide(self.HEAD, reserved_issue, (7,), owner_pr_number=7).kind, kind.RESERVED_OWNER_RECOVERY)
        reserved_machine = ShaCarrierResolution(CarrierActivation.RESERVED_INACTIVE, CarrierRole.MACHINE_PUBLICATION, machine.marker)
        self.assertEqual(decide(self.HEAD, reserved_machine, (7,), owner_pr_number=7).kind, kind.MACHINE_RECOVERY_DEFERRED)
        self.assertEqual(decide(self.HEAD, ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION), (12, 7)).kind, kind.EXTERNAL_STATUS)
        self.assertEqual(decide(self.HEAD, ShaCarrierResolution(CarrierActivation.LEGACY_CUTOVER_QUARANTINE), (7,)).kind, kind.LEGACY_QUARANTINE_DEFERRED)
        self.assertEqual(decide(self.HEAD, ShaCarrierResolution(CarrierActivation.CONFLICTING), (7,)).kind, kind.CONFLICTING_BLOCKED)
        self.assertEqual(decide(self.HEAD, issue_active, (7,)).kind, kind.NO_MUTATION)

    def test_decision_record_rejects_open_vocabulary_bad_groups_and_role_action_mismatch(self):
        kind = controller_module.Wave08DecisionKind
        target = controller_module.Wave08DispatchTarget
        decide = controller_module.wave08_decision_for_resolution
        unclaimed = ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
        issue = ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE,
            self.marker(CarrierRole.ISSUE_ACTIVE, "ISSUE_HEAD_CLAIM"),
        )
        machine = ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION,
            self.marker(CarrierRole.MACHINE_PUBLICATION, "MACHINE_REF_CLAIM", owner_kind="MACHINE_SOURCE", owner_key="source"),
        )
        for numbers in ((7, 7), (True,), (0,), (-1,)):
            with self.subTest(numbers=numbers), self.assertRaises(ValueError):
                decide(self.HEAD, unclaimed, numbers)
        for args in (
            ("A" * 40, unclaimed, ()),
            (self.HEAD, unclaimed, (7,), 8),
        ):
            with self.subTest(args=args), self.assertRaises(ValueError):
                if len(args) == 3:
                    decide(*args)
                else:
                    decide(args[0], args[1], args[2], owner_pr_number=args[3])
        with self.assertRaises(ValueError):
            decide(self.HEAD, issue, (7,), owner_pr_number=7, machine_target=target.MACHINE_FINALIZER)
        with self.assertRaises(ValueError):
            controller_module.Wave08Decision(
                self.HEAD, unclaimed, (), None, kind.ISSUE_OWNER_FINALIZER_RECOVERY,
                controller_module.Wave08DecisionReason.ISSUE_FINALIZER_REQUIRED, target.ISSUE_FINALIZER,
            )
        with self.assertRaises(ValueError):
            controller_module.Wave08Decision(
                self.HEAD, machine, (7,), 7, kind.ISSUE_OWNER_FINALIZER_RECOVERY,
                controller_module.Wave08DecisionReason.ISSUE_FINALIZER_REQUIRED, target.ISSUE_FINALIZER,
            )
        with self.assertRaises(ValueError):
            decide(self.HEAD, machine, (7,), owner_pr_number=7, machine_target="workflow.yml")
        with self.assertRaises(ValueError):
            controller_module.Wave08Decision(
                self.HEAD, unclaimed, (7,), None, "UNKNOWN_ACTION",
                controller_module.Wave08DecisionReason.ROLE_REQUIRES_NO_ACTION,
            )
        action = decide(self.HEAD, unclaimed, (7,))
        with self.assertRaises((AttributeError, TypeError)):
            action.kind = kind.NO_MUTATION

    def test_permission_profiles_are_closed_immutable_and_exact(self):
        level = controller_module.Wave08PermissionLevel
        lane = controller_module.Wave08PermissionLane
        expected = {
            lane.WG3_MANUAL_STATUS: {"actions": "write", "statuses": "write", "contents": "read", "pull_requests": "read", "issues": "read", "checks": "none"},
            lane.WG3_MACHINE_VALIDATION: {"actions": "write", "statuses": "none", "contents": "read", "pull_requests": "read", "issues": "read", "checks": "write"},
            lane.WG4_ISSUE_MANUAL_FINALIZER: {"actions": "write", "statuses": "write", "contents": "write", "pull_requests": "write", "issues": "read", "checks": "none"},
            lane.WG4_MACHINE_FINALIZER: {"actions": "write", "statuses": "none", "contents": "write", "pull_requests": "write", "issues": "read", "checks": "write"},
            lane.WG6_ORDINARY_RECOVERY: {"actions": "write", "statuses": "write", "contents": "write", "pull_requests": "write", "issues": "read", "checks": "none"},
        }
        profiles = {item.lane: dict(item.as_pairs()) for item in controller_module.WAVE08_PERMISSION_PROFILES}
        self.assertEqual(profiles, expected)
        self.assertEqual(set(profiles), set(lane))
        self.assertTrue(all(set(value) == set(next(iter(expected.values()))) for value in profiles.values()))
        self.assertEqual((level.NONE.value, level.READ.value, level.WRITE.value), ("none", "read", "write"))
        for profile in controller_module.WAVE08_PERMISSION_PROFILES:
            with self.subTest(lane=profile.lane), self.assertRaises((AttributeError, TypeError)):
                profile.checks = level.WRITE
        with self.assertRaises(TypeError):
            controller_module.Wave08PermissionProfile(
                lane.WG3_MANUAL_STATUS, actions=level.WRITE, statuses=level.WRITE,
                contents=level.READ, pull_requests=level.READ, issues=level.READ,
                checks=level.NONE, admin=level.WRITE,
            )
        with self.assertRaises(ValueError):
            controller_module.Wave08PermissionProfile(
                lane.WG3_MANUAL_STATUS, actions=level.WRITE, statuses=level.WRITE,
                contents=level.READ, pull_requests=level.READ, issues=level.READ,
                checks="none",
            )

    def test_legacy_disposition_adapter_receives_exact_sha_and_fails_closed(self):
        adapter = controller_module.wave08_legacy_disposition
        reads = []
        self.assertEqual(adapter(self.HEAD, lambda head: reads.append(head) or LegacyEvidenceDisposition.ABSENT), LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(reads, [self.HEAD])
        self.assertEqual(adapter(self.HEAD, None), LegacyEvidenceDisposition.CONFLICTING)
        self.assertEqual(adapter(self.HEAD, lambda _head: "ABSENT"), LegacyEvidenceDisposition.CONFLICTING)
        self.assertEqual(adapter(self.HEAD, lambda _head: (_ for _ in ()).throw(RuntimeError("offline"))), LegacyEvidenceDisposition.CONFLICTING)
        self.assertEqual(adapter("A" * 40, lambda _head: LegacyEvidenceDisposition.ABSENT), LegacyEvidenceDisposition.CONFLICTING)

    def test_issue_owner_derivation_uses_exact_full_binding_and_prebinding_fence_pr(self):
        client, _issue, _anchor, _lease, state, claim = Wave05ShaCarrierResolverTests().make_claim_client()
        initial_comment_writes = tuple(client.comment_writes)
        resolution = Wave05ShaCarrierResolverTests.resolve(client, claim.to_head_sha)
        owner = controller_module.derive_issue_owner_pr(
            client, Wave05ShaCarrierResolverTests.CENTRAL, claim.to_head_sha,
            resolution, Wave05ShaCarrierResolverTests.APP.slug,
        )
        self.assertEqual(owner.issue_number, state.binding.issue_number)
        self.assertEqual(owner.pull_request_number, state.binding.pull_request_number)
        self.assertEqual(owner.owner_key, resolution.marker.owner_key)
        self.assertEqual(owner.binding_authority, "FULL_BINDING")
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(client.forbidden_calls, [])
        self.assertEqual(client.pr_inventory_reads, 0)

        pre_client, pre_issue, _anchor, _lease, _state, _controller, fence = Wave07CancellationControllerTests()._prepare(binding="PRE_BINDING")
        initial_prebinding_comment_writes = tuple(pre_client.comment_writes)
        cancel_resolution = Wave05ShaCarrierResolverTests.resolve(pre_client, fence.cancellation_head_sha)
        pre_owner = controller_module.derive_issue_owner_pr(
            pre_client, Wave05ShaCarrierResolverTests.CENTRAL, fence.cancellation_head_sha,
            cancel_resolution, Wave05ShaCarrierResolverTests.APP.slug,
        )
        self.assertEqual((pre_owner.issue_number, pre_owner.pull_request_number), (pre_issue.number, fence.pull_request_number))
        self.assertEqual(pre_owner.binding_authority, "PRE_BINDING")
        self.assertEqual(tuple(pre_client.comment_writes), initial_prebinding_comment_writes)
        self.assertEqual(pre_client.forbidden_calls, [])

        full_client, full_issue, _anchor, _lease, full_state, _controller, full_fence = (
            Wave07CancellationControllerTests()._prepare(binding="FULL_BINDING")
        )
        full_resolution = Wave05ShaCarrierResolverTests.resolve(full_client, full_fence.cancellation_head_sha)
        full_owner = controller_module.derive_issue_owner_pr(
            full_client, Wave05ShaCarrierResolverTests.CENTRAL, full_fence.cancellation_head_sha,
            full_resolution, Wave05ShaCarrierResolverTests.APP.slug,
        )
        self.assertEqual((full_owner.issue_number, full_owner.pull_request_number), (full_issue.number, full_state.binding.pull_request_number))
        self.assertEqual(full_owner.binding_authority, "FULL_BINDING")

    def test_issue_owner_derivation_fails_closed_on_repository_issue_and_binding_drift(self):
        for corruption in ("owner", "repository", "issue", "binding"):
            with self.subTest(corruption=corruption):
                client, issue, _anchor, _lease, state, claim = Wave05ShaCarrierResolverTests().make_claim_client()
                resolution = Wave05ShaCarrierResolverTests.resolve(client, claim.to_head_sha)
                if corruption == "owner":
                    resolution = replace(
                        resolution,
                        marker=replace(resolution.marker, owner_key="R_central:701:I_other:8"),
                    )
                elif corruption == "repository":
                    client.repository = replace(client.repository, node_id="R_wrong")
                elif corruption == "issue":
                    client.issue = replace(issue, database_id=issue.database_id + 1)
                else:
                    comments = client.pr_comments[state.binding.pull_request_number]
                    comments[0] = replace(comments[0], body="edited binding")
                with self.assertRaises((R02Error, StaleAuthorityError)):
                    controller_module.derive_issue_owner_pr(
                        client, Wave05ShaCarrierResolverTests.CENTRAL, claim.to_head_sha,
                        resolution, Wave05ShaCarrierResolverTests.APP.slug,
                    )

    def test_real_machine_marker_resolver_remains_fail_closed_without_legacy_fallback(self):
        marker = self.marker(
            CarrierRole.MACHINE_PUBLICATION, "MACHINE_REF_CLAIM",
            owner_kind="MACHINE_SOURCE", owner_key="orphan-source",
        )
        legacy_reads = []
        client = Wave05ShaCarrierResolverTests.commit_message_client(self.HEAD, marker.render())
        resolution = resolve_sha_carrier_role(
            client, Wave05ShaCarrierResolverTests.CENTRAL, self.HEAD,
            Wave05ShaCarrierResolverTests.APP.slug,
            lambda: legacy_reads.append(self.HEAD) or LegacyEvidenceDisposition.ABSENT,
        )
        self.assertEqual(resolution.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(legacy_reads, [])
        decision = controller_module.wave08_decision_for_resolution(self.HEAD, resolution, (7,))
        self.assertEqual(decision.kind, controller_module.Wave08DecisionKind.CONFLICTING_BLOCKED)
        self.assertEqual(client.reads, [(Wave05ShaCarrierResolverTests.CENTRAL, self.HEAD)])


class Wave08RoleFirstRouteTests(unittest.TestCase):
    CENTRAL = Wave05ShaCarrierResolverTests.CENTRAL
    APP = Wave05ShaCarrierResolverTests.APP
    HEAD = "a" * 40

    @staticmethod
    def controller(client):
        return R02Controller(client, Wave08RoleFirstRouteTests.CENTRAL, Wave08RoleFirstRouteTests.APP)

    @staticmethod
    def active_issue_fixture():
        client, _issue, _anchor, _lease, state, claim = Wave05ShaCarrierResolverTests().make_claim_client()
        return client, state, claim, Wave08RoleFirstRouteTests.controller(client)

    @staticmethod
    def install_forbidden_mutation_spies(client):
        calls = []
        for name in (
            "create_check_run", "update_check_run", "update_refs", "update_pull_request_state",
            "create_issue_comment", "create_machine_pull_request", "create_pull_request",
            "merge_machine_pull_request", "close_pull_request",
        ):
            if hasattr(client, name):
                def forbidden(*args, _name=name, **kwargs):
                    calls.append((_name, args, kwargs))
                    raise AssertionError(f"role-first route unexpectedly called {_name}")
                setattr(client, name, forbidden)
        return calls

    def test_issue_active_owner_routes_after_sha_resolution_without_status_or_checks(self):
        client, state, claim, route = self.active_issue_fixture()
        initial_writes = tuple(client.comment_writes)
        mutation_calls = self.install_forbidden_mutation_spies(client)
        events = []
        file_reads = []
        original_pr = client.get_pull_request_metadata
        original_comments = client.list_issue_comments
        original_resolver = controller_module.resolve_sha_carrier_role

        def get_pr(repository, number):
            events.append(("pr", number))
            return original_pr(repository, number)

        def comments(repository, number):
            events.append(("comments", number))
            return original_comments(repository, number)

        def resolve(*args, **kwargs):
            events.append(("role", args[2]))
            return original_resolver(*args, **kwargs)

        dispatches = []

        def dispatch(decision, owner, fence):
            events.append(("dispatch", decision.dispatch_target))
            dispatches.append((decision, owner, fence))

        client.get_pull_request_metadata = get_pr
        client.list_issue_comments = comments
        client.list_pull_request_files = lambda *_args, **_kwargs: file_reads.append("unexpected")
        with patch.object(controller_module, "resolve_sha_carrier_role", side_effect=resolve):
            result = route.trusted_validation_role_first(
                state.binding.pull_request_number,
                lambda head: LegacyEvidenceDisposition.ABSENT,
                central_recovery_dispatcher=dispatch,
            )

        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY)
        self.assertEqual(result.dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_FINALIZER)
        self.assertEqual(result.owning_pr_number, state.binding.pull_request_number)
        self.assertEqual(len(dispatches), 1)
        self.assertEqual(dispatches[0][1].pull_request_number, state.binding.pull_request_number)
        self.assertIsNone(dispatches[0][2])
        self.assertLess(events.index(("pr", state.binding.pull_request_number)), events.index(("role", claim.to_head_sha)))
        self.assertLess(events.index(("role", claim.to_head_sha)), next(i for i, item in enumerate(events) if item[0] == "comments"))
        self.assertEqual(tuple(client.comment_writes), initial_writes)
        self.assertEqual(mutation_calls, [])
        self.assertEqual(file_reads, [])
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])
        self.assertEqual(client.check_calls if hasattr(client, "check_calls") else [], [])

    def test_issue_active_shared_head_nonowner_is_no_mutation_even_when_woken(self):
        client, state, claim, route = self.active_issue_fixture()
        owner_number = state.binding.pull_request_number
        nonowner_number = owner_number + 100
        client.pull_requests[nonowner_number] = replace(client.pull_requests[owner_number], number=nonowner_number)
        initial_writes = tuple(client.comment_writes)
        mutation_calls = self.install_forbidden_mutation_spies(client)
        dispatches = []
        result = route.trusted_validation_role_first(
            nonowner_number,
            lambda head: LegacyEvidenceDisposition.ABSENT,
            central_recovery_dispatcher=lambda *args: dispatches.append(args),
        )
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.NO_MUTATION)
        self.assertIsNone(result.owning_pr_number)
        self.assertEqual(result.pull_request_numbers, (nonowner_number,))
        self.assertEqual(dispatches, [])
        self.assertEqual(tuple(client.comment_writes), initial_writes)
        self.assertEqual(mutation_calls, [])
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])
        self.assertEqual(client.check_calls if hasattr(client, "check_calls") else [], [])
        self.assertEqual(
            client.pull_requests[nonowner_number].head_oid,
            client.pull_requests[owner_number].head_oid,
        )

    def test_finalizing_role_uses_only_issue_finalizer_dispatch_and_never_direct_green(self):
        client, issue, _anchor, _lease, state, _claim, _immediate, epoch = (
            Wave05ShaCarrierResolverTests().make_finalization_epoch_client()
        )
        route = self.controller(client)
        initial_statuses = tuple(getattr(client, "status_calls", ()))
        dispatches = []
        result = route.trusted_validation_role_first(
            state.binding.pull_request_number,
            None,
            central_recovery_dispatcher=lambda *args: dispatches.append(args),
        )
        self.assertEqual(result.resolution.role, CarrierRole.ISSUE_FINALIZING)
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY)
        self.assertEqual(result.dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_FINALIZER)
        self.assertEqual(len(dispatches), 1)
        self.assertEqual(dispatches[0][1].issue_number, issue.number)
        self.assertEqual(tuple(getattr(client, "status_calls", ())), initial_statuses)
        self.assertEqual(getattr(client, "check_calls", []), [])
        self.assertNotEqual(epoch.final_head_sha, "0" * 40)

    def test_cancellation_owner_writes_exact_failure_then_dispatches_terminal_recovery(self):
        client, issue, _anchor, _lease, state, _controller, fence = (
            Wave07CancellationControllerTests()._prepare(binding="FULL_BINDING")
        )
        route = self.controller(client)
        prior_stages = tuple(client.stage_calls)
        prior_ref = client.current_ref
        order = []

        def dispatch(decision, owner, exact_fence):
            order.append(("dispatch", len(client.status_posts)))
            self.assertEqual(decision.dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY)
            self.assertEqual(owner.pull_request_number, fence.pull_request_number)
            self.assertEqual(exact_fence, fence)

        result = route.trusted_validation_role_first(
            fence.pull_request_number,
            None,
            central_recovery_dispatcher=dispatch,
        )
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY)
        self.assertEqual(result.dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY)
        self.assertEqual(len(client.status_posts), 1)
        expected_cancel_description = render_status_description(
            StatusClass.CANCEL,
            cancel_status_evidence_digest(
                central_repository_node_id=fence.central_repository_node_id,
                issue_number=fence.issue_number,
                issue_database_id=fence.issue_database_id,
                issue_node_id=fence.issue_node_id,
                fence_id=fence.fence_id,
                cancellation_head_sha=fence.cancellation_head_sha,
                binding_authority=fence.binding_authority,
                pull_request_number=fence.pull_request_number,
                pull_request_database_id=fence.pull_request_database_id,
                pull_request_node_id=fence.pull_request_node_id,
            ),
        )
        self.assertEqual(client.status_posts[0], (
            self.CENTRAL, fence.cancellation_head_sha, "failure",
            "federation/trusted-validation", expected_cancel_description, None,
        ))
        self.assertEqual(order, [("dispatch", 1)])
        self.assertEqual(tuple(client.stage_calls), prior_stages)
        self.assertEqual(client.current_ref, prior_ref)
        self.assertEqual(issue.number, state.binding.issue_number)

    def test_cancellation_nonowner_never_writes_status_or_dispatches(self):
        client, _issue, _anchor, _lease, _state, _controller, fence = (
            Wave07CancellationControllerTests()._prepare(binding="FULL_BINDING")
        )
        owner = fence.pull_request_number
        nonowner = owner + 100
        client.pull_requests[nonowner] = replace(
            client.pull_requests[owner], number=nonowner,
            author_id="U_external", author_login="external-user",
            head_ref="external-copy", head_repository="fork/skills",
            head_repository_id="R_fork",
        )
        route = self.controller(client)
        dispatches = []
        result = route.trusted_validation_role_first(
            nonowner, None, central_recovery_dispatcher=lambda *args: dispatches.append(args),
        )
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.NO_MUTATION)
        self.assertEqual(client.status_posts, [])
        self.assertEqual(dispatches, [])
        self.assertEqual(client.stage_calls, [])

    def test_reserved_issue_role_returns_owner_recovery_without_a_carrier(self):
        client, state, claim, route = self.active_issue_fixture()
        client.current_ref = "f" * 40
        dispatches = []
        result = route.trusted_validation_role_first(
            state.binding.pull_request_number, None,
            central_recovery_dispatcher=lambda *args: dispatches.append(args),
        )
        self.assertEqual(result.resolution.activation, CarrierActivation.RESERVED_INACTIVE)
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.RESERVED_OWNER_RECOVERY)
        self.assertEqual(len(dispatches), 1)
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])
        self.assertEqual(client.check_calls if hasattr(client, "check_calls") else [], [])
        self.assertEqual(client.pull_requests[state.binding.pull_request_number].head_oid, claim.to_head_sha)

    def test_all_reserved_issue_roles_recover_only_for_exact_owner_and_reserved_machine_defers(self):
        client, state, _claim, route = self.active_issue_fixture()
        owner_number = state.binding.pull_request_number
        owner_key = "R_central:700:I_issue:7"
        role_markers = (
            (CarrierRole.ISSUE_ACTIVE, "ISSUE_HEAD_CLAIM"),
            (CarrierRole.ISSUE_FINALIZING, "ISSUE_FINALIZATION_EPOCH"),
            (CarrierRole.ISSUE_CANCEL, "ISSUE_CANCELLATION_FENCE"),
        )
        dispatches = []
        for role, claim_kind in role_markers:
            marker = ClaimedHeadMarker(
                claim_kind=claim_kind, role=role.value, owner_kind="ISSUE", owner_key=owner_key,
                claim_generation_id="5" * 64, carrier_nonce="6" * 64,
                transition_kind="INITIAL",
            )
            resolution = ShaCarrierResolution(CarrierActivation.RESERVED_INACTIVE, role, marker)
            owner = controller_module.IssueOwnerPR(7, owner_number, owner_key, "FULL_BINDING")
            with patch.object(controller_module, "resolve_sha_carrier_role", return_value=resolution), \
                 patch.object(controller_module, "derive_issue_owner_pr", return_value=owner):
                result = route.trusted_validation_role_first(
                    owner_number, None,
                    central_recovery_dispatcher=lambda decision, _owner, fence: dispatches.append((decision, fence)),
                )
            self.assertEqual(result.kind, controller_module.Wave08DecisionKind.RESERVED_OWNER_RECOVERY)
            self.assertIsNone(dispatches[-1][1])
        self.assertEqual(len(dispatches), len(role_markers))
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])
        self.assertEqual(client.check_calls if hasattr(client, "check_calls") else [], [])

        machine_marker = ClaimedHeadMarker(
            claim_kind="MACHINE_REF_CLAIM", role=CarrierRole.MACHINE_PUBLICATION.value,
            owner_kind="MACHINE_SOURCE", owner_key="R_central:accepted-source",
            claim_generation_id="7" * 64, carrier_nonce="8" * 64,
            transition_kind="MACHINE_PUBLICATION",
        )
        machine = ShaCarrierResolution(CarrierActivation.RESERVED_INACTIVE, CarrierRole.MACHINE_PUBLICATION, machine_marker)
        machine_dispatches = []
        with patch.object(controller_module, "resolve_sha_carrier_role", return_value=machine):
            deferred = route.trusted_validation_role_first(
                owner_number, None,
                machine_validation_dispatcher=lambda *args: machine_dispatches.append(args),
            )
        self.assertEqual(deferred.kind, controller_module.Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED)
        self.assertEqual(machine_dispatches, [])
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])

    def test_machine_active_requires_exact_accepted_source_pr_and_ref_then_dispatches_machine_only(self):
        client, state, _claim, route = self.active_issue_fixture()
        pr_number = state.binding.pull_request_number
        source = ControllerCoreTests.accepted_manifest().sources[0]
        repository = client.repository
        old_pr = client.pull_requests[pr_number]
        head_sha = old_pr.head_oid
        client.pull_requests[pr_number] = replace(
            old_pr,
            head_ref=controller_module._machine_branch(source.source_id),
            head_repository=repository.full_name,
            head_repository_id=repository.node_id,
            base_oid=IssueBranchLeaseControllerTests.BASE_SHA,
            base_ref="main",
            base_repository=repository.full_name,
            base_repository_id=repository.node_id,
        )
        marker = ClaimedHeadMarker(
            claim_kind="MACHINE_REF_CLAIM", role=CarrierRole.MACHINE_PUBLICATION.value,
            owner_kind="MACHINE_SOURCE", owner_key=f"{repository.node_id}:{source.source_id}",
            claim_generation_id="3" * 64, carrier_nonce="4" * 64,
            transition_kind="MACHINE_PUBLICATION",
        )
        machine_resolution = ShaCarrierResolution(CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION, marker)
        events = []
        route._accepted_sources = lambda _main: events.append("accepted-sources") or (source,)
        route._machine_authority = lambda _summary, accepted, _main, _repo: controller_module.MachinePRAuthority(
            pr_number, accepted.source_id, accepted.repository_id, head_sha,
        )
        original_ref = client.get_ref_oid
        client.get_ref_oid = lambda repository_name, ref: head_sha if ref == f"bot/federation/{source.source_id}" else original_ref(repository_name, ref)
        machine_calls, issue_calls = [], []
        with patch.object(
            controller_module, "resolve_sha_carrier_role",
            side_effect=lambda *_args, **_kwargs: events.append("role") or machine_resolution,
        ):
            result = route.trusted_validation_role_first(
                pr_number, None,
                central_recovery_dispatcher=lambda *args: issue_calls.append(args),
                machine_validation_dispatcher=lambda *args: machine_calls.append(args),
            )
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.MACHINE_VALIDATION_DISPATCH)
        self.assertEqual(result.dispatch_target, controller_module.Wave08DispatchTarget.MACHINE_VALIDATION)
        self.assertEqual(len(machine_calls), 1)
        self.assertEqual(machine_calls[0][1], controller_module.MachinePRAuthority(pr_number, source.source_id, source.repository_id, head_sha))
        self.assertEqual(issue_calls, [])
        self.assertLess(events.index("role"), events.index("accepted-sources"))

    def test_machine_owner_mismatch_is_blocked_without_status_check_or_dispatch(self):
        client, state, _claim, route = self.active_issue_fixture()
        source = ControllerCoreTests.accepted_manifest().sources[0]
        marker = ClaimedHeadMarker(
            claim_kind="MACHINE_REF_CLAIM", role=CarrierRole.MACHINE_PUBLICATION.value,
            owner_kind="MACHINE_SOURCE", owner_key=f"{client.repository.node_id}:wrong-source",
            claim_generation_id="3" * 64, carrier_nonce="4" * 64,
            transition_kind="MACHINE_PUBLICATION",
        )
        resolution = ShaCarrierResolution(CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION, marker)
        route._accepted_sources = lambda _main: (source,)
        calls = []
        with patch.object(controller_module, "resolve_sha_carrier_role", return_value=resolution):
            result = route.trusted_validation_role_first(
                state.binding.pull_request_number, None,
                machine_validation_dispatcher=lambda *args: calls.append(args),
            )
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.CONFLICTING_BLOCKED)
        self.assertIsNone(result.owning_pr_number)
        self.assertEqual(calls, [])
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])
        self.assertEqual(client.check_calls if hasattr(client, "check_calls") else [], [])

    def test_legacy_quarantine_defers_and_unclaimed_absent_writes_one_external_tuple(self):
        identity = GitCommitIdentity("Author", "author@example.test", "2026-10-05T00:00:00Z")
        pr = PullRequestMetadata(
            7, "", "B_bot", "bot", self.HEAD, "b" * 40, "feature", "main",
            "R_central", self.CENTRAL, "R_central", self.CENTRAL, None, False, False,
        )

        class ReadOnlyClient:
            def __init__(inner_self):
                inner_self.events = []

            def get_pull_request_metadata(inner_self, repository, number):
                inner_self.events.append(("pr", number))
                return pr

            def get_git_commit_object(inner_self, repository, sha):
                inner_self.events.append(("commit", sha))
                return GitCommitObject(sha, "plain commit", "c" * 40, (), identity, identity)

            def get_repository_metadata(inner_self, repository):
                inner_self.events.append(("repository", repository))
                return RepositoryMetadata(22, "R_central", repository, "main")

            def get_app_metadata(inner_self, slug):
                inner_self.events.append(("app", slug))
                return AppMetadata(self.APP.app_id, slug, self.APP.app_node_id)

            def get_bot_metadata(inner_self, slug):
                inner_self.events.append(("bot", slug))
                return BotMetadata(self.APP.bot_id, self.APP.bot_login, self.APP.bot_node_id, "Bot")

            def create_commit_status(inner_self, *args):
                inner_self.events.append(("status", args))
                raise AssertionError("external writer is replaced by its exact tuple spy")

            def list_issue_comments(inner_self, *args):
                raise AssertionError("legacy/quarantine routes cannot inspect Issue comments")

            def list_pull_request_files(inner_self, *args):
                raise AssertionError("role must resolve before PR file reads")

        client = ReadOnlyClient()
        route = self.controller(client)
        canonical_resolutions = iter((
            ShaCarrierResolution(CarrierActivation.LEGACY_CUTOVER_QUARANTINE),
            ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION),
        ))
        with patch.object(route, "resolve_current_sha_carrier_role", side_effect=lambda sha: (
            client.events.append(("role", sha)) or next(canonical_resolutions)
        )), patch.object(controller_module, "publish_unclaimed_external_success") as writer:
            quarantined = route.trusted_validation_role_first(
                7, lambda head: client.events.append(("legacy", head)) or LegacyEvidenceDisposition.QUARANTINE,
            )
            self.assertEqual(quarantined.kind, controller_module.Wave08DecisionKind.LEGACY_QUARANTINE_DEFERRED)
            self.assertEqual(writer.call_count, 0)
            client.events.clear()
            unclaimed = route.trusted_validation_role_first(
                7, lambda head: client.events.append(("legacy", head)) or LegacyEvidenceDisposition.ABSENT,
            )
            self.assertEqual(unclaimed.kind, controller_module.Wave08DecisionKind.EXTERNAL_STATUS)
            self.assertEqual(writer.call_count, 1)
            self.assertEqual(writer.call_args.args[2:4], (self.HEAD, unclaimed.resolution))
        events = client.events
        self.assertLess(events.index(("pr", 7)), events.index(("role", self.HEAD)))
        self.assertEqual(events.count(("legacy", self.HEAD)), 0)

    def test_legacy_dependency_failures_never_publish_external_success(self):
        identity = GitCommitIdentity("Author", "author@example.test", "2026-10-05T00:00:00Z")
        pr = PullRequestMetadata(
            7, "", "B_bot", "bot", self.HEAD, "b" * 40, "feature", "main",
            "R_central", self.CENTRAL, "R_central", self.CENTRAL, None, False, False,
        )

        class MarkerlessClient:
            def get_pull_request_metadata(inner_self, _repository, _number):
                return pr

            def get_git_commit_object(inner_self, _repository, sha):
                return GitCommitObject(sha, "plain commit", "c" * 40, (), identity, identity)

        for resolver in (
            None,
            lambda _head: "ABSENT",
            lambda _head: (_ for _ in ()).throw(RuntimeError("legacy unavailable")),
        ):
            with self.subTest(resolver=resolver), patch.object(controller_module, "publish_unclaimed_external_success") as writer:
                result = self.controller(MarkerlessClient()).trusted_validation_role_first(7, resolver)
                self.assertEqual(result.kind, controller_module.Wave08DecisionKind.CONFLICTING_BLOCKED)
                self.assertEqual(writer.call_count, 0)

    def test_callback_failure_fails_closed_without_fallback_status_or_current_main_wiring(self):
        client, state, _claim, route = self.active_issue_fixture()
        result = route.trusted_validation_role_first(
            state.binding.pull_request_number, None,
            central_recovery_dispatcher=lambda *_args: (_ for _ in ()).throw(RuntimeError("dispatch failed")),
        )
        self.assertEqual(result.kind, controller_module.Wave08DecisionKind.CONFLICTING_BLOCKED)
        self.assertEqual(result.reason, controller_module.Wave08DecisionReason.DISPATCH_FAILED)
        self.assertEqual(client.status_calls if hasattr(client, "status_calls") else [], [])
        self.assertEqual(client.check_calls if hasattr(client, "check_calls") else [], [])
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        main = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "main")
        called = {item.id for item in ast.walk(main) if isinstance(item, ast.Name)}
        self.assertNotIn("trusted_validation_role_first", called)


class Wave08UniversalRecoveryTests(unittest.TestCase):
    CENTRAL = Wave05ShaCarrierResolverTests.CENTRAL
    APP = Wave05ShaCarrierResolverTests.APP

    @staticmethod
    def install_inventories(client, pull_numbers=(), issue_numbers=(), machine_refs=(), events=None):
        events = events if events is not None else []

        def prs(_repository, *, max_pages=100):
            events.append("open_pr_inventory")
            return tuple({"number": number, "head_oid": "f" * 40} for number in pull_numbers)

        def issues(_repository, *, state="all", max_pages=100):
            events.append(("issue_inventory", state))
            return tuple({"number": number} for number in issue_numbers)

        def refs(_repository, *, max_pages=100):
            events.append("machine_ref_inventory")
            return tuple(machine_refs)

        client.list_open_pull_requests = prs
        client.list_repository_issues = issues
        client.list_machine_refs = refs
        return events

    @staticmethod
    def finalization_fixture():
        client, issue, _anchor, _lease, state, _claim, _immediate, epoch = (
            Wave05ShaCarrierResolverTests().make_finalization_epoch_client()
        )
        return client, issue, state, epoch, R02Controller(
            client, Wave08UniversalRecoveryTests.CENTRAL, Wave08UniversalRecoveryTests.APP,
        )

    def test_universal_read_only_rejects_semantic_dispatchers_before_inventory_or_mutation(self):
        callback_names = (
            "issue_intake_terminal_dispatcher",
            "issue_finalizer_dispatcher",
            "machine_validation_dispatcher",
            "machine_finalizer_dispatcher",
        )
        for callback_name in callback_names:
            with self.subTest(callback=callback_name):
                client, _issue, _state, _epoch, controller = self.finalization_fixture()
                events = self.install_inventories(client, events=[])
                client.check_calls = list(getattr(client, "check_calls", ()))
                calls = []

                def mutation_state():
                    return (
                        tuple(client.comments),
                        tuple(sorted(
                            (number, tuple(comments))
                            for number, comments in client.pr_comments.items()
                        )),
                        tuple(getattr(client, "comment_writes", ())),
                        tuple(getattr(client, "commit_calls", ())),
                        tuple(getattr(client, "ref_writes", ())),
                        tuple(getattr(client, "status_calls", ())),
                        tuple(getattr(client, "check_calls", ())),
                    )

                before = mutation_state()
                with self.assertRaisesRegex(
                    R02Error,
                    "universal recovery read_only mode forbids semantic dispatch callbacks",
                ):
                    controller.recover_universal_role_first(
                        None,
                        read_only=True,
                        **{callback_name: lambda *args: calls.append(args)},
                    )

                self.assertEqual(calls, [])
                self.assertEqual(events, [], "read-only callback rejection must happen before inventory")
                self.assertEqual(mutation_state(), before)

    def test_universal_failed_owner_fresh_read_shared_h_active_issue_active_revalidates_and_readmits_owner(self):
        client, issue, _anchor, _lease, state, claim = (
            Wave05ShaCarrierResolverTests().make_claim_client()
        )
        controller = R02Controller(client, self.CENTRAL, self.APP)
        owner_number = state.binding.pull_request_number
        peer_number = owner_number + 20
        head_sha = claim.to_head_sha
        stale_inventory_head = "c" * 40
        peer = replace(client.pull_requests[owner_number], number=peer_number, head_oid=head_sha)
        client.pull_requests[peer_number] = peer
        client.pull_request_metadata_sequences[owner_number] = [
            RuntimeError("first owner fresh read timed out"),
        ]
        self.install_inventories(
            client, (owner_number, peer_number), issue_numbers=(issue.number,),
        )
        client.check_calls = []
        initial_issue_comments = tuple(client.comments)
        initial_pr_comments = {number: tuple(comments) for number, comments in client.pr_comments.items()}
        initial_comment_writes = tuple(client.comment_writes)
        initial_commit_calls = tuple(client.commit_calls)
        initial_ref_writes = tuple(client.ref_writes)
        initial_status_calls = tuple(client.status_calls)
        initial_check_calls = tuple(client.check_calls)

        resolutions, owner_proofs, explicit_owner_revalidations = [], [], []
        finalizer_calls, wg1_calls = [], []
        original_resolver = controller_module.resolve_sha_carrier_role
        original_derive_owner = controller_module.derive_issue_owner_pr
        original_get_pr = client.get_pull_request_metadata

        def resolve(*args, **kwargs):
            resolutions.append(args[2])
            return original_resolver(*args, **kwargs)

        def derive_owner(*args, **kwargs):
            result = original_derive_owner(*args, **kwargs)
            owner_proofs.append(result)
            return result

        def get_pr(repository, number):
            if owner_proofs and number == owner_number:
                explicit_owner_revalidations.append(number)
            return original_get_pr(repository, number)

        client.get_pull_request_metadata = get_pr
        with (
            patch.object(controller_module, "resolve_sha_carrier_role", side_effect=resolve),
            patch.object(controller_module, "derive_issue_owner_pr", side_effect=derive_owner),
        ):
            result = controller.recover_universal_role_first(
                None,
                issue_finalizer_dispatcher=lambda decision, owner: finalizer_calls.append((decision, owner)),
                issue_intake_terminal_dispatcher=wg1_calls.append,
            )

        self.assertTrue(result.complete)
        self.assertTrue(any(
            reason.startswith(f"PR_{owner_number}_FRESH_METADATA_UNAVAILABLE:")
            for reason in result.blocked_reasons
        ))
        self.assertEqual(resolutions, [head_sha])
        self.assertNotIn(stale_inventory_head, resolutions)
        self.assertEqual(len(owner_proofs), 1)
        self.assertEqual(owner_proofs[0].pull_request_number, owner_number)
        self.assertEqual(explicit_owner_revalidations, [owner_number])
        self.assertEqual(len(result.decisions), 1)
        decision = result.decisions[0]
        self.assertEqual(decision.resolution.activation, CarrierActivation.ACTIVE)
        self.assertEqual(decision.resolution.role, CarrierRole.ISSUE_ACTIVE)
        self.assertEqual(decision.owning_pr_number, owner_number)
        self.assertEqual(decision.pull_request_numbers, (owner_number, peer_number))
        self.assertEqual(decision.dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_FINALIZER)
        self.assertEqual(len(finalizer_calls), 1)
        self.assertEqual(finalizer_calls[0][0], decision)
        self.assertEqual(finalizer_calls[0][1].pull_request_number, owner_number)
        self.assertEqual(wg1_calls, [])
        self.assertEqual(result.dispatch_intents, ())
        self.assertEqual(result.status_actions, ())
        self.assertEqual(tuple(client.comments), initial_issue_comments)
        self.assertEqual(
            {number: tuple(comments) for number, comments in client.pr_comments.items()},
            initial_pr_comments,
        )
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(tuple(client.commit_calls), initial_commit_calls)
        self.assertEqual(tuple(client.ref_writes), initial_ref_writes)
        self.assertEqual(tuple(client.status_calls), initial_status_calls)
        self.assertEqual(tuple(client.check_calls), initial_check_calls)

    def test_universal_failed_owner_fresh_read_shared_h_active_issue_finalizing_revalidates_and_readmits_owner(self):
        client, issue, state, epoch, controller = self.finalization_fixture()
        owner_number = state.binding.pull_request_number
        peer_number = owner_number + 20
        head_sha = epoch.final_head_sha
        stale_inventory_head = "c" * 40
        client.pull_requests[peer_number] = replace(
            client.pull_requests[owner_number], number=peer_number, head_oid=head_sha,
        )
        client.pull_request_metadata_sequences[owner_number] = [
            RuntimeError("first finalizing owner fresh read timed out"),
        ]
        self.install_inventories(
            client, (owner_number, peer_number), issue_numbers=(issue.number,),
        )
        client.check_calls = []
        initial_issue_comments = tuple(client.comments)
        initial_pr_comments = {number: tuple(comments) for number, comments in client.pr_comments.items()}
        initial_comment_writes = tuple(client.comment_writes)
        initial_commit_calls = tuple(client.commit_calls)
        initial_ref_writes = tuple(client.ref_writes)
        initial_status_calls = tuple(client.status_calls)
        initial_check_calls = tuple(client.check_calls)

        resolutions, owner_proofs, explicit_owner_revalidations = [], [], []
        finalizer_calls, wg1_calls = [], []
        original_resolver = controller_module.resolve_sha_carrier_role
        original_derive_owner = controller_module.derive_issue_owner_pr
        original_get_pr = client.get_pull_request_metadata

        def resolve(*args, **kwargs):
            resolutions.append(args[2])
            return original_resolver(*args, **kwargs)

        def derive_owner(*args, **kwargs):
            result = original_derive_owner(*args, **kwargs)
            owner_proofs.append(result)
            return result

        def get_pr(repository, number):
            if owner_proofs and number == owner_number:
                explicit_owner_revalidations.append(number)
            return original_get_pr(repository, number)

        client.get_pull_request_metadata = get_pr
        with (
            patch.object(controller_module, "resolve_sha_carrier_role", side_effect=resolve),
            patch.object(controller_module, "derive_issue_owner_pr", side_effect=derive_owner),
        ):
            result = controller.recover_universal_role_first(
                None,
                issue_finalizer_dispatcher=lambda decision, owner: finalizer_calls.append((decision, owner)),
                issue_intake_terminal_dispatcher=wg1_calls.append,
            )

        self.assertTrue(result.complete)
        self.assertTrue(any(
            reason.startswith(f"PR_{owner_number}_FRESH_METADATA_UNAVAILABLE:")
            for reason in result.blocked_reasons
        ))
        self.assertEqual(resolutions, [head_sha])
        self.assertNotIn(stale_inventory_head, resolutions)
        self.assertEqual(len(owner_proofs), 1)
        self.assertEqual(owner_proofs[0].pull_request_number, owner_number)
        self.assertEqual(explicit_owner_revalidations, [owner_number])
        self.assertEqual(len(result.decisions), 1)
        decision = result.decisions[0]
        self.assertEqual(decision.resolution.activation, CarrierActivation.ACTIVE)
        self.assertEqual(decision.resolution.role, CarrierRole.ISSUE_FINALIZING)
        self.assertEqual(decision.owning_pr_number, owner_number)
        self.assertEqual(decision.pull_request_numbers, (owner_number, peer_number))
        self.assertEqual(decision.dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_FINALIZER)
        self.assertEqual(len(finalizer_calls), 1)
        self.assertEqual(finalizer_calls[0][0], decision)
        self.assertEqual(finalizer_calls[0][1].pull_request_number, owner_number)
        self.assertEqual(wg1_calls, [])
        self.assertEqual(result.dispatch_intents, ())
        self.assertEqual(result.status_actions, ())
        self.assertEqual(tuple(client.comments), initial_issue_comments)
        self.assertEqual(
            {number: tuple(comments) for number, comments in client.pr_comments.items()},
            initial_pr_comments,
        )
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(tuple(client.commit_calls), initial_commit_calls)
        self.assertEqual(tuple(client.ref_writes), initial_ref_writes)
        self.assertEqual(tuple(client.status_calls), initial_status_calls)
        self.assertEqual(tuple(client.check_calls), initial_check_calls)

    def test_universal_owner_revalidation_head_change_suppresses_same_issue_wg1_and_preserves_unrelated_safe_h(self):
        client, issue, _anchor, _lease, state, claim = (
            Wave05ShaCarrierResolverTests().make_claim_client()
        )
        controller = R02Controller(client, self.CENTRAL, self.APP)
        owner_number = state.binding.pull_request_number
        peer_number = owner_number + 20
        unrelated_number = owner_number + 30
        head_sha = claim.to_head_sha
        unrelated_head = "9" * 40
        changed_owner_head = "8" * 40
        stale_owner_head = "f" * 40
        stale_peer_head = "e" * 40
        stale_unrelated_head = "d" * 40
        owner_pr = client.pull_requests[owner_number]
        client.pull_requests[peer_number] = replace(owner_pr, number=peer_number, head_oid=head_sha)
        client.pull_requests[unrelated_number] = replace(
            owner_pr, number=unrelated_number, head_oid=unrelated_head,
        )
        client.pull_request_metadata_sequences[owner_number] = [
            RuntimeError("first owner fresh read timed out"),
        ]
        self.install_inventories(
            client, (owner_number, peer_number, unrelated_number), issue_numbers=(issue.number,),
        )

        def stale_inventory(_repository, *, max_pages=100):
            return (
                {"number": owner_number, "head_oid": stale_owner_head},
                {"number": peer_number, "head_oid": stale_peer_head},
                {"number": unrelated_number, "head_oid": stale_unrelated_head},
            )

        client.list_open_pull_requests = stale_inventory
        client.check_calls = []
        initial_issue_comments = tuple(client.comments)
        initial_pr_comments = {number: tuple(comments) for number, comments in client.pr_comments.items()}
        initial_comment_writes = tuple(client.comment_writes)
        initial_commit_calls = tuple(client.commit_calls)
        initial_ref_writes = tuple(client.ref_writes)
        initial_status_calls = tuple(client.status_calls)
        initial_check_calls = tuple(client.check_calls)

        resolutions, owner_proofs = [], []
        explicit_owner_revalidations, revalidation_results = [], []
        finalizer_calls, wg1_calls, external_writes = [], [], []
        original_resolver = controller.resolve_current_sha_carrier_role
        original_derive_owner = controller_module.derive_issue_owner_pr
        original_get_pr = client.get_pull_request_metadata

        def resolve(sha):
            resolutions.append(sha)
            if sha == unrelated_head:
                return ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
            return original_resolver(sha)

        def derive_owner(*args, **kwargs):
            result = original_derive_owner(*args, **kwargs)
            owner_proofs.append(result)
            client.pull_request_metadata_sequences[owner_number] = [
                replace(owner_pr, head_oid=changed_owner_head),
            ]
            return result

        def get_pr(repository, number):
            value = original_get_pr(repository, number)
            if owner_proofs and number == owner_number:
                explicit_owner_revalidations.append(number)
                revalidation_results.append(value)
            return value

        def publish_external(_client, _repository, sha, _resolution, _app):
            external_writes.append(sha)

        client.get_pull_request_metadata = get_pr
        with (
            patch.object(controller, "resolve_current_sha_carrier_role", side_effect=resolve),
            patch.object(controller_module, "derive_issue_owner_pr", side_effect=derive_owner),
            patch.object(controller_module, "publish_unclaimed_external_success", side_effect=publish_external),
        ):
            result = controller.recover_universal_role_first(
                lambda _sha: LegacyEvidenceDisposition.ABSENT,
                issue_finalizer_dispatcher=lambda decision, owner: finalizer_calls.append((decision, owner)),
                issue_intake_terminal_dispatcher=wg1_calls.append,
            )

        self.assertTrue(result.complete)
        self.assertEqual(len(owner_proofs), 1)
        self.assertEqual(owner_proofs[0].pull_request_number, owner_number)
        self.assertEqual(explicit_owner_revalidations, [owner_number])
        self.assertEqual(len(revalidation_results), 1)
        self.assertEqual(revalidation_results[0].head_oid, changed_owner_head)
        self.assertEqual(resolutions, sorted((head_sha, unrelated_head)))
        self.assertNotIn(stale_owner_head, resolutions)
        self.assertNotIn(stale_peer_head, resolutions)
        self.assertNotIn(stale_unrelated_head, resolutions)

        owner_decision = next(item for item in result.decisions if item.head_sha == head_sha)
        self.assertEqual(owner_decision.resolution.activation, CarrierActivation.ACTIVE)
        self.assertEqual(owner_decision.resolution.role, CarrierRole.ISSUE_ACTIVE)
        self.assertIsNone(owner_decision.owning_pr_number)
        self.assertEqual(owner_decision.pull_request_numbers, (peer_number,))
        self.assertTrue(any(
            reason == f"{head_sha}:ISSUE_OWNER_PR_HEAD_CHANGED"
            for reason in result.blocked_reasons
        ))
        self.assertEqual(finalizer_calls, [])
        self.assertEqual(wg1_calls, [])
        self.assertFalse(any(intent.issue_number == issue.number for intent in result.dispatch_intents))

        self.assertEqual(external_writes, [unrelated_head])
        self.assertEqual(result.status_actions, ((unrelated_head, "EXTERNAL_SUCCESS"),))
        self.assertEqual(tuple(client.comments), initial_issue_comments)
        self.assertEqual(
            {number: tuple(comments) for number, comments in client.pr_comments.items()},
            initial_pr_comments,
        )
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(tuple(client.commit_calls), initial_commit_calls)
        self.assertEqual(tuple(client.ref_writes), initial_ref_writes)
        self.assertEqual(tuple(client.status_calls), initial_status_calls)
        self.assertEqual(tuple(client.check_calls), initial_check_calls)

    def test_universal_finalizing_head_dispatches_once_to_wg4_even_without_visible_status(self):
        client, issue, state, epoch, controller = self.finalization_fixture()
        owner_number = state.binding.pull_request_number
        owner_pr = client.pull_requests[owner_number]
        for number in (owner_number + 20, owner_number + 10):
            client.pull_requests[number] = replace(owner_pr, number=number)
        events = self.install_inventories(
            client, (owner_number + 20, owner_number, owner_number + 10),
            issue_numbers=(issue.number,), events=[],
        )
        client.check_calls = []
        initial_comment_writes = tuple(client.comment_writes)
        initial_issue_comments = tuple(client.comments)
        initial_pr_comments = {number: tuple(comments) for number, comments in client.pr_comments.items()}
        initial_ref_writes = tuple(client.ref_writes)
        initial_commit_calls = tuple(client.commit_calls)
        initial_status_calls = tuple(client.status_calls)
        initial_check_calls = tuple(client.check_calls)
        finalizer_calls, wg1_calls, resolutions = [], [], []
        original_resolver = controller_module.resolve_sha_carrier_role

        def resolve(*args, **kwargs):
            events.append(("resolve", args[2]))
            resolutions.append(args[2])
            return original_resolver(*args, **kwargs)

        with patch.object(controller_module, "resolve_sha_carrier_role", side_effect=resolve):
            result = controller.recover_universal_role_first(
                None,
                issue_intake_terminal_dispatcher=wg1_calls.append,
                issue_finalizer_dispatcher=lambda decision, owner: finalizer_calls.append((decision, owner)),
            )

        self.assertTrue(result.complete)
        self.assertEqual(result.distinct_pr_head_count, 1)
        self.assertEqual(resolutions, [epoch.final_head_sha])
        self.assertEqual(result.decisions[0].resolution.role, CarrierRole.ISSUE_FINALIZING)
        self.assertEqual(result.decisions[0].dispatch_target, controller_module.Wave08DispatchTarget.ISSUE_FINALIZER)
        self.assertEqual(result.decisions[0].pull_request_numbers, tuple(sorted(client.pull_requests)))
        self.assertEqual(result.decisions[0].owning_pr_number, owner_number)
        self.assertEqual(len(finalizer_calls), 1)
        self.assertEqual(finalizer_calls[0][1].issue_number, issue.number)
        self.assertEqual(wg1_calls, [])
        self.assertEqual(result.dispatch_intents, ())
        self.assertEqual(result.relevant_issue_count, 1)
        self.assertEqual(len(result.issue_recoveries), 1)
        self.assertEqual(result.issue_recoveries[0].issue_number, issue.number)
        self.assertEqual(result.issue_recoveries[0].outcome, "DEFERRED")
        self.assertEqual(
            result.issue_recoveries[0].reason,
            "EXACT_ACTIVE_ISSUE_FINALIZER_OWNS_WG4_DISPATCH",
        )
        self.assertEqual(result.status_actions, ())
        self.assertEqual(getattr(client, "status_calls", []), [])
        self.assertEqual(getattr(client, "check_calls", []), [])
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(tuple(client.comments), initial_issue_comments)
        self.assertEqual(
            {number: tuple(comments) for number, comments in client.pr_comments.items()},
            initial_pr_comments,
        )
        self.assertEqual(tuple(client.ref_writes), initial_ref_writes)
        self.assertEqual(tuple(client.commit_calls), initial_commit_calls)
        self.assertEqual(tuple(client.status_calls), initial_status_calls)
        self.assertEqual(tuple(client.check_calls), initial_check_calls)
        inventory_events = ("open_pr_inventory", ("issue_inventory", "all"), "machine_ref_inventory")
        self.assertLess(max(events.index(item) for item in inventory_events), events.index(("resolve", epoch.final_head_sha)))

    def test_wg1_direct_recovery_defers_exact_active_issue_finalizing_head_before_source_resolution(self):
        client, issue, state, epoch, controller = self.finalization_fixture()
        owner_number = state.binding.pull_request_number
        client.check_calls = []
        initial_issue_comments = tuple(client.comments)
        initial_pr_comments = tuple(client.pr_comments[owner_number])
        initial_comment_writes = tuple(client.comment_writes)
        initial_commit_calls = tuple(client.commit_calls)
        initial_ref_writes = tuple(client.ref_writes)
        initial_status_calls = tuple(client.status_calls)
        initial_check_calls = tuple(client.check_calls)
        source_resolver_calls = []
        final_green_calls, required_epoch_calls = [], []

        def source_resolver(*args):
            source_resolver_calls.append(args)
            raise AssertionError("Wg1 must hand finalizing authority to Wg4 before source resolution")

        controller.publish_issue_final_success = lambda *args, **kwargs: final_green_calls.append((args, kwargs))
        controller.revoke_required_status_epoch = lambda *args, **kwargs: required_epoch_calls.append((args, kwargs))
        result = controller.recover_issue_first_authority(issue.number, source_resolver)

        self.assertEqual(result.outcome, "DEFERRED")
        self.assertEqual(result.reason, "ISSUE_FINALIZER_OWNED_BY_WG4")
        self.assertEqual(source_resolver_calls, [])
        self.assertEqual(final_green_calls, [])
        self.assertEqual(required_epoch_calls, [])
        self.assertEqual(tuple(client.comments), initial_issue_comments)
        self.assertEqual(tuple(client.pr_comments[owner_number]), initial_pr_comments)
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(tuple(client.commit_calls), initial_commit_calls)
        self.assertEqual(tuple(client.ref_writes), initial_ref_writes)
        self.assertEqual(tuple(client.status_calls), initial_status_calls)
        self.assertEqual(tuple(client.check_calls), initial_check_calls)
        resolution = controller_module.resolve_sha_carrier_role(
            client, self.CENTRAL, epoch.final_head_sha, self.APP.slug,
            LegacyEvidenceDisposition.CONFLICTING,
        )
        self.assertEqual(resolution.activation, CarrierActivation.ACTIVE)
        self.assertEqual(resolution.role, CarrierRole.ISSUE_FINALIZING)
        self.assertEqual(
            tuple(client.pr_comments[owner_number]),
            initial_pr_comments,
            "Wg1 must not persist an IssueHeadClaim that poisons authority history",
        )

    def test_universal_isolates_one_fresh_pr_metadata_failure_from_safe_sha_work(self):
        client, _issue, state, _epoch, controller = self.finalization_fixture()
        first = client.pull_requests[state.binding.pull_request_number]
        failed_pr_number = first.number + 10
        safe_pr_number = first.number + 20
        stale_failed_head = "c" * 40
        stale_safe_head = "d" * 40
        safe_head = "e" * 40
        client.pull_requests[failed_pr_number] = replace(
            first, number=failed_pr_number, head_oid=stale_failed_head,
        )
        client.pull_requests[safe_pr_number] = replace(
            first, number=safe_pr_number, head_oid=safe_head,
        )
        client.pull_request_metadata_sequences[failed_pr_number] = [RuntimeError("fresh PR read timed out")]
        events = self.install_inventories(client, (failed_pr_number, safe_pr_number), events=[])

        def inventory_with_distinct_stale_heads(_repository, *, max_pages=100):
            events.append("open_pr_inventory")
            return (
                {"number": failed_pr_number, "head_oid": stale_failed_head},
                {"number": safe_pr_number, "head_oid": stale_safe_head},
            )

        client.list_open_pull_requests = inventory_with_distinct_stale_heads
        resolution_calls, external_writes = [], []

        def explicit_unclaimed(sha):
            events.append(("resolve", sha))
            resolution_calls.append(sha)
            return ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)

        def publish_external(_client, _repository, sha, _resolution, _app):
            events.append(("publish", sha))
            external_writes.append(sha)

        with (
            patch.object(controller, "resolve_current_sha_carrier_role", side_effect=explicit_unclaimed),
            patch.object(controller_module, "publish_unclaimed_external_success", side_effect=publish_external),
        ):
            result = controller.recover_universal_role_first(
                lambda _sha: LegacyEvidenceDisposition.ABSENT,
            )

        self.assertTrue(result.complete)
        self.assertEqual(result.open_pr_inventory_count, 2)
        self.assertEqual(result.fresh_pr_count, 1)
        self.assertEqual(result.distinct_pr_head_count, 1)
        self.assertEqual(resolution_calls, [safe_head])
        self.assertNotIn(stale_failed_head, resolution_calls)
        self.assertNotIn(stale_safe_head, resolution_calls)
        self.assertEqual(external_writes, [safe_head])
        self.assertEqual(result.status_actions, ((safe_head, "EXTERNAL_SUCCESS"),))
        self.assertEqual(tuple(item.head_sha for item in result.decisions), (safe_head,))
        self.assertTrue(any(
            reason.startswith(f"PR_{failed_pr_number}_FRESH_METADATA_UNAVAILABLE:")
            for reason in result.blocked_reasons
        ))
        self.assertFalse(any(
            "FRESH_PR_HEAD_UNAVAILABLE_OR_GROUPING_AMBIGUOUS; SHA ACTIONS SUPPRESSED" in reason
            for reason in result.blocked_reasons
        ))
        inventory_events = ("open_pr_inventory", ("issue_inventory", "all"), "machine_ref_inventory")
        self.assertLess(
            max(events.index(item) for item in inventory_events),
            events.index(("publish", safe_head)),
        )

    def test_universal_uses_fresh_heads_and_one_external_status_per_distinct_shared_sha(self):
        client, _issue, state, _epoch, controller = self.finalization_fixture()
        first_owner = state.binding.pull_request_number
        first = client.pull_requests[first_owner]
        second_sha, third_sha = "a" * 40, "b" * 40
        client.pull_requests[first_owner + 1] = replace(first, number=first_owner + 1)
        client.pull_requests[first_owner + 2] = replace(first, number=first_owner + 2, head_oid=second_sha)
        client.pull_requests[first_owner + 3] = replace(first, number=first_owner + 3, head_oid=second_sha)
        client.pull_requests[first_owner + 4] = replace(first, number=first_owner + 4, head_oid=third_sha)
        all_numbers = tuple(sorted(client.pull_requests))
        events = self.install_inventories(client, all_numbers, events=[])
        resolution_calls, status_calls = [], []

        def explicit_legacy(sha):
            events.append(("resolve", sha))
            resolution_calls.append(sha)
            return ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)

        with (
            patch.object(controller, "resolve_current_sha_carrier_role", side_effect=explicit_legacy),
            patch.object(controller_module, "publish_unclaimed_external_success", side_effect=lambda _client, _repo, sha, _resolution, _app: status_calls.append(sha)),
        ):
            result = controller.recover_universal_role_first(
                lambda _sha: LegacyEvidenceDisposition.ABSENT,
            )

        self.assertEqual(resolution_calls, sorted((first.head_oid, second_sha, third_sha)))
        self.assertEqual(result.distinct_pr_head_count, 3)
        self.assertEqual(status_calls, sorted((first.head_oid, second_sha, third_sha)), result)
        self.assertEqual(len(result.status_actions), 3)
        self.assertEqual(tuple(item.head_sha for item in result.decisions), tuple(sorted(resolution_calls)))
        self.assertTrue(all(item.kind is controller_module.Wave08DecisionKind.EXTERNAL_STATUS for item in result.decisions))
        self.assertEqual(events.count(("issue_inventory", "all")), 1)
        self.assertEqual(events.count("machine_ref_inventory"), 1)

    def test_machine_ref_without_open_pr_is_retained_as_orphan_deferred_evidence(self):
        client, _issue, _anchor, _lease = Wave05ShaCarrierResolverTests.make_client()
        controller = R02Controller(client, self.CENTRAL, self.APP)
        sha = "9" * 40
        self.install_inventories(client, machine_refs=(
            {"ref": "refs/heads/bot/federation/retired-source", "source_id": "retired-source", "sha": sha},
        ))
        controller._accepted_sources = lambda _main=None: ()
        result = controller.recover_universal_role_first(None)
        self.assertTrue(result.complete)
        self.assertEqual(result.machine_ref_inventory_count, 1)
        self.assertEqual(len(result.machine_refs), 1)
        self.assertEqual(result.machine_refs[0].head_sha, sha)
        self.assertEqual(result.machine_refs[0].outcome, "DEFERRED_ORPHANED_SOURCE")
        self.assertEqual(result.decisions, ())
        self.assertEqual(getattr(client, "status_calls", []), [])
        self.assertEqual(getattr(client, "check_calls", []), [])

    def test_machine_namespace_suppresses_unclaimed_success_and_reserved_machine_never_passes(self):
        client, _issue, _anchor, _lease, _state, claim = Wave05ShaCarrierResolverTests().make_claim_client()
        controller = R02Controller(client, self.CENTRAL, self.APP)
        owner_number = next(iter(client.pull_requests))
        row = {"ref": "refs/heads/bot/federation/owner-repo", "source_id": "owner-repo", "sha": claim.to_head_sha}
        self.install_inventories(client, (owner_number,), machine_refs=(row,))
        controller._accepted_sources = lambda _main=None: ()
        unclaimed_writes = []
        with (
            patch.object(controller_module, "resolve_sha_carrier_role", return_value=ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)),
            patch.object(controller_module, "publish_unclaimed_external_success", side_effect=lambda *args: unclaimed_writes.append(args)),
        ):
            result = controller.recover_universal_role_first(lambda _sha: LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(unclaimed_writes, [])
        self.assertEqual(result.decisions[0].kind, controller_module.Wave08DecisionKind.CONFLICTING_BLOCKED)
        self.assertEqual(getattr(client, "check_calls", []), [])

        marker = Wave08RoleDecisionContractTests.marker(
            CarrierRole.MACHINE_PUBLICATION, "MACHINE_REF_CLAIM",
            owner_kind="MACHINE_SOURCE", owner_key=f"{client.get_repository_metadata(self.CENTRAL).node_id}:owner-repo",
        )
        reserved = ShaCarrierResolution(CarrierActivation.RESERVED_INACTIVE, CarrierRole.MACHINE_PUBLICATION, marker)
        with patch.object(controller_module, "resolve_sha_carrier_role", return_value=reserved):
            result = controller.recover_universal_role_first(lambda _sha: LegacyEvidenceDisposition.ABSENT)
        self.assertEqual(result.decisions[0].kind, controller_module.Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED)
        self.assertEqual(result.status_actions, ())
        self.assertEqual(getattr(client, "check_calls", []), [])

    def test_exact_active_machine_role_dispatches_machine_validation_without_manual_status(self):
        client, _issue, _anchor, _lease, state, claim = Wave05ShaCarrierResolverTests().make_claim_client()
        controller = R02Controller(client, self.CENTRAL, self.APP)
        number = state.binding.pull_request_number
        head = claim.to_head_sha
        source = c02.SourceDeclaration(
            "owner-repo", "Owner/Repo", 41, "skills", "Source",
            (c02.LineDeclaration("refs/heads/main", ("owner-repo",)),),
        )
        central_node_id = client.get_repository_metadata(self.CENTRAL).node_id
        marker = Wave08RoleDecisionContractTests.marker(
            CarrierRole.MACHINE_PUBLICATION, "MACHINE_REF_CLAIM",
            owner_kind="MACHINE_SOURCE", owner_key=f"{central_node_id}:owner-repo",
        )
        active = ShaCarrierResolution(CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION, marker)
        original = client.pull_requests[number]
        client.pull_requests[number] = replace(
            original, head_ref="bot/federation/owner-repo", head_oid=head,
            head_repository=self.CENTRAL, head_repository_id=central_node_id,
            base_ref="main", base_repository=self.CENTRAL, base_repository_id=central_node_id,
        )
        self.install_inventories(client, (number,), machine_refs=(
            {"ref": "refs/heads/bot/federation/owner-repo", "source_id": "owner-repo", "sha": head},
        ))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_authority = lambda summary, declaration, _main, _repository: (
            controller_module.MachinePRAuthority(
                summary["number"], declaration.source_id, declaration.repository_id, head,
            )
        )
        machine_calls, manual_calls, wg1_calls = [], [], []
        with patch.object(controller_module, "resolve_sha_carrier_role", return_value=active):
            result = controller.recover_universal_role_first(
                None,
                issue_intake_terminal_dispatcher=wg1_calls.append,
                issue_finalizer_dispatcher=lambda *args: manual_calls.append(args),
                machine_validation_dispatcher=lambda decision, authority: machine_calls.append((decision, authority)),
            )
        self.assertEqual(len(machine_calls), 1)
        self.assertEqual(machine_calls[0][0].dispatch_target, controller_module.Wave08DispatchTarget.MACHINE_VALIDATION)
        self.assertEqual(machine_calls[0][1].head_sha, head)
        self.assertEqual(manual_calls, [])
        self.assertEqual(wg1_calls, [])
        self.assertEqual(result.status_actions, ())
        self.assertEqual(getattr(client, "status_calls", []), [])
        self.assertEqual(getattr(client, "check_calls", []), [])
        self.assertEqual(result.machine_refs[0].outcome, "DISPATCHED")

    def test_issue_inventory_dispatches_strict_unanchored_form_and_ignores_ordinary_issue(self):
        client, issue, _anchor, _lease = Wave05ShaCarrierResolverTests.make_client()
        controller = R02Controller(client, self.CENTRAL, self.APP)
        client.comments = []
        self.install_inventories(client, issue_numbers=(issue.number,))
        intents = []
        result = controller.recover_universal_role_first(
            None, issue_intake_terminal_dispatcher=intents.append,
        )
        self.assertEqual(result.relevant_issue_count, 1)
        self.assertEqual(len(intents), 1)
        self.assertEqual(intents[0].target, controller_module.Wave08DispatchTarget.ISSUE_INTAKE_TERMINAL_RECOVERY)
        self.assertEqual(intents[0].issue_number, issue.number)

        client.issue = replace(issue, body="An ordinary unrelated Issue")
        intents.clear()
        result = controller.recover_universal_role_first(
            None, issue_intake_terminal_dispatcher=intents.append,
        )
        self.assertEqual(result.relevant_issue_count, 0)
        self.assertEqual(intents, [])

        client.issue = replace(issue, body="### Federation request type\n\nnot a valid form")
        result = controller.recover_universal_role_first(
            None, issue_intake_terminal_dispatcher=intents.append,
        )
        self.assertEqual(result.relevant_issue_count, 1)
        self.assertEqual(result.issue_recoveries[0].outcome, "BLOCKED")
        self.assertEqual(intents, [])

    def test_wg6_active_cancel_publishes_exact_failure_before_wg1_dispatch(self):
        client, issue, _anchor, _lease, _state, controller, fence = (
            Wave07CancellationControllerTests()._prepare(binding="FULL_BINDING")
        )
        number = fence.pull_request_number
        self.install_inventories(client, (number,))
        initial_comment_writes = tuple(client.comment_writes)
        dispatch_observations = []
        result = controller.recover_universal_role_first(
            None,
            issue_intake_terminal_dispatcher=lambda intent: dispatch_observations.append(
                (intent, len(client.status_posts)),
            ),
        )
        self.assertEqual(len(client.status_posts), 1)
        self.assertEqual(result.status_actions, ((fence.cancellation_head_sha, "ISSUE_CANCEL_FAILURE"),))
        self.assertEqual(len(dispatch_observations), 1)
        intent, visible_status_posts = dispatch_observations[0]
        self.assertEqual(intent.target, controller_module.Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY)
        self.assertEqual(intent.issue_number, issue.number)
        self.assertEqual(visible_status_posts, 1)
        self.assertEqual(tuple(client.comment_writes), initial_comment_writes)
        self.assertEqual(getattr(client, "check_calls", []), [])

    def test_wg1_closed_anchor_only_recovery_never_uses_source_registry_or_finalizer_apis(self):
        client, issue, _anchor, _lease, controller = Wave07CancellationControllerTests()._no_pr_fixture(
            with_lease=False,
        )
        forbidden = []
        controller.publish_issue_final_success = lambda *_args, **_kwargs: forbidden.append("final-green")
        controller.revoke_required_status_epoch = lambda *_args, **_kwargs: forbidden.append("required-status-epoch")
        calls = []

        def source_resolver(*_args):
            calls.append("source")
            raise AssertionError("closed cancellation must not consult current source registry")

        result = controller.recover_issue_first_authority(issue.number, source_resolver)
        self.assertEqual(result.outcome, "CANCELLED_NO_PR")
        self.assertEqual(calls, [])
        self.assertEqual(forbidden, [])

    def test_recovery_layers_never_call_issue_final_green_rse_or_machine_check_writers(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        cls = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "R02Controller")
        methods = {item.name: item for item in cls.body if isinstance(item, ast.FunctionDef)}
        for name in ("recover_universal_role_first", "recover_issue_first_authority"):
            called = {
                item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
                for item in ast.walk(methods[name])
                if isinstance(item, ast.Call) and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
            }
            self.assertFalse(called & {
                "publish_issue_final_success", "revoke_required_status_epoch",
                "create_check_run", "update_check_run", "upsert_trusted_validation_check",
            })


class Wave09LegacyClassifierTests(unittest.TestCase):
    CENTRAL = "swiftstream/skills"
    HEAD = "a" * 40
    BASE = "b" * 40
    APP = AppIdentity("swift-stream-federation", 10, "A_app", 11, "B_bot", "swift-stream-federation[bot]")
    REPOSITORY = RepositoryMetadata(22, "R_central", CENTRAL, "main")

    def setUp(self):
        # Every exact machine-source fixture is deterministic and exercises the
        # same public metadata seam used by the fresh identity check.
        source_read = patch.object(
            controller_module,
            "read_public_source_metadata",
            return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None),
        )
        source_read.start()
        self.addCleanup(source_read.stop)

    class Client:
        def __init__(self, message="ordinary commit\n"):
            self.repository = Wave09LegacyClassifierTests.REPOSITORY
            self.app = Wave09LegacyClassifierTests.APP
            self.message = message
            self.parents = (Wave09LegacyClassifierTests.BASE,)
            self.class_reads = []
            self.fail_reads = set()
            self.prs = {}
            self.comments = {}
            self.files = {}
            self.checks = ()
            self.machine_refs = ()
            self.mutations = []
            self.status_calls = []
            self.repository_reads = 0
            self.receipt_builder = None

        def get_repository_metadata(self, _repository):
            self.repository_reads += 1
            return self.repository

        def get_git_commit_object(self, _repository, sha):
            identity = GitCommitIdentity("Maintainer", "maintainer@example.com", "2026-10-01T00:00:00Z")
            return GitCommitObject(sha, self.message, "c" * 40, self.parents, identity, identity)

        def get_app_metadata(self, slug):
            return AppMetadata(self.app.app_id, slug, self.app.app_node_id)

        def get_bot_metadata(self, slug):
            return BotMetadata(self.app.bot_id, self.app.bot_login, self.app.bot_node_id, "Bot")

        def list_machine_refs(self, _repository):
            self.class_reads.append("machine_refs")
            if "machine_refs" in self.fail_reads:
                raise RuntimeError("machine refs unavailable")
            return self.machine_refs

        def list_open_pull_requests(self, _repository):
            self.class_reads.append("open_prs")
            return tuple({"number": number} for number in self.prs)

        def list_pull_requests(self, _repository, *, state="open"):
            self.class_reads.append("all_prs")
            if "all_prs" in self.fail_reads:
                raise RuntimeError("PR inventory unavailable")
            return tuple({"number": number} for number in self.prs)

        def get_pull_request_metadata(self, _repository, number):
            self.class_reads.append("pr_metadata")
            return self.prs[number]

        def list_issue_comments(self, _repository, number):
            self.class_reads.append("comments")
            if "comments" in self.fail_reads:
                raise RuntimeError("comment inventory unavailable")
            return self.comments.get(number, ())

        def list_pull_request_files(self, _repository, number):
            self.class_reads.append("files")
            return self.files.get(number, ())

        def list_check_runs(self, _repository, _sha):
            self.class_reads.append("checks")
            if "checks" in self.fail_reads:
                raise RuntimeError("Check Run inventory unavailable")
            return self.checks

        def create_commit_status(self, repository, sha, state, context, description, target_url):
            self.status_calls.append((repository, sha, state, context, description, target_url))
            self.mutations.append("create_commit_status")
            if self.receipt_builder is not None:
                return self.receipt_builder(repository, sha, state, context, description, target_url)
            status = CommitStatus(
                901, "ST_status", state, context, description, target_url,
                self.app.bot_id, self.app.bot_node_id, self.app.bot_login, "Bot",
                "2026-10-07T00:00:00Z", "2026-10-07T00:00:00Z",
            )
            return StatusWriteReceipt(
                repository, sha, "POST", f"/repos/{repository}/statuses/{sha}",
                state, context, description, target_url, status,
            )

    @classmethod
    def controller(cls, client=None):
        return R02Controller(client or cls.Client(), cls.CENTRAL, cls.APP)

    @classmethod
    def manual_fixture(cls, *, request_class=RequestClass.UPDATE, author_id="U_human", author_login="alice",
                       comment_id=700, comment_node="IC_anchor", comment_author_id="B_bot",
                       comment_author_login="swift-stream-federation[bot]", comment_author_type="Bot",
                       app=None, body_text=None, changed_paths=("federation.json",), description="Source"):
        app = app or cls.APP
        request = parse_request_body(
            request_class,
            "Repository URL:\nhttps://github.com/Owner/Repo\n"
            f"Description:\n{description}\nBranch:\nmain\nSkills root:\nskills\n"
            "Skill prefixes:\nowner\nPublication lines:\nrefs/heads/main=owner\n",
        )
        body = controller_module.render_request_body(request) if body_text is None else body_text
        anchor = RequestAnchor(
            81, request_class, author_id, author_login, body_sha256(body), request,
        )
        pr = PullRequestMetadata(
            81, body, author_id, author_login, cls.HEAD, cls.BASE,
            "legacy/topic", "main", "R_central", cls.CENTRAL,
            "R_central", cls.CENTRAL, None, False, False,
        )
        comment = IssueComment(
            comment_node, comment_id, anchor.render(), comment_author_id,
            comment_author_login, comment_author_type, None, None, None, None, False,
        )
        client = cls.Client()
        client.app = app
        client.prs = {81: pr}
        client.comments = {81: (comment,)}
        client.files = {81: tuple({"filename": path} for path in changed_paths)}
        return client, app, pr, anchor, comment

    def test_reserved_family_matrix_conflicts_before_class_predicates(self):
        reserved_messages = (
            "swiftstream-federation-head:v0\n",
            "swiftstream-federation-head:v1\n",
            "swiftstream-federation-head:v3\n",
            "swiftstream-federation-head:v999\n",
            "swiftstream-federation-head:future\n",
            "swiftstream-federation-head:\n",
            "swiftstream-federation-head:v2x\n",
            "swiftstream-federation-head:v2\nrole=ISSUE_ACTIVE\nrole=ISSUE_CANCEL\n",
            "swiftstream-federation-head:v2\nclaim-kind=UNKNOWN\n",
            "swiftstream-federation-head:v2\nclaim-kind=ISSUE_HEAD_CLAIM\nrole=UNKNOWN\n",
            ClaimedHeadMarker(
                "ISSUE_BRANCH_LEASE", "ISSUE_ACTIVE", "ISSUE", "R_central:700:I_kwDOIssue:7",
                "1" * 64, "2" * 64, "INITIAL",
            ).render(),
        )
        for message in reserved_messages:
            with self.subTest(message=message):
                client = self.Client(message)
                result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
                self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)
                self.assertIsNone(result.evidence)
                self.assertEqual(result.reason, "RESERVED_CLAIM_FAMILY_PRESENT")
                self.assertEqual(client.class_reads, [])

    def test_empty_current_evidence_is_absent_and_adapter_preserves_wave08_semantics(self):
        result = self.controller().classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertEqual(result.outcome, LegacyClassificationOutcome.ABSENT)
        self.assertEqual(result.reason, "EXACT_LEGACY_EVIDENCE_ABSENT")
        self.assertEqual(legacy_classification_disposition(result), LegacyEvidenceDisposition.ABSENT)
        for outcome, disposition, activation in (
            (LegacyClassificationOutcome.ABSENT, LegacyEvidenceDisposition.ABSENT, CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION),
            (LegacyClassificationOutcome.QUARANTINE, LegacyEvidenceDisposition.QUARANTINE, CarrierActivation.LEGACY_CUTOVER_QUARANTINE),
            (LegacyClassificationOutcome.CONFLICTING, LegacyEvidenceDisposition.CONFLICTING, CarrierActivation.CONFLICTING),
        ):
            fake = self.Client()
            mapped = legacy_classification_disposition(LegacyClassificationResult(outcome, None, "EXACT_LEGACY_EVIDENCE_ABSENT") if outcome is not LegacyClassificationOutcome.QUARANTINE else LegacyClassificationResult(outcome, LegacyQuarantineEvidence(1, LegacyQuarantineClass.MACHINE, 22, "R_central", self.CENTRAL, self.HEAD, "f" * 64), "EXACT_LEGACY_MACHINE"))
            self.assertIs(mapped, disposition)
            resolution = resolve_sha_carrier_role(fake, self.CENTRAL, self.HEAD, self.APP.slug, mapped)
            self.assertIs(resolution.activation, activation)

    def test_manual_evidence_fixed_vector_uses_exact_anchor_scope_and_full_payload(self):
        client, app, pr, anchor, comment = self.manual_fixture()
        result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(result.outcome, LegacyClassificationOutcome.QUARANTINE)
        self.assertIs(result.evidence.evidence_class, LegacyQuarantineClass.MANUAL)
        self.assertEqual(result.reason, "EXACT_LEGACY_MANUAL")
        anchor_literal = anchor.render()
        self.assertEqual(anchor_literal,
            "<!-- swiftstream-federation-request-anchor:v1 -->\n"
            "{\"initialBodySha256\":\"419caaad53050bd924b100a38f83ed00c77aad68313a85d6bb16551411b837e4\","
            "\"initialRequest\":{\"Branch\":\"refs/heads/main\",\"Description\":\"Source\","
            "\"Dropped publication lines\":null,\"Publication lines\":[{\"ref\":\"refs/heads/main\","
            "\"skillPrefixes\":[\"owner\"]}],\"Reason\":null,\"Repository URL\":\"https://github.com/Owner/Repo\","
            "\"Skill prefixes\":[\"owner\"],\"Skills root\":\"skills\"},\"originalAuthorId\":\"U_human\","
            "\"originalAuthorLogin\":\"alice\",\"prNumber\":81,\"requestClass\":\"update\",\"schemaVersion\":2}\n")
        anchor_digest = hashlib.sha256(anchor_literal.encode("utf-8")).hexdigest()
        scope_value = {"changedPaths": ["federation.json"], "requestClass": "update"}
        scope_json = json.dumps(scope_value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        scope_digest = hashlib.sha256(("swiftstream-federation-legacy-manual-proposal-scope:v1\n" + scope_json).encode("utf-8")).hexdigest()
        payload = {
            "schemaVersion": 1,
            "pullRequestNumber": 81,
            "originalRequestAuthorNodeId": "U_human",
            "originalRequestAuthorLogin": "alice",
            "headOid": self.HEAD,
            "baseOid": self.BASE,
            "headRef": "legacy/topic",
            "baseRef": "main",
            "headRepositoryNodeId": "R_central",
            "baseRepositoryNodeId": "R_central",
            "headRepositoryFullName": self.CENTRAL,
            "baseRepositoryFullName": self.CENTRAL,
            "requestAnchorCommentDatabaseId": 700,
            "requestAnchorCommentNodeId": "IC_anchor",
            "requestAnchorCanonicalSha256": anchor_digest,
            "requestClass": "update",
            "initialBodySha256": anchor.initial_body_sha256,
            "appBotDatabaseId": app.bot_id,
            "appBotNodeId": app.bot_node_id,
            "appBotLogin": app.bot_login,
            "anchorCommentAuthorNodeId": comment.author_id,
            "anchorCommentAuthorLogin": comment.author_login,
            "anchorCommentAuthorType": comment.author_type,
            "anchorCommentEditorNodeId": comment.editor_id,
            "anchorCommentEditorLogin": comment.editor_login,
            "anchorCommentEditorType": comment.editor_type,
            "anchorCommentLastEditedAt": comment.last_edited_at,
            "anchorCommentIncludesCreatedEdit": comment.includes_created_edit,
            "proposalScopeDigest": scope_digest,
        }
        expected_payload_json = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        expected_digest = hashlib.sha256(("swiftstream-federation-legacy-manual-evidence:v1\n" + expected_payload_json).encode("utf-8")).hexdigest()
        self.assertEqual(result.evidence.evidence_payload_digest, expected_digest)

    def test_manual_evidence_sensitivity_binds_human_app_anchor_and_scope_fields(self):
        base_client, _app, _pr, _anchor, _comment = self.manual_fixture()
        baseline = self.controller(base_client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        baseline_digest = baseline.evidence.evidence_payload_digest
        variants = (
            {"author_id": "U_other"},
            {"author_login": "bob"},
            {"comment_id": 701},
            {"comment_node": "IC_other"},
            {"description": "Changed request"},
            {"request_class": RequestClass.ADD},
            {"app": replace(self.APP, bot_id=12)},
            {"app": replace(self.APP, bot_node_id="B_other"), "comment_author_id": "B_other"},
            {
                "app": replace(self.APP, slug="swift-stream-federation-next", bot_login="swift-stream-federation-next[bot]"),
                "comment_author_login": "swift-stream-federation-next[bot]",
            },
            {"comment_author_type": None},
            {"changed_paths": ("federation.lock.json",)},
        )
        for values in variants:
            with self.subTest(values=values):
                client, app, _pr, _anchor, _comment = self.manual_fixture(**values)
                result = R02Controller(client, self.CENTRAL, app).classify_legacy_head(
                    self.HEAD, implementation_reviewed_head_sha="e" * 40,
                )
                self.assertIs(result.outcome, LegacyClassificationOutcome.QUARANTINE)
                self.assertIs(result.evidence.evidence_class, LegacyQuarantineClass.MANUAL)
                self.assertNotEqual(result.evidence.evidence_payload_digest, baseline_digest)

    def test_manual_payload_digest_changes_for_exactly_one_frozen_field(self):
        baseline = {
            "schemaVersion": 1,
            "pullRequestNumber": 81,
            "originalRequestAuthorNodeId": "U_human",
            "originalRequestAuthorLogin": "alice",
            "headOid": self.HEAD,
            "baseOid": self.BASE,
            "headRef": "legacy/topic",
            "baseRef": "main",
            "headRepositoryNodeId": "R_central",
            "baseRepositoryNodeId": "R_central",
            "headRepositoryFullName": self.CENTRAL,
            "baseRepositoryFullName": self.CENTRAL,
            "requestAnchorCommentDatabaseId": 700,
            "requestAnchorCommentNodeId": "IC_anchor",
            "requestAnchorCanonicalSha256": "264f587ac8dbfb5f3d8b0342891b1b0881bb190f947e7366503a2fa0b831d8b0",
            "requestClass": "update",
            "initialBodySha256": "419caaad53050bd924b100a38f83ed00c77aad68313a85d6bb16551411b837e4",
            "appBotDatabaseId": 10,
            "appBotNodeId": "B_bot",
            "appBotLogin": "swift-stream-federation[bot]",
            "anchorCommentAuthorNodeId": "B_bot",
            "anchorCommentAuthorLogin": "swift-stream-federation[bot]",
            "anchorCommentAuthorType": "Bot",
            "anchorCommentEditorNodeId": None,
            "anchorCommentEditorLogin": None,
            "anchorCommentEditorType": None,
            "anchorCommentLastEditedAt": None,
            "anchorCommentIncludesCreatedEdit": False,
            "proposalScopeDigest": "a367ea6ccee3586aeb018c2d45aa796a49f165d5d23e6a9288b7983f0e892da4",
        }
        prefix = "swiftstream-federation-legacy-manual-evidence:v1\n"
        baseline_digest = _legacy_payload_digest(prefix, baseline)
        mutations = {
            "originalRequestAuthorNodeId": "U_other",
            "originalRequestAuthorLogin": "bob",
            "requestAnchorCommentDatabaseId": 701,
            "requestAnchorCommentNodeId": "IC_other",
            "requestAnchorCanonicalSha256": "4" * 64,
            "requestClass": "add",
            "initialBodySha256": "5" * 64,
            "appBotDatabaseId": 12,
            "appBotNodeId": "B_other",
            "appBotLogin": "other[bot]",
            "anchorCommentAuthorNodeId": "B_comment_other",
            "anchorCommentAuthorLogin": "comment-other[bot]",
            "anchorCommentAuthorType": "User",
            "proposalScopeDigest": "6" * 64,
        }
        self.assertEqual(set(mutations), {
            "originalRequestAuthorNodeId", "originalRequestAuthorLogin",
            "requestAnchorCommentDatabaseId", "requestAnchorCommentNodeId",
            "requestAnchorCanonicalSha256", "requestClass", "initialBodySha256",
            "appBotDatabaseId", "appBotNodeId", "appBotLogin",
            "anchorCommentAuthorNodeId", "anchorCommentAuthorLogin",
            "anchorCommentAuthorType", "proposalScopeDigest",
        })
        for key, value in mutations.items():
            changed = dict(baseline)
            changed[key] = value
            different_keys = {name for name in baseline if changed[name] != baseline[name]}
            with self.subTest(field=key):
                self.assertEqual(different_keys, {key})
                self.assertNotEqual(_legacy_payload_digest(prefix, changed), baseline_digest)

    def test_machine_exact_ref_source_scope_and_pr_evidence(self):
        client = self.Client("Swift Stream federation machine publication\n")
        client.machine_refs = ({
            "ref": "refs/heads/bot/federation/accepted-source",
            "source_id": "accepted-source",
            "sha": self.HEAD,
        },)
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(result.outcome, LegacyClassificationOutcome.QUARANTINE)
        self.assertIs(result.evidence.evidence_class, LegacyQuarantineClass.MACHINE)
        no_pr_digest = result.evidence.evidence_payload_digest

        client.prs[91] = PullRequestMetadata(
            91, "", self.APP.bot_node_id, self.APP.bot_login, self.HEAD, self.BASE,
            "bot/federation/accepted-source", "main", "R_central", self.CENTRAL,
            "R_central", self.CENTRAL, None, False, False,
        )
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            with_pr = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(with_pr.outcome, LegacyClassificationOutcome.QUARANTINE)
        self.assertIs(with_pr.evidence.evidence_class, LegacyQuarantineClass.MACHINE)
        self.assertNotEqual(with_pr.evidence.evidence_payload_digest, no_pr_digest)

        # A stale PR inventory hint is freshly re-read and cannot enter evidence.
        stale_client = self.Client("Swift Stream federation machine publication\n")
        stale_client.machine_refs = client.machine_refs
        stale_client.prs[91] = replace(client.prs[91], head_oid=self.BASE, head_ref="some-other-branch")
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            stale = self.controller(stale_client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(stale.outcome, LegacyClassificationOutcome.QUARANTINE)
        self.assertEqual(stale.evidence.evidence_payload_digest, no_pr_digest)

        duplicate_client = self.Client("Swift Stream federation machine publication\n")
        duplicate_client.machine_refs = client.machine_refs
        duplicate_client.prs[91] = client.prs[91]
        duplicate_client.prs[92] = replace(client.prs[91], number=92)
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            duplicate = self.controller(duplicate_client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(duplicate.outcome, LegacyClassificationOutcome.CONFLICTING)

    def test_machine_relevant_app_pr_contradictions_fail_closed_individually(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        client = self.Client("Swift Stream federation machine publication\n")
        client.machine_refs = ({
            "ref": "refs/heads/bot/federation/accepted-source",
            "source_id": "accepted-source",
            "sha": self.HEAD,
        },)
        exact_pr = PullRequestMetadata(
            91, "", self.APP.bot_node_id, self.APP.bot_login, self.HEAD, self.BASE,
            "bot/federation/accepted-source", "main", "R_central", self.CENTRAL,
            "R_central", self.CENTRAL, None, False, False,
        )
        contradictions = (
            ("wrong head repository ID", {"head_repository_id": "R_other"}),
            ("wrong head repository name", {"head_repository": "other/skills"}),
            ("wrong base repository ID", {"base_repository_id": "R_other"}),
            ("wrong base repository name", {"base_repository": "other/skills"}),
            ("wrong base ref", {"base_ref": "develop"}),
            ("wrong head ref while H is exact", {"head_ref": "bot/federation/other-source"}),
            ("wrong H while canonical branch is exact", {"head_oid": self.BASE}),
            ("exact node with wrong login", {"author_login": "other[bot]"}),
            ("exact login with wrong node", {"author_id": "B_other"}),
        )
        for label, changes in contradictions:
            with self.subTest(contradiction=label):
                case_client = self.Client("Swift Stream federation machine publication\n")
                case_client.machine_refs = client.machine_refs
                case_client.prs[91] = replace(exact_pr, **changes)
                with (
                    patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
                    patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
                    patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
                ):
                    result = self.controller(case_client).classify_legacy_head(
                        self.HEAD, implementation_reviewed_head_sha="e" * 40,
                    )
                self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)
                self.assertIsNone(result.evidence)

    def test_machine_relevant_foreign_pr_is_non_authority(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        client = self.Client("Swift Stream federation machine publication\n")
        client.machine_refs = ({
            "ref": "refs/heads/bot/federation/accepted-source",
            "source_id": "accepted-source",
            "sha": self.HEAD,
        },)
        client.prs[91] = PullRequestMetadata(
            91, "", "U_foreign", "foreign-user", self.HEAD, self.BASE,
            "bot/federation/accepted-source", "main", "R_central", self.CENTRAL,
            "R_central", self.CENTRAL, None, False, False,
        )
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            result = self.controller(client).classify_legacy_head(
                self.HEAD, implementation_reviewed_head_sha="e" * 40,
            )
        self.assertIs(result.outcome, LegacyClassificationOutcome.QUARANTINE)
        self.assertIs(result.evidence.evidence_class, LegacyQuarantineClass.MACHINE)
        self.assertEqual(result.evidence.evidence_payload_digest, _legacy_payload_digest(
            "swiftstream-federation-legacy-machine-evidence:v1\n",
            {
                "schemaVersion": 1,
                "sourceId": "accepted-source",
                "sourceRepositoryId": 41,
                "machineRef": "refs/heads/bot/federation/accepted-source",
                "currentMachineRefOid": self.HEAD,
                "candidateParentSha": self.BASE,
                "candidateTreeSha": "c" * 40,
                "candidateScopeDigest": hashlib.sha256(b'["skills/example/SKILL.md"]').hexdigest(),
                "machinePr": None,
            },
        ))

    def test_publish_legacy_failure_conflicting_app_pr_performs_zero_post(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        client = self.Client("Swift Stream federation machine publication\n")
        client.machine_refs = ({
            "ref": "refs/heads/bot/federation/accepted-source",
            "source_id": "accepted-source",
            "sha": self.HEAD,
        },)
        client.prs[91] = PullRequestMetadata(
            91, "", self.APP.bot_node_id, self.APP.bot_login, self.HEAD, self.BASE,
            "bot/federation/accepted-source", "main", "R_wrong", self.CENTRAL,
            "R_central", self.CENTRAL, None, False, False,
        )
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            with self.assertRaises(R02Error):
                self.controller(client).publish_legacy_failure(
                    self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40,
                )
        self.assertEqual(client.status_calls, [])
        self.assertEqual(client.mutations, [])

    def test_machine_ambiguous_ref_source_parent_and_scope_fail_closed(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        for refs, sources, scope_error in (
            ((), (source,), None),
            (({"ref": "refs/heads/bot/federation/accepted-source", "source_id": "accepted-source", "sha": self.BASE},), (source,), None),
            ((
                {"ref": "refs/heads/bot/federation/accepted-source", "source_id": "accepted-source", "sha": self.HEAD},
                {"ref": "refs/heads/bot/federation/other-source", "source_id": "other-source", "sha": self.HEAD},
            ), (source,), None),
            (({"ref": "refs/heads/bot/federation/accepted-source", "source_id": "accepted-source", "sha": self.HEAD},), (), None),
            (({"ref": "refs/heads/bot/federation/accepted-source", "source_id": "accepted-source", "sha": self.HEAD},), (source,), controller_module.CandidateScopeError("scope rejected")),
        ):
            client = self.Client("Swift Stream federation machine publication\n")
            client.machine_refs = refs
            with (
                patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
                patch.object(R02Controller, "_accepted_sources", return_value=sources),
                patch.object(controller_module, "validate_machine_generated_scope", side_effect=scope_error or ("skills/example/SKILL.md",)),
            ):
                result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)

    def test_machine_parent_cardinality_fails_closed(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        for parents in ((), (self.BASE, "f" * 40)):
            client = self.Client("Swift Stream federation machine publication\n")
            client.machine_refs = ({
                "ref": "refs/heads/bot/federation/accepted-source",
                "source_id": "accepted-source",
                "sha": self.HEAD,
            },)
            client.parents = parents
            with (
                patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
                patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
                patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
            ):
                result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            with self.subTest(parents=parents):
                self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)
                self.assertIsNone(result.evidence)

    def test_machine_current_source_identity_is_fresh_and_exact(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        cases = (
            (PublicSourceMetadata(41, "Owner/Repo", "main", "fresh description"), LegacyClassificationOutcome.QUARANTINE),
            (PublicSourceMetadata(42, "Owner/Repo", "main", None), LegacyClassificationOutcome.CONFLICTING),
            (PublicSourceMetadata(41, "Other/Repo", "main", None), LegacyClassificationOutcome.CONFLICTING),
            (RuntimeError("source metadata unavailable"), LegacyClassificationOutcome.CONFLICTING),
        )
        for metadata, expected in cases:
            client = self.Client("Swift Stream federation machine publication\n")
            client.machine_refs = ({
                "ref": "refs/heads/bot/federation/accepted-source",
                "source_id": "accepted-source",
                "sha": self.HEAD,
            },)
            metadata_patch = patch.object(
                controller_module,
                "read_public_source_metadata",
                side_effect=metadata if isinstance(metadata, BaseException) else None,
                return_value=None if isinstance(metadata, BaseException) else metadata,
            )
            with (
                patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
                patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
                metadata_patch,
                patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
            ):
                result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            with self.subTest(metadata=metadata):
                self.assertIs(result.outcome, expected)
                if expected is LegacyClassificationOutcome.QUARANTINE:
                    self.assertIs(result.evidence.evidence_class, LegacyQuarantineClass.MACHINE)
                    self.assertEqual(result.evidence.evidence_payload_digest, _legacy_payload_digest(
                        "swiftstream-federation-legacy-machine-evidence:v1\n",
                        {
                            "schemaVersion": 1,
                            "sourceId": "accepted-source",
                            "sourceRepositoryId": 41,
                            "machineRef": "refs/heads/bot/federation/accepted-source",
                            "currentMachineRefOid": self.HEAD,
                            "candidateParentSha": self.BASE,
                            "candidateTreeSha": "c" * 40,
                            "candidateScopeDigest": hashlib.sha256(b'["skills/example/SKILL.md"]').hexdigest(),
                            "machinePr": None,
                        },
                    ))
                else:
                    self.assertIsNone(result.evidence)

    def test_machine_repository_id_drift_blocks_legacy_failure_post(self):
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        client = self.Client("Swift Stream federation machine publication\n")
        client.machine_refs = ({
            "ref": "refs/heads/bot/federation/accepted-source",
            "source_id": "accepted-source",
            "sha": self.HEAD,
        },)
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(42, "Owner/Repo", "main", None)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            with self.assertRaises(R02Error):
                self.controller(client).publish_legacy_failure(
                    self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40,
                )
        self.assertEqual(client.status_calls, [])
        self.assertEqual(client.mutations, [])

    def test_two_exact_manual_prs_on_same_head_are_ambiguous(self):
        client, _app, _pr, anchor, comment = self.manual_fixture()
        second_client, _app, second_pr, second_anchor, second_comment = self.manual_fixture(
            author_id="U_second", author_login="bob", comment_id=702, comment_node="IC_second",
        )
        second_anchor = RequestAnchor(
            82, second_anchor.request_class, second_anchor.original_author_id,
            second_anchor.original_author_login, second_anchor.initial_body_sha256,
            second_anchor.initial_request,
        )
        second_pr = replace(second_pr, number=82)
        second_comment = replace(second_comment, body=second_anchor.render())
        client.prs[82] = second_pr
        client.comments[82] = (second_comment,)
        client.files[82] = second_client.files[81]
        result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)
        self.assertEqual(result.reason, "AMBIGUOUS_LEGACY_EVIDENCE")
        self.assertIsNone(result.evidence)

    def test_trusted_classifier_read_failures_are_conflicting(self):
        machine = self.Client("Swift Stream federation machine publication\n")
        machine.fail_reads.add("machine_refs")
        machine_result = self.controller(machine).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(machine_result.outcome, LegacyClassificationOutcome.CONFLICTING)

        manual, _app, _pr, _anchor, _comment = self.manual_fixture()
        manual.fail_reads.add("all_prs")
        manual_result = self.controller(manual).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(manual_result.outcome, LegacyClassificationOutcome.CONFLICTING)

        comments, _app, _pr, _anchor, _comment = self.manual_fixture()
        comments.fail_reads.add("comments")
        comments_result = self.controller(comments).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(comments_result.outcome, LegacyClassificationOutcome.CONFLICTING)

        check_client = self.Client()
        check_client.fail_reads.add("checks")
        check_result = self.controller(check_client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(check_result.outcome, LegacyClassificationOutcome.CONFLICTING)

    def test_manual_duplicate_anchor_invalid_scope_and_foreign_topology_fail_closed(self):
        client, _app, _pr, _anchor, comment = self.manual_fixture()
        client.comments[81] = (comment, replace(comment, database_id=701))
        duplicate = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(duplicate.outcome, LegacyClassificationOutcome.CONFLICTING)

        client, _app, _pr, _anchor, comment = self.manual_fixture()
        malformed = replace(comment, body=controller_module.ANCHOR_MARKER + "\n{invalid-json}\n")
        client.comments[81] = (malformed,)
        malformed_result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(malformed_result.outcome, LegacyClassificationOutcome.CONFLICTING)

        client, _app, pr, _anchor, _comment = self.manual_fixture()
        client.prs[81] = replace(pr, body=pr.body + "drift")
        body_drift = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(body_drift.outcome, LegacyClassificationOutcome.CONFLICTING)

        client, _app, _pr, _anchor, _comment = self.manual_fixture(changed_paths=(".github/workflows/bad.yml",))
        invalid_scope = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(invalid_scope.outcome, LegacyClassificationOutcome.CONFLICTING)

        client, _app, pr, _anchor, _comment = self.manual_fixture()
        client.prs[81] = replace(pr, head_repository="fork/Repo", head_repository_id="R_fork")
        foreign = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(foreign.outcome, LegacyClassificationOutcome.ABSENT)

    def test_manual_human_requester_and_app_comment_author_are_distinct(self):
        client, app, _pr, _anchor, _comment = self.manual_fixture()
        result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertEqual(result.outcome, LegacyClassificationOutcome.QUARANTINE)
        self.assertEqual(client.prs[81].author_id, "U_human")
        self.assertEqual(client.comments[81][0].author_id, app.bot_node_id)
        for author_id, author_login in ((app.bot_node_id, app.bot_login), ("U_human", "alice")):
            swapped, swapped_app, _pr, _anchor, _comment = self.manual_fixture(
                author_id=author_id, author_login=author_login,
                comment_author_id=app.bot_node_id, comment_author_login=app.bot_login,
            )
            if author_id == app.bot_node_id:
                classification = self.controller(swapped).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
                self.assertIs(classification.outcome, LegacyClassificationOutcome.CONFLICTING)
            else:
                self.assertEqual(swapped_app, app)

    def test_manual_anchor_app_author_and_edit_integrity_are_fail_closed(self):
        for changes in (
            {"comment_author_id": "U_other"},
            {"comment_author_login": "other[bot]"},
        ):
            client, app, _pr, _anchor, comment = self.manual_fixture(**changes)
            # Replace the malformed/mismatched anchor author while retaining the
            # exact current PR and encoded RequestAnchor payload.
            result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)
            self.assertIsNone(result.evidence)
        for field in ("editor_login", "editor_type"):
            client, _app, _pr, _anchor, comment = self.manual_fixture()
            changed = dict(comment.__dict__)
            changed[field] = "editor-value"
            client.comments[81] = (IssueComment(**changed),)
            result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)

    def test_collision_output_fixed_vector_and_output_digest_sensitivity(self):
        output = "class=machine-publication; head=" + "a" * 40 + "; result=failure"
        digests = {}
        for name, value in (("alpha", "alpha"), ("beta", "beta"), ("none", None), ("empty", ""), ("known", output)):
            client = self.Client()
            client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, value),)
            result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            self.assertIs(result.outcome, LegacyClassificationOutcome.QUARANTINE)
            self.assertIs(result.evidence.evidence_class, LegacyQuarantineClass.CHECK_COLLISION)
            digests[name] = result.evidence.evidence_payload_digest
            if name == "known":
                payload = {
                    "schemaVersion": 1,
                    "checkRunId": 501,
                    "name": "federation/trusted-validation",
                    "headSha": self.HEAD,
                    "status": "completed",
                    "conclusion": "failure",
                    "appId": 10,
                    "outputDigest": hashlib.sha256(output.encode("utf-8")).hexdigest(),
                    "implementationReviewedHeadSha": "e" * 40,
                }
                expected = hashlib.sha256((
                    "swiftstream-federation-legacy-check-collision-evidence:v1\n"
                    + json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
                ).encode("utf-8")).hexdigest()
                self.assertEqual(digests[name], expected)
        self.assertNotEqual(digests["alpha"], digests["beta"])
        self.assertNotEqual(digests["none"], digests["empty"])
        self.assertNotEqual(digests["none"], digests["known"])

    def test_collision_requires_reviewed_head_exclusion_and_unique_exact_app_row(self):
        client = self.Client()
        client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "out"),)
        missing = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha=None)
        self.assertIs(missing.outcome, LegacyClassificationOutcome.CONFLICTING)
        reviewed = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha=self.HEAD)
        self.assertIs(reviewed.outcome, LegacyClassificationOutcome.ABSENT)
        client.checks = client.checks * 2
        duplicate = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(duplicate.outcome, LegacyClassificationOutcome.CONFLICTING)
        client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 999, "foreign"),)
        foreign = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(foreign.outcome, LegacyClassificationOutcome.ABSENT)

    def test_manual_and_collision_exact_evidence_aggregates_as_conflicting(self):
        client, app, _pr, _anchor, _comment = self.manual_fixture()
        client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", app.app_id, None),)
        result = self.controller(client).classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
        self.assertIs(result.outcome, LegacyClassificationOutcome.CONFLICTING)
        self.assertEqual(result.reason, "AMBIGUOUS_LEGACY_EVIDENCE")

    def test_publish_legacy_failure_writes_exact_failure_for_each_quarantine_class(self):
        boundary = "d" * 64
        # Manual class uses the full current RequestAnchor and proposal evidence.
        manual, app, _pr, _anchor, _comment = self.manual_fixture()
        cases = [(manual, app, None)]

        # Collision class binds the exact current App Check Run.
        collision = self.Client()
        collision.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "failure output"),)
        cases.append((collision, self.APP, None))

        # Machine class binds current accepted source, machine ref, parent/tree/scope.
        machine = self.Client("Swift Stream federation machine publication\n")
        machine.machine_refs = ({
            "ref": "refs/heads/bot/federation/accepted-source",
            "source_id": "accepted-source",
            "sha": self.HEAD,
        },)
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        with (
            patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
            patch.object(R02Controller, "_accepted_sources", return_value=(source,)),
            patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
        ):
            cases.append((machine, self.APP, (source,)))

        for client, configured_app, machine_sources in cases:
            scoped = (
                patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
                patch.object(R02Controller, "_accepted_sources", return_value=machine_sources or ()),
                patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
            )
            with scoped[0], scoped[1], scoped[2]:
                before_reads = client.repository_reads
                controller = R02Controller(client, self.CENTRAL, configured_app)
                current = controller.classify_legacy_head(self.HEAD, implementation_reviewed_head_sha="e" * 40)
                self.assertIs(current.outcome, LegacyClassificationOutcome.QUARANTINE)
                expected_description = controller_module.render_status_description(
                    StatusClass.LEGACY,
                    legacy_status_evidence_digest(current.evidence, boundary),
                )
                receipt = controller.publish_legacy_failure(
                    self.HEAD, boundary, implementation_reviewed_head_sha="e" * 40,
                )
            self.assertIs(type(receipt), StatusWriteReceipt)
            self.assertEqual(client.status_calls[-1], (
                self.CENTRAL, self.HEAD, "failure", "federation/trusted-validation", expected_description, None,
            ))
            self.assertEqual(client.status_calls[-1][2], "failure")
            self.assertEqual(len(client.status_calls), 1)
            self.assertEqual(receipt.returned_status.creator_type, "Bot")
            self.assertEqual(receipt.returned_status.creator_database_id, configured_app.bot_id)
            self.assertEqual(receipt.returned_status.creator_node_id, configured_app.bot_node_id)
            self.assertEqual(receipt.returned_status.creator_login, configured_app.bot_login)
            self.assertGreater(client.repository_reads, before_reads)
            self.assertEqual(client.mutations, ["create_commit_status"])

    def test_publish_legacy_failure_reserved_family_performs_zero_post(self):
        client = self.Client("swiftstream-federation-head:v999\n")
        with self.assertRaises(R02Error):
            self.controller(client).publish_legacy_failure(
                self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40,
            )
        self.assertEqual(client.status_calls, [])
        self.assertEqual(client.mutations, [])
        self.assertEqual(client.class_reads, [])

    def test_publish_legacy_failure_rejects_invalid_inputs_before_authority_reads(self):
        invalid_calls = (
            ("A" * 40, "d" * 64, "e" * 40),
            (self.HEAD, None, "e" * 40),
            (self.HEAD, "D" * 64, "e" * 40),
            (self.HEAD, "d" * 63, "e" * 40),
            (self.HEAD, "d" * 65, "e" * 40),
            (self.HEAD, "d" * 64, "E" * 40),
            (self.HEAD, "d" * 64, "e" * 39),
        )
        for head, boundary, reviewed in invalid_calls:
            client = self.Client()
            with self.subTest(head=head, boundary=boundary, reviewed=reviewed), self.assertRaises(R02Error):
                self.controller(client).publish_legacy_failure(
                    head, boundary, implementation_reviewed_head_sha=reviewed,
                )
            self.assertEqual(client.status_calls, [])
            self.assertEqual(client.repository_reads, 0)
        self.assertEqual(
            tuple(inspect.signature(R02Controller.publish_legacy_failure).parameters),
            ("self", "head_sha", "trusted_activation_boundary_id", "implementation_reviewed_head_sha"),
        )
        with self.assertRaises(TypeError):
            self.controller().publish_legacy_failure(
                self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40, cutoverId="x",
            )

    def test_publish_legacy_failure_absent_or_conflicting_never_falls_back(self):
        for message, checks in (
            ("ordinary commit\n", ()),
            ("swiftstream-federation-head:future\n", ()),
        ):
            client = self.Client(message)
            client.checks = checks
            with self.subTest(message=message), self.assertRaises(R02Error):
                self.controller(client).publish_legacy_failure(
                    self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40,
                )
            self.assertEqual(client.status_calls, [])
            self.assertEqual(client.mutations, [])

        client = self.Client()
        client.checks = (
            CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "a"),
            CheckRun(502, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "b"),
        )
        with self.assertRaises(R02Error):
            self.controller(client).publish_legacy_failure(
                self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40,
            )
        self.assertEqual(client.status_calls, [])

    def test_publish_legacy_failure_same_tuple_retry_reclassifies_and_changed_evidence_changes_digest(self):
        client = self.Client()
        client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "alpha"),)
        controller = self.controller(client)
        boundary = "d" * 64
        first = controller.publish_legacy_failure(self.HEAD, boundary, implementation_reviewed_head_sha="e" * 40)
        second = controller.publish_legacy_failure(self.HEAD, boundary, implementation_reviewed_head_sha="e" * 40)
        self.assertEqual(client.status_calls[0], client.status_calls[1])
        self.assertEqual(first.requested_description, second.requested_description)
        self.assertEqual(client.repository_reads, 4)  # each invocation classifies, then re-reads write identity
        client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "beta"),)
        third = controller.publish_legacy_failure(self.HEAD, boundary, implementation_reviewed_head_sha="e" * 40)
        self.assertNotEqual(third.requested_description, first.requested_description)
        self.assertEqual(len(client.status_calls), 3)
        client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 999, "foreign"),)
        with self.assertRaises(R02Error):
            controller.publish_legacy_failure(self.HEAD, boundary, implementation_reviewed_head_sha="e" * 40)
        self.assertEqual(len(client.status_calls), 3)

    def test_publish_legacy_failure_rejects_adversarial_receipts(self):
        expected_context = "federation/trusted-validation"
        expected_description = "ssf:v1 legacy ev=" + "f" * 64

        def raw_receipt(repository, sha, state, context, description, target_url, **changes):
            requested = {
                "repository": repository,
                "requested_sha": sha,
                "method": "POST",
                "route": f"/repos/{repository}/statuses/{sha}",
                "requested_state": state,
                "requested_context": context,
                "requested_description": description,
                "requested_target_url": target_url,
            }
            status_values = dict(
                id=901, node_id="ST_status", state=state, context=context,
                description=description, target_url=target_url,
                creator_database_id=11, creator_node_id="B_bot",
                creator_login="swift-stream-federation[bot]", creator_type="Bot",
                created_at="2026-10-07T00:00:00Z", updated_at="2026-10-07T00:00:00Z",
            )
            requested_changes = changes.pop("requested", {})
            status_changes = changes.pop("status", {})
            requested.update(requested_changes)
            status_values.update(status_changes)
            status = CommitStatus(**status_values)
            receipt = object.__new__(StatusWriteReceipt)
            for key, value in {**requested, "returned_status": status}.items():
                object.__setattr__(receipt, key, value)
            return receipt

        for variant in (
            {"requested": {"route": "/wrong"}},
            {"requested": {"requested_sha": "f" * 40}},
            {"requested": {"requested_state": "success"}, "status": {"state": "success"}},
            {"requested": {"requested_context": "other"}, "status": {"context": "other"}},
            {"requested": {"requested_description": "other"}, "status": {"description": "other"}},
            {"requested": {"requested_target_url": "https://example.invalid"}, "status": {"target_url": "https://example.invalid"}},
            {"status": {"creator_database_id": 99, "creator_node_id": "B_foreign"}},
            {"requested": {"requested_state": "success"}, "status": {"state": "success"}},
            {"status": {"description": "other"}},
        ):
            client = self.Client()
            client.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, "out"),)
            client.receipt_builder = lambda repository, sha, state, context, description, target_url, variant=variant: raw_receipt(
                repository, sha, state, context, description, target_url, **variant,
            )
            with self.subTest(variant=variant), self.assertRaises(R02Error):
                self.controller(client).publish_legacy_failure(
                    self.HEAD, "d" * 64, implementation_reviewed_head_sha="e" * 40,
                )
            self.assertEqual(len(client.status_calls), 1)

    def test_plan_legacy_recovery_maps_all_classes_without_mutation(self):
        expected = {
            LegacyQuarantineClass.MACHINE: LegacyRecoveryAction.MACHINE_MIGRATION_REQUIRED,
            LegacyQuarantineClass.MANUAL: LegacyRecoveryAction.MANUAL_BLOCK_REQUIRES_ISSUE_FIRST,
            LegacyQuarantineClass.CHECK_COLLISION: LegacyRecoveryAction.CHECK_COLLISION_REQUIRES_CLEAN_HEAD,
        }
        manual, _app, _pr, _anchor, _comment = self.manual_fixture()
        collision = self.Client()
        collision.checks = (CheckRun(501, "federation/trusted-validation", self.HEAD, "completed", "failure", 10, None),)
        machine = self.Client("Swift Stream federation machine publication\n")
        machine.machine_refs = ({"ref": "refs/heads/bot/federation/accepted-source", "source_id": "accepted-source", "sha": self.HEAD},)
        source = ControllerCoreTests.accepted_manifest("accepted-source", "Owner/Repo", 41).sources[0]
        cases = ((manual, self.APP, None), (collision, self.APP, None), (machine, self.APP, (source,)))
        for client, app, sources in cases:
            with (
                patch.object(R02Controller, "current_accepted_main", return_value=(self.REPOSITORY, self.BASE)),
                patch.object(R02Controller, "_accepted_sources", return_value=sources or ()),
                patch.object(controller_module, "validate_machine_generated_scope", return_value=("skills/example/SKILL.md",)),
            ):
                decision = R02Controller(client, self.CENTRAL, app).plan_legacy_recovery(
                    self.HEAD, implementation_reviewed_head_sha="e" * 40,
                )
            self.assertIs(decision.action, expected[decision.evidence.evidence_class])
            self.assertEqual(client.status_calls, [])
            self.assertEqual(client.mutations, [])

        for message in ("ordinary commit\n", "swiftstream-federation-head:future\n"):
            client = self.Client(message)
            with self.assertRaises(R02Error):
                self.controller(client).plan_legacy_recovery(self.HEAD, implementation_reviewed_head_sha="e" * 40)
            self.assertEqual(client.mutations, [])

    def test_wave09_writer_and_recovery_methods_have_no_deferred_migration_calls(self):
        source = Path(controller_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        cls = next(item for item in tree.body if isinstance(item, ast.ClassDef) and item.name == "R02Controller")
        methods = {item.name: item for item in cls.body if isinstance(item, ast.FunctionDef)}
        forbidden = {
            "new_carrier_nonce", "claim_generation_id", "create_commit", "create_blob", "create_tree",
            "update_refs", "create_machine_pull_request", "create_check_run", "update_check_run",
            "update_pull_request_state", "dispatch_workflow",
        }
        for name in ("publish_legacy_failure", "plan_legacy_recovery"):
            called = {
                item.func.attr if isinstance(item.func, ast.Attribute) else item.func.id
                for item in ast.walk(methods[name])
                if isinstance(item, ast.Call) and (isinstance(item.func, ast.Attribute) or isinstance(item.func, ast.Name))
            }
            self.assertFalse(called & forbidden)


class Wave10InertActivationGuardTests(unittest.TestCase):
    EXPECTED_STDOUT = (
        '{"activationWriteAllowed":false,"ordinaryWriteAllowed":false,'
        '"reason":"WAVE10_INERT_GUARD","runtimeState":"MERGED_UNPROVEN"}\n'
    )

    @staticmethod
    def invoke_cli(environ):
        stdout = StringIO()
        stderr = StringIO()
        with patch.dict(controller_module.os.environ, environ, clear=True):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                exit_code = controller_module.main(["activation-guard"])
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_wave10_inert_activation_guard_is_canonical(self):
        result = controller_module.wave10_inert_activation_guard()

        self.assertEqual(
            tuple(state.value for state in controller_module.G8RuntimeState),
            ("ACTIVE_G8", "MERGED_UNPROVEN", "BLOCKED_POST_MERGE", "PRE_G8_NOT_APPLICABLE"),
        )
        self.assertIs(type(result.runtime_state), controller_module.G8RuntimeState)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.MERGED_UNPROVEN)
        self.assertIs(result.ordinary_write_allowed, False)
        self.assertIs(result.activation_write_allowed, False)
        self.assertEqual(result.reason, "WAVE10_INERT_GUARD")

    def test_wave10_inert_activation_guard_cannot_be_active(self):
        result = controller_module.wave10_inert_activation_guard()

        self.assertIsNot(result.runtime_state, controller_module.G8RuntimeState.ACTIVE_G8)
        self.assertFalse(result.ordinary_write_allowed)
        self.assertFalse(result.activation_write_allowed)
        with self.assertRaisesRegex(ValueError, "ordinary writes require ACTIVE_G8"):
            controller_module.G8ActivationGuardResult(
                runtime_state=controller_module.G8RuntimeState.MERGED_UNPROVEN,
                ordinary_write_allowed=True,
                activation_write_allowed=False,
                reason="WAVE10_INERT_GUARD",
            )

    def test_activation_guard_cli_succeeds_without_runtime_credentials(self):
        exit_code, stdout, stderr = self.invoke_cli({})

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, self.EXPECTED_STDOUT)
        self.assertEqual(stderr, "")

    def test_activation_guard_cli_ignores_authority_like_environment_overrides(self):
        overrides = {
            "FEDERATION_GITHUB_TOKEN": "ghs_plausible_authority_token",
            "FEDERATION_APP_SLUG": "swift-stream-federation[bot]",
            "GITHUB_REPOSITORY": "SwiftStream/skills",
            "FEDERATION_G8_RUNTIME_STATE": "ACTIVE_G8",
            "FEDERATION_G8_ACTIVE": "true",
            "FEDERATION_ACTIVATION_BOUNDARY_ID": "boundary-123",
            "FEDERATION_ACTIVATION_REF": "refs/heads/main",
            "FEDERATION_EVENT_PATH": "/tmp/nonexistent-g8-event.json",
        }
        exit_code, stdout, stderr = self.invoke_cli(overrides)

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, self.EXPECTED_STDOUT)
        self.assertEqual(stderr, "")

    def test_activation_guard_cli_does_not_construct_github_client(self):
        with patch.object(controller_module, "GitHubClient", side_effect=AssertionError("GitHubClient constructed")):
            exit_code, stdout, stderr = self.invoke_cli({})

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, self.EXPECTED_STDOUT)
        self.assertEqual(stderr, "")

    def test_activation_guard_cli_does_not_resolve_app_identity(self):
        with patch.object(controller_module, "resolve_app_identity", side_effect=AssertionError("App identity resolved")):
            exit_code, stdout, stderr = self.invoke_cli({})

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout, self.EXPECTED_STDOUT)
        self.assertEqual(stderr, "")

    def test_activation_guard_ast_has_no_mutation_surface(self):
        source_path = Path(inspect.getsourcefile(controller_module))
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        functions = {
            node.name: node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
        }
        guard = functions["wave10_inert_activation_guard"]
        self.assertEqual(guard.args.args, [])

        main = functions["main"]
        branches = [
            node for node in main.body
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Attribute)
            and node.test.left.attr == "command"
            and len(node.test.comparators) == 1
            and isinstance(node.test.comparators[0], ast.Constant)
            and node.test.comparators[0].value == "activation-guard"
        ]
        self.assertEqual(len(branches), 1)
        activation_branch = branches[0]
        branch_index = main.body.index(activation_branch)
        self.assertGreater(branch_index, 0)
        previous = main.body[branch_index - 1]
        self.assertIsInstance(previous, ast.Assign)
        self.assertIsInstance(previous.value, ast.Call)
        self.assertIsInstance(previous.value.func, ast.Attribute)
        self.assertEqual(previous.value.func.attr, "parse_args")

        forbidden = {
            "create_commit_status",
            "create_check_run",
            "update_check_run",
            "update_refs",
            "create_issue_comment",
            "dispatch_workflow",
            "create_pull_request",
            "reopen_pull_request",
            "mark_pull_request_ready_for_review",
            "convert_pull_request_to_draft",
            "close_pull_request",
            "create_git_blob",
            "create_git_tree",
            "create_git_commit",
        }
        isolated = ast.Module(body=[guard, activation_branch], type_ignores=[])
        called = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(isolated)
            if isinstance(node, ast.Call)
            and (isinstance(node.func, ast.Attribute) or isinstance(node.func, ast.Name))
        }
        self.assertFalse(called & forbidden)


class Wave11ActivationBoundaryControllerTests(unittest.TestCase):
    WRITERS = (
        ".github/workflows/federation-g8-issue-intake.yml",
        ".github/workflows/federation-g8-interactive.yml",
        ".github/workflows/federation-g8-trusted-validation.yml",
        ".github/workflows/federation-g8-state-finalize.yml",
        ".github/workflows/federation-g8-main-advance.yml",
        ".github/workflows/federation-g8-reconcile.yml",
    )
    CONTRACT_PATH = ".github/federation/g8-activation-contract.json"
    MANIFEST_PATH = ".github/federation/g8-authority-surface.json"
    SURFACE = tuple(sorted({
        CONTRACT_PATH, MANIFEST_PATH, *WRITERS,
        "automation/federation/__init__.py", "automation/federation/controller.py",
        "automation/federation/github_api.py", "automation/federation/request_model.py",
        "automation/federation/workspace.py", "scripts/federate.py",
    }))

    def contract(self, **overrides):
        value = {
            "schemaVersion": 1, "centralRepositoryNodeId": "R_kgDOUId1Tw",
            "implementationPrNumber": 27, "implementationPrDatabaseId": 4780363432,
            "implementationPrNodeId": "PR_kwDOUId1T88AAAABHO6OqA", "baseRef": "main",
            "activationRef": "refs/heads/bot/federation-g8-activation",
            "activationStatusContext": "federation/g8-activation",
            "exactNewWriterPaths": list(self.WRITERS), "authoritySurfaceManifestPath": self.MANIFEST_PATH,
            "contractVersion": "correction-12",
        }
        value.update(overrides)
        return value

    @staticmethod
    def canonical(value):
        return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()

    class Client:
        def __init__(self, test, *, discovery_contract=None, merged_contract=None, manifest=None, pr=None, compare=None):
            self.test = test
            self.calls = []
            self.discovery_contract = discovery_contract
            self.merged_contract = merged_contract
            self.manifest_value = manifest
            self.pr = pr or MergedPullRequestMetadata(
                "swiftstream/skills", "R_kgDOUId1Tw", 1351054671,
                "PR_kwDOUId1T88AAAABHO6OqA", 4780363432, 27, "CLOSED", False, True,
                "2026-10-08T10:11:12Z", "e" * 40, "d" * 40, "c" * 40,
                "g8/issue-first-federation-implementation", "main",
                "R_kgDOUId1Tw", 1351054671, "swiftstream/skills",
                "R_kgDOUId1Tw", 1351054671, "swiftstream/skills",
            )
            self.compare = compare or ("ahead", "e" * 40, "e" * 40)
            self.blobs = {}
            self.trees = {}
            test._populate_client(self)

        def get_repository_metadata(self, repository):
            self.calls.append(("repository", repository))
            return RepositoryMetadata(1351054671, "R_kgDOUId1Tw", "swiftstream/skills", "main")

        def get_ref_oid(self, repository, ref):
            self.calls.append(("ref", repository, ref))
            return "f" * 40

        def get_commit_tree(self, repository, sha):
            self.calls.append(("tree", sha))
            return sha, self.trees[sha]

        def get_blob(self, repository, sha):
            self.calls.append(("blob", sha))
            return self.blobs[sha]

        def get_merged_pull_request_metadata(self, repository, number):
            self.calls.append(("pr", number))
            return self.pr

        def compare_commits(self, repository, base, head):
            self.calls.append(("compare", base, head))
            return self.compare

    def _populate_client(self, client):
        valid_contract = self.contract()
        discovery = client.discovery_contract if client.discovery_contract is not None else self.canonical(valid_contract)
        merged = client.merged_contract if client.merged_contract is not None else discovery
        manifest_value = client.manifest_value if client.manifest_value is not None else {"schemaVersion": 2, "paths": list(self.SURFACE)}
        manifest = self.canonical(manifest_value)
        rows = {}
        for index, path in enumerate(self.SURFACE, 1):
            if path == self.CONTRACT_PATH:
                content = discovery
            elif path == self.MANIFEST_PATH:
                content = manifest
            else:
                content = ("trusted:" + path + "\n").encode()
            oid = f"{index:040x}"
            rows[path] = GitTreeEntry(path, "100644", "blob", oid)
            client.blobs[oid] = content
        merged_contract_oid = f"{len(self.SURFACE) + 20:040x}"
        rows[self.CONTRACT_PATH] = GitTreeEntry(self.CONTRACT_PATH, "100644", "blob", merged_contract_oid)
        client.blobs[merged_contract_oid] = merged
        main_rows = dict(rows)
        main_contract_oid = f"{len(self.SURFACE) + 21:040x}"
        main_rows[self.CONTRACT_PATH] = GitTreeEntry(self.CONTRACT_PATH, "100644", "blob", main_contract_oid)
        client.blobs[main_contract_oid] = discovery
        client.trees["f" * 40] = tuple(main_rows.values())
        client.trees["e" * 40] = tuple(rows.values())

    def controller(self, client):
        return R02Controller(client, "swiftstream/skills", AppIdentity("swift-stream-federation", 1, "A_app", 2, "B_bot", "swift-stream-federation[bot]"), environ={"IMPLEMENTATION_PR_NUMBER": "999"})

    def test_derives_boundary_from_exact_merged_result_and_fixed_pr(self):
        client = self.Client(self)
        evidence = self.controller(client).derive_activation_boundary_evidence()
        self.assertEqual(evidence.merged_result_oid, "e" * 40)
        self.assertEqual(evidence.implementation_reviewed_head_sha, "d" * 40)
        self.assertEqual(evidence.implementation_pr_number, 27)
        self.assertEqual(evidence.activation_boundary_id, controller_module.activation_boundary_id_digest(
            evidence.central_repository_node_id, evidence.implementation_pr_number,
            evidence.implementation_pr_database_id, evidence.implementation_pr_node_id,
            evidence.merged_result_oid, evidence.authority_surface_digest, evidence.new_writer_topology_digest,
        ))
        self.assertEqual([call for call in client.calls if call[0] == "pr"], [("pr", 27)])
        self.assertLess(client.calls.index(("blob", f"{len(self.SURFACE) + 21:040x}")), client.calls.index(("pr", 27)))

    def test_poisoned_discovery_tuple_fails_before_pr_query(self):
        bad = self.Client(self, discovery_contract=self.canonical(self.contract(implementationPrNumber=28)))
        with self.assertRaises(R02Error):
            self.controller(bad).derive_activation_boundary_evidence()
        self.assertFalse(any(call[0] == "pr" for call in bad.calls))

    def test_discovery_and_merged_contract_must_be_byte_identical(self):
        bad = self.Client(self, merged_contract=self.canonical(self.contract(contractVersion="correction-13")))
        with self.assertRaises(R02Error):
            self.controller(bad).derive_activation_boundary_evidence()

    def test_exact_head_topology_and_main_containment_are_required(self):
        bad_pr = self.Client(self, pr=replace(self.Client(self).pr, head_ref="other"))
        with self.assertRaises(R02Error):
            self.controller(bad_pr).derive_activation_boundary_evidence()
        bad_compare = self.Client(self, compare=("ahead", "e" * 40, "a" * 40))
        with self.assertRaises(R02Error):
            self.controller(bad_compare).derive_activation_boundary_evidence()
        for state in ("behind", "diverged"):
            client = self.Client(self, compare=(state, "e" * 40, "a" * 40))
            with self.subTest(state=state), self.assertRaises(R02Error):
                self.controller(client).derive_activation_boundary_evidence()

    def test_manifest_and_contract_bytes_must_be_canonical_and_exact(self):
        invalid = (
            {"schemaVersion": 1, "paths": list(self.SURFACE)},
            {"schemaVersion": 2, "paths": list(self.SURFACE[:-1])},
            {"schemaVersion": 2, "paths": list(self.SURFACE) + ["extra.py"]},
        )
        for manifest in invalid:
            client = self.Client(self, manifest=manifest)
            with self.subTest(manifest=manifest), self.assertRaises(R02Error):
                self.controller(client).derive_activation_boundary_evidence()


class Wave11CanonicalShaResolverTests(unittest.TestCase):
    CENTRAL = "swiftstream/skills"
    BASE = "b" * 40
    HEAD = "a" * 40
    TREE = "e" * 40
    BASE_TREE = "c" * 40
    APP = AppIdentity("swift-stream-federation", 1, "A_app", 2, "B_bot", "swift-stream-federation[bot]")
    REPOSITORY = RepositoryMetadata(1351054671, "R_kgDOUId1Tw", CENTRAL, "main")
    SOURCE = c02.SourceDeclaration(
        "source-one", "Owner/Repo", 41, "skills", "Source",
        (c02.LineDeclaration("refs/heads/main", ("source-one",)),),
    )
    PATHS = ("skills/source-one/SKILL.md",)

    @staticmethod
    def _canonical(value):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()

    class Client:
        def __init__(self, current_ref, message, with_pr):
            self.current_ref = current_ref
            self.message = message
            self.with_pr = with_pr
            self.calls = []
            self.identity = GitCommitIdentity("Maintainer", "maintainer@example.test", "2026-10-08T00:00:00Z")
            self.pr = PullRequestMetadata(
                55, "PR_node", "B_bot", "swift-stream-federation[bot]",
                Wave11CanonicalShaResolverTests.HEAD, Wave11CanonicalShaResolverTests.BASE,
                "bot/federation/source-one", "main", "R_kgDOUId1Tw",
                Wave11CanonicalShaResolverTests.CENTRAL, "R_kgDOUId1Tw", Wave11CanonicalShaResolverTests.CENTRAL,
                None, False, False,
            )

        def get_repository_metadata(self, _repository):
            self.calls.append("repository")
            return Wave11CanonicalShaResolverTests.REPOSITORY

        def get_ref_oid(self, _repository, ref):
            self.calls.append(("ref", ref))
            return Wave11CanonicalShaResolverTests.BASE if ref == "main" else self.current_ref

        def get_app_metadata(self, slug):
            return AppMetadata(Wave11CanonicalShaResolverTests.APP.app_id, slug, Wave11CanonicalShaResolverTests.APP.app_node_id)

        def get_bot_metadata(self, slug):
            app = Wave11CanonicalShaResolverTests.APP
            return BotMetadata(app.bot_id, app.bot_login, app.bot_node_id, "Bot")

        def get_git_commit_object(self, _repository, sha):
            self.calls.append(("commit", sha))
            if sha == Wave11CanonicalShaResolverTests.HEAD:
                return GitCommitObject(sha, self.message, Wave11CanonicalShaResolverTests.TREE, (Wave11CanonicalShaResolverTests.BASE,), self.identity, self.identity)
            return GitCommitObject(sha, "base\n", Wave11CanonicalShaResolverTests.BASE_TREE, (), self.identity, self.identity)

        def list_open_pull_requests(self, _repository):
            self.calls.append("open_prs")
            return ({"number": 55},) if self.with_pr else ()

        def get_pull_request_metadata(self, _repository, number):
            self.calls.append(("pr", number))
            return self.pr

    def _machine_claim(self):
        central = self.REPOSITORY.node_id
        owner = f"{central}:{self.SOURCE.source_id}"
        scope = hashlib.sha256(b"swiftstream-federation-machine-ref-claim-scope:v1\n" + self._canonical({
            "schemaVersion": 1, "candidateTreeSha": self.TREE, "changedPaths": list(self.PATHS),
        })).hexdigest()
        authority = machine_ref_claim_authority_digest(
            central_repository_node_id=central,
            owner_key=owner,
            source_id=self.SOURCE.source_id,
            source_repository_id=self.SOURCE.repository_id,
            machine_ref="refs/heads/bot/federation/source-one",
            accepted_base_sha=self.BASE,
            accepted_base_tree_sha=self.BASE_TREE,
            candidate_tree_sha=self.TREE,
            candidate_scope_digest=scope,
        )
        generation = claim_generation_id(
            authority_preimage_digest=authority, carrier_nonce="4" * 64,
            central_repository_node_id=central, owner_key=owner,
            from_head_sha=self.BASE, from_tree_sha=self.BASE_TREE,
            claim_kind="MACHINE_REF_CLAIM", role="MACHINE_PUBLICATION",
            owner_kind="MACHINE_SOURCE", transition_kind="MACHINE_PUBLICATION",
        )
        return ClaimedHeadMarker(
            "MACHINE_REF_CLAIM", "MACHINE_PUBLICATION", "MACHINE_SOURCE", owner,
            generation, "4" * 64, "MACHINE_PUBLICATION",
        )

    def _machine_controller(self, current_ref, *, with_pr=True, marker=None):
        marker = marker or self._machine_claim()
        client = self.Client(current_ref, marker.render(), with_pr)
        controller = R02Controller(client, self.CENTRAL, self.APP)
        controller._accepted_sources = lambda _main: (self.SOURCE,)
        return controller, client

    def test_markerless_path_uses_boundary_classification_before_unclaimed(self):
        controller, client = self._machine_controller(self.BASE, with_pr=False)
        identity = client.identity
        client.message = "ordinary commit\n"
        boundary_id = activation_boundary_id_digest(
            "R_kgDOUId1Tw", 27, 4780363432, "PR_kwDOUId1T88AAAABHO6OqA",
            "d" * 40, "1" * 64, "2" * 64,
        )
        boundary = ActivationBoundaryEvidence(
            1, "R_kgDOUId1Tw", 27, 4780363432, "PR_kwDOUId1T88AAAABHO6OqA",
            "f" * 40, "d" * 40, "1" * 64, "2" * 64, boundary_id,
        )
        calls = []
        classification = LegacyClassificationResult(LegacyClassificationOutcome.ABSENT, None, "ABSENT")
        with patch.object(controller, "derive_activation_boundary_evidence", side_effect=lambda: calls.append("boundary") or boundary), \
             patch.object(controller, "classify_legacy_head", side_effect=lambda sha, *, implementation_reviewed_head_sha: (
                 calls.append(("legacy", sha, implementation_reviewed_head_sha)) or classification
             )):
            result = controller.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual(result.activation, CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
        self.assertEqual(calls, ["boundary", ("legacy", self.HEAD, "f" * 40)])

    def test_machine_v2_requires_exact_fresh_ref_and_pr_authority(self):
        controller, _client = self._machine_controller(self.HEAD)
        source_read = patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None))
        with source_read, patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = controller.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual((result.activation, result.role), (CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION))

        moved, _client = self._machine_controller("9" * 40)
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = moved.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)

    def test_machine_v2_reserved_and_identity_generation_failures(self):
        reserved, _client = self._machine_controller(self.BASE, with_pr=False)
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = reserved.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual((result.activation, result.role), (CarrierActivation.RESERVED_INACTIVE, CarrierRole.MACHINE_PUBLICATION))

        wrong_owner, wrong_client = self._machine_controller(self.HEAD)
        original = self._machine_claim()
        wrong_client.message = replace(original, owner_key="R_kgDOUId1Tw:another-source").render()
        with patch.object(wrong_owner, "derive_activation_boundary_evidence", side_effect=AssertionError("reserved marker fallback")):
            self.assertEqual(wrong_owner.resolve_current_sha_carrier_role(self.HEAD).activation, CarrierActivation.CONFLICTING)

        bad_generation, bad_client = self._machine_controller(self.HEAD)
        bad_client.message = replace(original, claim_generation_id="f" * 64).render()
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            self.assertEqual(bad_generation.resolve_current_sha_carrier_role(self.HEAD).activation, CarrierActivation.CONFLICTING)

    def test_real_b_to_h_lifecycle_survives_full_controller_restart(self):
        marker = self._machine_claim()
        marker_bytes = marker.render()
        before_controller, before_client = self._machine_controller("9" * 40, marker=marker)
        self.assertEqual(before_client.message, marker_bytes)
        # The only durable mutation is the exact ref transition B -> H.
        before_client.current_ref = self.HEAD
        restarted_client = self.Client(self.HEAD, before_client.message, True)
        restarted_controller = R02Controller(restarted_client, self.CENTRAL, self.APP)
        restarted_controller._accepted_sources = lambda _main: (self.SOURCE,)
        self.assertEqual(restarted_client.message, marker_bytes)
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = restarted_controller.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual((result.activation, result.role), (CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION))
        self.assertEqual(result.marker, marker)

    def test_zero_to_h_restart_and_third_value_stay_reserved_or_conflicting(self):
        marker = self._machine_claim()
        absent_controller, absent_client = self._machine_controller(None, marker=marker)
        self.assertIsNone(absent_client.current_ref)
        absent_client.current_ref = self.HEAD
        restarted, _client = self._machine_controller(self.HEAD, marker=marker)
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = restarted.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual(result.activation, CarrierActivation.ACTIVE)

        third, _client = self._machine_controller("8" * 40, marker=marker)
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = third.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertIsNot(result.activation, CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)

    def test_old_v1_generation_is_not_accepted_by_fallback(self):
        central = self.REPOSITORY.node_id
        owner = f"{central}:{self.SOURCE.source_id}"
        scope = hashlib.sha256(b"swiftstream-federation-machine-ref-claim-scope:v1\n" + self._canonical({
            "schemaVersion": 1, "candidateTreeSha": self.TREE, "changedPaths": list(self.PATHS),
        })).hexdigest()
        authority = hashlib.sha256(b"swiftstream-federation-machine-ref-claim-authority:v1\n" + self._canonical({
            "schemaVersion": 1, "centralRepositoryNodeId": central, "ownerKey": owner,
            "sourceId": self.SOURCE.source_id, "sourceRepositoryId": self.SOURCE.repository_id,
            "acceptedBaseSha": self.BASE, "acceptedBaseTreeSha": self.BASE_TREE,
            "currentMachineRefOid": self.HEAD, "candidateTreeSha": self.TREE,
            "candidateScopeDigest": scope,
        })).hexdigest()
        generation = claim_generation_id(
            authority_preimage_digest=authority, carrier_nonce="4" * 64,
            central_repository_node_id=central, owner_key=owner,
            from_head_sha=self.BASE, from_tree_sha=self.BASE_TREE,
            claim_kind="MACHINE_REF_CLAIM", role="MACHINE_PUBLICATION",
            owner_kind="MACHINE_SOURCE", transition_kind="MACHINE_PUBLICATION",
        )
        old_marker = ClaimedHeadMarker(
            "MACHINE_REF_CLAIM", "MACHINE_PUBLICATION", "MACHINE_SOURCE", owner,
            generation, "4" * 64, "MACHINE_PUBLICATION",
        )
        controller, client = self._machine_controller(self.HEAD, marker=old_marker)
        with patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = controller.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual(result.activation, CarrierActivation.CONFLICTING)
        self.assertEqual(client.message, old_marker.render())

    def test_canonical_resolver_has_no_external_legacy_authority_or_reserved_fallback(self):
        controller, _client = self._machine_controller(self.HEAD)
        source = ast.parse(Path(controller_module.__file__).read_text(encoding="utf-8"))
        cls = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == "R02Controller")
        method = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "resolve_current_sha_carrier_role")
        self.assertEqual([arg.arg for arg in method.args.args], ["self", "head_sha"])
        calls = {
            item.func.id if isinstance(item.func, ast.Name) else item.func.attr
            for item in ast.walk(method)
            if isinstance(item, ast.Call) and (isinstance(item.func, ast.Name) or isinstance(item.func, ast.Attribute))
        }
        self.assertNotIn("wave08_legacy_disposition", calls)
        self.assertNotIn("legacy_disposition_resolver", calls)
        self.assertNotIn("legacy_evidence_disposition", calls)

    def test_reserved_marker_never_enters_legacy_or_unclaimed_fallback(self):
        controller, _client = self._machine_controller(self.HEAD)
        with patch.object(controller, "derive_activation_boundary_evidence", side_effect=AssertionError("legacy fallback")), \
             patch.object(controller, "classify_legacy_head", side_effect=AssertionError("legacy fallback")), \
             patch.object(controller_module, "read_public_source_metadata", return_value=PublicSourceMetadata(41, "Owner/Repo", "main", None)), \
             patch.object(controller_module, "validate_machine_generated_scope", return_value=self.PATHS):
            result = controller.resolve_current_sha_carrier_role(self.HEAD)
        self.assertEqual(result.activation, CarrierActivation.ACTIVE)


if __name__ == "__main__":
    unittest.main()
