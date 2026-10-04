import ast
import base64
import hashlib
from pathlib import Path
import unittest
from unittest.mock import patch

import automation.federation.controller as controller_module
from automation.federation.controller import (
    AppIdentity,
    C02CandidateBuilder,
    DuplicateAnchorError,
    IssueAnchorComment,
    IssueBranchLeaseComment,
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
    parse_c02_manifest,
    reconstruct_issue_from_github,
    resolve_issue_source_authority,
    validate_unique_issue_anchor,
)
from automation.federation.request_model import (
    ISSUE_REQUEST_ANCHOR_MARKER,
    ISSUE_BRANCH_LEASE_MARKER,
    PATCH_SENTINEL,
    CommentEvent,
    IssueRequestAnchor,
    IssueBranchLease,
    RequestClass,
    RequestAnchor,
    body_sha256,
    parse_request_body,
    parse_issue_request_body,
    parse_issue_branch_lease,
    issue_branch_ref,
)
from automation.federation.github_api import (
    GitCommitMetadata,
    GitObject,
    GitTreeEntry,
    IssueComment,
    IssueMetadata,
    RepositoryMetadata,
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

if __name__ == "__main__":
    unittest.main()
