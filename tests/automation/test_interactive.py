import io
import os
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from automation.federation.controller import (
    AppIdentity,
    CandidateScopeError,
    DuplicateAnchorError,
    ForkHeadError,
    IssueManagedNoSemanticChange,
    IssueManagedRouteResult,
    R02Error,
    ReservedIssuePRPendingManagedAuthority,
    StaleAuthorityError,
    allowed_proposal_paths,
    authorized_patch_events,
    create_anchor_once,
    has_result_for_comment,
    marker_classes,
    phase_gate,
    replace_request_ref_cas,
    result_idempotency_marker,
    validate_proposal_scope,
    validate_unique_anchor,
    c02_source_candidate,
    validate_readme_managed_diff,
    validate_existing_request_head,
    main,
    ProposalCandidate,
    R02Controller,
    trusted_c02_execution,
)
import automation.federation.controller as controller_module
from contextlib import contextmanager
from scripts import federate as c02
from automation.federation.github_api import GitHubAPIError, GraphQLError, RefCASConflict
from automation.federation.github_api import CheckRun, GitCommitMetadata, GitObject, GitTreeEntry, IssueComment, PullRequestMetadata, RepositoryMetadata
from automation.federation.request_model import RequestClass, body_sha256, parse_request_body, RequestAnchor


@contextmanager
def trusted_previous_patches():
    """Pin accepted-base loaders to empty schema-v3 authority (HEAD may still be v2)."""
    with patch.object(c02, "load_trusted_previous_manifest", return_value=c02.Manifest(())), patch.object(
        c02, "load_trusted_previous_lock", lambda manifest: c02.LockState((), {})
    ):
        yield


ROOT = Path(__file__).resolve().parents[2]
APP = AppIdentity("swiftstream-federation", 77, "A_app", 88, "U_bot", "swiftstream-federation[bot]")
BODY = "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nA source\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nswiftstream\n"


def pr(head="a" * 40, body=BODY, head_repo="swiftstream/skills", author_id="U_author", author_login="alice"):
    return PullRequestMetadata(7, body, author_id, author_login, head, "b" * 40, "proposal", "main", "7", head_repo, "7", "swiftstream/skills", None, False, False)


def comment(number, body, author_id="U_author", author_login="alice", author_type="User", editor_id=None, edited=None, created=False):
    return IssueComment(f"IC_{number}", number, body, author_id, author_login, author_type, editor_id, author_login if editor_id else None, author_type if editor_id else None, edited, created)


class FakeClient:
    def __init__(self, current_pr=None, comments=None):
        self.current_pr = current_pr or pr()
        self.comments = list(comments or [])
        self.permissions = {"maintainer": "admin", "writer": "write", "triager": "triage", "reader": "read"}
        self.created = []
        self.ref_calls = []
        self.reject_cas = False
        self.main_oid = "c" * 40

    def get_pull_request_metadata(self, repository, number):
        return self.current_pr

    def list_issue_comments(self, repository, number):
        return tuple(self.comments)

    def create_issue_comment(self, repository, number, body):
        new_id = 100 + len(self.created)
        created = comment(new_id, body, APP.bot_node_id, APP.bot_login, "Bot")
        self.comments.append(created)
        self.created.append(created)
        return created

    def get_collaborator_permission(self, repository, login):
        return self.permissions.get(login, "none")

    def update_refs(self, repository_id, updates):
        if self.reject_cas:
            raise RefCASConflict("CAS")
        self.ref_calls.extend(updates)

    def get_repository_metadata(self, repository):
        return RepositoryMetadata(7, "R_7", "swiftstream/skills", "main")

    def get_ref_oid(self, repository, branch):
        return self.main_oid

    def list_open_pull_requests(self, repository):
        return ({"number": 7}, {"number": 11})

    def get_commit_tree(self, repository, commit_sha):
        marker_sha = "8" * 40
        base_entries = (
            GitTreeEntry("federation.json", "100644", "blob", "1" * 40),
            GitTreeEntry("federation.lock.json", "100644", "blob", "2" * 40),
            GitTreeEntry("README.md", "100644", "blob", "3" * 40),
        )
        if commit_sha == self.current_pr.head_oid:
            return "5" * 40, base_entries + (GitTreeEntry(".federation-request", "100644", "blob", marker_sha),)
        return "4" * 40, base_entries

    def get_blob(self, repository, blob_sha):
        if blob_sha == "8" * 40:
            return b"add-source\n"
        return b""


class ProductionAddClient(FakeClient):
    """Deterministic fake GitHub transport used through controller.main()."""

    def __init__(self):
        super().__init__()
        self.main_oid = c02.head_commit_oid()
        self.central_node_id = "R_central_graphql"
        self.blobs = {
            "manifest": b'{"schemaVersion": 3, "sources": []}\n',
            "lock": b'{"schemaVersion": 3, "contentDigestAlgorithm": "sha256-file-manifest-v1", "publishedSourceIds": [], "skills": {}}\n',
            "readme": (ROOT / "README.md").read_bytes(),
        }
        self.candidate_head = "d" * 40
        self.marker_head = "a" * 40
        self.current_pr = replace(self.current_pr, head_oid=self.marker_head, base_oid=self.main_oid)
        self.source_dir = Path(tempfile.mkdtemp(prefix="c03-source-fixture-"))
        self.source_bare = self.source_dir / "repo.git"
        work = self.source_dir / "work"
        subprocess.run(["git", "init", "-q", "-b", "main", str(work)], check=True)
        subprocess.run(["git", "-C", str(work), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(work), "config", "user.name", "C03 test"], check=True)
        (work / "skills" / "swiftstream-demo").mkdir(parents=True)
        (work / "skills" / "swiftstream-demo" / "SKILL.md").write_text("---\nname: swiftstream-demo\ndescription: Demo\n---\n\n# Demo\n", encoding="utf-8")
        # Live registry may already publish SwifQL (skillsRoot=.agent/skills).
        (work / ".agent" / "skills" / "swifql-query-building").mkdir(parents=True)
        (work / ".agent" / "skills" / "swifql-query-building" / "SKILL.md").write_text("---\nname: swifql-query-building\ndescription: Demo\n---\n\n# Demo\n", encoding="utf-8")
        (work / ".agent" / "skills" / "swifql-custom-extensions").mkdir(parents=True)
        (work / ".agent" / "skills" / "swifql-custom-extensions" / "SKILL.md").write_text("---\nname: swifql-custom-extensions\ndescription: Demo\n---\n\n# Demo\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(work), "add", "skills", ".agent"], check=True)
        subprocess.run(["git", "-C", str(work), "commit", "-qm", "fixture"], check=True)
        # SwifQL is configured with refs/heads/master; keep both refs on the fixture tip.
        subprocess.run(["git", "-C", str(work), "branch", "master"], check=True)
        subprocess.run(["git", "clone", "-q", "--bare", str(work), str(self.source_bare)], check=True)
        self.source_commit = subprocess.check_output(["git", "-C", str(work), "rev-parse", "HEAD"], text=True).strip()
        self.checks = []
        self.check_objects = []
        self.dispatches = []
        self.open_prs = ({"number": 7},)
        self.source_http_observations = []
        self.git_invocations = []

    def get_app_metadata(self, slug):
        from automation.federation.github_api import AppMetadata
        return AppMetadata(APP.app_id, slug, APP.app_node_id)

    def get_bot_metadata(self, slug):
        from automation.federation.github_api import BotMetadata
        return BotMetadata(APP.bot_id, APP.bot_login, APP.bot_node_id, "Bot")

    def get_repository_metadata(self, repository):
        if repository != "swiftstream/skills":
            return RepositoryMetadata(99, "R_source", "Owner/Repo", "main", "A source repository")
        return RepositoryMetadata(7, self.central_node_id, "swiftstream/skills", "main")

    def read_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
        if commit_sha == self.marker_head and path == ".federation-request":
            self.marker_read = (repository, commit_sha, path, expected_mode)
            return b"add-source\n"
        return {"federation.json": self.blobs["manifest"], "federation.lock.json": self.blobs["lock"], "README.md": self.blobs["readme"]}[path]

    def read_optional_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
        if commit_sha == self.marker_head and path == ".federation-request":
            self.marker_read = (repository, commit_sha, path, expected_mode)
            return b"add-source\n"
        if path == ".federation-request":
            return None
        return self.read_commit_file(repository, commit_sha, path, expected_mode=expected_mode)

    def get_commit_tree(self, repository, commit_sha):
        entries = (
            GitTreeEntry("federation.json", "100644", "blob", "1" * 40),
            GitTreeEntry("federation.lock.json", "100644", "blob", "2" * 40),
            GitTreeEntry("README.md", "100644", "blob", "3" * 40),
        )
        if commit_sha == self.candidate_head:
            return "6" * 40, (
                GitTreeEntry("federation.json", "100644", "blob", "5" * 40),
                GitTreeEntry("federation.lock.json", "100644", "blob", "2" * 40),
                GitTreeEntry("README.md", "100644", "blob", "3" * 40),
            )
        if commit_sha == self.marker_head:
            return "5" * 40, entries + (GitTreeEntry(".federation-request", "100644", "blob", "4" * 40),)
        return "4" * 40, entries

    def get_blob(self, repository, blob_sha):
        if blob_sha == "4" * 40:
            return b"add-source\n"
        if blob_sha == "5" * 40:
            import base64
            return base64.b64decode(self.created_blob)
        return {"1" * 40: self.blobs["manifest"], "2" * 40: self.blobs["lock"], "3" * 40: self.blobs["readme"]}[blob_sha]

    def get_commit_metadata(self, repository, commit_sha):
        return GitCommitMetadata(commit_sha, "6" * 40 if commit_sha == self.candidate_head else "4" * 40, (self.main_oid,) if commit_sha == self.candidate_head else (), "2026-09-27T22:17:00Z")

    def bot_commit_timestamp_after(self, repository, parent_sha):
        return "2026-09-27T22:17:01Z"

    def create_blob(self, repository, content, *, encoding="base64"):
        self.created_blob = content
        return GitObject("5" * 40)

    def create_tree(self, repository, base_tree, entries):
        self.created_tree = (base_tree, list(entries))
        return GitObject("6" * 40)

    def create_commit(self, repository, message, tree, parents, *, timestamp=None):
        self.created_commit = (message, tree, list(parents), timestamp)
        return GitObject(self.candidate_head)

    def update_refs(self, repository_id, updates):
        self.asserted_repository_id = repository_id
        self.ref_calls.extend(updates)
        self.current_pr = replace(self.current_pr, head_oid=updates[0].after_oid)

    def dispatch_workflow(self, repository, workflow, ref, inputs=None):
        self.dispatches.append((repository, workflow, ref, inputs))

    def create_check_run(self, repository, name, head_sha, **kwargs):
        check = CheckRun(len(self.check_objects) + 1, name, head_sha, "completed", kwargs.get("conclusion"), APP.app_id)
        self.check_objects.append(check)
        self.checks.append((repository, name, head_sha, kwargs))
        return check

    def list_check_runs(self, repository, head_sha):
        return tuple(item for item in self.check_objects if item.head_sha == head_sha)

    def update_check_run(self, repository, check_id, *, head_sha, status="completed", conclusion=None, output=None):
        for index, item in enumerate(self.check_objects):
            if item.id == check_id:
                updated = CheckRun(item.id, item.name, item.head_sha, status, conclusion, item.app_id)
                self.check_objects[index] = updated
                self.checks.append((repository, item.name, item.head_sha, {"conclusion": conclusion, "output": output}))
                return updated
        raise AssertionError("unknown check id")

    def list_open_pull_requests(self, repository):
        return self.open_prs

    def source_http_get(self, url, headers, timeout, max_bytes):
        self.source_http_observations.append((url, dict(headers), dict(os.environ)))
        if url.endswith("/repos/Owner/Repo"):
            body = json.dumps({"id": 99, "full_name": "Owner/Repo", "default_branch": "main", "description": "A source repository"}).encode()
        elif url.endswith("/repos/SwifQL/SwifQL"):
            body = json.dumps({"id": 161410190, "full_name": "SwifQL/SwifQL", "default_branch": "master", "description": "A strongly typed, declarative, composable Swift SQL-building library."}).encode()
        elif url.endswith("/git/ref/heads/main") or url.endswith("/git/ref/heads/master"):
            ref = "refs/heads/master" if url.endswith("master") else "refs/heads/main"
            body = json.dumps({"ref": ref, "object": {"type": "commit", "sha": self.source_commit}}).encode()
        else:
            raise AssertionError(f"unexpected source URL: {url}")
        return c02.HttpResponse(200, url, body)

    def source_branch_fetcher(self, repo_path, source, ref):
        # Fixture only has refs/heads/main; live registry sources may use other refs
        # (e.g. SwifQL master). Always fetch the fixture main tip and report that SHA.
        subprocess.run(["git", "-C", str(repo_path), "fetch", "--no-tags", "--force", str(self.source_bare), "refs/heads/main"], check=True)
        return subprocess.check_output(["git", "-C", str(repo_path), "rev-parse", "FETCH_HEAD^{commit}"], text=True).strip()


class InteractiveTests(unittest.TestCase):
    def anchor(self, cls=RequestClass.ADD, pr_value=None):
        value = pr_value or pr()
        request = parse_request_body(cls, value.body if cls is RequestClass.ADD else ("Repository URL:\nhttps://github.com/Owner/Repo\n" if cls is RequestClass.RECONCILE else "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\nwhy\n"))
        return RequestAnchor(value.number, cls, value.author_id, value.author_login, body_sha256(value.body), request)

    def test_marker_classes_are_exact_and_title_is_never_authority(self):
        for value, cls in (("add-source", RequestClass.ADD), ("update-source", RequestClass.UPDATE), ("remove-source", RequestClass.REMOVE), ("reconcile-source", RequestClass.RECONCILE)):
            self.assertIs(marker_classes(".federation-request", value), cls)
        with self.assertRaises(R02Error):
            marker_classes(".federation-request", "Add-Source")

    def test_anchor_is_created_once_and_app_bot_identity_is_required(self):
        fake = FakeClient()
        created = create_anchor_once(fake, "swiftstream/skills", fake.current_pr, RequestClass.ADD, APP, ())
        self.assertEqual(len(fake.created), 1)
        self.assertEqual(validate_unique_anchor(fake.comments, fake.current_pr, RequestClass.ADD, APP), created)
        create_anchor_once(fake, "swiftstream/skills", fake.current_pr, RequestClass.ADD, APP, fake.comments)
        self.assertEqual(len(fake.created), 1)
        wrong = AppIdentity("other", 77, "A_other", 99, "U_other", "other[bot]")
        with self.assertRaises(R02Error):
            validate_unique_anchor(fake.comments, fake.current_pr, RequestClass.ADD, wrong)

    def test_duplicate_edited_missing_and_body_mismatch_anchors_fail_closed(self):
        anchor = self.anchor()
        body = anchor.render()
        one = comment(100, body, APP.bot_node_id, APP.bot_login, "Bot")
        duplicate = comment(101, body, APP.bot_node_id, APP.bot_login, "Bot")
        fake = FakeClient(comments=[one, duplicate])
        with self.assertRaises(DuplicateAnchorError):
            validate_unique_anchor(fake.comments, fake.current_pr, RequestClass.ADD, APP)
        edited = comment(100, body, APP.bot_node_id, APP.bot_login, "Bot", editor_id="U_editor", edited="2026-01-01")
        with self.assertRaises(R02Error):
            validate_unique_anchor([edited], fake.current_pr, RequestClass.ADD, APP)
        changed_pr = pr(body=BODY + " ")
        with self.assertRaises(R02Error):
            validate_unique_anchor([one], changed_pr, RequestClass.ADD, APP)

    def test_existing_anchor_only_path_cannot_create_missing_anchor(self):
        fake = FakeClient()
        controller = R02Controller(fake, "swiftstream/skills", APP)
        with patch.object(controller_module, "create_anchor_once", wraps=create_anchor_once) as creator:
            with self.assertRaises(DuplicateAnchorError):
                controller.anchor_and_reconstruct_existing(7, RequestClass.ADD)
        creator.assert_not_called()
        self.assertEqual(fake.created, [])

    def test_interactive_anchor_path_is_the_creation_capability(self):
        fake = FakeClient()
        controller = R02Controller(fake, "swiftstream/skills", APP)
        controller.interactive_anchor_and_reconstruct(7, RequestClass.ADD)
        self.assertEqual(len(fake.created), 1)
        controller.interactive_anchor_and_reconstruct(7, RequestClass.ADD)
        self.assertEqual(len(fake.created), 1)

    def test_reserved_issue_pr_blocks_legacy_anchor_proposal_validation_and_finalizer_paths(self):
        class ReservedClient(FakeClient):
            def __init__(self, branch="bot/federation/request/issue-7"):
                super().__init__(current_pr=replace(pr(), head_ref=branch))
                self.comment_reads = 0

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return super().list_issue_comments(repository, number)

        fake = ReservedClient()
        old_anchor = self.anchor(pr_value=fake.current_pr)
        fake.comments = [comment(100, old_anchor.render(), APP.bot_node_id, APP.bot_login, "Bot")]
        candidate_builder = Mock()
        controller = R02Controller(fake, "swiftstream/skills", APP, candidate_builder=candidate_builder)
        managed_route_results = []
        route_impl = controller.interactive_issue_managed_route

        def run_managed_route(*args, **kwargs):
            result = route_impl(*args, **kwargs)
            managed_route_results.append(result)
            return result

        with patch.object(controller_module, "validate_unique_anchor") as validate_anchor, patch.object(
            controller_module, "create_anchor_once", wraps=controller_module.create_anchor_once
        ) as create_anchor:
            with self.assertRaises(ReservedIssuePRPendingManagedAuthority):
                controller.interactive_anchor_and_reconstruct(7, RequestClass.ADD)
            with self.assertRaises(ReservedIssuePRPendingManagedAuthority):
                controller.anchor_and_reconstruct_existing(7, RequestClass.ADD)
            with self.assertRaises(ReservedIssuePRPendingManagedAuthority):
                controller.interactive_proposal(7, RequestClass.ADD, fake.main_oid, "refs/heads/topic")
            with self.assertRaises(ReservedIssuePRPendingManagedAuthority):
                controller.trusted_validation(7, fake.main_oid, candidate_builder)
            with patch.object(controller, "current_accepted_main", return_value=(RepositoryMetadata(7, "R_7", "swiftstream/skills", "main"), fake.main_oid)), patch.object(
                controller, "interactive_proposal"
            ) as proposal, patch.object(controller, "trusted_validation") as validation, patch.object(
                controller, "publish_finalizer_result"
            ) as publish, patch.object(controller, "dispatch_trusted_validation_recovery") as dispatch, patch.object(
                controller,
                "interactive_issue_managed_route",
                side_effect=run_managed_route,
            ) as managed_route, patch.object(
                controller,
                "interactive_issue_managed_proposal",
                side_effect=IssueManagedNoSemanticChange(RequestClass.ADD),
            ):
                finalizer_result = controller.finalize_one_manual_pr({"number": 7})
            proposal.assert_not_called()
            validation.assert_not_called()
            publish.assert_not_called()
            dispatch.assert_not_called()
            managed_route.assert_called_once()
            self.assertEqual(managed_route_results, [IssueManagedRouteResult(
                "NOOP", "NO_SEMANTIC_CHANGE", RequestClass.ADD,
            )])
            self.assertIs(finalizer_result, managed_route_results[0])
            self.assertIs(finalizer_result.request_class, RequestClass.ADD)
        validate_anchor.assert_not_called()
        create_anchor.assert_not_called()
        candidate_builder.assert_not_called()
        self.assertEqual(fake.comment_reads, 0)
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.ref_calls, [])

    def test_reserved_namespace_classifier_is_exact_and_malformed_attempts_are_quarantined(self):
        class ReservedClient(FakeClient):
            def __init__(self, branch):
                super().__init__(current_pr=replace(pr(), head_ref=branch))
                self.comment_reads = 0

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return super().list_issue_comments(repository, number)

        for branch in ("bot/federation/request/issue-7", "bot/federation/request/issue-01", "refs/heads/bot/federation/request/issue-7"):
            with self.subTest(branch=branch):
                fake = ReservedClient(branch)
                controller = R02Controller(fake, "swiftstream/skills", APP)
                with self.assertRaises(ReservedIssuePRPendingManagedAuthority):
                    controller.anchor_and_reconstruct_existing(7, RequestClass.ADD)
                self.assertEqual(fake.comment_reads, 0)

        fake = ReservedClient("bot/federation/requested/issue-7")
        controller = R02Controller(fake, "swiftstream/skills", APP)
        with self.assertRaises(DuplicateAnchorError):
            controller.anchor_and_reconstruct_existing(7, RequestClass.ADD)
        self.assertEqual(fake.comment_reads, 1)

    def test_live_reserved_issue_pr_commands_fail_before_legacy_mutation(self):
        class ReservedRuntimeClient(ProductionAddClient):
            def __init__(self):
                super().__init__()
                self.current_pr = replace(self.current_pr, head_ref="bot/federation/request/issue-7")
                self.comment_reads = 0
                self.file_reads = 0

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return super().list_issue_comments(repository, number)

            def list_pull_request_files(self, repository, number):
                self.file_reads += 1
                return super().list_pull_request_files(repository, number)

        for command in ("interactive", "trusted-validation"):
            with self.subTest(command=command):
                fake = ReservedRuntimeClient()
                environment = {
                    "GITHUB_REPOSITORY": "swiftstream/skills",
                    "FEDERATION_GITHUB_TOKEN": "token",
                    "FEDERATION_APP_SLUG": APP.slug,
                    "FEDERATION_WAKE_PULL_NUMBER": "7",
                    "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
                }
                with (
                    patch("automation.federation.controller.GitHubClient", return_value=fake),
                    trusted_previous_patches(),
                    patch.object(
                        R02Controller,
                        "interactive_issue_managed_route",
                        return_value=IssueManagedRouteResult("NOOP", "NO_SEMANTIC_CHANGE", RequestClass.ADD),
                    ) as managed_route,
                    patch.object(R02Controller, "validate_issue_managed_head_history") as validate_history,
                    patch.dict(os.environ, environment, clear=False),
                ):
                    self.assertEqual(main([command]), 0)
                self.assertEqual(fake.dispatches, [])
                if command == "interactive":
                    managed_route.assert_called_once()
                    self.assertEqual(managed_route.call_args.args[0], 7)
                    validate_history.assert_not_called()
                else:
                    validate_history.assert_called_once_with(7)
                    managed_route.assert_not_called()
                self.assertEqual(fake.created, [])
                self.assertEqual(fake.ref_calls, [])
                self.assertEqual(fake.dispatches, [])
                self.assertEqual(fake.checks, [])
                self.assertEqual(fake.check_objects, [])
                self.assertEqual(fake.comment_reads, 0)
                if command == "trusted-validation":
                    self.assertEqual(fake.file_reads, 0)

    def test_state_finalizer_cannot_recreate_anchor_after_authority_disappears(self):
        current_pr = replace(pr(), base_oid="c" * 40)
        anchor = self.anchor(pr_value=current_pr)
        anchor_comment = comment(100, anchor.render(), APP.bot_node_id, APP.bot_login, "Bot")

        class VanishingAnchorClient(FakeClient):
            def __init__(self):
                super().__init__(current_pr=current_pr, comments=[anchor_comment])
                self.comment_reads = 0

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return (anchor_comment,) if self.comment_reads == 1 else ()

        fake = VanishingAnchorClient()
        controller = R02Controller(fake, "swiftstream/skills", APP, candidate_builder=lambda *_args: None)
        with patch.object(controller_module, "create_anchor_once", wraps=create_anchor_once) as creator, patch.object(
            controller_module,
            "upsert_trusted_validation_check",
            return_value=CheckRun(1, "federation/trusted-validation", current_pr.head_oid, "completed", "failure", APP.app_id),
        ):
            controller.finalize_one_manual_pr({"number": 7})
        creator.assert_not_called()
        self.assertEqual(fake.created, [])

    def test_pre_anchor_edit_is_rejected(self):
        edited_pr = PullRequestMetadata(7, BODY, "U_author", "alice", "a" * 40, "b" * 40, "proposal", "main", "7", "swiftstream/skills", "7", "swiftstream/skills", "2026-01-01", True, False)
        with self.assertRaises(R02Error):
            create_anchor_once(FakeClient(edited_pr), "swiftstream/skills", edited_pr, RequestClass.ADD, APP, ())

    def test_anchor_establishment_detects_edit_and_restore_race(self):
        class RaceClient(FakeClient):
            def get_pull_request_metadata(self, repository, number):
                if self.created:
                    return replace(self.current_pr, last_edited_at="2026-09-02T00:00:00Z", includes_created_edit=True)
                return self.current_pr

        with self.assertRaises(StaleAuthorityError):
            create_anchor_once(RaceClient(), "swiftstream/skills", pr(), RequestClass.ADD, APP, ())

    def test_nonreserved_production_interactive_is_inert_for_marker_and_anchor_authority(self):
        class ObservedClient(ProductionAddClient):
            def __init__(self):
                super().__init__()
                self.marker_bytes = b"add-source\n"
                self.marker_reads = 0
                self.comment_reads = 0

            def read_optional_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
                if path == ".federation-request":
                    self.marker_reads += 1
                    return self.marker_bytes
                return super().read_optional_commit_file(repository, commit_sha, path, expected_mode=expected_mode)

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return super().list_issue_comments(repository, number)

        fake = ObservedClient()
        anchor = self.anchor(pr_value=fake.current_pr)
        cases = (
            ("ADD", b"add-source\n", ()),
            ("UPDATE", b"update-source\n", ()),
            ("REMOVE", b"remove-source\n", ()),
            ("RECONCILE", b"reconcile-source\n", ()),
            ("existing RequestAnchor", None, (comment(100, anchor.render(), APP.bot_node_id, APP.bot_login, "Bot"),)),
        )
        for label, marker_bytes, comments in cases:
            with self.subTest(authority=label):
                fake.marker_bytes = marker_bytes
                fake.comments = list(comments)
                fake.created.clear()
                fake.ref_calls.clear()
                fake.dispatches.clear()
                fake.marker_reads = 0
                fake.comment_reads = 0
                environment = {
                    "GITHUB_REPOSITORY": "swiftstream/skills",
                    "FEDERATION_GITHUB_TOKEN": "token",
                    "FEDERATION_APP_SLUG": APP.slug,
                    "FEDERATION_WAKE_PULL_NUMBER": "7",
                    "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
                    "FEDERATION_EVENT_PATH": "",
                }
                with (
                    patch("automation.federation.controller.GitHubClient", return_value=fake),
                    patch.object(R02Controller, "current_accepted_main", side_effect=AssertionError("standalone route reached accepted-main authority")) as accepted_main,
                    patch.object(R02Controller, "interactive_anchor_and_reconstruct", side_effect=AssertionError("standalone route reached anchor authority")) as anchor_route,
                    patch.object(R02Controller, "interactive_proposal", side_effect=AssertionError("standalone route reached proposal authority")) as proposal,
                    patch.object(R02Controller, "reconcile_interactive_request", side_effect=AssertionError("standalone route reached RECONCILE authority")) as reconcile,
                    patch.object(R02Controller, "interactive_issue_managed_route", side_effect=AssertionError("non-reserved PR entered Issue route")) as issue_route,
                    patch.object(controller_module, "read_optional_request_marker", wraps=controller_module.read_optional_request_marker) as read_marker,
                    patch.object(controller_module, "create_anchor_once", wraps=create_anchor_once) as create_anchor,
                    patch.dict(os.environ, environment, clear=False),
                ):
                    self.assertEqual(main(["interactive"]), 0)
                accepted_main.assert_not_called()
                anchor_route.assert_not_called()
                proposal.assert_not_called()
                reconcile.assert_not_called()
                issue_route.assert_not_called()
                read_marker.assert_not_called()
                create_anchor.assert_not_called()
                self.assertEqual(fake.marker_reads, 0)
                self.assertEqual(fake.comment_reads, 0)
                self.assertEqual(fake.created, [])
                self.assertEqual(fake.comments, list(comments))
                self.assertEqual(fake.ref_calls, [])
                self.assertEqual(fake.dispatches, [])

    def test_unrelated_pr_without_marker_is_clean_noop_for_federation_entrypoints(self):
        class UnrelatedClient(ProductionAddClient):
            def read_optional_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
                if path == ".federation-request":
                    return None
                return super().read_optional_commit_file(repository, commit_sha, path, expected_mode=expected_mode)

            def list_pull_request_files(self, repository, number):
                return ({"filename": "docs/README.md"},)

        for command in ("interactive", "trusted-validation"):
            with self.subTest(command=command):
                fake = UnrelatedClient()
                environment = {
                    "GITHUB_REPOSITORY": "swiftstream/skills",
                    "FEDERATION_GITHUB_TOKEN": "token",
                    "FEDERATION_APP_SLUG": APP.slug,
                    "FEDERATION_WAKE_PULL_NUMBER": "7",
                    "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
                }
                with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.dict(os.environ, environment, clear=False):
                    self.assertEqual(main([command]), 0)
                self.assertEqual(fake.created, [])
                self.assertEqual(fake.ref_calls, [])
                self.assertEqual(fake.dispatches, [])
                if command == "interactive":
                    self.assertEqual(fake.checks, [])
                    self.assertEqual(fake.check_objects, [])
                else:
                    self.assertEqual(len(fake.check_objects), 1)
                    self.assertEqual(fake.check_objects[0].conclusion, "skipped")
                    self.assertNotEqual(fake.check_objects[0].conclusion, "success")

    def test_markerless_fork_head_publishes_failure_not_skipped(self):
        class ForkUnrelatedClient(ProductionAddClient):
            def __init__(self):
                super().__init__()
                self.current_pr = replace(self.current_pr, head_repository="attacker/fork", head_repository_id="R_fork")

            def read_optional_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
                if path == ".federation-request":
                    return None
                return super().read_optional_commit_file(repository, commit_sha, path, expected_mode=expected_mode)

            def list_pull_request_files(self, repository, number):
                return ({"filename": "docs/README.md"},)

        fake = ForkUnrelatedClient()
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "7",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
        }
        with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.dict(os.environ, environment, clear=False):
            self.assertEqual(main(["trusted-validation"]), 0)
        self.assertEqual(len(fake.check_objects), 1)
        self.assertEqual(fake.check_objects[0].conclusion, "failure")
        self.assertNotEqual(fake.check_objects[0].conclusion, "skipped")
        self.assertNotEqual(fake.check_objects[0].conclusion, "success")

    def test_c05_hostile_environment_cannot_reactivate_nonreserved_interactive_authority(self):
        fake = ProductionAddClient()
        original_environment = dict(os.environ)
        hostile = {
            "PATH": "/attacker/bin",
            "GIT_INDEX_FILE": "/attacker/index",
            "GIT_EXTERNAL_DIFF": "attacker-diff",
            "GIT_TRACE": "1",
            "GIT_SSH_COMMAND": "attacker-ssh",
            "HOME": "/attacker/home",
            "XDG_CONFIG_HOME": "/attacker/xdg",
            "TMPDIR": str(ROOT / "attacker-tmp"),
            "TEMP": str(ROOT / "attacker-temp"),
            "TMP": str(ROOT / "attacker-tmp2"),
            "HTTPS_PROXY": "http://attacker.invalid:9999",
            "HTTP_PROXY": "http://attacker.invalid:9999",
            "ALL_PROXY": "http://attacker.invalid:9999",
            "NO_PROXY": "github.com",
            "SSL_CERT_FILE": str(ROOT / "attacker-cert"),
            "SSL_CERT_DIR": str(ROOT / "attacker-certs"),
            "DYLD_INSERT_LIBRARIES": "/attacker/lib.dylib",
            "LD_PRELOAD": "/attacker/lib.so",
            "SSH_AUTH_SOCK": "/attacker/ssh.sock",
            "PAGER": "attacker-pager",
            "EDITOR": "attacker-editor",
            "VISUAL": "attacker-visual",
            "PYTHONPATH": "/attacker/python",
            "VIRTUAL_ENV": "/attacker/venv",
            "FEDERATION_GITHUB_TOKEN": "central-app-secret-sentinel",
            "FEDERATION_NO_BYPASS_PROOF_V2": "signed-proof-secret-sentinel",
            "GITHUB_TOKEN": "wrong-source-token-sentinel",
            "GH_TOKEN": "wrong-source-token-sentinel",
        }
        real_run = subprocess.run

        def capture_run(argv, *args, **kwargs):
            if isinstance(argv, list) and argv and argv[0] == "/usr/bin/git":
                fake.git_invocations.append((list(argv), dict(kwargs.get("env", {})), kwargs.get("cwd")))
            return real_run(argv, *args, **kwargs)

        before_roots = set(Path("/tmp").glob("swiftstream-federation-workspace-*"))
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "central-app-secret-sentinel",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "7",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
            **hostile,
        }
        with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", c02.git_fetch_configured_branch), patch.object(c02, "repository_git_url", lambda repository: fake.source_bare.as_uri()), patch.object(controller_module.subprocess, "run", capture_run), patch.dict(os.environ, environment, clear=False):
            expected_environment = dict(os.environ)
            self.assertEqual(main(["interactive"]), 0)
            self.assertEqual(dict(os.environ), expected_environment)
        self.assertEqual(dict(os.environ), original_environment)
        self.assertEqual(fake.git_invocations, [])
        self.assertEqual(fake.source_http_observations, [])
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.ref_calls, [])
        self.assertEqual(fake.dispatches, [])
        self.assertEqual(set(Path("/tmp").glob("swiftstream-federation-workspace-*")), before_roots)

    def test_c05_capsule_failure_restores_parent_and_cleans_exact_trusted_root(self):
        original_environment = dict(os.environ)
        hostile = {"PATH": "/attacker/bin", "TMPDIR": str(ROOT / "attacker-tmp"), "FEDERATION_NO_BYPASS_PROOF_V2": "proof-sentinel"}
        before_roots = set(Path("/tmp").glob("swiftstream-federation-workspace-*"))
        with patch.dict(os.environ, hostile, clear=False):
            expected_environment = dict(os.environ)
            with self.assertRaises(c02.FederationError):
                with trusted_c02_execution() as temp_root:
                    trusted_base = controller_module.r01_workspace._resolve_trusted_temp_base(c02.ROOT)
                    self.assertEqual(temp_root.parent, trusted_base)
                    c02.run_git(["not-a-real-c02-command"])
            self.assertEqual(dict(os.environ), expected_environment)
        self.assertEqual(dict(os.environ), original_environment)
        self.assertEqual(set(Path("/tmp").glob("swiftstream-federation-workspace-*")), before_roots)

    def test_production_interactive_update_marker_is_inert_before_marker_read(self):
        class UpdateClient(ProductionAddClient):
            def __init__(self):
                super().__init__()
                self.marker_reads = 0

            def read_optional_commit_file(self, repository, commit_sha, path, *, expected_mode=None):
                if path == ".federation-request":
                    self.marker_reads += 1
                    return b"update-source\n"
                return super().read_optional_commit_file(repository, commit_sha, path, expected_mode=expected_mode)

        fake = UpdateClient()
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "7",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
        }
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.dict(os.environ, environment, clear=False):
            self.assertEqual(main(["interactive"]), 0)
        self.assertEqual(fake.marker_reads, 0)
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.ref_calls, [])
        self.assertEqual(fake.dispatches, [])

    def test_repeated_nonreserved_interactive_invocation_remains_inert(self):
        fake = ProductionAddClient()
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "7",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
        }
        with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, environment, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            first_ref_count = len(fake.ref_calls)
            first_commit = getattr(fake, "created_commit", None)
            self.assertEqual(main(["interactive"]), 0)
        self.assertEqual(len(fake.ref_calls), first_ref_count)
        self.assertEqual(getattr(fake, "created_commit", None), first_commit)
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.dispatches, [])

    def test_realistic_recursive_tree_candidate_accepts_directories_and_rejects_unsafe_leaves(self):
        from automation.federation.controller import C02CandidateBuilder

        base_sha = "b" * 40
        head_sha = "d" * 40

        class TreeClient:
            def __init__(self):
                self.base_entries = (
                    GitTreeEntry(".github", "040000", "tree", "1" * 40),
                    GitTreeEntry(".github/workflows", "040000", "tree", "2" * 40),
                    GitTreeEntry("docs", "040000", "tree", "3" * 40),
                    GitTreeEntry("skills", "040000", "tree", "4" * 40),
                    GitTreeEntry("skills/demo", "040000", "tree", "5" * 40),
                    GitTreeEntry("root.txt", "100644", "blob", "6" * 40),
                    GitTreeEntry(".github/workflows/federation.yml", "100644", "blob", "7" * 40),
                    GitTreeEntry("docs/guide.md", "100644", "blob", "8" * 40),
                    GitTreeEntry("skills/demo/SKILL.md", "100755", "blob", "9" * 40),
                )
                self.head_entries = self.base_entries[:-1] + (GitTreeEntry("skills/demo/SKILL.md", "100755", "blob", "a" * 40),)
                self.blobs = {"6" * 40: b"root", "7" * 40: b"workflow", "8" * 40: b"guide", "9" * 40: b"old", "a" * 40: b"new"}

            def get_commit_tree(self, repository, commit_sha):
                return "t" * 40, self.base_entries if commit_sha == base_sha else self.head_entries

            def get_blob(self, repository, blob_sha):
                return self.blobs[blob_sha]

            def get_commit_metadata(self, repository, commit_sha):
                return GitCommitMetadata(commit_sha, "t" * 40, (base_sha,))

        class TreeBuilder(C02CandidateBuilder):
            def _plan(self, request, request_class, accepted_base_sha):
                return {"skills/demo/SKILL.md": ("100755", b"new")}, {item.path: (item.mode, item.object_type, item.sha) for item in self.client.base_entries}, None, None

        fake = TreeClient()
        builder = TreeBuilder(fake, "swiftstream/skills", trusted_checkout_sha=base_sha)
        valid, reason = builder.validate_head(object(), RequestClass.UPDATE, base_sha, head_sha)
        self.assertTrue(valid, reason)
        fake.head_entries = fake.head_entries[:-1] + (GitTreeEntry("skills/demo/SKILL.md", "120000", "blob", "a" * 40),)
        self.assertEqual(builder.validate_head(object(), RequestClass.UPDATE, base_sha, head_sha), (False, "CANDIDATE_SYMLINK_FORBIDDEN"))
        fake.head_entries = fake.head_entries[:-1] + (GitTreeEntry("skills/demo/SKILL.md", "160000", "commit", "a" * 40),)
        self.assertEqual(builder.validate_head(object(), RequestClass.UPDATE, base_sha, head_sha), (False, "CANDIDATE_GITLINK_FORBIDDEN"))

    def test_existing_request_head_compares_semantic_leaves_and_allows_changed_ancestor_shas(self):
        base_sha = "b" * 40
        head_sha = "d" * 40

        class TreeClient:
            def __init__(self):
                self.base_entries = (
                    GitTreeEntry("skills", "040000", "tree", "1" * 40),
                    GitTreeEntry("skills/foo", "040000", "tree", "2" * 40),
                    GitTreeEntry("skills/foo/SKILL.md", "100755", "blob", "3" * 40),
                    GitTreeEntry("federation.json", "100644", "blob", "4" * 40),
                )
                self.head_entries = (
                    GitTreeEntry("skills", "040000", "tree", "5" * 40),
                    GitTreeEntry("skills/foo", "040000", "tree", "6" * 40),
                    GitTreeEntry("skills/foo/SKILL.md", "100755", "blob", "7" * 40),
                    GitTreeEntry("federation.json", "100644", "blob", "4" * 40),
                )

            def get_commit_tree(self, repository, commit_sha):
                return ("8" * 40, self.base_entries) if commit_sha == base_sha else ("9" * 40, self.head_entries)

        fake = TreeClient()
        validate_existing_request_head(fake, "swiftstream/skills", pr(head=head_sha), RequestClass.UPDATE, base_sha)

        fake.head_entries = tuple(
            GitTreeEntry(item.path, item.mode, item.object_type, "a" * 40) if item.object_type == "tree" else item
            for item in fake.base_entries
        )
        with self.assertRaises(CandidateScopeError):
            validate_existing_request_head(fake, "swiftstream/skills", pr(head=head_sha), RequestClass.UPDATE, base_sha)

        fake.head_entries = fake.base_entries + (GitTreeEntry(".github", "040000", "tree", "a" * 40), GitTreeEntry(".github/workflow.yml", "100644", "blob", "b" * 40))
        with self.assertRaises(CandidateScopeError):
            validate_existing_request_head(fake, "swiftstream/skills", pr(head=head_sha), RequestClass.UPDATE, base_sha)

    def test_nonreserved_route_stays_inert_and_helper_rejects_post_anchor_edit_restore(self):
        fake = ProductionAddClient()
        fake.current_pr = replace(fake.current_pr, base_oid="e" * 40)
        environment = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}
        with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, environment, clear=False):
            self.assertEqual(main(["interactive"]), 0)
        self.assertEqual(fake.ref_calls, [])
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.dispatches, [])

        race = ProductionAddClient()
        def edit_and_restore(_request, _request_class, _base, _head):
            race.current_pr = replace(race.current_pr, last_edited_at="2026-09-02T00:00:00Z", includes_created_edit=True)
            return ProposalCandidate("d" * 40, race.main_oid, ("federation.json",), RequestClass.ADD)
        controller = R02Controller(race, "swiftstream/skills", APP, candidate_builder=edit_and_restore)
        controller.interactive_anchor_and_reconstruct(7, RequestClass.ADD)
        with self.assertRaises(StaleAuthorityError):
            controller.interactive_proposal(7, RequestClass.ADD, race.main_oid, "refs/heads/proposal")
        self.assertEqual(race.ref_calls, [])

    def test_complete_authorized_patch_fold_is_sorted_and_maintainer_is_exact(self):
        anchor = self.anchor()
        events = [
            comment(30, "Federation PATCH\n\nDescription:\nwriter must not apply\n", author_id="U_writer", author_login="writer"),
            comment(20, "Federation PATCH\n\nBranch:\nrelease\n", author_id="U_maintainer", author_login="maintainer"),
            comment(10, "ordinary discussion", author_id="U_author", author_login="alice"),
            comment(40, "Federation PATCH\n\nDescription:\nfinal\n", author_id="U_author", author_login="alice"),
        ]
        result = authorized_patch_events(FakeClient(), "swiftstream/skills", AnchorCommentForTest(anchor, comment(5, anchor.render(), APP.bot_node_id, APP.bot_login, "Bot")), events)
        self.assertEqual([event.comment_id for event in result], [10, 20, 30, 40])
        self.assertEqual([event.authorized for event in result], [True, True, False, True])

    def test_remove_and_reconcile_are_phase_or_patch_immutable(self):
        self.assertEqual(phase_gate(RequestClass.RECONCILE), "RECONCILE_NOT_ENABLED_IN_R02")
        self.assertEqual(allowed_proposal_paths(RequestClass.ADD), frozenset({"federation.json"}))
        with self.assertRaises(CandidateScopeError):
            validate_proposal_scope(RequestClass.ADD, ["federation.json", "README.md"])

    def test_update_remove_generated_scope_is_safe_and_bounded(self):
        generated = ["federation.json", "federation.lock.json", "README.md", "skills/swiftstream-demo/SKILL.md"]
        for request_class in (RequestClass.UPDATE, RequestClass.REMOVE):
            self.assertEqual(validate_proposal_scope(request_class, generated).paths, tuple(sorted(generated)))
            for bad in ("skills/../federation.json", ".github/workflow.yml", "automation/controller.py", "unrelated.txt"):
                with self.subTest(request_class=request_class, bad=bad), self.assertRaises(CandidateScopeError):
                    validate_proposal_scope(request_class, [bad])

    def test_add_update_remove_candidate_adapters_delegate_manifest_validation_to_c02(self):
        add_request = parse_request_body(RequestClass.ADD, BODY)
        empty = c02.Manifest(())
        added = c02_source_candidate(add_request, empty, source_id="swiftstream", repository_id=7, default_branch="main", default_description="desc", default_prefixes=("swiftstream",))
        self.assertEqual(added.sources[0].repository, "Owner/Repo")
        accepted = added
        update_request = parse_request_body(RequestClass.UPDATE, BODY.replace("A source", "Updated"))
        updated = c02_source_candidate(update_request, accepted, source_id="swiftstream", repository_id=7, default_branch="main", default_description="desc", default_prefixes=("swiftstream",))
        self.assertEqual(updated.sources[0].description, "Updated")
        remove_request = parse_request_body(RequestClass.REMOVE, "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\ncleanup\n")
        removed = c02_source_candidate(remove_request, accepted, source_id="swiftstream", repository_id=7, default_branch="main", default_description="desc", default_prefixes=("swiftstream",))
        self.assertEqual(removed.sources, ())

    def test_readme_diff_is_limited_to_c02_managed_section(self):
        readme = (ROOT / "README.md").read_bytes()
        validate_readme_managed_diff(readme, readme)
        with self.assertRaises(CandidateScopeError):
            validate_readme_managed_diff(b"changed\n" + readme, readme)

    def test_fork_heads_fail_closed_and_no_pat_workaround_exists(self):
        from automation.federation.controller import require_same_repository_head
        with self.assertRaises(ForkHeadError):
            require_same_repository_head(pr(head_repo="attacker/fork"), "swiftstream/skills")

    def test_pre_mutation_cas_drift_and_rest_update_absence(self):
        fake = FakeClient()
        candidate = type("Candidate", (), {"commit_sha": "d" * 40})()
        fake.reject_cas = True
        with self.assertRaises(StaleAuthorityError):
            replace_request_ref_cas(fake, "7", "refs/heads/proposal", "a" * 40, candidate)
        self.assertEqual(fake.ref_calls, [])
        api_source = (ROOT / "automation/federation/github_api.py").read_text()
        self.assertNotIn("/git/refs", api_source)
        self.assertNotIn("Update-a-reference", api_source)

    def test_result_comments_are_idempotent_by_human_comment_id(self):
        marker = result_idempotency_marker("patch", 42)
        self.assertTrue(has_result_for_comment([comment(99, marker)], "patch", 42))
        self.assertFalse(has_result_for_comment([comment(99, marker)], "patch", 43))

    def test_existing_request_head_rejects_extra_path_and_unexpected_mode_before_builder(self):
        fake = FakeClient()
        original = fake.get_commit_tree

        def malicious(repository, commit_sha):
            tree_sha, entries = original(repository, commit_sha)
            if commit_sha == fake.current_pr.head_oid:
                entries = entries + (GitTreeEntry(".github/workflow.yml", "100644", "blob", "9" * 40),)
            return tree_sha, entries

        fake.get_commit_tree = malicious
        with self.assertRaises(CandidateScopeError):
            validate_existing_request_head(fake, "swiftstream/skills", fake.current_pr, RequestClass.ADD, fake.main_oid)

    def test_issue_comment_manual_patch_event_is_inert_for_nonreserved_pr(self):
        class RaceClient(ProductionAddClient):
            def update_refs(self, repository_id, updates):
                super().update_refs(repository_id, updates)
                self.comments.append(comment(201, "Federation PATCH\n\nDescription:\nLater\n"))

        fake = RaceClient()
        trigger_id = 200
        fake.comments.append(comment(trigger_id, "Federation PATCH\n\nDescription:\nTriggered\n"))
        event_file = Path(tempfile.mktemp(prefix="c03-issue-event-"))
        event_file.write_text(json.dumps({"action": "created", "issue": {"number": 7, "pull_request": {}}, "comment": {"id": trigger_id}}), encoding="utf-8")
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "",
            "FEDERATION_EVENT_PATH": str(event_file),
            "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
        }
        with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, environment, clear=False):
            self.assertEqual(main(["interactive"]), 0)
        self.assertEqual(fake.comments, [comment(trigger_id, "Federation PATCH\n\nDescription:\nTriggered\n")])
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.ref_calls, [])
        self.assertEqual(fake.dispatches, [])
        event_file.unlink(missing_ok=True)

    def test_app_bot_issue_comment_triggers_are_ignored(self):
        fake = ProductionAddClient()
        event_file = Path(tempfile.mktemp(prefix="c03-bot-issue-event-"))
        event_file.write_text(json.dumps({
            "action": "created",
            "issue": {"number": 7, "pull_request": {}},
            "comment": {"id": 900, "user": {"login": APP.bot_login, "type": "Bot"}},
        }), encoding="utf-8")
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_EVENT_PATH": str(event_file),
            "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid,
        }
        with patch("automation.federation.controller.GitHubClient", return_value=fake), trusted_previous_patches(), patch.dict(os.environ, environment, clear=False):
            self.assertEqual(main(["interactive"]), 0)
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.dispatches, [])
        event_file.unlink(missing_ok=True)

    def test_controller_logs_only_validated_graphql_diagnostics(self):
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
        }

        def run_with(error):
            stderr = io.StringIO()
            with patch("automation.federation.controller.GitHubClient", return_value=object()), patch.object(controller_module, "resolve_app_identity", side_effect=error), patch.dict(os.environ, environment, clear=True), patch("sys.stderr", stderr):
                self.assertEqual(main(["trusted-validation"]), 1)
            return stderr.getvalue()

        safe = run_with(GraphQLError("GRAPHQL:FORBIDDEN:repository.pullRequest.comments.0.author"))
        self.assertEqual(safe, "C03-R02 controller blocked: GraphQLError:GRAPHQL:FORBIDDEN:repository.pullRequest.comments.0.author\n")

        for error, sentinel in (
            (GraphQLError("server-secret-sentinel"), "server-secret-sentinel"),
            (GraphQLError("GRAPHQL:FORBIDDEN:repository.bad-segment"), "bad-segment"),
            (RefCASConflict("subclass-secret-sentinel"), "subclass-secret-sentinel"),
        ):
            with self.subTest(error=type(error).__name__):
                output = run_with(error)
                self.assertEqual(output, "C03-R02 controller blocked: GraphQLError:GRAPHQL:UNKNOWN:unknown-path\n")
                self.assertNotIn(sentinel, output)

        non_graphql = run_with(R02Error("user-secret-sentinel"))
        self.assertEqual(non_graphql, "C03-R02 controller blocked: R02Error\n")
        self.assertNotIn("user-secret-sentinel", non_graphql)

    def test_interactive_metadata_api_failure_does_not_read_or_write_blocked_result(self):
        class ObservedClient(FakeClient):
            def __init__(self, error):
                super().__init__()
                self.error = error
                self.metadata_reads = 0
                self.comment_reads = 0
                self.dispatches = []

            def get_pull_request_metadata(self, repository, number):
                self.metadata_reads += 1
                raise self.error

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return super().list_issue_comments(repository, number)

            def dispatch_workflow(self, repository, workflow, ref, inputs=None):
                self.dispatches.append((repository, workflow, ref, inputs))

        fake = ObservedClient(GitHubAPIError("metadata API unavailable"))
        anchor = self.anchor()
        fake.comments.append(comment(50, anchor.render(), APP.bot_node_id, APP.bot_login, "Bot"))
        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "7",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": "c" * 40,
        }
        stderr = io.StringIO()
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(
            controller_module, "resolve_app_identity", return_value=APP
        ), patch.dict(os.environ, environment, clear=True), patch("sys.stderr", stderr):
            self.assertEqual(main(["interactive"]), 1)
        self.assertEqual(stderr.getvalue(), "C03-R02 controller blocked: GitHubAPIError\n")
        self.assertEqual(fake.metadata_reads, 1)
        self.assertEqual(fake.comment_reads, 0)
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.comments, [comment(50, anchor.render(), APP.bot_node_id, APP.bot_login, "Bot")])
        self.assertEqual(fake.ref_calls, [])
        self.assertEqual(fake.dispatches, [])

    def test_interactive_preclassification_stale_skips_comment_reporting_and_wakes_only_reserved(self):
        class ObservedClient(FakeClient):
            def __init__(self, error=None, current_pr=None):
                super().__init__(current_pr=current_pr)
                self.error = error
                self.metadata_reads = 0
                self.comment_reads = 0
                self.dispatches = []

            def get_pull_request_metadata(self, repository, number):
                self.metadata_reads += 1
                if self.error is not None:
                    raise self.error
                return self.current_pr

            def list_issue_comments(self, repository, number):
                self.comment_reads += 1
                return super().list_issue_comments(repository, number)

            def dispatch_workflow(self, repository, workflow, ref, inputs=None):
                self.dispatches.append((repository, workflow, ref, inputs))

        environment = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "token",
            "FEDERATION_APP_SLUG": APP.slug,
            "FEDERATION_WAKE_PULL_NUMBER": "7",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": "c" * 40,
        }
        fake = ObservedClient(StaleAuthorityError("metadata authority changed"))
        anchor = self.anchor()
        fake.comments.append(comment(50, anchor.render(), APP.bot_node_id, APP.bot_login, "Bot"))
        stderr = io.StringIO()
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(
            controller_module, "resolve_app_identity", return_value=APP
        ), patch.dict(os.environ, environment, clear=True), patch("sys.stderr", stderr):
            self.assertEqual(main(["interactive"]), 1)
        self.assertEqual(stderr.getvalue(), "C03-R02 controller blocked: StaleAuthorityError\n")
        self.assertEqual(fake.metadata_reads, 1)
        self.assertEqual(fake.comment_reads, 0)
        self.assertEqual(fake.created, [])
        self.assertEqual(fake.ref_calls, [])
        self.assertEqual(fake.dispatches, [])

        reserved = ObservedClient(
            current_pr=replace(pr(), head_ref="bot/federation/request/issue-7"),
        )
        reserved_anchor = self.anchor(pr_value=reserved.current_pr)
        reserved.comments.append(comment(51, reserved_anchor.render(), APP.bot_node_id, APP.bot_login, "Bot"))
        reserved_stderr = io.StringIO()
        with patch("automation.federation.controller.GitHubClient", return_value=reserved), patch.object(
            controller_module, "resolve_app_identity", return_value=APP
        ), patch.object(
            R02Controller,
            "interactive_issue_managed_route",
            side_effect=StaleAuthorityError("classified Issue authority changed"),
        ), patch.dict(os.environ, environment, clear=True), patch("sys.stderr", reserved_stderr):
            self.assertEqual(main(["interactive"]), 1)
        self.assertEqual(reserved_stderr.getvalue(), "C03-R02 controller blocked: StaleAuthorityError\n")
        self.assertEqual(reserved.metadata_reads, 1)
        self.assertEqual(reserved.comment_reads, 0)
        self.assertEqual(reserved.created, [])
        self.assertEqual(reserved.comments, [comment(51, reserved_anchor.render(), APP.bot_node_id, APP.bot_login, "Bot")])
        self.assertEqual(reserved.ref_calls, [])
        self.assertEqual(
            reserved.dispatches,
            [("swiftstream/skills", "federation-g8-state-finalize.yml", "refs/heads/main", {})],
        )

    def test_proposal_blocked_reason_retains_exception_type_name(self):
        from automation.federation.controller import _bounded_error_reason

        class EmptyMessageError(Exception):
            pass

        empty = EmptyMessageError("")
        self.assertEqual(_bounded_error_reason(empty), "EmptyMessageError:")

        long_error = R02Error("z" * 200)
        bounded = _bounded_error_reason(long_error)
        self.assertTrue(bounded.startswith("R02Error:"))
        self.assertLessEqual(len(bounded), len("R02Error:") + 160)
        self.assertEqual(bounded, f"R02Error:{'z' * 160}")

        short_error = R02Error("why")
        self.assertEqual(_bounded_error_reason(short_error), "R02Error:why")

    def test_workflows_have_exact_triggers_pins_and_no_pr_head_execution(self):
        for name in ("federation-g8-interactive.yml", "federation-g8-trusted-validation.yml", "federation-g8-state-finalize.yml"):
            text = (ROOT / ".github/workflows" / name).read_text()
            self.assertIn("FEDERATION_EVENT_PATH: ${{ github.event_path }}", text)
            self.assertNotIn("FEDERATION_EVENT_PATH: $GITHUB_EVENT_PATH", text)
            self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", text)
            self.assertIn("actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1", text)
            self.assertIn("persist-credentials: false", text)
            self.assertNotIn("pull_request:\n", text)
            self.assertNotIn("checkout@main", text)
            self.assertNotIn("git push", text)
            self.assertNotIn("      actions: write\n", text)


class AnchorCommentForTest:
    def __init__(self, anchor, comment):
        self.anchor = anchor
        self.comment = comment


if __name__ == "__main__":
    unittest.main()
