import json
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

from automation.federation.controller import (
    AppIdentity,
    MachinePRAuthority,
    MachineReconcileResult,
    ProposalCandidate,
    R02Controller,
    R02Error,
    parse_repository_id_hint,
    validate_machine_generated_scope,
    TrustedValidationResult,
    bounded_check_output,
    render_check_run_output,
    verify_machine_check_identity,
)
from automation.federation.github_api import CheckRun, GitHubClient, GitTreeEntry, HttpResponse, IssueComment, NotFoundError, PullRequestMetadata, RepositoryMetadata, RefCASConflict
from automation.federation.request_model import ANCHOR_MARKER, RequestClass, RequestAnchor, body_sha256, parse_request_body
from scripts import federate as c02
import automation.federation.controller as controller_module


class ReconcileClient:
    def __init__(self):
        self.main = "a" * 40
        self.refs = []
        self.dispatches = []

    def get_repository_metadata(self, repository):
        return RepositoryMetadata(7, "R_central", repository, "main")

    def get_ref_oid(self, repository, branch):
        if branch == "main":
            return self.main
        raise NotFoundError("missing ref")

    def list_open_pull_requests(self, repository):
        return ()

    def update_refs(self, repository_id, updates):
        self.refs.extend(updates)

    def create_machine_pull_request(self, repository, **kwargs):
        self.created_pr = kwargs
        return 41

    def dispatch_workflow(self, repository, workflow, ref, inputs=None):
        self.dispatches.append((workflow, ref, inputs))


class ReconcileTests(unittest.TestCase):
    def _manual_reconcile_fixture(self, *, accepted=True, edited=False, fork=False):
        body = "Repository URL:\nhttps://github.com/Owner/Repo\n"
        current = "a" * 40
        request = parse_request_body(RequestClass.RECONCILE, body)
        anchor = RequestAnchor(7, RequestClass.RECONCILE, "U_author", "alice", body_sha256(body), request)
        anchor_comment = IssueComment("IC_anchor", 100, anchor.render(), "U_bot", "app[bot]", "Bot", None, None, None, None, False)

        class ManualClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(7, body, "U_author", "alice", "d" * 40, current, "request", "main", "R_central" if not fork else "R_fork", "swiftstream/skills" if not fork else "someone/fork", "R_central", "swiftstream/skills", "2026-01-01" if edited else None, edited)
                self.comments = [] if edited else [anchor_comment]
                self.states = []

            def get_pull_request_metadata(self, repository, number):
                return self.pr

            def list_issue_comments(self, repository, number):
                return tuple(self.comments)

            def create_issue_comment(self, repository, number, body):
                comment = IssueComment("IC_result", 101, body, "U_bot", "app[bot]", "Bot", None, None, None, None, False)
                self.comments.append(comment)
                return comment

            def update_pull_request_state(self, repository, number, *, state):
                self.states.append((number, state))

        client = ManualClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,) if accepted else ()
        return client, controller, source

    def test_repository_id_hint_is_bounded_and_exact(self):
        self.assertEqual(parse_repository_id_hint("123"), 123)
        for value in ("0", "-1", "01", "9" * 19 + "9", "1;rm", None):
            with self.subTest(value=value), self.assertRaises(R02Error):
                parse_repository_id_hint(value)

    def test_unknown_repository_id_is_noop_without_mutation(self):
        client = ReconcileClient()
        client.main = c02.head_commit_oid()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"))
        controller._accepted_sources = lambda _main=None: ()
        result = controller.reconcile("99")
        self.assertEqual(result, MachineReconcileResult("NOOP", repository_id=99, reason="UNKNOWN_REPOSITORY_ID"))
        self.assertEqual(client.refs, [])
        self.assertEqual(client.dispatches, [])

    def test_changed_source_uses_zero_before_oid_and_global_finalizer_wake(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        candidate = ProposalCandidate("d" * 40, client.main, ("README.md", "federation.lock.json"), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        builder = type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"), candidate_builder=builder)
        controller._accepted_sources = lambda _main=None: (source,)
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(client.refs[0].before_oid, "0" * 40)
        self.assertFalse(client.refs[0].force)
        self.assertEqual(client.dispatches[-1][0], "federation-state-finalize.yml")

    def test_machine_scope_rejects_non_generated_paths(self):
        class Trees:
            def get_commit_tree(self, repository, commit):
                entries = (GitTreeEntry("federation.json", "100644", "blob", "1" * 40), GitTreeEntry("README.md", "100644", "blob", "2" * 40))
                if commit == "h" * 40:
                    entries = (GitTreeEntry("federation.json", "100644", "blob", "3" * 40), GitTreeEntry("README.md", "100644", "blob", "2" * 40))
                return "t" * 40, entries
        with self.assertRaises(Exception):
            validate_machine_generated_scope(Trees(), "swiftstream/skills", "b" * 40, "h" * 40)

    def _controller_with_source(self, client, source=None, builder=None):
        source = source or c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"), candidate_builder=builder)
        controller._accepted_sources = lambda _main=None: (source,)
        return controller, source

    def test_repository_id_hint_zero_negative_overflow_and_injection_are_blocked(self):
        for value in (0, -1, 10**19, "0", "-1", "1;rm", "1\n2", True):
            with self.subTest(value=value), self.assertRaises(R02Error):
                parse_repository_id_hint(value)

    def test_unknown_mapping_is_noop_after_bound_manifest_read(self):
        client = ReconcileClient()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"))
        calls = []
        controller._accepted_sources = lambda _main=None: calls.append(_main) or ()
        result = controller.reconcile("123")
        self.assertEqual(result.outcome, "NOOP")
        self.assertEqual(calls, [client.main])
        self.assertEqual(client.refs, [])
        self.assertEqual(client.dispatches, [])

    def test_reconcile_never_uses_wake_hint_as_source_authority(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("real", "Owner/Repo", 99, "refs/heads/main", "skills", ("real",), "Real")
        candidate = ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "real", 99)
        builder = type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})()
        controller, _ = self._controller_with_source(client, source, builder)
        self.assertEqual(controller.reconcile("99").source_id, "real")
        self.assertEqual(controller.reconcile("123").outcome, "NOOP")

    def test_reconcile_candidate_identity_failure_is_bounded_fail(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        builder = type("Builder", (), {"machine_candidate": lambda _self, base, source_id: (_ for _ in ()).throw(R02Error("identity"))})()
        controller, _ = self._controller_with_source(client, source, builder)
        result = controller.reconcile(99)
        self.assertEqual((result.outcome, result.reason), ("FAIL", "identity"))
        self.assertEqual(client.refs, [])

    def test_cas_loss_recomputes_with_fresh_main_and_before_oid(self):
        class CASClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.branch_reads = 0
                self.updates = 0

            def get_ref_oid(self, repository, branch):
                if branch == "main":
                    return self.main
                self.branch_reads += 1
                return "b" * 40 if self.branch_reads == 1 else "c" * 40

            def update_refs(self, repository_id, updates):
                self.updates += 1
                if self.updates == 1:
                    raise RefCASConflict("competitor won")
                self.refs.extend(updates)

        client = CASClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        candidates = [ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99), ProposalCandidate("e" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)]
        seen = []
        class Builder:
            def machine_candidate(self, base, source_id):
                seen.append((base, source_id))
                return candidates[len(seen) - 1]
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(len(seen), 2)
        self.assertEqual(client.refs[0].before_oid, "c" * 40)
        self.assertTrue(client.refs[0].force)

    def test_repeated_cas_loss_exhausts_without_stale_overwrite(self):
        class AlwaysCAS(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.reads = 0
                self.updates = 0

            def get_ref_oid(self, repository, branch):
                if branch == "main":
                    return self.main
                self.reads += 1
                return ("b" if self.reads == 1 else "c") * 40

            def update_refs(self, repository_id, updates):
                self.updates += 1
                raise RefCASConflict("always loses")

        client = AlwaysCAS()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        candidate = ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        controller, _ = self._controller_with_source(client, source, type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})())
        result = controller.reconcile(99)
        self.assertEqual(result.reason, "MACHINE_BRANCH_CAS_CONFLICT_RECOMPUTE_EXHAUSTED")
        self.assertEqual(client.updates, 3)
        self.assertEqual(client.refs, [])

    def test_existing_matching_branch_has_no_cas_churn(self):
        class Matching(ReconcileClient):
            def get_ref_oid(self, repository, branch):
                return self.main if branch == "main" else "d" * 40
        client = Matching()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        candidate = ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        controller, _ = self._controller_with_source(client, source, type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})())
        self.assertEqual(controller.reconcile(99).outcome, "CHANGED")
        self.assertEqual(client.refs, [])

    def test_rendered_machine_evidence_binds_class_head_base_source_and_repository(self):
        result = TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, "a" * 40, "b" * 40, "demo", 99, "BLOCKED"))
        output = render_check_run_output(result)
        for field, value in (("class", "machine-publication"), ("head", "a" * 40), ("accepted_base", "b" * 40), ("sourceId", "demo"), ("repositoryId", "99")):
            self.assertIn(f"{field}={value}", output["text"])
        self.assertNotIn("token", json.dumps(output).lower())

    def test_trusted_manifest_read_is_capsule_bound_and_parent_environment_restored(self):
        client = ReconcileClient()
        client.main = c02.head_commit_oid()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"))
        original = dict(os.environ)
        hostile = {"PATH": "/attacker", "GIT_DIR": "/attacker/repo", "HOME": "/attacker/home", "TMPDIR": "/attacker/tmp", "HTTPS_PROXY": "http://attacker.invalid", "FEDERATION_GITHUB_TOKEN": "secret"}
        with patch.dict(os.environ, hostile, clear=False):
            self.assertEqual(controller._accepted_sources(client.main), ())
        self.assertEqual(dict(os.environ), original)

    def test_machine_source_scope_rejects_federation_docs_scripts_automation_and_unrelated_roots(self):
        for path in ("federation.json", "docs/x", "scripts/x", ".github/x", "automation/x", "other/x"):
            with self.subTest(path=path):
                client = ReconcileClient()
                source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
                candidate = ProposalCandidate("d" * 40, "a" * 40, (path,), RequestClass.MACHINE_PUBLICATION, "demo", 99)
                class Builder:
                    def __init__(self):
                        self.calls = []

                    def machine_candidate(self, base, source_id):
                        self.calls.append((base, source_id))
                        return candidate

                builder = Builder()
                controller, _ = self._controller_with_source(client, source, builder)
                result = controller.reconcile(99)

                self.assertEqual(result.outcome, "FAIL")
                self.assertEqual((result.source_id, result.repository_id), ("demo", 99))
                self.assertIn(result.reason, {
                    "proposal changed a path outside the exact R02 class scope",
                    "machine candidate changed a forbidden path",
                })
                self.assertEqual(builder.calls, [(client.main, "demo")])
                self.assertEqual(client.refs, [])
                self.assertFalse(hasattr(client, "created_pr"))
                self.assertEqual(client.dispatches, [])

    def test_machine_branch_is_validated_as_nested_central_ref(self):
        class Transport:
            def __init__(self):
                self.calls = []
            def request(self, method, url, headers, body, timeout):
                self.calls.append((method, url, json.loads(body)))
                return HttpResponse(201, url, b'{"number":41}')
        transport = Transport()
        client = GitHubClient("secret", transport)
        self.assertEqual(client.create_machine_pull_request("swiftstream/skills", head="bot/federation/demo", base="main", title="t", body="b"), 41)
        self.assertEqual(transport.calls[0][2]["head"], "bot/federation/demo")
        for unsafe in ("owner:bot/federation/demo", "refs/heads/bot/federation/demo", "bot\\federation\\demo", "bot/federation/../demo"):
            with self.subTest(unsafe=unsafe), self.assertRaises(Exception):
                client.create_machine_pull_request("swiftstream/skills", head=unsafe, base="main", title="t", body="b")

    def test_exact_owned_invalid_machine_pr_is_commented_and_closed(self):
        class OwnedInvalid(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(7, "", "U", "app[bot]", "d" * 40, self.main, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False)
                self.comments = []
                self.states = []
            def list_open_pull_requests(self, repository):
                return ({"number": 7},)
            def get_pull_request_metadata(self, repository, number):
                return self.pr
            def list_issue_comments(self, repository, number):
                return tuple(self.comments)
            def create_issue_comment(self, repository, number, body):
                self.comments.append(type("Comment", (), {"body": body, "database_id": len(self.comments) + 1})())
            def update_pull_request_state(self, repository, number, *, state):
                self.states.append((number, state))
            def get_commit_tree(self, repository, commit):
                entries = (GitTreeEntry("federation.json", "100644", "blob", "1" * 40), GitTreeEntry("README.md", "100644", "blob", "2" * 40))
                if commit == self.pr.head_oid:
                    entries = (GitTreeEntry("federation.json", "100644", "blob", "3" * 40), GitTreeEntry("README.md", "100644", "blob", "2" * 40))
                return "t" * 40, entries
        client = OwnedInvalid()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        candidate = ProposalCandidate("e" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        controller, _ = self._controller_with_source(client, source, type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "FAIL")
        self.assertEqual(client.states, [(7, "closed")])
        self.assertIn("MACHINE_RECONCILE_FAILED", client.comments[0].body)

    def test_wrong_app_same_machine_branch_is_not_owned_or_mutated(self):
        class WrongApp(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(7, "", "wrong", "other[bot]", "d" * 40, self.main, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False)
                self.states = []
            def list_open_pull_requests(self, repository):
                return ({"number": 7},)
            def get_pull_request_metadata(self, repository, number):
                return self.pr
            def update_pull_request_state(self, repository, number, *, state):
                self.states.append((number, state))
        client = WrongApp()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller, _ = self._controller_with_source(client, source, None)
        self.assertEqual(controller._machine_prs(client.main, client.get_repository_metadata("swiftstream/skills"), (source,))["demo"], [])
        self.assertEqual(client.states, [])

    def test_manual_reconcile_uses_immutable_anchor_and_same_controller_logic(self):
        client, controller, _source = self._manual_reconcile_fixture()
        calls = []
        controller.reconcile = lambda repository_id, **kwargs: calls.append(repository_id) or MachineReconcileResult("NOOP", "demo", repository_id, "CURRENT_STATE_ALREADY_MATCHES")
        with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
            result = controller.reconcile_interactive_request(7, client.main)
        self.assertEqual(result.outcome, "NOOP")
        self.assertEqual(calls, [99])
        self.assertEqual(client.states, [(7, "closed")])
        self.assertEqual(sum("swiftstream-federation-result:reconcile:100" in item.body for item in client.comments), 1)

    def test_manual_reconcile_unknown_source_guides_and_closes_without_machine_work(self):
        client, controller, _source = self._manual_reconcile_fixture(accepted=False)
        controller.reconcile = lambda _repository_id: self.fail("unknown source must not reconcile")
        with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
            result = controller.reconcile_interactive_request(7, client.main)
        self.assertEqual(result.reason, "SOURCE_NOT_ACCEPTED_USE_ADD_SOURCE")
        self.assertIn("RECONCILE_UNKNOWN_SOURCE", client.comments[-1].body)
        self.assertEqual(client.states, [(7, "closed")])

    def test_manual_reconcile_changed_and_failed_outcomes_are_bounded_and_closed(self):
        for outcome, reason, code in (("CHANGED", "MACHINE_PR_41", "RECONCILE_CHANGED"), ("FAIL", "bounded failure", "RECONCILE_FAILED")):
            with self.subTest(outcome=outcome):
                client, controller, _source = self._manual_reconcile_fixture()
                controller.reconcile = lambda _repository_id, outcome=outcome, reason=reason, **kwargs: MachineReconcileResult(outcome, "demo", 99, reason)
                with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
                    controller.reconcile_interactive_request(7, client.main)
                self.assertIn(code, client.comments[-1].body)
                self.assertEqual(client.states, [(7, "closed")])

    def test_manual_reconcile_result_identity_makes_replay_idempotent(self):
        client, controller, _source = self._manual_reconcile_fixture()
        calls = []
        controller.reconcile = lambda repository_id, **kwargs: calls.append(repository_id) or MachineReconcileResult("CHANGED", "demo", repository_id, "MACHINE_PR_41")
        with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
            controller.reconcile_interactive_request(7, client.main)
            controller.reconcile_interactive_request(7, client.main)
        self.assertEqual(calls, [99])
        self.assertEqual(len(client.comments), 2)
        self.assertEqual(client.states, [(7, "closed")])

    def test_manual_reconcile_preanchor_edit_and_fork_fail_before_reconcile(self):
        for edited, fork in ((True, False), (False, True)):
            with self.subTest(edited=edited, fork=fork):
                client, controller, _source = self._manual_reconcile_fixture(edited=edited, fork=fork)
                controller.reconcile = lambda _repository_id: self.fail("invalid technical request must not reconcile")
                with self.assertRaises(R02Error):
                    controller.reconcile_interactive_request(7, client.main)
                self.assertEqual(client.states, [])

    def test_manual_reconcile_never_cas_mutates_the_technical_request_branch(self):
        client, controller, _source = self._manual_reconcile_fixture()
        client.update_refs = lambda *args, **kwargs: self.fail("technical request must never branch-CAS")
        controller.reconcile = lambda repository_id, **kwargs: MachineReconcileResult("NOOP", "demo", repository_id, "CURRENT_STATE_ALREADY_MATCHES")
        with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
            controller.reconcile_interactive_request(7, client.main)

    def test_machine_validation_rejects_stale_base_before_candidate_validation(self):
        client = ReconcileClient()
        client.pr = PullRequestMetadata(7, "", "U", "app[bot]", "d" * 40, "b" * 40, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False)
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        called = []
        builder = type("Builder", (), {"validate_machine_head": lambda _self, *args: called.append(args) or (True, "ok")})()
        controller, _ = self._controller_with_source(client, source, builder)
        client.get_pull_request_metadata = lambda _repository, _number: client.pr
        result = controller.trusted_machine_validation(7, client.main, expected_head_sha=client.pr.head_oid)
        self.assertEqual(result.output["result"], "MACHINE_PR_BASE_MISMATCH")
        self.assertEqual(called, [])

    def test_machine_check_identity_rejects_missing_wrong_and_duplicate_evidence(self):
        head = "a" * 40
        base = "b" * 40
        prefix = f"class=machine-publication; head={head}; accepted_base={base}; sourceId=demo; repositoryId=99"
        for text in (None, prefix.replace("repositoryId=99", "repositoryId=98"), prefix + "; sourceId=demo", prefix.replace(f"accepted_base={base}", f"accepted_base={'c' * 40}")):
            with self.subTest(text=text):
                check = CheckRun(1, "federation/trusted-validation", head, "completed", "failure", 1, text)
                with self.assertRaises(R02Error):
                    verify_machine_check_identity(check, head_sha=head, accepted_base_sha=base, source_id="demo", repository_id=99)

    def test_machine_check_identity_accepts_exact_canonical_evidence(self):
        head = "a" * 40
        base = "b" * 40
        text = f"class=machine-publication; head={head}; accepted_base={base}; sourceId=demo; repositoryId=99; result=READY"
        check = CheckRun(1, "federation/trusted-validation", head, "completed", "success", 1, text)
        verify_machine_check_identity(check, head_sha=head, accepted_base_sha=base, source_id="demo", repository_id=99)

    def test_manual_reconcile_guard_blocks_request_race_before_first_machine_mutation(self):
        client, controller, source = self._manual_reconcile_fixture()
        candidate = ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        controller.candidate_builder = type("Builder", (), {"machine_candidate": lambda _self, _base, _source_id: candidate})()
        reads = 0
        original = client.pr

        def read_pr(_repository, _number):
            nonlocal reads
            reads += 1
            if reads == 3:
                client.pr = replace(original, head_oid="e" * 40)
            return client.pr

        client.get_pull_request_metadata = read_pr
        with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
            with self.assertRaises(controller_module.StaleAuthorityError):
                controller.reconcile_interactive_request(7, client.main)
        self.assertEqual(client.refs, [])
        self.assertFalse(hasattr(client, "created_pr"))
        self.assertEqual(client.dispatches, [])
        self.assertEqual(client.states, [])
        self.assertEqual(len(client.comments), 1)

    def test_manual_reconcile_guard_blocks_request_race_before_finalizer_dispatch(self):
        client, controller, _source = self._manual_reconcile_fixture()
        candidate = ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        controller.candidate_builder = type("Builder", (), {"machine_candidate": lambda _self, _base, _source_id: candidate})()
        controller._machine_prs = lambda _main, _repository, _sources: {"demo": [MachinePRAuthority(41, "demo", 99, "c" * 40)]}
        reads = 0
        original = client.pr

        def read_pr(_repository, _number):
            nonlocal reads
            reads += 1
            if reads == 4:
                client.pr = replace(original, head_oid="e" * 40)
            return client.pr

        client.get_pull_request_metadata = read_pr
        with patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", "Demo")):
            with self.assertRaises(controller_module.StaleAuthorityError):
                controller.reconcile_interactive_request(7, client.main)
        self.assertEqual(len(client.refs), 1)
        self.assertEqual(client.dispatches, [])
        self.assertFalse(hasattr(client, "created_pr"))
        self.assertEqual(client.states, [])
        self.assertEqual(len(client.comments), 1)

    def test_reconcile_guard_runs_before_machine_pr_comment_and_close(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller, _ = self._controller_with_source(client, source, None)
        controller.candidate_builder = type("Builder", (), {"machine_candidate": lambda _self, _base, _source_id: ProposalCandidate("d" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)})()
        controller._machine_prs = lambda _main, _repository, _sources: {"demo": [MachinePRAuthority(7, "demo", 99, "d" * 40, False, "bad") ]}
        guard_calls = []

        def stale_guard():
            guard_calls.append(True)
            raise controller_module.StaleAuthorityError("stale manual authority")

        with self.assertRaises(controller_module.StaleAuthorityError):
            controller.reconcile(99, pre_mutation_guard=stale_guard)
        self.assertEqual(len(guard_calls), 1)
        self.assertEqual(client.refs, [])
        self.assertEqual(client.dispatches, [])
        self.assertFalse(hasattr(client, "created_pr"))

    def _main_advance_controller(self, sources, machine):
        client = ReconcileClient()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"))
        controller._accepted_sources = lambda _main=None: tuple(sources)
        controller._machine_prs = lambda _main, _repository, _sources: machine
        return client, controller

    def _manual_main_advance_pr(self, request_class=RequestClass.ADD, number=8, **overrides):
        bodies = {
            RequestClass.ADD: "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nDemo\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\ndemo\n",
            RequestClass.UPDATE: "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nUpdated\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\ndemo\n",
            RequestClass.REMOVE: "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\ncleanup\n",
        }
        body = bodies[request_class]
        request = parse_request_body(request_class, body)
        anchor = RequestAnchor(number, request_class, "U_author", "alice", body_sha256(body), request)
        comment = IssueComment("IC_anchor", 200, anchor.render(), "U_bot", "app[bot]", "Bot", None, None, None, None, False)
        values = {
            "number": number,
            "body": body,
            "author_id": "U_author",
            "author_login": "alice",
            "head_oid": "d" * 40,
            "base_oid": "a" * 40,
            "head_ref": "request",
            "base_ref": "main",
            "head_repository_id": "R_central",
            "head_repository": "swiftstream/skills",
            "base_repository_id": "R_central",
            "base_repository": "swiftstream/skills",
            "last_edited_at": None,
            "includes_created_edit": False,
        }
        values.update(overrides)
        return PullRequestMetadata(**values), comment

    def _main_advance_with_prs(self, prs, comments_by_pr, machine=None):
        class MainAdvanceClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.prs = prs
                self.updated_branches = []

            def list_open_pull_requests(self, _repository):
                return tuple({"number": number} for number in self.prs)

            def get_pull_request_metadata(self, _repository, number):
                return self.prs[number]

            def list_issue_comments(self, _repository, number):
                return tuple(comments_by_pr.get(number, ()))

            def update_pull_request_branch(self, _repository, number, *, expected_head_sha):
                self.updated_branches.append((number, expected_head_sha))

        client = MainAdvanceClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda _main, _repository, _sources: machine or {"demo": []}
        return client, controller

    def test_main_advance_owned_machine_pr_uses_manifest_repository_id_and_one_coalesced_wake(self):
        source = c02.SourceDeclaration("real", "Owner/Repo", 123, "refs/heads/main", "skills", ("real",), "Real")
        authority = MachinePRAuthority(41, "real", 123, "d" * 40)
        client, controller = self._main_advance_controller((source,), {"real": [authority]})
        result = controller.main_advance()
        self.assertEqual(result, "MAIN_ADVANCE_DISPATCHED:1")
        self.assertEqual(client.dispatches, [
            ("federation-reconcile.yml", "refs/heads/main", {"repository_id": "123"}),
            ("federation-state-finalize.yml", "refs/heads/main", {}),
        ])

    def test_main_advance_multiple_sources_is_deterministic_and_finalizer_is_coalesced(self):
        source_b = c02.SourceDeclaration("b", "Owner/B", 2, "refs/heads/main", "skills", ("b",), "B")
        source_a = c02.SourceDeclaration("a", "Owner/A", 1, "refs/heads/main", "skills", ("a",), "A")
        machine = {"b": [MachinePRAuthority(2, "b", 2, "b" * 40)], "a": [MachinePRAuthority(1, "a", 1, "a" * 40)]}
        client, controller = self._main_advance_controller((source_b, source_a), machine)
        controller.main_advance()
        self.assertEqual([item[2]["repository_id"] for item in client.dispatches[:2]], ["1", "2"])
        self.assertEqual(sum(item[0] == "federation-state-finalize.yml" for item in client.dispatches), 1)

    def test_main_advance_owned_manual_pr_wakes_only_shared_finalizer(self):
        body = "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nDemo\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\ndemo\n"
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(8, RequestClass.ADD, "U_author", "alice", body_sha256(body), request)
        comment = IssueComment("IC_anchor", 200, anchor.render(), "U_bot", "app[bot]", "Bot", None, None, None, None, False)

        class ManualAdvanceClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(8, body, "U_author", "alice", "d" * 40, self.main, "request", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False)
                self.comments = [comment]

            def list_open_pull_requests(self, _repository):
                return ({"number": 8},)

            def get_pull_request_metadata(self, _repository, _number):
                return self.pr

            def list_issue_comments(self, _repository, _number):
                return tuple(self.comments)

        client = ManualAdvanceClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda _main, _repository, _sources: {"demo": []}
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:0")
        self.assertEqual(client.dispatches, [("federation-state-finalize.yml", "refs/heads/main", {})])

    def test_main_advance_valid_central_manual_add_update_remove_each_wakes_one_shared_finalizer(self):
        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(request_class=request_class):
                pr, comment = self._manual_main_advance_pr(request_class)
                client, controller = self._main_advance_with_prs({pr.number: pr}, {pr.number: (comment,)})
                self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:0")
                self.assertEqual(client.dispatches, [("federation-state-finalize.yml", "refs/heads/main", {})])

    def test_main_advance_manual_requires_central_trusted_head_and_exact_head_identity(self):
        cases = (
            {"head_repository_id": "R_fork", "head_repository": "attacker/fork"},
            {"head_ref": "request..invalid"},
            {"head_repository_id": "R_other"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides):
                pr, comment = self._manual_main_advance_pr(**overrides)
                client, controller = self._main_advance_with_prs({pr.number: pr}, {pr.number: (comment,)})
                self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
                self.assertEqual(client.dispatches, [])

    def test_main_advance_manual_invalid_anchor_forms_do_not_wake(self):
        pr, valid_comment = self._manual_main_advance_pr()
        cases = (
            ("malformed", (replace(valid_comment, body=f"{ANCHOR_MARKER}\nnot-json\n"),)),
            ("duplicate", (valid_comment, replace(valid_comment, node_id="IC_anchor_2", database_id=201))),
            ("wrong-app", (replace(valid_comment, author_id="U_other", author_login="other[bot]"),)),
        )
        for label, comments in cases:
            with self.subTest(anchor=label):
                client, controller = self._main_advance_with_prs({pr.number: pr}, {pr.number: comments})
                self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
                self.assertEqual(client.dispatches, [])

    def test_main_advance_machine_pr_stays_under_machine_authority(self):
        machine_pr, _ = self._manual_main_advance_pr(number=41, head_ref="bot/federation/demo", author_id="U_bot", author_login="app[bot]")
        client, controller = self._main_advance_with_prs(
            {machine_pr.number: machine_pr},
            {machine_pr.number: ()},
            {"demo": [MachinePRAuthority(41, "demo", 99, machine_pr.head_oid)]},
        )
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:1")
        self.assertEqual(client.dispatches, [
            ("federation-reconcile.yml", "refs/heads/main", {"repository_id": "99"}),
            ("federation-state-finalize.yml", "refs/heads/main", {}),
        ])

    def test_main_advance_valid_machine_and_manual_work_coalesce_to_one_shared_finalizer_wake(self):
        machine_pr, _ = self._manual_main_advance_pr(number=41, head_ref="bot/federation/demo", author_id="U_bot", author_login="app[bot]")
        manual_pr, manual_comment = self._manual_main_advance_pr(number=8, request_class=RequestClass.UPDATE)
        client, controller = self._main_advance_with_prs(
            {machine_pr.number: machine_pr, manual_pr.number: manual_pr},
            {machine_pr.number: (), manual_pr.number: (manual_comment,)},
            {"demo": [MachinePRAuthority(41, "demo", 99, machine_pr.head_oid)]},
        )
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:1")
        self.assertEqual(sum(item[0] == "federation-state-finalize.yml" for item in client.dispatches), 1)
        self.assertEqual(len(client.dispatches), 2)

    def test_main_advance_stale_base_and_unrelated_prs_remain_no_wake(self):
        stale_pr, stale_comment = self._manual_main_advance_pr(base_oid="b" * 40)
        unrelated_pr, _ = self._manual_main_advance_pr(number=9, head_ref="topic")
        client, controller = self._main_advance_with_prs(
            {stale_pr.number: stale_pr, unrelated_pr.number: unrelated_pr},
            {stale_pr.number: (stale_comment,), unrelated_pr.number: ()},
        )
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.dispatches, [])
        self.assertEqual(client.updated_branches, [])

    def test_main_advance_stale_initial_marker_request_is_cloud_normalized_with_head_cas(self):
        stale_pr, _ = self._manual_main_advance_pr(base_oid="b" * 40)
        client, controller = self._main_advance_with_prs({stale_pr.number: stale_pr}, {stale_pr.number: ()})
        with patch.object(controller_module, "read_request_marker", return_value=RequestClass.ADD) as read_marker, patch.object(controller_module, "validate_existing_request_head") as validate_head:
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:0")
        read_marker.assert_called_once_with(client, "swiftstream/skills", stale_pr.head_oid)
        validate_head.assert_called_once_with(client, "swiftstream/skills", stale_pr, RequestClass.ADD, stale_pr.base_oid)
        self.assertEqual(client.updated_branches, [(stale_pr.number, stale_pr.head_oid)])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_stale_initial_request_ignores_ordinary_non_request_anchor_comment(self):
        stale_pr, _ = self._manual_main_advance_pr(base_oid="b" * 40)
        compatibility_comment = IssueComment(
            "IC_compat",
            201,
            "SwiftStream federation P1 compatibility anchor: C02-20260917-3b7e91c2",
            "U_author",
            "alice",
            "User",
            None,
            None,
            None,
            None,
            False,
        )
        client, controller = self._main_advance_with_prs(
            {stale_pr.number: stale_pr},
            {stale_pr.number: (compatibility_comment,)},
        )
        with patch.object(controller_module, "read_request_marker", return_value=RequestClass.ADD), patch.object(controller_module, "validate_existing_request_head"):
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:0")
        self.assertEqual(client.updated_branches, [(stale_pr.number, stale_pr.head_oid)])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_stale_initial_request_fails_closed_before_update_on_scope_error(self):
        stale_pr, _ = self._manual_main_advance_pr(base_oid="b" * 40)
        client, controller = self._main_advance_with_prs({stale_pr.number: stale_pr}, {stale_pr.number: ()})
        with patch.object(controller_module, "read_request_marker", return_value=RequestClass.ADD), patch.object(controller_module, "validate_existing_request_head", side_effect=R02Error("unsafe stale request")):
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.updated_branches, [])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_unrelated_wrong_app_and_stale_manual_prs_do_not_wake(self):
        body = "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nDemo\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\ndemo\n"
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(8, RequestClass.ADD, "U_author", "alice", body_sha256(body), request)
        comment = IssueComment("IC_anchor", 200, anchor.render(), "U_bot", "app[bot]", "Bot", None, None, None, None, False)

        class InvalidClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.prs = {
                    8: PullRequestMetadata(8, body, "U_author", "alice", "d" * 40, "b" * 40, "request", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False),
                    9: PullRequestMetadata(9, "", "U", "other[bot]", "d" * 40, self.main, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False),
                }
                self.comments_by_pr = {8: (comment,), 9: ()}

            def list_open_pull_requests(self, _repository):
                return ({"number": 8}, {"number": 9})

            def get_pull_request_metadata(self, _repository, number):
                return self.prs[number]

            def list_issue_comments(self, _repository, number):
                return self.comments_by_pr[number]

        client = InvalidClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda _main, _repository, _sources: {"demo": []}
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.dispatches, [])

    def test_main_advance_workflow_has_push_main_static_boundaries(self):
        workflow = (controller_module.Path(__file__).resolve().parents[2] / ".github/workflows/federation-main-advance.yml").read_text()
        self.assertIn("branches: [main]", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("FEDERATION_NO_BYPASS_PROOF_V2", workflow)


if __name__ == "__main__":
    unittest.main()
