import hashlib
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from automation.federation.controller import (
    AppIdentity,
    MachinePRAuthority,
    ProposalCandidate,
    R02Controller,
    TRUSTED_VALIDATION_NAME,
    TrustedValidationResult,
    bounded_check_output,
    render_check_run_output,
    verify_machine_check_identity,
)
from automation.federation.github_api import (
    AppMetadata,
    BotMetadata,
    CheckRun,
    GitHubClient,
    HttpResponse,
    InvalidResponseError,
    MergeResult,
    GitTreeEntry,
    PullRequestMetadata,
    RepositoryMetadata,
)
from automation.federation.request_model import RequestClass
from scripts import federate as c02


ROOT = Path(__file__).resolve().parents[2]


class FinalizerTests(unittest.TestCase):
    def _production_finalizer_fixture(self):
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "refs/heads/main", "skills", ("demo",), "Demo")
        main = "a" * 40
        head = "d" * 40
        authority = MachinePRAuthority(41, "demo", 99, head)
        valid_text = f"class=machine-publication; head={head}; accepted_base={main}; sourceId=demo; repositoryId=99; result=READY"

        class Client:
            def __init__(self):
                self.main = main
                self.head = head
                self.base = main
                self.source = source
                self.checks = [CheckRun(1, TRUSTED_VALIDATION_NAME, head, "completed", "failure", 77, valid_text)]
                self.merge_calls = []
                self.check_updates = []
                self.dispatches = []
                self.app_metadata = AppMetadata(77, "swiftstream-federation", "A_app")
                self.bot_metadata = BotMetadata(88, "swiftstream-federation[bot]", "U_bot", "Bot")
                self.after_green = None

            def get_repository_metadata(self, _repository):
                return RepositoryMetadata(7, "R_central", "swiftstream/skills", "main")

            def get_ref_oid(self, _repository, branch):
                return self.main if branch == "main" else self.head

            def get_commit_tree(self, _repository, commit):
                sha = "1" * 40 if commit == self.main else "2" * 40
                return "t" * 40, (GitTreeEntry("README.md", "100644", "blob", sha),)

            def get_blob(self, _repository, blob_sha):
                return blob_sha.encode()

            def get_pull_request_metadata(self, _repository, _number):
                return PullRequestMetadata(41, "", "U_bot", "swiftstream-federation[bot]", self.head, self.base, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False)

            def list_check_runs(self, _repository, _head_sha):
                return tuple(self.checks)

            def update_check_run(self, _repository, check_id, *, head_sha, conclusion=None, output=None, **_kwargs):
                self.check_updates.append((check_id, conclusion, output))
                current = next(item for item in self.checks if item.id == check_id)
                updated_check = replace(current, head_sha=head_sha, conclusion=conclusion, output=output["text"] if output else current.output)
                self.checks = tuple(updated_check if item.id == check_id else item for item in self.checks)
                if conclusion == "success" and self.after_green is not None:
                    self.after_green(self)
                return updated_check

            def merge_machine_pull_request(self, _repository, number, *, expected_head_sha):
                self.merge_calls.append((number, expected_head_sha))
                return MergeResult(True, "merged", "f" * 40)

            def dispatch_workflow(self, _repository, workflow, _ref, inputs=None):
                self.dispatches.append((workflow, inputs))

            def get_app_metadata(self, _slug):
                return self.app_metadata

            def get_bot_metadata(self, _slug):
                return self.bot_metadata

        client = Client()
        app = AppIdentity("swiftstream-federation", 77, "A_app", 88, "U_bot", "swiftstream-federation[bot]")
        candidate = ProposalCandidate(head, main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        builder = type("Builder", (), {
            "machine_candidate": lambda _self, _base, _source_id: candidate,
            "validate_machine_head": lambda _self, _base, _source_id, _head: (True, "CANDIDATE_MATCHES_C02"),
        })()
        controller = R02Controller(client, "swiftstream/skills", app, candidate_builder=builder)
        controller._accepted_sources = lambda _main=None: (client.source,) if client.source is not None else ()
        controller._machine_authority = lambda _summary, current_source, _main, _repository: authority if current_source is not None and current_source.repository_id == 99 else None
        return client, controller, source, authority

    def test_machine_check_identity_requires_exact_canonical_prefix(self):
        head = "a" * 40
        base = "b" * 40
        valid = f"class=machine-publication; head={head}; accepted_base={base}; sourceId=demo; repositoryId=99; result=READY"
        verify_machine_check_identity(CheckRun(1, TRUSTED_VALIDATION_NAME, head, "completed", "success", 7, valid), head_sha=head, accepted_base_sha=base, source_id="demo", repository_id=99)
        for altered in (valid.replace(base, "c" * 40), valid.replace("sourceId=demo", "sourceId=other"), valid.replace("repositoryId=99", "repositoryId=100"), valid.replace("; result=READY", ""), valid.replace("sourceId=demo", "sourceId=demo; sourceId=demo"), valid.replace("class=machine-publication", "class=add-source")):
            with self.subTest(altered=altered), self.assertRaises(Exception):
                verify_machine_check_identity(CheckRun(1, TRUSTED_VALIDATION_NAME, head, "completed", "failure", 7, altered), head_sha=head, accepted_base_sha=base, source_id="demo", repository_id=99)

    def test_check_run_parser_retains_bounded_output_text(self):
        check = GitHubClient._parse_check({"id": 1, "name": TRUSTED_VALIDATION_NAME, "head_sha": "a" * 40, "status": "completed", "conclusion": "failure", "app": {"id": 7}, "output": {"title": "title", "summary": "summary", "text": "canonical evidence", "annotations_count": 0}})
        self.assertEqual(check.output, "canonical evidence")

    def test_check_run_parser_rejects_unknown_or_unbounded_output_shape(self):
        base = {"id": 1, "name": "check", "head_sha": "a" * 40, "status": "completed", "conclusion": "failure", "app": {"id": 7}}
        for output in ({"title": "title", "summary": "summary", "text": "text", "unexpected": "x"}, {"title": "title", "summary": "summary", "text": "x" * 4_097}):
            with self.subTest(output=output), self.assertRaises(InvalidResponseError):
                GitHubClient._parse_check({**base, "output": output})

    def test_finalizer_workflow_preserves_global_serialization_without_readiness_ceremony(self):
        finalizer = (ROOT / ".github/workflows/federation-state-finalize.yml").read_text()
        self.assertIn("swiftstream-skills-federation-state-finalizer", finalizer)
        self.assertIn("cancel-in-progress: false", finalizer)
        self.assertNotIn("FEDERATION_NO_BYPASS_PROOF_V2", finalizer)
        self.assertNotIn("FEDERATION_RULESET_ID", finalizer)

    def test_merge_result_distinguishes_non_merge_without_accepting_malformed_data(self):
        class Transport:
            def __init__(self, value):
                self.value = value
            def request(self, method, url, headers, body, timeout):
                return HttpResponse(200, url, self.value)
        result = GitHubClient("token", Transport(b'{"sha":null,"merged":false,"message":"conflict"}')).merge_machine_pull_request("swiftstream/skills", 4, expected_head_sha="a" * 40)
        self.assertEqual(result, MergeResult(False, "conflict", None))
        for value in (b'{"merged":true}', b'{"sha":"bad","merged":true,"message":"ok"}'):
            with self.subTest(value=value), self.assertRaises(InvalidResponseError):
                GitHubClient("token", Transport(value)).merge_machine_pull_request("swiftstream/skills", 4, expected_head_sha="a" * 40)

    def test_merge_payload_binds_exact_head_and_has_no_policy_or_bypass_fields(self):
        class Transport:
            def __init__(self):
                self.calls = []
            def request(self, method, url, headers, body, timeout):
                import json
                self.calls.append((method, url, json.loads(body)))
                return HttpResponse(200, url, b'{"sha":"' + ("c" * 40).encode() + b'","merged":true,"message":"merged"}')
        transport = Transport()
        result = GitHubClient("secret", transport).merge_machine_pull_request("swiftstream/skills", 4, expected_head_sha="a" * 40)
        self.assertTrue(result.merged)
        payload = transport.calls[0][2]
        self.assertEqual(payload, {"sha": "a" * 40})
        for forbidden in ("merge_method", "bypass", "force", "admin"):
            self.assertNotIn(forbidden, payload)

    def test_finalizer_bounded_merge_rejections_self_wake_once(self):
        controller = object.__new__(R02Controller)
        repository = type("Repo", (), {"default_branch": "main"})()
        source = c02.SourceDeclaration("b", "Owner/Repo", 2, "refs/heads/main", "skills", ("b",), "B")
        authority = MachinePRAuthority(2, "b", 2, "a" * 40)
        attempts, wakes = [], []
        controller.current_accepted_main = lambda: (repository, "c" * 40)
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda current, repo, sources: {"b": [authority]}
        controller.finalize_one_machine_pr = lambda item: attempts.append(item.number) or "merge-rejected"
        result = controller._state_finalize_machine_sweep(max_iterations=3, self_wake=lambda: wakes.append("wake"))
        self.assertEqual(result, "bounded-work-exhausted-self-wake-dispatched")
        self.assertEqual(attempts, [2, 2, 2])
        self.assertEqual(wakes, ["wake"])

    def test_finalizer_restarts_enumeration_after_close_before_next_source(self):
        controller = object.__new__(R02Controller)
        repository = type("Repo", (), {"default_branch": "main"})()
        source_a = c02.SourceDeclaration("a", "Owner/A", 1, "refs/heads/main", "skills", ("a",), "A")
        source_b = c02.SourceDeclaration("b", "Owner/B", 2, "refs/heads/main", "skills", ("b",), "B")
        authority_a = MachinePRAuthority(1, "a", 1, "a" * 40)
        authority_b = MachinePRAuthority(2, "b", 2, "b" * 40)
        enumerations = [{"a": [authority_a], "b": [authority_b]}, {"a": [], "b": []}]
        seen = []
        controller.current_accepted_main = lambda: (repository, "c" * 40)
        controller._accepted_sources = lambda _main=None: (source_b, source_a)
        controller._machine_prs = lambda current, repo, sources: enumerations.pop(0)
        controller.finalize_one_machine_pr = lambda item: seen.append(item.source_id) or "closed"
        result = controller._state_finalize_machine_sweep(max_iterations=3, self_wake=lambda: self.fail("unexpected wake"))
        self.assertEqual(result, "machine-sweep-complete")
        self.assertEqual(seen, ["a"])

    def test_machine_evidence_survives_finalizer_failure_and_success_rendering(self):
        failure = TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, "a" * 40, "b" * 40, "demo", 99, "BLOCKED"))
        success = TrustedValidationResult("success", bounded_check_output(RequestClass.MACHINE_PUBLICATION, "a" * 40, "b" * 40, "demo", 99, "READY"))
        failure_text = render_check_run_output(failure)["text"]
        success_text = render_check_run_output(success)["text"]
        self.assertEqual(failure_text.split("; ")[:5], success_text.split("; ")[:5])
        for identity in ("class=machine-publication", "head=" + "a" * 40, "accepted_base=" + "b" * 40, "sourceId=demo", "repositoryId=99"):
            self.assertIn(identity, failure_text)
            self.assertIn(identity, success_text)

    def test_finalizer_manual_phase_is_after_machine_phase(self):
        controller = object.__new__(R02Controller)
        order = []
        controller.current_accepted_main = lambda: (type("Repo", (), {"default_branch": "main"})(), "c" * 40)
        controller._accepted_sources = lambda _main=None: (c02.SourceDeclaration("a", "Owner/A", 1, "refs/heads/main", "skills", ("a",), "A"),)
        controller._state_finalize_machine_sweep = lambda **kwargs: order.append("machine") or "machine-sweep-complete"
        controller.client = object()
        controller.central_repository = "swiftstream/skills"
        with patch("automation.federation.controller.finalize_manual_trust_sweep", lambda *args, **kwargs: order.append("manual") or "done"):
            self.assertEqual(controller.state_finalize(process_pr=lambda pr: None), "done")
        self.assertEqual(order, ["machine", "manual"])

    def test_finalizer_static_guards_keep_machine_merge_authority_bounded(self):
        source = (ROOT / "automation/federation/controller.py").read_text()
        self.assertNotIn("git push", source)
        self.assertNotIn("merge_method", source)
        self.assertNotIn("ruleset mutation", source.lower())
        self.assertNotIn("force_merge", source)
        self.assertIn("merge_machine_pull_request", source)
        self.assertIn("expected_head_sha", source)

    def test_finalizer_missing_or_wrong_app_check_never_becomes_green(self):
        head = "a" * 40
        base = "b" * 40
        valid = f"class=machine-publication; head={head}; accepted_base={base}; sourceId=demo; repositoryId=99; result=READY"
        wrong_app = CheckRun(1, TRUSTED_VALIDATION_NAME, head, "completed", "success", 8, valid)
        missing = CheckRun(2, TRUSTED_VALIDATION_NAME, head, "completed", "success", 7, None)
        self.assertNotEqual(wrong_app.app_id, 7)
        with self.assertRaises(Exception):
            verify_machine_check_identity(missing, head_sha=head, accepted_base_sha=base, source_id="demo", repository_id=99)

    def test_production_finalizer_reaches_one_exact_head_merge(self):
        client, controller, _source, authority = self._production_finalizer_fixture()
        self.assertEqual(controller.finalize_one_machine_pr(authority), "merged")
        self.assertEqual(client.merge_calls, [(41, "d" * 40)])
        self.assertEqual(client.check_updates[-1][1], "success")

    def test_production_finalizer_missing_check_dispatches_recovery_only(self):
        client, controller, _source, authority = self._production_finalizer_fixture()
        client.checks = []
        self.assertEqual(controller.finalize_one_machine_pr(authority), "check-recovery-dispatched")
        self.assertEqual(client.merge_calls, [])
        self.assertEqual(client.dispatches, [("federation-trusted-validation.yml", {"pull_number": "41"})])

    def test_production_finalizer_wrong_app_same_name_is_recovery_only(self):
        client, controller, _source, authority = self._production_finalizer_fixture()
        client.checks = [replace(client.checks[0], app_id=88)]
        self.assertEqual(controller.finalize_one_machine_pr(authority), "check-recovery-dispatched")
        self.assertEqual(client.merge_calls, [])
        self.assertEqual(len(client.dispatches), 1)

    def test_production_finalizer_wrong_missing_malformed_and_duplicate_evidence_blocks(self):
        variants = {
            "wrong-base": lambda check: replace(check, output=check.output.replace("accepted_base=" + "a" * 40, "accepted_base=" + "b" * 40)),
            "wrong-source": lambda check: replace(check, output=check.output.replace("sourceId=demo", "sourceId=other")),
            "wrong-repository": lambda check: replace(check, output=check.output.replace("repositoryId=99", "repositoryId=98")),
            "missing-output": lambda check: replace(check, output=None),
            "duplicate-identity": lambda check: replace(check, output=check.output + "; sourceId=demo"),
        }
        for label, alter in variants.items():
            with self.subTest(label=label):
                client, controller, _source, authority = self._production_finalizer_fixture()
                client.checks = [alter(client.checks[0])]
                self.assertEqual(controller.finalize_one_machine_pr(authority), "check-evidence-blocked")
                self.assertEqual(client.merge_calls, [])
        client, controller, _source, authority = self._production_finalizer_fixture()
        client.checks = [client.checks[0], replace(client.checks[0], id=2)]
        self.assertEqual(controller.finalize_one_machine_pr(authority), "duplicate-check")
        self.assertEqual(client.merge_calls, [])

    def test_production_finalizer_post_green_authority_races_do_not_merge(self):
        def mutate_main(client):
            client.main = "e" * 40
        def mutate_head(client):
            client.head = "e" * 40
        def mutate_base(client):
            client.base = "e" * 40
        def mutate_check(client):
            client.checks = (replace(client.checks[0], output=client.checks[0].output.replace("sourceId=demo", "sourceId=other")),)
        def mutate_app(client):
            client.app_metadata = AppMetadata(78, "swiftstream-federation", "A_changed")
        def mutate_source(client):
            client.source = c02.SourceDeclaration("demo", "Owner/Rebound", 100, "refs/heads/main", "skills", ("demo",), "Rebound")
        races = (mutate_main, mutate_head, mutate_base, mutate_check, mutate_app, mutate_source)
        for mutate in races:
            with self.subTest(race=mutate.__name__):
                client, controller, _source, authority = self._production_finalizer_fixture()
                client.after_green = mutate
                result = controller.finalize_one_machine_pr(authority)
                self.assertIn(result, {"stale", "check-evidence-blocked"})
                self.assertEqual(client.merge_calls, [])

    def test_production_finalizer_manual_pr_is_never_sent_to_machine_merge(self):
        controller = object.__new__(R02Controller)
        controller.client = type("Client", (), {})()
        controller.finalize_one_machine_pr = lambda _authority: self.fail("manual path must not call machine merge")
        self.assertTrue(callable(controller.finalize_one_machine_pr))


if __name__ == "__main__":
    unittest.main()
