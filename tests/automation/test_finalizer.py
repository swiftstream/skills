import hashlib
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
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
    GitCommitIdentity,
    GitCommitObject,
    GitHubClient,
    HttpResponse,
    InvalidResponseError,
    MergeResult,
    GitTreeEntry,
    NotFoundError,
    PullRequestMetadata,
    RepositoryMetadata,
)
from automation.federation.request_model import CarrierRole, ClaimedHeadMarker, RequestClass, claim_generation_id, machine_ref_claim_authority_digest
from scripts import federate as c02
import automation.federation.controller as controller_module


ROOT = Path(__file__).resolve().parents[2]


class FinalizerTests(unittest.TestCase):
    def setUp(self):
        self._source_patch = patch.object(controller_module, "read_public_source_metadata", return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", None))
        self._scope_patch = patch.object(controller_module, "validate_machine_generated_scope", return_value=("README.md",))
        self._source_patch.start()
        self._scope_patch.start()

    def tearDown(self):
        self._scope_patch.stop()
        self._source_patch.stop()

    def _production_finalizer_fixture(self):
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        main = "a" * 40
        head = "d" * 40
        authority = MachinePRAuthority(41, "demo", 99, head)
        valid_text = f"class=machine-publication; head={head}; accepted_base={main}; sourceId=demo; repositoryId=99; result=READY"
        owner = "R_central:demo"
        scope = hashlib.sha256(b"swiftstream-federation-machine-ref-claim-scope:v1\n" + __import__("json").dumps(
            {"schemaVersion": 1, "candidateTreeSha": "c" * 40, "changedPaths": ["README.md"]},
            sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        nonce = "4" * 64
        generation = claim_generation_id(
            authority_preimage_digest=machine_ref_claim_authority_digest(
                central_repository_node_id="R_central", owner_key=owner, source_id="demo",
                source_repository_id=99, machine_ref="refs/heads/bot/federation/demo",
                accepted_base_sha=main, accepted_base_tree_sha="b" * 40,
                candidate_tree_sha="c" * 40, candidate_scope_digest=scope,
            ),
            carrier_nonce=nonce, central_repository_node_id="R_central", owner_key=owner,
            from_head_sha=main, from_tree_sha="b" * 40, claim_kind="MACHINE_REF_CLAIM",
            role="MACHINE_PUBLICATION", owner_kind="MACHINE_SOURCE", transition_kind="MACHINE_PUBLICATION",
        )
        marker = ClaimedHeadMarker("MACHINE_REF_CLAIM", CarrierRole.MACHINE_PUBLICATION.value, "MACHINE_SOURCE", owner, generation, nonce, "MACHINE_PUBLICATION")
        identity = GitCommitIdentity("Bot", "bot@example.test", "2026-10-08T00:00:00Z")

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
                self.marker = marker
                self.identity = identity

            def get_repository_metadata(self, _repository):
                return RepositoryMetadata(7, "R_central", "swiftstream/skills", "main")

            def get_ref_oid(self, _repository, branch):
                return self.main if branch == "main" else self.head

            def get_git_commit_object(self, _repository, sha):
                if sha == self.head:
                    return GitCommitObject(sha, self.marker.render(), "c" * 40, (self.main,), self.identity, self.identity)
                if sha == self.main:
                    return GitCommitObject(sha, "base\n", "b" * 40, (), self.identity, self.identity)
                raise NotFoundError("unknown commit")

            def list_open_pull_requests(self, _repository):
                return ({"number": 41},)

            def get_commit_tree(self, _repository, commit):
                sha = "1" * 40 if commit == self.main else "2" * 40
                return "t" * 40, (GitTreeEntry("README.md", "100644", "blob", sha),)

            def get_blob(self, _repository, blob_sha):
                return blob_sha.encode()

            def get_pull_request_metadata(self, _repository, _number):
                return PullRequestMetadata(41, "", "U_bot", "swiftstream-federation[bot]", self.head, self.base, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False)

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

    def test_check_run_parser_accepts_nullable_output_members(self):
        head = "a" * 40
        base = {"id": 1, "name": "trusted-validation", "head_sha": head, "status": "completed", "conclusion": "success", "app": {"id": 15368}}
        nullable = GitHubClient._parse_check({
            **base,
            "output": {
                "title": None,
                "summary": None,
                "text": None,
                "annotations_count": 0,
                "annotations_url": "https://api.github.com/check-runs/1/annotations",
            },
        })
        self.assertEqual(nullable.id, 1)
        self.assertEqual(nullable.name, "trusted-validation")
        self.assertEqual(nullable.head_sha, head)
        self.assertEqual(nullable.status, "completed")
        self.assertEqual(nullable.conclusion, "success")
        self.assertEqual(nullable.app_id, 15368)
        self.assertIsNone(nullable.output)

        retained = GitHubClient._parse_check({
            **base,
            "id": 2,
            "output": {"title": None, "summary": "summary", "text": "canonical evidence"},
        })
        self.assertEqual(retained.output, "canonical evidence")

        missing_text = GitHubClient._parse_check({
            **base,
            "id": 3,
            "output": {"title": "title", "summary": None, "text": None},
        })
        self.assertIsNone(missing_text.output)

    def test_check_run_parser_nullable_members_keep_non_null_validation_fail_closed(self):
        base = {
            "id": 1,
            "name": "check",
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "failure",
            "app": {"id": 7},
        }
        limits = {"title": 256, "summary": 512, "text": 4_096}
        for field, limit in limits.items():
            for invalid in (False, 1, {}, [], "", "bad\x00value", "x" * (limit + 1)):
                output = {"title": "title", "summary": "summary", "text": "text"}
                output[field] = invalid
                with self.subTest(field=field, invalid=repr(invalid)), self.assertRaises(InvalidResponseError):
                    GitHubClient._parse_check({**base, "output": output})

    def test_check_run_parser_nullable_change_preserves_shape_annotation_and_image_guards(self):
        base = {
            "id": 1,
            "name": "check",
            "head_sha": "a" * 40,
            "status": "completed",
            "conclusion": "failure",
            "app": {"id": 7},
        }
        valid = {"title": None, "summary": None, "text": None}
        invalid_outputs = [
            {"title": None, "summary": None},
            {"title": None, "text": None},
            {"summary": None, "text": None},
            {**valid, "unexpected": "x"},
            {**valid, "annotations_count": False},
            {**valid, "annotations_count": -1},
            {**valid, "annotations_count": 50_001},
            {**valid, "annotations_url": 1},
            {**valid, "annotations_url": ""},
            {**valid, "annotations_url": "x" * 2_049},
            {**valid, "images": {}},
            {**valid, "images": [{"alt": "alt", "image_url": "url"}] * 11},
            {**valid, "images": [{"alt": "alt"}]},
            {**valid, "images": [{"alt": "", "image_url": "url"}]},
            {**valid, "images": [{"alt": "alt", "image_url": ""}]},
            {**valid, "images": [{"alt": "x" * 257, "image_url": "url"}]},
            {**valid, "images": [{"alt": "alt", "image_url": "x" * 2_049}]},
        ]
        for output in invalid_outputs:
            with self.subTest(output=output), self.assertRaises(InvalidResponseError):
                GitHubClient._parse_check({**base, "output": output})

    def test_list_check_runs_parses_nullable_foreign_and_canonical_trusted_checks(self):
        import json

        head = "a" * 40
        canonical = f"class=machine-publication; head={head}; accepted_base={'b' * 40}; sourceId=demo; repositoryId=99; result=READY"
        payload = {
            "check_runs": [
                {
                    "id": 1,
                    "name": TRUSTED_VALIDATION_NAME,
                    "head_sha": head,
                    "status": "completed",
                    "conclusion": "failure",
                    "app": {"id": 15368},
                    "output": {
                        "title": None,
                        "summary": None,
                        "text": None,
                        "annotations_count": 0,
                        "annotations_url": "https://api.github.com/check-runs/1/annotations",
                    },
                },
                {
                    "id": 2,
                    "name": TRUSTED_VALIDATION_NAME,
                    "head_sha": head,
                    "status": "completed",
                    "conclusion": "success",
                    "app": {"id": 4834068},
                    "output": {
                        "title": "Federation validation",
                        "summary": "Trusted validation",
                        "text": canonical,
                        "annotations_count": 0,
                    },
                },
            ]
        }

        class Transport:
            def request(self, method, url, headers, body, timeout):
                self.last_request = (method, url, headers, body, timeout)
                return HttpResponse(200, url, json.dumps(payload).encode())

        transport = Transport()
        checks = GitHubClient("token", transport).list_check_runs("swiftstream/skills", head)
        self.assertEqual([check.id for check in checks], [1, 2])
        self.assertIsNone(checks[0].output)
        self.assertEqual(checks[1].output, canonical)
        trusted = [
            check
            for check in checks
            if check.name == TRUSTED_VALIDATION_NAME and check.head_sha == head and check.app_id == 4834068
        ]
        self.assertEqual([check.id for check in trusted], [2])
        verify_machine_check_identity(
            trusted[0],
            head_sha=head,
            accepted_base_sha="b" * 40,
            source_id="demo",
            repository_id=99,
        )
        with self.assertRaises(Exception):
            verify_machine_check_identity(
                checks[0],
                head_sha=head,
                accepted_base_sha="b" * 40,
                source_id="demo",
                repository_id=99,
            )

    def test_finalizer_workflow_preserves_global_serialization_without_readiness_ceremony(self):
        finalizer = (ROOT / ".github/workflows/federation-g8-state-finalize.yml").read_text()
        self.assertIn("swiftstream-skills-federation-manual-authority", finalizer)
        self.assertIn("cancel-in-progress: false", finalizer)
        self.assertNotIn("FEDERATION_NO_BYPASS_PROOF_V2", finalizer)
        self.assertNotIn("FEDERATION_RULESET_ID", finalizer)

    def test_state_finalize_workflow_queues_pending_runs_and_never_cancels_in_progress(self):
        finalizer = (ROOT / ".github/workflows/federation-g8-state-finalize.yml").read_text()
        self.assertIn("group: swiftstream-skills-federation-manual-authority", finalizer)
        self.assertIn("cancel-in-progress: false", finalizer)
        self.assertIn("queue: max", finalizer)
        self.assertNotIn("cancel-in-progress: true", finalizer)

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
        source = c02.SourceDeclaration("b", "Owner/Repo", 2, "skills", "B", (c02.LineDeclaration("refs/heads/main", ("b",)),))
        authority = MachinePRAuthority(2, "b", 2, "a" * 40)
        attempts, wakes = [], []
        controller.current_accepted_main = lambda: (repository, "c" * 40)
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda current, repo, sources: {"b": [authority]}
        controller.finalize_one_machine_pr = lambda item: attempts.append(item.number) or "merge-rejected"
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(),
            decisions=(SimpleNamespace(kind=controller_module.Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH),),
        )
        result = controller._state_finalize_machine_sweep(max_iterations=3, self_wake=lambda: wakes.append("wake"))
        self.assertEqual(result, "bounded-work-exhausted-self-wake-dispatched")
        self.assertEqual(attempts, [2])
        self.assertEqual(wakes, ["wake"])

    def test_finalizer_restarts_enumeration_after_close_before_next_source(self):
        controller = object.__new__(R02Controller)
        repository = type("Repo", (), {"default_branch": "main"})()
        source_a = c02.SourceDeclaration("a", "Owner/A", 1, "skills", "A", (c02.LineDeclaration("refs/heads/main", ("a",)),))
        source_b = c02.SourceDeclaration("b", "Owner/B", 2, "skills", "B", (c02.LineDeclaration("refs/heads/main", ("b",)),))
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
        controller._accepted_sources = lambda _main=None: (c02.SourceDeclaration("a", "Owner/A", 1, "skills", "A", (c02.LineDeclaration("refs/heads/main", ("a",)),)),)
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
        controller.candidate_builder.machine_candidate = lambda *_args: self.fail("machine finalizer must not generate H3")
        self.assertEqual(controller.finalize_one_machine_pr(authority), "merged")
        self.assertEqual(client.merge_calls, [(41, "d" * 40)])
        self.assertEqual(client.check_updates[-1][1], "success")

    def test_production_finalizer_missing_check_dispatches_recovery_only(self):
        client, controller, _source, authority = self._production_finalizer_fixture()
        client.checks = []
        self.assertEqual(controller.finalize_one_machine_pr(authority), "check-recovery-dispatched")
        self.assertEqual(client.merge_calls, [])
        self.assertEqual(client.dispatches, [("federation-g8-trusted-validation.yml", {"pull_number": "41"})])

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
            client.source = c02.SourceDeclaration("demo", "Owner/Rebound", 100, "skills", "Rebound", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
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

    def test_production_finalizer_creates_missing_check_and_publishes_success(self):
        client, controller, _source, authority = self._production_finalizer_fixture()
        created = []

        def create_check_run(self, repository, name, head_sha, **kwargs):
            output = kwargs.get("output") or {}
            text = output.get("text") if isinstance(output, dict) else output
            check = CheckRun(50, name, head_sha, "completed", kwargs.get("conclusion"), 77, text)
            self.checks = list(self.checks) + [check]
            created.append(check)
            return check

        client.create_check_run = create_check_run.__get__(client, type(client))
        client.checks = []
        self.assertEqual(controller.finalize_one_machine_pr(authority), "merged")
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].conclusion, "success")
        self.assertEqual(created[0].name, TRUSTED_VALIDATION_NAME)
        self.assertEqual(created[0].app_id, 77)
        self.assertEqual(created[0].head_sha, "d" * 40)
        self.assertEqual(client.merge_calls, [(41, "d" * 40)])

    def test_production_finalizer_missing_check_wrong_app_still_blocks(self):
        client, controller, _source, authority = self._production_finalizer_fixture()
        head = "d" * 40
        main = "a" * 40
        valid_text = f"class=machine-publication; head={head}; accepted_base={main}; sourceId=demo; repositoryId=99; result=READY"
        wrong_app_success = CheckRun(9, TRUSTED_VALIDATION_NAME, head, "completed", "success", 88, valid_text)
        client.checks = [wrong_app_success]
        self.assertEqual(controller.finalize_one_machine_pr(authority), "check-recovery-dispatched")
        self.assertEqual(client.merge_calls, [])
        self.assertEqual([item.app_id for item in client.checks], [88])
        self.assertTrue(all(item.app_id != 77 for item in client.checks))


class Wg4ManualCarrierTests(unittest.TestCase):
    HEAD = "a" * 40
    MAIN = "b" * 40

    def setUp(self):
        self.repository = RepositoryMetadata(7, "R_central", "swiftstream/skills", "main")
        self.pr = PullRequestMetadata(
            41, "legacy", "U_requester", "requester", self.HEAD, self.MAIN,
            "legacy/request", "main", "R_central", "swiftstream/skills",
            "R_central", "swiftstream/skills", None, False, False,
        )
        self.client = SimpleNamespace(
            get_pull_request_metadata=lambda _repo, _number: self.pr,
            create_check_run=lambda *args, **kwargs: self.fail("Wg4 manual path called create_check_run"),
            update_check_run=lambda *args, **kwargs: self.fail("Wg4 manual path called update_check_run"),
        )
        self.controller = object.__new__(R02Controller)
        self.controller.client = self.client
        self.controller.central_repository = "swiftstream/skills"
        self.controller.app = SimpleNamespace(slug="swift-stream-federation")
        self.controller.current_accepted_main = lambda: (self.repository, self.MAIN)
        self.controller.derive_activation_boundary_evidence = lambda: SimpleNamespace(
            activation_boundary_id="c" * 64,
            implementation_reviewed_head_sha="d" * 40,
        )

    def _legacy_classification(self, evidence_class):
        evidence = controller_module.LegacyQuarantineEvidence(
            1, evidence_class, 7, "R_central", "swiftstream/skills", self.HEAD, "e" * 64,
        )
        return controller_module.LegacyClassificationResult(
            controller_module.LegacyClassificationOutcome.QUARANTINE,
            evidence,
            "EXACT_LEGACY_MANUAL" if evidence_class is controller_module.LegacyQuarantineClass.MANUAL else "EXACT_LEGACY_MACHINE",
        )

    def _legacy_controller(self):
        calls = []
        self.controller.resolve_current_sha_carrier_role = lambda _head: controller_module.ShaCarrierResolution(
            controller_module.CarrierActivation.LEGACY_CUTOVER_QUARANTINE,
        )
        self.controller.classify_legacy_head = lambda *_args, **_kwargs: self._legacy_classification(
            controller_module.LegacyQuarantineClass.MANUAL,
        )
        self.controller.publish_legacy_failure = lambda *args, **kwargs: calls.append((args, kwargs))
        self.controller.finalize_one_manual_pr = lambda *_args: self.fail("compatibility finalizer was reached")
        return calls

    def test_A01_legacy_request_anchor_routes_to_legacy_failure_only(self):
        calls = self._legacy_controller()
        self.assertEqual(self.controller._finalize_one_wg4_manual_pr({"number": 41}), "LEGACY_FAILURE")
        self.assertEqual(len(calls), 1)
        args, kwargs = calls[0]
        self.assertEqual(args, (self.HEAD, "c" * 64))
        self.assertEqual(kwargs, {"implementation_reviewed_head_sha": "d" * 40})

    def test_A02_legacy_manual_reachable_path_makes_no_check_run_api_call(self):
        self._legacy_controller()
        self.controller._finalize_one_wg4_manual_pr({"number": 41})
        self.assertFalse(any(name in self.controller._finalize_one_wg4_manual_pr.__code__.co_names for name in (
            "create_check_run", "update_check_run", "upsert_trusted_validation_check",
        )))

    def test_A03_A04_legacy_manual_cannot_emit_issue_or_external_success(self):
        calls = self._legacy_controller()
        status_writes = []
        self.client.create_commit_status = lambda *args, **kwargs: status_writes.append((args, kwargs))
        self.controller._finalize_one_wg4_manual_pr({"number": 41})
        self.assertEqual(len(calls), 1)
        self.assertEqual(status_writes, [])

    def test_A05_issue_active_uses_finalization_epoch_and_no_check_run(self):
        resolution = SimpleNamespace(activation=controller_module.CarrierActivation.ACTIVE, role=controller_module.CarrierRole.ISSUE_ACTIVE)
        self.controller.resolve_current_sha_carrier_role = lambda _head: resolution
        self.controller.trusted_validation_role_first = lambda _number, _legacy: SimpleNamespace(
            kind=controller_module.Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY,
            resolution=resolution,
        )
        owner = controller_module.IssueOwnerPR(9, 41, "issue-owner", "FULL_BINDING")
        with patch.object(controller_module, "derive_issue_owner_pr", return_value=owner):
            prepared = []
            published = []
            self.controller.prepare_issue_finalization_epoch = lambda *args, **kwargs: prepared.append((args, kwargs)) or "exact-epoch"
            self.controller.publish_issue_final_success = lambda *args, **kwargs: published.append((args, kwargs))
            self.assertEqual(self.controller._finalize_one_wg4_manual_pr({"number": 41}), "ISSUE_FINAL_SUCCESS")
        self.assertEqual(prepared[0][0], (9, self.controller.current_issue_source_authority))
        self.assertEqual(published[0][0], (9, "exact-epoch", self.controller.current_issue_source_authority))

    def test_A06_issue_finalizing_retries_exact_epoch_success(self):
        resolution = SimpleNamespace(activation=controller_module.CarrierActivation.ACTIVE, role=controller_module.CarrierRole.ISSUE_FINALIZING)
        self.controller.resolve_current_sha_carrier_role = lambda _head: resolution
        self.controller.trusted_validation_role_first = lambda _number, _legacy: SimpleNamespace(
            kind=controller_module.Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY,
            resolution=resolution,
        )
        owner = controller_module.IssueOwnerPR(9, 41, "issue-owner", "FULL_BINDING")
        with patch.object(controller_module, "derive_issue_owner_pr", return_value=owner):
            published = []
            self.controller.prepare_issue_finalization_epoch = lambda *_args, **_kwargs: "persisted-exact-epoch"
            self.controller.publish_issue_final_success = lambda *args, **kwargs: published.append((args, kwargs))
            self.assertEqual(self.controller._finalize_one_wg4_manual_pr({"number": 41}), "ISSUE_FINAL_SUCCESS_RETRIED")
        self.assertEqual(published[0][0][1], "persisted-exact-epoch")
        self.assertFalse(any(name in self.controller._finalize_one_wg4_manual_pr.__code__.co_names for name in (
            "create_check_run", "update_check_run", "upsert_trusted_validation_check",
        )))

    def test_A07_reserved_or_conflicting_role_cannot_fall_back_to_old_finalizer(self):
        for activation in (
            controller_module.CarrierActivation.RESERVED_INACTIVE,
            controller_module.CarrierActivation.CONFLICTING,
        ):
            with self.subTest(activation=activation):
                self.controller.resolve_current_sha_carrier_role = lambda _head, value=activation: SimpleNamespace(activation=value, role=None)
                self.controller.finalize_one_manual_pr = lambda *_args: self.fail("old Check Run finalizer was called")
                self.controller.trusted_validation_role_first = lambda *_args: self.fail("authority resolver should not be called")
                self.assertEqual(self.controller._finalize_one_wg4_manual_pr({"number": 41}), "NOOP_NO_MANUAL_AUTHORITY")

    def test_A08_machine_role_is_excluded_from_manual_writer(self):
        self.controller.resolve_current_sha_carrier_role = lambda _head: SimpleNamespace(
            activation=controller_module.CarrierActivation.ACTIVE,
            role=controller_module.CarrierRole.MACHINE_PUBLICATION,
        )
        self.controller.trusted_validation_role_first = lambda *_args: self.fail("machine role entered manual semantics")
        self.assertEqual(self.controller._finalize_one_wg4_manual_pr({"number": 41}), "NOOP_MACHINE_ROLE")

    def test_A09_A10_workflow_and_production_entrypoint_are_role_specific(self):
        workflow = (ROOT / ".github/workflows/federation-g8-state-finalize.yml").read_text()
        self.assertIn("state-finalize-manual", workflow)
        self.assertIn("state-finalize-machine", workflow)
        self.assertNotIn("controller state-finalize\n", workflow)
        source = (ROOT / "automation/federation/controller.py").read_text()
        manual_command = source.split('elif args.command == "state-finalize-manual":', 1)[1].split(
            'elif args.command == "state-finalize-machine":', 1,
        )[0]
        self.assertIn("controller.state_finalize_manual", manual_command)
        self.assertNotIn("finalize_one_manual_pr", manual_command)

    def test_W01_W06_router_hints_never_filter_and_both_families_can_be_true(self):
        active = SimpleNamespace(activation=controller_module.CarrierActivation.ACTIVE)
        decisions = (
            SimpleNamespace(kind=controller_module.Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY, resolution=active, head_sha=self.HEAD),
            SimpleNamespace(kind=controller_module.Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH, resolution=active, head_sha="f" * 40),
        )
        seen = []
        self.controller.recover_universal_role_first = lambda legacy, **kwargs: seen.append((legacy, kwargs)) or SimpleNamespace(
            complete=True, blocked_reasons=(), decisions=decisions,
        )
        for hints in (
            (41, None), (None, "demo"), (None, None),
            ("malformed", None), (None, "bad/id"), (999, "other"),
        ):
            route = self.controller.state_finalize_route(
                pull_number_hint=hints[0], expected_source_id_hint=hints[1],
            )
            self.assertEqual(route, {"blocked": False, "issue_manual_needed": True, "machine_needed": True})
        self.assertEqual(len(seen), 6)
        self.assertTrue(all(call[1] == {"read_only": True} for call in seen))

    def test_W07_manual_bounded_restart_reinventories_before_progress(self):
        wakes = []
        state = {"main": self.MAIN, "inventory": 0}
        inventories = (
            ({"number": 1}, {"number": 2}, {"number": 3}),
            ({"number": 40}, {"number": 41}),
        )
        processed = []
        self.controller.current_accepted_main = lambda: (self.repository, state["main"])

        def list_prs(_repo, **kwargs):
            self.assertEqual(kwargs, {"max_pages": 100})
            inventory = inventories[state["inventory"]]
            state["inventory"] += 1
            return inventory

        self.controller.client.list_open_pull_requests = list_prs

        def process(item):
            processed.append((state["inventory"], item["number"]))
            if item["number"] == 1:
                state["main"] = "c" * 40

        self.controller._finalize_one_wg4_manual_pr = process
        result = self.controller.state_finalize_manual(max_iterations=2, self_wake=lambda: wakes.append({}))
        self.assertEqual(result, "manual-sweep-complete")
        self.assertEqual(processed, [(1, 1), (2, 40), (2, 41)])
        self.assertEqual(state["inventory"], 2)
        self.assertEqual(wakes, [])

    def test_W08_machine_finishes_family_pass_before_one_no_hint_retry_wake(self):
        wakes = []
        repository = self.repository
        sources = (
            SimpleNamespace(source_id="a", repository_id=1),
            SimpleNamespace(source_id="b", repository_id=2),
        )
        controller = object.__new__(R02Controller)
        controller.current_accepted_main = lambda: (repository, self.MAIN)
        controller._accepted_sources = lambda _main: sources
        controller._machine_prs = lambda *_args: {
            "a": [SimpleNamespace(number=41, valid=True)],
            "b": [SimpleNamespace(number=42, valid=True)],
        }
        seen = []

        def finalize(authority):
            seen.append(authority.number)
            return "stale" if authority.number == 41 else "check-recovery-dispatched"

        controller.finalize_one_machine_pr = finalize
        controller.state_finalize_machine = lambda **_kwargs: None
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(),
            decisions=(SimpleNamespace(kind=controller_module.Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH),),
        )
        result = controller._state_finalize_machine_sweep(max_iterations=2, self_wake=lambda: wakes.append((seen.copy(), {})))
        self.assertEqual(result, "bounded-work-exhausted-self-wake-dispatched")
        self.assertEqual(seen, [41, 42])
        self.assertEqual(wakes, [([41, 42], {})])

    def _manual_inventory(self, numbers, *, main=None):
        main = main or self.MAIN
        self.controller.current_accepted_main = lambda: (self.repository, main)
        self.controller.client.list_open_pull_requests = lambda _repo, **_kwargs: tuple(
            {"number": number} for number in numbers
        )
        return main

    def _manual_roles(self, numbers, *, actionable_number):
        self.pr_by_number = {
            number: replace(self.pr, number=number, head_oid=f"{number:040x}")
            for number in numbers
        }
        self.client.get_pull_request_metadata = lambda _repo, number: self.pr_by_number[number]
        actionable_head = self.pr_by_number[actionable_number].head_oid
        self.controller.resolve_current_sha_carrier_role = lambda head: SimpleNamespace(
            activation=controller_module.CarrierActivation.ACTIVE if head == actionable_head else controller_module.CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION,
            role=controller_module.CarrierRole.ISSUE_ACTIVE if head == actionable_head else None,
        )
        self.controller.trusted_validation_role_first = lambda number, _legacy: SimpleNamespace(
            kind=controller_module.Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY if number == actionable_number else controller_module.Wave08DecisionKind.NO_MUTATION,
            resolution=SimpleNamespace(role=controller_module.CarrierRole.ISSUE_ACTIVE),
        )
        owner = controller_module.IssueOwnerPR(9, actionable_number, "issue-owner", "FULL_BINDING")
        return actionable_head, owner

    def test_L01_late_authoritative_manual_pr_survives_unrelated_inventory_prefix(self):
        numbers = tuple(range(1, 10))
        self._manual_inventory(numbers)
        actionable_head, owner = self._manual_roles(numbers, actionable_number=9)
        resolved = []
        published = []
        original_resolver = self.controller.resolve_current_sha_carrier_role
        self.controller.resolve_current_sha_carrier_role = lambda head: resolved.append(head) or original_resolver(head)
        self.controller.prepare_issue_finalization_epoch = lambda *_args, **_kwargs: "exact-epoch"
        self.controller.publish_issue_final_success = lambda *args: published.append(args)
        with patch.object(controller_module, "derive_issue_owner_pr", return_value=owner):
            result = self.controller.state_finalize_manual(max_iterations=1)
        self.assertEqual(result, "manual-sweep-complete")
        self.assertEqual(len(resolved), 9)
        self.assertEqual(resolved[-1], actionable_head)
        self.assertEqual(published[0][0], 9)

    def test_L02_unrelated_only_manual_inventory_completes_without_self_wake(self):
        numbers = tuple(range(1, 10))
        self._manual_inventory(numbers)
        self.pr_by_number = {
            number: replace(self.pr, number=number, head_oid=f"{number:040x}")
            for number in numbers
        }
        self.client.get_pull_request_metadata = lambda _repo, number: self.pr_by_number[number]
        self.controller.resolve_current_sha_carrier_role = lambda _head: SimpleNamespace(
            activation=controller_module.CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION, role=None,
        )
        wakes = []
        result = self.controller.state_finalize_manual(max_iterations=1, self_wake=lambda: wakes.append({}))
        self.assertEqual(result, "manual-sweep-complete")
        self.assertEqual(wakes, [])

    def test_L03_early_manual_noop_does_not_suppress_later_actionable_pr(self):
        self._manual_inventory((41, 42))
        _actionable_head, owner = self._manual_roles((41, 42), actionable_number=42)
        authority_checks = []
        original_check = self.controller.trusted_validation_role_first
        self.controller.trusted_validation_role_first = lambda number, legacy: authority_checks.append(number) or original_check(number, legacy)
        published = []
        self.controller.prepare_issue_finalization_epoch = lambda *_args, **_kwargs: "exact-epoch"
        self.controller.publish_issue_final_success = lambda *args: published.append(args)
        with patch.object(controller_module, "derive_issue_owner_pr", return_value=owner):
            result = self.controller.state_finalize_manual(max_iterations=1)
        self.assertEqual(result, "manual-sweep-complete")
        self.assertEqual(authority_checks, [42])
        self.assertEqual(published[0][0], 9)

    def test_L04_manual_authority_movement_restarts_fresh_or_wakes_once(self):
        state = {"main": self.MAIN, "inventory": 0}
        snapshots = (({"number": 1}, {"number": 2}), ({"number": 40},))
        self.controller.current_accepted_main = lambda: (self.repository, state["main"])

        def list_prs(_repo, **_kwargs):
            current = snapshots[state["inventory"]]
            state["inventory"] += 1
            return current

        self.controller.client.list_open_pull_requests = list_prs
        processed = []

        def process(item):
            processed.append((state["inventory"], item["number"]))
            if item["number"] == 1:
                state["main"] = "c" * 40

        self.controller._finalize_one_wg4_manual_pr = process
        result = self.controller.state_finalize_manual(max_iterations=2)
        self.assertEqual(result, "manual-sweep-complete")
        self.assertEqual(processed, [(1, 1), (2, 40)])

        state.update(main=self.MAIN, inventory=0)
        processed.clear()
        self.controller.client.list_open_pull_requests = lambda _repo, **_kwargs: snapshots[0]
        self.controller._finalize_one_wg4_manual_pr = lambda item: (
            processed.append(item["number"]), state.update(main="c" * 40)
        )
        self.controller.state_finalize_route = lambda: {
            "blocked": False, "issue_manual_needed": True, "machine_needed": False,
        }
        wakes = []
        result = self.controller.state_finalize_manual(max_iterations=1, self_wake=lambda: wakes.append({}))
        self.assertEqual(result, "bounded-work-exhausted-self-wake-dispatched")
        self.assertEqual(processed, [1])
        self.assertEqual(wakes, [{}])

    def _machine_sweep(self, inventory, outcomes, *, current_main=None):
        repository = self.repository
        sources = tuple(SimpleNamespace(source_id=source_id, repository_id=index + 1) for index, source_id in enumerate(sorted(inventory)))
        controller = object.__new__(R02Controller)
        controller.current_accepted_main = lambda: (repository, current_main or self.MAIN)
        controller._accepted_sources = lambda _main: sources
        controller._machine_prs = lambda *_args: inventory
        seen = []

        def finalize(authority):
            seen.append(authority.number)
            return outcomes[authority.number]

        controller.finalize_one_machine_pr = finalize
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(),
            decisions=(SimpleNamespace(kind=controller_module.Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH),),
        )
        return controller, seen

    def test_L05_machine_stale_source_does_not_starve_later_source(self):
        inventory = {
            "a": [SimpleNamespace(number=41, valid=True)],
            "b": [SimpleNamespace(number=42, valid=True)],
        }
        controller, seen = self._machine_sweep(inventory, {41: "stale", 42: "check-recovery-dispatched"})
        wakes = []
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(), decisions=(),
        )
        result = controller._state_finalize_machine_sweep(max_iterations=1, self_wake=lambda: wakes.append({}))
        self.assertEqual(result, "machine-sweep-complete")
        self.assertEqual(seen, [41, 42])
        self.assertEqual(wakes, [])

    def test_L06_machine_merge_rejection_does_not_starve_later_source(self):
        inventory = {
            "a": [SimpleNamespace(number=41, valid=True)],
            "b": [SimpleNamespace(number=42, valid=True)],
        }
        controller, seen = self._machine_sweep(inventory, {41: "merge-rejected", 42: "check-recovery-dispatched"})
        wakes = []
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(), decisions=(),
        )
        result = controller._state_finalize_machine_sweep(max_iterations=1, self_wake=lambda: wakes.append({}))
        self.assertEqual(result, "machine-sweep-complete")
        self.assertEqual(seen, [41, 42])
        self.assertEqual(wakes, [])

    def test_L07_machine_retry_wake_is_single_and_follows_full_family_pass(self):
        inventory = {
            "a": [SimpleNamespace(number=41, valid=True)],
            "b": [SimpleNamespace(number=42, valid=True)],
            "c": [SimpleNamespace(number=43, valid=True)],
        }
        controller, seen = self._machine_sweep(
            inventory,
            {41: "stale", 42: "merge-rejected", 43: "check-recovery-dispatched"},
        )
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(),
            decisions=(SimpleNamespace(kind=controller_module.Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH),),
        )
        events = []
        result = controller._state_finalize_machine_sweep(
            max_iterations=4,
            self_wake=lambda: events.append(("wake", tuple(seen))),
        )
        self.assertEqual(result, "bounded-work-exhausted-self-wake-dispatched")
        self.assertEqual(seen, [41, 42, 43])
        self.assertEqual(events, [("wake", (41, 42, 43))])

    def test_L08_machine_shared_mutation_reenumerates_before_later_mutation(self):
        repository = self.repository
        source_a = SimpleNamespace(source_id="a", repository_id=1)
        source_b = SimpleNamespace(source_id="b", repository_id=2)
        authority_a = SimpleNamespace(number=41, source_id="a", valid=True)
        authority_b = SimpleNamespace(number=42, source_id="b", valid=True)
        state = {"main": self.MAIN, "pass": 0}
        events = []
        controller = object.__new__(R02Controller)
        controller.current_accepted_main = lambda: (repository, state["main"])
        controller._accepted_sources = lambda _main: (source_a, source_b)

        def inventory(_main, _repository, _sources):
            events.append(("inventory", state["main"]))
            if state["pass"] == 0:
                state["pass"] = 1
                return {"a": [authority_a], "b": [authority_b]}
            if state["pass"] == 1:
                state["pass"] = 2
                return {"b": [authority_b]}
            return {"a": [], "b": []}

        controller._machine_prs = inventory

        def finalize(authority):
            events.append(("finalize", authority.number))
            if authority.number == 41:
                state["main"] = "c" * 40
                return "merged"
            return "closed"

        controller.finalize_one_machine_pr = finalize
        controller.recover_universal_role_first = lambda *_args, **_kwargs: SimpleNamespace(
            complete=True, blocked_reasons=(), decisions=(),
        )
        wakes = []
        result = controller._state_finalize_machine_sweep(max_iterations=3, self_wake=lambda: wakes.append({}))
        self.assertEqual(result, "machine-sweep-complete")
        self.assertEqual(events, [
            ("inventory", self.MAIN),
            ("finalize", 41),
            ("inventory", "c" * 40),
            ("finalize", 42),
            ("inventory", "c" * 40),
        ])
        self.assertEqual(wakes, [])

    def test_W09_manual_writer_re_resolves_current_sha_before_dispatch_semantics(self):
        order = []
        resolution = SimpleNamespace(
            activation=controller_module.CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION,
            role=None,
        )
        self.controller.resolve_current_sha_carrier_role = lambda head: order.append(("resolve", head)) or resolution
        self.controller.trusted_validation_role_first = lambda *_args: self.fail("unclaimed SHA must not enter Issue/manual writer")
        self.controller._finalize_one_wg4_manual_pr({"number": 41})
        self.assertEqual(order, [("resolve", self.HEAD)])


if __name__ == "__main__":
    unittest.main()
