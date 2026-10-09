import ast
import importlib
import json
import re
import unittest
from dataclasses import replace
from pathlib import Path

from automation.federation.controller import R02Error

CORE_TESTS = importlib.import_module("tests.automation.test_controller_core")
RECONCILE_TESTS = importlib.import_module("tests.automation.test_reconcile")
FINALIZER_TESTS = importlib.import_module("tests.automation.test_finalizer")


ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "automation/federation/controller.py"
REQUEST_MODEL = ROOT / "automation/federation/request_model.py"
GITHUB_API = ROOT / "automation/federation/github_api.py"


class Wave11RuntimeStaticProofTests(unittest.TestCase):
    def test_C01_existing_machine_ref_response_lost_resumes_persisted_H(self):
        fixture = RECONCILE_TESTS.ReconcileTests()
        fixture.setUp()
        try:
            client = RECONCILE_TESTS.ReconcileClient()
            source = RECONCILE_TESTS.c02.SourceDeclaration(
                "demo", "Owner/Repo", 99, "skills", "Demo",
                (RECONCILE_TESTS.c02.LineDeclaration("refs/heads/main", ("demo",)),),
            )
            old = fixture._candidate(client, source, "c" * 40, ("README.md",), nonce="1" * 64)
            candidate = fixture._candidate(client, source, "d" * 40, ("README.md",), nonce="2" * 64)
            client.ref_values["bot/federation/demo"] = old.commit_sha
            client.pull_requests[41] = RECONCILE_TESTS.PullRequestMetadata(
                41, "PR_node", "U", "app[bot]", old.commit_sha, client.main,
                "bot/federation/demo", "main", "R_central", "swiftstream/skills",
                "R_central", "swiftstream/skills", None, False, False,
            )

            class LostExistingRefResponse(RECONCILE_TESTS.ReconcileClient):
                def __init__(self):
                    super().__init__()
                    self.main = client.main
                    self.ref_values = dict(client.ref_values)
                    self.commit_objects = dict(client.commit_objects)
                    self.pull_requests = dict(client.pull_requests)
                    self.machine_changed_paths = dict(client.machine_changed_paths)
                    self.updates = []

                def get_repository_metadata(self, repository):
                    return client.get_repository_metadata(repository)

                def get_app_metadata(self, slug):
                    return client.get_app_metadata(slug)

                def get_bot_metadata(self, slug):
                    return client.get_bot_metadata(slug)

                def get_git_commit_object(self, repository, sha):
                    return client.get_git_commit_object(repository, sha)

                def list_open_pull_requests(self, repository):
                    return tuple({"number": number} for number in sorted(self.pull_requests))

                def update_refs(self, repository_id, updates):
                    self.updates.extend(updates)
                    super().update_refs(repository_id, updates)
                    if len(self.updates) == 1:
                        raise RECONCILE_TESTS.GitHubAPIError("existing-ref CAS response lost")

            lost_client = LostExistingRefResponse()
            builds = []

            class Builder:
                def machine_candidate(_self, base, source_id):
                    builds.append((base, source_id))
                    return candidate

                def validate_machine_head(_self, _base, _source_id, head):
                    return head == candidate.commit_sha, "MATCHES" if head == candidate.commit_sha else "SUCCESSOR_REQUIRED"

            controller, _ = fixture._controller_with_source(lost_client, source, Builder())
            result = controller.reconcile(99)
            self.assertEqual(result.outcome, "CHANGED")
            self.assertEqual(len(builds), 1)
            self.assertEqual(len(lost_client.updates), 1)
            self.assertEqual(lost_client.updates[0].before_oid, old.commit_sha)
            self.assertEqual(lost_client.updates[0].after_oid, candidate.commit_sha)
            self.assertEqual(lost_client.ref_values["bot/federation/demo"], candidate.commit_sha)
            self.assertEqual(candidate.claimed_head_marker.carrier_nonce, "2" * 64)
        finally:
            fixture.tearDown()

    def test_activation_discovery_and_boundary_are_exact(self):
        fixture = CORE_TESTS.Wave11ActivationBoundaryControllerTests()
        valid = fixture.canonical(fixture.contract())
        positive = fixture.Client(fixture)
        evidence = fixture.controller(positive).derive_activation_boundary_evidence()
        self.assertEqual(evidence.implementation_pr_number, 27)
        self.assertEqual(evidence.implementation_reviewed_head_sha, "d" * 40)
        self.assertEqual([call for call in positive.calls if call[0] == "pr"], [("pr", 27)])

        # D01-D08: valid discovery; every frozen lookup field is checked before
        # the only PR query; bytes and merged tuple are rebound afterward.
        discovery_fields = (
            {"implementationPrNumber": 28},
            {"implementationPrDatabaseId": 999},
            {"implementationPrNodeId": "PR_poison"},
            {"centralRepositoryNodeId": "R_poison"},
        )
        for case_id, changes in zip(("D02", "D03", "D04", "D05"), discovery_fields):
            with self.subTest(case=case_id):
                poisoned = fixture.Client(
                    fixture,
                    discovery_contract=fixture.canonical(fixture.contract(**changes)),
                )
                with self.assertRaises(R02Error):
                    fixture.controller(poisoned).derive_activation_boundary_evidence()
                self.assertFalse(any(call[0] == "pr" for call in poisoned.calls))
        self.assertEqual(valid, fixture.canonical(fixture.contract()))

        different_bytes = fixture.Client(
            fixture,
            merged_contract=fixture.canonical(fixture.contract(contractVersion="correction-13")),
        )
        with self.subTest(case="D06"), self.assertRaises(R02Error):
            fixture.controller(different_bytes).derive_activation_boundary_evidence()

        poisoned_hint = fixture.controller(fixture.Client(fixture))
        poisoned_hint.environ["IMPLEMENTATION_PR_NUMBER"] = "999"
        with self.subTest(case="D07"):
            poisoned_hint.derive_activation_boundary_evidence()
        self.assertEqual([call for call in poisoned_hint.client.calls if call[0] == "pr"], [("pr", 27)])

        merged_tuple = fixture.Client(
            fixture,
            merged_contract=fixture.canonical(fixture.contract(implementationPrNodeId="PR_other")),
        )
        with self.subTest(case="D08"), self.assertRaises(R02Error):
            fixture.controller(merged_tuple).derive_activation_boundary_evidence()

        source = CONTROLLER.read_text(encoding="utf-8")
        method = source.split("    def derive_activation_boundary_evidence(", 1)[1].split(
            "    def resolve_current_sha_carrier_role(", 1,
        )[0]
        self.assertIn('contract_path = ".github/federation/g8-activation-contract.json"', method)
        self.assertIn('get_merged_pull_request_metadata(self.central_repository, 27)', method)
        self.assertIn("merged_contract_bytes != discovery_bytes", method)
        self.assertIn('repository.default_branch != "main"', method)
        self.assertIn('merged_pr.head_ref != "g8/issue-first-federation-implementation"', method)
        self.assertIn('merged_pr.base_ref != "main"', method)
        self.assertIn('merged_pr.merged is not True', method)
        self.assertIn('merged_pr.state != "CLOSED"', method)
        self.assertIn('or merged_pr.is_draft is not False', method)
        self.assertIn('len(paths) != 14', method)
        self.assertNotIn("cutoverId", method)
        self.assertNotIn("os.environ", method)
        self.assertNotIn("IMPLEMENTATION_PR_NUMBER", method)

    def test_merged_pr_head_topology_cases_H01_to_H07(self):
        fixture = CORE_TESTS.Wave11ActivationBoundaryControllerTests()
        valid_pr = fixture.Client(fixture).pr
        positive = fixture.controller(fixture.Client(fixture)).derive_activation_boundary_evidence()
        self.assertEqual(positive.implementation_reviewed_head_sha, valid_pr.head_oid)

        bad_records = (
            ("H02", {"head_repository_node_id": "R_fork"}),
            ("H03", {"head_repository_full_name": "fork/skills"}),
            ("H04", {"head_ref": "other"}),
            ("H05", {"base_repository_node_id": "R_other"}),
            ("H06a", {"is_draft": True}),
            ("H06b", {"state": "OPEN"}),
        )
        for case_id, changes in bad_records:
            with self.subTest(case=case_id):
                client = fixture.Client(fixture, pr=replace(valid_pr, **changes))
                with self.assertRaises(R02Error):
                    fixture.controller(client).derive_activation_boundary_evidence()

        client = fixture.Client(fixture)
        controller = fixture.controller(client)
        controller.environ["IMPLEMENTATION_REVIEWED_HEAD_SHA"] = "9" * 40
        evidence = controller.derive_activation_boundary_evidence()
        with self.subTest(case="H07"):
            self.assertEqual(evidence.implementation_reviewed_head_sha, valid_pr.head_oid)

    def test_machine_authority_v2_digest_and_cas_source_proof(self):
        model = REQUEST_MODEL.read_text(encoding="utf-8")
        tree = ast.parse(model)
        function = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "machine_ref_claim_authority_digest"
        )
        parameters = [arg.arg for arg in function.args.args + function.args.kwonlyargs]
        self.assertEqual(parameters, [
            "central_repository_node_id", "owner_key", "source_id", "source_repository_id",
            "machine_ref", "accepted_base_sha", "accepted_base_tree_sha", "candidate_tree_sha",
            "candidate_scope_digest",
        ])
        source = ast.get_source_segment(model, function)
        self.assertIn('MACHINE_REF_CLAIM_AUTHORITY_PREFIX + _canonical_json(value)', source)
        self.assertIn('"schemaVersion": 2', source)
        self.assertIn('"machineRef": expected_ref', source)
        self.assertNotIn("currentMachineRefOid", source)
        self.assertNotIn("beforeOid", source)
        self.assertEqual(model.count('MACHINE_REF_CLAIM_AUTHORITY_PREFIX = "swiftstream-federation-machine-ref-claim-authority:v2\\n"'), 1)

        controller = CONTROLLER.read_text(encoding="utf-8")
        builder = controller.split("    def machine_candidate(", 1)[1].split("    def validate_machine_head(", 1)[0]
        resolver = controller.split("    def _resolve_machine_v2_carrier(", 1)[1].split("    def ", 1)[0]
        reconcile = controller.split("    def reconcile(", 1)[1].split("    def ", 1)[0]
        self.assertIn("machine_ref_claim_authority_digest(", builder)
        self.assertIn("machine_ref_claim_authority_digest(", resolver)
        self.assertIn("current_ref = self.client.get_ref_oid(", resolver)
        self.assertIn("if current_ref == head_sha", resolver)
        self.assertIn("before_oid = self.client.get_ref_oid(", reconcile)
        self.assertIn("RefUpdate(machine_ref, before_oid, candidate.commit_sha", reconcile)
        self.assertIn("self.client.get_ref_oid(self.central_repository, branch)", reconcile)
        self.assertIn("outcome = \"AMBIGUOUS\"", reconcile)
        self.assertIn("if observed_ref == candidate.commit_sha", reconcile)
        self.assertIn("retry_ref != before_oid", reconcile)
        self.assertIn("retry_repository != repository", reconcile)
        self.assertIn("retry_main != current_main", reconcile)
        self.assertIn("retry_sources != (source,)", reconcile)
        self.assertIn("retry_app != initial_app", reconcile)
        self.assertIn("retry_prs != initial_machine_prs", reconcile)
        self.assertIn("MACHINE_AMBIGUOUS_RETRY_EXHAUSTED", reconcile)
        self.assertIn("branch = _machine_branch(source.source_id)", reconcile)
        self.assertIn('machine_ref = f"refs/heads/{branch}"', reconcile)
        self.assertNotRegex(controller, r"machine_ref_claim_authority_digest\([\s\S]{0,500}currentMachineRefOid")
        self.assertNotIn("get_ref_history", controller)
        self.assertNotIn("get_reflog", controller)
        self.assertNotIn("MACHINE_BEFORE_OID", controller)
        self.assertNotIn("FEDERATION_BEFORE_OID", controller)

        api = GITHUB_API.read_text(encoding="utf-8")
        ref_update = api.split("class RefUpdate:", 1)[1].split("\n@dataclass", 1)[0]
        self.assertIn("force requires concrete nonzero beforeOid and afterOid", ref_update)
        self.assertIn('"beforeOid": self.before_oid', ref_update)
        self.assertIn("force=before_oid != ZERO_OID", reconcile)

    def test_role_resolver_preserves_reserved_order_and_machine_restart(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        wrapper = controller.split("    def resolve_current_sha_carrier_role(", 1)[1].split(
            "    def _resolve_machine_v2_carrier(", 1,
        )[0]
        resolver = controller.split("def resolve_sha_carrier_role(", 1)[1].split(
            "def _resolve_issue_cancellation_carrier(", 1,
        )[0]
        self.assertLess(resolver.index("marker_count == 0"), resolver.index("# The whole literal namespace is reserved"))
        self.assertIn("if marker.claim_kind == \"MACHINE_REF_CLAIM\":", wrapper)
        self.assertIn("return self._resolve_machine_v2_carrier", wrapper)
        self.assertIn("return _conflicting_sha_carrier()", wrapper)
        self.assertNotIn("MACHINE_REF_CLAIM", resolver)
        generic_issue_call = wrapper.split("return resolve_sha_carrier_role(", 1)[1].split(")", 1)[0]
        self.assertIn("LegacyEvidenceDisposition.CONFLICTING", generic_issue_call)
        self.assertNotIn("pull_number_hint", wrapper)
        self.assertIn("current_ref = self.client.get_ref_oid(", controller)
        self.assertIn("current_ref == head_sha", controller)
        # P01-P06 execute the real distinct-B -> H restart fixture and its
        # ZERO, third-value, v1 rejection, marker and reserved-role cases.
        fixture = CORE_TESTS.Wave11CanonicalShaResolverTests()
        for method_name in (
            "test_real_b_to_h_lifecycle_survives_full_controller_restart",
            "test_zero_to_h_restart_and_third_value_stay_reserved_or_conflicting",
            "test_old_v1_generation_is_not_accepted_by_fallback",
            "test_reserved_marker_never_enters_legacy_or_unclaimed_fallback",
        ):
            with self.subTest(case=method_name):
                getattr(fixture, method_name)()

    def test_frozen_cas_wg4_and_preimage_matrices_have_exact_case_inventory(self):
        reconcile = (ROOT / "tests/automation/test_reconcile.py").read_text(encoding="utf-8")
        finalizer = (ROOT / "tests/automation/test_finalizer.py").read_text(encoding="utf-8")
        core = (ROOT / "tests/automation/test_controller_core.py").read_text(encoding="utf-8")
        dedicated = Path(__file__).read_text(encoding="utf-8")
        mappings = {
            "C01-C09": (9, reconcile + dedicated, (
                "test_C01_existing_machine_ref_response_lost_resumes_persisted_H",
                "test_ambiguous_unchanged_ref_retries_exact_same_cas_once",
                "test_ambiguous_retry_exhaustion_does_not_create_h3_or_new_nonce",
                "test_third_ref_makes_old_h_lose_and_successor_uses_fresh_nonce_and_head",
                "test_response_lost_after_persisted_h_and_full_restart_reuses_same_generation",
                "test_cas_loss_recomputes_with_fresh_main_and_before_oid",
                "test_reported_cas_success_with_third_ref_is_contradiction",
                "test_ambiguous_unchanged_ref_with_changed_main_stops_without_retry",
                "test_persisted_h_with_changed_accepted_main_is_not_replaced",
            )),
            "W01-W09": (9, finalizer, (
                *("test_W01_W06_router_hints_never_filter_and_both_families_can_be_true" for _ in range(6)),
                "test_W07_manual_bounded_restart_reinventories_before_progress",
                "test_W08_machine_finishes_family_pass_before_one_no_hint_retry_wake",
                "test_W09_manual_writer_re_resolves_current_sha_before_dispatch_semantics",
            )),
            "P01-P14": (14, core + reconcile + dedicated, (
                "test_real_b_to_h_lifecycle_survives_full_controller_restart",
                "test_zero_to_h_restart_and_third_value_stay_reserved_or_conflicting",
                "test_old_v1_generation_is_not_accepted_by_fallback",
                "test_machine_v2_requires_exact_fresh_ref_and_pr_authority",
                "test_machine_v2_reserved_and_identity_generation_failures",
                "test_C01_existing_machine_ref_response_lost_resumes_persisted_H",
                "test_ambiguous_unchanged_ref_retries_exact_same_cas_once",
                "test_ambiguous_retry_exhaustion_does_not_create_h3_or_new_nonce",
                "test_third_ref_makes_old_h_lose_and_successor_uses_fresh_nonce_and_head",
                "test_cas_loss_recomputes_with_fresh_main_and_before_oid",
                "test_legacy_machine_h_migrates_to_fresh_h2_with_exact_before_cas",
                "test_legacy_machine_h_migrates_to_fresh_h2_with_exact_before_cas",
                "test_no_pr_A_B_results_are_exact_idempotent_and_do_not_mutate_refs",
                "test_reserved_marker_never_enters_legacy_or_unclaimed_fallback",
            )),
        }
        for label, (expected, corpus, names) in mappings.items():
            with self.subTest(matrix=label):
                self.assertEqual(len(names), expected)
                for name in names:
                    self.assertIn(f"def {name}(", corpus, name)
                if label == "W01-W09":
                    for name in names[6:8]:
                        case = FINALIZER_TESTS.Wg4ManualCarrierTests(name)
                        result = unittest.TestResult()
                        case.run(result)
                        self.assertTrue(result.wasSuccessful(), f"{name}: {result.errors!r} {result.failures!r}")

        liveness_cases = (
            "test_L01_late_authoritative_manual_pr_survives_unrelated_inventory_prefix",
            "test_L02_unrelated_only_manual_inventory_completes_without_self_wake",
            "test_L03_early_manual_noop_does_not_suppress_later_actionable_pr",
            "test_L04_manual_authority_movement_restarts_fresh_or_wakes_once",
            "test_L05_machine_stale_source_does_not_starve_later_source",
            "test_L06_machine_merge_rejection_does_not_starve_later_source",
            "test_L07_machine_retry_wake_is_single_and_follows_full_family_pass",
            "test_L08_machine_shared_mutation_reenumerates_before_later_mutation",
        )
        finalizer = (ROOT / "tests/automation/test_finalizer.py").read_text(encoding="utf-8")
        for case_id, name in enumerate(liveness_cases, start=1):
            with self.subTest(matrix="L01-L08", case=f"L{case_id:02d}"):
                self.assertIn(f"def {name}(", finalizer)
                case = FINALIZER_TESTS.Wg4ManualCarrierTests(name)
                result = unittest.TestResult()
                case.run(result)
                self.assertTrue(result.wasSuccessful(), f"{name}: {result.errors!r} {result.failures!r}")

        workflow = (ROOT / ".github/workflows/federation-g8-state-finalize.yml").read_text(encoding="utf-8")
        router = workflow.split("  role-router:", 1)[1].split("  issue-manual-finalizer:", 1)[0]
        manual = workflow.split("  issue-manual-finalizer:", 1)[1].split("  machine-finalizer:", 1)[0]
        machine = workflow.split("  machine-finalizer:", 1)[1]
        self.assertIn("permissions:\n      contents: read", router)
        self.assertIn("if: needs.activation-guard.outputs.runtime_state == 'ACTIVE_G8'", router)
        self.assertNotRegex(router, r"permission-[a-z-]+:\s+write")
        self.assertIn("state-finalize-route", router)
        self.assertIn("state-finalize-manual", manual)
        self.assertIn("state-finalize-machine", machine)
        self.assertNotIn("permission-checks:", manual)
        self.assertNotIn("permission-statuses:", machine)
        self.assertIn("issue_manual_needed == 'true'", manual)
        self.assertIn("machine_needed == 'true'", machine)
        self.assertIn("blocked == 'false'", manual)
        self.assertIn("blocked == 'false'", machine)
        self.assertIn("runtime_state == 'ACTIVE_G8'", manual)
        self.assertIn("runtime_state == 'ACTIVE_G8'", machine)

        reconcile_workflow = (ROOT / ".github/workflows/federation-g8-reconcile.yml").read_text(encoding="utf-8")
        self.assertIn("controller universal-recovery", reconcile_workflow)
        self.assertNotIn("controller reconcile\n", reconcile_workflow)
        self.assertNotIn("permission-checks:", reconcile_workflow)
        blocked_job = reconcile_workflow.split("activate-g8-wave10-blocked:", 1)[1]
        self.assertIn("inputs.mode == 'activate-g8'", blocked_job)
        self.assertIn("WAVE10_ACTIVATION_NOT_IMPLEMENTED", blocked_job)
        self.assertNotIn("actions/create-github-app-token", blocked_job)

    def test_wave12_runtime_and_authority_surface_are_absent(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        workflows = "\n".join(
            (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            for name in (
                "federation-g8-issue-intake.yml", "federation-g8-interactive.yml",
                "federation-g8-trusted-validation.yml", "federation-g8-state-finalize.yml",
                "federation-g8-main-advance.yml", "federation-g8-reconcile.yml",
            )
        )
        active_source = controller + workflows
        for forbidden in (
            "ActivationRecoveryWitness", "class ActivationEpoch",
            "create_activation_ref", "update_activation_ref", 'runtime_state = "ACTIVE_G8"',
            "post_activation_catch_up",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, active_source)
        manifest = json.loads((ROOT / ".github/federation/g8-authority-surface.json").read_text())
        self.assertEqual(manifest["schemaVersion"], 2)
        self.assertEqual(len(manifest["paths"]), 14)
        self.assertEqual(manifest["paths"], sorted(set(manifest["paths"]), key=lambda value: value.encode("utf-8")))


if __name__ == "__main__":
    unittest.main()
