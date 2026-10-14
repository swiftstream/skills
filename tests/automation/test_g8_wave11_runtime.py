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
        self.assertEqual(evidence.implementation_pr_number, 28)
        self.assertEqual(evidence.implementation_reviewed_head_sha, "d" * 40)
        self.assertEqual([call for call in positive.calls if call[0] == "pr"], [("pr", 27), ("pr", 28)])

        # D01-D08: valid discovery; every frozen lookup field is checked before
        # both fixed PR reads; bytes and merged tuple are rebound afterward.
        discovery_fields = (
            {"implementationPrNumber": 29},
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
        self.assertEqual([call for call in poisoned_hint.client.calls if call[0] == "pr"], [("pr", 27), ("pr", 28)])

        merged_tuple = fixture.Client(
            fixture,
            merged_contract=fixture.canonical(fixture.contract(implementationPrNodeId="PR_other")),
        )
        with self.subTest(case="D08"), self.assertRaises(R02Error):
            fixture.controller(merged_tuple).derive_activation_boundary_evidence()

        source = CONTROLLER.read_text(encoding="utf-8")
        tree = ast.parse(source)
        controller_class = next(
            node for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "R02Controller"
        )
        function = next(
            node for node in controller_class.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "derive_activation_boundary_evidence"
        )
        method = ast.get_source_segment(source, function)
        self.assertIsNotNone(method)
        self.assertIn('contract_path = ".github/federation/g8-activation-contract.json"', method)
        self.assertIn('G8_PREDECESSOR_IMPLEMENTATION_PR_NUMBER', method)
        self.assertIn('G8_IMPLEMENTATION_PR_NUMBER', method)
        self.assertIn("merged_contract_bytes != discovery_bytes", method)
        self.assertIn('repository.default_branch != "main"', method)
        self.assertIn('predecessor_pr.head_ref != "g8/issue-first-federation-implementation"', method)
        self.assertIn('repair_pr.head_ref != G8_IMPLEMENTATION_HEAD_REF', method)
        self.assertIn('repair_pr.base_oid != G8_PREDECESSOR_MERGED_RESULT_OID', method)
        self.assertIn('predecessor_pr.state != "MERGED"', method)
        self.assertIn('repair_pr.state != "MERGED"', method)
        self.assertIn('repair_merge_metadata.parents != (G8_PREDECESSOR_MERGED_RESULT_OID, repair_pr.head_oid)', method)
        self.assertIn('repair_merge_metadata.tree_sha != repair_head_metadata.tree_sha', method)
        self.assertIn('len(paths) != 14', method)
        self.assertNotIn("cutoverId", method)
        self.assertNotIn("os.environ", method)
        self.assertNotIn('environ.get("IMPLEMENTATION_PR_NUMBER")', method)

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
        controller_tree = ast.parse(controller)
        controller_class = next(
            node for node in controller_tree.body
            if isinstance(node, ast.ClassDef) and node.name == "C02CandidateBuilder"
        )
        methods = {
            node.name: ast.get_source_segment(controller, node)
            for node in controller_class.body
            if isinstance(node, ast.FunctionDef)
        }
        shared_builder = methods["_machine_candidate"]
        ordinary_builder = methods["machine_candidate"]
        claim_builder = methods["machine_claim_candidate"]
        resolver = controller.split("    def _resolve_machine_v2_carrier(", 1)[1].split("    def ", 1)[0]
        reconcile = controller.split("    def reconcile(", 1)[1].split("    def ", 1)[0]
        self.assertIn("machine_ref_claim_authority_digest(", shared_builder)
        self.assertIn("require_claim_generation: bool", shared_builder)
        self.assertIn("claim_generation_id(", shared_builder)
        self.assertIn("self._machine_candidate(", ordinary_builder)
        self.assertIn("require_claim_generation=False", ordinary_builder)
        self.assertIn("self._machine_candidate(", claim_builder)
        self.assertIn("require_claim_generation=True", claim_builder)
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

        reconcile_workflow_path = ROOT / ".github/workflows/federation-g8-reconcile.yml"
        reconcile_workflow_bytes = reconcile_workflow_path.read_bytes()
        self.assertEqual(
            importlib.import_module("hashlib").sha256(reconcile_workflow_bytes).hexdigest(),
            "b7be9b3828b2b432681df95de874860b124c72bbdf474425ca21fa338b00e602",
        )
        reconcile_workflow = reconcile_workflow_path.read_text(encoding="utf-8")
        self.assertEqual(
            [line for line in reconcile_workflow.splitlines() if line and not line[0].isspace()],
            ["name: Federation G8 reconcile", "on:", "permissions:", "concurrency:", "jobs:"],
        )
        self.assertIn("controller universal-recovery", reconcile_workflow)
        self.assertNotIn("controller reconcile\n", reconcile_workflow)
        self.assertNotIn("activate-g8-wave10-blocked:", reconcile_workflow)
        self.assertNotIn("WAVE10_ACTIVATION_NOT_IMPLEMENTED", reconcile_workflow)
        self.assertNotIn("permission-checks:", reconcile_workflow)

        jobs_headers = list(re.finditer(r"(?m)^jobs:[ \t]*$", reconcile_workflow))
        self.assertEqual(len(jobs_headers), 1)
        jobs_source = reconcile_workflow[jobs_headers[0].end():]
        job_headers = list(re.finditer(r"(?m)^  ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*$", jobs_source))
        job_names = [match.group(1) for match in job_headers]
        self.assertEqual(len(job_names), len(set(job_names)))
        self.assertEqual(
            job_names,
            ["activation-guard", "recover", "activation-preflight", "activate-g8"],
        )
        self.assertEqual(
            [line for line in jobs_source.splitlines() if re.match(r"^  \S", line)],
            [
                "  activation-guard:",
                "  recover:",
                "  activation-preflight:",
                "  activate-g8:",
            ],
        )
        job_slices = {}
        for index, header in enumerate(job_headers):
            end = job_headers[index + 1].start() if index + 1 < len(job_headers) else len(jobs_source)
            job_slices[header.group(1)] = jobs_source[header.start():end]
        self.assertIn("activation-preflight", job_slices)
        self.assertIn("activate-g8", job_slices)
        preflight_job = job_slices["activation-preflight"]
        expected_preflight_job = "\n".join(
            (
                '  activation-preflight:',
                '    needs: activation-guard',
                "    if: github.event_name == 'workflow_dispatch' && inputs.mode == 'activate-g8' && github.ref == 'refs/heads/main'",
                '    runs-on: ubuntu-latest',
                '    permissions:',
                '      contents: read',
                '    outputs:',
                '      decision: ${{ steps.parse-preflight.outputs.decision }}',
                '      trusted_sha: ${{ steps.trusted-checkout.outputs.sha }}',
                '    steps:',
                '      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
                '        with:',
                '          ref: refs/heads/main',
                '          persist-credentials: false',
                '          submodules: false',
                '          lfs: false',
                '      - id: trusted-checkout',
                '        name: Bind read-only preflight checkout to HEAD',
                '        run: |',
                '          set -euo pipefail',
                '          trusted_head="$(git rev-parse --verify HEAD^{commit})"',
                '          if [[ ! "$trusted_head" =~ ^[0-9a-f]{40}$ ]]; then',
                '            echo "trusted checkout HEAD is not a lowercase commit SHA" >&2',
                '            exit 1',
                '          fi',
                '          echo "sha=$trusted_head" >> "$GITHUB_OUTPUT"',
                '      - id: preflight-token',
                '        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1',
                '        with:',
                '          client-id: ${{ vars.APP_CLIENT_ID }}',
                '          private-key: ${{ secrets.APP_PRIVATE_KEY }}',
                '          permission-actions: read',
                '          permission-contents: read',
                '          permission-statuses: read',
                '          permission-issues: read',
                '          permission-pull-requests: read',
                '      - id: preflight',
                '        name: Re-read exact admin and activation guard',
                '        env:',
                '          FEDERATION_GITHUB_TOKEN: ${{ steps.preflight-token.outputs.token }}',
                '          FEDERATION_APP_SLUG: ${{ steps.preflight-token.outputs.app-slug }}',
                '          FEDERATION_TRUSTED_CHECKOUT_SHA: ${{ steps.trusted-checkout.outputs.sha }}',
                '          INPUT_MODE: ${{ inputs.mode }}',
                '        run: |',
                '          set -euo pipefail',
                '          PYTHONDONTWRITEBYTECODE=1 python3 -B -m automation.federation.controller activation-preflight > "${RUNNER_TEMP}/g8-activation-preflight.out"',
                '      - id: parse-preflight',
                '        name: Strictly validate activation preflight decision',
                '        run: |',
                '          set -euo pipefail',
                '          python3 - "${RUNNER_TEMP}/g8-activation-preflight.out" "$GITHUB_OUTPUT" <<\'PY\'',
                '          import json',
                '          import pathlib',
                '          import sys',
                '',
                '          def unique_object(pairs):',
                '              result = {}',
                '              for key, value in pairs:',
                '                  if key in result:',
                '                      raise ValueError("duplicate JSON key")',
                '                  result[key] = value',
                '              return result',
                '',
                '          def reject_constant(value):',
                '              raise ValueError("non-standard JSON constant")',
                '',
                '          raw = pathlib.Path(sys.argv[1]).read_bytes()',
                '          if not raw or raw.count(b"\\n") != 1 or not raw.endswith(b"\\n") or b"\\r" in raw:',
                '              raise SystemExit("invalid activation preflight framing")',
                '          try:',
                '              value = json.loads(raw[:-1].decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)',
                '          except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:',
                '              raise SystemExit("invalid activation preflight JSON") from exc',
                '          if type(value) is not dict or set(value) != {"decision"} or type(value["decision"]) is not str:',
                '              raise SystemExit("invalid activation preflight shape")',
                '          decision = value["decision"]',
                '          if decision not in {"READY", "ACTIVE_NOOP", "BLOCKED"}:',
                '              raise SystemExit("unknown activation preflight decision")',
                '          canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\\n")',
                '          if canonical != raw:',
                '              raise SystemExit("non-canonical activation preflight bytes")',
                '          with pathlib.Path(sys.argv[2]).open("a", encoding="utf-8", newline="\\n") as output:',
                '              output.write("decision=" + decision + "\\n")',
                '          PY',
                '',
                ''
            )
        )
        self.assertEqual(preflight_job, expected_preflight_job)
        activate_job = job_slices["activate-g8"]
        expected_activate_job = "\n".join(
            (
                "  activate-g8:",
                "    needs: activation-preflight",
                "    if: github.event_name == 'workflow_dispatch' && inputs.mode == 'activate-g8' && github.ref == 'refs/heads/main' && needs.activation-preflight.outputs.decision == 'READY'",
                "    runs-on: ubuntu-latest",
                "    permissions:",
                "      contents: read",
                "    steps:",
                "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "        with:",
                "          ref: refs/heads/main",
                "          persist-credentials: false",
                "          submodules: false",
                "          lfs: false",
                "      - name: Require the exact preflight checkout",
                "        env:",
                "          PREFLIGHT_SHA: ${{ needs.activation-preflight.outputs.trusted_sha }}",
                "        run: |",
                "          set -euo pipefail",
                "          current=\"$(git rev-parse --verify HEAD^{commit})\"",
                "          if [[ ! \"$current\" =~ ^[0-9a-f]{40}$ || \"$current\" != \"$PREFLIGHT_SHA\" ]]; then",
                "            echo \"trusted main changed after read-only activation preflight\" >&2",
                "            exit 1",
                "          fi",
                "      - id: activation-token",
                "        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1",
                "        with:",
                "          client-id: ${{ vars.APP_CLIENT_ID }}",
                "          private-key: ${{ secrets.APP_PRIVATE_KEY }}",
                "          permission-actions: write",
                "          permission-statuses: write",
                "          permission-contents: write",
                "          permission-issues: write",
                "          permission-pull-requests: write",
                "      - name: Execute exact activate-g8 controller command",
                "        env:",
                "          FEDERATION_GITHUB_TOKEN: ${{ steps.activation-token.outputs.token }}",
                "          FEDERATION_APP_SLUG: ${{ steps.activation-token.outputs.app-slug }}",
                "          FEDERATION_TRUSTED_CHECKOUT_SHA: ${{ needs.activation-preflight.outputs.trusted_sha }}",
                "          INPUT_MODE: ${{ inputs.mode }}",
                "        run: |",
                "          set -euo pipefail",
                "          PYTHONDONTWRITEBYTECODE=1 python3 -B -m automation.federation.controller activate-g8",
                "",
            )
        )
        self.assertEqual(activate_job, expected_activate_job)
        activate_step_headers = re.findall(r"(?m)^      - (.+?)[ \t]*$", activate_job)
        self.assertEqual(
            activate_step_headers,
            [
                "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                "name: Require the exact preflight checkout",
                "id: activation-token",
                "name: Execute exact activate-g8 controller command",
            ],
        )
        activation_token_step_headers = [
            header for header in activate_step_headers if header == "id: activation-token"
        ]
        self.assertEqual(activation_token_step_headers, ["id: activation-token"])
        activation_token_step_index = activate_step_headers.index("id: activation-token")
        post_token_step_headers = activate_step_headers[activation_token_step_index + 1:]
        self.assertEqual(len(post_token_step_headers), 1)
        self.assertEqual(
            post_token_step_headers,
            ["name: Execute exact activate-g8 controller command"],
        )

        def job_step(job, header):
            marker = f"      - {header}\n"
            self.assertEqual(job.count(marker), 1, f"expected one workflow step {header!r}")
            start = job.index(marker)
            after = job[start + len(marker):]
            next_step = re.search(r"(?m)^      - ", after)
            end = len(after) if next_step is None else next_step.start()
            return job[start:start + len(marker) + end]

        def job_level_permissions(job):
            permission_blocks = list(re.finditer(r"(?m)^    permissions:[ \t]*$", job))
            self.assertEqual(len(permission_blocks), 1)
            permission_lines = []
            for line in job[permission_blocks[0].end():].splitlines():
                if not line.strip():
                    continue
                indentation = len(line) - len(line.lstrip(" "))
                if indentation < 6:
                    break
                permission_lines.append(line)
            permission_pairs = []
            for line in permission_lines:
                match = re.fullmatch(
                    r"      ([A-Za-z_][A-Za-z0-9_-]*):[ \t]*([^ \t#]+)[ \t]*(?:#.*)?",
                    line,
                )
                self.assertIsNotNone(match, f"malformed job-level permissions line: {line!r}")
                permission_pairs.append(match.groups())
            self.assertTrue(permission_pairs, "job-level permissions must be a nonempty mapping")
            permissions = dict(permission_pairs)
            self.assertEqual(len(permission_pairs), len(permissions), "duplicate job-level permission key")
            self.assertEqual(permissions, {"contents": "read"})
            self.assertFalse(any(value.endswith("write") for value in permissions.values()))
            return permissions

        def step_run_body(step):
            run_blocks = list(re.finditer(r"(?m)^        run:[ \t]*\|[ \t]*$", step))
            self.assertEqual(len(run_blocks), 1)
            body = []
            for line in step[run_blocks[0].end():].splitlines():
                if not line.strip():
                    body.append("")
                    continue
                indentation = len(line) - len(line.lstrip(" "))
                if indentation < 10:
                    break
                body.append(line[10:])
            return body

        preflight_gate = (
            "github.event_name == 'workflow_dispatch' && "
            "inputs.mode == 'activate-g8' && "
            "github.ref == 'refs/heads/main'"
        )
        self.assertEqual(
            re.findall(r"(?m)^    if:[ \t]*(.*)$", preflight_job),
            [preflight_gate],
        )
        self.assertEqual(
            re.findall(r"(?m)^    needs:[ \t]*(.*)$", preflight_job),
            ["activation-guard"],
        )
        self.assertEqual(job_level_permissions(preflight_job), {"contents": "read"})
        self.assertNotIn("permission-checks:", preflight_job)
        self.assertEqual(preflight_job.count("actions/create-github-app-token@"), 1)

        preflight_token = job_step(preflight_job, "id: preflight-token")
        self.assertEqual(preflight_token.count("actions/create-github-app-token@"), 1)
        preflight_permissions = re.findall(
            r"(?m)^[ \t]+permission-([a-z-]+):[ \t]*([^ \t\r\n#]+)[ \t]*$",
            preflight_token,
        )
        expected_preflight_permissions = {
            "actions": "read",
            "contents": "read",
            "statuses": "read",
            "issues": "read",
            "pull-requests": "read",
        }
        self.assertEqual(len(preflight_permissions), len(expected_preflight_permissions))
        self.assertEqual(dict(preflight_permissions), expected_preflight_permissions)
        self.assertNotRegex(preflight_token, r"(?m)^[ \t]+permission-[a-z-]+:[ \t]*write[ \t]*$")

        preflight_command = job_step(preflight_job, "id: preflight")
        self.assertIn(
            "FEDERATION_GITHUB_TOKEN: ${{ steps.preflight-token.outputs.token }}",
            preflight_command,
        )
        self.assertEqual(
            re.findall(
                r"(?m)^[ \t]*PYTHONDONTWRITEBYTECODE=1 python3 -B -m "
                r"automation\.federation\.controller ([a-z-]+)(?:[ \t]+>|[ \t]*$)",
                preflight_command,
            ),
            ["activation-preflight"],
        )
        decision_parser = job_step(preflight_job, "id: parse-preflight")
        parser_run_lines = step_run_body(decision_parser)
        parser_run_body = "\n".join(parser_run_lines)
        parser_command_pattern = re.compile(
            r"""^python3 - "\$\{RUNNER_TEMP\}/g8-activation-preflight\.out" "\$GITHUB_OUTPUT" <<'PY'$"""
        )
        parser_command_indices = [
            index for index, line in enumerate(parser_run_lines)
            if parser_command_pattern.fullmatch(line.strip())
        ]
        self.assertEqual(len(parser_command_indices), 1)
        parser_command_index = parser_command_indices[0]
        parser_prefix_commands = [
            line.strip()
            for line in parser_run_lines[:parser_command_index]
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(parser_prefix_commands, ["set -euo pipefail"])
        parser_terminators = [
            index for index, line in enumerate(parser_run_lines)
            if index > parser_command_index and line.strip() == "PY"
        ]
        self.assertEqual(len(parser_terminators), 1)
        parser_postlude_commands = [
            line.strip()
            for line in parser_run_lines[parser_terminators[0] + 1:]
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(parser_postlude_commands, [])
        parser_blocks = re.findall(
            r"(?ms)^python3 - .* <<'PY'[ \t]*\n(.*?)^PY[ \t]*$",
            parser_run_body,
        )
        self.assertEqual(len(parser_blocks), 1)
        parser_source = parser_blocks[0]
        parser_tree = ast.parse(parser_source)
        expected_parser_source = "\n".join(
            (
                "import json",
                "import pathlib",
                "import sys",
                "",
                "def unique_object(pairs):",
                "    result = {}",
                "    for key, value in pairs:",
                "        if key in result:",
                '            raise ValueError("duplicate JSON key")',
                "        result[key] = value",
                "    return result",
                "",
                "def reject_constant(value):",
                '    raise ValueError("non-standard JSON constant")',
                "",
                "raw = pathlib.Path(sys.argv[1]).read_bytes()",
                'if not raw or raw.count(b"\\n") != 1 or not raw.endswith(b"\\n") or b"\\r" in raw:',
                '    raise SystemExit("invalid activation preflight framing")',
                "try:",
                '    value = json.loads(raw[:-1].decode("utf-8"), object_pairs_hook=unique_object, parse_constant=reject_constant)',
                "except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:",
                '    raise SystemExit("invalid activation preflight JSON") from exc',
                'if type(value) is not dict or set(value) != {"decision"} or type(value["decision"]) is not str:',
                '    raise SystemExit("invalid activation preflight shape")',
                'decision = value["decision"]',
                'if decision not in {"READY", "ACTIVE_NOOP", "BLOCKED"}:',
                '    raise SystemExit("unknown activation preflight decision")',
                'canonical = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\\n")',
                "if canonical != raw:",
                '    raise SystemExit("non-canonical activation preflight bytes")',
                'with pathlib.Path(sys.argv[2]).open("a", encoding="utf-8", newline="\\n") as output:',
                '    output.write("decision=" + decision + "\\n")',
            )
        )
        expected_parser_tree = ast.parse(expected_parser_source)
        self.assertEqual(
            ast.dump(parser_tree, include_attributes=False),
            ast.dump(expected_parser_tree, include_attributes=False),
            "parse-preflight executable Python AST differs from frozen parser",
        )
        expected_shape_condition = (
            'type(value) is not dict or set(value) != {"decision"} '
            'or type(value["decision"]) is not str'
        )
        shape_guards = [
            node for node in ast.walk(parser_tree)
            if isinstance(node, ast.If)
            and ast.get_source_segment(parser_source, node.test) == expected_shape_condition
        ]
        self.assertEqual(len(shape_guards), 1)
        self.assertEqual(len(shape_guards[0].body), 1)
        self.assertIsInstance(shape_guards[0].body[0], ast.Raise)
        self.assertEqual(shape_guards[0].orelse, [])

        decision_stores = [
            node for node in ast.walk(parser_tree)
            if isinstance(node, ast.Name)
            and node.id == "decision"
            and isinstance(node.ctx, ast.Store)
        ]
        self.assertEqual(len(decision_stores), 1, "decision must never be reassigned")
        decision_assignments = [
            node for node in ast.walk(parser_tree)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == "decision"
        ]
        self.assertEqual(len(decision_assignments), 1)
        decision_assignment = decision_assignments[0]
        self.assertEqual(
            ast.get_source_segment(parser_source, decision_assignment),
            'decision = value["decision"]',
        )

        decision_checks = [
            node for node in ast.walk(parser_tree)
            if isinstance(node, ast.If)
            and isinstance(node.test, ast.Compare)
            and len(node.test.ops) == 1
            and isinstance(node.test.ops[0], ast.NotIn)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "decision"
        ]
        self.assertEqual(len(decision_checks), 1)
        decision_check = decision_checks[0]
        self.assertEqual(
            ast.literal_eval(decision_check.test.comparators[0]),
            {"READY", "ACTIVE_NOOP", "BLOCKED"},
        )
        self.assertEqual(len(decision_check.body), 1)
        self.assertIsInstance(decision_check.body[0], ast.Raise)
        self.assertEqual(decision_check.orelse, [])

        output_writes = [
            node for node in ast.walk(parser_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "output"
            and node.func.attr == "write"
        ]
        self.assertEqual(len(output_writes), 1)
        output_write = output_writes[0]
        self.assertEqual(
            ast.get_source_segment(parser_source, output_write),
            'output.write("decision=" + decision + "\\n")',
        )
        self.assertLess(shape_guards[0].lineno, decision_assignment.lineno)
        self.assertLess(decision_assignment.lineno, decision_check.lineno)
        self.assertLess(decision_check.lineno, output_write.lineno)
        self.assertEqual(
            re.findall(r"(?m)^      decision:[ \t]*(.*)$", preflight_job),
            ["${{ steps.parse-preflight.outputs.decision }}"],
        )

        activate_gate = (
            "github.event_name == 'workflow_dispatch' && "
            "inputs.mode == 'activate-g8' && "
            "github.ref == 'refs/heads/main' && "
            "needs.activation-preflight.outputs.decision == 'READY'"
        )
        self.assertEqual(
            re.findall(r"(?m)^    if:[ \t]*(.*)$", activate_job),
            [activate_gate],
        )
        self.assertEqual(
            re.findall(r"(?m)^    needs:[ \t]*(.*)$", activate_job),
            ["activation-preflight"],
        )
        self.assertEqual(job_level_permissions(activate_job), {"contents": "read"})
        self.assertNotIn("always()", activate_job)
        self.assertNotIn("permission-checks:", activate_job)
        self.assertEqual(activate_job.count("actions/create-github-app-token@"), 1)

        activate_token = job_step(activate_job, "id: activation-token")
        self.assertEqual(activate_token.count("actions/create-github-app-token@"), 1)
        activate_permissions = re.findall(
            r"(?m)^[ \t]+permission-([a-z-]+):[ \t]*([^ \t\r\n#]+)[ \t]*$",
            activate_token,
        )
        expected_activate_permissions = {
            "actions": "write",
            "statuses": "write",
            "contents": "write",
            "issues": "write",
            "pull-requests": "write",
        }
        self.assertEqual(len(activate_permissions), len(expected_activate_permissions))
        self.assertEqual(dict(activate_permissions), expected_activate_permissions)
        self.assertNotIn("permission-checks:", activate_token)

        activate_command = job_step(activate_job, "name: Execute exact activate-g8 controller command")
        self.assertIn(
            "FEDERATION_GITHUB_TOKEN: ${{ steps.activation-token.outputs.token }}",
            activate_command,
        )
        writer_executable_lines = [
            line.strip()
            for line in step_run_body(activate_command)
            if line.strip() and not line.strip().startswith("#")
        ]
        self.assertEqual(
            writer_executable_lines,
            [
                "set -euo pipefail",
                "PYTHONDONTWRITEBYTECODE=1 python3 -B -m automation.federation.controller activate-g8",
            ],
        )
        activate_step_expressions = [
            expression.strip()
            for expression in re.findall(r"\$\{\{(.*?)\}\}", activate_job)
            if re.search(r"\bsteps\b", expression, re.IGNORECASE)
        ]
        self.assertEqual(
            activate_step_expressions,
            [
                "steps.activation-token.outputs.token",
                "steps.activation-token.outputs.app-slug",
            ],
        )
        token_output_reference = re.compile(
            r"(?ix)\bsteps\s*"
            r"(?:\.\s*activation-token|\[\s*['\"]activation-token['\"]\s*\])\s*"
            r"\.\s*outputs\s*"
            r"(?:\.\s*token|\[\s*['\"]token['\"]\s*\])"
        )
        token_output_expressions = [
            expression
            for expression in activate_step_expressions
            if token_output_reference.search(expression)
        ]
        self.assertEqual(token_output_expressions, ["steps.activation-token.outputs.token"])
        writer_step_expressions = [
            expression.strip()
            for expression in re.findall(r"\$\{\{(.*?)\}\}", activate_command)
            if re.search(r"\bsteps\b", expression, re.IGNORECASE)
        ]
        writer_token_output_expressions = [
            expression
            for expression in writer_step_expressions
            if token_output_reference.search(expression)
        ]
        self.assertEqual(
            writer_token_output_expressions,
            ["steps.activation-token.outputs.token"],
        )
        self.assertEqual(token_output_expressions, writer_token_output_expressions)

    def test_wave12_runtime_and_authority_surface_preserves_task02_recovery_only(self):
        controller = CONTROLLER.read_text(encoding="utf-8")
        controller_tree = ast.parse(controller)
        recovery_method = next(
            node for node in ast.walk(controller_tree)
            if isinstance(node, ast.FunctionDef) and node.name == "run_g8_activation_recovery"
        )
        recovery_source = ast.get_source_segment(controller, recovery_method)
        witness_constructions = [
            node for node in ast.walk(recovery_method)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "ActivationRecoveryWitness"
        ]
        self.assertTrue(witness_constructions)
        self.assertIn("ActivationRecoveryWitness(", recovery_source)
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
            "class ActivationEpoch",
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
