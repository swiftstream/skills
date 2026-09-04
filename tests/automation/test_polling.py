import re
import unittest
from pathlib import Path

from automation.federation.controller import AppIdentity, MachineReconcileResult, R02Controller, TrustedValidationResult, evaluate_trusted_validation
from automation.federation.request_model import RequestClass
from automation.federation import controller as controller_module
from scripts import federate as c02


ROOT = Path(__file__).resolve().parents[2]


def source(source_id: str, repository_id: int) -> c02.SourceDeclaration:
    return c02.SourceDeclaration(source_id, f"Owner/{source_id}", repository_id, "refs/heads/main", "skills", (source_id,), source_id)


class PollingTests(unittest.TestCase):
    def controller(self, sources):
        controller = object.__new__(R02Controller)
        controller.central_repository = "swiftstream/skills"
        controller.client = type("Client", (), {"dispatch_workflow": lambda self, *args: dispatches.append(args)})()
        controller.current_accepted_main = lambda: (type("Repo", (), {"default_branch": "main"})(), "a" * 40)
        controller._accepted_sources = lambda _main=None: tuple(sources)
        dispatches = []
        return controller, dispatches

    def test_no_hint_reconcile_enumerates_each_source_once_in_deterministic_order(self):
        sources = [source("zeta", 30), source("alpha", 10), source("middle", 20)]
        controller, dispatches = self.controller(sources)
        seen = []
        controller.reconcile = lambda repository_id, **kwargs: seen.append(repository_id) or MachineReconcileResult("NOOP", repository_id=repository_id)
        result = controller.reconcile_all()
        self.assertEqual(seen, [10, 20, 30])
        self.assertEqual([item.repository_id for item in result], [10, 20, 30])
        self.assertEqual(dispatches, [])

    def test_empty_registry_is_a_clean_bounded_noop(self):
        controller, dispatches = self.controller([])
        controller.reconcile = lambda *_args, **_kwargs: self.fail("empty registry must not reconcile a source")
        self.assertEqual(controller.reconcile_all(), ())
        self.assertEqual(dispatches, [])

    def test_targeted_manual_repository_id_reconciles_one_source(self):
        sources = [source("alpha", 10), source("beta", 20)]
        controller, dispatches = self.controller(sources)
        seen = []
        controller.reconcile = lambda repository_id, **kwargs: seen.append(repository_id) or MachineReconcileResult("CHANGED", repository_id=repository_id)
        result = controller.reconcile(20, dispatch_finalizer=True)
        self.assertEqual(seen, [20])
        self.assertEqual(result.repository_id, 20)

    def test_unknown_source_during_sweep_is_bounded_noop_without_onboarding(self):
        first = source("alpha", 10)
        controller, dispatches = self.controller([first, source("beta", 20)])
        seen = []

        def reconcile(repository_id, **kwargs):
            seen.append(repository_id)
            if repository_id == 10:
                return MachineReconcileResult("NOOP", repository_id=repository_id, reason="UNKNOWN_REPOSITORY_ID")
            return MachineReconcileResult("NOOP", repository_id=repository_id, reason="CURRENT_STATE_ALREADY_MATCHES")

        controller.reconcile = reconcile
        result = controller.reconcile_all()
        self.assertEqual(seen, [10, 20])
        self.assertEqual([item.reason for item in result], ["UNKNOWN_REPOSITORY_ID", "CURRENT_STATE_ALREADY_MATCHES"])
        self.assertEqual(dispatches, [])

    def test_changed_multi_source_sweep_emits_one_finalizer_wake(self):
        controller, dispatches = self.controller([source("alpha", 10), source("beta", 20)])
        controller.reconcile = lambda repository_id, **kwargs: MachineReconcileResult("CHANGED", repository_id=repository_id)
        controller.reconcile_all()
        self.assertEqual(len(dispatches), 1)
        self.assertEqual(dispatches[0][1], "federation-state-finalize.yml")

    def test_reconcile_workflow_is_scheduled_and_manually_targetable(self):
        workflow = (ROOT / ".github/workflows/federation-reconcile.yml").read_text()
        self.assertIn("schedule:", workflow)
        self.assertIn("cron: '*/15 * * * *'", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("repository_id:", workflow)
        self.assertRegex(workflow, r"repository_id:\n\s+required: false\n\s+type: string")
        self.assertIn("group: swiftstream-skills-federation-reconcile", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("FEDERATION_RECONCILE_REPOSITORY_ID", workflow)

    def test_readme_states_simplified_polling_current_truth(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        catalog_marker = "<!-- BEGIN FEDERATED SKILLS CATALOG -->"
        self.assertIn(catalog_marker, readme)
        human_text = re.sub(r"\s+", " ", readme.split(catalog_marker, 1)[0]).lower()

        no_requirements = re.search(r"source repository needs no (.+?central credential)", human_text)
        self.assertIsNotNone(no_requirements)
        for fragment in ("federation notifier workflow", "federation secret", "oidc setup", "wake url", "signing key", "central credential"):
            self.assertIn(fragment, no_requirements.group(1))
        self.assertIn("accepted in central `federation.json`", human_text)
        self.assertIn("central scheduled polling (about every 15 minutes)", human_text)
        self.assertIn("manually dispatch reconciliation sooner", human_text)
        self.assertIn("normal source change may otherwise take until the next successful poll", human_text)

    def test_stable_docs_state_current_polling_and_wave1_policy(self):
        agents = re.sub(r"\s+", " ", (ROOT / "AGENTS.md").read_text(encoding="utf-8")).lower()
        mechanics = re.sub(r"\s+", " ", (ROOT / "docs/MECHANICS.md").read_text(encoding="utf-8")).lower()

        self.assertNotIn("automatic notifications from repositories absent from accepted `federation.json`", agents)
        self.assertIn("scheduled/manual reconciliation operates only on repositories accepted in central `federation.json`", agents)
        self.assertIn("unknown targeted repository id is a bounded noop", agents)
        self.assertIn("cannot onboard a source", agents)

        self.assertNotIn("future automatic push notifications", mechanics)
        self.assertIn("after removal, scheduled polling no longer enumerates the source from accepted `federation.json`", mechanics)
        self.assertIn("later targeted reconcile using that removed/unknown repository id is a bounded noop", mechanics)
        self.assertIn("cannot restore trust or onboard the source", mechanics)
        self.assertNotIn("central automation that detects a tag/release or cannot establish the required channel state must fail closed", mechanics)
        self.assertNotIn("not merely repository-local governance", mechanics)
        self.assertIn("wave-1 zero-tags/zero-releases/no-real-publish is a trusted maintainer/operator policy", mechanics)
        self.assertIn("c03 runtime federation automation does not enumerate remote tags/releases", mechanics)
        self.assertIn("does not perform a channel-readiness/anti-admin gate", mechanics)

    def test_deleted_notifier_relay_and_ceremony_are_absent_from_stable_production_surface(self):
        production_paths = list((ROOT / "automation/federation").rglob("*.py")) + [
            *((ROOT / ".github/workflows").glob("federation-*.yml")),
        ]
        production = "\n".join(path.read_text(encoding="utf-8") for path in production_paths)
        for forbidden in ("OIDC", "JWKS", "JWT", "relay", "notifier", "FEDERATION_WAKE_URL", "FEDERATION_WAKE_REPOSITORY_ID", "FEDERATION_NO_BYPASS_PROOF_V2", "FEDERATION_RULESET_ID", "attestation", "keyring", "readiness"):
            self.assertNotIn(forbidden, production)
        self.assertFalse((ROOT / "automation/federation/relay.py").exists())
        self.assertFalse((ROOT / "automation/federation/templates/swiftstream-skills-notify.yml").exists())
        self.assertFalse((ROOT / ".github/workflows/federation-channel-guard.yml").exists())

    def test_no_third_party_runtime_dependency_import_or_install_remains(self):
        production_paths = list((ROOT / "automation/federation").rglob("*.py"))
        production = "\n".join(path.read_text(encoding="utf-8") for path in production_paths)
        for package in ("cryptography", "jwt", "cffi", "pycparser"):
            self.assertNotRegex(production, rf"(?:from|import)\s+{re.escape(package)}")
        workflows = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / ".github/workflows").glob("federation-*.yml"))
        self.assertNotIn("pip install", workflows)
        self.assertNotIn("requirements-security", workflows)
        self.assertNotIn("requirements-relay", workflows)
        self.assertFalse((ROOT / "automation/requirements-security.txt").exists())
        self.assertFalse((ROOT / "automation/requirements-relay.txt").exists())

    def test_trusted_validation_requires_finalizer_authority_for_green(self):
        candidate = lambda: (True, "CANDIDATE_MATCHES_C02")
        ordinary = evaluate_trusted_validation(RequestClass.ADD, "a" * 40, "b" * 40, candidate)
        finalizer = evaluate_trusted_validation(RequestClass.ADD, "a" * 40, "b" * 40, candidate, allow_success=True)
        self.assertIsInstance(ordinary, TrustedValidationResult)
        self.assertEqual(ordinary.conclusion, "failure")
        self.assertEqual(finalizer.conclusion, "success")

    def test_production_controller_has_no_deleted_ceremony_symbols(self):
        controller = (ROOT / "automation/federation/controller.py").read_text()
        for forbidden in ("verify_live_readiness", "verify_wave1_channel", "verify_expected_app_preassociation", "keyring_path", "establish_live_readiness", "admin_attestation"):
            self.assertNotIn(forbidden, controller)
        self.assertIn("reconcile_all", controller)
        self.assertIn("FEDERATION_RECONCILE_REPOSITORY_ID", controller)


if __name__ == "__main__":
    unittest.main()
