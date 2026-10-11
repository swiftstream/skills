from __future__ import annotations

import inspect
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

from automation.federation import controller as controller_module
from automation.federation import request_model as rm
from automation.federation.github_api import (
    CommitStatus,
    GitCommitIdentity,
    GitCommitObject,
    GitTreeEntry,
    IssueComment,
    RepositoryMetadata,
    WorkflowMetadata,
    WorkflowRunMetadata,
)


class Wave12ActivationGuardSnapshotTests(unittest.TestCase):
    APP = controller_module.AppIdentity(
        "swift-stream-federation",
        101,
        "A_app",
        202,
        "B_bot",
        "swift-stream-federation[bot]",
    )
    MERGED = "e" * 40
    HAE = "f" * 40
    TRUSTED_MAIN = "d" * 40

    @classmethod
    def boundary(cls, *, surface: str = "2" * 64, topology: str = "3" * 64):
        boundary_id = rm.activation_boundary_id_digest(
            rm.G8_CENTRAL_REPOSITORY_NODE_ID,
            rm.G8_IMPLEMENTATION_PR_NUMBER,
            rm.G8_IMPLEMENTATION_PR_DATABASE_ID,
            rm.G8_IMPLEMENTATION_PR_NODE_ID,
            cls.MERGED,
            surface,
            topology,
        )
        return rm.ActivationBoundaryEvidence(
            1,
            rm.G8_CENTRAL_REPOSITORY_NODE_ID,
            rm.G8_IMPLEMENTATION_PR_NUMBER,
            rm.G8_IMPLEMENTATION_PR_DATABASE_ID,
            rm.G8_IMPLEMENTATION_PR_NODE_ID,
            "c" * 40,
            cls.MERGED,
            surface,
            topology,
            boundary_id,
        )

    @classmethod
    def evidence(cls, boundary=None, *, legacy_digest="8" * 64):
        boundary = boundary or cls.boundary()
        witness = rm.ActivationRecoveryWitness(
            1,
            boundary.activation_boundary_id,
            7001,
            2,
            "4" * 64,
            rm.ordered_recovery_actions_digest(()),
            "5" * 64,
            0,
            "6" * 64,
            "7" * 64,
        )
        return rm.ActivationRecoveryEvidence(
            1,
            "G8_ACTIVATION_RECOVERY",
            rm.G8_CENTRAL_REPOSITORY_NODE_ID,
            rm.G8_IMPLEMENTATION_PR_NUMBER,
            rm.G8_IMPLEMENTATION_PR_DATABASE_ID,
            rm.G8_IMPLEMENTATION_PR_NODE_ID,
            boundary.activation_boundary_id,
            boundary.merged_result_oid,
            boundary.authority_surface_digest,
            boundary.new_writer_topology_digest,
            witness.activation_run_id,
            witness.activation_run_attempt,
            witness.pre_recovery_inventory_digest,
            witness.ordered_recovery_actions_digest,
            0,
            witness.post_recovery_inventory_digest,
            0,
            witness.old_run_terminal_digest,
            witness.six_workflow_identity_digest,
            legacy_digest,
            witness.witness_id(),
            "SUCCESS",
        )

    @classmethod
    def record(cls, boundary=None, evidence=None):
        boundary = boundary or cls.boundary()
        evidence = evidence or cls.evidence(boundary)
        return rm.ActivationEpochRecord(
            1,
            boundary.activation_boundary_id,
            rm.G8_CENTRAL_REPOSITORY_NODE_ID,
            rm.G8_IMPLEMENTATION_PR_NUMBER,
            rm.G8_IMPLEMENTATION_PR_DATABASE_ID,
            rm.G8_IMPLEMENTATION_PR_NODE_ID,
            boundary.merged_result_oid,
            boundary.authority_surface_digest,
            boundary.new_writer_topology_digest,
            tuple(
                rm.ActivationWorkflowIdentity(path, 1000 + index, "active")
                for index, path in enumerate(rm.G8_NEW_WRITER_PATHS)
            ),
            tuple(
                rm.HistoricWorkflowIdentity(path, workflow_id)
                for path, workflow_id in rm.G8_OLD_WRITERS
            ),
            "9" * 64,
            "a" * 64,
            evidence.legacy_inventory_quarantine_migration_digest,
            evidence.activation_recovery_witness_id,
            evidence.result_digest(),
            9001,
            3,
            "2026-10-09T12:34:56Z",
        )

    @classmethod
    def app_comment(cls, body, *, edited=False, database_id=10):
        return IssueComment(
            f"IC_{database_id}",
            database_id,
            body,
            cls.APP.bot_node_id,
            cls.APP.bot_login,
            "Bot",
            "U_editor" if edited else None,
            "editor" if edited else None,
            "User" if edited else None,
            "2026-10-09T13:00:00Z" if edited else None,
            edited,
        )

    @staticmethod
    def foreign_comment(body, *, database_id=50):
        return IssueComment(
            f"IC_foreign_{database_id}",
            database_id,
            body,
            "U_foreign",
            "foreign-user",
            "User",
            None,
            None,
            None,
            None,
            False,
        )

    @classmethod
    def status(cls, record, boundary, *, description=None, creator=True, state="success", status_id=1):
        return CommitStatus(
            status_id,
            None,
            state,
            rm.G8_ACTIVATION_STATUS_CONTEXT,
            description if description is not None else rm.activation_status_description(
                record, cls.HAE, boundary.activation_boundary_id,
            ),
            None,
            cls.APP.bot_id if creator else 999,
            cls.APP.bot_node_id if creator else "U_foreign",
            cls.APP.bot_login if creator else "foreign-user",
            "Bot" if creator else "User",
            "2026-10-09T12:35:00Z",
            f"2026-10-09T12:35:{status_id:02d}Z",
        )

    class SnapshotClient:
        def __init__(
            self,
            test,
            boundary,
            record,
            evidence,
            *,
            refs=None,
            statuses=None,
            comments=None,
            wrong_parent=False,
            extra_tree=False,
        ):
            self.test = test
            self.boundary = boundary
            self.record = record
            self.evidence = evidence
            self.refs = list(refs if refs is not None else [test.HAE, test.HAE])
            self.statuses = list(statuses if statuses is not None else [
                test.status(record, boundary),
            ])
            self.comments = list(comments if comments is not None else [
                test.app_comment(evidence.render()),
            ])
            self.wrong_parent = wrong_parent
            self.extra_tree = extra_tree
            self.record_blob = "b" * 40
            self.hae_tree = "a" * 40
            self.base_entries = (
                GitTreeEntry("README.md", "100644", "blob", "1" * 40),
            )
            self.hae_entries = self.base_entries + (
                GitTreeEntry(
                    rm.G8_ACTIVATION_RECORD_PATH,
                    "100644",
                    "blob",
                    self.record_blob,
                ),
            )
            if extra_tree:
                self.hae_entries += (
                    GitTreeEntry("unexpected.txt", "100644", "blob", "2" * 40),
                )
            identity = GitCommitIdentity(
                "Swift Stream Federation",
                "automation@swiftstream.invalid",
                "2026-10-09T12:34:56Z",
            )
            self.commit = GitCommitObject(
                test.HAE,
                (
                    "swiftstream-federation-g8-activation:v1\n"
                    f"boundary={boundary.activation_boundary_id}\n"
                    f"record={rm.activation_record_digest(record)}"
                ),
                self.hae_tree,
                (("0" * 40) if wrong_parent else boundary.merged_result_oid,),
                identity,
                identity,
            )

        def get_optional_ref_oid(self, repository, branch):
            self.test.assertEqual(repository, "swiftstream/skills")
            self.test.assertEqual(branch, "bot/federation-g8-activation")
            if not self.refs:
                return self.test.HAE
            return self.refs.pop(0)

        def get_git_commit_object(self, repository, sha):
            self.test.assertEqual((repository, sha), ("swiftstream/skills", self.test.HAE))
            return self.commit

        def get_commit_tree(self, repository, sha):
            self.test.assertEqual((repository, sha), ("swiftstream/skills", self.boundary.merged_result_oid))
            return "3" * 40, self.base_entries

        def get_tree(self, repository, tree_sha):
            self.test.assertEqual((repository, tree_sha), ("swiftstream/skills", self.hae_tree))
            return self.hae_tree, self.hae_entries

        def get_blob(self, repository, blob_sha):
            self.test.assertEqual((repository, blob_sha), ("swiftstream/skills", self.record_blob))
            return self.record.render().encode()

        def list_issue_comments(self, repository, number):
            self.test.assertEqual((repository, number), ("swiftstream/skills", 27))
            return tuple(self.comments)

        def list_commit_statuses(self, repository, sha):
            self.test.assertEqual((repository, sha), ("swiftstream/skills", self.test.HAE))
            return tuple(self.statuses)

    class GuardController(controller_module.R02Controller):
        def __init__(self, client, app, boundary, *, pre=False, surface_error=False):
            super().__init__(
                client,
                "swiftstream/skills",
                app,
                environ={"FEDERATION_TRUSTED_CHECKOUT_SHA": "d" * 40},
            )
            self._test_boundary = boundary
            self._test_pre = pre
            self._test_surface_error = surface_error

        def derive_activation_boundary_evidence(self):
            if self._test_pre:
                raise controller_module.PreG8NotApplicableError("pre-g8")
            return self._test_boundary

        def _require_current_g8_guard_surface(self, boundary):
            if self._test_surface_error:
                raise controller_module.R02Error("surface drift")
            if boundary != self._test_boundary:
                raise controller_module.R02Error("boundary drift")
            return "d" * 40

    def make_guard(
        self,
        *,
        boundary=None,
        evidence=None,
        record=None,
        refs=None,
        statuses=None,
        comments=None,
        wrong_parent=False,
        extra_tree=False,
        pre=False,
        surface_error=False,
    ):
        boundary = boundary or self.boundary()
        evidence = evidence or self.evidence(boundary)
        record = record or self.record(boundary, evidence)
        client = self.SnapshotClient(
            self,
            boundary,
            record,
            evidence,
            refs=refs,
            statuses=statuses,
            comments=comments,
            wrong_parent=wrong_parent,
            extra_tree=extra_tree,
        )
        controller = self.GuardController(
            client,
            self.APP,
            boundary,
            pre=pre,
            surface_error=surface_error,
        )
        return controller, client, boundary, evidence, record

    def derive(self, controller):
        with patch.object(
            controller_module,
            "resolve_app_identity",
            return_value=self.APP,
        ):
            return controller.derive_g8_activation_guard()

    def test_no_activation_ref_is_merged_unproven_and_activation_eligible_only(self):
        controller, _client, _boundary, _evidence, _record = self.make_guard(
            refs=[None],
        )
        result = self.derive(controller)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.MERGED_UNPROVEN)
        self.assertFalse(result.ordinary_write_allowed)
        self.assertTrue(result.activation_write_allowed)
        self.assertEqual(result.reason, "MERGED_UNPROVEN_NO_VALID_EPOCH")

    def test_exact_epoch_evidence_status_and_final_rereads_prove_active(self):
        controller, _client, _boundary, _evidence, _record = self.make_guard()
        result = self.derive(controller)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.ACTIVE_G8)
        self.assertTrue(result.ordinary_write_allowed)
        self.assertFalse(result.activation_write_allowed)
        self.assertEqual(result.reason, "ACTIVE_G8_EPOCH_PROVEN")

    def test_pre_g8_is_non_mutating_not_applicable(self):
        controller, _client, _boundary, _evidence, _record = self.make_guard(
            refs=[None],
            pre=True,
        )
        result = self.derive(controller)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.PRE_G8_NOT_APPLICABLE)
        self.assertFalse(result.ordinary_write_allowed)
        self.assertFalse(result.activation_write_allowed)

    def test_valid_epoch_with_missing_status_is_recoverable_merged_unproven(self):
        controller, _client, _boundary, _evidence, _record = self.make_guard(
            statuses=[],
        )
        result = self.derive(controller)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.MERGED_UNPROVEN)
        self.assertTrue(result.activation_write_allowed)

    def test_foreign_status_is_not_authority_and_behaves_as_status_absence(self):
        boundary = self.boundary()
        evidence = self.evidence(boundary)
        record = self.record(boundary, evidence)
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=evidence,
            record=record,
            statuses=[self.status(record, boundary, creator=False)],
        )
        result = self.derive(controller)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.MERGED_UNPROVEN)

    def test_latest_exact_app_status_conflict_blocks(self):
        boundary = self.boundary()
        evidence = self.evidence(boundary)
        record = self.record(boundary, evidence)
        statuses = [
            self.status(record, boundary, status_id=1),
            self.status(
                record,
                boundary,
                description="g8a:v1 active ev=" + "0" * 64,
                status_id=2,
            ),
        ]
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=evidence,
            record=record,
            statuses=statuses,
        )
        result = self.derive(controller)
        self.assertIs(result.runtime_state, controller_module.G8RuntimeState.BLOCKED_POST_MERGE)
        self.assertFalse(result.activation_write_allowed)

    def test_foreign_malformed_recovery_marker_is_noise_but_exact_app_malformed_blocks(self):
        boundary = self.boundary()
        evidence = self.evidence(boundary)
        valid = self.app_comment(evidence.render(), database_id=11)
        foreign = self.foreign_comment(
            rm.G8_ACTIVATION_RECOVERY_EVIDENCE_MARKER + "\nnot-json\n",
        )
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=evidence,
            comments=[foreign, valid],
        )
        self.assertIs(
            self.derive(controller).runtime_state,
            controller_module.G8RuntimeState.ACTIVE_G8,
        )

        malformed_app = self.app_comment(
            rm.G8_ACTIVATION_RECOVERY_EVIDENCE_MARKER + "\nnot-json\n",
            database_id=12,
        )
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=evidence,
            comments=[malformed_app, valid],
        )
        self.assertIs(
            self.derive(controller).runtime_state,
            controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
        )

    def test_edited_or_missing_selected_recovery_evidence_blocks(self):
        boundary = self.boundary()
        evidence = self.evidence(boundary)
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=evidence,
            comments=[self.app_comment(evidence.render(), edited=True)],
        )
        self.assertIs(
            self.derive(controller).runtime_state,
            controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
        )
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=evidence,
            comments=[],
        )
        self.assertIs(
            self.derive(controller).runtime_state,
            controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
        )

    def test_conflicting_same_run_exact_app_evidence_blocks(self):
        boundary = self.boundary()
        selected = self.evidence(boundary)
        conflicting = self.evidence(boundary, legacy_digest="f" * 64)
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=selected,
            comments=[
                self.app_comment(selected.render(), database_id=10),
                self.app_comment(conflicting.render(), database_id=11),
            ],
        )
        self.assertIs(
            self.derive(controller).runtime_state,
            controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
        )

    def test_wrong_parent_extra_tree_surface_drift_and_final_ref_drift_block(self):
        cases = (
            {"wrong_parent": True},
            {"extra_tree": True},
            {"surface_error": True},
            {"refs": [self.HAE, "0" * 40]},
        )
        for kwargs in cases:
            with self.subTest(kwargs=kwargs):
                controller, *_ = self.make_guard(**kwargs)
                result = self.derive(controller)
                self.assertIs(
                    result.runtime_state,
                    controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
                )

    def test_record_bound_to_different_boundary_blocks(self):
        boundary = self.boundary()
        selected = self.evidence(boundary)
        different_boundary = self.boundary(surface="c" * 64)
        different_evidence = self.evidence(different_boundary)
        different_record = self.record(different_boundary, different_evidence)
        controller, *_ = self.make_guard(
            boundary=boundary,
            evidence=selected,
            record=different_record,
            statuses=[self.status(different_record, different_boundary)],
        )
        self.assertIs(
            self.derive(controller).runtime_state,
            controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
        )

    def test_full_process_restart_reloads_selected_evidence_and_retries_status_only(self):
        harness = Wave12ActivationPublicationExecutionTests(self)
        p1, p1_client, _boundary, _execution = harness.new_publication_process()
        p1_client.crash_after_ref_persist = True
        with self.assertRaises(harness.CrashPoint):
            p1.publish_g8_activation_epoch(
                _execution,
                created_at="2026-10-09T12:34:56Z",
            )
        self.assertEqual(p1_client.ref_oid, self.HAE)
        self.assertEqual(p1_client.status_rows, [])
        self.assertEqual(len(p1_client.blob_writes), 1)
        self.assertEqual(len(p1_client.tree_writes), 1)
        self.assertEqual(len(p1_client.commit_writes), 1)

        # JSON is the process boundary: P2 receives only serialized platform
        # values, never a P1 controller, client, model, witness, or body object.
        durable_state = p1_client.serialize_durable_state()
        self.assertIs(type(json.loads(durable_state)), dict)
        del _execution, _boundary, p1_client, p1

        p2_client = harness.PlatformClient.from_durable_state(self, durable_state)
        p2 = harness.controller(p2_client, harness.boundary_from_durable_state(durable_state))
        resumed_record, resumed_hae = p2.resume_g8_activation_epoch()
        self.assertEqual(resumed_hae, self.HAE)
        self.assertEqual(resumed_record.activation_recovery_result_digest, p2_client.selected_result_digest)
        self.assertGreaterEqual(p2_client.reads["commit"], 1)
        self.assertGreaterEqual(p2_client.reads["tree"], 1)
        self.assertGreaterEqual(p2_client.reads["blob"], 1)
        self.assertGreaterEqual(p2_client.reads["comments"], 2)
        self.assertGreaterEqual(p2_client.reads["workflow_path"], 6)
        self.assertGreaterEqual(p2_client.reads["workflow_runs"], len(rm.G8_OLD_WRITERS))
        self.assertEqual(len(p2_client.status_writes), 1)
        self.assertEqual(p2_client.ref_oid, self.HAE)
        self.assertEqual(p2_client.blob_writes, [])
        self.assertEqual(p2_client.tree_writes, [])
        self.assertEqual(p2_client.commit_writes, [])
        self.assertEqual(p2_client.ref_writes, [])
        self.assertEqual(p2_client.status_rows[0]["context"], rm.G8_ACTIVATION_STATUS_CONTEXT)
        self.assertEqual(p2_client.status_rows[0]["state"], "success")
        self.assertEqual(
            p2_client.status_rows[0]["description"],
            rm.activation_status_description(resumed_record, resumed_hae, self.boundary().activation_boundary_id),
        )
        self.assertGreaterEqual(p2_client.reads["inventory_pr"], 1)
        self.assertGreaterEqual(p2_client.reads["inventory_issue"], 1)
        self.assertGreaterEqual(p2_client.reads["inventory_machine"], 1)

        guard_client = harness.PlatformClient.from_durable_state(self, durable_state)
        guard = harness.controller(guard_client, harness.boundary_from_durable_state(durable_state))
        self.assertIs(
            guard.derive_g8_activation_guard().runtime_state,
            controller_module.G8RuntimeState.MERGED_UNPROVEN,
        )

    def test_task04_activation_command_reaches_publication_and_resume_methods(self):
        source = inspect.getsource(controller_module.main)
        self.assertIn("publish_g8_activation_epoch", source)
        self.assertIn("resume_g8_activation_epoch", source)
        self.assertIn('"activate-g8"', source)
        self.assertIn('"activation-guard"', source)
        self.assertLess(source.index("run_g8_activation_recovery"), source.index("publish_g8_activation_epoch"))
        self.assertLess(source.index("derive_g8_activation_guard()"), source.index('"federation-g8-reconcile.yml"'))

    def test_activate_g8_dispatches_catchup_only_after_fresh_active_guard(self):
        calls = []
        app = Wave12ActivationGuardSnapshotTests.APP

        class Client:
            def get_optional_ref_oid(self, repository, branch):
                calls.append(("read-ref", repository, branch))
                return None

            def dispatch_workflow(self, repository, workflow, ref, inputs):
                calls.append(("dispatch", repository, workflow, ref, inputs))
                raise RuntimeError("dispatch response lost")

        class Controller:
            def _require_g8_activation_run_authority(self, command):
                calls.append(("authority", command))

            def run_g8_activation_recovery(self, command):
                calls.append(("recovery", command))
                return object()

            def publish_g8_activation_epoch(self, execution, *, created_at):
                calls.append(("publish", execution, created_at))
                return object(), "f" * 40

            def derive_g8_activation_guard(self):
                calls.append(("guard",))
                return controller_module._g8_activation_guard_result(
                    controller_module.G8RuntimeState.ACTIVE_G8,
                )

        env = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "activation-token",
            "FEDERATION_APP_SLUG": app.slug,
            "FEDERATION_TRUSTED_CHECKOUT_SHA": "e" * 40,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "maintainer",
            "GITHUB_RUN_ID": "7001",
            "GITHUB_RUN_ATTEMPT": "2",
            "INPUT_MODE": "activate-g8",
        }
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with (
            patch.object(controller_module, "GitHubClient", return_value=Client()),
            patch.object(controller_module, "resolve_app_identity", return_value=app),
            patch.object(controller_module, "C02CandidateBuilder", return_value=object()),
            patch.object(controller_module, "R02Controller", return_value=Controller()),
            patch.dict(controller_module.os.environ, env, clear=True),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = controller_module.main(["activate-g8"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(
            [item[0] for item in calls],
            ["authority", "read-ref", "recovery", "publish", "guard", "dispatch"],
        )
        self.assertEqual(calls[-1], (
            "dispatch", "swiftstream/skills", "federation-g8-reconcile.yml",
            "refs/heads/main", {"mode": "recover"},
        ))
        self.assertIn('"catchup":"UNCERTAIN"', stdout.getvalue())

    def test_activate_g8_resumes_exact_partial_epoch_before_active_catchup(self):
        calls = []
        app = Wave12ActivationGuardSnapshotTests.APP
        hae = "c" * 40

        class Client:
            def get_optional_ref_oid(self, repository, branch):
                calls.append(("read-ref", repository, branch))
                return hae

            def dispatch_workflow(self, repository, workflow, ref, inputs):
                calls.append(("dispatch", repository, workflow, ref, inputs))

        class Controller:
            def _require_g8_activation_run_authority(self, command):
                calls.append(("authority", command))

            def resume_g8_activation_epoch(self):
                calls.append(("resume",))
                return object(), hae

            def derive_g8_activation_guard(self):
                calls.append(("guard-active",))
                return controller_module._g8_activation_guard_result(
                    controller_module.G8RuntimeState.ACTIVE_G8,
                )

        env = {
            "GITHUB_REPOSITORY": "swiftstream/skills",
            "FEDERATION_GITHUB_TOKEN": "activation-token",
            "FEDERATION_APP_SLUG": app.slug,
            "FEDERATION_TRUSTED_CHECKOUT_SHA": "e" * 40,
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "maintainer",
            "GITHUB_RUN_ID": "7001",
            "GITHUB_RUN_ATTEMPT": "2",
            "INPUT_MODE": "activate-g8",
        }
        stdout = __import__("io").StringIO()
        stderr = __import__("io").StringIO()
        with (
            patch.object(controller_module, "GitHubClient", return_value=Client()),
            patch.object(controller_module, "resolve_app_identity", return_value=app),
            patch.object(controller_module, "C02CandidateBuilder", return_value=object()),
            patch.object(controller_module, "R02Controller", return_value=Controller()),
            patch.dict(controller_module.os.environ, env, clear=True),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            exit_code = controller_module.main(["activate-g8"])

        self.assertEqual(exit_code, 0, stderr.getvalue())
        self.assertEqual(
            [item[0] for item in calls],
            ["authority", "read-ref", "resume", "guard-active", "dispatch"],
        )
        self.assertEqual(calls[1], (
            "read-ref", "swiftstream/skills", "bot/federation-g8-activation",
        ))
        self.assertEqual(calls[-1], (
            "dispatch", "swiftstream/skills", "federation-g8-reconcile.yml",
            "refs/heads/main", {"mode": "recover"},
        ))
        self.assertIn(f'"hae":"{hae}"', stdout.getvalue())
        self.assertIn('"epoch":"RESUMED"', stdout.getvalue())

class Wave12ActivationPublicationExecutionTests(unittest.TestCase):
    """Local platform model for actual Task03 writer/restart execution."""

    APP = Wave12ActivationGuardSnapshotTests.APP
    MAIN = Wave12ActivationGuardSnapshotTests.MERGED
    HAE = Wave12ActivationGuardSnapshotTests.HAE

    class CrashPoint(BaseException):
        pass

    def __init__(self, methodName="runTest", test=None):
        if isinstance(methodName, unittest.TestCase):
            test = methodName
            methodName = "runTest"
        super().__init__(methodName)
        self.test = test if test is not None else self

    class PlatformClient:
        def __init__(self, test, state):
            self.test = test
            self.state = state
            self.reads = {key: 0 for key in (
                "commit", "tree", "blob", "comments", "workflow_path", "workflow_runs",
                "main", "ref", "status", "inventory_pr", "inventory_issue", "inventory_machine",
            )}
            self.blob_writes = []
            self.tree_writes = []
            self.commit_writes = []
            self.ref_writes = []
            self.status_writes = []
            self.status_attempts = []
            self.trace = []
            self.crash_after_ref_persist = False
            self.accept_status_then_lose_response = False
            self.fail_next_ref_read = False
            self.fail_ref_read_after_cas_failure = False
            self.ref_retry_then_success = False
            self.fail_status_once_without_persist = False
            self.third_value_on_ref_write = False
            self.crash_after_commit_create = False

        @property
        def ref_oid(self):
            return self.state["ref_oid"]

        @property
        def status_rows(self):
            return self.state["status_rows"]

        @property
        def selected_result_digest(self):
            return self.state["selected_result_digest"]

        @classmethod
        def initial_state(cls, test, boundary):
            surface_paths = sorted(controller_module.R02Controller._g8_authority_surface_paths())
            main_entries = [
                {"path": path, "mode": "100644", "object_type": "blob", "sha": f"{index + 1:040x}"}
                for index, path in enumerate(surface_paths)
            ]
            workflow_by_path = {}
            for index, path in enumerate(rm.G8_NEW_WRITER_PATHS):
                sha = next(row["sha"] for row in main_entries if row["path"] == path)
                workflow_by_path[path] = {
                    "id": 1000 + index,
                    "node_id": f"W_new_{index}",
                    "name": f"new-{index}",
                    "path": path,
                    "state": "active",
                    "blob_sha": sha,
                }
            old_by_id = {
                workflow_id: {
                    "id": workflow_id,
                    "node_id": f"W_old_{index}",
                    "name": f"old-{index}",
                    "path": path,
                    "state": "disabled_manually",
                }
                for index, (path, workflow_id) in enumerate(rm.G8_OLD_WRITERS)
            }
            return {
                "boundary": {
                    "schema_version": 1,
                    "central_repository_node_id": boundary.central_repository_node_id,
                    "implementation_pr_number": boundary.implementation_pr_number,
                    "implementation_pr_database_id": boundary.implementation_pr_database_id,
                    "implementation_pr_node_id": boundary.implementation_pr_node_id,
                    "implementation_reviewed_head_sha": boundary.implementation_reviewed_head_sha,
                    "merged_result_oid": boundary.merged_result_oid,
                    "authority_surface_digest": boundary.authority_surface_digest,
                    "new_writer_topology_digest": boundary.new_writer_topology_digest,
                    "activation_boundary_id": boundary.activation_boundary_id,
                },
                "main_entries": main_entries,
                "workflows": workflow_by_path,
                "old_workflows": {str(key): value for key, value in old_by_id.items()},
                "ref_oid": None,
                "blob_bytes_by_sha": {},
                "tree_entries_by_sha": {},
                "commit_by_sha": {},
                "comments": [],
                "status_rows": [],
                "next_status_id": 1,
                "selected_result_digest": None,
                "durable_writes": {"blob": 0, "tree": 0, "commit": 0, "ref": 0, "status": 0},
            }

        @classmethod
        def from_durable_state(cls, test, raw_state):
            return cls(test, json.loads(raw_state))

        def serialize_durable_state(self):
            return json.dumps(self.state, sort_keys=True, separators=(",", ":"))

        def _entries(self, rows):
            return tuple(GitTreeEntry(row["path"], row["mode"], row["object_type"], row["sha"]) for row in rows)

        def get_repository_metadata(self, repository):
            self.test.assertEqual(repository, "swiftstream/skills")
            return RepositoryMetadata(1351054671, rm.G8_CENTRAL_REPOSITORY_NODE_ID, repository, "main")

        def get_ref_oid(self, repository, branch):
            self.trace.append(("main", branch))
            self.test.assertEqual((repository, branch), ("swiftstream/skills", "main"))
            self.reads["main"] += 1
            return Wave12ActivationPublicationExecutionTests.MAIN

        def compare_commits(self, repository, base, head):
            self.trace.append(("compare_main", base, head))
            self.test.assertEqual((repository, base, head), (
                "swiftstream/skills",
                Wave12ActivationPublicationExecutionTests.MAIN,
                Wave12ActivationPublicationExecutionTests.MAIN,
            ))
            return "identical", base, base

        def get_commit_tree(self, repository, sha):
            self.test.assertEqual(repository, "swiftstream/skills")
            if sha in {Wave12ActivationPublicationExecutionTests.MAIN, self.state["boundary"]["merged_result_oid"]}:
                return "3" * 40, self._entries(self.state["main_entries"])
            commit = self.state["commit_by_sha"].get(sha)
            if commit is not None:
                return commit["tree_sha"], self._entries(self.state["tree_entries_by_sha"][commit["tree_sha"]])
            raise AssertionError(f"unexpected commit tree read: {sha}")

        def get_tree(self, repository, tree_sha):
            self.reads["tree"] += 1
            self.test.assertEqual(repository, "swiftstream/skills")
            return tree_sha, self._entries(self.state["tree_entries_by_sha"][tree_sha])

        def get_blob(self, repository, blob_sha):
            self.reads["blob"] += 1
            self.test.assertEqual(repository, "swiftstream/skills")
            for row in self.state["main_entries"]:
                if row["sha"] == blob_sha:
                    return f"workflow:{blob_sha}".encode()
            return bytes.fromhex(self.state["blob_bytes_by_sha"][blob_sha])

        def get_workflow_metadata_by_path(self, repository, path):
            self.trace.append(("workflow_path", path))
            self.test.assertEqual(repository, "swiftstream/skills")
            self.reads["workflow_path"] += 1
            row = self.state["workflows"].get(path)
            if row is None:
                raise AssertionError(f"unexpected workflow path lookup: {path}")
            return WorkflowMetadata(row["id"], row["node_id"], row["name"], row["path"], row["state"])

        def get_workflow_metadata_by_id(self, repository, workflow_id):
            self.test.assertEqual(repository, "swiftstream/skills")
            row = self.state["workflows"].get(next((path for path, value in self.state["workflows"].items() if value["id"] == workflow_id), ""))
            if row is None:
                row = self.state["old_workflows"].get(str(workflow_id))
            if row is None:
                raise AssertionError(f"unexpected workflow ID lookup: {workflow_id}")
            return WorkflowMetadata(row["id"], row["node_id"], row["name"], row["path"], row["state"])

        def list_workflow_runs(self, repository, workflow_id, *, max_pages=100):
            self.trace.append(("workflow_runs", workflow_id))
            self.test.assertEqual((repository, max_pages), ("swiftstream/skills", 100))
            self.reads["workflow_runs"] += 1
            return ()

        def get_optional_ref_oid(self, repository, branch):
            self.trace.append(("ref_read", branch))
            self.test.assertEqual((repository, branch), ("swiftstream/skills", "bot/federation-g8-activation"))
            self.reads["ref"] += 1
            if self.fail_next_ref_read:
                self.fail_next_ref_read = False
                raise OSError("transient fake ref read failure")
            return self.state["ref_oid"]

        def update_refs(self, repository_node_id, updates):
            self.trace.append(("update_refs", tuple(
                (item.name, item.before_oid, item.after_oid, item.force) for item in updates
            )))
            self.test.assertEqual(repository_node_id, rm.G8_CENTRAL_REPOSITORY_NODE_ID)
            self.ref_writes.append(tuple((item.name, item.before_oid, item.after_oid, item.force) for item in updates))
            self.state["durable_writes"]["ref"] += 1
            update = updates[0]
            if self.third_value_on_ref_write:
                self.state["ref_oid"] = "1" * 40
                raise OSError("fake CAS raced with third value")
            if self.ref_retry_then_success and len(self.ref_writes) == 1:
                if self.fail_ref_read_after_cas_failure:
                    self.fail_next_ref_read = True
                raise OSError("fake CAS transient failure with ref still absent")
            if self.state["ref_oid"] != (None if update.before_oid == "0" * 40 else update.before_oid):
                raise OSError("fake CAS expected-head conflict")
            self.state["ref_oid"] = update.after_oid
            if self.crash_after_ref_persist:
                self.crash_after_ref_persist = False
                raise Wave12ActivationPublicationExecutionTests.CrashPoint()

        def get_git_commit_object(self, repository, sha):
            self.test.assertEqual(repository, "swiftstream/skills")
            self.reads["commit"] += 1
            row = self.state["commit_by_sha"].get(sha)
            if row is None:
                raise AssertionError(f"missing fake commit: {sha}")
            identity = GitCommitIdentity(row["author_name"], row["author_email"], row["author_date"])
            return GitCommitObject(sha, row["message"], row["tree_sha"], tuple(row["parents"]), identity, identity)

        def create_blob(self, repository, content, *, encoding):
            self.test.assertEqual((repository, encoding), ("swiftstream/skills", "base64"))
            import base64
            blob = base64.b64decode(content, validate=True)
            sha = f"{len(self.state['blob_bytes_by_sha']) + 40:040x}"
            self.state["blob_bytes_by_sha"][sha] = blob.hex()
            self.state["durable_writes"]["blob"] += 1
            self.blob_writes.append(sha)
            return SimpleNamespace(sha=sha)

        def create_tree(self, repository, base_tree, entries):
            self.test.assertEqual((repository, base_tree), ("swiftstream/skills", "3" * 40))
            submitted = [dict(entry) for entry in entries]
            self.tree_writes.append((base_tree, submitted))
            self.state["durable_writes"]["tree"] += 1
            tree_sha = f"{len(self.state['tree_entries_by_sha']) + 50:040x}"
            self.state["tree_entries_by_sha"][tree_sha] = self.state["main_entries"] + [
                {
                    "path": entry["path"],
                    "mode": entry["mode"],
                    "object_type": entry["type"],
                    "sha": entry["sha"],
                }
                for entry in submitted
            ]
            return SimpleNamespace(sha=tree_sha)

        def create_commit(self, repository, message, tree_sha, parents, *, timestamp):
            self.test.assertEqual(repository, "swiftstream/skills")
            self.commit_writes.append((message, tree_sha, tuple(parents), timestamp))
            self.state["durable_writes"]["commit"] += 1
            sha = "f" * 40
            self.state["commit_by_sha"][sha] = {
                "message": message,
                "tree_sha": tree_sha,
                "parents": list(parents),
                "author_name": "Swift Stream Federation",
                "author_email": "automation@swiftstream.invalid",
                "author_date": timestamp,
            }
            if self.crash_after_commit_create:
                self.crash_after_commit_create = False
                raise Wave12ActivationPublicationExecutionTests.CrashPoint()
            return SimpleNamespace(sha=sha)

        def list_issue_comments(self, repository, number):
            self.trace.append(("comments", number))
            self.test.assertEqual((repository, number), ("swiftstream/skills", 27))
            self.reads["comments"] += 1
            return tuple(IssueComment(
                row["node_id"], row["database_id"], row["body"], row["author_id"], row["author_login"],
                row["author_type"], row["editor_id"], row["editor_login"], row["editor_type"],
                row["edited_at"], row["is_edited"],
            ) for row in self.state["comments"])

        def get_app_metadata(self, slug):
            app = Wave12ActivationPublicationExecutionTests.APP
            self.test.assertEqual(slug, app.slug)
            return SimpleNamespace(slug=slug, id=app.app_id, node_id=app.app_node_id)

        def get_bot_metadata(self, slug):
            app = Wave12ActivationPublicationExecutionTests.APP
            self.test.assertEqual(slug, app.slug)
            return SimpleNamespace(login=app.bot_login, id=app.bot_id, node_id=app.bot_node_id, type="Bot")

        def list_commit_statuses(self, repository, sha):
            self.trace.append(("status_read", sha))
            self.test.assertEqual(repository, "swiftstream/skills")
            self.reads["status"] += 1
            return tuple(CommitStatus(
                row["id"], None, row["state"], row["context"], row["description"], row["target_url"],
                row["creator_database_id"], row["creator_node_id"], row["creator_login"], row["creator_type"],
                row["created_at"], row["updated_at"],
            ) for row in self.state["status_rows"] if row["sha"] == sha)

        def create_commit_status(self, repository, sha, state, context, description, target_url):
            call = (repository, sha, state, context, description, target_url)
            self.status_attempts.append(call)
            self.trace.append(("status_write", call))
            self.test.assertEqual(repository, "swiftstream/skills")
            if self.fail_status_once_without_persist:
                self.fail_status_once_without_persist = False
                raise OSError("fake status write failed without persistence")
            status_id = self.state["next_status_id"]
            self.state["next_status_id"] += 1
            row = {
                "id": status_id, "sha": sha, "state": state, "context": context,
                "description": description, "target_url": target_url,
                "creator_database_id": Wave12ActivationPublicationExecutionTests.APP.bot_id,
                "creator_node_id": Wave12ActivationPublicationExecutionTests.APP.bot_node_id,
                "creator_login": Wave12ActivationPublicationExecutionTests.APP.bot_login, "creator_type": "Bot",
                "created_at": "2026-10-09T12:35:00Z", "updated_at": f"2026-10-09T12:35:{status_id:02d}Z",
            }
            self.state["status_rows"].append(row)
            self.state["durable_writes"]["status"] += 1
            self.status_writes.append(dict(row))
            receipt = SimpleNamespace(returned_status=CommitStatus(
                status_id, None, state, context, description, target_url,
                Wave12ActivationPublicationExecutionTests.APP.bot_id,
                Wave12ActivationPublicationExecutionTests.APP.bot_node_id,
                Wave12ActivationPublicationExecutionTests.APP.bot_login, "Bot",
                row["created_at"], row["updated_at"],
            ))
            if self.accept_status_then_lose_response:
                self.accept_status_then_lose_response = False
                raise OSError("fake accepted status but dropped the response")
            return receipt

        def list_open_pull_requests(self, repository, *, max_pages):
            self.trace.append(("inventory_pr", repository, max_pages))
            self.reads["inventory_pr"] += 1
            return ()

        def list_repository_issues(self, repository, *, state, max_pages):
            self.trace.append(("inventory_issue", repository, state, max_pages))
            self.reads["inventory_issue"] += 1
            return ()

        def list_machine_refs(self, repository, *, max_pages):
            self.trace.append(("inventory_machine", repository, max_pages))
            self.reads["inventory_machine"] += 1
            return ()

    class PublicationController(controller_module.R02Controller):
        def __init__(self, client, boundary):
            super().__init__(
                client,
                "swiftstream/skills",
                Wave12ActivationPublicationExecutionTests.APP,
                environ={"FEDERATION_TRUSTED_CHECKOUT_SHA": boundary.merged_result_oid},
            )
            self.boundary = boundary

        def derive_activation_boundary_evidence(self):
            self.client.trace.append(("boundary", self.boundary.activation_boundary_id))
            return self.boundary

    def boundary_from_durable_state(self, raw_state):
        value = json.loads(raw_state)["boundary"]
        return rm.ActivationBoundaryEvidence(
            value["schema_version"], value["central_repository_node_id"], value["implementation_pr_number"],
            value["implementation_pr_database_id"], value["implementation_pr_node_id"],
            value["implementation_reviewed_head_sha"], value["merged_result_oid"],
            value["authority_surface_digest"], value["new_writer_topology_digest"], value["activation_boundary_id"],
        )

    def controller(self, client, boundary):
        return self.PublicationController(client, boundary)

    def new_publication_process(self):
        boundary = self.boundary_from_durable_state(json.dumps(
            self.PlatformClient.initial_state(self.test, Wave12ActivationGuardSnapshotTests.boundary())
        ))
        client = self.PlatformClient(self.test, self.PlatformClient.initial_state(self.test, boundary))
        controller = self.controller(client, boundary)
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            preflight = controller._g8_activation_preflight(boundary)
            empty = controller_module.Wave08UniversalRecoveryResult(
                True, 0, 0, 0, 0, 0, 0, (), (), (), (), (), (), 0,
            )
            post_digest = rm.activation_recovery_inventory_digest(
                "POST", controller._g8_activation_inventory_material(empty, preflight),
            )
            witness = rm.ActivationRecoveryWitness(
                1, boundary.activation_boundary_id, 7001, 2, "4" * 64,
                rm.ordered_recovery_actions_digest(()), post_digest, 0,
                preflight.old_run_terminal_digest, preflight.six_workflow_identity_digest,
            )
            evidence = rm.ActivationRecoveryEvidence(
                1, "G8_ACTIVATION_RECOVERY", boundary.central_repository_node_id,
                boundary.implementation_pr_number, boundary.implementation_pr_database_id,
                boundary.implementation_pr_node_id, boundary.activation_boundary_id,
                boundary.merged_result_oid, boundary.authority_surface_digest,
                boundary.new_writer_topology_digest, witness.activation_run_id,
                witness.activation_run_attempt, witness.pre_recovery_inventory_digest,
                witness.ordered_recovery_actions_digest, 0, witness.post_recovery_inventory_digest,
                0, witness.old_run_terminal_digest, witness.six_workflow_identity_digest,
                "9" * 64, witness.witness_id(), "SUCCESS",
            )
            client.state["comments"] = [{
                "node_id": "IC_10", "database_id": 10, "body": evidence.render(),
                "author_id": self.APP.bot_node_id, "author_login": self.APP.bot_login,
                "author_type": "Bot", "editor_id": None, "editor_login": None,
                "editor_type": None, "edited_at": None, "is_edited": False,
            }]
            client.state["selected_result_digest"] = evidence.result_digest()
            execution = controller_module.G8ActivationRecoveryExecution(
                preflight, (), witness, evidence, evidence.result_digest(), 10,
            )
        return controller, client, boundary, execution

    def test_publisher_builds_exact_hae_ref_and_status_and_repeated_attempt_is_idempotent(self):
        controller, client, _boundary, execution = self.new_publication_process()
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            record, hae = controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
            second_record, second_hae = controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(record.render(), second_record.render())
        self.test.assertEqual((hae, second_hae), (self.HAE, self.HAE))
        self.test.assertEqual(len(client.blob_writes), 1)
        self.test.assertEqual(len(client.tree_writes), 1)
        submitted_base, submitted_entries = client.tree_writes[0]
        self.test.assertEqual(submitted_base, "3" * 40)
        self.test.assertEqual(submitted_entries, [{
            "path": controller_module.G8_ACTIVATION_RECORD_PATH,
            "mode": "100644",
            "type": "blob",
            "sha": client.blob_writes[0],
        }])
        base_rows = client.state["main_entries"]
        readback_rows = client.state["tree_entries_by_sha"][client.commit_writes[0][1]]
        expected_rows = base_rows + [{
            "path": controller_module.G8_ACTIVATION_RECORD_PATH,
            "mode": "100644",
            "object_type": "blob",
            "sha": client.blob_writes[0],
        }]
        self.test.assertEqual(readback_rows, expected_rows)
        self.test.assertEqual(len(client.commit_writes), 1)
        self.test.assertEqual(len(client.ref_writes), 1)
        self.test.assertEqual(len(client.status_writes), 1)
        message, _tree, parents, timestamp = client.commit_writes[0]
        self.test.assertEqual(parents, (record.merged_result_oid,))
        self.test.assertEqual(timestamp, "2026-10-09T12:34:56Z")
        self.test.assertEqual(message, "swiftstream-federation-g8-activation:v1\n" +
                              f"boundary={record.activation_boundary_id}\nrecord={rm.activation_record_digest(record)}")
        self.test.assertEqual(client.ref_writes[0][0][1:], ("0" * 40, self.HAE, False))
        self.test.assertEqual(client.status_writes[0]["description"], rm.activation_status_description(record, hae, record.activation_boundary_id))

    def test_hae_commit_created_with_activation_ref_absent_is_recoverable_state(self):
        controller, client, _boundary, execution = self.new_publication_process()
        client.crash_after_commit_create = True
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaises(self.CrashPoint):
                controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(len(client.commit_writes), 1)
        self.test.assertEqual(client.ref_oid, None)
        self.test.assertEqual(client.ref_writes, [])
        self.test.assertEqual(client.status_writes, [])
        guard = controller.derive_g8_activation_guard()
        self.test.assertIs(guard.runtime_state, controller_module.G8RuntimeState.MERGED_UNPROVEN)
        self.test.assertFalse(guard.ordinary_write_allowed)
        self.test.assertTrue(guard.activation_write_allowed)

    def test_writer_handles_status_response_loss_and_one_fully_revalidated_absence_retry(self):
        controller, client, _boundary, execution = self.new_publication_process()
        client.accept_status_then_lose_response = True
        client.ref_retry_then_success = True
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            record, hae = controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual((hae, client.state["ref_oid"]), (self.HAE, self.HAE))
        self.test.assertEqual(len(client.ref_writes), 2)
        self.test.assertEqual(len(client.status_writes), 1)
        updates = [
            (index, event) for index, event in enumerate(client.trace)
            if event[0] == "update_refs"
        ]
        self.test.assertEqual(len(updates), 2)
        exact_update = ((rm.G8_ACTIVATION_REF, "0" * 40, self.HAE, False),)
        self.test.assertEqual([event for _index, event in updates], [("update_refs", exact_update)] * 2)
        first_index, _first = updates[0]
        second_index, _second = updates[1]
        retry_proof = client.trace[first_index + 1:second_index]
        labels = [event[0] for event in retry_proof]
        self.assertEqual(labels[0], "ref_read")  # fresh read after ambiguous first CAS
        self.assertIn(("main", "main"), retry_proof)
        self.assertTrue(any(event[0] == "compare_main" for event in retry_proof))
        self.assertTrue(all(("workflow_path", path) in retry_proof for path in rm.G8_NEW_WRITER_PATHS))
        self.assertTrue(all(("workflow_runs", workflow_id) in retry_proof for _path, workflow_id in rm.G8_OLD_WRITERS))
        self.assertIn(("comments", 27), retry_proof)
        self.assertGreaterEqual(labels.count("comments"), 2)
        self.assertIn("inventory_pr", labels)
        self.assertIn("inventory_issue", labels)
        self.assertIn("inventory_machine", labels)
        boundary_positions = [index for index, event in enumerate(retry_proof) if event[0] == "boundary"]
        ref_positions = [index for index, event in enumerate(retry_proof) if event[0] == "ref_read"]
        self.assertGreaterEqual(len(boundary_positions), 2)
        self.assertGreaterEqual(len(ref_positions), 2)  # ambiguous-response and final revalidation reads
        self.assertGreater(boundary_positions[-1], retry_proof.index(("inventory_machine", "swiftstream/skills", 100)))
        self.assertGreater(ref_positions[-1], boundary_positions[-1])
        self.assertGreater(retry_proof.index(("comments", 27), ref_positions[-1]), ref_positions[-1])
        self.test.assertEqual(client.status_writes[0]["description"], rm.activation_status_description(record, hae, record.activation_boundary_id))

    def test_ambiguous_cas_fresh_read_failure_never_retries_or_publishes_status(self):
        controller, client, _boundary, execution = self.new_publication_process()
        client.ref_retry_then_success = True
        client.fail_ref_read_after_cas_failure = True
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaises(controller_module.R02Error):
                controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(len(client.ref_writes), 1)
        self.test.assertEqual(client.status_writes, [])
        self.test.assertEqual(client.status_attempts, [])
        self.test.assertEqual(client.state["ref_oid"], None)

    def test_status_write_without_persistence_revalidates_before_one_exact_retry(self):
        controller, client, _boundary, execution = self.new_publication_process()
        client.fail_status_once_without_persist = True
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            record, hae = controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(len(client.status_attempts), 2)
        first = client.status_attempts[0]
        self.test.assertEqual(client.status_attempts[1], first)
        self.test.assertEqual(first, (
            "swiftstream/skills", self.HAE, "success", rm.G8_ACTIVATION_STATUS_CONTEXT,
            rm.activation_status_description(record, hae, record.activation_boundary_id), None,
        ))
        self.test.assertEqual(len(client.status_writes), 1)
        writes = [
            index for index, event in enumerate(client.trace) if event[0] == "status_write"
        ]
        self.assertEqual(len(writes), 2)
        retry_proof = client.trace[writes[0] + 1:writes[1]]
        labels = [event[0] for event in retry_proof]
        self.assertIn("status_read", labels)
        self.assertIn(("main", "main"), retry_proof)
        self.assertTrue(any(event[0] == "compare_main" for event in retry_proof))
        self.assertTrue(all(("workflow_path", path) in retry_proof for path in rm.G8_NEW_WRITER_PATHS))
        self.assertTrue(all(("workflow_runs", workflow_id) in retry_proof for _path, workflow_id in rm.G8_OLD_WRITERS))
        self.assertIn(("comments", 27), retry_proof)
        self.assertGreaterEqual(labels.count("comments"), 2)
        self.assertIn("inventory_pr", labels)
        self.assertIn("inventory_issue", labels)
        self.assertIn("inventory_machine", labels)
        self.assertLessEqual(len(client.status_attempts), 2)
        second_write = writes[1]
        self.assertTrue(any(
            index > second_write and event == ("status_read", self.HAE)
            for index, event in enumerate(client.trace)
        ))
        self.assertEqual(len(client.state["status_rows"]), 1)
        latest = max(client.state["status_rows"], key=lambda row: (row["updated_at"], row["created_at"], row["id"]))
        self.assertEqual((latest["sha"], latest["state"], latest["context"], latest["description"]), first[1:5])

    def test_writer_fails_closed_on_transient_read_third_ref_and_conflicting_status(self):
        controller, client, _boundary, execution = self.new_publication_process()
        client.fail_next_ref_read = True
        from unittest.mock import patch
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaises(OSError):
                controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(client.blob_writes, [])

        controller, client, _boundary, execution = self.new_publication_process()
        client.third_value_on_ref_write = True
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaisesRegex(controller_module.R02Error, "third value"):
                controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(client.state["ref_oid"], "1" * 40)
        self.test.assertEqual(len(client.ref_writes), 1)
        self.test.assertEqual(client.status_writes, [])

        controller, client, boundary, execution = self.new_publication_process()
        client.state["status_rows"].append({
            "id": 1, "sha": self.MAIN, "state": "failure", "context": rm.G8_ACTIVATION_STATUS_CONTEXT,
            "description": "conflicting", "target_url": None,
            "creator_database_id": self.APP.bot_id, "creator_node_id": self.APP.bot_node_id,
            "creator_login": self.APP.bot_login, "creator_type": "Bot",
            "created_at": "2026-10-09T12:35:00Z", "updated_at": "2026-10-09T12:35:00Z",
        })
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaises(controller_module.R02Error):
                controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        self.test.assertEqual(client.blob_writes, [])
        self.test.assertIsNotNone(boundary)

        controller, client, boundary, execution = self.new_publication_process()
        client.crash_after_ref_persist = True
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaises(self.CrashPoint):
                controller.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
        client.state["status_rows"].append({
            "id": 1, "sha": self.HAE, "state": "failure", "context": rm.G8_ACTIVATION_STATUS_CONTEXT,
            "description": "conflicting", "target_url": None,
            "creator_database_id": self.APP.bot_id, "creator_node_id": self.APP.bot_node_id,
            "creator_login": self.APP.bot_login, "creator_type": "Bot",
            "created_at": "2026-10-09T12:35:00Z", "updated_at": "2026-10-09T12:35:00Z",
        })
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            with self.test.assertRaises(controller_module.R02Error):
                controller.resume_g8_activation_epoch()
        self.test.assertEqual(client.status_writes, [])
        self.test.assertIsNotNone(boundary)

    def test_resume_rejects_missing_edited_malformed_wrong_app_wrong_boundary_and_wrong_digest_evidence(self):
        cases = ("missing", "edited", "malformed", "wrong_app", "wrong_boundary", "wrong_digest")
        for case in cases:
            with self.test.subTest(case=case):
                p1, p1_client, boundary, execution = self.new_publication_process()
                p1_client.crash_after_ref_persist = True
                from unittest.mock import patch
                with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
                    with self.test.assertRaises(self.CrashPoint):
                        p1.publish_g8_activation_epoch(execution, created_at="2026-10-09T12:34:56Z")
                durable_state = p1_client.serialize_durable_state()
                del p1, p1_client, execution
                p2_boundary = self.boundary_from_durable_state(durable_state)
                p2_client = self.PlatformClient.from_durable_state(self.test, durable_state)
                p2 = self.controller(p2_client, p2_boundary)
                original_record = p2._read_g8_activation_epoch(p2_boundary, self.HAE)
                rows = p2_client.state["comments"]
                if case == "missing":
                    rows.clear()
                elif case == "edited":
                    rows[0]["is_edited"] = True
                elif case == "malformed":
                    rows[0]["body"] = rm.G8_ACTIVATION_RECOVERY_EVIDENCE_MARKER + "\nnot-json\n"
                elif case == "wrong_app":
                    rows[0]["author_id"] = "U_wrong"
                    rows[0]["author_login"] = "wrong[bot]"
                elif case == "wrong_boundary":
                    other_boundary = Wave12ActivationGuardSnapshotTests.boundary(surface="c" * 64)
                    other_evidence = Wave12ActivationGuardSnapshotTests.evidence(other_boundary)
                    wrong_boundary_record = Wave12ActivationGuardSnapshotTests.record(p2_boundary, other_evidence)
                    blob_sha = "b" * 40
                    tree_sha = "c" * 40
                    p2_client.state["blob_bytes_by_sha"][blob_sha] = wrong_boundary_record.render().encode().hex()
                    p2_client.state["tree_entries_by_sha"][tree_sha] = [
                        dict(entry) for entry in p2_client.state["tree_entries_by_sha"][p2_client.state["commit_by_sha"][self.HAE]["tree_sha"]]
                    ]
                    record_entry = next(
                        entry for entry in p2_client.state["tree_entries_by_sha"][tree_sha]
                        if entry["path"] == controller_module.G8_ACTIVATION_RECORD_PATH
                    )
                    record_entry["sha"] = blob_sha
                    p2_client.state["commit_by_sha"][self.HAE]["tree_sha"] = tree_sha
                    p2_client.state["commit_by_sha"][self.HAE]["message"] = (
                        "swiftstream-federation-g8-activation:v1\n"
                        f"boundary={p2_boundary.activation_boundary_id}\n"
                        f"record={rm.activation_record_digest(wrong_boundary_record)}"
                    )
                    rows[0]["body"] = other_evidence.render()
                elif case == "wrong_digest":
                    other_evidence = Wave12ActivationGuardSnapshotTests.evidence(
                        p2_boundary, legacy_digest="f" * 64,
                    )
                    self.test.assertNotEqual(
                        other_evidence.result_digest(),
                        original_record.activation_recovery_result_digest,
                    )
                    rows[0]["body"] = other_evidence.render()
                if case == "wrong_boundary":
                    selected_record = p2._read_g8_activation_epoch(p2_boundary, self.HAE)
                    self.test.assertEqual(
                        selected_record.activation_recovery_result_digest,
                        other_evidence.result_digest(),
                    )
                    self.test.assertEqual(
                        selected_record.activation_recovery_witness_id,
                        other_evidence.activation_recovery_witness_id,
                    )
                with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
                    if case == "wrong_boundary":
                        expected = "does not bind the activation record/current boundary"
                    elif case == "wrong_digest":
                        expected = "selected recovery evidence is missing"
                    else:
                        expected = None
                    if expected is None:
                        with self.test.assertRaises(controller_module.R02Error):
                            p2.resume_g8_activation_epoch()
                    else:
                        with self.test.assertRaisesRegex(controller_module.R02Error, expected):
                            p2.resume_g8_activation_epoch()
                self.test.assertEqual(p2_client.status_writes, [])
                self.test.assertEqual(p2_client.blob_writes, [])
                self.test.assertEqual(p2_client.tree_writes, [])
                self.test.assertEqual(p2_client.commit_writes, [])
                self.test.assertEqual(p2_client.ref_writes, [])
                self.test.assertGreaterEqual(p2_client.reads["comments"], 1)
                guard = p2.derive_g8_activation_guard()
                self.test.assertIs(
                    guard.runtime_state,
                    controller_module.G8RuntimeState.BLOCKED_POST_MERGE,
                )
                self.test.assertFalse(guard.ordinary_write_allowed)
                self.test.assertFalse(guard.activation_write_allowed)


class Wave12CurrentAuthoritySurfaceTests(unittest.TestCase):
    APP = Wave12ActivationGuardSnapshotTests.APP
    BOUNDARY = Wave12ActivationGuardSnapshotTests.boundary()
    MAIN = "d" * 40

    class SurfaceClient:
        def __init__(self, test, *, drift=False):
            self.test = test
            self.drift = drift
            paths = sorted(controller_module.R02Controller._g8_authority_surface_paths())
            self.merged = tuple(
                GitTreeEntry(path, "100644", "blob", f"{index + 1:040x}")
                for index, path in enumerate(paths)
            )
            current = list(self.merged)
            if drift:
                current[0] = GitTreeEntry(
                    current[0].path,
                    current[0].mode,
                    current[0].object_type,
                    "f" * 40,
                )
            self.current = tuple(current)

        def get_repository_metadata(self, repository):
            self.test.assertEqual(repository, "swiftstream/skills")
            return RepositoryMetadata(
                1351054671,
                rm.G8_CENTRAL_REPOSITORY_NODE_ID,
                "swiftstream/skills",
                "main",
            )

        def get_ref_oid(self, repository, branch):
            self.test.assertEqual((repository, branch), ("swiftstream/skills", "main"))
            return Wave12CurrentAuthoritySurfaceTests.MAIN

        def compare_commits(self, repository, base, head):
            self.test.assertEqual(
                (repository, base, head),
                (
                    "swiftstream/skills",
                    Wave12CurrentAuthoritySurfaceTests.BOUNDARY.merged_result_oid,
                    Wave12CurrentAuthoritySurfaceTests.MAIN,
                ),
            )
            return "ahead", base, base

        def get_commit_tree(self, repository, sha):
            if sha == Wave12CurrentAuthoritySurfaceTests.BOUNDARY.merged_result_oid:
                return "1" * 40, self.merged
            if sha == Wave12CurrentAuthoritySurfaceTests.MAIN:
                return "2" * 40, self.current
            raise AssertionError(sha)

    def controller(self, *, drift=False, trusted=None):
        return controller_module.R02Controller(
            self.SurfaceClient(self, drift=drift),
            "swiftstream/skills",
            self.APP,
            environ={
                "FEDERATION_TRUSTED_CHECKOUT_SHA": trusted or self.MAIN,
            },
        )

    def test_exact_current_surface_and_containment_pass(self):
        self.assertEqual(
            self.controller()._require_current_g8_guard_surface(self.BOUNDARY),
            self.MAIN,
        )

    def test_surface_drift_or_stale_checkout_fails_closed(self):
        with self.assertRaises(controller_module.R02Error):
            self.controller(drift=True)._require_current_g8_guard_surface(self.BOUNDARY)
        with self.assertRaises(controller_module.R02Error):
            self.controller(trusted="0" * 40)._require_current_g8_guard_surface(self.BOUNDARY)


class Wave12ActivationAuthorizationAndPreflightTests(unittest.TestCase):
    APP = Wave12ActivationGuardSnapshotTests.APP
    BOUNDARY = Wave12ActivationGuardSnapshotTests.boundary()
    MAIN = BOUNDARY.merged_result_oid

    class AuthorizationClient:
        def __init__(self, permission="admin"):
            self.permission = permission

        def get_repository_metadata(self, repository):
            if repository != "swiftstream/skills":
                raise AssertionError(repository)
            return RepositoryMetadata(
                1351054671,
                rm.G8_CENTRAL_REPOSITORY_NODE_ID,
                "swiftstream/skills",
                "main",
            )

        def get_collaborator_permission(self, repository, actor):
            if (repository, actor) != ("swiftstream/skills", "maintainer"):
                raise AssertionError((repository, actor))
            return self.permission

    class AuthorizationController(controller_module.R02Controller):
        def derive_g8_activation_guard(self):
            return controller_module._g8_activation_guard_result(
                controller_module.G8RuntimeState.MERGED_UNPROVEN,
            )

    def authorization_controller(self, *, permission="admin", environ=None):
        values = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "maintainer",
            "GITHUB_RUN_ID": "7001",
            "GITHUB_RUN_ATTEMPT": "2",
        }
        if environ:
            values.update(environ)
        return self.AuthorizationController(
            self.AuthorizationClient(permission),
            "swiftstream/skills",
            self.APP,
            environ=values,
        )

    def test_activation_authorization_requires_exact_admin_dispatch_main_and_run_identity(self):
        controller = self.authorization_controller()
        self.assertEqual(
            controller._require_g8_activation_run_authority("activate-g8"),
            (7001, 2, "maintainer"),
        )
        for kwargs in (
            {"permission": "maintain"},
            {"environ": {"GITHUB_EVENT_NAME": "push"}},
            {"environ": {"GITHUB_REF": "refs/heads/topic"}},
            {"environ": {"GITHUB_RUN_ID": "0"}},
            {"environ": {"GITHUB_RUN_ATTEMPT": "01"}},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(controller_module.R02Error):
                    self.authorization_controller(**kwargs)._require_g8_activation_run_authority(
                        "activate-g8",
                    )
        with self.assertRaises(controller_module.R02Error):
            controller._require_g8_activation_run_authority("recover")
        with patch.object(
            controller,
            "derive_g8_activation_guard",
            return_value=controller_module._g8_activation_guard_result(
                controller_module.G8RuntimeState.ACTIVE_G8,
            ),
        ):
            with self.assertRaises(controller_module.R02Error):
                controller._require_g8_activation_run_authority("activate-g8")

    def test_read_only_preflight_decision_requires_exact_context_and_admin(self):
        env = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "maintainer",
            "GITHUB_RUN_ID": "7001",
            "GITHUB_RUN_ATTEMPT": "2",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": "f" * 40,
            "INPUT_MODE": "activate-g8",
        }
        controller = self.gate_controller(self.PreflightClient(self))
        controller.environ = env
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            self.assertEqual(controller.g8_activation_preflight_decision(), "READY")
        for state, expected in (
            (controller_module.G8RuntimeState.ACTIVE_G8, "ACTIVE_NOOP"),
            (controller_module.G8RuntimeState.BLOCKED_POST_MERGE, "BLOCKED"),
        ):
            with patch.object(
                controller,
                "derive_g8_activation_guard",
                return_value=controller_module._g8_activation_guard_result(state),
            ):
                self.assertEqual(controller.g8_activation_preflight_decision(), expected)
        for changes in (
            {"INPUT_MODE": "recover"},
            {"GITHUB_EVENT_NAME": "schedule"},
            {"GITHUB_REF": "refs/heads/topic"},
            {"GITHUB_RUN_ID": "01"},
        ):
            with self.subTest(changes=changes):
                bad = self.authorization_controller(environ={**env, **changes})
                with self.assertRaises(controller_module.R02Error):
                    bad.g8_activation_preflight_decision()
        denied = self.authorization_controller(permission="maintain", environ=env)
        with self.assertRaises(controller_module.R02Error):
            denied.g8_activation_preflight_decision()

    class PreflightClient:
        def __init__(
            self,
            test,
            *,
            old_active=False,
            nonterminal=False,
            path_drift=False,
            id_drift=False,
            state_drift=False,
            old_path_present=False,
            activation_ref=None,
        ):
            self.test = test
            self.old_active = old_active
            self.nonterminal = nonterminal
            self.path_drift = path_drift
            self.id_drift = id_drift
            self.state_drift = state_drift
            self.activation_ref = activation_ref
            self.calls = []
            self.entries = tuple(
                GitTreeEntry(path, "100644", "blob", f"{index + 1:040x}")
                for index, path in enumerate(rm.G8_NEW_WRITER_PATHS)
            )
            if old_path_present:
                self.entries += (
                    GitTreeEntry(rm.G8_OLD_WRITERS[0][0], "100644", "blob", "f" * 40),
                )
            self.new_metadata = {
                path: WorkflowMetadata(
                    1000 + index,
                    f"W_new_{index}",
                    f"new-{index}",
                    path,
                    "active",
                )
                for index, path in enumerate(rm.G8_NEW_WRITER_PATHS)
            }
            self.old_metadata = {
                workflow_id: WorkflowMetadata(
                    workflow_id,
                    f"W_old_{index}",
                    f"old-{index}",
                    path,
                    "active" if old_active and index == 0 else "disabled_manually",
                )
                for index, (path, workflow_id) in enumerate(rm.G8_OLD_WRITERS)
            }

        def get_repository_metadata(self, repository):
            self.test.assertEqual(repository, "swiftstream/skills")
            return RepositoryMetadata(
                1351054671,
                rm.G8_CENTRAL_REPOSITORY_NODE_ID,
                "swiftstream/skills",
                "main",
            )

        def get_ref_oid(self, repository, branch):
            self.test.assertEqual((repository, branch), ("swiftstream/skills", "main"))
            return Wave12ActivationAuthorizationAndPreflightTests.MAIN

        def get_commit_tree(self, repository, sha):
            self.test.assertEqual(
                (repository, sha),
                ("swiftstream/skills", Wave12ActivationAuthorizationAndPreflightTests.MAIN),
            )
            return "a" * 40, self.entries

        def get_blob(self, repository, sha):
            self.test.assertEqual(repository, "swiftstream/skills")
            return f"blob:{sha}".encode()

        def get_workflow_metadata_by_path(self, repository, path):
            self.calls.append(("workflow-path", path))
            self.test.assertEqual(repository, "swiftstream/skills")
            metadata = self.new_metadata[path]
            if self.path_drift and path == rm.G8_NEW_WRITER_PATHS[0]:
                return self.new_metadata[rm.G8_NEW_WRITER_PATHS[1]]
            if self.state_drift and path == rm.G8_NEW_WRITER_PATHS[0]:
                return WorkflowMetadata(
                    metadata.id, metadata.name, metadata.node_id, metadata.path, "disabled_manually",
                )
            return metadata

        def get_workflow_metadata_by_id(self, repository, workflow_id):
            self.test.assertEqual(repository, "swiftstream/skills")
            for metadata in self.new_metadata.values():
                if metadata.id == workflow_id:
                    if self.id_drift and metadata.path == rm.G8_NEW_WRITER_PATHS[0]:
                        return WorkflowMetadata(
                            metadata.id + 1, metadata.name, metadata.node_id, metadata.path, metadata.state,
                        )
                    return metadata
            return self.old_metadata[workflow_id]

        def list_workflow_runs(self, repository, workflow_id, *, max_pages=100):
            self.calls.append(("workflow-runs", workflow_id))
            self.test.assertEqual((repository, max_pages), ("swiftstream/skills", 100))
            status = "in_progress" if self.nonterminal and workflow_id == rm.G8_OLD_WRITERS[0][1] else "completed"
            return (
                WorkflowRunMetadata(
                    workflow_id + 10_000,
                    1,
                    status,
                    None if status != "completed" else "success",
                    workflow_id,
                    "push",
                    "main",
                    "b" * 40,
                ),
            )

        def get_optional_ref_oid(self, repository, branch):
            self.calls.append(("activation-ref", branch, self.activation_ref))
            self.test.assertEqual(
                (repository, branch),
                ("swiftstream/skills", "bot/federation-g8-activation"),
            )
            return self.activation_ref

        def list_commit_statuses(self, repository, sha):
            self.test.assertEqual(
                (repository, sha),
                ("swiftstream/skills", Wave12ActivationAuthorizationAndPreflightTests.MAIN),
            )
            return ()

        def get_collaborator_permission(self, repository, actor):
            self.test.assertEqual((repository, actor), ("swiftstream/skills", "maintainer"))
            return "admin"

    class PreflightController(controller_module.R02Controller):
        def __init__(self, client, app, boundary):
            super().__init__(
                client,
                "swiftstream/skills",
                app,
                environ={"FEDERATION_TRUSTED_CHECKOUT_SHA": boundary.merged_result_oid},
            )
            self._boundary = boundary

        def derive_activation_boundary_evidence(self):
            return self._boundary

        def _require_current_g8_guard_surface(self, boundary):
            if boundary != self._boundary:
                raise controller_module.R02Error("boundary drift")
            return boundary.merged_result_oid

    class GatePreflightController(PreflightController):
        def derive_g8_activation_guard(self):
            return controller_module._g8_activation_guard_result(
                controller_module.G8RuntimeState.MERGED_UNPROVEN,
            )

    def gate_controller(self, client):
        controller = self.GatePreflightController(client, self.APP, self.BOUNDARY)
        controller.environ = {
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_ACTOR": "maintainer",
            "GITHUB_RUN_ID": "7001",
            "GITHUB_RUN_ATTEMPT": "2",
            "FEDERATION_TRUSTED_CHECKOUT_SHA": self.BOUNDARY.merged_result_oid,
            "INPUT_MODE": "activate-g8",
        }
        return controller

    def test_ready_decision_runs_complete_preflight_and_binds_exact_observed_ref(self):
        partial_hae = "c" * 40
        client = self.PreflightClient(self, activation_ref=partial_hae)
        controller = self.gate_controller(client)
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            self.assertEqual(controller.g8_activation_preflight_decision(), "READY")
        self.assertEqual(
            [call for call in client.calls if call[0] == "activation-ref"],
            [
                ("activation-ref", "bot/federation-g8-activation", partial_hae),
                ("activation-ref", "bot/federation-g8-activation", partial_hae),
            ],
        )
        self.assertEqual(
            len([call for call in client.calls if call[0] == "workflow-path"]),
            len(rm.G8_NEW_WRITER_PATHS),
        )
        self.assertEqual(
            len([call for call in client.calls if call[0] == "workflow-runs"]),
            len(rm.G8_OLD_WRITERS),
        )

    def test_ready_decision_fails_closed_on_full_preflight_rejections(self):
        for kwargs in (
            {"old_active": True},
            {"nonterminal": True},
            {"path_drift": True},
            {"id_drift": True},
            {"state_drift": True},
            {"old_path_present": True},
        ):
            with self.subTest(kwargs=kwargs):
                client = self.PreflightClient(self, **kwargs)
                controller = self.gate_controller(client)
                with (
                    patch.object(controller_module, "resolve_app_identity", return_value=self.APP),
                    self.assertRaises(controller_module.R02Error),
                ):
                    controller.g8_activation_preflight_decision()
                workflow_path_was_read = any(
                    call[0] == "workflow-path" for call in client.calls
                )
                if kwargs.get("old_path_present"):
                    self.assertFalse(workflow_path_was_read)
                else:
                    self.assertTrue(workflow_path_was_read)

    def test_activation_preflight_proves_old_absence_six_live_identities_and_terminal_runs(self):
        client = self.PreflightClient(self)
        controller = self.PreflightController(client, self.APP, self.BOUNDARY)
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            result = controller._g8_activation_preflight(self.BOUNDARY)
        self.assertEqual(result.current_main_oid, self.MAIN)
        self.assertEqual(tuple(item.path for item in result.new_workflows), rm.G8_NEW_WRITER_PATHS)
        self.assertEqual(len({item.workflow_id for item in result.new_workflows}), 6)
        self.assertRegex(result.old_path_absence_proof_digest, r"^[0-9a-f]{64}$")
        self.assertRegex(result.old_run_terminal_digest, r"^[0-9a-f]{64}$")
        self.assertRegex(result.six_workflow_identity_digest, r"^[0-9a-f]{64}$")

    def test_activation_preflight_rejects_active_old_writer_nonterminal_run_or_path_identity_drift(self):
        for kwargs in (
            {"old_active": True},
            {"nonterminal": True},
            {"path_drift": True},
            {"old_path_present": True},
        ):
            with self.subTest(kwargs=kwargs):
                client = self.PreflightClient(self, **kwargs)
                controller = self.PreflightController(client, self.APP, self.BOUNDARY)
                with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
                    with self.assertRaises(controller_module.R02Error):
                        controller._g8_activation_preflight(self.BOUNDARY)


class Wave12ActivationRecoveryPolicyTests(unittest.TestCase):
    APP = Wave12ActivationGuardSnapshotTests.APP
    BOUNDARY = Wave12ActivationGuardSnapshotTests.boundary()

    @classmethod
    def preflight(cls):
        proofs = tuple(
            controller_module.G8ActivationWorkflowProof(
                path,
                f"{index + 1:040x}",
                f"{index + 1:064x}",
                1000 + index,
                "active",
            )
            for index, path in enumerate(rm.G8_NEW_WRITER_PATHS)
        )
        return controller_module.G8ActivationPreflightResult(
            cls.BOUNDARY,
            cls.BOUNDARY.merged_result_oid,
            proofs,
            "1" * 64,
            "2" * 64,
            "3" * 64,
        )

    @staticmethod
    def empty_recovery(*, decisions=(), machine_refs=(), dispatch_intents=(), blocked_reasons=()):
        return controller_module.Wave08UniversalRecoveryResult(
            True,
            len(decisions),
            len(decisions),
            len(decisions),
            0,
            0,
            len(machine_refs),
            tuple(decisions),
            (),
            tuple(machine_refs),
            tuple(dispatch_intents),
            (),
            tuple(blocked_reasons),
            0,
        )

    def test_pre_recovery_blocker_filter_allows_only_exact_machine_recovery_blocker(self):
        head = "c" * 40
        decision = controller_module.Wave08Decision(
            head,
            rm.ShaCarrierResolution(rm.CarrierActivation.LEGACY_CUTOVER_QUARANTINE),
            (),
            None,
            controller_module.Wave08DecisionKind.LEGACY_QUARANTINE_DEFERRED,
            controller_module.Wave08DecisionReason.LEGACY_CLASSIFIER_DEFERRED,
        )
        record = controller_module.Wave08MachineRefRecord(
            "refs/heads/bot/federation/source-a",
            "source-a",
            head,
            "BLOCKED",
            "SHA_ROLE_DOES_NOT_AUTHORIZE_MACHINE_RECOVERY",
        )
        exact_reason = (
            "refs/heads/bot/federation/source-a:"
            "SHA_ROLE_DOES_NOT_AUTHORIZE_MACHINE_RECOVERY"
        )
        recoverable = self.empty_recovery(
            decisions=(decision,),
            machine_refs=(record,),
            blocked_reasons=(exact_reason,),
        )
        self.assertEqual(
            controller_module.R02Controller._g8_activation_fatal_pre_recovery_reasons(
                recoverable,
            ),
            (),
        )
        fatal = self.empty_recovery(
            decisions=(decision,),
            machine_refs=(record,),
            blocked_reasons=(exact_reason, "UNRELATED_FATAL_AUTHORITY_CONFLICT"),
        )
        self.assertEqual(
            controller_module.R02Controller._g8_activation_fatal_pre_recovery_reasons(
                fatal,
            ),
            ("UNRELATED_FATAL_AUTHORITY_CONFLICT",),
        )

    def test_post_machine_ref_must_be_fully_converged(self):
        converged = self.empty_recovery(machine_refs=(
            controller_module.Wave08MachineRefRecord(
                "refs/heads/bot/federation/source-a",
                "source-a",
                "a" * 40,
                "DISPATCHED",
                "EXACT_MACHINE_ROLE_AND_OWNER_PR_VALIDATED",
            ),
        ))
        controller_module.R02Controller._g8_require_post_machine_refs_converged(
            converged,
        )
        unresolved = self.empty_recovery(machine_refs=(
            controller_module.Wave08MachineRefRecord(
                "refs/heads/bot/federation/source-a",
                "source-a",
                "a" * 40,
                "DEFERRED_NO_OPEN_PR",
                "MACHINE_REF_IS_DISCOVERY_ONLY",
            ),
        ))
        with self.assertRaises(controller_module.R02Error):
            controller_module.R02Controller._g8_require_post_machine_refs_converged(
                unresolved,
            )

    def test_activation_recovery_source_has_no_passing_writer_or_dispatch_primitive(self):
        source = inspect.getsource(controller_module.R02Controller._run_g8_activation_recovery)
        for forbidden in (
            "publish_unclaimed_external_success",
            "publish_issue_final_success",
            "create_check_run",
            "dispatch_workflow",
            "merge_machine_pull_request",
        ):
            self.assertNotIn(forbidden, source)

    def test_task02_execution_has_no_activation_epoch_ref_or_status_writer(self):
        source = inspect.getsource(controller_module.R02Controller.run_g8_activation_recovery)
        for forbidden in (
            "create_blob",
            "create_tree",
            "create_commit(",
            "update_refs",
            "create_commit_status",
            "G8_ACTIVATION_REF",
            "G8_ACTIVATION_STATUS_CONTEXT",
            "activation_status_description",
        ):
            self.assertNotIn(forbidden, source)

    def test_external_success_is_not_published_pre_epoch(self):
        decision = controller_module.Wave08Decision(
            "a" * 40,
            rm.ShaCarrierResolution(rm.CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION),
            (7,),
            None,
            controller_module.Wave08DecisionKind.EXTERNAL_STATUS,
            controller_module.Wave08DecisionReason.EXPLICITLY_UNCLAIMED,
        )
        controller = controller_module.R02Controller(
            object(),
            "swiftstream/skills",
            self.APP,
            environ={},
        )
        actions = controller._run_g8_activation_recovery(
            self.BOUNDARY,
            self.preflight(),
            self.empty_recovery(decisions=(decision,)),
        )
        self.assertEqual(actions, ())

    def test_recovery_action_material_rejects_shape_and_policy_drift_before_hashing(self):
        controller = controller_module.R02Controller(
            object(),
            "swiftstream/skills",
            self.APP,
            environ={},
        )
        valid = controller._g8_recovery_action(
            0,
            rm.ActivationRecoveryActionClass.ISSUE_TERMINAL_CLEANUP,
            {
                "issueNumber": 7,
                "fenceId": "fence-7",
                "cancellationHeadSha": "a" * 40,
            },
            {
                "deferredUntil": "ACTIVE_G8",
                "reason": "CANCELLATION_CLEANUP_POST_ACTIVE",
            },
            rm.ActivationRecoveryResultClass.DEFERRED_POST_ACTIVE,
        )
        self.assertIs(
            valid.action_class,
            rm.ActivationRecoveryActionClass.ISSUE_TERMINAL_CLEANUP,
        )
        with self.assertRaises(controller_module.R02Error):
            controller._g8_recovery_action(
                0,
                rm.ActivationRecoveryActionClass.ISSUE_TERMINAL_CLEANUP,
                {
                    "issueNumber": 7,
                    "fenceId": "fence-7",
                    "cancellationHeadSha": "a" * 40,
                    "unexpected": "authority-drift",
                },
                {
                    "deferredUntil": "ACTIVE_G8",
                    "reason": "CANCELLATION_CLEANUP_POST_ACTIVE",
                },
                rm.ActivationRecoveryResultClass.DEFERRED_POST_ACTIVE,
            )
        with self.assertRaises(controller_module.R02Error):
            controller._g8_recovery_action(
                0,
                rm.ActivationRecoveryActionClass.ISSUE_TERMINAL_CLEANUP,
                {
                    "issueNumber": 7,
                    "fenceId": "fence-7",
                    "cancellationHeadSha": "a" * 40,
                },
                {
                    "deferredUntil": "ACTIVE_G8",
                    "reason": "ARBITRARY_REASON",
                },
                rm.ActivationRecoveryResultClass.DEFERRED_POST_ACTIVE,
            )
        with self.assertRaises(controller_module.R02Error):
            controller._g8_recovery_action(
                0,
                rm.ActivationRecoveryActionClass.RESERVED_TRANSITION_RECOVERY,
                {
                    "headSha": "b" * 40,
                    "role": rm.CarrierRole.MACHINE_PUBLICATION.value,
                    "owningPrNumber": 88,
                },
                {
                    "deferredUntil": "ACTIVE_G8",
                    "reason": "RESERVED_MACHINE_TRANSITION_POST_ACTIVE",
                },
                rm.ActivationRecoveryResultClass.DEFERRED_POST_ACTIVE,
            )

    class ReservedMachineController(controller_module.R02Controller):
        def __init__(self):
            self.head = "b" * 40
            self.marker = rm.ClaimedHeadMarker(
                "MACHINE_REF_CLAIM",
                rm.CarrierRole.MACHINE_PUBLICATION.value,
                "MACHINE_SOURCE",
                f"{rm.G8_CENTRAL_REPOSITORY_NODE_ID}:source-a",
                "c" * 64,
                "d" * 64,
                "MACHINE_PUBLICATION",
            )
            self.active = False
            self.reconcile_calls = []
            client = SimpleNamespace(
                get_ref_oid=lambda repository, branch: (
                    self.head
                    if (repository, branch) == (
                        "swiftstream/skills",
                        "bot/federation/source-a",
                    )
                    else (_ for _ in ()).throw(AssertionError((repository, branch)))
                ),
            )
            super().__init__(client, "swiftstream/skills", Wave12ActivationRecoveryPolicyTests.APP, environ={})

        def resolve_current_sha_carrier_role(self, head_sha):
            if head_sha != self.head:
                raise AssertionError(head_sha)
            return rm.ShaCarrierResolution(
                (
                    rm.CarrierActivation.ACTIVE
                    if self.active
                    else rm.CarrierActivation.RESERVED_INACTIVE
                ),
                rm.CarrierRole.MACHINE_PUBLICATION,
                self.marker,
            )

        def current_accepted_main(self):
            return (
                RepositoryMetadata(
                    1351054671,
                    rm.G8_CENTRAL_REPOSITORY_NODE_ID,
                    "swiftstream/skills",
                    "main",
                ),
                Wave12ActivationRecoveryPolicyTests.BOUNDARY.merged_result_oid,
            )

        def _accepted_sources(self, current_main=None):
            return (
                SimpleNamespace(source_id="source-a", repository_id=44),
            )

        def _g8_activation_recovery_mutation_guard(self, boundary):
            if boundary != Wave12ActivationRecoveryPolicyTests.BOUNDARY:
                raise AssertionError(boundary)

        def reconcile(
            self,
            repository_id,
            *,
            pre_mutation_guard=None,
            dispatch_finalizer=True,
            legacy_failure_receipt=None,
        ):
            self.reconcile_calls.append((
                repository_id,
                pre_mutation_guard,
                dispatch_finalizer,
                legacy_failure_receipt,
            ))
            if pre_mutation_guard is None:
                raise AssertionError("missing pre-mutation guard")
            if legacy_failure_receipt is not None:
                raise AssertionError("reserved machine recovery must not carry legacy failure evidence")
            pre_mutation_guard()
            self.active = True
            return controller_module.MachineReconcileResult(
                "CHANGED",
                "source-a",
                repository_id,
                "PERSISTED_MACHINE_PR_88",
            )

    def test_current_reserved_machine_ref_without_open_pr_recovers_before_epoch_without_dispatch(self):
        controller = self.ReservedMachineController()
        machine_ref = controller_module.Wave08MachineRefRecord(
            "refs/heads/bot/federation/source-a",
            "source-a",
            controller.head,
            "DEFERRED_NO_OPEN_PR",
            "MACHINE_REF_IS_DISCOVERY_ONLY",
        )
        actions = controller._run_g8_activation_recovery(
            self.BOUNDARY,
            self.preflight(),
            self.empty_recovery(machine_refs=(machine_ref,)),
        )
        self.assertEqual(len(actions), 1)
        self.assertIs(
            actions[0].action_class,
            rm.ActivationRecoveryActionClass.RESERVED_TRANSITION_RECOVERY,
        )
        self.assertIs(
            actions[0].result_class,
            rm.ActivationRecoveryResultClass.APPLIED,
        )
        self.assertTrue(controller.active)
        self.assertIs(controller.reconcile_calls[0][2], False)

    def test_represented_reserved_machine_decision_recovers_without_nullable_owner_shape(self):
        controller = self.ReservedMachineController()
        resolution = controller.resolve_current_sha_carrier_role(controller.head)
        decision = controller_module.Wave08Decision(
            controller.head,
            resolution,
            (88,),
            None,
            controller_module.Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED,
            controller_module.Wave08DecisionReason.MACHINE_AUTHORITY_PENDING,
        )
        machine_ref = controller_module.Wave08MachineRefRecord(
            "refs/heads/bot/federation/source-a",
            "source-a",
            controller.head,
            "DEFERRED",
            "SHA_ROLE_NOT_RESOLVED",
        )
        actions = controller._run_g8_activation_recovery(
            self.BOUNDARY,
            self.preflight(),
            self.empty_recovery(decisions=(decision,), machine_refs=(machine_ref,)),
        )
        self.assertEqual(len(actions), 1)
        self.assertIs(
            actions[0].action_class,
            rm.ActivationRecoveryActionClass.RESERVED_TRANSITION_RECOVERY,
        )
        self.assertIs(
            actions[0].result_class,
            rm.ActivationRecoveryResultClass.APPLIED,
        )
        self.assertTrue(controller.active)
        self.assertIs(controller.reconcile_calls[0][2], False)

    def test_unclaimed_machine_ref_without_open_pr_blocks_instead_of_disappearing_from_witness(self):
        class Unclaimed(self.ReservedMachineController):
            def resolve_current_sha_carrier_role(self, head_sha):
                if head_sha != self.head:
                    raise AssertionError(head_sha)
                return rm.ShaCarrierResolution(
                    rm.CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION,
                )

        controller = Unclaimed()
        machine_ref = controller_module.Wave08MachineRefRecord(
            "refs/heads/bot/federation/source-a",
            "source-a",
            controller.head,
            "DEFERRED_NO_OPEN_PR",
            "MACHINE_REF_IS_DISCOVERY_ONLY",
        )
        with self.assertRaises(controller_module.R02Error):
            controller._run_g8_activation_recovery(
                self.BOUNDARY,
                self.preflight(),
                self.empty_recovery(machine_refs=(machine_ref,)),
            )
        self.assertEqual(controller.reconcile_calls, [])

    class LegacyMachineController(controller_module.R02Controller):
        def __init__(self, evidence):
            self.after_head = "e" * 40
            self.after_marker = rm.ClaimedHeadMarker(
                "MACHINE_REF_CLAIM",
                rm.CarrierRole.MACHINE_PUBLICATION.value,
                "MACHINE_SOURCE",
                f"{rm.G8_CENTRAL_REPOSITORY_NODE_ID}:source-a",
                "a" * 64,
                "b" * 64,
                "MACHINE_PUBLICATION",
            )
            client = SimpleNamespace(
                get_ref_oid=lambda repository, branch: (
                    self.after_head
                    if (repository, branch) == ("swiftstream/skills", "bot/federation/source-a")
                    else (_ for _ in ()).throw(AssertionError((repository, branch)))
                ),
            )
            super().__init__(client, "swiftstream/skills", Wave12ActivationRecoveryPolicyTests.APP, environ={})
            self.evidence = evidence
            self.reconcile_calls = []

        def resolve_current_sha_carrier_role(self, head_sha):
            if head_sha == self.evidence.head_sha:
                return rm.ShaCarrierResolution(
                    rm.CarrierActivation.LEGACY_CUTOVER_QUARANTINE,
                )
            if head_sha == self.after_head:
                return rm.ShaCarrierResolution(
                    rm.CarrierActivation.ACTIVE,
                    rm.CarrierRole.MACHINE_PUBLICATION,
                    self.after_marker,
                )
            raise AssertionError(head_sha)

        def classify_legacy_head(self, head_sha, *, implementation_reviewed_head_sha):
            if head_sha != self.evidence.head_sha:
                raise AssertionError(head_sha)
            if implementation_reviewed_head_sha != Wave12ActivationRecoveryPolicyTests.BOUNDARY.implementation_reviewed_head_sha:
                raise AssertionError(implementation_reviewed_head_sha)
            return rm.LegacyClassificationResult(
                rm.LegacyClassificationOutcome.QUARANTINE,
                self.evidence,
                "EXACT_LEGACY_MACHINE",
            )

        def current_accepted_main(self):
            return (
                RepositoryMetadata(
                    1351054671,
                    rm.G8_CENTRAL_REPOSITORY_NODE_ID,
                    "swiftstream/skills",
                    "main",
                ),
                Wave12ActivationRecoveryPolicyTests.BOUNDARY.merged_result_oid,
            )

        def _accepted_sources(self, current_main):
            if current_main != Wave12ActivationRecoveryPolicyTests.BOUNDARY.merged_result_oid:
                raise AssertionError(current_main)
            return (SimpleNamespace(source_id="source-a", repository_id=44),)

        def _g8_activation_recovery_mutation_guard(self, boundary):
            if boundary != Wave12ActivationRecoveryPolicyTests.BOUNDARY:
                raise AssertionError(boundary)

        def publish_legacy_failure(
            self,
            head_sha,
            trusted_activation_boundary_id,
            *,
            implementation_reviewed_head_sha,
        ):
            if head_sha != self.evidence.head_sha:
                raise AssertionError(head_sha)
            digest = rm.legacy_status_evidence_digest(
                self.evidence,
                trusted_activation_boundary_id,
            )
            description = rm.render_status_description(rm.StatusClass.LEGACY, digest)
            status = CommitStatus(
                901,
                "CS_901",
                "failure",
                "federation/trusted-validation",
                description,
                None,
                self.app.bot_id,
                self.app.bot_node_id,
                self.app.bot_login,
                "Bot",
                "2026-10-10T00:00:00Z",
                "2026-10-10T00:00:00Z",
            )
            return controller_module.StatusWriteReceipt(
                "swiftstream/skills",
                head_sha,
                "POST",
                f"/repos/swiftstream/skills/statuses/{head_sha}",
                "failure",
                "federation/trusted-validation",
                description,
                None,
                status,
            )

        def reconcile(
            self,
            repository_id,
            *,
            pre_mutation_guard=None,
            dispatch_finalizer=True,
            legacy_failure_receipt=None,
        ):
            self.reconcile_calls.append((
                repository_id,
                pre_mutation_guard,
                dispatch_finalizer,
                legacy_failure_receipt,
            ))
            if pre_mutation_guard is None:
                raise AssertionError("missing pre-mutation guard")
            if legacy_failure_receipt is None:
                raise AssertionError("legacy failure receipt was not carried into canonical reconcile")
            pre_mutation_guard()
            return controller_module.MachineReconcileResult(
                "CHANGED",
                "source-a",
                repository_id,
                "MACHINE_PR_88",
            )

    def test_legacy_machine_recovery_uses_canonical_h2_reconcile_without_finalizer_dispatch(self):
        head = "c" * 40
        evidence = rm.LegacyQuarantineEvidence(
            1,
            rm.LegacyQuarantineClass.MACHINE,
            1351054671,
            rm.G8_CENTRAL_REPOSITORY_NODE_ID,
            "swiftstream/skills",
            head,
            "d" * 64,
        )
        decision = controller_module.Wave08Decision(
            head,
            rm.ShaCarrierResolution(rm.CarrierActivation.LEGACY_CUTOVER_QUARANTINE),
            (88,),
            None,
            controller_module.Wave08DecisionKind.LEGACY_QUARANTINE_DEFERRED,
            controller_module.Wave08DecisionReason.LEGACY_CLASSIFIER_DEFERRED,
        )
        machine_ref = controller_module.Wave08MachineRefRecord(
            "refs/heads/bot/federation/source-a",
            "source-a",
            head,
            "DEFERRED",
            "SHA_ROLE_NOT_RESOLVED",
        )
        controller = self.LegacyMachineController(evidence)
        actions = controller._run_g8_activation_recovery(
            self.BOUNDARY,
            self.preflight(),
            self.empty_recovery(decisions=(decision,), machine_refs=(machine_ref,)),
        )
        self.assertEqual(len(actions), 2)
        self.assertIs(
            actions[0].action_class,
            rm.ActivationRecoveryActionClass.LEGACY_FAILURE_STATUS,
        )
        self.assertIs(
            actions[0].result_class,
            rm.ActivationRecoveryResultClass.APPLIED,
        )
        self.assertIs(
            actions[1].action_class,
            rm.ActivationRecoveryActionClass.LEGACY_MACHINE_MIGRATION,
        )
        self.assertIs(
            actions[1].result_class,
            rm.ActivationRecoveryResultClass.APPLIED,
        )
        self.assertEqual(controller.reconcile_calls[0][0], 44)
        self.assertIs(controller.reconcile_calls[0][2], False)
        self.assertIsNotNone(controller.reconcile_calls[0][3])

    def test_legacy_machine_ref_without_open_pr_is_still_recovered_from_machine_inventory(self):
        head = "c" * 40
        evidence = rm.LegacyQuarantineEvidence(
            1,
            rm.LegacyQuarantineClass.MACHINE,
            1351054671,
            rm.G8_CENTRAL_REPOSITORY_NODE_ID,
            "swiftstream/skills",
            head,
            "d" * 64,
        )
        machine_ref = controller_module.Wave08MachineRefRecord(
            "refs/heads/bot/federation/source-a",
            "source-a",
            head,
            "DEFERRED_NO_OPEN_PR",
            "MACHINE_REF_IS_DISCOVERY_ONLY",
        )
        controller = self.LegacyMachineController(evidence)
        actions = controller._run_g8_activation_recovery(
            self.BOUNDARY,
            self.preflight(),
            self.empty_recovery(machine_refs=(machine_ref,)),
        )
        self.assertEqual(
            tuple(action.action_class for action in actions),
            (
                rm.ActivationRecoveryActionClass.LEGACY_FAILURE_STATUS,
                rm.ActivationRecoveryActionClass.LEGACY_MACHINE_MIGRATION,
            ),
        )
        self.assertEqual(len(controller.reconcile_calls), 1)


class Wave12ActivationRecoveryEvidencePersistenceTests(unittest.TestCase):
    APP = Wave12ActivationGuardSnapshotTests.APP
    BOUNDARY = Wave12ActivationGuardSnapshotTests.boundary()

    @classmethod
    def evidence(cls, *, legacy_digest="8" * 64):
        return Wave12ActivationGuardSnapshotTests.evidence(
            cls.BOUNDARY,
            legacy_digest=legacy_digest,
        )

    class EvidenceClient:
        def __init__(self, comments=(), *, append_on_create=True, raise_after_append=False):
            self.comments = list(comments)
            self.append_on_create = append_on_create
            self.raise_after_append = raise_after_append
            self.create_calls = 0

        def list_issue_comments(self, repository, number):
            if (repository, number) != ("swiftstream/skills", rm.G8_IMPLEMENTATION_PR_NUMBER):
                raise AssertionError((repository, number))
            return tuple(self.comments)

        def create_issue_comment(self, repository, number, body):
            if (repository, number) != ("swiftstream/skills", rm.G8_IMPLEMENTATION_PR_NUMBER):
                raise AssertionError((repository, number))
            self.create_calls += 1
            if self.append_on_create:
                self.comments.append(Wave12ActivationGuardSnapshotTests.app_comment(
                    body,
                    database_id=100 + self.create_calls,
                ))
            if self.raise_after_append:
                raise RuntimeError("response lost after durable POST")
            return self.comments[-1] if self.comments else SimpleNamespace()

    class PersistenceController(controller_module.R02Controller):
        def _g8_activation_recovery_mutation_guard(self, boundary):
            if boundary != Wave12ActivationRecoveryEvidencePersistenceTests.BOUNDARY:
                raise AssertionError(boundary)

    def controller(self, client):
        return self.PersistenceController(
            client,
            "swiftstream/skills",
            self.APP,
            environ={},
        )

    def test_exact_same_run_body_is_reused_without_post(self):
        evidence = self.evidence()
        comment = Wave12ActivationGuardSnapshotTests.app_comment(
            evidence.render(),
            database_id=41,
        )
        client = self.EvidenceClient((comment,))
        result = self.controller(client)._persist_g8_activation_recovery_evidence(
            evidence,
            self.APP,
            self.BOUNDARY,
        )
        self.assertEqual(result, 41)
        self.assertEqual(client.create_calls, 0)

    def test_equivalent_duplicate_same_run_bodies_collapse_to_lowest_database_id(self):
        evidence = self.evidence()
        comments = (
            Wave12ActivationGuardSnapshotTests.app_comment(
                evidence.render(),
                database_id=43,
            ),
            Wave12ActivationGuardSnapshotTests.app_comment(
                evidence.render(),
                database_id=41,
            ),
        )
        client = self.EvidenceClient(comments)
        result = self.controller(client)._persist_g8_activation_recovery_evidence(
            evidence,
            self.APP,
            self.BOUNDARY,
        )
        self.assertEqual(result, 41)
        self.assertEqual(client.create_calls, 0)

    def test_edited_exact_app_evidence_blocks_before_post(self):
        evidence = self.evidence()
        edited = Wave12ActivationGuardSnapshotTests.app_comment(
            evidence.render(),
            edited=True,
            database_id=44,
        )
        client = self.EvidenceClient((edited,))
        with self.assertRaises(controller_module.R02Error):
            self.controller(client)._persist_g8_activation_recovery_evidence(
                evidence,
                self.APP,
                self.BOUNDARY,
            )
        self.assertEqual(client.create_calls, 0)

    def test_same_run_different_exact_app_body_blocks(self):
        selected = self.evidence()
        conflicting = self.evidence(legacy_digest="f" * 64)
        client = self.EvidenceClient((
            Wave12ActivationGuardSnapshotTests.app_comment(
                conflicting.render(),
                database_id=42,
            ),
        ))
        with self.assertRaises(controller_module.R02Error):
            self.controller(client)._persist_g8_activation_recovery_evidence(
                selected,
                self.APP,
                self.BOUNDARY,
            )
        self.assertEqual(client.create_calls, 0)

    def test_ambiguous_post_is_resolved_only_by_full_durable_readback(self):
        evidence = self.evidence()
        client = self.EvidenceClient(raise_after_append=True)
        result = self.controller(client)._persist_g8_activation_recovery_evidence(
            evidence,
            self.APP,
            self.BOUNDARY,
        )
        self.assertEqual(result, 101)
        self.assertEqual(client.create_calls, 1)

    def test_successful_post_without_durable_readback_is_not_success(self):
        evidence = self.evidence()
        client = self.EvidenceClient(append_on_create=False)
        with self.assertRaises(controller_module.R02Error):
            self.controller(client)._persist_g8_activation_recovery_evidence(
                evidence,
                self.APP,
                self.BOUNDARY,
            )
        self.assertEqual(client.create_calls, 1)
        self.assertEqual(client.comments, [])

    def test_ambiguous_post_without_durable_readback_stops_fail_closed(self):
        evidence = self.evidence()
        client = self.EvidenceClient(
            append_on_create=False,
            raise_after_append=True,
        )
        with self.assertRaises(controller_module.R02Error):
            self.controller(client)._persist_g8_activation_recovery_evidence(
                evidence,
                self.APP,
                self.BOUNDARY,
            )
        self.assertEqual(client.create_calls, 1)
        self.assertEqual(client.comments, [])

    def test_foreign_marker_is_noise_but_exact_app_malformed_blocks(self):
        evidence = self.evidence()
        foreign = Wave12ActivationGuardSnapshotTests.foreign_comment(
            rm.G8_ACTIVATION_RECOVERY_EVIDENCE_MARKER + "\nnot-json\n",
            database_id=51,
        )
        client = self.EvidenceClient((foreign,))
        result = self.controller(client)._persist_g8_activation_recovery_evidence(
            evidence,
            self.APP,
            self.BOUNDARY,
        )
        self.assertEqual(result, 101)

        malformed = Wave12ActivationGuardSnapshotTests.app_comment(
            rm.G8_ACTIVATION_RECOVERY_EVIDENCE_MARKER + "\nnot-json\n",
            database_id=52,
        )
        with self.assertRaises(controller_module.R02Error):
            self.controller(self.EvidenceClient((malformed,)))._persist_g8_activation_recovery_evidence(
                evidence,
                self.APP,
                self.BOUNDARY,
            )


class Wave12ActivationRecoveryWitnessExecutionTests(unittest.TestCase):
    APP = Wave12ActivationGuardSnapshotTests.APP
    BOUNDARY = Wave12ActivationGuardSnapshotTests.boundary()

    @classmethod
    def preflight(cls):
        proofs = tuple(
            controller_module.G8ActivationWorkflowProof(
                path,
                f"{index + 20:040x}",
                f"{index + 20:064x}",
                2000 + index,
                "active",
            )
            for index, path in enumerate(rm.G8_NEW_WRITER_PATHS)
        )
        return controller_module.G8ActivationPreflightResult(
            cls.BOUNDARY,
            cls.BOUNDARY.merged_result_oid,
            proofs,
            "4" * 64,
            "5" * 64,
            "6" * 64,
        )

    @staticmethod
    def empty_recovery():
        return controller_module.Wave08UniversalRecoveryResult(
            True, 0, 0, 0, 0, 0, 0,
            (), (), (), (), (), (), 0,
        )

    class ExecutionController(controller_module.R02Controller):
        def __init__(self, preflight):
            super().__init__(object(), "swiftstream/skills", Wave12ActivationRecoveryWitnessExecutionTests.APP, environ={})
            self.proof = preflight
            self.persisted = []

        def _require_g8_activation_run_authority(self, mode):
            if mode != "activate-g8":
                raise AssertionError(mode)
            return 7001, 2, "maintainer"

        def derive_activation_boundary_evidence(self):
            return Wave12ActivationRecoveryWitnessExecutionTests.BOUNDARY

        def _g8_activation_preflight(self, boundary):
            if boundary != Wave12ActivationRecoveryWitnessExecutionTests.BOUNDARY:
                raise AssertionError(boundary)
            return self.proof

        def recover_universal_role_first(self, legacy_disposition_resolver, *, read_only=False, **kwargs):
            if legacy_disposition_resolver is not None or read_only is not True or kwargs:
                raise AssertionError((legacy_disposition_resolver, read_only, kwargs))
            return Wave12ActivationRecoveryWitnessExecutionTests.empty_recovery()

        def _run_g8_activation_recovery(self, boundary, preflight, pre):
            if boundary != Wave12ActivationRecoveryWitnessExecutionTests.BOUNDARY or preflight != self.proof:
                raise AssertionError((boundary, preflight))
            return ()

        def _persist_g8_activation_recovery_evidence(self, evidence, app, boundary):
            if app != Wave12ActivationRecoveryWitnessExecutionTests.APP:
                raise AssertionError(app)
            if boundary != Wave12ActivationRecoveryWitnessExecutionTests.BOUNDARY:
                raise AssertionError(boundary)
            self.persisted.append(evidence.render())
            return 77

    def test_execution_builds_exact_deterministic_witness_and_persisted_evidence(self):
        preflight = self.preflight()
        controller = self.ExecutionController(preflight)
        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            first = controller.run_g8_activation_recovery("activate-g8")
            second = controller.run_g8_activation_recovery("activate-g8")
        self.assertEqual(first.witness, second.witness)
        self.assertEqual(first.evidence, second.evidence)
        self.assertEqual(first.result_digest, second.result_digest)
        self.assertEqual(first.persisted_comment_database_id, 77)
        self.assertEqual(first.evidence.recovery_result, "SUCCESS")
        self.assertEqual(first.evidence.unresolved_authority_count, 0)
        self.assertEqual(first.evidence.recovery_action_count, 0)
        self.assertEqual(first.evidence.to_witness(), first.witness)
        self.assertEqual(first.result_digest, rm.activation_recovery_result_digest(first.evidence))
        self.assertEqual(first.witness.activation_run_id, 7001)
        self.assertEqual(first.witness.activation_run_attempt, 2)
        self.assertNotEqual(
            first.witness.pre_recovery_inventory_digest,
            first.witness.post_recovery_inventory_digest,
        )
        self.assertEqual(len(controller.persisted), 2)

    def test_legacy_inventory_digest_binds_activation_boundary_even_when_inventory_is_empty(self):
        first_boundary = self.BOUNDARY
        second_boundary = Wave12ActivationGuardSnapshotTests.boundary(surface="c" * 64)
        first_preflight = self.preflight()
        second_preflight = controller_module.G8ActivationPreflightResult(
            second_boundary,
            second_boundary.merged_result_oid,
            first_preflight.new_workflows,
            first_preflight.old_path_absence_proof_digest,
            first_preflight.old_run_terminal_digest,
            first_preflight.six_workflow_identity_digest,
        )
        first_controller = self.ExecutionController(first_preflight)
        second_controller = self.ExecutionController(second_preflight)

        def second_boundary_reader():
            return second_boundary

        def second_preflight_reader(boundary):
            if boundary != second_boundary:
                raise AssertionError(boundary)
            return second_preflight

        def second_recovery(boundary, preflight, pre):
            if boundary != second_boundary or preflight != second_preflight:
                raise AssertionError((boundary, preflight))
            return ()

        def second_persist(evidence, app, boundary):
            if app != self.APP or boundary != second_boundary:
                raise AssertionError((app, boundary))
            return 78

        second_controller.derive_activation_boundary_evidence = second_boundary_reader
        second_controller._g8_activation_preflight = second_preflight_reader
        second_controller._run_g8_activation_recovery = second_recovery
        second_controller._persist_g8_activation_recovery_evidence = second_persist

        with patch.object(controller_module, "resolve_app_identity", return_value=self.APP):
            first = first_controller.run_g8_activation_recovery("activate-g8")
            second = second_controller.run_g8_activation_recovery("activate-g8")

        self.assertNotEqual(
            first_boundary.activation_boundary_id,
            second_boundary.activation_boundary_id,
        )
        self.assertEqual(
            first.witness.pre_recovery_inventory_digest,
            second.witness.pre_recovery_inventory_digest,
        )
        self.assertEqual(
            first.witness.post_recovery_inventory_digest,
            second.witness.post_recovery_inventory_digest,
        )
        self.assertNotEqual(
            first.evidence.legacy_inventory_quarantine_migration_digest,
            second.evidence.legacy_inventory_quarantine_migration_digest,
        )


if __name__ == "__main__":
    unittest.main()
