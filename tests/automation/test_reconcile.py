import json
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

from automation.federation.controller import (
    AppMetadata,
    BotMetadata,
    AppIdentity,
    MachinePRAuthority,
    MachineReconcileResult,
    ProposalCandidate,
    R02Controller,
    R02Error,
    IssueManagedRouteResult,
    parse_repository_id_hint,
    validate_machine_generated_scope,
    TrustedValidationResult,
    bounded_check_output,
    render_check_run_output,
    verify_machine_check_identity,
)
from automation.federation.github_api import CheckRun, CommitStatus, GitCommitIdentity, GitCommitObject, GitHubAPIError, GitHubClient, GitTreeEntry, HttpResponse, IssueComment, NotFoundError, PullRequestMetadata, RepositoryMetadata, RefCASConflict
from automation.federation.request_model import ANCHOR_MARKER, ActivationBoundaryEvidence, CarrierRole, ClaimedHeadMarker, IssuePRBinding, LegacyClassificationOutcome, LegacyClassificationResult, LegacyQuarantineClass, LegacyQuarantineEvidence, RequestClass, RequestAnchor, activation_boundary_id_digest, body_sha256, claim_generation_id, machine_ref_claim_authority_digest, parse_request_body
from scripts import federate as c02
import automation.federation.controller as controller_module


class ReconcileClient:
    def __init__(self):
        self.main = "a" * 40
        self.refs = []
        self.dispatches = []
        self.ref_values = {}
        self.commit_objects = {}
        self.pull_requests = {}
        self.identity = GitCommitIdentity("Bot", "bot@example.test", "2026-10-08T00:00:00Z")

    def get_repository_metadata(self, repository):
        return RepositoryMetadata(7, "R_central", repository, "main")

    def get_ref_oid(self, repository, branch):
        if branch == "main":
            return self.main
        if branch in self.ref_values:
            return self.ref_values[branch]
        raise NotFoundError("missing ref")

    def get_app_metadata(self, slug):
        return AppMetadata(1, slug, "A")

    def get_bot_metadata(self, slug):
        return BotMetadata(2, "app[bot]", getattr(self, "bot_node_id", "U"), "Bot")

    def get_git_commit_object(self, repository, sha):
        if sha in self.commit_objects:
            return self.commit_objects[sha]
        if sha == self.main:
            return GitCommitObject(sha, "base\n", "b" * 40, (), self.identity, self.identity)
        raise NotFoundError("unknown commit")

    def list_open_pull_requests(self, repository):
        return tuple({"number": number} for number in sorted(self.pull_requests))

    def get_pull_request_metadata(self, repository, number):
        return self.pull_requests[number]

    def update_refs(self, repository_id, updates):
        self.refs.extend(updates)
        for update in updates:
            branch = update.name.removeprefix("refs/heads/")
            self.ref_values[branch] = update.after_oid
            self.pull_requests = {
                number: replace(pr, head_oid=update.after_oid)
                if pr.head_ref == branch else pr
                for number, pr in self.pull_requests.items()
            }

    def create_machine_pull_request(self, repository, **kwargs):
        self.created_pr = kwargs
        number = 41
        self.pull_requests[number] = PullRequestMetadata(
            number, "PR_node", "U", "app[bot]", self.ref_values[kwargs["head"]], self.main,
            kwargs["head"], kwargs["base"], "R_central", repository, "R_central", repository,
            None, False, False,
        )
        return number

    def dispatch_workflow(self, repository, workflow, ref, inputs=None):
        self.dispatches.append((workflow, ref, inputs))


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self._public_source_patch = patch.object(
            controller_module, "read_public_source_metadata",
            return_value=controller_module.PublicSourceMetadata(99, "Owner/Repo", "main", None),
        )
        self._scope_patch = patch.object(
            controller_module, "validate_machine_generated_scope",
            side_effect=lambda client, _repository, _base, head: getattr(client, "machine_changed_paths", {}).get(head, ("skills/demo/SKILL.md",)),
        )
        self._public_source_patch.start()
        self._scope_patch.start()

    def tearDown(self):
        self._scope_patch.stop()
        self._public_source_patch.stop()

    def _candidate(self, client, source, commit_sha, changed_paths, *, tree_sha="e" * 40, nonce="4" * 64):
        central = client.get_repository_metadata("swiftstream/skills").node_id
        owner = f"{central}:{source.source_id}"
        paths = tuple(sorted(changed_paths, key=lambda item: item.encode("utf-8")))
        scope = __import__("hashlib").sha256(
            b"swiftstream-federation-machine-ref-claim-scope:v1\n"
            + json.dumps({"schemaVersion": 1, "candidateTreeSha": tree_sha, "changedPaths": list(paths)}, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        authority = machine_ref_claim_authority_digest(
            central_repository_node_id=central, owner_key=owner, source_id=source.source_id,
            source_repository_id=source.repository_id,
            machine_ref=f"refs/heads/bot/federation/{source.source_id}",
            accepted_base_sha=client.main, accepted_base_tree_sha="b" * 40,
            candidate_tree_sha=tree_sha, candidate_scope_digest=scope,
        )
        generation = claim_generation_id(
            authority_preimage_digest=authority, carrier_nonce=nonce,
            central_repository_node_id=central, owner_key=owner,
            from_head_sha=client.main, from_tree_sha="b" * 40,
            claim_kind="MACHINE_REF_CLAIM", role="MACHINE_PUBLICATION",
            owner_kind="MACHINE_SOURCE", transition_kind="MACHINE_PUBLICATION",
        )
        marker = ClaimedHeadMarker("MACHINE_REF_CLAIM", CarrierRole.MACHINE_PUBLICATION.value, "MACHINE_SOURCE", owner, generation, nonce, "MACHINE_PUBLICATION")
        client.commit_objects[commit_sha] = GitCommitObject(commit_sha, marker.render(), tree_sha, (client.main,), client.identity, client.identity)
        client.machine_changed_paths = getattr(client, "machine_changed_paths", {})
        client.machine_changed_paths[commit_sha] = paths
        return ProposalCandidate(commit_sha, client.main, paths, RequestClass.MACHINE_PUBLICATION, source.source_id, source.repository_id, True, marker, tree_sha)

    def _manual_reconcile_fixture(self, *, accepted=True, edited=False, fork=False):
        body = "Repository URL:\nhttps://github.com/Owner/Repo\n"
        current = "a" * 40
        request = parse_request_body(RequestClass.RECONCILE, body)
        anchor = RequestAnchor(7, RequestClass.RECONCILE, "U_author", "alice", body_sha256(body), request)
        anchor_comment = IssueComment("IC_anchor", 100, anchor.render(), "U_bot", "app[bot]", "Bot", None, None, None, None, False)

        class ManualClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(7, body, "U_author", "alice", "d" * 40, current, "request", "main", "R_central" if not fork else "R_fork", "swiftstream/skills" if not fork else "someone/fork", "R_central", "swiftstream/skills", "2026-01-01" if edited else None, edited, False)
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
        client.bot_node_id = "U_bot"
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
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
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md", "federation.lock.json"))
        builder = type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"), candidate_builder=builder)
        controller._accepted_sources = lambda _main=None: (source,)
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(client.refs[0].before_oid, "0" * 40)
        self.assertFalse(client.refs[0].force)
        self.assertEqual(client.dispatches[-1][0], "federation-g8-state-finalize.yml")

    def test_response_lost_after_persisted_h_and_full_restart_reuses_same_generation(self):
        class LostResponse(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, repository_id, updates):
                self.updates.extend(updates)
                super().update_refs(repository_id, updates)
                raise GitHubAPIError("accepted CAS response lost")

        client = LostResponse()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidate
            def validate_machine_head(_self, _base, _source_id, _head):
                return True, "MATCHES"
        controller, _ = self._controller_with_source(client, source, Builder())
        first = controller.reconcile(99)
        self.assertEqual(first.outcome, "CHANGED")
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.updates[0].after_oid, candidate.commit_sha)
        generation = candidate.claimed_head_marker.claim_generation_id
        nonce = candidate.claimed_head_marker.carrier_nonce

        # New invocation has no prior B or generation memory; the current H
        # and its exact marker are sufficient to recover/create the PR.
        second = controller.reconcile(99)
        self.assertEqual(second.outcome, "NOOP")
        self.assertEqual(len(builds), 1)
        self.assertEqual(client.ref_values["bot/federation/demo"], candidate.commit_sha)
        self.assertEqual(candidate.claimed_head_marker.claim_generation_id, generation)
        self.assertEqual(candidate.claimed_head_marker.carrier_nonce, nonce)

    def test_restart_after_cas_before_pr_creation_recovers_existing_h_without_generation(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        client.ref_values["bot/federation/demo"] = candidate.commit_sha
        class RecoveryOnlyBuilder:
            def machine_candidate(_self, *_args):
                self.fail("persisted H must be recovered without generating H3")
            def validate_machine_head(_self, _base, _source_id, head_sha):
                self.assertEqual(head_sha, candidate.commit_sha)
                return True, "MATCHES"
        controller, _ = self._controller_with_source(client, source, RecoveryOnlyBuilder())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(client.refs, [])
        self.assertEqual(client.pull_requests[41].head_oid, candidate.commit_sha)
        self.assertEqual(client.ref_values["bot/federation/demo"], candidate.commit_sha)

    def test_ambiguous_unchanged_ref_retries_exact_same_cas_once(self):
        class RetryClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, repository_id, updates):
                self.updates.extend(updates)
                if len(self.updates) == 1:
                    raise GitHubAPIError("CAS outcome ambiguous")
                super().update_refs(repository_id, updates)

        client = RetryClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidate
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(len(builds), 1)
        self.assertEqual(client.updates, [client.updates[0], client.updates[0]])
        self.assertEqual(client.updates[0].before_oid, "0" * 40)
        self.assertEqual(client.updates[0].after_oid, candidate.commit_sha)

    def test_ambiguous_retry_guard_rejection_stops_before_second_cas(self):
        class AmbiguousClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, _repository_id, updates):
                self.updates.extend(updates)
                raise GitHubAPIError("CAS outcome ambiguous")

        client = AmbiguousClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builder = type("Builder", (), {"machine_candidate": lambda _self, _base, _source_id: candidate})()
        controller, _ = self._controller_with_source(client, source, builder)
        guard_calls = []

        def guard():
            guard_calls.append(None)
            if len(guard_calls) == 2:
                raise R02Error("Task02 mutation authority became stale")

        result = controller.reconcile(99, pre_mutation_guard=guard, dispatch_finalizer=False)

        self.assertEqual(result.outcome, "FAIL")
        self.assertEqual(len(guard_calls), 2)
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.updates[0].before_oid, "0" * 40)
        self.assertEqual(client.updates[0].after_oid, candidate.commit_sha)
        self.assertEqual(client.ref_values, {})
        self.assertEqual(client.refs, [])
        self.assertFalse(hasattr(client, "created_pr"))
        self.assertEqual(client.dispatches, [])

    def test_ambiguous_retry_exhaustion_does_not_create_h3_or_new_nonce(self):
        class StuckClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, _repository_id, updates):
                self.updates.extend(updates)
                raise GitHubAPIError("CAS outcome unresolved")

        client = StuckClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidate
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual((result.outcome, result.reason), ("FAIL", "MACHINE_AMBIGUOUS_RETRY_EXHAUSTED"))
        self.assertEqual(len(builds), 1)
        self.assertEqual(len(client.updates), 2)
        self.assertEqual(client.updates[0], client.updates[1])
        self.assertFalse(hasattr(client, "created_pr"))

    def test_reported_cas_success_with_third_ref_is_contradiction(self):
        class ContradictorySuccessClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, _repository_id, updates):
                self.updates.extend(updates)
                # Simulate a successful API response while a distinct valid
                # generation owns the ref, proving this H did not win.
                self.ref_values[updates[0].name.removeprefix("refs/heads/")] = "e" * 40

        client = ContradictorySuccessClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        self._candidate(client, source, "e" * 40, ("README.md",), nonce="5" * 64)
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidate
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual((result.outcome, result.reason), ("FAIL", "MACHINE_CAS_SUCCESS_REF_CONTRADICTION"))
        self.assertEqual(len(builds), 1)
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.updates[0].before_oid, "0" * 40)
        self.assertFalse(hasattr(client, "created_pr"))

    def test_ambiguous_unchanged_ref_with_changed_main_stops_without_retry(self):
        class ChangedMainClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, _repository_id, updates):
                self.updates.extend(updates)
                self.main = "f" * 40
                raise GitHubAPIError("CAS response ambiguous; main advanced")

        client = ChangedMainClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidate
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual((result.outcome, result.reason), ("FAIL", "MACHINE_AMBIGUOUS_AUTHORITY_CHANGED"))
        self.assertEqual(len(builds), 1)
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.updates[0].after_oid, candidate.commit_sha)
        self.assertFalse(hasattr(client, "created_pr"))

    def test_persisted_h_with_changed_accepted_main_is_not_replaced(self):
        class AdvancingMainClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = []
            def update_refs(self, repository_id, updates):
                self.updates.extend(updates)
                super().update_refs(repository_id, updates)
                self.main = "f" * 40

        client = AdvancingMainClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidate
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual((result.outcome, result.reason), ("FAIL", "MACHINE_PERSISTED_GENERATION_AUTHORITY_STALE"))
        self.assertEqual(len(builds), 1)
        self.assertEqual(len(client.updates), 1)
        self.assertEqual(client.ref_values["bot/federation/demo"], candidate.commit_sha)
        self.assertFalse(hasattr(client, "created_pr"))

    def test_ref_b_changed_after_generation_prevents_stale_cas(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        losing = self._candidate(client, source, "c" * 40, ("README.md",), nonce="4" * 64)
        competitor = self._candidate(client, source, "d" * 40, ("README.md",), nonce="5" * 64)
        successor = self._candidate(client, source, "e" * 40, ("README.md",), nonce="6" * 64)
        candidates = [losing, successor]
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                if len(builds) == 1:
                    # A competing valid generation lands after B was read but
                    # before the first candidate's exact CAS.
                    client.ref_values["bot/federation/demo"] = competitor.commit_sha
                return candidates[len(builds) - 1]
            def validate_machine_head(_self, _base, _source_id, _head):
                return False, "NEW_SUCCESSOR_REQUIRED"
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(len(builds), 2)
        self.assertEqual(len(client.refs), 1)
        self.assertEqual(client.refs[0].before_oid, competitor.commit_sha)
        self.assertEqual(client.refs[0].after_oid, successor.commit_sha)
        self.assertNotEqual(client.refs[0].after_oid, losing.commit_sha)

    def test_legacy_machine_h_migrates_to_fresh_h2_with_exact_before_cas(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        legacy_head = "c" * 40
        client.ref_values["bot/federation/demo"] = legacy_head
        client.commit_objects[legacy_head] = GitCommitObject(
            legacy_head, "Swift Stream federation machine publication\n", "d" * 40,
            (client.main,), client.identity, client.identity,
        )
        client.pull_requests[40] = PullRequestMetadata(
            40, "PR_node", "U", "app[bot]", legacy_head, client.main,
            "bot/federation/demo", "main", "R_central", "swiftstream/skills",
            "R_central", "swiftstream/skills", None, False, False,
        )
        candidate = self._candidate(client, source, "e" * 40, ("README.md",), nonce="5" * 64)
        builder = type("Builder", (), {
            "machine_candidate": lambda _self, _base, _source_id: candidate,
            "validate_machine_head": lambda _self, _base, _source_id, _head: (True, "MATCHES"),
        })()
        controller, _ = self._controller_with_source(client, source, builder)
        boundary_id = activation_boundary_id_digest("R_central", 27, 100, "PR_node", "f" * 40, "1" * 64, "2" * 64)
        boundary = ActivationBoundaryEvidence(1, "R_central", 27, 100, "PR_node", "f" * 40, "f" * 40, "1" * 64, "2" * 64, boundary_id)
        legacy_evidence = LegacyQuarantineEvidence(1, LegacyQuarantineClass.MACHINE, 7, "R_central", "swiftstream/skills", legacy_head, "f" * 64)
        classification = LegacyClassificationResult(LegacyClassificationOutcome.QUARANTINE, legacy_evidence, "EXACT_LEGACY_MACHINE")
        original_resolver = controller.resolve_current_sha_carrier_role
        controller.resolve_current_sha_carrier_role = lambda sha: (
            controller_module.ShaCarrierResolution(controller_module.CarrierActivation.LEGACY_CUTOVER_QUARANTINE)
            if sha == legacy_head else original_resolver(sha)
        )
        controller.derive_activation_boundary_evidence = lambda: boundary
        controller.classify_legacy_head = lambda _sha, *, implementation_reviewed_head_sha: classification
        failures = []
        controller.publish_legacy_failure = lambda head, activation_id, *, implementation_reviewed_head_sha: failures.append((head, activation_id, implementation_reviewed_head_sha))

        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(failures, [(legacy_head, boundary_id, "f" * 40)])
        self.assertEqual(client.refs[0].before_oid, legacy_head)
        self.assertEqual(client.refs[0].after_oid, candidate.commit_sha)
        self.assertTrue(client.refs[0].force)
        self.assertEqual(client.commit_objects[legacy_head].message, "Swift Stream federation machine publication\n")
        self.assertNotEqual(candidate.claimed_head_marker.carrier_nonce, "4" * 64)
        self.assertEqual(client.pull_requests[40].head_oid, candidate.commit_sha)

    def test_machine_claim_candidate_mints_fresh_v2_head_for_empty_file_diff(self):
        source = c02.SourceDeclaration(
            "demo", "Owner/Repo", 99, "skills", "Demo",
            (c02.LineDeclaration("refs/heads/main", ("demo",)),),
        )

        class ClaimClient:
            def __init__(self):
                self.tree_calls = 0
                self.commit_calls = []

            def get_commit_tree(self, repository, sha):
                self.assertion = (repository, sha)
                return "b" * 40, ()

            def bot_commit_timestamp_after(self, repository, sha):
                return "2026-10-10T00:00:01Z"

            def create_tree(self, *_args, **_kwargs):
                self.tree_calls += 1
                raise AssertionError("empty-diff claim migration must reuse the exact base tree")

            def create_commit(self, repository, message, tree, parents, *, timestamp=None):
                self.commit_calls.append((repository, message, tree, tuple(parents), timestamp))
                return type("GitObject", (), {"sha": "e" * 40})()

        client = ClaimClient()
        builder = controller_module.C02CandidateBuilder(
            client,
            "swiftstream/skills",
            trusted_checkout_sha="a" * 40,
        )
        builder._machine_plan = lambda base, source_id: (
            {},
            {},
            source,
            RepositoryMetadata(7, "R_central", "swiftstream/skills", "main"),
        )
        with patch.object(controller_module, "new_carrier_nonce", return_value="5" * 64):
            candidate = builder.machine_claim_candidate("a" * 40, "demo")

        self.assertEqual(candidate.changed_paths, ())
        self.assertTrue(candidate.marker_present)
        self.assertEqual(candidate.commit_sha, "e" * 40)
        self.assertEqual(candidate.candidate_tree_sha, "b" * 40)
        self.assertEqual(candidate.claimed_head_marker.carrier_nonce, "5" * 64)
        self.assertEqual(candidate.claimed_head_marker.claim_kind, "MACHINE_REF_CLAIM")
        self.assertEqual(candidate.claimed_head_marker.role, "MACHINE_PUBLICATION")
        self.assertEqual(client.tree_calls, 0)
        self.assertEqual(client.commit_calls[0][2], "b" * 40)
        self.assertEqual(client.commit_calls[0][3], ("a" * 40,))

    def test_legacy_machine_byte_identical_tree_still_migrates_to_fresh_claimed_h2(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        legacy_head = "c" * 40
        client.ref_values["bot/federation/demo"] = legacy_head
        client.commit_objects[legacy_head] = GitCommitObject(
            legacy_head, "Swift Stream federation machine publication\n", "b" * 40,
            (client.main,), client.identity, client.identity,
        )
        client.pull_requests[40] = PullRequestMetadata(
            40, "PR_node", "U", "app[bot]", legacy_head, client.main,
            "bot/federation/demo", "main", "R_central", "swiftstream/skills",
            "R_central", "swiftstream/skills", None, False, False,
        )
        claimed = self._candidate(
            client,
            source,
            "e" * 40,
            (),
            tree_sha="b" * 40,
            nonce="5" * 64,
        )
        ordinary_noop = ProposalCandidate(
            client.main,
            client.main,
            (),
            RequestClass.MACHINE_PUBLICATION,
            source.source_id,
            source.repository_id,
            False,
        )
        builder = type("Builder", (), {
            "machine_candidate": lambda _self, _base, _source_id: ordinary_noop,
            "machine_claim_candidate": lambda _self, _base, _source_id: claimed,
            "validate_machine_head": lambda _self, _base, _source_id, _head: (True, "MATCHES"),
        })()
        controller, _ = self._controller_with_source(client, source, builder)
        boundary_id = activation_boundary_id_digest("R_central", 27, 100, "PR_node", "f" * 40, "1" * 64, "2" * 64)
        boundary = ActivationBoundaryEvidence(1, "R_central", 27, 100, "PR_node", "f" * 40, "f" * 40, "1" * 64, "2" * 64, boundary_id)
        legacy_evidence = LegacyQuarantineEvidence(
            1, LegacyQuarantineClass.MACHINE, 7, "R_central",
            "swiftstream/skills", legacy_head, "f" * 64,
        )
        classification = LegacyClassificationResult(
            LegacyClassificationOutcome.QUARANTINE,
            legacy_evidence,
            "EXACT_LEGACY_MACHINE",
        )
        original_resolver = controller.resolve_current_sha_carrier_role
        controller.resolve_current_sha_carrier_role = lambda sha: (
            controller_module.ShaCarrierResolution(controller_module.CarrierActivation.LEGACY_CUTOVER_QUARANTINE)
            if sha == legacy_head else original_resolver(sha)
        )
        controller.derive_activation_boundary_evidence = lambda: boundary
        controller.classify_legacy_head = lambda _sha, *, implementation_reviewed_head_sha: classification
        controller.publish_legacy_failure = lambda *_args, **_kwargs: None

        result = controller.reconcile(99)

        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(len(client.refs), 1)
        self.assertEqual(client.refs[0].before_oid, legacy_head)
        self.assertEqual(client.refs[0].after_oid, claimed.commit_sha)
        self.assertNotEqual(client.refs[0].after_oid, legacy_head)
        self.assertEqual(claimed.changed_paths, ())
        self.assertTrue(claimed.marker_present)
        self.assertIsNotNone(claimed.claimed_head_marker)
        self.assertEqual(client.pull_requests[40].head_oid, claimed.commit_sha)

    def test_legacy_machine_reconcile_accepts_exact_preconfirmed_failure_receipt_without_duplicate_post(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration(
            "demo", "Owner/Repo", 99, "skills", "Demo",
            (c02.LineDeclaration("refs/heads/main", ("demo",)),),
        )
        legacy_head = "c" * 40
        client.ref_values["bot/federation/demo"] = legacy_head
        client.commit_objects[legacy_head] = GitCommitObject(
            legacy_head, "Swift Stream federation machine publication\n", "d" * 40,
            (client.main,), client.identity, client.identity,
        )
        client.pull_requests[40] = PullRequestMetadata(
            40, "PR_node", "U", "app[bot]", legacy_head, client.main,
            "bot/federation/demo", "main", "R_central", "swiftstream/skills",
            "R_central", "swiftstream/skills", None, False, False,
        )
        candidate = self._candidate(client, source, "e" * 40, ("README.md",), nonce="5" * 64)
        builder = type("Builder", (), {
            "machine_candidate": lambda _self, _base, _source_id: candidate,
            "machine_claim_candidate": lambda _self, _base, _source_id: candidate,
            "validate_machine_head": lambda _self, _base, _source_id, _head: (True, "MATCHES"),
        })()
        controller, _ = self._controller_with_source(client, source, builder)
        boundary_id = activation_boundary_id_digest(
            "R_central", 27, 100, "PR_node",
            "f" * 40, "1" * 64, "2" * 64,
        )
        boundary = ActivationBoundaryEvidence(
            1, "R_central", 27, 100, "PR_node",
            "f" * 40, "f" * 40, "1" * 64, "2" * 64, boundary_id,
        )
        legacy_evidence = LegacyQuarantineEvidence(
            1, LegacyQuarantineClass.MACHINE, 7, "R_central",
            "swiftstream/skills", legacy_head, "f" * 64,
        )
        classification = LegacyClassificationResult(
            LegacyClassificationOutcome.QUARANTINE,
            legacy_evidence,
            "EXACT_LEGACY_MACHINE",
        )
        original_resolver = controller.resolve_current_sha_carrier_role
        controller.resolve_current_sha_carrier_role = lambda sha: (
            controller_module.ShaCarrierResolution(
                controller_module.CarrierActivation.LEGACY_CUTOVER_QUARANTINE,
            )
            if sha == legacy_head else original_resolver(sha)
        )
        controller.derive_activation_boundary_evidence = lambda: boundary
        controller.classify_legacy_head = lambda _sha, *, implementation_reviewed_head_sha: classification

        digest = controller_module.legacy_status_evidence_digest(
            legacy_evidence,
            boundary_id,
        )
        description = controller_module.render_status_description(
            controller_module.StatusClass.LEGACY,
            digest,
        )
        status = CommitStatus(
            77,
            "CS_77",
            "failure",
            "federation/trusted-validation",
            description,
            None,
            controller.app.bot_id,
            controller.app.bot_node_id,
            controller.app.bot_login,
            "Bot",
            "2026-10-10T00:00:00Z",
            "2026-10-10T00:00:00Z",
        )
        receipt = controller_module.StatusWriteReceipt(
            "swiftstream/skills",
            legacy_head,
            "POST",
            f"/repos/swiftstream/skills/statuses/{legacy_head}",
            "failure",
            "federation/trusted-validation",
            description,
            None,
            status,
        )
        controller.publish_legacy_failure = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("preconfirmed receipt must suppress duplicate legacy failure POST")
        )

        result = controller.reconcile(
            99,
            legacy_failure_receipt=receipt,
        )
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(client.refs[0].before_oid, legacy_head)
        self.assertEqual(client.refs[0].after_oid, candidate.commit_sha)

    def test_third_ref_makes_old_h_lose_and_successor_uses_fresh_nonce_and_head(self):
        class ThirdValueClient(ReconcileClient):
            def __init__(self, third):
                super().__init__()
                self.third = third
                self.update_payloads = []
            def update_refs(self, repository_id, updates):
                self.update_payloads.extend(updates)
                if len(self.update_payloads) == 1:
                    update = updates[0]
                    self.ref_values[update.name.removeprefix("refs/heads/")] = self.third
                    self.pull_requests = {number: replace(pr, head_oid=self.third) for number, pr in self.pull_requests.items()}
                    raise GitHubAPIError("ambiguous CAS with third value")
                super().update_refs(repository_id, updates)

        third_sha = "d" * 40
        client = ThirdValueClient(third_sha)
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        old = self._candidate(client, source, "c" * 40, ("README.md",), nonce="4" * 64)
        third = self._candidate(client, source, third_sha, ("README.md",), nonce="5" * 64)
        first_successor = self._candidate(client, source, "e" * 40, ("README.md",), nonce="6" * 64)
        fresh_successor = self._candidate(client, source, "f" * 40, ("README.md",), nonce="7" * 64)
        client.ref_values["bot/federation/demo"] = old.commit_sha
        client.pull_requests[40] = PullRequestMetadata(
            40, "PR_node", "U", "app[bot]", old.commit_sha, client.main,
            "bot/federation/demo", "main", "R_central", "swiftstream/skills",
            "R_central", "swiftstream/skills", None, False, False,
        )
        candidates = [first_successor, fresh_successor]
        builds = []
        class Builder:
            def machine_candidate(_self, base, source_id):
                builds.append((base, source_id))
                return candidates[len(builds) - 1]
            def validate_machine_head(_self, _base, _source_id, _head):
                return False, "SUCCESSOR_REQUIRED"
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(len(builds), 2)
        self.assertEqual(client.update_payloads[0].before_oid, old.commit_sha)
        self.assertEqual(client.update_payloads[0].after_oid, first_successor.commit_sha)
        self.assertEqual(client.update_payloads[1].before_oid, third.commit_sha)
        self.assertEqual(client.update_payloads[1].after_oid, fresh_successor.commit_sha)
        self.assertNotEqual(first_successor.claimed_head_marker.carrier_nonce, fresh_successor.claimed_head_marker.carrier_nonce)
        self.assertNotEqual(first_successor.commit_sha, fresh_successor.commit_sha)
        self.assertEqual(controller.resolve_current_sha_carrier_role(first_successor.commit_sha).activation, controller_module.CarrierActivation.CONFLICTING)

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
        source = source or c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
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
        source = c02.SourceDeclaration("real", "Owner/Repo", 99, "skills", "Real", (c02.LineDeclaration("refs/heads/main", ("real",)),))
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
        builder = type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})()
        controller, _ = self._controller_with_source(client, source, builder)
        self.assertEqual(controller.reconcile("99").source_id, "real")
        self.assertEqual(controller.reconcile("123").outcome, "NOOP")

    def test_reconcile_candidate_identity_failure_is_bounded_fail(self):
        client = ReconcileClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        builder = type("Builder", (), {"machine_candidate": lambda _self, base, source_id: (_ for _ in ()).throw(R02Error("identity"))})()
        controller, _ = self._controller_with_source(client, source, builder)
        result = controller.reconcile(99)
        self.assertEqual((result.outcome, result.reason), ("FAIL", "identity"))
        self.assertEqual(client.refs, [])

    def test_cas_loss_recomputes_with_fresh_main_and_before_oid(self):
        class CASClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = 0

            def get_ref_oid(self, repository, branch):
                return super().get_ref_oid(repository, branch)

            def update_refs(self, repository_id, updates):
                self.updates += 1
                if self.updates == 1:
                    raise RefCASConflict("competitor won")
                super().update_refs(repository_id, updates)

        client = CASClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidates = [
            self._candidate(client, source, "d" * 40, ("README.md",), nonce="4" * 64),
            self._candidate(client, source, "e" * 40, ("README.md",), nonce="5" * 64),
        ]
        seen = []
        class Builder:
            def machine_candidate(self, base, source_id):
                seen.append((base, source_id))
                return candidates[len(seen) - 1]
        controller, _ = self._controller_with_source(client, source, Builder())
        result = controller.reconcile(99)
        self.assertEqual(result.outcome, "CHANGED")
        self.assertEqual(len(seen), 2)
        self.assertEqual(client.refs[0].before_oid, "0" * 40)
        self.assertFalse(client.refs[0].force)
        self.assertNotEqual(candidates[0].claimed_head_marker.carrier_nonce, candidates[1].claimed_head_marker.carrier_nonce)
        self.assertNotEqual(candidates[0].commit_sha, candidates[1].commit_sha)

    def test_repeated_cas_loss_exhausts_without_stale_overwrite(self):
        class AlwaysCAS(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.updates = 0

            def get_ref_oid(self, repository, branch):
                if branch != "main" and branch not in self.ref_values:
                    return "b" * 40
                return super().get_ref_oid(repository, branch)

            def update_refs(self, repository_id, updates):
                self.updates += 1
                raise RefCASConflict("always loses")

        client = AlwaysCAS()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidates = [self._candidate(client, source, chr(ord("d") + i) * 40, ("README.md",), nonce=f"{i + 1:064x}") for i in range(3)]
        calls = []
        def build(_self, base, source_id):
            calls.append((base, source_id))
            return candidates[len(calls) - 1]
        controller, _ = self._controller_with_source(client, source, type("Builder", (), {"machine_candidate": build})())
        result = controller.reconcile(99)
        self.assertEqual(result.reason, "MACHINE_BRANCH_CAS_CONFLICT_RECOMPUTE_EXHAUSTED")
        self.assertEqual(client.updates, 3)
        self.assertEqual(client.refs, [])

    def test_existing_matching_branch_has_no_cas_churn(self):
        class Matching(ReconcileClient):
            def get_ref_oid(self, repository, branch):
                return self.main if branch == "main" else self.ref_values.get(branch, "d" * 40)
        client = Matching()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = self._candidate(client, source, "e" * 40, ("README.md",))
        controller, _ = self._controller_with_source(client, source, type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})())
        self.assertEqual(controller.reconcile(99).outcome, "CHANGED")
        self.assertEqual(client.refs[0].before_oid, "d" * 40)
        self.assertTrue(client.refs[0].force)

    def test_rendered_machine_evidence_binds_class_head_base_source_and_repository(self):
        result = TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, "a" * 40, "b" * 40, "demo", 99, "BLOCKED"))
        output = render_check_run_output(result)
        for field, value in (("class", "machine-publication"), ("head", "a" * 40), ("accepted_base", "b" * 40), ("sourceId", "demo"), ("repositoryId", "99")):
            self.assertIn(f"{field}={value}", output["text"])
        self.assertNotIn("token", json.dumps(output).lower())

    def test_machine_publication_uses_lineRef_in_lock(self):
        lock = c02.LockState(
            ("demo",),
            {
                "demo-skill": c02.LockEntry(
                    source_id="demo",
                    line_ref="refs/heads/main",
                    resolved_commit="a" * 40,
                    content_sha256="b" * 64,
                )
            },
        )
        rendered = json.loads(c02.render_lock(lock).decode("utf-8"))
        self.assertEqual(rendered["schemaVersion"], 3)
        self.assertEqual(rendered["skills"]["demo-skill"]["lineRef"], "refs/heads/main")

    def test_fixture_manifests_use_schema_v3(self):
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        self.assertEqual(source.lines[0].ref, "refs/heads/main")
        self.assertFalse(hasattr(source, "ref"))
        self.assertFalse(hasattr(source, "skill_prefixes"))

    def test_trusted_manifest_read_is_capsule_bound_and_parent_environment_restored(self):
        client = ReconcileClient()
        client.main = c02.head_commit_oid()
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U", "app[bot]"))
        original = dict(os.environ)
        hostile = {"PATH": "/attacker", "GIT_DIR": "/attacker/repo", "HOME": "/attacker/home", "TMPDIR": "/attacker/tmp", "HTTPS_PROXY": "http://attacker.invalid", "FEDERATION_GITHUB_TOKEN": "secret"}
        with patch.dict(os.environ, hostile, clear=False), patch.object(c02, "load_trusted_previous_manifest", return_value=c02.Manifest(())):
            sources = controller._accepted_sources(client.main)
        self.assertIsInstance(sources, tuple)
        self.assertEqual(sources, ())
        self.assertEqual(dict(os.environ), original)

    def test_machine_source_scope_rejects_federation_docs_scripts_automation_and_unrelated_roots(self):
        for path in ("federation.json", "docs/x", "scripts/x", ".github/x", "automation/x", "other/x"):
            with self.subTest(path=path):
                client = ReconcileClient()
                source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
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
                self.pr = PullRequestMetadata(7, "", "U", "app[bot]", "d" * 40, self.main, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False)
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
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        candidate = ProposalCandidate("e" * 40, client.main, ("README.md",), RequestClass.MACHINE_PUBLICATION, "demo", 99)
        controller, _ = self._controller_with_source(client, source, type("Builder", (), {"machine_candidate": lambda _self, base, source_id: candidate})())
        with patch.object(controller_module, "validate_machine_generated_scope", side_effect=controller_module.CandidateScopeError("forbidden")):
            result = controller.reconcile(99)
        self.assertEqual(result.outcome, "FAIL")
        self.assertEqual(client.states, [(7, "closed")])
        self.assertIn("MACHINE_RECONCILE_FAILED", client.comments[0].body)

    def test_wrong_app_same_machine_branch_is_not_owned_or_mutated(self):
        class WrongApp(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(7, "", "wrong", "other[bot]", "d" * 40, self.main, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False)
                self.states = []
            def list_open_pull_requests(self, repository):
                return ({"number": 7},)
            def get_pull_request_metadata(self, repository, number):
                return self.pr
            def update_pull_request_state(self, repository, number, *, state):
                self.states.append((number, state))
        client = WrongApp()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
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
        client.pr = PullRequestMetadata(7, "", "U", "app[bot]", "d" * 40, "b" * 40, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False)
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
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
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
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
        client, controller, source = self._manual_reconcile_fixture()
        candidate = self._candidate(client, source, "d" * 40, ("README.md",))
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
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        controller, _ = self._controller_with_source(client, source, None)
        controller.candidate_builder = type("Builder", (), {"machine_candidate": lambda _self, _base, _source_id: self._candidate(client, source, "d" * 40, ("README.md",))})()
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
            "draft": False,
        }
        values.update(overrides)
        return PullRequestMetadata(**values), comment

    def _main_advance_with_prs(self, prs, comments_by_pr, machine=None):
        class MainAdvanceClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.prs = prs
                self.updated_branches = []
                self.comment_reads = 0

            def list_open_pull_requests(self, _repository):
                return tuple({"number": number} for number in self.prs)

            def get_pull_request_metadata(self, _repository, number):
                return self.prs[number]

            def list_issue_comments(self, _repository, number):
                self.comment_reads += 1
                return tuple(comments_by_pr.get(number, ()))

            def update_pull_request_branch(self, _repository, number, *, expected_head_sha):
                self.updated_branches.append((number, expected_head_sha))

        client = MainAdvanceClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda _main, _repository, _sources: machine or {"demo": []}
        return client, controller

    def test_main_advance_owned_machine_pr_uses_manifest_repository_id_and_one_coalesced_wake(self):
        source = c02.SourceDeclaration("real", "Owner/Repo", 123, "skills", "Real", (c02.LineDeclaration("refs/heads/main", ("real",)),))
        authority = MachinePRAuthority(41, "real", 123, "d" * 40)
        client, controller = self._main_advance_controller((source,), {"real": [authority]})
        result = controller.main_advance()
        self.assertEqual(result, "MAIN_ADVANCE_DISPATCHED:1")
        self.assertEqual(client.dispatches, [
            ("federation-g8-reconcile.yml", "refs/heads/main", {"repository_id": "123"}),
            ("federation-g8-state-finalize.yml", "refs/heads/main", {}),
        ])

    def test_main_advance_multiple_sources_is_deterministic_and_finalizer_is_coalesced(self):
        source_b = c02.SourceDeclaration("b", "Owner/B", 2, "skills", "B", (c02.LineDeclaration("refs/heads/main", ("b",)),))
        source_a = c02.SourceDeclaration("a", "Owner/A", 1, "skills", "A", (c02.LineDeclaration("refs/heads/main", ("a",)),))
        machine = {"b": [MachinePRAuthority(2, "b", 2, "b" * 40)], "a": [MachinePRAuthority(1, "a", 1, "a" * 40)]}
        client, controller = self._main_advance_controller((source_b, source_a), machine)
        controller.main_advance()
        self.assertEqual([item[2]["repository_id"] for item in client.dispatches[:2]], ["1", "2"])
        self.assertEqual(sum(item[0] == "federation-g8-state-finalize.yml" for item in client.dispatches), 1)

    def test_main_advance_owned_standalone_manual_pr_is_inert(self):
        body = "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nDemo\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\ndemo\n"
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(8, RequestClass.ADD, "U_author", "alice", body_sha256(body), request)
        comment = IssueComment("IC_anchor", 200, anchor.render(), "U_bot", "app[bot]", "Bot", None, None, None, None, False)

        class ManualAdvanceClient(ReconcileClient):
            def __init__(self):
                super().__init__()
                self.pr = PullRequestMetadata(8, body, "U_author", "alice", "d" * 40, self.main, "request", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False)
                self.comments = [comment]
                self.comment_reads = 0

            def list_open_pull_requests(self, _repository):
                return ({"number": 8},)

            def get_pull_request_metadata(self, _repository, _number):
                return self.pr

            def list_issue_comments(self, _repository, _number):
                self.comment_reads += 1
                return tuple(self.comments)

        client = ManualAdvanceClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda _main, _repository, _sources: {"demo": []}
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.comment_reads, 0)
        self.assertEqual(client.dispatches, [])

    def test_main_advance_valid_standalone_manual_add_update_remove_are_inert(self):
        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE):
            with self.subTest(request_class=request_class):
                pr, comment = self._manual_main_advance_pr(request_class)
                client, controller = self._main_advance_with_prs({pr.number: pr}, {pr.number: (comment,)})
                self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
                self.assertEqual(client.comment_reads, 0)
                self.assertEqual(client.updated_branches, [])
                self.assertEqual(client.dispatches, [])

    def test_main_advance_standalone_manual_is_inert_before_head_or_comment_authority(self):
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
                self.assertEqual(client.comment_reads, 0)
                self.assertEqual(client.updated_branches, [])
                self.assertEqual(client.dispatches, [])

    def test_main_advance_does_not_inspect_standalone_anchor_forms(self):
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
                self.assertEqual(client.comment_reads, 0)
                self.assertEqual(client.updated_branches, [])
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
            ("federation-g8-reconcile.yml", "refs/heads/main", {"repository_id": "99"}),
            ("federation-g8-state-finalize.yml", "refs/heads/main", {}),
        ])

    def test_main_advance_manual_pr_does_not_change_machine_dispatch_or_finalizer_wake(self):
        machine_pr, _ = self._manual_main_advance_pr(number=41, head_ref="bot/federation/demo", author_id="U_bot", author_login="app[bot]")
        manual_pr, manual_comment = self._manual_main_advance_pr(number=8, request_class=RequestClass.UPDATE)
        client, controller = self._main_advance_with_prs(
            {machine_pr.number: machine_pr, manual_pr.number: manual_pr},
            {machine_pr.number: (), manual_pr.number: (manual_comment,)},
            {"demo": [MachinePRAuthority(41, "demo", 99, machine_pr.head_oid)]},
        )
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_DISPATCHED:1")
        self.assertEqual(sum(item[0] == "federation-g8-state-finalize.yml" for item in client.dispatches), 1)
        self.assertEqual(len(client.dispatches), 2)
        self.assertEqual(client.comment_reads, 0)
        self.assertEqual(client.updated_branches, [])

    def test_main_advance_stale_base_and_unrelated_prs_remain_no_wake(self):
        stale_pr, stale_comment = self._manual_main_advance_pr(base_oid="b" * 40)
        unrelated_pr, _ = self._manual_main_advance_pr(number=9, head_ref="topic")
        client, controller = self._main_advance_with_prs(
            {stale_pr.number: stale_pr, unrelated_pr.number: unrelated_pr},
            {stale_pr.number: (stale_comment,), unrelated_pr.number: ()},
        )
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.comment_reads, 0)
        self.assertEqual(client.dispatches, [])
        self.assertEqual(client.updated_branches, [])

    def test_main_advance_stale_marker_only_manual_pr_is_not_normalized(self):
        stale_pr, _ = self._manual_main_advance_pr(base_oid="b" * 40)
        client, controller = self._main_advance_with_prs({stale_pr.number: stale_pr}, {stale_pr.number: ()})
        with patch.object(controller_module, "read_request_marker", return_value=RequestClass.ADD) as read_marker, patch.object(controller_module, "validate_existing_request_head") as validate_head:
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        read_marker.assert_not_called()
        validate_head.assert_not_called()
        self.assertEqual(client.comment_reads, 0)
        self.assertEqual(client.updated_branches, [])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_reserved_issue_pr_is_quarantined_at_current_and_stale_bases(self):
        binding = IssuePRBinding.create(
            issue_number=7,
            issue_database_id=700,
            issue_node_id="I_7",
            issue_request_anchor_comment_database_id=701,
            issue_request_anchor_sha256="1" * 64,
            issue_branch_lease_comment_database_id=702,
            issue_branch_lease_sha256="2" * 64,
            source_id="demo",
            source_repository_id=99,
            branch_ref="refs/heads/bot/federation/request/issue-7",
            pull_request_number=8,
            pull_request_database_id=800,
            pull_request_node_id="PR_8",
            initial_head_sha="d" * 40,
            base_ref="main",
            central_repository_node_id="R_central",
        )
        issue_binding = IssueComment(
            "IC_binding", 300, binding.render_issue_binding(), "U_bot", "app[bot]", "Bot",
            None, None, None, None, False,
        )
        pr_binding = IssueComment(
            "IC_origin", 301, binding.render_pr_origin_binding(), "U_bot", "app[bot]", "Bot",
            None, None, None, None, False,
        )
        comment_states = {
            "missing": (),
            "half-issue-side": (issue_binding,),
            "half-pr-side": (pr_binding,),
            "complete": (issue_binding, pr_binding),
        }
        for base_oid in ("a" * 40, "b" * 40):
            for binding_state, comments in comment_states.items():
                with self.subTest(base_oid=base_oid, binding_state=binding_state):
                    pr_value, _ = self._manual_main_advance_pr(base_oid=base_oid)
                    reserved_pr = replace(pr_value, head_ref="bot/federation/request/issue-7")
                    client, controller = self._main_advance_with_prs(
                        {reserved_pr.number: reserved_pr}, {reserved_pr.number: comments}
                    )
                    with patch.object(controller_module, "read_request_marker") as read_marker:
                        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
                    read_marker.assert_not_called()
                    self.assertEqual(client.updated_branches, [])
                    self.assertEqual(client.dispatches, [])

    def test_main_advance_routes_reserved_issue_head_through_claim_path_without_branch_update(self):
        pr_value, _ = self._manual_main_advance_pr()
        reserved_pr = replace(pr_value, head_ref="bot/federation/request/issue-7")
        client, controller = self._main_advance_with_prs(
            {reserved_pr.number: reserved_pr}, {reserved_pr.number: ()},
        )
        result = IssueManagedRouteResult("CLAIM_READY", "PROPOSAL", RequestClass.ADD)
        with patch.object(controller, "interactive_issue_managed_route", return_value=result) as route:
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        route.assert_called_once()
        self.assertEqual(route.call_args.args[0], 7)
        self.assertIs(route.call_args.args[1].__self__, controller)
        self.assertEqual(client.updated_branches, [])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_preserves_exact_managed_noop_result(self):
        pr_value, _ = self._manual_main_advance_pr()
        reserved_pr = replace(pr_value, head_ref="bot/federation/request/issue-7")
        client, controller = self._main_advance_with_prs(
            {reserved_pr.number: reserved_pr}, {reserved_pr.number: ()},
        )
        expected = IssueManagedRouteResult("NOOP", "NO_SEMANTIC_CHANGE", RequestClass.ADD)
        with patch.object(controller, "interactive_issue_managed_route", return_value=expected):
            self.assertIs(controller.main_advance(), expected)
        self.assertEqual(client.updated_branches, [])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_malformed_reserved_issue_prefix_fails_closed(self):
        pr_value, _ = self._manual_main_advance_pr(base_oid="b" * 40)
        malformed_pr = replace(pr_value, head_ref="bot/federation/request/issue-01")
        client, controller = self._main_advance_with_prs({malformed_pr.number: malformed_pr}, {malformed_pr.number: ()})
        with patch.object(controller_module, "read_request_marker") as read_marker:
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        read_marker.assert_not_called()
        self.assertEqual(client.comment_reads, 0)
        self.assertEqual(client.updated_branches, [])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_stale_marker_only_pr_ignores_all_comments_and_stays_inert(self):
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
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.comment_reads, 0)
        self.assertEqual(client.updated_branches, [])
        self.assertEqual(client.dispatches, [])

    def test_main_advance_stale_marker_only_pr_does_not_validate_or_update_branch(self):
        stale_pr, _ = self._manual_main_advance_pr(base_oid="b" * 40)
        client, controller = self._main_advance_with_prs({stale_pr.number: stale_pr}, {stale_pr.number: ()})
        with patch.object(controller_module, "read_request_marker") as read_marker, patch.object(
            controller_module, "validate_existing_request_head", side_effect=R02Error("unsafe stale request")
        ) as validate_head:
            self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        read_marker.assert_not_called()
        validate_head.assert_not_called()
        self.assertEqual(client.comment_reads, 0)
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
                    8: PullRequestMetadata(8, body, "U_author", "alice", "d" * 40, "b" * 40, "request", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False),
                    9: PullRequestMetadata(9, "", "U", "other[bot]", "d" * 40, self.main, "bot/federation/demo", "main", "R_central", "swiftstream/skills", "R_central", "swiftstream/skills", None, False, False),
                }
                self.comments_by_pr = {8: (comment,), 9: ()}

            def list_open_pull_requests(self, _repository):
                return ({"number": 8}, {"number": 9})

            def get_pull_request_metadata(self, _repository, number):
                return self.prs[number]

            def list_issue_comments(self, _repository, number):
                return self.comments_by_pr[number]

        client = InvalidClient()
        source = c02.SourceDeclaration("demo", "Owner/Repo", 99, "skills", "Demo", (c02.LineDeclaration("refs/heads/main", ("demo",)),))
        controller = R02Controller(client, "swiftstream/skills", AppIdentity("app", 1, "A", 2, "U_bot", "app[bot]"))
        controller._accepted_sources = lambda _main=None: (source,)
        controller._machine_prs = lambda _main, _repository, _sources: {"demo": []}
        self.assertEqual(controller.main_advance(), "MAIN_ADVANCE_NOOP")
        self.assertEqual(client.dispatches, [])

    def test_main_advance_workflow_has_push_main_static_boundaries(self):
        workflow = (controller_module.Path(__file__).resolve().parents[2] / ".github/workflows/federation-g8-main-advance.yml").read_text()
        self.assertIn("branches: [main]", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("permission-contents: write", workflow)
        self.assertIn("permission-pull-requests: write", workflow)
        self.assertIn("group: swiftstream-skills-federation-manual-authority", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("queue: max", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertNotIn("FEDERATION_NO_BYPASS_PROOF_V2", workflow)

    def test_main_advance_and_interactive_share_request_anchor_authority_concurrency(self):
        workflows = controller_module.Path(__file__).resolve().parents[2] / ".github/workflows"
        main_advance = (workflows / "federation-g8-main-advance.yml").read_text()
        interactive = (workflows / "federation-g8-interactive.yml").read_text()
        group = "group: swiftstream-skills-federation-manual-authority"
        self.assertEqual(main_advance.count(group), 1)
        self.assertEqual(interactive.count(group), 1)
        self.assertIn("cancel-in-progress: false", main_advance)
        self.assertIn("cancel-in-progress: false", interactive)
        self.assertIn("queue: max", main_advance)
        self.assertIn("queue: max", interactive)
        self.assertNotIn("group: federation-interactive-pr-", interactive)


if __name__ == "__main__":
    unittest.main()
