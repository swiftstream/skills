import hashlib
import json
import os
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from automation.federation.controller import (
    AppIdentity,
    DuplicateCheckRunError,
    MissingTrustedCheckError,
    R02Error,
    TRUSTED_VALIDATION_NAME,
    TrustedValidationResult,
    evaluate_trusted_validation,
    finalize_manual_trust_sweep,
    bounded_check_output,
    resolve_app_identity,
    upsert_trusted_validation_check,
    main,
    trusted_c02_execution,
)
import automation.federation.controller as controller_module
from scripts import federate as c02
from automation.federation.github_api import CheckRun, RepositoryMetadata
from automation.federation.github_api import REST_BASE_URL, GitHubClient, HttpResponse, UrllibTransport
from tests.automation.test_interactive import ProductionAddClient


ROOT = Path(__file__).resolve().parents[2]
APP = AppIdentity("swiftstream-federation", 77, "A_app", 88, "U_bot", "swiftstream-federation[bot]")


class ValidationTests(unittest.TestCase):
    def test_valid_fixture_only_can_pass_and_exact_check_output_is_bounded(self):
        request_class = __import__("automation.federation.request_model", fromlist=["RequestClass"]).RequestClass.ADD
        result = evaluate_trusted_validation(request_class, "a" * 40, "b" * 40, lambda: (True, "candidate-ok"), allow_success=True)
        self.assertEqual(result.conclusion, "success")
        proofless = evaluate_trusted_validation(request_class, "a" * 40, "b" * 40, lambda: (True, "candidate-ok"))
        self.assertEqual(proofless.conclusion, "failure")
        self.assertEqual(set(result.output), {"class", "head", "accepted_base", "result"})

    def test_fixed_graphql_metadata_and_complete_comment_pagination(self):
        class Transport:
            def __init__(self):
                self.calls = []

            def request(self, method, url, headers, body, timeout):
                self.calls.append((method, url, body))
                if url == REST_BASE_URL + "/apps/swiftstream-federation":
                    return HttpResponse(200, url, b'{"id":77,"slug":"swiftstream-federation","node_id":"A_app"}')
                if url == REST_BASE_URL + "/users/swiftstream-federation%5Bbot%5D":
                    return HttpResponse(200, url, b'{"id":88,"login":"swiftstream-federation[bot]","node_id":"U_bot","type":"Bot"}')
                payload = json.loads(body)
                if "FederationPullRequest" in payload["query"]:
                    return HttpResponse(200, url, json.dumps({"data": {"repository": {"pullRequest": {"number": 7, "body": "body", "author": {"id": "U_author", "login": "alice"}, "headRefOid": "a" * 40, "baseRefOid": "b" * 40, "headRefName": "proposal", "baseRefName": "main", "headRepository": {"id": "7", "nameWithOwner": "swiftstream/skills"}, "baseRepository": {"id": "7", "nameWithOwner": "swiftstream/skills"}, "lastEditedAt": None, "includesCreatedEdit": False}}}}).encode())
                cursor = payload["variables"]["after"]
                node = {"id": "IC_" + ("2" if cursor else "1"), "databaseId": 2 if cursor else 1, "body": "comment", "author": {"id": "U_author", "login": "alice", "__typename": "User"}, "editor": None, "lastEditedAt": None, "includesCreatedEdit": False}
                page = {"nodes": [node], "pageInfo": {"hasNextPage": cursor is None, "endCursor": "cursor-1" if cursor is None else None}}
                return HttpResponse(200, url, json.dumps({"data": {"repository": {"issue": {"comments": page}}}}).encode())

        transport = Transport()
        client = GitHubClient("token", transport)
        self.assertEqual(resolve_app_identity(client, "swiftstream-federation").bot_node_id, "U_bot")
        self.assertEqual(client.get_app_metadata("swiftstream-federation").id, 77)
        self.assertEqual(client.get_bot_metadata("swiftstream-federation").node_id, "U_bot")
        self.assertEqual(client.get_pull_request_metadata("swiftstream/skills", 7).head_oid, "a" * 40)
        self.assertEqual([item.database_id for item in client.list_issue_comments("swiftstream/skills", 7)], [1, 2])
        self.assertTrue(all("swiftstream/skills" not in json.loads(call[2])["query"] for call in transport.calls if call[0] == "POST"))

    def test_commit_metadata_is_frozen_and_check_update_cannot_retarget_head(self):
        tree = "1" * 40
        parent = "2" * 40
        message = "Swift Stream federation add-source\n"
        body = (
            f"tree {tree}\nparent {parent}\n"
            "author Swift Stream Federation <automation@swiftstream.invalid> 946684800 +0000\n"
            "committer Swift Stream Federation <automation@swiftstream.invalid> 946684800 +0000\n\n"
        ).encode() + message.encode()
        commit_sha = hashlib.sha1(b"commit " + str(len(body)).encode() + b"\0" + body).hexdigest()

        class Transport:
            def __init__(self):
                self.calls = []

            def request(self, method, url, headers, payload, timeout):
                self.calls.append((method, url, payload))
                if method == "POST" and url.endswith("/git/commits"):
                    return HttpResponse(201, url, json.dumps({"sha": commit_sha, "author": {"name": "Swift Stream Federation", "email": "automation@swiftstream.invalid", "date": "2000-01-01T00:00:00Z"}, "committer": {"name": "Swift Stream Federation", "email": "automation@swiftstream.invalid", "date": "2000-01-01T00:00:00Z"}}).encode())
                if method == "PATCH" and "/check-runs/12" in url:
                    return HttpResponse(200, url, json.dumps({"id": 12, "name": TRUSTED_VALIDATION_NAME, "head_sha": "a" * 40, "status": "completed", "conclusion": "success", "app": {"id": 77}}).encode())
                raise AssertionError((method, url))

        transport = Transport()
        client = GitHubClient("token", transport)
        self.assertEqual(client.create_commit("swiftstream/skills", message, tree, [parent]).sha, commit_sha)
        self.assertEqual(client.create_commit("swiftstream/skills", message, tree, [parent]).sha, commit_sha)
        commit_payloads = [json.loads(item[2]) for item in transport.calls if item[0] == "POST"]
        self.assertEqual(commit_payloads[0]["author"], {"name": "Swift Stream Federation", "email": "automation@swiftstream.invalid", "date": "2000-01-01T00:00:00Z"})
        updated = client.update_check_run("swiftstream/skills", 12, head_sha="a" * 40, conclusion="success")
        self.assertEqual(updated.head_sha, "a" * 40)
        patch_payload = json.loads(next(item[2] for item in transport.calls if item[0] == "PATCH"))
        self.assertNotIn("head_sha", patch_payload)

    def test_production_trusted_validation_main_uses_real_checker_and_valid_check_run_output(self):
        from tests.automation.test_interactive import ProductionAddClient

        fake = ProductionAddClient()
        base_env = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, base_env, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            self.assertEqual(main(["trusted-validation"]), 0)
            self.assertEqual(main(["trusted-validation"]), 0)
        self.assertEqual(fake.checks[-1][1], TRUSTED_VALIDATION_NAME)
        self.assertEqual(fake.checks[-1][2], fake.current_pr.head_oid)
        self.assertEqual(len(fake.check_objects), 1)
        self.assertEqual(fake.checks[0][1], TRUSTED_VALIDATION_NAME)
        payload = fake.checks[-1][3]["output"]
        self.assertEqual(set(payload), {"title", "summary", "text"})
        self.assertEqual(fake.checks[-1][3]["conclusion"], "failure")
        self.assertEqual(fake.dispatches[-1][1], "federation-state-finalize.yml")

    def test_c05_central_transport_has_explicit_empty_proxy_handler(self):
        transport = UrllibTransport()
        proxy_handlers = [handler for handler in transport._opener.handlers if type(handler).__name__ == "ProxyHandler"]
        self.assertEqual(proxy_handlers, [])

    def test_c05_static_inventory_has_no_ambient_c02_or_default_runtime_authority(self):
        controller_source = (ROOT / "automation/federation/controller.py").read_text()
        github_source = (ROOT / "automation/federation/github_api.py").read_text()
        self.assertNotIn("c02.validate_ref", github_source)
        self.assertNotIn("c02.run_git", github_source)
        self.assertNotIn("TemporaryDirectory(", controller_source)
        self.assertNotIn("tempfile.mkdtemp", controller_source)
        self.assertNotIn("os.environ.copy", controller_source)
        self.assertIn("_verified_trusted_git", controller_source)
        self.assertIn("_trusted_child_environment", controller_source)
        self.assertIn("ProxyHandler({})", github_source)

    def test_production_state_finalize_main_regenerates_checks_without_merge_and_uses_trusted_env(self):
        from tests.automation.test_interactive import ProductionAddClient

        fake = ProductionAddClient()
        env = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "999", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, env, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            self.assertEqual(main(["state-finalize"]), 0)
            self.assertEqual(fake.check_objects, [])
            self.assertEqual(fake.dispatches[-1][1], "federation-trusted-validation.yml")
            self.assertEqual(fake.dispatches[-1][3], {"pull_number": "7"})
            self.assertEqual(main(["trusted-validation"]), 0)
            self.assertEqual(main(["state-finalize"]), 0)
        self.assertEqual(fake.checks[-1][1], TRUSTED_VALIDATION_NAME)
        self.assertEqual(len(fake.check_objects), 1)
        self.assertEqual(fake.checks[-2][3]["conclusion"], "failure")
        self.assertEqual(fake.checks[-1][3]["conclusion"], "success")
        self.assertFalse(hasattr(fake, "merge_calls"))

    def test_check_run_upsert_ignores_wrong_app_updates_one_and_fails_on_duplicate(self):
        class Checks:
            def __init__(self, checks):
                self.checks = list(checks)
                self.created = []
                self.updated = []

            def list_check_runs(self, repository, head_sha):
                return tuple(item for item in self.checks if item.head_sha == head_sha)

            def create_check_run(self, repository, name, head_sha, **kwargs):
                value = CheckRun(99, name, head_sha, "completed", kwargs.get("conclusion"), APP.app_id)
                self.created.append(value)
                self.checks.append(value)
                return value

            def update_check_run(self, repository, check_id, *, head_sha, status="completed", conclusion=None, output=None):
                self.updated.append((check_id, head_sha, conclusion, output))
                value = next(item for item in self.checks if item.id == check_id)
                return CheckRun(value.id, value.name, value.head_sha, status, conclusion, value.app_id)

        head = "a" * 40
        result = TrustedValidationResult("failure", bounded_check_output(__import__("automation.federation.request_model", fromlist=["RequestClass"]).RequestClass.ADD, head, "b" * 40, reason="BLOCKED"))
        wrong = CheckRun(1, TRUSTED_VALIDATION_NAME, head, "completed", "success", 999)
        client = Checks([wrong])
        created = upsert_trusted_validation_check(client, "swiftstream/skills", APP, result, allow_create=True)
        self.assertEqual(created.app_id, APP.app_id)
        self.assertEqual(client.created[0].id, 99)
        owned = CheckRun(2, TRUSTED_VALIDATION_NAME, head, "completed", "failure", APP.app_id)
        client = Checks([owned])
        updated = upsert_trusted_validation_check(client, "swiftstream/skills", APP, result, allow_create=True)
        self.assertEqual(updated.id, 2)
        self.assertEqual(client.updated[0][0], 2)
        duplicate = Checks([owned, CheckRun(3, TRUSTED_VALIDATION_NAME, head, "completed", "failure", APP.app_id)])
        with self.assertRaises(DuplicateCheckRunError):
            upsert_trusted_validation_check(duplicate, "swiftstream/skills", APP, result, allow_create=True)
        missing = Checks([])
        with self.assertRaises(MissingTrustedCheckError):
            upsert_trusted_validation_check(missing, "swiftstream/skills", APP, result, allow_create=False)
        self.assertEqual(missing.created, [])
        green = TrustedValidationResult("success", bounded_check_output(__import__("automation.federation.request_model", fromlist=["RequestClass"]).RequestClass.ADD, head, "b" * 40, reason="READY"))
        with self.assertRaises(R02Error):
            upsert_trusted_validation_check(Checks([]), "swiftstream/skills", APP, green, allow_create=True)

    def test_trusted_validation_production_main_never_attaches_h1_result_to_h2(self):
        from tests.automation.test_interactive import ProductionAddClient
        from automation.federation.controller import C02CandidateBuilder

        fake = ProductionAddClient()
        base_env = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}

        class HeadRaceBuilder(C02CandidateBuilder):
            def validate_head(self, request, request_class, accepted_base_sha, head_sha):
                calls.append(head_sha)
                fake.current_pr = replace(fake.current_pr, head_oid="e" * 40)
                return True, "CANDIDATE_MATCHES_C02"

        calls = []
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, base_env, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            dispatch_count = len(fake.dispatches)
            with patch.object(controller_module, "C02CandidateBuilder", HeadRaceBuilder):
                self.assertEqual(main(["trusted-validation"]), 1, (fake.current_pr.head_oid, calls, fake.dispatches))
        self.assertEqual(fake.check_objects, [], fake.dispatches)
        self.assertEqual(len(fake.dispatches), dispatch_count + 1)
        self.assertNotEqual(fake.dispatches[-1][3], {"pull_number": "7"})

    def test_trusted_validation_production_main_invalidates_comment_change_during_candidate_check(self):
        from tests.automation.test_interactive import ProductionAddClient
        from automation.federation.controller import C02CandidateBuilder

        fake = ProductionAddClient()
        base_env = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}

        class CommentRaceBuilder(C02CandidateBuilder):
            def validate_head(self, request, request_class, accepted_base_sha, head_sha):
                fake.comments.append(__import__("tests.automation.test_interactive", fromlist=["comment"]).comment(250, "ordinary comment"))
                return True, "CANDIDATE_MATCHES_C02"

        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, base_env, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            dispatch_count = len(fake.dispatches)
            with patch.object(controller_module, "C02CandidateBuilder", CommentRaceBuilder):
                self.assertEqual(main(["trusted-validation"]), 1)
        self.assertEqual(fake.check_objects, [])
        self.assertEqual(len(fake.dispatches), dispatch_count + 1)

    def test_state_finalize_rechecks_current_main_immediately_before_green(self):
        from tests.automation.test_interactive import ProductionAddClient

        class RuntimeClient(ProductionAddClient):
            def __init__(self):
                super().__init__()
                self.ref_reads = 0

            def get_ref_oid(self, repository, branch):
                self.ref_reads += 1
                if self.ref_reads == 7:
                    self.main_oid = "e" * 40
                return self.main_oid

        fake = RuntimeClient()
        env = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, env, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            fake.ref_reads = 0
            self.assertEqual(main(["state-finalize"]), 1)
        self.assertFalse(any(item[3].get("conclusion") == "success" for item in fake.checks))
        self.assertEqual(fake.dispatches[-1][1], "federation-state-finalize.yml")

    def test_state_finalize_stale_checkout_self_wakes_without_cas_or_green(self):
        from tests.automation.test_interactive import ProductionAddClient

        fake = ProductionAddClient()
        good = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": fake.main_oid}
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, good, clear=False):
            self.assertEqual(main(["interactive"]), 0)
            refs_before = len(fake.ref_calls)
            stale = dict(good, FEDERATION_TRUSTED_CHECKOUT_SHA="0" * 40)
            with patch.dict(os.environ, stale, clear=False):
                self.assertEqual(main(["state-finalize"]), 0)
        self.assertEqual(len(fake.ref_calls), refs_before)
        self.assertEqual(fake.check_objects, [])
        self.assertEqual(fake.dispatches[-1][3], {})

    def test_finalizer_ignores_hints_and_sweeps_all_manual_prs_with_bound(self):
        class Client:
            def get_repository_metadata(self, _repository):
                return RepositoryMetadata(7, "R_7", "swiftstream/skills", "main")
            def get_ref_oid(self, _repository, _branch):
                return "a" * 40
            def list_open_pull_requests(self, _repository):
                return ({"number": 13}, {"number": 2}, {"number": 9})
        client = Client()
        seen = []
        result = finalize_manual_trust_sweep(client, "swiftstream/skills", lambda pr: seen.append(pr["number"]), wake_hints={"pull_number": 999}, max_iterations=2)
        self.assertEqual(result, "swept-all-manual-trust-prs")
        self.assertEqual(seen, [2, 9, 13])

    def test_stale_trusted_checkout_blocks_production_main_before_any_cas(self):
        from tests.automation.test_interactive import ProductionAddClient
        fake = ProductionAddClient()
        env = {"GITHUB_REPOSITORY": "swiftstream/skills", "FEDERATION_GITHUB_TOKEN": "token", "FEDERATION_APP_SLUG": APP.slug, "FEDERATION_WAKE_PULL_NUMBER": "7", "FEDERATION_TRUSTED_CHECKOUT_SHA": "0" * 40}
        with patch("automation.federation.controller.GitHubClient", return_value=fake), patch.object(controller_module, "SOURCE_HTTP_GET", fake.source_http_get), patch.object(controller_module, "SOURCE_BRANCH_FETCHER", fake.source_branch_fetcher), patch.dict(os.environ, env, clear=False):
            self.assertEqual(main(["interactive"]), 1)
        self.assertEqual(fake.ref_calls, [])

if __name__ == "__main__":
    unittest.main()
