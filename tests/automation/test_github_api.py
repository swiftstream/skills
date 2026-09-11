import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automation.federation.github_api import (
    GRAPHQL_ENDPOINT,
    ISSUE_COMMENTS_QUERY,
    PULL_REQUEST_BODY_FALLBACK_QUERY,
    PULL_REQUEST_ROUTING_AFTER_QUERY,
    PULL_REQUEST_ROUTING_BEFORE_QUERY,
    UPDATE_REFS_MUTATION,
    ZERO_OID,
    GitHubClient,
    GitHubAPIError,
    GraphQLError,
    HttpResponse,
    InvalidResponseError,
    RedirectError,
    RefCASConflict,
    RefUpdate,
    ResponseBodyTooLargeError,
    TransportError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    UnprocessableError,
    RateLimitedError,
    ServerError,
    UnexpectedStatusError,
    REST_BASE_URL,
)


class FakeTransport:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def request(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        return self.response


def _routing_payload(*, repository="swiftstream/skills", number=7, head_oid="a" * 40, base_oid="b" * 40,
                     head_ref="proposal", base_ref="main", last_edited_at=None, includes_created_edit=False):
    return {"data": {"repository": {"nameWithOwner": repository, "pullRequest": {
        "number": number,
        "headRefOid": head_oid,
        "baseRefOid": base_oid,
        "headRefName": head_ref,
        "baseRefName": base_ref,
        "lastEditedAt": last_edited_at,
        "includesCreatedEdit": includes_created_edit,
    }}}}


def _rest_payload(*, body="body", number=7, head_oid="a" * 40, base_oid="b" * 40,
                  head_ref="proposal", base_ref="main"):
    return {"number": number, "body": body,
            "user": {"login": "alice", "node_id": "U_author"},
            "head": {"sha": head_oid, "ref": head_ref,
                     "repo": {"node_id": "N_head", "full_name": "alice/skills"}},
            "base": {"sha": base_oid, "ref": base_ref,
                     "repo": {"node_id": "N_base", "full_name": "swiftstream/skills"}}}


class PullMetadataTransport:
    def __init__(self, *, before=None, rest=None, after=None, fallback=None):
        self.before = _routing_payload() if before is None else before
        self.rest = _rest_payload() if rest is None else rest
        self.after = _routing_payload() if after is None else after
        self.fallback = fallback
        self.calls = []

    def request(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        if url == GRAPHQL_ENDPOINT:
            query = json.loads(body)["query"]
            if query == PULL_REQUEST_ROUTING_BEFORE_QUERY:
                payload = self.before
            elif query == PULL_REQUEST_ROUTING_AFTER_QUERY:
                payload = self.after
            elif query == PULL_REQUEST_BODY_FALLBACK_QUERY:
                payload = self.fallback
            else:
                raise AssertionError(query)
            return HttpResponse(200, url, json.dumps(payload, separators=(",", ":")).encode())
        if url == REST_BASE_URL + "/repos/swiftstream/skills/pulls/7":
            return HttpResponse(200, url, json.dumps(self.rest, separators=(",", ":")).encode())
        raise AssertionError((method, url))


def _call_signature(calls):
    return [(method, url, None if body is None else json.loads(body)["query"]) for method, url, _headers, body, _timeout in calls]


class GitHubAPITests(unittest.TestCase):
    def _graphql_error(self, error, *, errors=None, token="test-token", variables=None, client_class=GitHubClient):
        payload = {"errors": [error] if errors is None else errors, "data": {"mustNotReturn": True}}
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps(payload, separators=(",", ":")).encode()))
        client = client_class(token, fake)
        supplied_variables = variables if variables is not None else {"owner": "swiftstream", "name": "skills", "number": 1}
        with self.assertRaises(GraphQLError) as caught:
            client._graphql(ISSUE_COMMENTS_QUERY, supplied_variables)
        return str(caught.exception), fake

    def test_headers_token_redaction_and_json(self):
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b'{"data":{"updateRefs":{"clientMutationId":null}}}'))
        token = "super-secret-token"
        client = GitHubClient(token, fake)
        update = RefUpdate("refs/heads/bot", ZERO_OID, "1" * 40)
        client.update_refs("repo-node", [update])
        method, url, headers, body, timeout = fake.calls[0]
        self.assertEqual((method, url, timeout), ("POST", GRAPHQL_ENDPOINT, 15.0))
        self.assertEqual(headers["X-GitHub-Api-Version"], "2026-03-10")
        self.assertEqual(headers["Accept"], "application/vnd.github+json")
        self.assertEqual(headers["User-Agent"], "swiftstream-skills-federation")
        self.assertNotIn(token, repr(client))
        payload = json.loads(body)
        self.assertIn("updateRefs", payload["query"])
        self.assertNotIn("repo-node", payload["query"])
        self.assertEqual(len(payload["variables"]["refUpdates"]), 1)

    def test_graphql_error_diagnostic_preserves_only_bounded_structure(self):
        text, _ = self._graphql_error({"type": "FORBIDDEN", "path": ["repository", "pullRequest"]})
        self.assertEqual(text, "GRAPHQL:FORBIDDEN:repository.pullRequest")

        text, _ = self._graphql_error({"type": "FORBIDDEN", "path": ["repository", "pullRequest", "comments", 0, "author"]})
        self.assertEqual(text, "GRAPHQL:FORBIDDEN:repository.pullRequest.comments.0.author")

        for error, expected in (
            ({"type": "FORBIDDEN"}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "forbidden", "path": ["repository"]}, "GRAPHQL:UNKNOWN:repository"),
            ({"type": "A" * 65, "path": ["repository"]}, "GRAPHQL:UNKNOWN:repository"),
            ({"type": "FORBIDDEN", "path": ["repository", True]}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "FORBIDDEN", "path": ["repository", "bad-segment"]}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "FORBIDDEN", "path": ["repository", "bad\nsegment"]}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "FORBIDDEN", "path": ["repository", -1]}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "FORBIDDEN", "path": ["repository", 1_000_000]}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "FORBIDDEN", "path": ["x"] * 17}, "GRAPHQL:FORBIDDEN:unknown-path"),
            ({"type": "FORBIDDEN", "path": []}, "GRAPHQL:FORBIDDEN:unknown-path"),
        ):
            with self.subTest(error=error):
                text, _ = self._graphql_error(error)
                self.assertEqual(text, expected)

        long_path = ["a" * 64] * 16
        text, _ = self._graphql_error({"type": "A" * 64, "path": long_path})
        self.assertEqual(text, "GRAPHQL:UNKNOWN:unknown-path")
        self.assertLessEqual(len(text.encode("utf-8")), 512)

    def test_graphql_error_diagnostic_uses_first_error_and_excludes_remote_or_request_secrets(self):
        message_sentinel = "message-secret-sentinel"
        extension_sentinel = "extension-secret-sentinel"
        variable_sentinel = "variable-secret-sentinel"
        token_sentinel = "token-secret-sentinel"
        header_sentinel = "header-secret-sentinel"

        class SentinelHeaderClient(GitHubClient):
            def _headers(self):
                headers = super()._headers()
                headers["X-Test-Sentinel"] = header_sentinel
                return headers

        first = {
            "type": "FORBIDDEN",
            "path": ["repository", "pullRequest"],
            "message": message_sentinel,
            "extensions": {"private": extension_sentinel},
        }
        second = {"type": "UNAUTHORIZED", "path": ["second", "mustNotAppear"], "message": "second-message-sentinel"}
        variables = {"owner": variable_sentinel, "name": "skills", "number": 1}
        text, fake = self._graphql_error(first, errors=[first, second], token=token_sentinel, variables=variables, client_class=SentinelHeaderClient)
        self.assertEqual(text, "GRAPHQL:FORBIDDEN:repository.pullRequest")
        self.assertEqual(fake.calls[0][2]["X-Test-Sentinel"], header_sentinel)
        for sentinel in (message_sentinel, extension_sentinel, variable_sentinel, token_sentinel, header_sentinel, "second", "second-message-sentinel"):
            self.assertNotIn(sentinel, text)

    def test_graphql_errors_remain_fail_closed_for_malformed_shapes_and_data(self):
        for errors in ({}, [], ["bad"], [{"type": "FORBIDDEN"}, "bad"]):
            payload = {"errors": errors, "data": {"mustNotReturn": True}}
            fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps(payload, separators=(",", ":")).encode()))
            with self.subTest(errors=errors), self.assertRaises(GraphQLError):
                GitHubClient(None, fake)._graphql(ISSUE_COMMENTS_QUERY, {"owner": "swiftstream", "name": "skills", "number": 1})

        text, _ = self._graphql_error({"type": "FORBIDDEN", "path": ["repository"]})
        self.assertEqual(text, "GRAPHQL:FORBIDDEN:repository")

    def test_cas_semantics_and_single_atomic_call(self):
        with self.assertRaises(Exception):
            RefUpdate("refs/heads/x", ZERO_OID, ZERO_OID)
        with self.assertRaises(Exception):
            RefUpdate("refs/heads/x", ZERO_OID, "1" * 40, True)
        self.assertEqual(RefUpdate("refs/heads/x", ZERO_OID, "1" * 40).operation, "create")
        self.assertEqual(RefUpdate("refs/heads/x", "1" * 40, "2" * 40).operation, "update")
        self.assertEqual(RefUpdate("refs/heads/x", "1" * 40, ZERO_OID).operation, "delete")
        self.assertNotIn("PATCH /git/refs", UPDATE_REFS_MUTATION)
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b'{"errors":[{"message":"CAS"}]}'))
        with self.assertRaises(RefCASConflict):
            GitHubClient(None, fake).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40), RefUpdate("refs/heads/b", "2" * 40, ZERO_OID)])
        self.assertEqual(len(fake.calls), 1)

    def test_status_body_and_json_errors_are_controlled(self):
        statuses = ((401, UnauthorizedError), (403, ForbiddenError), (404, NotFoundError), (409, ConflictError), (422, UnprocessableError), (429, RateLimitedError), (500, ServerError), (599, ServerError), (300, UnexpectedStatusError))
        for status, kind in statuses:
            fake = FakeTransport(HttpResponse(status, GRAPHQL_ENDPOINT, b"{}"))
            with self.subTest(status=status):
                with self.assertRaises(kind):
                    try:
                        GitHubClient("secret", fake).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)])
                    except kind as error:
                        self.assertNotIn("secret", str(error))
                        raise
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b"{" + b"x" * 1048577 + b"}"))
        with self.assertRaises(ResponseBodyTooLargeError):
            GitHubClient(None, fake).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)])
        self.assertIn("$repositoryId", UPDATE_REFS_MUTATION)
        self.assertIn("$refUpdates", UPDATE_REFS_MUTATION)

    def test_transport_redirect_timeout_wrong_object_and_response_encoding(self):
        redirected = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT + "/redirect", b"{}"))
        with self.assertRaises(RedirectError):
            GitHubClient(None, redirected).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)])
        class TimeoutTransport:
            def request(self, *args):
                raise socket.timeout("timed out")
        with self.assertRaises(TransportError):
            GitHubClient(None, TimeoutTransport()).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)])
        with self.assertRaises(InvalidResponseError):
            GitHubClient(None, lambda *args: object()).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)])
        for body in (b"\xff", b"not-json", b'{"data":1,"data":2}'):
            with self.subTest(body=body), self.assertRaises(InvalidResponseError):
                GitHubClient(None, FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, body))).update_refs("repo", [RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)])

    def test_invalid_repository_ref_sha_force_and_path_segments(self):
        update = lambda: RefUpdate("refs/heads/a", ZERO_OID, "1" * 40)
        for value in (None, "", 123, "repo\x00id", "repo\nid"):
            with self.subTest(value=value), self.assertRaises(Exception):
                GitHubClient(None, FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b"{}"))).update_refs(value, [update()])
        for name in ("main", "refs/tags/x", "refs/heads/", "refs/heads/../x", "refs/heads/x\n"):
            with self.subTest(name=name), self.assertRaises(Exception):
                RefUpdate(name, ZERO_OID, "1" * 40)
        for before, after in (("0", "1" * 40), ("g" * 40, "1" * 40), ("1" * 40, "0"), ("1" * 40, "2" * 40)):
            if before == "1" * 40 and after == "2" * 40:
                continue
            with self.subTest(before=before, after=after), self.assertRaises(Exception):
                RefUpdate("refs/heads/a", before, after)
        with self.assertRaises(Exception):
            RefUpdate("refs/heads/a", ZERO_OID, "1" * 40, True)
        with self.assertRaises(Exception):
            RefUpdate("refs/heads/a", "1" * 40, ZERO_OID, True)
        client = GitHubClient(None, FakeTransport(HttpResponse(200, REST_BASE_URL + "/a", b"{}")))
        for segments in (("..",), ("a/b",), ("a\\b",), ("",), ("x\x00",)):
            with self.subTest(segments=segments), self.assertRaises(Exception):
                client.request_json("GET", list(segments))

    def test_hostile_path_cannot_execute_fake_git_for_ref_update_validation(self):
        with tempfile.TemporaryDirectory() as temp_name:
            attacker = Path(temp_name) / "attacker"
            attacker.mkdir()
            sentinel = attacker / "fake-git-ran"
            fake_git = attacker / "git"
            fake_git.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 99\n")
            fake_git.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(attacker)}, clear=False):
                update = RefUpdate("refs/heads/safe", ZERO_OID, "1" * 40)
            self.assertEqual(update.name, "refs/heads/safe")
            self.assertFalse(sentinel.exists())

    def test_graphql_shapes_are_fail_closed_and_variables_are_data(self):
        update = RefUpdate("refs/heads/injected", ZERO_OID, "1" * 40)
        malformed = (
            {"errors": {}},
            {"errors": ["bad"]},
            {"data": None},
            {"data": {"updateRefs": None}},
            {"data": {"updateRefs": {"clientMutationId": None, "extra": 1}}},
            {"data": {"updateRefs": {"clientMutationId": 4}}},
        )
        for result in malformed:
            body = json.dumps(result, separators=(",", ":")).encode()
            with self.subTest(result=result), self.assertRaises((GraphQLError, InvalidResponseError)):
                GitHubClient(None, FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, body))).update_refs("repo\"} injection", [update])
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b'{"data":{"updateRefs":{"clientMutationId":null}}}'))
        repository_id = 'repo"} mutation { deleteRepository(id: "x") {'
        GitHubClient(None, fake).update_refs(repository_id, [update])
        payload = json.loads(fake.calls[0][3])
        self.assertNotIn(repository_id, payload["query"])
        self.assertNotIn(update.name, payload["query"])
        self.assertEqual(payload["variables"]["repositoryId"], repository_id)

    def test_pull_metadata_normal_order_and_complete_contract(self):
        transport = PullMetadataTransport()
        metadata = GitHubClient("token", transport).get_pull_request_metadata("swiftstream/skills", 7)
        self.assertEqual(_call_signature(transport.calls), [
            ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_BEFORE_QUERY),
            ("GET", REST_BASE_URL + "/repos/swiftstream/skills/pulls/7", None),
            ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_AFTER_QUERY),
        ])
        self.assertEqual(metadata.number, 7)
        self.assertEqual(metadata.body, "body")
        self.assertEqual(metadata.author_id, "U_author")
        self.assertEqual(metadata.author_login, "alice")
        self.assertEqual(metadata.head_oid, "a" * 40)
        self.assertEqual(metadata.base_oid, "b" * 40)
        self.assertEqual(metadata.head_ref, "proposal")
        self.assertEqual(metadata.base_ref, "main")
        self.assertEqual(metadata.head_repository_id, "N_head")
        self.assertEqual(metadata.head_repository, "alice/skills")
        self.assertEqual(metadata.base_repository_id, "N_base")
        self.assertEqual(metadata.base_repository, "swiftstream/skills")
        self.assertIsNone(metadata.last_edited_at)
        self.assertFalse(metadata.includes_created_edit)

    def test_pull_metadata_null_body_uses_one_exact_fallback_and_preserves_body(self):
        for body in ("", "body from fallback"):
            with self.subTest(body=body):
                transport = PullMetadataTransport(rest=_rest_payload(body=None), fallback={
                    "data": {"repository": {"nameWithOwner": "swiftstream/skills", "pullRequest": {"number": 7, "body": body}}}
                })
                metadata = GitHubClient(None, transport).get_pull_request_metadata("swiftstream/skills", 7)
                self.assertEqual(metadata.body, body)
                self.assertEqual(_call_signature(transport.calls), [
                    ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_BEFORE_QUERY),
                    ("GET", REST_BASE_URL + "/repos/swiftstream/skills/pulls/7", None),
                    ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_BODY_FALLBACK_QUERY),
                    ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_AFTER_QUERY),
                ])

    def test_pull_graphql_documents_are_p2_free_and_old_document_is_not_trusted(self):
        for document in (PULL_REQUEST_ROUTING_BEFORE_QUERY, PULL_REQUEST_ROUTING_AFTER_QUERY):
            self.assertNotIn("body", document)
            self.assertNotIn("author", document)
        self.assertIn("body", PULL_REQUEST_BODY_FALLBACK_QUERY)
        self.assertNotIn("author", PULL_REQUEST_BODY_FALLBACK_QUERY)
        old_document = "query FederationPullRequest($owner: String!, $name: String!, $number: Int!) { repository { pullRequest { body author { id } } } }"
        with self.assertRaises(GitHubAPIError):
            GitHubClient(None, FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b'{}')))._graphql(
                old_document, {"owner": "swiftstream", "name": "skills", "number": 7}
            )

    def test_pull_routing_drift_rejects_all_authority_fields(self):
        variants = (
            ("headRefOid", "c" * 40),
            ("baseRefOid", "d" * 40),
            ("headRefName", "other-head"),
            ("baseRefName", "other-base"),
            ("lastEditedAt", "2026-09-10T00:00:00Z"),
            ("includesCreatedEdit", True),
        )
        for field, changed in variants:
            with self.subTest(field=field):
                after = _routing_payload()
                after["data"]["repository"]["pullRequest"][field] = changed
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, PullMetadataTransport(after=after)).get_pull_request_metadata("swiftstream/skills", 7)

        timestamp = "2026-09-10T00:00:00Z"
        for before_value, after_value in ((None, timestamp), (timestamp, None)):
            with self.subTest(before_value=before_value, after_value=after_value):
                before = _routing_payload(last_edited_at=before_value)
                after = _routing_payload(last_edited_at=after_value)
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, PullMetadataTransport(before=before, after=after)).get_pull_request_metadata("swiftstream/skills", 7)

    def test_pull_rest_topology_mismatch_rejects_sha_and_ref_changes(self):
        for field, changed in (("head_oid", "c" * 40), ("base_oid", "d" * 40), ("head_ref", "other-head"), ("base_ref", "other-base")):
            with self.subTest(field=field):
                values = {field: changed}
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, PullMetadataTransport(rest=_rest_payload(**values))).get_pull_request_metadata("swiftstream/skills", 7)

    def test_pull_rest_malformed_identity_and_number_fail_closed(self):
        cases = (
            ("number", 8),
            ("user", None),
            ("head", None),
            ("base", None),
        )
        for field, value in cases:
            with self.subTest(field=field):
                rest = _rest_payload()
                rest[field] = value
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, PullMetadataTransport(rest=rest)).get_pull_request_metadata("swiftstream/skills", 7)

        for path, value in ((("user", "login"), None), (("user", "node_id"), 1),
                            (("head", "sha"), "not-sha"), (("base", "ref"), ""),
                            (("head", "repo"), None), (("base", "repo", "full_name"), "")):
            with self.subTest(path=path):
                rest = _rest_payload()
                target = rest
                for part in path[:-1]:
                    target = target[part]
                target[path[-1]] = value
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, PullMetadataTransport(rest=rest)).get_pull_request_metadata("swiftstream/skills", 7)

    def test_pull_rest_body_validation_is_exact_and_bounded(self):
        missing = _rest_payload()
        missing.pop("body")
        cases = [("missing", missing), ("int", _rest_payload(body=1)), ("list", _rest_payload(body=[])),
                 ("object", _rest_payload(body={})), ("oversized", _rest_payload(body="x" * 16_385))]
        for label, rest in cases:
            with self.subTest(body=label), self.assertRaises(InvalidResponseError):
                GitHubClient(None, PullMetadataTransport(rest=rest)).get_pull_request_metadata("swiftstream/skills", 7)

    def test_pull_rest_string_body_never_sends_body_fallback(self):
        transport = PullMetadataTransport(rest=_rest_payload(body="exact REST body"), fallback={"errors": [{"type": "FORBIDDEN"}]})
        self.assertEqual(GitHubClient(None, transport).get_pull_request_metadata("swiftstream/skills", 7).body, "exact REST body")
        self.assertNotIn(PULL_REQUEST_BODY_FALLBACK_QUERY, [item[2] for item in _call_signature(transport.calls) if item[2]])

    def test_pull_body_fallback_errors_fail_closed_without_retry_or_after(self):
        error_payload = {"errors": [{"type": "FORBIDDEN", "path": ["repository", "pullRequest"]}], "data": {}}
        transport = PullMetadataTransport(rest=_rest_payload(body=None), fallback=error_payload)
        with self.assertRaises(GraphQLError) as caught:
            GitHubClient(None, transport).get_pull_request_metadata("swiftstream/skills", 7)
        self.assertEqual(str(caught.exception), "GRAPHQL:FORBIDDEN:pullBodyFallback.repository.pullRequest")
        self.assertEqual(len(transport.calls), 3)

        fallback_cases = (
            {"nameWithOwner": "other/skills", "pullRequest": {"number": 7, "body": "x"}},
            {"nameWithOwner": "swiftstream/skills", "pullRequest": {"number": 8, "body": "x"}},
            {"nameWithOwner": "swiftstream/skills", "pullRequest": {"number": 7, "body": None}},
            {"nameWithOwner": "swiftstream/skills", "pullRequest": {"number": 7, "body": "x" * 16_385}},
        )
        for pull in fallback_cases:
            with self.subTest(pull=pull):
                transport = PullMetadataTransport(rest=_rest_payload(body=None), fallback={"data": {"repository": pull}})
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, transport).get_pull_request_metadata("swiftstream/skills", 7)
                self.assertEqual(len(transport.calls), 3)

    def test_pull_routing_repository_identity_is_required_before_and_after(self):
        for operation in ("before", "after"):
            for identity in (None, 1, "other/skills"):
                with self.subTest(operation=operation, identity=identity):
                    kwargs = {operation: _routing_payload(repository=identity)}
                    transport = PullMetadataTransport(**kwargs)
                    with self.assertRaises(InvalidResponseError):
                        GitHubClient(None, transport).get_pull_request_metadata("swiftstream/skills", 7)
                    if operation == "before":
                        self.assertEqual(
                            _call_signature(transport.calls),
                            [("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_BEFORE_QUERY)],
                        )
                    else:
                        self.assertEqual(
                            _call_signature(transport.calls),
                            [
                                ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_BEFORE_QUERY),
                                ("GET", REST_BASE_URL + "/repos/swiftstream/skills/pulls/7", None),
                                ("POST", GRAPHQL_ENDPOINT, PULL_REQUEST_ROUTING_AFTER_QUERY),
                            ],
                        )

    def test_pull_routing_diagnostics_are_local_and_secret_free(self):
        variables = {"owner": "swiftstream", "name": "skills", "number": 7}
        for document, operation in ((PULL_REQUEST_ROUTING_BEFORE_QUERY, "pullRoutingBefore"),
                                    (PULL_REQUEST_ROUTING_AFTER_QUERY, "pullRoutingAfter"),
                                    (PULL_REQUEST_BODY_FALLBACK_QUERY, "pullBodyFallback")):
            for error, expected in (
                ({"type": "UNKNOWN"}, f"GRAPHQL:UNKNOWN:{operation}"),
                ({"type": "FORBIDDEN", "path": ["repository", "pullRequest"]}, f"GRAPHQL:FORBIDDEN:{operation}.repository.pullRequest"),
            ):
                with self.subTest(operation=operation, error=error):
                    fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps({"errors": [error], "data": {}}).encode()))
                    with self.assertRaises(GraphQLError) as caught:
                        GitHubClient(None, fake)._graphql(document, variables, operation=operation)
                    self.assertEqual(str(caught.exception), expected)

            segment_boundary_path = ["a"] * 16
            segment_baseline = "GRAPHQL:FORBIDDEN:" + ".".join(segment_boundary_path)
            fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps({"errors": [{"type": "FORBIDDEN", "path": segment_boundary_path}], "data": {}}).encode()))
            with self.assertRaises(GraphQLError) as caught:
                GitHubClient(None, fake)._graphql(document, variables)
            self.assertEqual(str(caught.exception), segment_baseline)

            fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps({"errors": [{"type": "FORBIDDEN", "path": segment_boundary_path}], "data": {}}).encode()))
            with self.assertRaises(GraphQLError) as caught:
                GitHubClient(None, fake)._graphql(document, variables, operation=operation)
            self.assertEqual(str(caught.exception), f"GRAPHQL:FORBIDDEN:{operation}")

            byte_boundary_path = ["a" * 60] * 8
            byte_baseline = "GRAPHQL:FORBIDDEN:" + ".".join(byte_boundary_path)
            self.assertEqual(len(byte_baseline.encode("utf-8")), 505)
            fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps({"errors": [{"type": "FORBIDDEN", "path": byte_boundary_path}], "data": {}}).encode()))
            with self.assertRaises(GraphQLError) as caught:
                GitHubClient(None, fake)._graphql(document, variables)
            self.assertEqual(str(caught.exception), byte_baseline)

            fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps({"errors": [{"type": "FORBIDDEN", "path": byte_boundary_path}], "data": {}}).encode()))
            with self.assertRaises(GraphQLError) as caught:
                GitHubClient(None, fake)._graphql(document, variables, operation=operation)
            self.assertEqual(str(caught.exception), f"GRAPHQL:FORBIDDEN:{operation}")

            secret = "remote-secret-sentinel"
            secret_error = {"type": "FORBIDDEN", "path": ["repository"], "message": secret, "extensions": {"secret": secret}}
            fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps({"errors": [secret_error], "data": {}}).encode()))
            with self.assertRaises(GraphQLError) as caught:
                GitHubClient(None, fake)._graphql(document, variables, operation=operation)
            self.assertNotIn(secret, str(caught.exception))

    def test_pull_routing_rejects_wrong_shapes_and_middle_body_edit_race(self):
        for operation in ("before", "after"):
            for shape in ({"extra": 1}, {"repository": None}, {"repository": {"nameWithOwner": "swiftstream/skills", "pullRequest": None}}):
                with self.subTest(operation=operation, shape=shape):
                    kwargs = {operation: shape}
                    with self.assertRaises(InvalidResponseError):
                        GitHubClient(None, PullMetadataTransport(**kwargs)).get_pull_request_metadata("swiftstream/skills", 7)

        before = _routing_payload(last_edited_at=None)
        after = _routing_payload(last_edited_at="2026-09-10T00:00:00Z")
        transport = PullMetadataTransport(before=before, rest=_rest_payload(body="changed body"), after=after)
        with self.assertRaises(InvalidResponseError):
            GitHubClient(None, transport).get_pull_request_metadata("swiftstream/skills", 7)
        self.assertEqual(_call_signature(transport.calls)[1][0:2], ("GET", REST_BASE_URL + "/repos/swiftstream/skills/pulls/7"))


if __name__ == "__main__":
    unittest.main()
