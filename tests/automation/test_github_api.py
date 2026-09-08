import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automation.federation.github_api import (
    GRAPHQL_ENDPOINT,
    PULL_REQUEST_QUERY,
    UPDATE_REFS_MUTATION,
    ZERO_OID,
    GitHubClient,
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


class GitHubAPITests(unittest.TestCase):
    def _graphql_error(self, error, *, errors=None, token="test-token", variables=None, client_class=GitHubClient):
        payload = {"errors": [error] if errors is None else errors, "data": {"mustNotReturn": True}}
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps(payload, separators=(",", ":")).encode()))
        client = client_class(token, fake)
        supplied_variables = variables if variables is not None else {"owner": "swiftstream", "name": "skills", "number": 1}
        with self.assertRaises(GraphQLError) as caught:
            client._graphql(PULL_REQUEST_QUERY, supplied_variables)
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
                GitHubClient(None, fake)._graphql(PULL_REQUEST_QUERY, {"owner": "swiftstream", "name": "skills", "number": 1})

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


if __name__ == "__main__":
    unittest.main()
