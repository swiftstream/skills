import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from automation.federation.github_api import (
    GRAPHQL_ENDPOINT,
    ISSUE_COMMENT_NODES_QUERY,
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


class CommentsTransport:
    def __init__(self, rest_snapshots, graphql_responses):
        self.rest_snapshots = [list(snapshot) for snapshot in rest_snapshots]
        self.graphql_responses = list(graphql_responses)
        self.current_snapshot = None
        self.calls = []

    def request(self, method, url, headers, body, timeout):
        self.calls.append((method, url, headers, body, timeout))
        if url == GRAPHQL_ENDPOINT:
            payload = json.loads(body)
            if payload["query"] != ISSUE_COMMENT_NODES_QUERY:
                raise AssertionError(payload["query"])
            if not self.graphql_responses:
                raise AssertionError("unexpected comment GraphQL request")
            response = self.graphql_responses.pop(0)
            return HttpResponse(200, url, json.dumps(response, separators=(",", ":")).encode())
        if "/issues/7/comments?per_page=100&page=" not in url:
            raise AssertionError((method, url))
        page = int(url.rsplit("=", 1)[1])
        if page == 1:
            if not self.rest_snapshots:
                raise AssertionError("unexpected REST snapshot")
            self.current_snapshot = self.rest_snapshots.pop(0)
        if self.current_snapshot is None or page > len(self.current_snapshot):
            raise AssertionError(("missing REST page", page, self.current_snapshot))
        value = self.current_snapshot[page - 1]
        return HttpResponse(200, url, json.dumps(value, separators=(",", ":")).encode())


def _rest_comment(database_id=1, *, node_id=None, author=None, body="comment", created_at="2026-09-10T00:00:00Z", updated_at="2026-09-10T00:00:00Z", issue_url="https://api.github.com/repos/swiftstream/skills/issues/7"):
    return {
        "id": database_id,
        "node_id": node_id or f"IC_{database_id}",
        "body": body,
        "created_at": created_at,
        "updated_at": updated_at,
        "issue_url": issue_url,
        "user": author,
    }


def _graphql_comment_node(rest, *, editor=None, last_edited_at=None, includes_created_edit=False, total_count=0, body=None, created_at=None, updated_at=None, node_id=None, typename="IssueComment", full_database_id=None):
    author = None if rest["user"] is None else {"id": rest["user"]["node_id"], "login": rest["user"]["login"], "__typename": rest["user"]["type"]}
    return {
        "__typename": typename,
        "id": node_id or rest["node_id"],
        "fullDatabaseId": str(rest["id"] if full_database_id is None else full_database_id),
        "body": rest["body"] if body is None else body,
        "createdAt": rest["created_at"] if created_at is None else created_at,
        "updatedAt": rest["updated_at"] if updated_at is None else updated_at,
        "author": author,
        "editor": editor,
        "lastEditedAt": last_edited_at,
        "includesCreatedEdit": includes_created_edit,
        "userContentEdits": {"totalCount": total_count},
    }


def _graphql_response(nodes):
    return {"data": {"nodes": nodes}}


def _snapshot(records):
    pages = [records[index:index + 100] for index in range(0, len(records), 100)]
    if len(records) % 100 == 0:
        pages.append([])
    return pages


def _clean_rest_comment(database_id=1, **kwargs):
    return _rest_comment(database_id, author={"node_id": "U_author", "login": "alice", "type": "User"}, **kwargs)


def _call_signature(calls):
    return [(method, url, None if body is None else json.loads(body)["query"]) for method, url, _headers, body, _timeout in calls]


class GitHubAPITests(unittest.TestCase):
    def _graphql_error(self, error, *, errors=None, token="test-token", variables=None, client_class=GitHubClient):
        payload = {"errors": [error] if errors is None else errors, "data": {"mustNotReturn": True}}
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, json.dumps(payload, separators=(",", ":")).encode()))
        client = client_class(token, fake)
        supplied_variables = variables if variables is not None else {"ids": ["IC_1"]}
        with self.assertRaises(GraphQLError) as caught:
            client._graphql(ISSUE_COMMENT_NODES_QUERY, supplied_variables)
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
                GitHubClient(None, fake)._graphql(ISSUE_COMMENT_NODES_QUERY, {"ids": ["IC_1"]})

        text, _ = self._graphql_error({"type": "FORBIDDEN", "path": ["repository"]})
        self.assertEqual(text, "GRAPHQL:FORBIDDEN:repository")

    def test_issue_comment_nodes_query_shape_and_trusted_allowlist(self):
        self.assertIn("query FederationIssueCommentNodes($ids: [ID!]!)", ISSUE_COMMENT_NODES_QUERY)
        for field in ("nodes(ids: $ids)", "__typename", "id", "fullDatabaseId", "body", "createdAt", "updatedAt", "author", "editor", "lastEditedAt", "includesCreatedEdit", "userContentEdits(first: 1)", "totalCount"):
            self.assertIn(field, ISSUE_COMMENT_NODES_QUERY)
        self.assertNotIn("databaseId", ISSUE_COMMENT_NODES_QUERY)
        self.assertNotIn("pullRequest", ISSUE_COMMENT_NODES_QUERY)
        self.assertNotIn("issue(number", ISSUE_COMMENT_NODES_QUERY)
        fake = FakeTransport(HttpResponse(200, GRAPHQL_ENDPOINT, b'{"data":{"nodes":[]}}'))
        self.assertEqual(GitHubClient(None, fake)._graphql(ISSUE_COMMENT_NODES_QUERY, {"ids": []}), {"nodes": []})
        for old in ("""query OldPull { repository { pullRequest(number: 7) { comments { nodes { id } } } } }""", """query OldIssue { repository { issue(number: 7) { comments { nodes { id } } } } }"""):
            with self.assertRaises(GitHubAPIError):
                GitHubClient(None, fake)._graphql(old, {})

    def test_issue_comment_zero_comments_uses_two_rest_snapshots_and_zero_graphql(self):
        transport = CommentsTransport([_snapshot([]), _snapshot([])], [])
        self.assertEqual(GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7), ())
        self.assertEqual(sum(call[1] == GRAPHQL_ENDPOINT for call in transport.calls), 0)
        self.assertEqual([call[1] for call in transport.calls], [
            REST_BASE_URL + "/repos/swiftstream/skills/issues/7/comments?per_page=100&page=1",
            REST_BASE_URL + "/repos/swiftstream/skills/issues/7/comments?per_page=100&page=1",
        ])

    def test_issue_comment_one_and_multiple_map_in_remote_order(self):
        records = [_clean_rest_comment(1), _rest_comment(2, author=None, body="second")]
        nodes = [_graphql_comment_node(record) for record in records]
        transport = CommentsTransport([_snapshot(records), _snapshot(records)], [_graphql_response(list(reversed(nodes)))])
        result = GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)
        self.assertEqual([item.database_id for item in result], [1, 2])
        self.assertEqual(result[0].author_id, "U_author")
        self.assertIsNone(result[1].author_id)
        variables = json.loads(next(call[3] for call in transport.calls if call[1] == GRAPHQL_ENDPOINT))["variables"]
        self.assertEqual(variables, {"ids": ["IC_1", "IC_2"]})

    def test_issue_comment_pagination_short_full_and_multi_page(self):
        records = [_clean_rest_comment(1)]
        pages = [[records[0]], [_clean_rest_comment(2), _clean_rest_comment(3)]]
        snapshots = [pages, pages]
        transport = CommentsTransport(snapshots, [_graphql_response([_graphql_comment_node(record) for record in records])])
        self.assertEqual([item.database_id for item in GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)], [1])
        full = [_clean_rest_comment(i) for i in range(1, 101)]
        transport = CommentsTransport([_snapshot(full), _snapshot(full)], [_graphql_response([_graphql_comment_node(record) for record in full])])
        self.assertEqual(len(GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)), 100)
        self.assertEqual(sum("/comments?" in call[1] for call in transport.calls), 4)

    def test_issue_comment_hard_bound_requires_empty_page_101_and_rejects_nonempty(self):
        records = [_clean_rest_comment(i) for i in range(1, 10_001)]
        empty_sentinel = _snapshot(records)
        nodes = [_graphql_comment_node(record) for record in records]
        transport = CommentsTransport([empty_sentinel, empty_sentinel], [_graphql_response(nodes[i:i + 100]) for i in range(0, len(nodes), 100)])
        self.assertEqual(len(GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)), 10_000)
        self.assertEqual(sum("page=101" in call[1] for call in transport.calls), 2)
        nonempty = list(empty_sentinel)
        nonempty[-1] = [_clean_rest_comment(10_001)]
        transport = CommentsTransport([nonempty], [])
        with self.assertRaises(InvalidResponseError):
            GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)

    def test_issue_comment_bounds_and_no_retry_are_fail_closed(self):
        records = [_clean_rest_comment(1)]
        for kwargs in ({"max_pages": 0}, {"max_pages": 101}, {"max_records": 0}, {"max_records": 10_001}, {"max_pages": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(GitHubAPIError):
                GitHubClient(None, CommentsTransport([], [])).list_issue_comments("swiftstream/skills", 7, **kwargs)
        full = [_clean_rest_comment(i) for i in range(1, 101)]
        transport = CommentsTransport([_snapshot(full)], [])
        with self.assertRaises(InvalidResponseError):
            GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7, max_pages=1)
        self.assertEqual(len(transport.calls), 1)
        transport = CommentsTransport([[_clean_rest_comment(1), _clean_rest_comment(2)]], [])
        with self.assertRaises(InvalidResponseError):
            GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7, max_records=1)
        self.assertEqual(len(transport.calls), 1)

    def test_issue_comment_rest_shape_identity_order_timestamp_and_binding_validation(self):
        valid = _clean_rest_comment(1)
        variants = [
            ("page", {}, InvalidResponseError),
            ("oversized page", [valid] * 101, InvalidResponseError),
            ("duplicate id", [_clean_rest_comment(1), _clean_rest_comment(1, node_id="IC_2")], InvalidResponseError),
            ("out of order", [_clean_rest_comment(2), _clean_rest_comment(1)], InvalidResponseError),
            ("duplicate node", [_clean_rest_comment(1), _clean_rest_comment(2, node_id="IC_1")], InvalidResponseError),
            ("bad id", [dict(valid, id=True)], InvalidResponseError),
            ("zero id", [dict(valid, id=0)], InvalidResponseError),
            ("negative id", [dict(valid, id=-1)], InvalidResponseError),
            ("wrong type id", [dict(valid, id="1")], InvalidResponseError),
            ("bad node", [dict(valid, node_id="")], InvalidResponseError),
            ("bad body", [dict(valid, body=1)], InvalidResponseError),
            ("oversized body", [dict(valid, body="x" * 16_385)], InvalidResponseError),
            ("bad created", [dict(valid, created_at="not-time")], InvalidResponseError),
            ("naive created", [dict(valid, created_at="2026-09-10T00:00:00")], InvalidResponseError),
            ("bad updated", [dict(valid, updated_at="not-time")], InvalidResponseError),
            ("updated before created", [dict(valid, created_at="2026-09-10T00:00:01Z", updated_at="2026-09-10T00:00:00Z")], InvalidResponseError),
            ("bad user", [dict(valid, user="bad")], InvalidResponseError),
            ("missing author field", [dict(valid, user={"node_id": "U"})], InvalidResponseError),
            ("wrong issue", [dict(valid, issue_url="https://api.github.com/repos/other/skills/issues/7")], InvalidResponseError),
            ("wrong number", [dict(valid, issue_url="https://api.github.com/repos/swiftstream/skills/issues/8")], InvalidResponseError),
            ("missing issue", [dict(valid, issue_url=None)], InvalidResponseError),
        ]
        for label, page, expected in variants:
            value = {} if label == "page" else page
            with self.subTest(label=label):
                transport = CommentsTransport([[value]], [])
                with self.assertRaises(expected):
                    GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)

    def test_issue_comment_full_database_id_and_current_state_parity(self):
        record = _clean_rest_comment(1)
        def run(node):
            transport = CommentsTransport([_snapshot([record]), _snapshot([record])], [_graphql_response([node])])
            return GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)
        self.assertEqual(run(_graphql_comment_node(record, created_at="2026-09-09T20:00:00-04:00"))[0].database_id, 1)
        for mutation in (
            {"full_database_id": "0"}, {"full_database_id": "-1"}, {"full_database_id": "x"}, {"full_database_id": "9223372036854775808"},
            {"full_database_id": "2"}, {"node_id": "other"}, {"body": "other"},
            {"created_at": "2026-09-10T00:00:01Z"}, {"updated_at": "2026-09-09T23:59:59Z"},
        ):
            node = _graphql_comment_node(record, **mutation)
            with self.subTest(mutation=mutation), self.assertRaises(InvalidResponseError):
                run(node)

    def test_issue_comment_author_editor_history_and_timestamp_regressions(self):
        record = _clean_rest_comment(1)
        clean = _graphql_comment_node(record)
        result = GitHubClient(None, CommentsTransport([_snapshot([record]), _snapshot([record])], [_graphql_response([clean])])).list_issue_comments("swiftstream/skills", 7)
        self.assertFalse(result[0].includes_created_edit)
        edited = _graphql_comment_node(record, editor={"id": "U_editor", "login": "bob", "__typename": "User"}, last_edited_at="2026-09-10T01:00:00Z", total_count=1, includes_created_edit=True)
        result = GitHubClient(None, CommentsTransport([_snapshot([record]), _snapshot([record])], [_graphql_response([edited])])).list_issue_comments("swiftstream/skills", 7)
        self.assertTrue(result[0].includes_created_edit)
        self.assertEqual(result[0].last_edited_at, "2026-09-10T01:00:00Z")
        self.assertEqual(result[0].editor_id, "U_editor")
        record_same_times = _clean_rest_comment(1, created_at="2026-09-10T00:00:00Z", updated_at="2026-09-10T00:00:00Z")
        edited = _graphql_comment_node(record_same_times, editor=None, last_edited_at="2026-09-10T01:00:00Z", total_count=1)
        result = GitHubClient(None, CommentsTransport([_snapshot([record_same_times]), _snapshot([record_same_times])], [_graphql_response([edited])])).list_issue_comments("swiftstream/skills", 7)
        self.assertEqual(result[0].last_edited_at, "2026-09-10T01:00:00Z")
        for node in (
            dict(clean, author={"id": "U_other", "login": "mallory", "__typename": "User"}),
            dict(clean, userContentEdits=None),
            dict(clean, userContentEdits={"totalCount": True}),
            dict(clean, userContentEdits={"totalCount": -1}),
            dict(clean, lastEditedAt="bad"),
            dict(clean, userContentEdits={"totalCount": 0}, lastEditedAt="2026-09-10T01:00:00Z"),
            dict(clean, userContentEdits={"totalCount": 0}, editor={"id": "U_editor", "login": "bob", "__typename": "User"}),
            dict(clean, userContentEdits={"totalCount": 0}, includesCreatedEdit=True),
            dict(clean, userContentEdits={"totalCount": 1}, lastEditedAt=None),
            dict(clean, editor={"id": None, "login": "bob", "__typename": "User"}),
        ):
            with self.subTest(node=node):
                transport = CommentsTransport([_snapshot([record]), _snapshot([record])], [_graphql_response([node])])
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)

        null_record = _rest_comment(1, author=None)
        actor_node = _graphql_comment_node(null_record)
        actor_node["author"] = {"id": "U_author", "login": "alice", "__typename": "User"}
        for rest_record, node in ((null_record, actor_node), (record, dict(clean, author=None))):
            with self.subTest(rest_record=rest_record, node=node):
                transport = CommentsTransport([_snapshot([rest_record]), _snapshot([rest_record])], [_graphql_response([node])])
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)

        edited_with_editor = _graphql_comment_node(record, editor={"id": "U_editor", "login": "bob", "__typename": "User"}, last_edited_at="2026-09-10T01:00:00Z", total_count=1)
        transport = CommentsTransport([_snapshot([record]), _snapshot([record])], [_graphql_response([edited_with_editor])])
        self.assertEqual(GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)[0].editor_id, "U_editor")

    def test_issue_comment_batching_result_sets_graphql_errors_and_no_fallback(self):
        records = [_clean_rest_comment(i) for i in range(1, 102)]
        nodes = [_graphql_comment_node(record) for record in records]
        transport = CommentsTransport([_snapshot(records), _snapshot(records)], [_graphql_response(list(reversed(nodes[:100]))), _graphql_response([nodes[100]])])
        self.assertEqual(len(GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)), 101)
        calls = [json.loads(call[3]) for call in transport.calls if call[1] == GRAPHQL_ENDPOINT]
        self.assertEqual([len(call["variables"]["ids"]) for call in calls], [100, 1])
        for bad_nodes in (None, [None], [dict(nodes[0], __typename="User")], [nodes[0], nodes[0]], [dict(nodes[0], id="extra")]):
            response = _graphql_response(bad_nodes)
            transport = CommentsTransport([_snapshot([records[0]]), _snapshot([records[0]])], [response])
            with self.subTest(bad_nodes=bad_nodes), self.assertRaises(InvalidResponseError):
                GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)
            self.assertEqual(len([call for call in transport.calls if call[1] == GRAPHQL_ENDPOINT]), 1)
        error = {"errors": [{"type": "FORBIDDEN", "path": ["nodes"]}], "data": {"nodes": []}}
        transport = CommentsTransport([_snapshot([records[0]]), _snapshot([records[0]])], [error])
        with self.assertRaises(GraphQLError):
            GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)
        self.assertEqual(len([call for call in transport.calls if call[1] == GRAPHQL_ENDPOINT]), 1)

    def test_issue_comment_rest_a_b_races_fail_and_exact_match_succeeds(self):
        original = _clean_rest_comment(1)
        valid_node = _graphql_comment_node(original)
        changes = (
            ("insertion", [original, _clean_rest_comment(2)]),
            ("deletion", []),
            ("body", [dict(original, body="changed")]),
            ("database id", [dict(original, id=2)]),
            ("node id", [dict(original, node_id="other")]),
            ("author presence", [dict(original, user=None)]),
            ("author id", [dict(original, user={"node_id": "other", "login": "alice", "type": "User"})]),
            ("author login", [dict(original, user={"node_id": "U_author", "login": "other", "type": "User"})]),
            ("author type", [dict(original, user={"node_id": "U_author", "login": "alice", "type": "Bot"})]),
            ("created", [dict(original, created_at="2026-09-11T00:00:00Z")]),
            ("updated", [dict(original, updated_at="2026-09-11T00:00:00Z")]),
            ("binding", [dict(original, issue_url="https://api.github.com/repos/other/skills/issues/7")]),
            ("order", [_clean_rest_comment(2), original]),
            ("page boundary", [_clean_rest_comment(i) for i in range(1, 101)]),
        )
        for label, changed in changes:
            with self.subTest(label=label):
                transport = CommentsTransport([_snapshot([original]), _snapshot(changed)], [_graphql_response([valid_node])])
                with self.assertRaises(InvalidResponseError):
                    GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)
        transport = CommentsTransport([_snapshot([original]), _snapshot([original])], [_graphql_response([valid_node])])
        self.assertEqual(GitHubClient(None, transport).list_issue_comments("swiftstream/skills", 7)[0].database_id, 1)

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
