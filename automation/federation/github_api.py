"""Deterministic GitHub transport seams and the sole R01 ref-CAS primitive."""

from __future__ import annotations

import json
import base64
import hashlib
import re
import socket
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Protocol
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from scripts import federate as c02
from automation.federation.workspace import WorkspaceError, validate_trusted_ref

REST_BASE_URL = "https://api.github.com"
GRAPHQL_ENDPOINT = "https://api.github.com/graphql"
REST_API_VERSION = "2026-03-10"
ACCEPT_HEADER = "application/vnd.github+json"
USER_AGENT = "swiftstream-skills-federation"
REQUEST_TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 1_048_576
ZERO_OID = "0" * 40
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_GRAPHQL_ERROR_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_GRAPHQL_ERROR_PATH_SEGMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_GRAPHQL_GENERIC_DIAGNOSTIC = "GRAPHQL:UNKNOWN:unknown-path"
_GRAPHQL_DIAGNOSTIC_MAX_BYTES = 512

UPDATE_REFS_MUTATION = """mutation FederationUpdateRefs($repositoryId: ID!, $refUpdates: [RefUpdate!]!) {
  updateRefs(input: {repositoryId: $repositoryId, refUpdates: $refUpdates}) {
    clientMutationId
  }
}"""

# These documents are deliberately fixed strings.  All repository, login, ref,
# and comment values enter as GraphQL variables; none can become query syntax.
PULL_REQUEST_QUERY = """query FederationPullRequest($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    id
    nameWithOwner
    defaultBranchRef { name }
    pullRequest(number: $number) {
      number body
      author { id login }
      headRefOid baseRefOid headRefName baseRefName
      headRepository { id nameWithOwner }
      baseRepository { id nameWithOwner }
      lastEditedAt includesCreatedEdit
    }
  }
}"""

ISSUE_COMMENTS_QUERY = """query FederationIssueComments($owner: String!, $name: String!, $number: Int!, $after: String) {
  repository(owner: $owner, name: $name) {
    issue(number: $number) {
      comments(first: 100, after: $after) {
        nodes { id databaseId body author { id login __typename } editor { id login __typename } lastEditedAt includesCreatedEdit }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}"""

APP_QUERY = """query FederationApp($slug: String!) {
  app(slug: $slug) { id slug databaseId nodeId name }
}"""

BOT_QUERY = """query FederationBot($login: String!) {
  user(login: $login) { id login databaseId __typename }
}"""


def _bounded_text(value: Any, label: str, limit: int = 256) -> str:
    if type(value) is not str or not value or len(value) > limit or c02.contains_control(value):
        raise InvalidResponseError(f"{label} has invalid bounded text")
    return value


def _positive_id(value: Any, label: str) -> int:
    if type(value) is not int or type(value) is bool or not 1 <= value <= 9_223_372_036_854_775_807:
        raise InvalidResponseError(f"{label} must be a positive bounded integer")
    return value


def _optional_iso(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label, 128)


def _optional_bounded_text(value: Any, label: str, limit: int) -> str:
    if type(value) is not str or len(value) > limit or c02.contains_control(value):
        raise InvalidResponseError(f"{label} has invalid bounded text")
    return value


def _graphql_error_diagnostic(error: Mapping[str, Any]) -> str:
    error_type = error.get("type")
    if type(error_type) is not str or not _GRAPHQL_ERROR_TYPE_RE.fullmatch(error_type):
        error_type = "UNKNOWN"

    raw_path = error.get("path")
    rendered_path = "unknown-path"
    if type(raw_path) is list and raw_path and len(raw_path) <= 16:
        parts: list[str] = []
        valid = True
        for segment in raw_path:
            if type(segment) is str and _GRAPHQL_ERROR_PATH_SEGMENT_RE.fullmatch(segment):
                parts.append(segment)
            elif type(segment) is int and type(segment) is not bool and 0 <= segment <= 999_999:
                parts.append(str(segment))
            else:
                valid = False
                break
        if valid:
            rendered_path = ".".join(parts)

    diagnostic = f"GRAPHQL:{error_type}:{rendered_path}"
    if len(diagnostic.encode("utf-8")) > _GRAPHQL_DIAGNOSTIC_MAX_BYTES:
        return _GRAPHQL_GENERIC_DIAGNOSTIC
    return diagnostic


class GitHubAPIError(RuntimeError):
    """Base class for controlled, secret-free API failures."""


class UnauthorizedError(GitHubAPIError):
    pass


class ForbiddenError(GitHubAPIError):
    pass


class NotFoundError(GitHubAPIError):
    pass


class ConflictError(GitHubAPIError):
    pass


class UnprocessableError(GitHubAPIError):
    pass


class RateLimitedError(GitHubAPIError):
    pass


class ServerError(GitHubAPIError):
    pass


class UnexpectedStatusError(GitHubAPIError):
    pass


class TransportError(GitHubAPIError):
    pass


class RedirectError(TransportError):
    pass


class ResponseBodyTooLargeError(TransportError):
    pass


class InvalidResponseError(TransportError):
    pass


class GraphQLError(GitHubAPIError):
    pass


class RefCASConflict(GraphQLError):
    pass


@dataclass(frozen=True)
class HttpResponse:
    status: int
    url: str
    body: bytes


@dataclass(frozen=True)
class RepositoryMetadata:
    id: int
    node_id: str
    full_name: str
    default_branch: str
    description: str | None = None


@dataclass(frozen=True)
class AppMetadata:
    id: int
    slug: str
    node_id: str


@dataclass(frozen=True)
class BotMetadata:
    id: int
    login: str
    node_id: str
    type: str


@dataclass(frozen=True)
class PullRequestMetadata:
    number: int
    body: str
    author_id: str
    author_login: str
    head_oid: str
    base_oid: str
    head_ref: str
    base_ref: str
    head_repository_id: str
    head_repository: str
    base_repository_id: str
    base_repository: str
    last_edited_at: str | None
    includes_created_edit: bool


@dataclass(frozen=True)
class IssueComment:
    node_id: str
    database_id: int
    body: str
    author_id: str | None
    author_login: str | None
    author_type: str | None
    editor_id: str | None
    editor_login: str | None
    editor_type: str | None
    last_edited_at: str | None
    includes_created_edit: bool


@dataclass(frozen=True)
class GitObject:
    sha: str


@dataclass(frozen=True)
class GitTreeEntry:
    path: str
    mode: str
    object_type: str
    sha: str


@dataclass(frozen=True)
class GitCommitMetadata:
    sha: str
    tree_sha: str
    parents: tuple[str, ...]


@dataclass(frozen=True)
class CheckRun:
    id: int
    name: str
    head_sha: str
    status: str
    conclusion: str | None
    app_id: int | None
    output: str | None = None


@dataclass(frozen=True)
class MergeResult:
    merged: bool
    message: str
    sha: str | None


class HttpTransport(Protocol):
    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> HttpResponse:
        ...


class _NoRedirectHandler(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, request: urlrequest.Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise RedirectError("redirects are forbidden")


class UrllibTransport:
    """Production-shaped transport; R01 never calls it from tests or the CLI."""

    def __init__(self) -> None:
        # App-token requests must never be routed by ambient proxy settings.
        self._opener = urlrequest.build_opener(urlrequest.ProxyHandler({}), _NoRedirectHandler)

    def request(self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float) -> HttpResponse:
        request = urlrequest.Request(url, data=body, headers=dict(headers), method=method)
        try:
            response = self._opener.open(request, timeout=timeout)
            status = int(response.status)
            final_url = response.geturl()
            raw = _read_bounded(response)
        except urlerror.HTTPError as error:
            status = int(error.code)
            final_url = error.geturl() or url
            raw = _read_bounded(error)
        except RedirectError:
            raise
        except (urlerror.URLError, TimeoutError, socket.timeout, OSError) as error:
            raise TransportError(f"GitHub transport failed: {type(error).__name__}") from None
        return HttpResponse(status, final_url, raw)


def _read_bounded(response: Any) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(min(64 * 1024, MAX_RESPONSE_BYTES - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_RESPONSE_BYTES:
            raise ResponseBodyTooLargeError("GitHub response body exceeds the configured limit")
        chunks.append(chunk)
    return b"".join(chunks)


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise InvalidResponseError(f"request JSON cannot be encoded: {type(error).__name__}") from None


def _decode_json(body: bytes) -> Any:
    if len(body) > MAX_RESPONSE_BYTES:
        raise ResponseBodyTooLargeError("GitHub response body exceeds the configured limit")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidResponseError("GitHub response is not UTF-8") from None
    try:
        return c02.decode_json(text)
    except Exception as error:
        raise InvalidResponseError(f"GitHub response JSON is invalid: {type(error).__name__}") from None


def _validate_segment(segment: str) -> str:
    if type(segment) is not str or not segment or segment in {".", ".."} or "/" in segment or "\\" in segment:
        raise GitHubAPIError("invalid GitHub URL path segment")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in segment):
        raise GitHubAPIError("invalid GitHub URL path segment")
    return urlparse.quote(segment, safe="-._~")


def _validate_tree_path(path: str) -> str:
    if type(path) is not str or not path or path.startswith("/") or "\\" in path or "\x00" in path or c02.contains_control(path):
        raise GitHubAPIError("Git tree path is invalid")
    if any(part in {"", ".", ".."} for part in path.split("/")):
        raise GitHubAPIError("Git tree path contains traversal")
    return path


@dataclass(frozen=True)
class RefUpdate:
    name: str
    before_oid: str
    after_oid: str
    force: bool = False

    def __post_init__(self) -> None:
        try:
            validate_trusted_ref(self.name)
        except (c02.FederationError, WorkspaceError) as error:
            raise GitHubAPIError(str(error)) from None
        for value, label in ((self.before_oid, "beforeOid"), (self.after_oid, "afterOid")):
            if type(value) is not str or not _SHA40_RE.fullmatch(value):
                raise GitHubAPIError(f"{label} must be lowercase 40-hex")
        if type(self.force) is not bool:
            raise GitHubAPIError("force must be boolean")
        if self.before_oid == ZERO_OID and self.after_oid == ZERO_OID:
            raise GitHubAPIError("zero beforeOid and zero afterOid is invalid")
        if self.force and (self.before_oid == ZERO_OID or self.after_oid == ZERO_OID):
            raise GitHubAPIError("force requires concrete nonzero beforeOid and afterOid")

    @property
    def operation(self) -> str:
        if self.before_oid == ZERO_OID:
            return "create"
        if self.after_oid == ZERO_OID:
            return "delete"
        return "update"

    def as_graphql_value(self) -> dict[str, Any]:
        return {"name": self.name, "beforeOid": self.before_oid, "afterOid": self.after_oid, "force": self.force}


class GitHubClient:
    def __init__(self, token: str | None, transport: HttpTransport | Callable[..., HttpResponse] | None = None) -> None:
        if token is not None and type(token) is not str:
            raise ValueError("token must be a string or None")
        self._token = token
        self._transport = transport or UrllibTransport()

    def __repr__(self) -> str:
        return "GitHubClient(token=<redacted>, transport=<configured>)"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": ACCEPT_HEADER, "User-Agent": USER_AGENT, "X-GitHub-Api-Version": REST_API_VERSION}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    def _request(self, method: str, url: str, payload: Any = None) -> Any:
        if url not in {GRAPHQL_ENDPOINT} and not url.startswith(REST_BASE_URL + "/"):
            raise GitHubAPIError("GitHub URL is outside the fixed API endpoints")
        body = _json_bytes(payload) if payload is not None else None
        headers = self._headers()
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            if hasattr(self._transport, "request"):
                response = self._transport.request(method, url, headers, body, REQUEST_TIMEOUT_SECONDS)  # type: ignore[attr-defined]
            else:
                response = self._transport(method, url, headers, body, REQUEST_TIMEOUT_SECONDS)  # type: ignore[operator]
        except GitHubAPIError:
            raise
        except Exception as error:
            raise TransportError(f"GitHub transport failed: {type(error).__name__}") from None
        if not isinstance(response, HttpResponse):
            raise InvalidResponseError("transport returned an invalid response object")
        if response.url != url:
            raise RedirectError("redirects are forbidden")
        self._raise_for_status(response.status)
        if response.status == 204 and not response.body:
            return {}
        return _decode_json(response.body)

    @staticmethod
    def _raise_for_status(status: int) -> None:
        if 200 <= status < 300:
            return
        mapping: dict[int, type[GitHubAPIError]] = {
            401: UnauthorizedError,
            403: ForbiddenError,
            404: NotFoundError,
            409: ConflictError,
            422: UnprocessableError,
            429: RateLimitedError,
        }
        if status in mapping:
            raise mapping[status](f"GitHub request failed with HTTP {status}")
        if 500 <= status <= 599:
            raise ServerError(f"GitHub request failed with HTTP {status}")
        raise UnexpectedStatusError(f"GitHub request failed with HTTP {status}")

    def request_json(self, method: str, path_segments: list[str], payload: Any = None) -> Any:
        if method not in {"GET", "POST", "PATCH", "PUT", "DELETE"}:
            raise GitHubAPIError("unsupported HTTP method")
        path = "/" + "/".join(_validate_segment(segment) for segment in path_segments)
        return self._request(method, REST_BASE_URL + path, payload)

    def _graphql(self, document: str, variables: Mapping[str, Any]) -> dict[str, Any]:
        if type(document) is not str or document not in {PULL_REQUEST_QUERY, ISSUE_COMMENTS_QUERY, APP_QUERY, BOT_QUERY, UPDATE_REFS_MUTATION}:
            raise GitHubAPIError("GraphQL document is not an accepted trusted document")
        result = self._request("POST", GRAPHQL_ENDPOINT, {"query": document, "variables": dict(variables)})
        if type(result) is not dict:
            raise InvalidResponseError("GraphQL response must be an object")
        if "errors" in result:
            if type(result["errors"]) is not list or not result["errors"] or any(type(item) is not dict for item in result["errors"]):
                raise GraphQLError("GraphQL returned malformed errors")
            raise GraphQLError(_graphql_error_diagnostic(result["errors"][0]))
        if set(result) != {"data"} or type(result["data"]) is not dict:
            raise InvalidResponseError("GraphQL response has invalid exact top-level shape")
        return result["data"]

    @staticmethod
    def _owner_repo(repository: str) -> tuple[str, str]:
        if type(repository) is not str or repository.count("/") != 1:
            raise GitHubAPIError("repository must be OWNER/REPO")
        owner, name = repository.split("/")
        return _validate_segment(owner), _validate_segment(name)

    @staticmethod
    def _sha(value: Any, label: str) -> str:
        if type(value) is not str or not _SHA40_RE.fullmatch(value):
            raise InvalidResponseError(f"{label} must be lowercase 40-hex")
        return value

    def get_repository_metadata(self, repository: str) -> RepositoryMetadata:
        owner, name = self._owner_repo(repository)
        value = self.request_json("GET", ["repos", owner, name])
        if type(value) is not dict:
            raise InvalidResponseError("repository metadata must be an object")
        return RepositoryMetadata(
            _positive_id(value.get("id"), "repository.id"),
            _bounded_text(value.get("node_id"), "repository.node_id"),
            _bounded_text(value.get("full_name"), "repository.full_name"),
            _bounded_text(value.get("default_branch"), "repository.default_branch"),
            None if value.get("description") is None else _optional_bounded_text(value.get("description"), "repository.description", 1_000),
        )

    def get_commit_metadata(self, repository: str, commit_sha: str) -> GitCommitMetadata:
        owner, name = self._owner_repo(repository)
        commit = self._sha(commit_sha, "commit.sha")
        value = self.request_json("GET", ["repos", owner, name, "git", "commits", commit])
        if type(value) is not dict or type(value.get("tree")) is not dict or type(value.get("parents")) is not list:
            raise InvalidResponseError("Git commit metadata has invalid shape")
        tree_sha = self._sha(value["tree"].get("sha"), "commit.tree.sha")
        parents: list[str] = []
        for parent in value["parents"]:
            if type(parent) is not dict:
                raise InvalidResponseError("Git commit parent has invalid shape")
            parents.append(self._sha(parent.get("sha"), "commit.parent.sha"))
        returned_sha = value.get("sha", commit)
        if returned_sha != commit:
            raise InvalidResponseError("Git commit response identity does not match requested commit")
        return GitCommitMetadata(commit, tree_sha, tuple(parents))

    def get_commit_tree(self, repository: str, commit_sha: str) -> tuple[str, tuple[GitTreeEntry, ...]]:
        owner, name = self._owner_repo(repository)
        metadata = self.get_commit_metadata(repository, commit_sha)
        url = f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/trees/{urlparse.quote(metadata.tree_sha)}?recursive=1"
        value = self._request("GET", url)
        if type(value) is not dict or type(value.get("tree")) is not list or value.get("truncated") is not False:
            raise InvalidResponseError("Git tree response is truncated or malformed")
        entries: list[GitTreeEntry] = []
        for item in value["tree"]:
            if type(item) is not dict:
                raise InvalidResponseError("Git tree entry is malformed")
            path = item.get("path")
            if type(path) is not str or not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")):
                raise InvalidResponseError("Git tree entry path is unsafe")
            mode = item.get("mode")
            object_type = item.get("type")
            if type(mode) is not str or mode not in {"040000", "100644", "100755", "120000", "160000"}:
                raise InvalidResponseError("Git tree entry mode is invalid")
            if object_type not in {"tree", "blob", "commit"}:
                raise InvalidResponseError("Git tree entry type is invalid")
            if object_type == "tree" and mode != "040000":
                raise InvalidResponseError("Git tree directory mode/type combination is invalid")
            if object_type == "commit" and mode != "160000":
                raise InvalidResponseError("Git tree gitlink mode/type combination is invalid")
            if object_type == "blob" and mode not in {"100644", "100755", "120000"}:
                raise InvalidResponseError("Git tree blob mode/type combination is invalid")
            entries.append(GitTreeEntry(path, mode, object_type, self._sha(item.get("sha"), "tree.entry.sha")))
        if len(entries) > 100_000 or len({item.path for item in entries}) != len(entries):
            raise InvalidResponseError("Git tree entry count or identity is invalid")
        return metadata.tree_sha, tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))

    def get_blob(self, repository: str, blob_sha: str) -> bytes:
        owner, name = self._owner_repo(repository)
        value = self.request_json("GET", ["repos", owner, name, "git", "blobs", self._sha(blob_sha, "blob.sha")])
        if type(value) is not dict or value.get("encoding") != "base64" or type(value.get("content")) is not str:
            raise InvalidResponseError("Git blob response is malformed")
        content = value["content"].replace("\n", "")
        try:
            data = base64.b64decode(content, validate=True)
        except (ValueError, base64.binascii.Error):
            raise InvalidResponseError("Git blob base64 content is invalid") from None
        if len(data) > MAX_RESPONSE_BYTES:
            raise ResponseBodyTooLargeError("Git blob exceeds the configured limit")
        return data

    def read_commit_file(self, repository: str, commit_sha: str, path: str, *, expected_mode: str | None = None) -> bytes:
        _validate_tree_path(path)
        _tree_sha, entries = self.get_commit_tree(repository, commit_sha)
        matches = [item for item in entries if item.path == path]
        if len(matches) != 1:
            raise InvalidResponseError("requested committed file is missing or ambiguous")
        entry = matches[0]
        if entry.object_type != "blob" or (expected_mode is not None and entry.mode != expected_mode):
            raise InvalidResponseError("requested committed file is not the expected regular blob")
        return self.get_blob(repository, entry.sha)

    def get_app_metadata(self, app_slug: str) -> AppMetadata:
        slug = _validate_segment(app_slug)
        value = self.request_json("GET", ["apps", slug])
        if type(value) is not dict:
            raise InvalidResponseError("App metadata must be an object")
        returned_slug = _bounded_text(value.get("slug"), "App.slug")
        if returned_slug != app_slug:
            raise InvalidResponseError("App slug does not match trusted token-action output")
        return AppMetadata(
            _positive_id(value.get("id"), "App.id"),
            returned_slug,
            _bounded_text(value.get("node_id"), "App.node_id"),
        )

    def get_bot_metadata(self, app_slug: str) -> BotMetadata:
        login = f"{_validate_segment(app_slug)}[bot]"
        value = self.request_json("GET", ["users", login])
        if type(value) is not dict:
            raise InvalidResponseError("Bot metadata must be an object")
        expected_login = f"{app_slug}[bot]"
        actual_login = _bounded_text(value.get("login"), "Bot.login")
        actual_type = _bounded_text(value.get("type"), "Bot.type")
        if actual_login != expected_login or actual_type != "Bot":
            raise InvalidResponseError("Bot identity does not match the expected App slug")
        return BotMetadata(
            _positive_id(value.get("id"), "Bot.id"),
            actual_login,
            _bounded_text(value.get("node_id"), "Bot.node_id"),
            actual_type,
        )

    def get_pull_request_metadata(self, repository: str, number: int) -> PullRequestMetadata:
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("pull request number must be positive")
        value = self._graphql(PULL_REQUEST_QUERY, {"owner": owner, "name": name, "number": number})
        if set(value) != {"repository"} or type(value["repository"]) is not dict:
            raise InvalidResponseError("pull request response has invalid repository shape")
        repo = value["repository"]
        pull = repo.get("pullRequest")
        if type(pull) is not dict:
            raise InvalidResponseError("pull request metadata is missing")
        author = pull.get("author")
        head_repo = pull.get("headRepository")
        base_repo = pull.get("baseRepository")
        if type(author) is not dict or type(head_repo) is not dict or type(base_repo) is not dict:
            raise InvalidResponseError("pull request identity metadata is incomplete")
        author_id = _bounded_text(author.get("id"), "PR.author.id")
        author_login = _bounded_text(author.get("login"), "PR.author.login")
        if type(pull.get("number")) is not int or pull["number"] != number or type(pull.get("body")) is not str or len(pull["body"].encode("utf-8")) > 16_384:
            raise InvalidResponseError("pull request number/body has invalid shape")
        if type(pull.get("includesCreatedEdit")) is not bool:
            raise InvalidResponseError("PR.includesCreatedEdit must be boolean")
        return PullRequestMetadata(
            number,
            pull["body"],
            author_id,
            author_login,
            self._sha(pull.get("headRefOid"), "PR.headRefOid"),
            self._sha(pull.get("baseRefOid"), "PR.baseRefOid"),
            _bounded_text(pull.get("headRefName"), "PR.headRefName"),
            _bounded_text(pull.get("baseRefName"), "PR.baseRefName"),
            _bounded_text(head_repo.get("id"), "PR.headRepository.id"),
            _bounded_text(head_repo.get("nameWithOwner"), "PR.headRepository.nameWithOwner"),
            _bounded_text(base_repo.get("id"), "PR.baseRepository.id"),
            _bounded_text(base_repo.get("nameWithOwner"), "PR.baseRepository.nameWithOwner"),
            _optional_iso(pull.get("lastEditedAt"), "PR.lastEditedAt"),
            pull["includesCreatedEdit"],
        )

    def list_issue_comments(self, repository: str, number: int, *, max_pages: int = 100, max_records: int = 10_000) -> tuple[IssueComment, ...]:
        owner, name = self._owner_repo(repository)
        if max_pages <= 0 or max_records <= 0:
            raise GitHubAPIError("comment pagination bounds must be positive")
        comments: list[IssueComment] = []
        cursor: str | None = None
        for _page in range(max_pages):
            data = self._graphql(ISSUE_COMMENTS_QUERY, {"owner": owner, "name": name, "number": number, "after": cursor})
            repo = data.get("repository")
            if type(repo) is not dict or type(repo.get("issue")) is not dict:
                raise InvalidResponseError("issue comment response is missing issue")
            connection = repo["issue"].get("comments")
            if type(connection) is not dict or type(connection.get("nodes")) is not list or type(connection.get("pageInfo")) is not dict:
                raise InvalidResponseError("issue comment connection has invalid shape")
            for value in connection["nodes"]:
                if type(value) is not dict:
                    raise InvalidResponseError("issue comment node must be an object")
                author = value.get("author")
                editor = value.get("editor")
                if author is not None and type(author) is not dict:
                    raise InvalidResponseError("comment author has invalid shape")
                if editor is not None and type(editor) is not dict:
                    raise InvalidResponseError("comment editor has invalid shape")
                if type(value.get("includesCreatedEdit")) is not bool or type(value.get("body")) is not str:
                    raise InvalidResponseError("comment body/edit metadata has invalid shape")
                comments.append(IssueComment(
                    _bounded_text(value.get("id"), "comment.node_id"),
                    _positive_id(value.get("databaseId"), "comment.databaseId"),
                    value["body"],
                    _bounded_text(author.get("id"), "comment.author.id") if author is not None else None,
                    _bounded_text(author.get("login"), "comment.author.login") if author is not None else None,
                    _bounded_text(author.get("__typename"), "comment.author.type") if author is not None and author.get("__typename") is not None else None,
                    _bounded_text(editor.get("id"), "comment.editor.id") if editor is not None else None,
                    _bounded_text(editor.get("login"), "comment.editor.login") if editor is not None else None,
                    _bounded_text(editor.get("__typename"), "comment.editor.type") if editor is not None and editor.get("__typename") is not None else None,
                    _optional_iso(value.get("lastEditedAt"), "comment.lastEditedAt"),
                    value["includesCreatedEdit"],
                ))
                if len(comments) > max_records:
                    raise InvalidResponseError("comment pagination exceeds configured bound")
            page_info = connection["pageInfo"]
            if type(page_info.get("hasNextPage")) is not bool:
                raise InvalidResponseError("comment pageInfo.hasNextPage must be boolean")
            if not page_info["hasNextPage"]:
                return tuple(sorted(comments, key=lambda item: item.database_id))
            cursor_value = page_info.get("endCursor")
            if type(cursor_value) is not str or not cursor_value:
                raise InvalidResponseError("next comment page is missing endCursor")
            cursor = cursor_value
        raise InvalidResponseError("comment pagination exceeds configured page bound")

    def create_issue_comment(self, repository: str, number: int, body: str) -> IssueComment:
        owner, name = self._owner_repo(repository)
        if type(body) is not str or not body or len(body.encode("utf-8")) > 16_384:
            raise GitHubAPIError("comment body is invalid or exceeds the bound")
        value = self.request_json("POST", ["repos", owner, name, "issues", str(number), "comments"], {"body": body})
        if type(value) is not dict:
            raise InvalidResponseError("created comment must be an object")
        return IssueComment(
            _bounded_text(value.get("node_id"), "created comment.node_id"),
            _positive_id(value.get("id"), "created comment.id"),
            _bounded_text(value.get("body"), "created comment.body", 16_384),
            None, None, None, None, None, None, None, False,
        )

    def get_collaborator_permission(self, repository: str, login: str) -> str:
        owner, name = self._owner_repo(repository)
        value = self.request_json("GET", ["repos", owner, name, "collaborators", _validate_segment(login), "permission"])
        if type(value) is not dict or type(value.get("permission")) is not str:
            raise InvalidResponseError("collaborator permission response is malformed")
        permission = value["permission"]
        if permission not in {"admin", "maintain", "write", "triage", "read", "none"}:
            raise InvalidResponseError("collaborator permission is unknown")
        return permission

    def list_pull_request_files(self, repository: str, number: int, *, max_pages: int = 100) -> tuple[dict[str, Any], ...]:
        owner, name = self._owner_repo(repository)
        result: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            value = self._request("GET", f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/pulls/{number}/files?per_page=30&page={page}")
            if type(value) is not list or any(type(item) is not dict for item in value):
                raise InvalidResponseError("pull request files response is malformed")
            result.extend(value)
            if len(value) < 30:
                return tuple(result)
        raise InvalidResponseError("pull request file pagination exceeds bound")

    def get_ref_oid(self, repository: str, branch: str) -> str:
        owner, name = self._owner_repo(repository)
        if type(branch) is not str or not branch or "\\" in branch or c02.contains_control(branch):
            raise GitHubAPIError("branch name is invalid")
        try:
            validate_trusted_ref(f"refs/heads/{branch}")
        except (c02.FederationError, WorkspaceError):
            raise GitHubAPIError("branch name is not a valid trusted branch") from None
        value = self._request("GET", f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/ref/heads/{urlparse.quote(branch, safe='-._~/')}")
        if type(value) is not dict or type(value.get("object")) is not dict:
            raise InvalidResponseError("Git ref response is malformed")
        return self._sha(value["object"].get("sha"), "ref.object.sha")

    def create_blob(self, repository: str, content: str, *, encoding: str = "base64") -> GitObject:
        owner, name = self._owner_repo(repository)
        if encoding not in {"base64", "utf-8"} or type(content) is not str:
            raise GitHubAPIError("Git blob content encoding is invalid")
        value = self.request_json("POST", ["repos", owner, name, "git", "blobs"], {"content": content, "encoding": encoding})
        if type(value) is not dict:
            raise InvalidResponseError("Git blob response is malformed")
        return GitObject(self._sha(value.get("sha"), "blob.sha"))

    def create_tree(self, repository: str, base_tree: str, entries: Iterable[Mapping[str, Any]]) -> GitObject:
        owner, name = self._owner_repo(repository)
        base = self._sha(base_tree, "base tree")
        items = list(entries)
        if not items or any(type(item) is not dict for item in items):
            raise GitHubAPIError("Git tree entries are invalid")
        value = self.request_json("POST", ["repos", owner, name, "git", "trees"], {"base_tree": base, "tree": items})
        if type(value) is not dict:
            raise InvalidResponseError("Git tree response is malformed")
        return GitObject(self._sha(value.get("sha"), "tree.sha"))

    def create_commit(self, repository: str, message: str, tree: str, parents: Iterable[str]) -> GitObject:
        owner, name = self._owner_repo(repository)
        if type(message) is not str or not message or len(message.encode("utf-8")) > 16_384:
            raise GitHubAPIError("commit message is invalid")
        tree_sha = self._sha(tree, "commit tree")
        parent_list = list(parents)
        if any(type(parent) is not str or not _SHA40_RE.fullmatch(parent) for parent in parent_list):
            raise GitHubAPIError("commit parents are invalid")
        author = {"name": "Swift Stream Federation", "email": "automation@swiftstream.invalid", "date": "2000-01-01T00:00:00Z"}
        committer = dict(author)
        payload = {"message": message, "tree": tree_sha, "parents": parent_list, "author": author, "committer": committer}
        value = self.request_json("POST", ["repos", owner, name, "git", "commits"], payload)
        if type(value) is not dict:
            raise InvalidResponseError("Git commit response is malformed")
        returned_sha = self._sha(value.get("sha"), "commit.sha")
        # GitHub's commit API accepts author/committer metadata.  Recompute the
        # Git object identity locally so a server rewrite cannot silently break
        # deterministic regeneration or cause a ref-CAS convergence loop.
        timestamp = "946684800 +0000"
        commit_body = (
            f"tree {tree_sha}\n"
            + "".join(f"parent {parent}\n" for parent in parent_list)
            + f"author Swift Stream Federation <automation@swiftstream.invalid> {timestamp}\n"
            + f"committer Swift Stream Federation <automation@swiftstream.invalid> {timestamp}\n\n"
        ).encode("utf-8") + message.encode("utf-8")
        expected_sha = hashlib.sha1(b"commit " + str(len(commit_body)).encode("ascii") + b"\0" + commit_body).hexdigest()
        if returned_sha != expected_sha:
            raise InvalidResponseError("GitHub rewrote deterministic commit identity")
        for identity in ("author", "committer"):
            returned = value.get(identity)
            if returned is not None:
                if type(returned) is not dict or returned.get("name") != author["name"] or returned.get("email") != author["email"] or returned.get("date") != author["date"]:
                    raise InvalidResponseError("GitHub rewrote deterministic commit metadata")
        return GitObject(returned_sha)

    def create_check_run(self, repository: str, name: str, head_sha: str, *, status: str = "completed", conclusion: str | None = None, output: Mapping[str, Any] | None = None) -> CheckRun:
        owner, repo = self._owner_repo(repository)
        if type(name) is not str or not name or len(name) > 100 or c02.contains_control(name):
            raise GitHubAPIError("check name is invalid")
        sha = self._sha(head_sha, "check head_sha")
        if status not in {"queued", "in_progress", "completed"} or (conclusion is not None and conclusion not in {"success", "failure", "action_required", "cancelled", "timed_out", "neutral", "skipped"}):
            raise GitHubAPIError("check status/conclusion is invalid")
        payload: dict[str, Any] = {"name": name, "head_sha": sha, "status": status}
        if conclusion is not None:
            payload["conclusion"] = conclusion
        if output is not None:
            payload["output"] = dict(output)
        return self._parse_check(self.request_json("POST", ["repos", owner, repo, "check-runs"], payload))

    def list_check_runs(self, repository: str, head_sha: str, *, max_pages: int = 100) -> tuple[CheckRun, ...]:
        owner, repo = self._owner_repo(repository)
        sha = self._sha(head_sha, "check head_sha")
        checks: list[CheckRun] = []
        for page in range(1, max_pages + 1):
            value = self._request("GET", f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(repo)}/commits/{sha}/check-runs?per_page=100&page={page}")
            if type(value) is not dict or type(value.get("check_runs")) is not list:
                raise InvalidResponseError("check-run list response is malformed")
            checks.extend(self._parse_check(item) for item in value["check_runs"])
            if len(value["check_runs"]) < 100:
                return tuple(checks)
        raise InvalidResponseError("check-run pagination exceeds bound")

    def update_check_run(self, repository: str, check_id: int, *, head_sha: str, status: str = "completed", conclusion: str | None = None, output: Mapping[str, Any] | None = None) -> CheckRun:
        owner, repo = self._owner_repo(repository)
        check = _positive_id(check_id, "check ID")
        sha = self._sha(head_sha, "check head_sha")
        if status not in {"queued", "in_progress", "completed"} or (conclusion is not None and conclusion not in {"success", "failure", "action_required", "cancelled", "timed_out", "neutral", "skipped"}):
            raise GitHubAPIError("check status/conclusion is invalid")
        payload: dict[str, Any] = {"status": status}
        if conclusion is not None:
            payload["conclusion"] = conclusion
        if output is not None:
            payload["output"] = dict(output)
        returned = self._parse_check(self.request_json("PATCH", ["repos", owner, repo, "check-runs", str(check)], payload))
        if returned.head_sha != sha:
            raise InvalidResponseError("check-run update retargeted its immutable head")
        return returned

    @staticmethod
    def _parse_check(value: Any) -> CheckRun:
        if type(value) is not dict:
            raise InvalidResponseError("check-run response is malformed")
        app = value.get("app")
        app_id = _positive_id(app.get("id"), "check.app.id") if isinstance(app, dict) and app.get("id") is not None else None
        output_value = value.get("output") if "output" in value else None
        output_text: str | None = None
        if "output" in value:
            allowed_output_keys = {"title", "summary", "text", "annotations_count", "annotations_url", "images"}
            if type(output_value) is not dict or not {"title", "summary", "text"}.issubset(output_value) or not set(output_value).issubset(allowed_output_keys):
                raise InvalidResponseError("check.output has invalid exact shape")
            _bounded_text(output_value.get("title"), "check.output.title", 256)
            _bounded_text(output_value.get("summary"), "check.output.summary", 512)
            output_text = _bounded_text(output_value.get("text"), "check.output.text", 4_096)
            if "annotations_count" in output_value and (type(output_value["annotations_count"]) is not int or not 0 <= output_value["annotations_count"] <= 50_000):
                raise InvalidResponseError("check.output.annotations_count is invalid")
            if "annotations_url" in output_value:
                _bounded_text(output_value["annotations_url"], "check.output.annotations_url", 2_048)
            if "images" in output_value:
                images = output_value["images"]
                if type(images) is not list or len(images) > 10:
                    raise InvalidResponseError("check.output.images is invalid")
                for image in images:
                    if type(image) is not dict or set(image) != {"alt", "image_url"}:
                        raise InvalidResponseError("check.output image is malformed")
                    _bounded_text(image.get("alt"), "check.output.image.alt", 256)
                    _bounded_text(image.get("image_url"), "check.output.image.image_url", 2_048)
        return CheckRun(
            _positive_id(value.get("id"), "check.id"),
            _bounded_text(value.get("name"), "check.name", 100),
            GitHubClient._sha(value.get("head_sha"), "check.head_sha"),
            _bounded_text(value.get("status"), "check.status", 32),
            _optional_iso(value.get("conclusion"), "check.conclusion"),
            app_id,
            output_text,
        )

    def dispatch_workflow(self, repository: str, workflow: str, ref: str, inputs: Mapping[str, str] | None = None) -> None:
        owner, name = self._owner_repo(repository)
        if type(workflow) is not str or not workflow or "/" in workflow or "\\" in workflow:
            raise GitHubAPIError("workflow identifier is invalid")
        try:
            validate_trusted_ref(ref)
        except (c02.FederationError, WorkspaceError):
            raise GitHubAPIError("workflow ref is not a valid trusted branch") from None
        if inputs is not None and (type(inputs) is not dict or any(type(k) is not str or type(v) is not str for k, v in inputs.items())):
            raise GitHubAPIError("workflow inputs must be string data")
        self.request_json("POST", ["repos", owner, name, "actions", "workflows", workflow, "dispatches"], {"ref": ref, "inputs": dict(inputs or {})})

    def list_open_pull_requests(self, repository: str, *, max_pages: int = 100) -> tuple[dict[str, Any], ...]:
        owner, name = self._owner_repo(repository)
        result: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            value = self._request("GET", f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/pulls?state=open&per_page=100&page={page}")
            if type(value) is not list or any(type(item) is not dict for item in value):
                raise InvalidResponseError("open PR enumeration is malformed")
            result.extend(value)
            if len(value) < 100:
                return tuple(sorted(result, key=lambda item: _positive_id(item.get("number"), "PR.number")))
        raise InvalidResponseError("open PR enumeration exceeds bound")

    def create_machine_pull_request(self, repository: str, *, head: str, base: str, title: str, body: str) -> int:
        """Create a bounded machine PR; branch and base are data, never URL/query syntax."""
        owner, name = self._owner_repo(repository)
        for value, label, limit in ((head, "machine PR head", 256), (base, "machine PR base", 256), (title, "machine PR title", 256), (body, "machine PR body", 16_384)):
            if type(value) is not str or not value or len(value.encode("utf-8")) > limit or c02.contains_control(value):
                raise GitHubAPIError(f"{label} is invalid or exceeds its bound")
        # GitHub accepts either a plain branch name or owner:branch for a PR
        # head.  Federation machine authority is central-only, so reject the
        # fork form while allowing the required nested bot/federation/* ref.
        if ":" in head or head.startswith("refs/"):
            raise GitHubAPIError("machine PR head must be a central branch ref")
        try:
            validate_trusted_ref(f"refs/heads/{head}")
            validate_trusted_ref(f"refs/heads/{base}")
        except (c02.FederationError, WorkspaceError):
            raise GitHubAPIError("machine PR branch is not trusted") from None
        value = self.request_json("POST", ["repos", owner, name, "pulls"], {"title": title, "head": head, "base": base, "body": body})
        if type(value) is not dict:
            raise InvalidResponseError("created machine PR response is malformed")
        return _positive_id(value.get("number"), "created machine PR.number")

    def update_pull_request_state(self, repository: str, number: int, *, state: str) -> None:
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0 or state not in {"open", "closed"}:
            raise GitHubAPIError("pull request state update is invalid")
        value = self.request_json("PATCH", ["repos", owner, name, "pulls", str(number)], {"state": state})
        if type(value) is not dict or type(value.get("number")) is not int or value["number"] != number:
            raise InvalidResponseError("updated pull request response is malformed")

    def merge_machine_pull_request(self, repository: str, number: int, *, expected_head_sha: str) -> MergeResult:
        """Merge only with GitHub's exact expected-head compare-and-swap input."""
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("pull request number must be positive")
        head = self._sha(expected_head_sha, "expected PR head SHA")
        value = self.request_json("PUT", ["repos", owner, name, "pulls", str(number), "merge"], {"sha": head})
        if type(value) is not dict or set(value) != {"sha", "merged", "message"}:
            raise InvalidResponseError("merge response has invalid exact shape")
        if type(value["merged"]) is not bool or type(value["message"]) is not str or not value["message"] or len(value["message"]) > 512 or c02.contains_control(value["message"]):
            raise InvalidResponseError("merge response has invalid status fields")
        sha = None if value["sha"] is None else self._sha(value["sha"], "merge.sha")
        if value["merged"] and sha is None:
            raise InvalidResponseError("successful merge response has no merge SHA")
        return MergeResult(value["merged"], value["message"][:512], sha)

    def update_refs(self, repository_id: str, updates: list[RefUpdate] | tuple[RefUpdate, ...]) -> dict[str, Any]:
        if type(repository_id) is not str or not repository_id or any(ord(char) < 0x20 for char in repository_id):
            raise GitHubAPIError("repository_id must be a nonempty opaque ID")
        update_list = list(updates)
        if not update_list:
            raise GitHubAPIError("updateRefs requires at least one ref update")
        variables = {"repositoryId": repository_id, "refUpdates": [item.as_graphql_value() for item in update_list]}
        result = self._request("POST", GRAPHQL_ENDPOINT, {"query": UPDATE_REFS_MUTATION, "variables": variables})
        if type(result) is not dict:
            raise InvalidResponseError("GraphQL response must be an object")
        if "errors" in result:
            errors = result["errors"]
            if type(errors) is not list or not errors or any(type(item) is not dict for item in errors):
                raise GraphQLError("GraphQL returned malformed errors")
            raise RefCASConflict("GraphQL updateRefs rejected the ref-CAS operation")
        if set(result) != {"data"} or type(result["data"]) is not dict:
            raise InvalidResponseError("GraphQL response has invalid exact top-level shape")
        data = result["data"]
        if set(data) != {"updateRefs"} or type(data["updateRefs"]) is not dict:
            raise InvalidResponseError("GraphQL updateRefs response has invalid shape")
        if set(data["updateRefs"]) != {"clientMutationId"}:
            raise InvalidResponseError("GraphQL updateRefs payload has invalid exact shape")
        if data["updateRefs"]["clientMutationId"] is not None and type(data["updateRefs"]["clientMutationId"]) is not str:
            raise InvalidResponseError("GraphQL clientMutationId has invalid shape")
        return data["updateRefs"]
