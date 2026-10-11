"""Deterministic GitHub transport seams and the sole R01 ref-CAS primitive."""

from __future__ import annotations

import json
import base64
import hashlib
import re
import socket
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Literal, Mapping, Protocol
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest

from scripts import federate as c02
from automation.federation.workspace import WorkspaceError, validate_trusted_ref
from automation.federation.request_model import (
    MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES,
    RequestModelError,
    parse_issue_patch_projection,
    parse_status_description,
    reserved_issue_branch_number,
)

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
_ISSUE_COMMENT_COMPOSITE_RACE = "issue comment REST authority changed during composite read"
_ISSUE_COMMENT_COMPOSITE_MAX_ATTEMPTS = 3

UPDATE_REFS_MUTATION = """mutation FederationUpdateRefs($repositoryId: ID!, $refUpdates: [RefUpdate!]!) {
  updateRefs(input: {repositoryId: $repositoryId, refUpdates: $refUpdates}) {
    clientMutationId
  }
}"""

REOPEN_PULL_REQUEST_MUTATION = """mutation FederationReopenPullRequest($pullRequestId: ID!, $clientMutationId: String!) {
  reopenPullRequest(input: {pullRequestId: $pullRequestId, clientMutationId: $clientMutationId}) {
    clientMutationId
    pullRequest {
      id
      fullDatabaseId
      number
      state
      isDraft
      merged
      mergedAt
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      headRepository { id }
      baseRepository { id }
    }
  }
}"""

MARK_PULL_REQUEST_READY_FOR_REVIEW_MUTATION = """mutation FederationMarkPullRequestReadyForReview($pullRequestId: ID!, $clientMutationId: String!) {
  markPullRequestReadyForReview(input: {pullRequestId: $pullRequestId, clientMutationId: $clientMutationId}) {
    clientMutationId
    pullRequest {
      id
      fullDatabaseId
      number
      state
      isDraft
      merged
      mergedAt
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      headRepository { id }
      baseRepository { id }
    }
  }
}"""

CONVERT_PULL_REQUEST_TO_DRAFT_MUTATION = """mutation FederationConvertPullRequestToDraft($pullRequestId: ID!, $clientMutationId: String!) {
  convertPullRequestToDraft(input: {pullRequestId: $pullRequestId, clientMutationId: $clientMutationId}) {
    clientMutationId
    pullRequest {
      id
      fullDatabaseId
      number
      state
      isDraft
      merged
      mergedAt
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      headRepository { id }
      baseRepository { id }
    }
  }
}"""

CLOSE_PULL_REQUEST_MUTATION = """mutation FederationClosePullRequest($pullRequestId: ID!, $clientMutationId: String!) {
  closePullRequest(input: {pullRequestId: $pullRequestId, clientMutationId: $clientMutationId}) {
    clientMutationId
    pullRequest {
      id
      fullDatabaseId
      number
      state
      isDraft
      merged
      mergedAt
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      headRepository { id }
      baseRepository { id }
    }
  }
}"""

_PULL_REQUEST_STAGE_MUTATIONS = {
    "REOPEN": (REOPEN_PULL_REQUEST_MUTATION, "reopenPullRequest"),
    "READY_FOR_REVIEW": (MARK_PULL_REQUEST_READY_FOR_REVIEW_MUTATION, "markPullRequestReadyForReview"),
    "CONVERT_TO_DRAFT": (CONVERT_PULL_REQUEST_TO_DRAFT_MUTATION, "convertPullRequestToDraft"),
    "CLOSE": (CLOSE_PULL_REQUEST_MUTATION, "closePullRequest"),
}

# These documents are deliberately fixed strings.  All repository, login, ref,
# and comment values enter as GraphQL variables; none can become query syntax.
PULL_REQUEST_ROUTING_BEFORE_QUERY = """query FederationPullRequestRoutingBefore($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) {
      number
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      isDraft
      lastEditedAt
      includesCreatedEdit
    }
  }
}"""

PULL_REQUEST_ROUTING_AFTER_QUERY = """query FederationPullRequestRoutingAfter($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) {
      number
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      isDraft
      lastEditedAt
      includesCreatedEdit
    }
  }
}"""

ISSUE_ROUTING_BEFORE_QUERY = """query FederationIssueRoutingBefore($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    issueOrPullRequest(number: $number) {
      __typename
      ... on Issue {
        id
        number
        lastEditedAt
        includesCreatedEdit
        closed
      }
      ... on PullRequest {
        id
        number
        lastEditedAt
        includesCreatedEdit
        closed
      }
    }
  }
}"""

ISSUE_ROUTING_AFTER_QUERY = """query FederationIssueRoutingAfter($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    issueOrPullRequest(number: $number) {
      __typename
      ... on Issue {
        id
        number
        lastEditedAt
        includesCreatedEdit
        closed
      }
      ... on PullRequest {
        id
        number
        lastEditedAt
        includesCreatedEdit
        closed
      }
    }
  }
}"""

PULL_REQUEST_BODY_FALLBACK_QUERY = """query FederationPullRequestBodyFallback($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    nameWithOwner
    pullRequest(number: $number) {
      number
      body
    }
  }
}"""

MERGED_PULL_REQUEST_QUERY = """query FederationMergedPullRequest($owner: String!, $name: String!, $number: Int!) {
  repository(owner: $owner, name: $name) {
    id
    databaseId
    nameWithOwner
    pullRequest(number: $number) {
      id
      databaseId
      number
      state
      isDraft
      merged
      mergedAt
      mergeCommit { oid }
      headRefOid
      baseRefOid
      headRefName
      baseRefName
      headRepository { id databaseId nameWithOwner }
      baseRepository { id databaseId nameWithOwner }
    }
  }
}"""

ISSUE_COMMENT_NODES_QUERY = """query FederationIssueCommentNodes($ids: [ID!]!) {
  nodes(ids: $ids) {
    __typename
    id
    ... on IssueComment {
      fullDatabaseId
      body
      createdAt
      updatedAt
      author {
        __typename
        login
        ... on Node { id }
      }
      editor {
        __typename
        login
        ... on Node { id }
      }
      lastEditedAt
      includesCreatedEdit
      userContentEdits(first: 1) {
        totalCount
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


def _positive_graphql_bigint(value: Any, label: str = "PullRequest.fullDatabaseId") -> int:
    """Parse GitHub BigInt JSON only from its canonical decimal string form."""
    if type(value) is not str or re.fullmatch(r"[1-9][0-9]*", value) is None:
        raise InvalidResponseError(f"{label} must be canonical positive decimal text")
    try:
        parsed = int(value)
    except (ValueError, OverflowError):
        raise InvalidResponseError(f"{label} is invalid") from None
    if parsed <= 0:
        raise InvalidResponseError(f"{label} must be positive")
    return parsed


def _canonical_stage_timestamp(value: Any, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", value
    ) is None:
        raise InvalidResponseError(f"{label} must be a canonical UTC timestamp or null")
    try:
        datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        raise InvalidResponseError(f"{label} must be a canonical UTC timestamp or null") from None
    return value


def _stage_client_mutation_id(value: Any, label: str) -> str:
    text = _bounded_text(value, label, 256)
    if len(text.encode("utf-8")) > 256:
        raise InvalidResponseError(f"{label} exceeds 256 UTF-8 bytes")
    return text


def _optional_iso(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _bounded_text(value, label, 128)


def _optional_bounded_text(value: Any, label: str, limit: int) -> str:
    if type(value) is not str or len(value) > limit or c02.contains_control(value):
        raise InvalidResponseError(f"{label} has invalid bounded text")
    return value


def _parse_github_timestamp(value: Any, label: str) -> Any:
    text = _bounded_text(value, label, 128)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        raise InvalidResponseError(f"{label} must be a valid timestamp") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InvalidResponseError(f"{label} must be timezone-aware")
    return parsed


def _graphql_error_diagnostic(error: Mapping[str, Any], operation: str | None = None) -> str:
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

    if operation is not None:
        if rendered_path == "unknown-path":
            rendered_path = operation
        else:
            candidate = f"{operation}.{rendered_path}"
            if type(raw_path) is list and len(raw_path) < 16 and len(f"GRAPHQL:{error_type}:{candidate}".encode("utf-8")) <= _GRAPHQL_DIAGNOSTIC_MAX_BYTES:
                rendered_path = candidate
            else:
                rendered_path = operation

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


_WORKFLOW_STATES = frozenset({
    "active", "deleted", "disabled_fork", "disabled_inactivity", "disabled_manually",
})
_WORKFLOW_RUN_STATUSES = frozenset({
    "queued", "in_progress", "completed", "waiting", "requested", "pending",
})
_WORKFLOW_RUN_CONCLUSIONS = frozenset({
    "success", "failure", "neutral", "cancelled", "skipped",
    "timed_out", "action_required", "stale", "startup_failure",
})


@dataclass(frozen=True)
class WorkflowMetadata:
    id: int
    node_id: str
    name: str
    path: str
    state: str

    def __post_init__(self) -> None:
        _positive_id(self.id, "workflow.id")
        _bounded_text(self.node_id, "workflow.node_id", 256)
        _bounded_text(self.name, "workflow.name", 256)
        path = _bounded_text(self.path, "workflow.path", 256)
        prefix = ".github/workflows/"
        if (
            not path.startswith(prefix)
            or path == prefix
            or "/" in path[len(prefix):]
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise InvalidResponseError("workflow.path must be an exact workflow file path")
        if type(self.state) is not str or self.state not in _WORKFLOW_STATES:
            raise InvalidResponseError("workflow.state is not a closed known value")


@dataclass(frozen=True)
class WorkflowRunMetadata:
    id: int
    run_attempt: int
    status: str
    conclusion: str | None
    workflow_id: int
    event: str
    head_branch: str | None
    head_sha: str

    def __post_init__(self) -> None:
        _positive_id(self.id, "workflow_run.id")
        _positive_id(self.run_attempt, "workflow_run.run_attempt")
        _positive_id(self.workflow_id, "workflow_run.workflow_id")
        if type(self.status) is not str or self.status not in _WORKFLOW_RUN_STATUSES:
            raise InvalidResponseError("workflow_run.status is not a closed known value")
        if self.conclusion is not None and (
            type(self.conclusion) is not str or self.conclusion not in _WORKFLOW_RUN_CONCLUSIONS
        ):
            raise InvalidResponseError("workflow_run.conclusion is not a closed known value")
        _bounded_text(self.event, "workflow_run.event", 64)
        if self.head_branch is not None:
            _bounded_text(self.head_branch, "workflow_run.head_branch", 256)
        if type(self.head_sha) is not str or not _SHA40_RE.fullmatch(self.head_sha):
            raise InvalidResponseError("workflow_run.head_sha must be lowercase 40-hex")


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
    draft: bool


@dataclass(frozen=True)
class MergedPullRequestMetadata:
    repository_full_name: str
    repository_node_id: str
    repository_database_id: int
    pull_request_node_id: str
    pull_request_database_id: int
    pull_request_number: int
    state: str
    is_draft: bool
    merged: bool
    merged_at: str | None
    merge_commit_oid: str | None
    head_oid: str
    base_oid: str
    head_ref: str
    base_ref: str
    head_repository_node_id: str
    head_repository_database_id: int
    head_repository_full_name: str
    base_repository_node_id: str
    base_repository_database_id: int
    base_repository_full_name: str


@dataclass(frozen=True)
class PullRequestStageMutationReceipt:
    """Exact PR identity and topology returned by one fixed GraphQL mutation."""

    operation: str
    requested_pull_request_node_id: str
    requested_client_mutation_id: str
    returned_client_mutation_id: str
    pull_request_node_id: str
    pull_request_database_id: int
    pull_request_number: int
    state: str
    is_draft: bool
    merged: bool
    merged_at: str | None
    head_oid: str
    base_oid: str
    head_ref: str
    base_ref: str
    head_repository_node_id: str
    base_repository_node_id: str

    def __post_init__(self) -> None:
        if self.operation not in _PULL_REQUEST_STAGE_MUTATIONS or type(self.operation) is not str:
            raise InvalidResponseError("PR-stage operation is invalid")
        _bounded_text(self.requested_pull_request_node_id, "requested pullRequestId", 256)
        _stage_client_mutation_id(self.requested_client_mutation_id, "requested clientMutationId")
        _stage_client_mutation_id(self.returned_client_mutation_id, "returned clientMutationId")
        _bounded_text(self.pull_request_node_id, "pullRequest.id", 256)
        if self.requested_pull_request_node_id != self.pull_request_node_id:
            raise InvalidResponseError("PR-stage response node ID does not match requested PR")
        if self.requested_client_mutation_id != self.returned_client_mutation_id:
            raise InvalidResponseError("PR-stage response clientMutationId does not match request")
        if type(self.pull_request_database_id) is not int or self.pull_request_database_id <= 0:
            raise InvalidResponseError("pullRequest.fullDatabaseId must be a positive Python integer")
        _positive_id(self.pull_request_number, "pullRequest.number")
        if self.state not in {"OPEN", "CLOSED"} or type(self.state) is not str:
            raise InvalidResponseError("pullRequest.state is invalid")
        if type(self.is_draft) is not bool or type(self.merged) is not bool:
            raise InvalidResponseError("pullRequest draft/merge fields must be exact booleans")
        _canonical_stage_timestamp(self.merged_at, "pullRequest.mergedAt")
        if not self.merged and self.merged_at is not None:
            raise InvalidResponseError("unmerged PR-stage response must have null mergedAt")
        for value, label in ((self.head_oid, "pullRequest.headRefOid"), (self.base_oid, "pullRequest.baseRefOid")):
            if type(value) is not str or not _SHA40_RE.fullmatch(value):
                raise InvalidResponseError(f"{label} must be lowercase 40-hex")
        for value, label in ((self.head_ref, "pullRequest.headRefName"), (self.base_ref, "pullRequest.baseRefName")):
            _bounded_text(value, label, 256)
        _bounded_text(self.head_repository_node_id, "pullRequest.headRepository.id", 256)
        _bounded_text(self.base_repository_node_id, "pullRequest.baseRepository.id", 256)
        if self.operation == "REOPEN" and (self.state != "OPEN" or self.merged or self.merged_at is not None):
            raise InvalidResponseError("reopen mutation did not return OPEN unmerged PR")
        if self.operation == "READY_FOR_REVIEW" and (self.state != "OPEN" or self.is_draft or self.merged or self.merged_at is not None):
            raise InvalidResponseError("ready mutation did not return OPEN ready unmerged PR")
        if self.operation == "CONVERT_TO_DRAFT" and (self.state != "OPEN" or not self.is_draft or self.merged or self.merged_at is not None):
            raise InvalidResponseError("draft mutation did not return OPEN draft unmerged PR")
        if self.operation == "CLOSE" and (self.state != "CLOSED" or self.merged or self.merged_at is not None):
            raise InvalidResponseError("close mutation did not return CLOSED unmerged PR")


@dataclass(frozen=True)
class IssueMetadata:
    number: int
    database_id: int
    node_id: str
    body: str
    state: Literal["open", "closed"]
    author_id: str
    author_login: str
    last_edited_at: str | None
    includes_created_edit: bool
    is_pull_request: bool


@dataclass(frozen=True)
class _PullRequestRoutingSnapshot:
    number: int
    head_oid: str
    base_oid: str
    head_ref: str
    base_ref: str
    draft: bool
    last_edited_at: str | None
    includes_created_edit: bool


@dataclass(frozen=True)
class _IssueRoutingSnapshot:
    typename: str
    node_id: str
    number: int
    last_edited_at: str | None
    includes_created_edit: bool
    closed: bool

    @property
    def is_pull_request(self) -> bool:
        return self.typename == "PullRequest"


@dataclass(frozen=True)
class _IssueRESTDetail:
    number: int
    database_id: int
    node_id: str
    body: str
    state: str
    author_id: str
    author_login: str
    is_pull_request: bool


@dataclass(frozen=True)
class _PullRequestRESTDetail:
    number: int
    body: str | None
    author_id: str
    author_login: str
    head_oid: str
    base_oid: str
    head_ref: str
    base_ref: str
    draft: bool
    head_repository_id: str
    head_repository: str
    base_repository_id: str
    base_repository: str


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
class _IssueCommentRESTRecord:
    database_id: int
    node_id: str
    body: str
    author_id: str | None
    author_login: str | None
    author_type: str | None
    created_at: str
    updated_at: str
    issue_url: str


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
    author_date: str = "2000-01-01T00:00:00Z"


@dataclass(frozen=True)
class GitCommitIdentity:
    name: str
    email: str
    date: str

    def __post_init__(self) -> None:
        _bounded_text(self.name, "commit identity name", 256)
        _bounded_text(self.email, "commit identity email", 320)
        _canonical_utc_timestamp(self.date, "commit identity date")


@dataclass(frozen=True)
class GitCommitObject:
    sha: str
    message: str
    tree_sha: str
    parents: tuple[str, ...]
    author: GitCommitIdentity
    committer: GitCommitIdentity

    def __post_init__(self) -> None:
        if type(self.sha) is not str or not _SHA40_RE.fullmatch(self.sha):
            raise GitHubAPIError("commit object sha must be lowercase 40-hex")
        if type(self.tree_sha) is not str or not _SHA40_RE.fullmatch(self.tree_sha):
            raise GitHubAPIError("commit object tree sha must be lowercase 40-hex")
        if type(self.message) is not str:
            raise GitHubAPIError("commit object message must be a string")
        try:
            message_bytes = self.message.encode("utf-8")
        except UnicodeEncodeError:
            raise GitHubAPIError("commit object message must be valid UTF-8") from None
        if len(message_bytes) > 65_536 or "\x00" in self.message:
            raise GitHubAPIError("commit object message exceeds bounds or contains NUL")
        if type(self.parents) is not tuple or len(self.parents) > 1_000:
            raise GitHubAPIError("commit object parents must be a bounded tuple")
        if any(type(parent) is not str or not _SHA40_RE.fullmatch(parent) for parent in self.parents):
            raise GitHubAPIError("commit object parent sha must be lowercase 40-hex")
        if type(self.author) is not GitCommitIdentity or type(self.committer) is not GitCommitIdentity:
            raise GitHubAPIError("commit object author and committer metadata are required")


@dataclass(frozen=True)
class CommitStatus:
    id: int
    node_id: str | None
    state: str
    context: str
    description: str | None
    target_url: str | None
    creator_database_id: int
    creator_node_id: str
    creator_login: str
    creator_type: str
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        _positive_id(self.id, "status.id")
        if self.node_id is not None:
            _bounded_text(self.node_id, "status.node_id")
        if type(self.state) is not str or self.state not in {"error", "failure", "pending", "success"}:
            raise GitHubAPIError("status.state is invalid")
        _bounded_text(self.context, "status.context", 100)
        if self.description is not None:
            text = _optional_bounded_text(self.description, "status.description", 140)
            if text.startswith("ssf:v1"):
                try:
                    parse_status_description(text)
                except RequestModelError as error:
                    raise GitHubAPIError(f"status.description is invalid: {error}") from None
        if self.target_url is not None:
            _optional_bounded_text(self.target_url, "status.target_url", 2_048)
        _positive_id(self.creator_database_id, "status.creator.id")
        _bounded_text(self.creator_node_id, "status.creator.node_id")
        _bounded_text(self.creator_login, "status.creator.login")
        if type(self.creator_type) is not str or self.creator_type not in {"Bot", "User"}:
            raise GitHubAPIError("status.creator.type must be exact Bot or User")
        _canonical_utc_timestamp(self.created_at, "status.created_at")
        _canonical_utc_timestamp(self.updated_at, "status.updated_at")


@dataclass(frozen=True)
class StatusWriteReceipt:
    repository: str
    requested_sha: str
    method: str
    route: str
    requested_state: str
    requested_context: str
    requested_description: str | None
    requested_target_url: str | None
    returned_status: CommitStatus

    def __post_init__(self) -> None:
        expected_route = _canonical_status_route(self.repository, self.requested_sha)
        if self.method != "POST":
            raise GitHubAPIError("status receipt method must be exact POST")
        if self.route != expected_route:
            raise GitHubAPIError("status receipt route does not match repository and SHA")
        _validate_status_request(
            self.requested_state, self.requested_context,
            self.requested_description, self.requested_target_url,
        )
        if type(self.returned_status) is not CommitStatus:
            raise GitHubAPIError("status receipt must contain the exact returned CommitStatus")
        if (
            self.returned_status.state != self.requested_state
            or self.returned_status.context != self.requested_context
            or self.returned_status.description != self.requested_description
            or self.returned_status.target_url != self.requested_target_url
        ):
            raise InvalidResponseError("returned commit status does not match the request receipt")


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


def latest_exact_app_status(
    statuses: Iterable[CommitStatus],
    context: str,
    *,
    bot_database_id: int,
    bot_node_id: str,
    bot_login: str,
) -> CommitStatus | None:
    _bounded_text(context, "status context", 100)
    _positive_id(bot_database_id, "status bot database ID")
    _bounded_text(bot_node_id, "status bot node ID")
    _bounded_text(bot_login, "status bot login")
    for status in statuses:
        if type(status) is not CommitStatus:
            raise InvalidResponseError("status history contains a non-CommitStatus value")
        if (
            status.context == context
            and status.creator_database_id == bot_database_id
            and status.creator_node_id == bot_node_id
            and status.creator_login == bot_login
            and status.creator_type == "Bot"
        ):
            return status
    return None


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


_CANONICAL_UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


def _canonical_utc_timestamp(value: Any, label: str) -> str:
    if type(value) is not str or not _CANONICAL_UTC_RE.fullmatch(value):
        raise InvalidResponseError(f"{label} must be canonical UTC timestamp text")
    instant = _parse_github_timestamp(value, label)
    if instant.isoformat(timespec="seconds").replace("+00:00", "Z") != value:
        raise InvalidResponseError(f"{label} must be canonical UTC timestamp text")
    return value


def _canonical_repository_parts(repository: Any) -> tuple[str, str, str, str]:
    if type(repository) is not str or repository.count("/") != 1 or len(repository) > 512:
        raise GitHubAPIError("repository must be exact OWNER/REPO text")
    owner, name = repository.split("/")
    if not owner or not name:
        raise GitHubAPIError("repository must be exact OWNER/REPO text")
    return owner, name, _validate_segment(owner), _validate_segment(name)


def _canonical_status_route(repository: Any, requested_sha: Any) -> str:
    _owner, _name, owner_path, name_path = _canonical_repository_parts(repository)
    if type(requested_sha) is not str or not _SHA40_RE.fullmatch(requested_sha):
        raise GitHubAPIError("requested status SHA must be lowercase 40-hex")
    return f"/repos/{owner_path}/{name_path}/statuses/{requested_sha}"


def _validate_status_request(state: Any, context: Any, description: Any, target_url: Any) -> None:
    if type(state) is not str or state not in {"error", "failure", "pending", "success"}:
        raise GitHubAPIError("commit status state is invalid")
    _bounded_text(context, "commit status context", 100)
    if description is not None:
        _optional_bounded_text(description, "commit status description", 140)
        if description.startswith("ssf:v1"):
            try:
                parse_status_description(description)
            except RequestModelError as error:
                raise GitHubAPIError(f"canonical status description is invalid: {error}") from None
    if target_url is not None:
        _optional_bounded_text(target_url, "commit status target_url", 2_048)


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

    def _request_response(self, method: str, url: str, payload: Any = None) -> HttpResponse:
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
        return response

    def _request(self, method: str, url: str, payload: Any = None) -> Any:
        response = self._request_response(method, url, payload)
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

    def _graphql(self, document: str, variables: Mapping[str, Any], *, operation: str | None = None) -> dict[str, Any]:
        if type(document) is not str or document not in {
            PULL_REQUEST_ROUTING_BEFORE_QUERY,
            PULL_REQUEST_ROUTING_AFTER_QUERY,
            ISSUE_ROUTING_BEFORE_QUERY,
            ISSUE_ROUTING_AFTER_QUERY,
            PULL_REQUEST_BODY_FALLBACK_QUERY,
            MERGED_PULL_REQUEST_QUERY,
            ISSUE_COMMENT_NODES_QUERY,
            APP_QUERY,
            BOT_QUERY,
            UPDATE_REFS_MUTATION,
            REOPEN_PULL_REQUEST_MUTATION,
            MARK_PULL_REQUEST_READY_FOR_REVIEW_MUTATION,
            CONVERT_PULL_REQUEST_TO_DRAFT_MUTATION,
            CLOSE_PULL_REQUEST_MUTATION,
        }:
            raise GitHubAPIError("GraphQL document is not an accepted trusted document")
        result = self._request("POST", GRAPHQL_ENDPOINT, {"query": document, "variables": dict(variables)})
        if type(result) is not dict:
            raise InvalidResponseError("GraphQL response must be an object")
        if "errors" in result:
            if type(result["errors"]) is not list or not result["errors"] or any(type(item) is not dict for item in result["errors"]):
                raise GraphQLError("GraphQL returned malformed errors")
            raise GraphQLError(_graphql_error_diagnostic(result["errors"][0], operation))
        if set(result) != {"data"} or type(result["data"]) is not dict:
            raise InvalidResponseError("GraphQL response has invalid exact top-level shape")
        return result["data"]

    @classmethod
    def _parse_pull_request_stage_mutation(
        cls, data: Any, *, operation: str, mutation_field: str,
        requested_pull_request_node_id: str, requested_client_mutation_id: str,
    ) -> PullRequestStageMutationReceipt:
        if type(data) is not dict or set(data) != {mutation_field} or type(data.get(mutation_field)) is not dict:
            raise InvalidResponseError("PR-stage mutation data has invalid exact shape")
        payload = data[mutation_field]
        if set(payload) != {"clientMutationId", "pullRequest"}:
            raise InvalidResponseError("PR-stage mutation payload has invalid exact shape")
        returned_client_mutation_id = _stage_client_mutation_id(payload["clientMutationId"], "clientMutationId")
        pull = payload["pullRequest"]
        pull_keys = {
            "id", "fullDatabaseId", "number", "state", "isDraft", "merged", "mergedAt",
            "headRefOid", "baseRefOid", "headRefName", "baseRefName", "headRepository", "baseRepository",
        }
        if type(pull) is not dict or set(pull) != pull_keys:
            raise InvalidResponseError("PR-stage mutation PullRequest has invalid exact shape")
        for key, label in (("headRepository", "headRepository"), ("baseRepository", "baseRepository")):
            if type(pull[key]) is not dict or set(pull[key]) != {"id"}:
                raise InvalidResponseError(f"PR-stage mutation {label} has invalid exact shape")
        receipt = PullRequestStageMutationReceipt(
            operation=operation,
            requested_pull_request_node_id=requested_pull_request_node_id,
            requested_client_mutation_id=requested_client_mutation_id,
            returned_client_mutation_id=returned_client_mutation_id,
            pull_request_node_id=_bounded_text(pull["id"], "pullRequest.id", 256),
            pull_request_database_id=_positive_graphql_bigint(pull["fullDatabaseId"]),
            pull_request_number=_positive_id(pull["number"], "pullRequest.number"),
            state=pull["state"],
            is_draft=pull["isDraft"],
            merged=pull["merged"],
            merged_at=_canonical_stage_timestamp(pull["mergedAt"], "pullRequest.mergedAt"),
            head_oid=cls._sha(pull["headRefOid"], "pullRequest.headRefOid"),
            base_oid=cls._sha(pull["baseRefOid"], "pullRequest.baseRefOid"),
            head_ref=_bounded_text(pull["headRefName"], "pullRequest.headRefName", 256),
            base_ref=_bounded_text(pull["baseRefName"], "pullRequest.baseRefName", 256),
            head_repository_node_id=_bounded_text(pull["headRepository"]["id"], "headRepository.id", 256),
            base_repository_node_id=_bounded_text(pull["baseRepository"]["id"], "baseRepository.id", 256),
        )
        return receipt

    def _pull_request_stage_mutation(
        self, operation: str, pull_request_node_id: str, client_mutation_id: str,
    ) -> PullRequestStageMutationReceipt:
        if operation not in _PULL_REQUEST_STAGE_MUTATIONS:
            raise GitHubAPIError("unsupported PR-stage operation")
        node_id = _bounded_text(pull_request_node_id, "pullRequestId", 256)
        mutation_id = _stage_client_mutation_id(client_mutation_id, "clientMutationId")
        document, mutation_field = _PULL_REQUEST_STAGE_MUTATIONS[operation]
        data = self._graphql(
            document,
            {"pullRequestId": node_id, "clientMutationId": mutation_id},
            operation=f"prStage{operation}",
        )
        return self._parse_pull_request_stage_mutation(
            data, operation=operation, mutation_field=mutation_field,
            requested_pull_request_node_id=node_id, requested_client_mutation_id=mutation_id,
        )

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
        author = value.get("author")
        author_date = "2000-01-01T00:00:00Z"
        if type(author) is dict and type(author.get("date")) is str:
            author_date = _parse_github_timestamp(author["date"], "commit.author.date").strftime("%Y-%m-%dT%H:%M:%SZ")
        return GitCommitMetadata(commit, tree_sha, tuple(parents), author_date)

    def get_git_commit_object(self, repository: str, sha: str) -> GitCommitObject:
        _owner, _name, owner_path, name_path = _canonical_repository_parts(repository)
        commit = self._sha(sha, "commit.sha")
        url = f"{REST_BASE_URL}/repos/{owner_path}/{name_path}/git/commits/{commit}"
        value = self._request("GET", url)
        if type(value) is not dict or type(value.get("tree")) is not dict or type(value.get("parents")) is not list:
            raise InvalidResponseError("Git commit object has invalid shape")
        returned_sha = self._sha(value.get("sha"), "commit.sha")
        if returned_sha != commit:
            raise InvalidResponseError("Git commit object identity does not match requested SHA")
        tree_sha = self._sha(value["tree"].get("sha"), "commit.tree.sha")
        message = value.get("message")
        if type(message) is not str:
            raise InvalidResponseError("Git commit message must be exact string text")
        try:
            message_size = len(message.encode("utf-8"))
        except UnicodeEncodeError:
            raise InvalidResponseError("Git commit message is not valid UTF-8") from None
        if message_size > 65_536 or "\x00" in message:
            raise InvalidResponseError("Git commit message exceeds bounds or contains NUL")
        parents: list[str] = []
        for parent in value["parents"]:
            if type(parent) is not dict:
                raise InvalidResponseError("Git commit parent has invalid shape")
            parents.append(self._sha(parent.get("sha"), "commit.parent.sha"))
        if len(parents) > 1_000:
            raise InvalidResponseError("Git commit parent list exceeds bound")

        def parse_identity(identity: Any, label: str) -> GitCommitIdentity:
            if type(identity) is not dict:
                raise InvalidResponseError(f"{label} metadata must be an object")
            try:
                return GitCommitIdentity(
                    _bounded_text(identity.get("name"), f"{label}.name", 256),
                    _bounded_text(identity.get("email"), f"{label}.email", 320),
                    _canonical_utc_timestamp(identity.get("date"), f"{label}.date"),
                )
            except (GitHubAPIError, InvalidResponseError) as error:
                raise InvalidResponseError(f"{label} metadata is invalid: {error}") from None

        return GitCommitObject(
            returned_sha,
            message,
            tree_sha,
            tuple(parents),
            parse_identity(value.get("author"), "commit.author"),
            parse_identity(value.get("committer"), "commit.committer"),
        )

    @staticmethod
    def _parse_commit_status(value: Any) -> CommitStatus:
        if type(value) is not dict:
            raise InvalidResponseError("commit status must be an object")
        creator = value.get("creator")
        if type(creator) is not dict:
            raise InvalidResponseError("commit status creator must be an object")
        try:
            return CommitStatus(
                id=_positive_id(value.get("id"), "status.id"),
                node_id=None if value.get("node_id") is None else _bounded_text(value.get("node_id"), "status.node_id"),
                state=value.get("state"),
                context=_bounded_text(value.get("context"), "status.context", 100),
                description=None if value.get("description") is None else _optional_bounded_text(value.get("description"), "status.description", 140),
                target_url=None if value.get("target_url") is None else _optional_bounded_text(value.get("target_url"), "status.target_url", 2_048),
                creator_database_id=_positive_id(creator.get("id"), "status.creator.id"),
                creator_node_id=_bounded_text(creator.get("node_id"), "status.creator.node_id"),
                creator_login=_bounded_text(creator.get("login"), "status.creator.login"),
                creator_type=creator.get("type"),
                created_at=_canonical_utc_timestamp(value.get("created_at"), "status.created_at"),
                updated_at=_canonical_utc_timestamp(value.get("updated_at"), "status.updated_at"),
            )
        except GitHubAPIError as error:
            raise InvalidResponseError(f"commit status is invalid: {error}") from None

    def create_commit_status(
        self,
        repository: str,
        requested_sha: str,
        state: str,
        context: str,
        description: str | None,
        target_url: str | None = None,
    ) -> StatusWriteReceipt:
        route = _canonical_status_route(repository, requested_sha)
        _validate_status_request(state, context, description, target_url)
        payload = {
            "state": state,
            "context": context,
            "description": description,
            "target_url": target_url,
        }
        response = self._request_response("POST", REST_BASE_URL + route, payload)
        if response.status != 201:
            raise UnexpectedStatusError("commit status creation requires same-response HTTP 201")
        returned = self._parse_commit_status(_decode_json(response.body))
        return StatusWriteReceipt(
            repository=repository,
            requested_sha=requested_sha,
            method="POST",
            route=route,
            requested_state=state,
            requested_context=context,
            requested_description=description,
            requested_target_url=target_url,
            returned_status=returned,
        )

    def list_commit_statuses(
        self,
        repository: str,
        queried_sha: str,
        *,
        max_pages: int = 100,
    ) -> tuple[CommitStatus, ...]:
        _owner, _name, owner_path, name_path = _canonical_repository_parts(repository)
        sha = self._sha(queried_sha, "queried status SHA")
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise GitHubAPIError("status max_pages must be an integer from 1 through 100")
        statuses: list[CommitStatus] = []
        for page in range(1, max_pages + 1):
            url = (
                f"{REST_BASE_URL}/repos/{owner_path}/{name_path}/commits/{sha}/statuses"
                f"?per_page=100&page={page}"
            )
            value = self._request("GET", url)
            if type(value) is not list:
                raise InvalidResponseError("commit status page must be a list")
            page_statuses = tuple(self._parse_commit_status(item) for item in value)
            if len(page_statuses) > 100:
                raise InvalidResponseError("commit status page exceeds 100 entries")
            statuses.extend(page_statuses)
            if len(page_statuses) < 100:
                return tuple(statuses)
        raise InvalidResponseError("commit status pagination exceeds configured page bound")

    @classmethod
    def _parse_tree_response(cls, tree_sha: str, value: Any) -> tuple[str, tuple[GitTreeEntry, ...]]:
        tree = cls._sha(tree_sha, "tree.sha")
        if type(value) is not dict or type(value.get("tree")) is not list or value.get("truncated") is not False:
            raise InvalidResponseError("Git tree response is truncated or malformed")
        if "sha" in value and value["sha"] != tree:
            raise InvalidResponseError("Git tree response identity does not match requested tree")
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
            entries.append(GitTreeEntry(path, mode, object_type, cls._sha(item.get("sha"), "tree.entry.sha")))
        if len(entries) > 100_000 or len({item.path for item in entries}) != len(entries):
            raise InvalidResponseError("Git tree entry count or identity is invalid")
        return tree, tuple(sorted(entries, key=lambda item: item.path.encode("utf-8")))

    def get_tree(self, repository: str, tree_sha: str) -> tuple[str, tuple[GitTreeEntry, ...]]:
        owner, name = self._owner_repo(repository)
        tree = self._sha(tree_sha, "tree.sha")
        url = f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/trees/{urlparse.quote(tree)}?recursive=1"
        return self._parse_tree_response(tree, self._request("GET", url))

    def get_commit_tree(self, repository: str, commit_sha: str) -> tuple[str, tuple[GitTreeEntry, ...]]:
        metadata = self.get_commit_metadata(repository, commit_sha)
        tree_sha, entries = self.get_tree(repository, metadata.tree_sha)
        if tree_sha != metadata.tree_sha:
            raise InvalidResponseError("Git tree response identity does not match commit metadata")
        return tree_sha, entries

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
        data = self.read_optional_commit_file(repository, commit_sha, path, expected_mode=expected_mode)
        if data is None:
            raise InvalidResponseError("requested committed file is missing or ambiguous")
        return data

    def read_optional_commit_file(self, repository: str, commit_sha: str, path: str, *, expected_mode: str | None = None) -> bytes | None:
        _validate_tree_path(path)
        _tree_sha, entries = self.get_commit_tree(repository, commit_sha)
        matches = [item for item in entries if item.path == path]
        if not matches:
            return None
        if len(matches) != 1:
            raise InvalidResponseError("requested committed file is ambiguous")
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

    @staticmethod
    def _parse_pull_request_routing(data: Mapping[str, Any], repository: str, number: int) -> _PullRequestRoutingSnapshot:
        if set(data) != {"repository"} or type(data["repository"]) is not dict:
            raise InvalidResponseError("pull request routing response has invalid repository shape")
        repo = data["repository"]
        if _bounded_text(repo.get("nameWithOwner"), "repository.nameWithOwner") != repository:
            raise InvalidResponseError("pull request routing repository does not match requested repository")
        pull = repo.get("pullRequest")
        if type(pull) is not dict:
            raise InvalidResponseError("pull request routing metadata is missing")
        if type(pull.get("number")) is not int or type(pull.get("number")) is bool or pull["number"] != number:
            raise InvalidResponseError("pull request routing number does not match requested number")
        if type(pull.get("includesCreatedEdit")) is not bool:
            raise InvalidResponseError("PR.includesCreatedEdit must be boolean")
        if type(pull.get("isDraft")) is not bool:
            raise InvalidResponseError("PR.isDraft must be boolean")
        return _PullRequestRoutingSnapshot(
            number,
            GitHubClient._sha(pull.get("headRefOid"), "PR.headRefOid"),
            GitHubClient._sha(pull.get("baseRefOid"), "PR.baseRefOid"),
            _bounded_text(pull.get("headRefName"), "PR.headRefName"),
            _bounded_text(pull.get("baseRefName"), "PR.baseRefName"),
            pull["isDraft"],
            _optional_iso(pull.get("lastEditedAt"), "PR.lastEditedAt"),
            pull["includesCreatedEdit"],
        )

    @staticmethod
    def _body_text(value: Any, label: str) -> str:
        if type(value) is not str:
            raise InvalidResponseError(f"{label} must be a string")
        try:
            if len(value.encode("utf-8")) > 16_384:
                raise InvalidResponseError(f"{label} exceeds 16KiB")
        except UnicodeEncodeError:
            raise InvalidResponseError(f"{label} is not valid UTF-8") from None
        return value

    @staticmethod
    def _issue_comment_body_text(value: Any, label: str) -> str:
        if type(value) is not str:
            raise InvalidResponseError(f"{label} must be a string")
        try:
            if len(value.encode("utf-8")) > MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES:
                raise InvalidResponseError(f"{label} exceeds the Issue comment bound")
        except UnicodeEncodeError:
            raise InvalidResponseError(f"{label} is not valid UTF-8") from None
        return value

    @classmethod
    def _parse_pull_request_rest_detail(cls, value: Any, number: int) -> _PullRequestRESTDetail:
        if type(value) is not dict:
            raise InvalidResponseError("pull request REST response must be an object")
        if type(value.get("number")) is not int or type(value.get("number")) is bool or value["number"] != number:
            raise InvalidResponseError("pull request REST number does not match requested number")
        if "body" not in value:
            raise InvalidResponseError("pull request REST body is missing")
        body_value = value["body"]
        body = None if body_value is None else cls._body_text(body_value, "pull request REST body")
        if type(value.get("user")) is not dict or type(value.get("head")) is not dict or type(value.get("base")) is not dict:
            raise InvalidResponseError("pull request REST identity metadata is incomplete")
        if type(value.get("draft")) is not bool:
            raise InvalidResponseError("pull request REST draft must be boolean")
        user = value["user"]
        head = value["head"]
        base = value["base"]
        if type(head.get("repo")) is not dict or type(base.get("repo")) is not dict:
            raise InvalidResponseError("pull request REST repository metadata is incomplete")
        head_repo = head["repo"]
        base_repo = base["repo"]
        return _PullRequestRESTDetail(
            number,
            body,
            _bounded_text(user.get("node_id"), "PR.author.node_id"),
            _bounded_text(user.get("login"), "PR.author.login"),
            cls._sha(head.get("sha"), "PR.head.sha"),
            cls._sha(base.get("sha"), "PR.base.sha"),
            _bounded_text(head.get("ref"), "PR.head.ref"),
            _bounded_text(base.get("ref"), "PR.base.ref"),
            value["draft"],
            _bounded_text(head_repo.get("node_id"), "PR.head.repo.node_id"),
            _bounded_text(head_repo.get("full_name"), "PR.head.repo.full_name"),
            _bounded_text(base_repo.get("node_id"), "PR.base.repo.node_id"),
            _bounded_text(base_repo.get("full_name"), "PR.base.repo.full_name"),
        )

    @staticmethod
    def _parse_pull_request_body_fallback(data: Mapping[str, Any], repository: str, number: int) -> str:
        if set(data) != {"repository"} or type(data["repository"]) is not dict:
            raise InvalidResponseError("pull request body fallback has invalid repository shape")
        repo = data["repository"]
        if _bounded_text(repo.get("nameWithOwner"), "repository.nameWithOwner") != repository:
            raise InvalidResponseError("pull request body fallback repository does not match requested repository")
        pull = repo.get("pullRequest")
        if type(pull) is not dict or type(pull.get("number")) is not int or type(pull.get("number")) is bool or pull["number"] != number:
            raise InvalidResponseError("pull request body fallback number does not match requested number")
        return GitHubClient._body_text(pull.get("body"), "pull request body fallback")

    def get_pull_request_metadata(self, repository: str, number: int) -> PullRequestMetadata:
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("pull request number must be positive")
        variables = {"owner": owner, "name": name, "number": number}
        before = self._parse_pull_request_routing(
            self._graphql(PULL_REQUEST_ROUTING_BEFORE_QUERY, variables, operation="pullRoutingBefore"), repository, number
        )
        rest = self._parse_pull_request_rest_detail(self.request_json("GET", ["repos", owner, name, "pulls", str(number)]), number)
        body = rest.body
        if body is None:
            body = self._parse_pull_request_body_fallback(
                self._graphql(PULL_REQUEST_BODY_FALLBACK_QUERY, variables, operation="pullBodyFallback"), repository, number
            )
        after = self._parse_pull_request_routing(
            self._graphql(PULL_REQUEST_ROUTING_AFTER_QUERY, variables, operation="pullRoutingAfter"), repository, number
        )
        if before != after:
            raise InvalidResponseError("pull request routing authority changed during composite read")
        if (rest.number, rest.head_oid, rest.base_oid, rest.head_ref, rest.base_ref) != (
            before.number,
            before.head_oid,
            before.base_oid,
            before.head_ref,
            before.base_ref,
        ):
            raise InvalidResponseError("pull request REST topology does not match routing authority")
        if rest.draft != before.draft:
            raise InvalidResponseError("pull request REST draft does not match routing authority")
        return PullRequestMetadata(
            before.number,
            body,
            rest.author_id,
            rest.author_login,
            before.head_oid,
            before.base_oid,
            before.head_ref,
            before.base_ref,
            rest.head_repository_id,
            rest.head_repository,
            rest.base_repository_id,
            rest.base_repository,
            before.last_edited_at,
            before.includes_created_edit,
            before.draft,
        )

    def get_merged_pull_request_metadata(self, repository: str, number: int) -> MergedPullRequestMetadata:
        """Read one exact PR merge/topology snapshot using a fixed read-only query."""
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("pull request number must be positive")
        data = self._graphql(
            MERGED_PULL_REQUEST_QUERY,
            {"owner": owner, "name": name, "number": number},
            operation="mergedPullRequest",
        )
        if type(data) is not dict or set(data) != {"repository"} or type(data.get("repository")) is not dict:
            raise InvalidResponseError("merged PR response has invalid exact top-level shape")
        repo = data["repository"]
        if set(repo) != {"id", "databaseId", "nameWithOwner", "pullRequest"}:
            raise InvalidResponseError("merged PR repository response has invalid exact shape")
        repo_full_name = _bounded_text(repo.get("nameWithOwner"), "repository.nameWithOwner", 512)
        repo_node_id = _bounded_text(repo.get("id"), "repository.id", 256)
        repo_database_id = _positive_id(repo.get("databaseId"), "repository.databaseId")
        pull = repo.get("pullRequest")
        expected_pull_keys = {
            "id", "databaseId", "number", "state", "isDraft", "merged", "mergedAt", "mergeCommit",
            "headRefOid", "baseRefOid", "headRefName", "baseRefName", "headRepository", "baseRepository",
        }
        if type(pull) is not dict or set(pull) != expected_pull_keys:
            raise InvalidResponseError("merged PR response has invalid exact pull request shape")
        returned_number = pull.get("number")
        if type(returned_number) is not int or type(returned_number) is bool or returned_number != number:
            raise InvalidResponseError("merged PR number does not match requested number")
        state = pull.get("state")
        if type(state) is not str or state not in {"OPEN", "CLOSED"}:
            raise InvalidResponseError("merged PR state is invalid")
        is_draft, merged = pull.get("isDraft"), pull.get("merged")
        if type(is_draft) is not bool or type(merged) is not bool:
            raise InvalidResponseError("merged PR draft/merged fields must be exact booleans")
        merged_at = pull.get("mergedAt")
        if merged_at is not None:
            merged_at = _canonical_utc_timestamp(merged_at, "pullRequest.mergedAt")
        merge_commit = pull.get("mergeCommit")
        if merge_commit is None:
            merge_commit_oid = None
        elif type(merge_commit) is dict and set(merge_commit) == {"oid"}:
            merge_commit_oid = self._sha(merge_commit.get("oid"), "pullRequest.mergeCommit.oid")
        else:
            raise InvalidResponseError("merged PR mergeCommit is malformed")

        def repository_identity(raw: Any, label: str) -> tuple[str, int, str]:
            if type(raw) is not dict or set(raw) != {"id", "databaseId", "nameWithOwner"}:
                raise InvalidResponseError(f"{label} repository identity is malformed")
            return (
                _bounded_text(raw.get("id"), f"{label}.id", 256),
                _positive_id(raw.get("databaseId"), f"{label}.databaseId"),
                _bounded_text(raw.get("nameWithOwner"), f"{label}.nameWithOwner", 512),
            )

        head_repo = repository_identity(pull.get("headRepository"), "headRepository")
        base_repo = repository_identity(pull.get("baseRepository"), "baseRepository")
        return MergedPullRequestMetadata(
            repo_full_name, repo_node_id, repo_database_id,
            _bounded_text(pull.get("id"), "pullRequest.id", 256),
            _positive_id(pull.get("databaseId"), "pullRequest.databaseId"),
            returned_number, state, is_draft, merged, merged_at, merge_commit_oid,
            self._sha(pull.get("headRefOid"), "pullRequest.headRefOid"),
            self._sha(pull.get("baseRefOid"), "pullRequest.baseRefOid"),
            _bounded_text(pull.get("headRefName"), "pullRequest.headRefName", 256),
            _bounded_text(pull.get("baseRefName"), "pullRequest.baseRefName", 256),
            *head_repo, *base_repo,
        )

    def compare_commits(self, repository: str, base_sha: str, head_sha: str) -> tuple[str, str, str]:
        """Return strict (status, base SHA, merge-base SHA) for bounded ancestry proof."""
        owner, name = self._owner_repo(repository)
        base, head = self._sha(base_sha, "compare base SHA"), self._sha(head_sha, "compare head SHA")
        url = (
            f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}"
            f"/compare/{base}...{head}"
        )
        value = self._request("GET", url)
        if type(value) is not dict or type(value.get("base_commit")) is not dict or type(value.get("merge_base_commit")) is not dict:
            raise InvalidResponseError("commit compare response is malformed")
        returned_base = self._sha(value["base_commit"].get("sha"), "compare.base_commit.sha")
        raw_commits = value.get("commits")
        if type(raw_commits) is not list or any(type(item) is not dict for item in raw_commits):
            raise InvalidResponseError("commit compare commits list is malformed")
        merge_base = self._sha(value["merge_base_commit"].get("sha"), "compare.merge_base_commit.sha")
        status = value.get("status")
        if type(status) is not str or status not in {"identical", "ahead", "behind", "diverged"}:
            raise InvalidResponseError("commit compare status is invalid")
        if returned_base != base:
            raise InvalidResponseError("commit compare response base identity differs from request")
        returned_head = base if not raw_commits else self._sha(raw_commits[-1].get("sha"), "compare.head SHA")
        if status == "identical":
            coherent = head == base and not raw_commits and merge_base == base
        elif status == "ahead":
            coherent = returned_head == head and merge_base == base
        elif status == "behind":
            coherent = not raw_commits and merge_base == head
        else:
            coherent = returned_head == head and merge_base not in {base, head}
        if not coherent:
            raise InvalidResponseError("commit compare response status, head, and merge base are inconsistent")
        return status, returned_base, merge_base

    def reopen_pull_request(self, pull_request_node_id: str, client_mutation_id: str) -> PullRequestStageMutationReceipt:
        return self._pull_request_stage_mutation("REOPEN", pull_request_node_id, client_mutation_id)

    def mark_pull_request_ready_for_review(self, pull_request_node_id: str, client_mutation_id: str) -> PullRequestStageMutationReceipt:
        return self._pull_request_stage_mutation("READY_FOR_REVIEW", pull_request_node_id, client_mutation_id)

    def convert_pull_request_to_draft(self, pull_request_node_id: str, client_mutation_id: str) -> PullRequestStageMutationReceipt:
        return self._pull_request_stage_mutation("CONVERT_TO_DRAFT", pull_request_node_id, client_mutation_id)

    def close_pull_request(self, pull_request_node_id: str, client_mutation_id: str) -> PullRequestStageMutationReceipt:
        return self._pull_request_stage_mutation("CLOSE", pull_request_node_id, client_mutation_id)

    @staticmethod
    def _parse_issue_routing(data: Mapping[str, Any], repository: str, number: int) -> _IssueRoutingSnapshot:
        if type(data) is not dict or set(data) != {"repository"} or type(data.get("repository")) is not dict:
            raise InvalidResponseError("Issue routing response has invalid repository shape")
        repo = data["repository"]
        if _bounded_text(repo.get("nameWithOwner"), "repository.nameWithOwner") != repository:
            raise InvalidResponseError("Issue routing repository does not match requested repository")
        item = repo.get("issueOrPullRequest")
        if type(item) is not dict:
            raise InvalidResponseError("Issue routing union member is missing or null")
        typename = item.get("__typename")
        if type(typename) is not str or typename not in {"Issue", "PullRequest"}:
            raise InvalidResponseError("Issue routing union member type is unknown")
        expected_fields = {"__typename", "id", "number", "lastEditedAt", "includesCreatedEdit", "closed"}
        if set(item) != expected_fields:
            raise InvalidResponseError("Issue routing union member has invalid exact fields")
        returned_number = item.get("number")
        if type(returned_number) is not int or type(returned_number) is bool or returned_number != number:
            raise InvalidResponseError("Issue routing number does not match requested number")
        includes_created_edit = item.get("includesCreatedEdit")
        closed = item.get("closed")
        last_edited_at = item.get("lastEditedAt")
        if type(includes_created_edit) is not bool:
            raise InvalidResponseError("Issue.includesCreatedEdit must be boolean")
        if type(closed) is not bool:
            raise InvalidResponseError("Issue.closed must be boolean")
        if last_edited_at is not None:
            _parse_github_timestamp(last_edited_at, "Issue.lastEditedAt")
        return _IssueRoutingSnapshot(
            typename,
            _bounded_text(item.get("id"), "Issue.node_id"),
            returned_number,
            last_edited_at,
            includes_created_edit,
            closed,
        )

    @classmethod
    def _parse_issue_rest_detail(cls, value: Any, number: int) -> _IssueRESTDetail:
        if type(value) is not dict:
            raise InvalidResponseError("Issue REST response must be an object")
        returned_number = value.get("number")
        if type(returned_number) is not int or type(returned_number) is bool or returned_number != number:
            raise InvalidResponseError("Issue REST number does not match requested number")
        body = cls._body_text(value.get("body"), "Issue REST body")
        state = value.get("state")
        if type(state) is not str or state not in {"open", "closed"}:
            raise InvalidResponseError("Issue REST state must be exactly open or closed")
        user = value.get("user")
        if type(user) is not dict:
            raise InvalidResponseError("Issue REST author metadata is missing or malformed")
        if "pull_request" in value and type(value["pull_request"]) is not dict:
            raise InvalidResponseError("Issue REST pull_request discriminator is malformed")
        return _IssueRESTDetail(
            returned_number,
            _positive_id(value.get("id"), "Issue.id"),
            _bounded_text(value.get("node_id"), "Issue.node_id"),
            body,
            state,
            _bounded_text(user.get("node_id"), "Issue.author.node_id"),
            _bounded_text(user.get("login"), "Issue.author.login"),
            "pull_request" in value,
        )

    def get_issue_metadata(self, repository: str, number: int) -> IssueMetadata:
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("Issue number must be positive")
        variables = {"owner": owner, "name": name, "number": number}
        before = self._parse_issue_routing(
            self._graphql(ISSUE_ROUTING_BEFORE_QUERY, variables, operation="issueRoutingBefore"),
            repository,
            number,
        )
        rest = self._parse_issue_rest_detail(
            self.request_json("GET", ["repos", owner, name, "issues", str(number)]),
            number,
        )
        after = self._parse_issue_routing(
            self._graphql(ISSUE_ROUTING_AFTER_QUERY, variables, operation="issueRoutingAfter"),
            repository,
            number,
        )
        if before != after:
            raise InvalidResponseError("Issue routing authority changed during composite read")
        if (rest.number, rest.node_id, rest.is_pull_request) != (
            before.number,
            before.node_id,
            before.is_pull_request,
        ):
            raise InvalidResponseError("Issue REST identity/type does not match routing authority")
        if (rest.state == "closed") != before.closed:
            raise InvalidResponseError("Issue REST lifecycle state does not match routing authority")
        return IssueMetadata(
            rest.number,
            rest.database_id,
            rest.node_id,
            rest.body,
            rest.state,
            rest.author_id,
            rest.author_login,
            before.last_edited_at,
            before.includes_created_edit,
            before.is_pull_request,
        )

    @classmethod
    def _parse_issue_comment_rest_record(cls, value: Any, issue_url: str) -> _IssueCommentRESTRecord:
        if type(value) is not dict:
            raise InvalidResponseError("issue comment REST record must be an object")
        database_id = _positive_id(value.get("id"), "comment.id")
        node_id = _bounded_text(value.get("node_id"), "comment.node_id")
        body = cls._issue_comment_body_text(value.get("body"), "comment.body")
        created_at = _bounded_text(value.get("created_at"), "comment.created_at", 128)
        updated_at = _bounded_text(value.get("updated_at"), "comment.updated_at", 128)
        created_instant = _parse_github_timestamp(created_at, "comment.created_at")
        updated_instant = _parse_github_timestamp(updated_at, "comment.updated_at")
        if updated_instant < created_instant:
            raise InvalidResponseError("comment.updated_at is earlier than comment.created_at")

        user = value.get("user")
        if user is None:
            author_id = author_login = author_type = None
        else:
            if type(user) is not dict:
                raise InvalidResponseError("comment.user must be null or an object")
            author_id = _bounded_text(user.get("node_id"), "comment.author.node_id")
            author_login = _bounded_text(user.get("login"), "comment.author.login")
            author_type = _bounded_text(user.get("type"), "comment.author.type")

        returned_issue_url = _bounded_text(value.get("issue_url"), "comment.issue_url", 2_048)
        if returned_issue_url != issue_url:
            raise InvalidResponseError("comment.issue_url does not match the requested issue")
        return _IssueCommentRESTRecord(
            database_id,
            node_id,
            body,
            author_id,
            author_login,
            author_type,
            created_at,
            updated_at,
            returned_issue_url,
        )

    @classmethod
    def _validate_comment_bounds(cls, max_pages: int, max_records: int) -> tuple[int, int]:
        if type(max_pages) is not int or max_pages <= 0 or max_pages > 100:
            raise GitHubAPIError("comment max_pages must be a positive integer no greater than 100")
        if type(max_records) is not int or max_records <= 0 or max_records > 10_000:
            raise GitHubAPIError("comment max_records must be a positive integer no greater than 10000")
        return max_pages, max_records

    def _read_issue_comment_rest_snapshot(self, owner: str, name: str, number: int, max_pages: int, max_records: int) -> tuple[_IssueCommentRESTRecord, ...]:
        issue_url = f"{REST_BASE_URL}/repos/{owner}/{name}/issues/{number}"
        records: list[_IssueCommentRESTRecord] = []
        seen_database_ids: set[int] = set()
        seen_node_ids: set[str] = set()
        previous_database_id: int | None = None

        for page in range(1, max_pages + 1):
            url = f"{REST_BASE_URL}/repos/{owner}/{name}/issues/{number}/comments?per_page=100&page={page}"
            value = self._request("GET", url)
            if type(value) is not list:
                raise InvalidResponseError("issue comment REST page must be a list")
            if len(value) > 100:
                raise InvalidResponseError("issue comment REST page exceeds 100 records")
            for raw_record in value:
                record = self._parse_issue_comment_rest_record(raw_record, issue_url)
                if previous_database_id is not None and record.database_id <= previous_database_id:
                    raise InvalidResponseError("issue comment REST database IDs are not strictly increasing")
                if record.database_id in seen_database_ids:
                    raise InvalidResponseError("issue comment REST database ID is duplicated")
                if record.node_id in seen_node_ids:
                    raise InvalidResponseError("issue comment REST node ID is duplicated")
                records.append(record)
                seen_database_ids.add(record.database_id)
                seen_node_ids.add(record.node_id)
                previous_database_id = record.database_id
                if len(records) > max_records:
                    raise InvalidResponseError("issue comment REST snapshot exceeds configured record bound")

            if len(value) < 100:
                return tuple(records)
            if len(records) >= max_records:
                if page == 100 and max_pages == 100 and max_records == 10_000 and len(records) == 10_000:
                    sentinel_url = f"{REST_BASE_URL}/repos/{owner}/{name}/issues/{number}/comments?per_page=100&page=101"
                    sentinel = self._request("GET", sentinel_url)
                    if type(sentinel) is not list or sentinel:
                        raise InvalidResponseError("issue comment REST page 101 must be an empty sentinel")
                    return tuple(records)
                raise InvalidResponseError("full issue comment REST page exhausted configured bound")
            if page == max_pages:
                raise InvalidResponseError("issue comment REST pagination exceeds configured page bound")
        raise InvalidResponseError("issue comment REST pagination exceeds configured page bound")

    @staticmethod
    def _parse_issue_comment_graphql_actor(value: Any, label: str) -> tuple[str, str, str]:
        if type(value) is not dict:
            raise InvalidResponseError(f"{label} must be an object")
        return (
            _bounded_text(value.get("id"), f"{label}.id"),
            _bounded_text(value.get("login"), f"{label}.login"),
            _bounded_text(value.get("__typename"), f"{label}.__typename"),
        )

    @staticmethod
    def _validate_issue_comment_author_parity(
        rest_author_id: str,
        rest_author_login: str,
        rest_author_type: str,
        graphql_author_id: str,
        graphql_author_login: str,
        graphql_author_type: str,
    ) -> None:
        if graphql_author_id != rest_author_id:
            raise InvalidResponseError("comment author does not match REST")
        if graphql_author_type != rest_author_type:
            raise InvalidResponseError("comment author does not match REST")
        if rest_author_type != "Bot":
            if graphql_author_login != rest_author_login:
                raise InvalidResponseError("comment author does not match REST")
            return
        suffix = "[bot]"
        if not rest_author_login.endswith(suffix):
            raise InvalidResponseError("comment author does not match REST")
        bare_login = rest_author_login[:-len(suffix)]
        if not bare_login or bare_login.endswith(suffix):
            raise InvalidResponseError("comment author does not match REST")
        if graphql_author_login not in {rest_author_login, bare_login}:
            raise InvalidResponseError("comment author does not match REST")

    @classmethod
    def _parse_issue_comment_graphql_node(cls, value: Any, rest: _IssueCommentRESTRecord) -> IssueComment:
        if type(value) is not dict:
            raise InvalidResponseError("issue comment GraphQL node must be an object")
        if value.get("__typename") != "IssueComment":
            raise InvalidResponseError("issue comment GraphQL node has the wrong type")
        node_id = _bounded_text(value.get("id"), "comment.node_id")
        if node_id != rest.node_id:
            raise InvalidResponseError("comment GraphQL node ID does not match REST")

        full_database_id = value.get("fullDatabaseId")
        if type(full_database_id) is not str or not re.fullmatch(r"[0-9]{1,19}", full_database_id):
            raise InvalidResponseError("comment.fullDatabaseId must be strict bounded decimal text")
        try:
            database_id = _positive_id(int(full_database_id), "comment.fullDatabaseId")
        except (ValueError, TypeError):
            raise InvalidResponseError("comment.fullDatabaseId is invalid") from None
        if database_id != rest.database_id:
            raise InvalidResponseError("comment GraphQL database ID does not match REST")

        body = cls._issue_comment_body_text(value.get("body"), "comment.body")
        if body != rest.body:
            raise InvalidResponseError("comment body does not match REST")
        created_at = _bounded_text(value.get("createdAt"), "comment.createdAt", 128)
        updated_at = _bounded_text(value.get("updatedAt"), "comment.updatedAt", 128)
        if _parse_github_timestamp(created_at, "comment.createdAt") != _parse_github_timestamp(rest.created_at, "comment.created_at"):
            raise InvalidResponseError("comment created timestamp does not match REST")
        if _parse_github_timestamp(updated_at, "comment.updatedAt") != _parse_github_timestamp(rest.updated_at, "comment.updated_at"):
            raise InvalidResponseError("comment updated timestamp does not match REST")

        author = value.get("author")
        if rest.author_id is None:
            if author is not None:
                raise InvalidResponseError("comment GraphQL author is present but REST author is null")
        else:
            author_id, author_login, author_type = cls._parse_issue_comment_graphql_actor(author, "comment.author")
            cls._validate_issue_comment_author_parity(
                rest.author_id,
                rest.author_login,
                rest.author_type,
                author_id,
                author_login,
                author_type,
            )

        editor = value.get("editor")
        if editor is None:
            editor_id = editor_login = editor_type = None
        else:
            editor_id, editor_login, editor_type = cls._parse_issue_comment_graphql_actor(editor, "comment.editor")

        last_edited_at = value.get("lastEditedAt")
        if last_edited_at is not None:
            last_edited_at = _bounded_text(last_edited_at, "comment.lastEditedAt", 128)
            _parse_github_timestamp(last_edited_at, "comment.lastEditedAt")
        includes_created_edit = value.get("includesCreatedEdit")
        if type(includes_created_edit) is not bool:
            raise InvalidResponseError("comment.includesCreatedEdit must be boolean")
        history = value.get("userContentEdits")
        if type(history) is not dict:
            raise InvalidResponseError("comment.userContentEdits must be an object")
        total_count = history.get("totalCount")
        if type(total_count) is not int or type(total_count) is bool or total_count < 0:
            raise InvalidResponseError("comment.userContentEdits.totalCount is invalid")
        if total_count == 0:
            if last_edited_at is not None or editor is not None or includes_created_edit:
                raise InvalidResponseError("comment history is inconsistent with a clean comment")
        elif last_edited_at is None:
            raise InvalidResponseError("edited comment is missing lastEditedAt")

        return IssueComment(
            rest.node_id,
            rest.database_id,
            rest.body,
            rest.author_id,
            rest.author_login,
            rest.author_type,
            editor_id,
            editor_login,
            editor_type,
            last_edited_at,
            includes_created_edit,
        )

    def _enrich_issue_comment_snapshot(self, records: tuple[_IssueCommentRESTRecord, ...]) -> tuple[IssueComment, ...]:
        enriched: dict[str, IssueComment] = {}
        for offset in range(0, len(records), 100):
            batch = records[offset:offset + 100]
            requested_ids = [record.node_id for record in batch]
            data = self._graphql(ISSUE_COMMENT_NODES_QUERY, {"ids": requested_ids}, operation="issueCommentNodes")
            if set(data) != {"nodes"} or type(data["nodes"]) is not list:
                raise InvalidResponseError("issue comment GraphQL nodes response has invalid shape")
            nodes = data["nodes"]
            if len(nodes) != len(requested_ids):
                raise InvalidResponseError("issue comment GraphQL node count does not match the request")
            requested_set = set(requested_ids)
            returned: dict[str, Any] = {}
            for node in nodes:
                if type(node) is not dict:
                    raise InvalidResponseError("issue comment GraphQL node must not be null or non-object")
                returned_id = _bounded_text(node.get("id"), "comment.node_id")
                if returned_id not in requested_set:
                    raise InvalidResponseError("issue comment GraphQL node was not requested")
                if returned_id in returned:
                    raise InvalidResponseError("issue comment GraphQL node ID is duplicated")
                returned[returned_id] = node
            if set(returned) != requested_set:
                raise InvalidResponseError("issue comment GraphQL node IDs do not match the request")
            for record in batch:
                enriched[record.node_id] = self._parse_issue_comment_graphql_node(returned[record.node_id], record)
        return tuple(enriched[record.node_id] for record in records)

    def _list_issue_comments_composite(self, owner: str, name: str, number: int, max_pages: int, max_records: int) -> tuple[IssueComment, ...]:
        rest_a = self._read_issue_comment_rest_snapshot(owner, name, number, max_pages, max_records)
        if not rest_a:
            rest_b = self._read_issue_comment_rest_snapshot(owner, name, number, max_pages, max_records)
            if rest_a != rest_b:
                raise InvalidResponseError(_ISSUE_COMMENT_COMPOSITE_RACE)
            return ()
        enriched = self._enrich_issue_comment_snapshot(rest_a)
        rest_b = self._read_issue_comment_rest_snapshot(owner, name, number, max_pages, max_records)
        if rest_a != rest_b:
            raise InvalidResponseError(_ISSUE_COMMENT_COMPOSITE_RACE)
        return enriched

    def list_issue_comments(self, repository: str, number: int, *, max_pages: int = 100, max_records: int = 10_000) -> tuple[IssueComment, ...]:
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("issue number must be positive")
        max_pages, max_records = self._validate_comment_bounds(max_pages, max_records)
        for attempt in range(_ISSUE_COMMENT_COMPOSITE_MAX_ATTEMPTS):
            try:
                return self._list_issue_comments_composite(owner, name, number, max_pages, max_records)
            except InvalidResponseError as error:
                if str(error) != _ISSUE_COMMENT_COMPOSITE_RACE or attempt == _ISSUE_COMMENT_COMPOSITE_MAX_ATTEMPTS - 1:
                    raise
        raise InvalidResponseError(_ISSUE_COMMENT_COMPOSITE_RACE)

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

    def create_issue_patch_projection_comment(self, repository: str, number: int, body: str) -> IssueComment:
        """Create an exact canonical machine projection with its dedicated wider bound."""
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("issue number must be positive")
        if type(body) is not str or not body:
            raise GitHubAPIError("IssuePatchProjection body must be nonempty text")
        try:
            body_bytes = body.encode("utf-8")
        except UnicodeEncodeError:
            raise GitHubAPIError("IssuePatchProjection body is not valid UTF-8") from None
        if len(body_bytes) > MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES:
            raise GitHubAPIError("IssuePatchProjection body exceeds the bound")
        try:
            projection = parse_issue_patch_projection(body)
        except RequestModelError as error:
            raise GitHubAPIError("IssuePatchProjection body is not canonical") from error
        value = self.request_json(
            "POST",
            ["repos", owner, name, "issues", str(number), "comments"],
            {"body": body},
        )
        if type(value) is not dict:
            raise InvalidResponseError("created projection comment must be an object")
        returned_body = self._issue_comment_body_text(value.get("body"), "created projection comment.body")
        if returned_body != body:
            raise InvalidResponseError("created projection comment body differs from the exact canonical payload")
        return IssueComment(
            _bounded_text(value.get("node_id"), "created projection comment.node_id"),
            _positive_id(value.get("id"), "created projection comment.id"),
            returned_body,
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

    def get_optional_ref_oid(self, repository: str, branch: str) -> str | None:
        try:
            return self.get_ref_oid(repository, branch)
        except NotFoundError:
            return None

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

    def create_commit(self, repository: str, message: str, tree: str, parents: Iterable[str], *, timestamp: str | None = None) -> GitObject:
        owner, name = self._owner_repo(repository)
        if type(message) is not str or not message or len(message.encode("utf-8")) > 16_384:
            raise GitHubAPIError("commit message is invalid")
        tree_sha = self._sha(tree, "commit tree")
        parent_list = list(parents)
        if any(type(parent) is not str or not _SHA40_RE.fullmatch(parent) for parent in parent_list):
            raise GitHubAPIError("commit parents are invalid")
        if timestamp is None:
            raise GitHubAPIError("commit timestamp is required")
        if type(timestamp) is not str or not timestamp.endswith("Z") or "T" not in timestamp:
            raise GitHubAPIError("commit timestamp must be UTC ISO-8601 ending in Z")
        author_instant = _parse_github_timestamp(timestamp, "commit.timestamp")
        git_timestamp = f"{int(author_instant.timestamp())} +0000"
        iso_date = author_instant.strftime("%Y-%m-%dT%H:%M:%SZ")
        author = {"name": "Swift Stream Federation", "email": "automation@swiftstream.invalid", "date": iso_date}
        committer = dict(author)
        payload = {"message": message, "tree": tree_sha, "parents": parent_list, "author": author, "committer": committer}
        value = self.request_json("POST", ["repos", owner, name, "git", "commits"], payload)
        if type(value) is not dict:
            raise InvalidResponseError("Git commit response is malformed")
        returned_sha = self._sha(value.get("sha"), "commit.sha")
        # GitHub's commit API accepts author/committer metadata.  Recompute the
        # Git object identity locally so a server rewrite cannot silently break
        # deterministic regeneration or cause a ref-CAS convergence loop.
        commit_body = (
            f"tree {tree_sha}\n"
            + "".join(f"parent {parent}\n" for parent in parent_list)
            + f"author Swift Stream Federation <automation@swiftstream.invalid> {git_timestamp}\n"
            + f"committer Swift Stream Federation <automation@swiftstream.invalid> {git_timestamp}\n\n"
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

    def bot_commit_timestamp_after(self, repository: str, parent_sha: str) -> str:
        """Deterministic bot timestamp: parent author date + 1s (stable per parent, never epoch-2000)."""
        parent = self.get_commit_metadata(repository, parent_sha)
        instant = _parse_github_timestamp(parent.author_date, "parent.author.date")
        return (instant + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

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
            title = output_value.get("title")
            summary = output_value.get("summary")
            text = output_value.get("text")
            if title is not None:
                _bounded_text(title, "check.output.title", 256)
            if summary is not None:
                _bounded_text(summary, "check.output.summary", 512)
            if text is not None:
                output_text = _bounded_text(text, "check.output.text", 4_096)
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

    @staticmethod
    def _workflow_path(value: Any) -> str:
        path = _bounded_text(value, "workflow path", 256)
        prefix = ".github/workflows/"
        if (
            not path.startswith(prefix)
            or path == prefix
            or "/" in path[len(prefix):]
            or "\\" in path
            or any(part in {"", ".", ".."} for part in path.split("/"))
        ):
            raise GitHubAPIError("workflow path must be an exact .github/workflows file")
        return path

    @classmethod
    def _parse_workflow_metadata(
        cls,
        value: Any,
        *,
        expected_path: str | None = None,
        expected_id: int | None = None,
    ) -> WorkflowMetadata:
        exact_keys = {
            "id", "node_id", "name", "path", "state",
            "created_at", "updated_at", "url", "html_url", "badge_url",
        }
        if type(value) is not dict or set(value) != exact_keys:
            raise InvalidResponseError("workflow metadata response has invalid exact shape")
        metadata = WorkflowMetadata(
            _positive_id(value["id"], "workflow.id"),
            _bounded_text(value["node_id"], "workflow.node_id", 256),
            _bounded_text(value["name"], "workflow.name", 256),
            _bounded_text(value["path"], "workflow.path", 256),
            _bounded_text(value["state"], "workflow.state", 64),
        )
        _parse_github_timestamp(value["created_at"], "workflow.created_at")
        _parse_github_timestamp(value["updated_at"], "workflow.updated_at")
        for key in ("url", "html_url", "badge_url"):
            _bounded_text(value[key], f"workflow.{key}", 2_048)
        if expected_path is not None and metadata.path != expected_path:
            raise InvalidResponseError("workflow metadata path does not match the exact requested path")
        if expected_id is not None and metadata.id != expected_id:
            raise InvalidResponseError("workflow metadata ID does not match the exact requested ID")
        return metadata

    def get_workflow_metadata_by_path(self, repository: str, workflow_path: str) -> WorkflowMetadata:
        owner, name = self._owner_repo(repository)
        path = self._workflow_path(workflow_path)
        filename = path.removeprefix(".github/workflows/")
        value = self.request_json(
            "GET",
            ["repos", owner, name, "actions", "workflows", filename],
        )
        return self._parse_workflow_metadata(value, expected_path=path)

    def get_workflow_metadata_by_id(self, repository: str, workflow_id: int) -> WorkflowMetadata:
        owner, name = self._owner_repo(repository)
        identifier = _positive_id(workflow_id, "workflow ID")
        value = self.request_json(
            "GET",
            ["repos", owner, name, "actions", "workflows", str(identifier)],
        )
        return self._parse_workflow_metadata(value, expected_id=identifier)

    @classmethod
    def _parse_workflow_run(cls, value: Any, *, expected_workflow_id: int) -> WorkflowRunMetadata:
        if type(value) is not dict:
            raise InvalidResponseError("workflow run must be an object")
        required = {
            "id", "run_attempt", "status", "conclusion",
            "workflow_id", "event", "head_branch", "head_sha",
        }
        if not required.issubset(value):
            raise InvalidResponseError("workflow run is missing required exact metadata")
        head_branch = value["head_branch"]
        if head_branch is not None:
            head_branch = _bounded_text(head_branch, "workflow_run.head_branch", 256)
        run = WorkflowRunMetadata(
            _positive_id(value["id"], "workflow_run.id"),
            _positive_id(value["run_attempt"], "workflow_run.run_attempt"),
            _bounded_text(value["status"], "workflow_run.status", 32),
            None if value["conclusion"] is None else _bounded_text(value["conclusion"], "workflow_run.conclusion", 64),
            _positive_id(value["workflow_id"], "workflow_run.workflow_id"),
            _bounded_text(value["event"], "workflow_run.event", 64),
            head_branch,
            cls._sha(value["head_sha"], "workflow_run.head_sha"),
        )
        if run.workflow_id != expected_workflow_id:
            raise InvalidResponseError("workflow run workflow_id does not match requested workflow")
        return run

    def list_workflow_runs(
        self,
        repository: str,
        workflow_id: int,
        *,
        max_pages: int = 100,
    ) -> tuple[WorkflowRunMetadata, ...]:
        owner, name = self._owner_repo(repository)
        identifier = _positive_id(workflow_id, "workflow ID")
        if type(max_pages) is not int or type(max_pages) is bool or not 1 <= max_pages <= 100:
            raise GitHubAPIError("workflow run max_pages must be an exact integer from 1 to 100")
        runs: list[WorkflowRunMetadata] = []
        seen_run_ids: set[int] = set()
        expected_total: int | None = None
        for page in range(1, max_pages + 1):
            value = self._request(
                "GET",
                f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/actions/workflows/{identifier}/runs?per_page=100&page={page}",
            )
            if type(value) is not dict or set(value) != {"total_count", "workflow_runs"}:
                raise InvalidResponseError("workflow run list response has invalid exact shape")
            total_count = value["total_count"]
            page_runs = value["workflow_runs"]
            if (
                type(total_count) is not int
                or type(total_count) is bool
                or not 0 <= total_count <= 9_223_372_036_854_775_807
                or type(page_runs) is not list
                or len(page_runs) > 100
            ):
                raise InvalidResponseError("workflow run list count/page is invalid")
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise InvalidResponseError("workflow run total_count changed during pagination")
            for raw in page_runs:
                run = self._parse_workflow_run(raw, expected_workflow_id=identifier)
                if run.id in seen_run_ids:
                    raise InvalidResponseError("workflow run ID is duplicated across pagination")
                seen_run_ids.add(run.id)
                runs.append(run)
            if len(runs) > total_count:
                raise InvalidResponseError("workflow run pages exceed declared total_count")
            if len(runs) == total_count:
                return tuple(runs)
            if len(page_runs) < 100:
                raise InvalidResponseError("workflow run pagination ended before declared total_count")
        raise InvalidResponseError("workflow run pagination exceeds configured page bound")

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

    def list_pull_requests(
        self, repository: str, *, state: str = "open", max_pages: int = 100,
    ) -> tuple[dict[str, Any], ...]:
        if type(state) is not str or state not in {"open", "closed", "all"}:
            raise GitHubAPIError("pull request state must be open, closed, or all")
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise GitHubAPIError("pull request max_pages must be an exact integer from 1 to 100")
        owner, name = self._owner_repo(repository)
        result: list[dict[str, Any]] = []
        seen_numbers: set[int] = set()
        for page in range(1, max_pages + 1):
            value = self._request(
                "GET",
                f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/pulls?state={state}&per_page=100&page={page}",
            )
            if type(value) is not list or len(value) > 100 or any(type(item) is not dict for item in value):
                raise InvalidResponseError("PR enumeration is malformed")
            for item in value:
                number = _positive_id(item.get("number"), "PR.number")
                if number in seen_numbers:
                    raise InvalidResponseError("PR enumeration contains duplicate numbers")
                seen_numbers.add(number)
            result.extend(value)
            if len(value) < 100:
                return tuple(sorted(result, key=lambda item: _positive_id(item.get("number"), "PR.number")))
        raise InvalidResponseError("PR enumeration reached bounded pagination exhaustion")

    def list_open_pull_requests(self, repository: str, *, max_pages: int = 100) -> tuple[dict[str, Any], ...]:
        return self.list_pull_requests(repository, state="open", max_pages=max_pages)

    def list_repository_issues(
        self, repository: str, *, state: str = "open", max_pages: int = 100,
    ) -> tuple[dict[str, int], ...]:
        """Enumerate bounded Issue-number discovery hints, excluding PR rows."""
        if type(state) is not str or state not in {"open", "closed", "all"}:
            raise GitHubAPIError("Issue state must be open, closed, or all")
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise GitHubAPIError("Issue max_pages must be an exact integer from 1 to 100")
        owner, name = self._owner_repo(repository)
        numbers: set[int] = set()
        for page in range(1, max_pages + 1):
            value = self._request(
                "GET",
                f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/issues?state={state}&per_page=100&page={page}",
            )
            if type(value) is not list or len(value) > 100 or any(type(item) is not dict for item in value):
                raise InvalidResponseError("Issue enumeration is malformed")
            for item in value:
                # GitHub's Issues endpoint deliberately includes pull requests.
                # Their number must not enter the Issue authority inventory.
                if "pull_request" in item:
                    continue
                number = _positive_id(item.get("number"), "Issue.number")
                if number in numbers:
                    raise InvalidResponseError("Issue enumeration contains duplicate Issue numbers")
                numbers.add(number)
            if len(value) < 100:
                return tuple({"number": number} for number in sorted(numbers))
        raise InvalidResponseError("Issue enumeration reached bounded pagination exhaustion")

    def list_machine_refs(self, repository: str, *, max_pages: int = 100) -> tuple[dict[str, str], ...]:
        """Enumerate canonical machine publication refs; namespace is discovery only."""
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise GitHubAPIError("machine-ref max_pages must be an exact integer from 1 to 100")
        owner, name = self._owner_repo(repository)
        prefix = "refs/heads/bot/federation/"
        refs: dict[str, dict[str, str]] = {}
        source_ids: set[str] = set()
        for page in range(1, max_pages + 1):
            value = self._request(
                "GET",
                f"{REST_BASE_URL}/repos/{urlparse.quote(owner)}/{urlparse.quote(name)}/git/matching-refs/heads/bot/federation?per_page=100&page={page}",
            )
            if type(value) is not list or len(value) > 100 or any(type(item) is not dict for item in value):
                raise InvalidResponseError("machine-ref enumeration is malformed")
            for item in value:
                ref = item.get("ref")
                if type(ref) is not str or not ref.startswith(prefix):
                    raise InvalidResponseError("machine-ref row has a malformed ref name")
                suffix = ref[len(prefix):]
                target = item.get("object")
                if type(target) is not dict:
                    raise InvalidResponseError("machine-ref target object is malformed")
                if "type" in target and target["type"] != "commit":
                    raise InvalidResponseError("machine-ref target is not a commit")
                sha = self._sha(target.get("sha"), "machine-ref object.sha")
                # Matching refs also returns nested Issue/request refs. Validate
                # their endpoint shape, then keep them outside this inventory.
                if not suffix or "/" in suffix:
                    continue
                try:
                    source_id = c02.validate_source_id(suffix)
                except c02.FederationError:
                    raise InvalidResponseError("machine-ref sourceId is not canonical") from None
                if ref in refs or source_id in source_ids:
                    raise InvalidResponseError("machine-ref enumeration contains duplicate ref/sourceId")
                refs[ref] = {"ref": ref, "source_id": source_id, "sha": sha}
                source_ids.add(source_id)
            if len(value) < 100:
                return tuple(refs[key] for key in sorted(refs, key=lambda ref: (refs[ref]["source_id"], ref)))
        raise InvalidResponseError("machine-ref enumeration reached bounded pagination exhaustion")

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

    def create_issue_pull_request(self, repository: str, *, head: str, base: str, title: str, body: str) -> int:
        """Create exactly one nondraft central PR for the reserved Issue branch."""
        owner, name = self._owner_repo(repository)
        if type(head) is not str or not head or ":" in head or head.startswith("refs/"):
            raise GitHubAPIError("Issue PR head must be a reserved short central branch")
        try:
            reserved_number = reserved_issue_branch_number(head)
        except RequestModelError:
            raise GitHubAPIError("Issue PR head must be an exact reserved Issue branch") from None
        if reserved_number is None:
            raise GitHubAPIError("Issue PR head must be an exact reserved Issue branch")
        try:
            validate_trusted_ref(f"refs/heads/{head}")
        except (c02.FederationError, WorkspaceError):
            raise GitHubAPIError("Issue PR head is not a valid trusted branch") from None
        if type(base) is not str or base != "main":
            raise GitHubAPIError("Issue PR base must be exact main")
        if type(title) is not str:
            raise GitHubAPIError("Issue PR title is invalid or exceeds its bound")
        try:
            title_bytes = title.encode("utf-8")
        except UnicodeEncodeError:
            raise GitHubAPIError("Issue PR title is invalid or exceeds its bound") from None
        if not title or len(title_bytes) > 256 or c02.contains_control(title):
            raise GitHubAPIError("Issue PR title is invalid or exceeds its bound")
        if type(body) is not str:
            raise GitHubAPIError("Issue PR body is invalid or exceeds its bound")
        try:
            body_bytes = body.encode("utf-8")
        except UnicodeEncodeError:
            raise GitHubAPIError("Issue PR body is invalid or exceeds its bound") from None
        if (
            not body or len(body_bytes) > 16_384
            or any((ord(character) < 0x20 and character != "\n") or ord(character) == 0x7F for character in body)
        ):
            raise GitHubAPIError("Issue PR body is invalid or exceeds its bound")
        value = self.request_json(
            "POST", ["repos", owner, name, "pulls"],
            {"title": title, "head": head, "base": base, "body": body, "draft": False},
        )
        if type(value) is not dict:
            raise InvalidResponseError("created Issue PR response is malformed")
        return _positive_id(value.get("number"), "created Issue PR.number")

    def update_pull_request_state(self, repository: str, number: int, *, state: str) -> None:
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0 or state not in {"open", "closed"}:
            raise GitHubAPIError("pull request state update is invalid")
        value = self.request_json("PATCH", ["repos", owner, name, "pulls", str(number)], {"state": state})
        if type(value) is not dict or type(value.get("number")) is not int or value["number"] != number:
            raise InvalidResponseError("updated pull request response is malformed")

    def update_pull_request_branch(self, repository: str, number: int, *, expected_head_sha: str) -> None:
        """Merge the current base into a PR head with GitHub's expected-head CAS."""
        owner, name = self._owner_repo(repository)
        if type(number) is not int or type(number) is bool or number <= 0:
            raise GitHubAPIError("pull request number must be positive")
        head = self._sha(expected_head_sha, "expected PR head SHA")
        value = self.request_json(
            "PUT",
            ["repos", owner, name, "pulls", str(number), "update-branch"],
            {"expected_head_sha": head},
        )
        if type(value) is not dict or set(value) != {"message", "url"}:
            raise InvalidResponseError("update-branch response has invalid exact shape")
        _bounded_text(value.get("message"), "update-branch.message", 512)
        _bounded_text(value.get("url"), "update-branch.url", 2_048)

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
