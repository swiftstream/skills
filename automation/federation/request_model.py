"""Strict request, anchor, and complete PATCH-fold models for federation R01."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import urlsplit

from scripts import federate as c02
from automation.federation.workspace import WorkspaceError, validate_trusted_ref

MAX_BODY_BYTES = 16_384
MAX_PATCH_CANONICAL_EXPANSION_BYTES = 18
MAX_CANONICAL_PATCH_BYTES = MAX_BODY_BYTES + MAX_PATCH_CANONICAL_EXPANSION_BYTES
MAX_ISSUE_PATCH_PROJECTION_ENVELOPE_BYTES = 1_024
MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES = 17_408
ANCHOR_MARKER = "<!-- swiftstream-federation-request-anchor:v1 -->"
ISSUE_REQUEST_ANCHOR_MARKER = "<!-- swiftstream-federation-issue-request-anchor:v1 -->"
ISSUE_PATCH_PROJECTION_MARKER = "<!-- swiftstream-federation-issue-patch-projection:v1 -->"
ISSUE_HEAD_CLAIM_MARKER = "<!-- swiftstream-federation-issue-head-claim:v2 -->"
PATCH_SENTINEL = "Federation PATCH"
REQUEST_MARKER = ".federation-request"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
ISSUE_HEAD_CLAIM_AUTHORITY_PREFIX = "swiftstream-federation-issue-head-claim-authority:v1\n"
EFFECTIVE_REQUEST_DIGEST_PREFIX = "swiftstream-federation-effective-request:v1\n"
ISSUE_PATCH_PROJECTION_EVIDENCE_PREFIX = "swiftstream-federation-issue-patch-projection-evidence:v1\n"
NORMALIZE_TARGET_EVIDENCE_PREFIX = "swiftstream-federation-issue-head-normalize-target:v1\n"
PROPOSAL_TARGET_EVIDENCE_PREFIX = "swiftstream-federation-issue-head-proposal-target:v1\n"
EXTERNAL_STATUS_EVIDENCE_PREFIX = "swiftstream-federation-external-status-evidence:v1\n"
REQUIRED_STATUS_EPOCH_MARKER = "<!-- swiftstream-federation-required-status-epoch:v2 -->"
ISSUE_FINALIZATION_EPOCH_MARKER = "<!-- swiftstream-federation-issue-finalization-epoch:v1 -->"
REQUIRED_STATUS_EPOCH_AUTHORITY_PREFIX = "swiftstream-federation-required-status-epoch-authority:v1\n"
REQUIRED_STATUS_EPOCH_ID_PREFIX = "swiftstream-federation-required-status-epoch-id:v1\n"
ISSUE_FINALIZATION_EPOCH_AUTHORITY_PREFIX = "swiftstream-federation-issue-finalization-epoch-authority:v1\n"
ISSUE_FINALIZATION_EPOCH_EVIDENCE_PREFIX = "swiftstream-federation-issue-finalization-evidence:v1\n"
ISSUE_FINALIZATION_EPOCH_ID_PREFIX = "swiftstream-federation-issue-finalization-epoch-id:v1\n"
ISSUE_FINAL_STATUS_EVIDENCE_PREFIX = "swiftstream-federation-issue-final-status-evidence:v1\n"
EXACT_APP_REQUIRED_STATUS_EVIDENCE_PREFIX = "swiftstream-federation-prior-required-status-evidence:v1\n"

CLAIMED_HEAD_MARKER_HEADER = "swiftstream-federation-head:v2"
ISSUE_BRANCH_LEASE_MARKER = "<!-- swiftstream-federation-issue-branch-lease:v1 -->"
CLAIM_GENERATION_PREFIX = "swiftstream-federation-claim-generation:v1\n"
ISSUE_BRANCH_LEASE_AUTHORITY_PREFIX = "swiftstream-federation-issue-branch-lease-authority:v1\n"
_CLAIM_KINDS = frozenset({
    "ISSUE_BRANCH_LEASE", "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH",
    "ISSUE_FINALIZATION_EPOCH", "ISSUE_CANCELLATION_FENCE", "MACHINE_REF_CLAIM",
})
_CLAIM_ROLES = frozenset({"ISSUE_ACTIVE", "ISSUE_FINALIZING", "ISSUE_CANCEL", "MACHINE_PUBLICATION"})
_CLAIM_OWNER_KINDS = frozenset({"ISSUE", "MACHINE_SOURCE"})
_TRANSITION_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_LEASE_KEYS = frozenset({
    "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
    "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256", "sourceId",
    "sourceRepositoryId", "centralRepositoryNodeId", "branchRef", "acceptedBaseSha",
    "carrierRole", "claimKind", "claimGenerationId", "carrierNonce",
    "authorityPreimageDigest", "initialHeadSha", "initialHeadTreeSha",
    "initialHeadParentSha", "initialHeadMarkerDigest", "requestClass", "leaseId",
})


class RequestModelError(ValueError):
    """Controlled rejection of request syntax or integrity data."""


class RequestClass(Enum):
    ADD = "add-source"
    UPDATE = "update-source"
    REMOVE = "remove-source"
    RECONCILE = "reconcile-source"
    MACHINE_PUBLICATION = "machine-publication"
    UNRELATED = "unrelated"


_BODY_FIELDS: dict[RequestClass, tuple[str, ...]] = {
    RequestClass.ADD: (
        "Repository URL:",
        "Description:",
        "Branch:",
        "Skills root:",
        "Skill prefixes:",
        "Publication lines:",
        "Dropped publication lines:",
    ),
    RequestClass.UPDATE: (
        "Repository URL:",
        "Description:",
        "Branch:",
        "Skills root:",
        "Skill prefixes:",
        "Publication lines:",
        "Dropped publication lines:",
    ),
    RequestClass.REMOVE: ("Repository URL:", "Reason:"),
    RequestClass.RECONCILE: ("Repository URL:",),
}
_REQUEST_KEYS = (
    "Repository URL",
    "Description",
    "Branch",
    "Skills root",
    "Skill prefixes",
    "Publication lines",
    "Dropped publication lines",
    "Reason",
)
_ISSUE_HEADING_TO_FIELD = {
    "### Federation request type": None,
    "### Repository URL": "Repository URL",
    "### Description": "Description",
    "### Branch": "Branch",
    "### Skills root": "Skills root",
    "### Skill prefixes": "Skill prefixes",
    "### Publication lines": "Publication lines",
    "### Dropped publication lines": "Dropped publication lines",
    "### Reason": "Reason",
}
_ISSUE_HEADINGS_BY_CLASS: dict[RequestClass, tuple[str, ...]] = {
    RequestClass.ADD: (
        "### Federation request type",
        "### Repository URL",
        "### Description",
        "### Branch",
        "### Skills root",
        "### Skill prefixes",
        "### Publication lines",
    ),
    RequestClass.UPDATE: (
        "### Federation request type",
        "### Repository URL",
        "### Description",
        "### Branch",
        "### Skills root",
        "### Skill prefixes",
        "### Publication lines",
        "### Dropped publication lines",
    ),
    RequestClass.REMOVE: (
        "### Federation request type",
        "### Repository URL",
        "### Reason",
    ),
}
_ISSUE_EMPTY_RESPONSE = "_No response_"
_ISSUE_UNSUPPORTED_EMPTY_ALIASES = frozenset({"No response", "_no response_", "none", "null"})


def _fail(message: str) -> None:
    raise RequestModelError(message)


def _check_body_size(body: str, context: str = "body", *, max_bytes: int = MAX_BODY_BYTES) -> None:
    try:
        size = len(body.encode("utf-8"))
    except UnicodeEncodeError:
        _fail(f"{context} is not valid UTF-8")
    if size > max_bytes:
        _fail(f"{context} exceeds {max_bytes} UTF-8 bytes")


def _normalized_lines(body: str, context: str, *, max_bytes: int = MAX_BODY_BYTES) -> list[str]:
    _check_body_size(body, context, max_bytes=max_bytes)
    if "\x00" in body:
        _fail(f"{context} contains NUL")
    normalized = body.replace("\r\n", "\n")
    if "\r" in normalized:
        _fail(f"{context} contains unsupported carriage return")
    return normalized.split("\n")


def _parse_blocks(
    body: str,
    allowed: tuple[str, ...],
    context: str,
    *,
    max_bytes: int = MAX_BODY_BYTES,
) -> dict[str, str | None]:
    lines = _normalized_lines(body, context, max_bytes=max_bytes)
    values: dict[str, str | None] = {}
    index = 0
    while index < len(lines):
        if lines[index] == "":
            index += 1
            continue
        label = lines[index]
        if not label.endswith(":") or label not in allowed:
            _fail(f"unknown or misplaced field in {context}: {label!r}")
        if label in values:
            _fail(f"duplicate field in {context}: {label!r}")
        if index + 1 >= len(lines):
            _fail(f"missing value for {context} field: {label!r}")
        value = lines[index + 1]
        if "\n" in value or "\r" in value or "\x00" in value:
            _fail(f"multiline value in {context} field: {label!r}")
        values[label[:-1]] = value
        index += 2
    present = [label for label in allowed if f"{label}"[:-1] in values]
    actual_order = [line for line in lines if line in allowed]
    if actual_order != present:
        _fail(f"fields in {context} are out of order")
    return values


def _repository_url(value: str | None) -> str:
    if value is None or value == "":
        _fail("Repository URL is required and nonempty")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.username or parsed.password:
        _fail("Repository URL must use exact https://github.com/OWNER/REPO syntax")
    if parsed.query or parsed.fragment or parsed.path.endswith("/"):
        _fail("Repository URL must not contain query, fragment, or trailing slash")
    if not parsed.path.startswith("/") or parsed.path.count("/") != 2:
        _fail("Repository URL must have exactly OWNER/REPO path components")
    repository = parsed.path[1:]
    if repository.endswith(".git"):
        _fail("Repository URL must not use a .git suffix")
    try:
        c02.validate_repository(repository)
        return value
    except c02.FederationError as error:
        _fail(str(error))
    raise AssertionError("unreachable")


def _optional_text(value: str | None, field: str, *, allow_empty: bool = False) -> str | None:
    if value is None:
        return None
    if not allow_empty and value == "":
        _fail(f"{field} cannot be empty")
    if len(value) > 500:
        _fail(f"{field} must contain at most 500 Unicode code points")
    if c02.contains_control(value):
        _fail(f"{field} contains a C0/DEL control character")
    if value != value.strip():
        _fail(f"{field} must not contain leading/trailing Unicode whitespace")
    return value


def _branch(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return validate_trusted_ref(value if value.startswith("refs/heads/") else f"refs/heads/{value}")
    except (c02.FederationError, WorkspaceError) as error:
        _fail(str(error))
    raise AssertionError("unreachable")


def _anchor_branch(value: str | None) -> str | None:
    if value is None:
        return None
    if type(value) is not str or not value.startswith("refs/heads/"):
        _fail("anchor Branch must be a canonical refs/heads/** ref")
    try:
        return validate_trusted_ref(value)
    except (c02.FederationError, WorkspaceError) as error:
        _fail(str(error))
    raise AssertionError("unreachable")


def _skills_root(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return c02.validate_posix_relative_path(value, "Skills root")
    except c02.FederationError as error:
        _fail(str(error))
    raise AssertionError("unreachable")


def _prefixes(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    items = value.split(",")
    result: list[str] = []
    for item in items:
        prefix = item.strip(" ")
        if not prefix:
            _fail("Skill prefixes contains an empty item")
        try:
            c02.validate_lower_hyphen_identifier(prefix, "Skill prefix")
        except c02.FederationError as error:
            _fail(str(error))
        if prefix in result:
            _fail("Skill prefixes contains duplicates")
        result.append(prefix)
    return tuple(result)


def _canonical_prefix_tuple(value: tuple[str, ...] | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if type(value) is not tuple or any(type(item) is not str for item in value):
        _fail("Skill prefixes must be a tuple of strings or null")
    result: list[str] = []
    for prefix in value:
        try:
            c02.validate_lower_hyphen_identifier(prefix, "Skill prefix")
        except c02.FederationError as error:
            _fail(str(error))
        if prefix in result:
            _fail("Skill prefixes contains duplicates")
        result.append(prefix)
    return tuple(result)


@dataclass(frozen=True)
class PublicationLineRequest:
    ref: str
    skill_prefixes: tuple[str, ...]


def _canonical_publication_line(value: Any) -> PublicationLineRequest:
    if type(value) is not dict:
        _fail("Publication lines item must be an object")
    if set(value) != {"ref", "skillPrefixes"}:
        _fail("Publication lines item has invalid exact keys")
    try:
        ref = validate_trusted_ref(value["ref"])
    except (c02.FederationError, WorkspaceError) as error:
        _fail(str(error))
    prefixes = _canonical_prefix_tuple(
        tuple(value["skillPrefixes"])
        if type(value["skillPrefixes"]) is list
        else value["skillPrefixes"]
    )
    if prefixes is None or not prefixes:
        _fail("Publication lines item skillPrefixes must be a nonempty array")
    return PublicationLineRequest(ref=ref, skill_prefixes=prefixes)


def _publication_lines(value: str | None) -> tuple[PublicationLineRequest, ...] | None:
    if value is None:
        return None
    if value == "":
        _fail("Publication lines cannot be empty")
    items = value.split(";")
    if not items or any(item.strip(" ") == "" for item in items):
        _fail("Publication lines contains an empty item")
    lines: list[PublicationLineRequest] = []
    root_namespaces: set[str] = set()
    seen_refs: set[str] = set()
    seen_prefixes: set[str] = set()
    for item in items:
        piece = item.strip(" ")
        if "=" not in piece:
            _fail("Publication lines item must use ref=prefix[,prefix...] syntax")
        ref_text, prefix_text = piece.split("=", 1)
        if not ref_text or not prefix_text:
            _fail("Publication lines item must use ref=prefix[,prefix...] syntax")
        try:
            ref = validate_trusted_ref(ref_text)
        except (c02.FederationError, WorkspaceError) as error:
            _fail(str(error))
        if ref in seen_refs:
            _fail(f"Publication lines contains duplicate ref: {ref}")
        seen_refs.add(ref)
        prefixes = _prefixes(prefix_text)
        if prefixes is None or not prefixes:
            _fail("Publication lines item skillPrefixes must be nonempty")
        for prefix in prefixes:
            if prefix in seen_prefixes:
                _fail(f"Publication lines contains duplicate skill prefix: {prefix}")
            seen_prefixes.add(prefix)
            root = prefix.split("-", 1)[0]
            if root in root_namespaces:
                _fail(f"Publication lines contains duplicate root namespace: {root}")
            root_namespaces.add(root)
        lines.append(PublicationLineRequest(ref=ref, skill_prefixes=prefixes))
    return tuple(lines)


def _dropped_publication_lines(value: str | None) -> tuple[str, ...] | None:
    if value is None:
        return None
    if value == "":
        _fail("Dropped publication lines cannot be empty")
    items = value.split(",")
    refs: list[str] = []
    for item in items:
        piece = item.strip(" ")
        if not piece:
            _fail("Dropped publication lines contains an empty item")
        try:
            ref = validate_trusted_ref(piece)
        except (c02.FederationError, WorkspaceError) as error:
            _fail(str(error))
        if ref in refs:
            _fail(f"Dropped publication lines contains duplicate ref: {ref}")
        refs.append(ref)
    return tuple(refs)


def _require_single_line_match(
    branch: str | None,
    prefixes: tuple[str, ...] | None,
    lines: tuple[PublicationLineRequest, ...],
) -> None:
    if branch is None and prefixes is None:
        return
    matches: list[PublicationLineRequest] = []
    for line in lines:
        if branch is not None and line.ref != branch:
            continue
        if prefixes is not None and line.skill_prefixes != prefixes:
            continue
        matches.append(line)
    if len(matches) != 1:
        _fail("Branch/Skill prefixes alongside Publication lines must match exactly one listed line")


def resolve_publication_lines(
    request: "Request",
    *,
    default_branch: str,
    default_prefixes: tuple[str, ...],
    existing_refs: tuple[str, ...] | None = None,
) -> tuple[PublicationLineRequest, ...]:
    if request.publication_lines is not None:
        return request.publication_lines
    if request.branch is None and request.skill_prefixes is None and existing_refs is not None:
        # UPDATE with no line fields keeps the accepted line set unchanged.
        raise _KeepExistingLines(existing_refs)
    branch = request.branch or default_branch
    try:
        branch = validate_trusted_ref(
            branch if branch.startswith("refs/heads/") else f"refs/heads/{branch}"
        )
    except (c02.FederationError, WorkspaceError) as error:
        _fail(str(error))
    prefixes = request.skill_prefixes if request.skill_prefixes is not None else default_prefixes
    if not prefixes:
        _fail("resolved publication line requires nonempty skill prefixes")
    return (PublicationLineRequest(ref=branch, skill_prefixes=tuple(prefixes)),)


class _KeepExistingLines(Exception):
    def __init__(self, refs: tuple[str, ...]) -> None:
        self.refs = refs


def proposed_line_refs(
    request: "Request",
    *,
    default_branch: str,
    default_prefixes: tuple[str, ...],
    existing_refs: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    try:
        lines = resolve_publication_lines(
            request,
            default_branch=default_branch,
            default_prefixes=default_prefixes,
            existing_refs=existing_refs,
        )
    except _KeepExistingLines as keep:
        return keep.refs
    return tuple(line.ref for line in lines)


def validate_drop_set(
    request_class: RequestClass,
    request: "Request",
    *,
    accepted_line_refs: tuple[str, ...],
    proposed_refs: tuple[str, ...],
) -> None:
    named_drops = request.dropped_publication_lines
    proposed_set = set(proposed_refs)

    if named_drops is None:
        if request_class is RequestClass.ADD:
            return
        missing = set(accepted_line_refs) - proposed_set
        if missing:
            _fail(
                "UPDATE that omits accepted publication lines must name each drop in "
                "Dropped publication lines: " + ", ".join(sorted(missing))
            )
        return

    if request_class is not RequestClass.UPDATE:
        _fail("Dropped publication lines is only valid on UPDATE requests")
    if not proposed_set:
        _fail("Dropping the last remaining publication line is invalid; use remove-source")
    named = set(named_drops)
    still_proposed = named & proposed_set
    if still_proposed:
        _fail(
            "Dropped publication lines cannot include refs still proposed: "
            + ", ".join(sorted(still_proposed))
        )
    expected = set(accepted_line_refs) - proposed_set
    if named != expected:
        _fail(
            "Dropped publication lines must equal exactly the accepted refs omitted from the "
            f"proposed set (expected {sorted(expected)!r}, got {sorted(named)!r})"
        )


def _validate_anchor_request(request_class: RequestClass, request: "Request") -> None:
    if type(request) is not Request:
        _fail("anchor initialRequest must be a Request")
    if request.request_class is not request_class:
        _fail("anchor request class does not match initial request")
    _repository_url(request.repository_url)
    _optional_text(request.description, "Description")
    _anchor_branch(request.branch)
    _skills_root(request.skills_root)
    _canonical_prefix_tuple(request.skill_prefixes)
    if request.publication_lines is not None:
        for line in request.publication_lines:
            _canonical_publication_line({"ref": line.ref, "skillPrefixes": list(line.skill_prefixes)})
        refs = [line.ref for line in request.publication_lines]
        if len(set(refs)) != len(refs):
            _fail("anchor Publication lines contains duplicate refs")
        roots: set[str] = set()
        seen_prefixes: set[str] = set()
        for line in request.publication_lines:
            for prefix in line.skill_prefixes:
                if prefix in seen_prefixes:
                    _fail("anchor Publication lines contains duplicate skill prefixes")
                seen_prefixes.add(prefix)
                root = prefix.split("-", 1)[0]
                if root in roots:
                    _fail("anchor Publication lines contains duplicate root namespaces")
                roots.add(root)
        _require_single_line_match(request.branch, request.skill_prefixes, request.publication_lines)
    if request.dropped_publication_lines is not None:
        for ref in request.dropped_publication_lines:
            try:
                validate_trusted_ref(ref)
            except (c02.FederationError, WorkspaceError) as error:
                _fail(str(error))
    _optional_text(request.reason, "Reason")
    if request_class in {RequestClass.ADD, RequestClass.UPDATE}:
        if request.reason is not None:
            _fail("ADD/UPDATE anchors cannot contain Reason")
        if request_class is RequestClass.ADD and request.dropped_publication_lines is not None:
            _fail("ADD anchors cannot contain Dropped publication lines")
    elif request_class is RequestClass.REMOVE:
        if any(
            getattr(request, name) is not None
            for name in (
                "description",
                "branch",
                "skills_root",
                "skill_prefixes",
                "publication_lines",
                "dropped_publication_lines",
            )
        ):
            _fail("REMOVE anchors cannot contain mutable ADD/UPDATE fields")
    elif request_class is RequestClass.RECONCILE:
        if any(
            getattr(request, name) is not None
            for name in (
                "description",
                "branch",
                "skills_root",
                "skill_prefixes",
                "publication_lines",
                "dropped_publication_lines",
                "reason",
            )
        ):
            _fail("RECONCILE anchors cannot contain mutable request fields")
    else:
        _fail("anchor requestClass must be a human request class")


@dataclass(frozen=True)
class Request:
    request_class: RequestClass
    repository_url: str
    description: str | None = None
    branch: str | None = None
    skills_root: str | None = None
    skill_prefixes: tuple[str, ...] | None = None
    publication_lines: tuple[PublicationLineRequest, ...] | None = None
    dropped_publication_lines: tuple[str, ...] | None = None
    reason: str | None = None

    def as_anchor_value(self) -> dict[str, Any]:
        return {
            "Repository URL": self.repository_url,
            "Description": self.description,
            "Branch": self.branch,
            "Skills root": self.skills_root,
            "Skill prefixes": list(self.skill_prefixes) if self.skill_prefixes is not None else None,
            "Publication lines": (
                [{"ref": line.ref, "skillPrefixes": list(line.skill_prefixes)} for line in self.publication_lines]
                if self.publication_lines is not None
                else None
            ),
            "Dropped publication lines": (
                list(self.dropped_publication_lines) if self.dropped_publication_lines is not None else None
            ),
            "Reason": self.reason,
        }


def parse_request_body(request_class: RequestClass, body: str) -> Request:
    if request_class not in _BODY_FIELDS:
        _fail("machine or unrelated classes do not have a human request body")
    values = _parse_blocks(body, _BODY_FIELDS[request_class], "request body")
    for key in ("Description", "Branch", "Skills root", "Skill prefixes", "Reason"):
        if values.get(key) == "":
            values[key] = None
    if values.get("Publication lines") == "":
        _fail("Publication lines cannot be empty")
    if values.get("Dropped publication lines") == "":
        _fail("Dropped publication lines cannot be empty")
    repository = _repository_url(values.get("Repository URL"))
    description = _optional_text(values.get("Description"), "Description")
    branch = _branch(values.get("Branch"))
    skills_root = _skills_root(values.get("Skills root"))
    prefixes = _prefixes(values.get("Skill prefixes"))
    publication_lines = _publication_lines(values.get("Publication lines"))
    dropped = _dropped_publication_lines(values.get("Dropped publication lines"))
    reason = _optional_text(values.get("Reason"), "Reason")
    if request_class is RequestClass.REMOVE:
        return Request(request_class, repository, reason=reason)
    if request_class is RequestClass.RECONCILE:
        return Request(request_class, repository)
    if publication_lines is not None:
        _require_single_line_match(branch, prefixes, publication_lines)
    if request_class is RequestClass.ADD and dropped is not None:
        _fail("Dropped publication lines is only valid on UPDATE requests")
    return Request(
        request_class,
        repository,
        description,
        branch,
        skills_root,
        prefixes,
        publication_lines,
        dropped,
    )


def render_request_body(request: Request) -> str:
    """Render the canonical existing manual Request grammar for an Issue PR."""
    if type(request) is not Request or request.request_class not in {
        RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE,
    }:
        _fail("only ADD, UPDATE, or REMOVE requests have a canonical Issue PR body")
    _validate_anchor_request(request.request_class, request)
    value_by_field: dict[str, str | None] = {
        "Repository URL": request.repository_url,
        "Description": request.description,
        "Branch": request.branch,
        "Skills root": request.skills_root,
        "Skill prefixes": (
            ",".join(request.skill_prefixes) if request.skill_prefixes is not None else None
        ),
        "Publication lines": (
            ";".join(
                f"{line.ref}={','.join(line.skill_prefixes)}"
                for line in request.publication_lines
            ) if request.publication_lines is not None else None
        ),
        "Dropped publication lines": (
            ",".join(request.dropped_publication_lines)
            if request.dropped_publication_lines is not None else None
        ),
        "Reason": request.reason,
    }
    blocks = [
        f"{label}\n{value_by_field[label[:-1]]}"
        for label in _BODY_FIELDS[request.request_class]
        if value_by_field[label[:-1]] is not None
    ]
    rendered = "\n\n".join(blocks) + "\n"
    _check_body_size(rendered, "canonical request body")
    if parse_request_body(request.request_class, rendered) != request:
        _fail("canonical request body did not round-trip to the exact Request")
    return rendered


def parse_issue_request_body(body: str) -> Request:
    """Adapt one rendered Issue Form body to the existing strict Request grammar.

    Only the visible Markdown headings and their single-line values carry
    authority. Form IDs, titles, labels, and event metadata are outside this
    body-only API.
    """
    if type(body) is not str:
        _fail("Issue request body must be a string")
    lines = _normalized_lines(body, "Issue request body")
    if any(c02.contains_control(line) for line in lines):
        _fail("Issue request body contains unsupported control data")

    def skip_separators(index: int) -> int:
        while index < len(lines) and lines[index] == "":
            index += 1
        return index

    cursor = skip_separators(0)
    first_heading = "### Federation request type"
    if cursor >= len(lines) or lines[cursor] != first_heading:
        _fail("Issue request must begin with the exact Federation request type heading")
    cursor = skip_separators(cursor + 1)
    if cursor >= len(lines):
        _fail("Issue request type value is missing")
    request_type = lines[cursor]
    try:
        request_class = next(
            item
            for item in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE)
            if item.value == request_type
        )
    except StopIteration:
        _fail("Issue request type is unsupported")
    cursor += 1

    expected_headings = _ISSUE_HEADINGS_BY_CLASS[request_class]
    values: dict[str, str] = {}
    seen_headings = {first_heading}
    for heading in expected_headings[1:]:
        cursor = skip_separators(cursor)
        if cursor >= len(lines):
            _fail(f"Issue request is missing heading: {heading}")
        actual_heading = lines[cursor]
        if actual_heading.startswith("### "):
            if actual_heading not in _ISSUE_HEADING_TO_FIELD:
                _fail(f"Issue request contains an unknown heading: {actual_heading!r}")
            if actual_heading in seen_headings:
                _fail(f"Issue request contains a duplicate heading: {actual_heading!r}")
            if actual_heading != heading:
                _fail("Issue request headings are out of order")
        elif actual_heading != heading:
            _fail(f"Issue request contains free-form authority prose: {actual_heading!r}")
        seen_headings.add(heading)
        cursor = skip_separators(cursor + 1)
        if cursor >= len(lines):
            _fail(f"Issue request value is missing for heading: {heading}")
        value = lines[cursor]
        if value.startswith("### "):
            if value not in _ISSUE_HEADING_TO_FIELD:
                _fail(f"Issue request contains an unknown heading: {value!r}")
            if value in seen_headings:
                _fail(f"Issue request contains a duplicate heading: {value!r}")
            _fail(f"Issue request value is missing for heading: {heading}")
        field = _ISSUE_HEADING_TO_FIELD[heading]
        if field is None:
            _fail("Issue request type heading cannot be parsed as an optional field")
        values[field] = value
        cursor += 1

    cursor = skip_separators(cursor)
    if cursor < len(lines):
        extra = lines[cursor]
        if extra.startswith("### "):
            if extra not in _ISSUE_HEADING_TO_FIELD:
                _fail(f"Issue request contains an unknown heading: {extra!r}")
            if extra in seen_headings:
                _fail(f"Issue request contains a duplicate heading: {extra!r}")
            _fail("Issue request contains an unexpected heading")
        _fail(f"Issue request contains free-form authority prose: {extra!r}")

    if values["Repository URL"] == _ISSUE_EMPTY_RESPONSE:
        _fail("Repository URL cannot use the Issue Form no-response value")
    optional_fields = (
        "Description",
        "Branch",
        "Skills root",
        "Skill prefixes",
        "Publication lines",
        "Dropped publication lines",
        "Reason",
    )
    request_fields = [("Repository URL", values["Repository URL"])]
    for field in optional_fields:
        value = values.get(field)
        if value is None or value == _ISSUE_EMPTY_RESPONSE:
            continue
        if value in _ISSUE_UNSUPPORTED_EMPTY_ALIASES:
            _fail(f"{field} uses an unsupported Issue Form empty-value alias")
        if field in values:
            request_fields.append((field, value))
    canonical_body = "".join(f"{field}:\n{value}\n" for field, value in request_fields)
    return parse_request_body(request_class, canonical_body)


@dataclass(frozen=True)
class Patch:
    assignments: dict[str, Any]


_PATCH_FIELDS = (
    "Description",
    "Branch",
    "Skills root",
    "Skill prefixes",
    "Publication lines",
    "Dropped publication lines",
)


def _parse_patch(comment: str, *, max_bytes: int) -> Patch | None:
    lines = _normalized_lines(comment, "PATCH comment", max_bytes=max_bytes)
    first_nonempty = next((line for line in lines if line != ""), None)
    if first_nonempty != PATCH_SENTINEL:
        return None
    sentinel_index = next(index for index, line in enumerate(lines) if line != "")
    remainder = "\n".join(lines[sentinel_index + 1 :])
    values = _parse_blocks(
        remainder,
        tuple(f"{field}:" for field in _PATCH_FIELDS),
        "PATCH",
        max_bytes=max_bytes,
    )
    if not values:
        _fail("PATCH must contain at least one field")
    for key in ("Description", "Branch", "Skills root", "Skill prefixes"):
        if values.get(key) == "":
            values[key] = None
    return Patch({key: value for key, value in values.items()})


def parse_patch(comment: str) -> Patch | None:
    """Parse a human/source PATCH comment within the unchanged 16 KiB authority."""
    return _parse_patch(comment, max_bytes=MAX_BODY_BYTES)


def render_patch(patch: Patch) -> str:
    """Render one semantically validated PATCH using the frozen canonical bytes."""
    if type(patch) is not Patch or type(patch.assignments) is not dict:
        _fail("PATCH must be a Patch with an exact assignment mapping")
    if not patch.assignments or set(patch.assignments) - set(_PATCH_FIELDS):
        _fail("PATCH assignments are empty or contain unknown fields")

    canonical_values: dict[str, str | None] = {}
    for field in _PATCH_FIELDS:
        if field not in patch.assignments:
            continue
        value = patch.assignments[field]
        if value is not None and type(value) is not str:
            _fail(f"PATCH {field} assignment must be a string or null")
        if field == "Description":
            normalized = None if value in (None, "") else _optional_text(value, field)
            canonical_values[field] = normalized
        elif field == "Branch":
            normalized = None if value in (None, "") else _branch(value)
            canonical_values[field] = normalized
        elif field == "Skills root":
            normalized = None if value in (None, "") else _skills_root(value)
            canonical_values[field] = normalized
        elif field == "Skill prefixes":
            normalized = None if value in (None, "") else _prefixes(value)
            canonical_values[field] = ",".join(normalized) if normalized is not None else None
        elif field == "Publication lines":
            normalized = _publication_lines(value)
            if normalized is None:
                _fail("Publication lines cannot be cleared")
            canonical_values[field] = ";".join(
                f"{line.ref}={','.join(line.skill_prefixes)}" for line in normalized
            )
        else:
            normalized = _dropped_publication_lines(value)
            if normalized is None:
                _fail("Dropped publication lines cannot be cleared")
            canonical_values[field] = ",".join(normalized)

    blocks = [
        f"{field}:\n{canonical_values[field] or ''}"
        for field in _PATCH_FIELDS
        if field in canonical_values
    ]
    rendered = f"{PATCH_SENTINEL}\n\n" + "\n\n".join(blocks) + "\n"
    _check_body_size(rendered, "canonical PATCH", max_bytes=MAX_CANONICAL_PATCH_BYTES)
    reparsed = _parse_patch(rendered, max_bytes=MAX_CANONICAL_PATCH_BYTES)
    if reparsed != Patch(canonical_values):
        _fail("canonical PATCH did not round-trip to exact semantic assignments")
    return rendered


def _parse_projection_canonical_patch(comment: str) -> Patch:
    """Parse the wider canonical PATCH domain for machine projection evidence only."""
    patch = _parse_patch(comment, max_bytes=MAX_CANONICAL_PATCH_BYTES)
    if patch is None or render_patch(patch) != comment:
        _fail("projected PATCH is not the exact semantic canonical representation")
    return patch


@dataclass(frozen=True)
class IssuePatchProjection:
    schema_version: int
    issue_database_id: int
    issue_number: int
    issue_anchor_comment_id: int
    issue_comment_id: int
    issue_comment_body_sha256: str
    binding_id: str
    patch: Patch

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssuePatchProjection schemaVersion must be exact integer 1")
        for name in (
            "issue_database_id", "issue_number", "issue_anchor_comment_id", "issue_comment_id",
        ):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_comment_body_sha256", "binding_id"):
            if type(getattr(self, name)) is not str or not _SHA256_RE.fullmatch(getattr(self, name)):
                _fail(f"{name} must be lowercase 64-hex")
        if type(self.patch) is not Patch:
            _fail("IssuePatchProjection patch must be a Patch")
        render_patch(self.patch)

    def envelope_value(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "issueDatabaseId": self.issue_database_id,
            "issueNumber": self.issue_number,
            "issueAnchorCommentId": self.issue_anchor_comment_id,
            "issueCommentId": self.issue_comment_id,
            "issueCommentBodySha256": self.issue_comment_body_sha256,
            "bindingId": self.binding_id,
        }

    def render(self) -> str:
        envelope = f"{ISSUE_PATCH_PROJECTION_MARKER}\n{_canonical_json(self.envelope_value())}\n\n"
        _check_body_size(
            envelope,
            "IssuePatchProjection envelope",
            max_bytes=MAX_ISSUE_PATCH_PROJECTION_ENVELOPE_BYTES,
        )
        rendered = envelope + render_patch(self.patch)
        _check_body_size(
            rendered,
            "IssuePatchProjection comment",
            max_bytes=MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES,
        )
        return rendered

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_issue_patch_projection(text: str) -> IssuePatchProjection:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("IssuePatchProjection must use exact LF-terminated lines")
    _check_body_size(
        text,
        "IssuePatchProjection comment",
        max_bytes=MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES,
    )
    lines = text.split("\n", 2)
    if len(lines) != 3 or lines[0] != ISSUE_PATCH_PROJECTION_MARKER or not lines[1]:
        _fail("IssuePatchProjection marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid IssuePatchProjection JSON: {error}")
    exact_keys = {
        "schemaVersion", "issueDatabaseId", "issueNumber", "issueAnchorCommentId",
        "issueCommentId", "issueCommentBodySha256", "bindingId",
    }
    if type(value) is not dict or set(value) != exact_keys:
        _fail("IssuePatchProjection has invalid exact keys")
    envelope = f"{lines[0]}\n{lines[1]}\n\n"
    _check_body_size(
        envelope,
        "IssuePatchProjection envelope",
        max_bytes=MAX_ISSUE_PATCH_PROJECTION_ENVELOPE_BYTES,
    )
    if not lines[2].startswith("\n"):
        _fail("IssuePatchProjection must separate its envelope from PATCH with one blank line")
    patch = _parse_projection_canonical_patch(lines[2][1:])
    projection = IssuePatchProjection(
        value["schemaVersion"], value["issueDatabaseId"], value["issueNumber"],
        value["issueAnchorCommentId"], value["issueCommentId"],
        value["issueCommentBodySha256"], value["bindingId"], patch,
    )
    if lines[1] != _canonical_json(projection.envelope_value()) or projection.render() != text:
        _fail("IssuePatchProjection representation is not canonical")
    return projection


def apply_patch(request: Request, patch: Patch) -> Request:
    assignments: dict[str, Any] = {}
    for key in ("Description", "Branch", "Skills root", "Skill prefixes"):
        if key in patch.assignments and patch.assignments[key] == "":
            patch.assignments[key] = None
    if "Description" in patch.assignments:
        assignments["description"] = _optional_text(patch.assignments["Description"], "Description")
    if "Branch" in patch.assignments:
        assignments["branch"] = _branch(patch.assignments["Branch"])
    if "Skills root" in patch.assignments:
        assignments["skills_root"] = _skills_root(patch.assignments["Skills root"])
    if "Skill prefixes" in patch.assignments:
        assignments["skill_prefixes"] = _prefixes(patch.assignments["Skill prefixes"])
    if "Publication lines" in patch.assignments:
        if patch.assignments["Publication lines"] == "":
            _fail("Publication lines cannot be empty")
        assignments["publication_lines"] = _publication_lines(patch.assignments["Publication lines"])
    if "Dropped publication lines" in patch.assignments:
        if patch.assignments["Dropped publication lines"] == "":
            _fail("Dropped publication lines cannot be empty")
        assignments["dropped_publication_lines"] = _dropped_publication_lines(
            patch.assignments["Dropped publication lines"]
        )
    proposed = replace(request, **assignments)
    if proposed.publication_lines is not None:
        _require_single_line_match(
            proposed.branch, proposed.skill_prefixes, proposed.publication_lines
        )
    return proposed


@dataclass(frozen=True)
class CommentEvent:
    comment_id: int
    authorized: bool
    body: str


@dataclass(frozen=True)
class FoldEvidence:
    comment_id: int
    kind: str


@dataclass(frozen=True)
class PatchFoldResult:
    request: Request
    evidence: tuple[FoldEvidence, ...]


def fold_patch_events(
    anchor: "RequestAnchor",
    events: Iterable[CommentEvent],
    semantic_validator: Callable[[Request], bool] | None = None,
) -> PatchFoldResult:
    event_list = list(events)
    ids: set[int] = set()
    for event in event_list:
        if type(event.comment_id) is not int or event.comment_id <= 0:
            _fail("comment IDs must be positive integers")
        if event.comment_id in ids:
            _fail("duplicate comment ID")
        if type(event.authorized) is not bool:
            _fail("comment authorization must be boolean")
        ids.add(event.comment_id)
    current = anchor.initial_request
    evidence: list[FoldEvidence] = []
    for event in sorted(event_list, key=lambda item: item.comment_id):
        try:
            patch = parse_patch(event.body)
        except RequestModelError:
            if next((line for line in _normalized_lines(event.body, "PATCH comment") if line != ""), None) == PATCH_SENTINEL:
                evidence.append(FoldEvidence(event.comment_id, "invalid"))
                continue
            raise
        if patch is None:
            continue
        if anchor.request_class not in {RequestClass.ADD, RequestClass.UPDATE}:
            evidence.append(FoldEvidence(event.comment_id, "invalid"))
            continue
        if not event.authorized:
            evidence.append(FoldEvidence(event.comment_id, "unauthorized"))
            continue
        try:
            proposed = apply_patch(current, patch)
            if semantic_validator is not None and not semantic_validator(proposed):
                evidence.append(FoldEvidence(event.comment_id, "semantic-invalid"))
                continue
        except RequestModelError:
            evidence.append(FoldEvidence(event.comment_id, "invalid"))
            continue
        current = proposed
        evidence.append(FoldEvidence(event.comment_id, "applied"))
    return PatchFoldResult(current, tuple(evidence))


@dataclass(frozen=True)
class RequestAnchor:
    pr_number: int
    request_class: RequestClass
    original_author_id: str
    original_author_login: str
    initial_body_sha256: str
    initial_request: Request
    comment_id: int | None = None
    actor_id: str | None = None
    actor_login: str | None = None

    def __post_init__(self) -> None:
        if type(self.pr_number) is not int or not 1 <= self.pr_number <= 9_223_372_036_854_775_807:
            _fail("prNumber must be an exact integer in the signed 64-bit positive range")
        if self.request_class not in _BODY_FIELDS:
            _fail("anchor requestClass must be a human request class")
        for value, label, limit in ((self.original_author_id, "originalAuthorId", 256), (self.original_author_login, "originalAuthorLogin", 100)):
            if type(value) is not str or not value or len(value) > limit or c02.contains_control(value):
                _fail(f"invalid {label}")
        if type(self.initial_body_sha256) is not str or not _SHA256_RE.fullmatch(self.initial_body_sha256):
            _fail("initialBodySha256 must be lowercase 64-hex")
        _validate_anchor_request(self.request_class, self.initial_request)
        if self.comment_id is not None and (type(self.comment_id) is not int or self.comment_id <= 0):
            _fail("anchor comment ID must be positive when supplied")

    def as_value(self) -> dict[str, Any]:
        return {
            "schemaVersion": 2,
            "prNumber": self.pr_number,
            "requestClass": self.request_class.name.lower(),
            "originalAuthorId": self.original_author_id,
            "originalAuthorLogin": self.original_author_login,
            "initialBodySha256": self.initial_body_sha256,
            "initialRequest": self.initial_request.as_anchor_value(),
        }

    def render(self) -> str:
        line = json.dumps(self.as_value(), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return f"{ANCHOR_MARKER}\n{line}\n"


def _request_from_anchor_value(request_class: RequestClass, value: dict[str, Any]) -> Request:
    if set(value) != set(_REQUEST_KEYS):
        _fail("initialRequest has invalid exact keys")
    if any(value[key] is not None and type(value[key]) is not str for key in (
        "Repository URL", "Description", "Branch", "Skills root", "Reason"
    )):
        _fail("initialRequest values have invalid types")
    prefixes_value = value["Skill prefixes"]
    if prefixes_value is not None and (type(prefixes_value) is not list or any(type(item) is not str for item in prefixes_value)):
        _fail("initialRequest.Skill prefixes must be an array of strings or null")
    anchor_prefixes: tuple[str, ...] | None = None
    if prefixes_value is not None:
        for prefix in prefixes_value:
            try:
                c02.validate_lower_hyphen_identifier(prefix, "initialRequest.Skill prefixes item")
            except c02.FederationError as error:
                _fail(str(error))
        if len(set(prefixes_value)) != len(prefixes_value):
            _fail("initialRequest.Skill prefixes contains duplicates")
        anchor_prefixes = tuple(prefixes_value)
    publication_value = value["Publication lines"]
    publication_lines: tuple[PublicationLineRequest, ...] | None = None
    if publication_value is not None:
        if type(publication_value) is not list or not publication_value:
            _fail("initialRequest.Publication lines must be a nonempty array or null")
        parsed_lines: list[PublicationLineRequest] = []
        for item in publication_value:
            parsed_lines.append(_canonical_publication_line(item))
        publication_lines = tuple(parsed_lines)
    dropped_value = value["Dropped publication lines"]
    dropped: tuple[str, ...] | None = None
    if dropped_value is not None:
        if type(dropped_value) is not list or any(type(item) is not str for item in dropped_value):
            _fail("initialRequest.Dropped publication lines must be an array of strings or null")
        dropped = tuple(dropped_value)
    request = Request(
        request_class,
        _repository_url(value["Repository URL"]),
        _optional_text(value["Description"], "Description"),
        _anchor_branch(value["Branch"]),
        _skills_root(value["Skills root"]),
        anchor_prefixes,
        publication_lines,
        dropped,
        _optional_text(value["Reason"], "Reason"),
    )
    _validate_anchor_request(request_class, request)
    return request


def parse_anchor(text: str) -> RequestAnchor:
    lines = _normalized_lines(text, "anchor")
    nonempty = [index for index, line in enumerate(lines) if line != ""]
    if not nonempty or lines[nonempty[0]] != ANCHOR_MARKER:
        _fail("anchor marker is not exact")
    marker_index = nonempty[0]
    json_indices = [index for index in range(marker_index + 1, len(lines)) if lines[index] != ""]
    if len(json_indices) != 1:
        _fail("anchor must contain exactly one nonempty JSON line")
    line = lines[json_indices[0]]
    try:
        value = c02.decode_json(line)
    except Exception as error:
        _fail(f"invalid anchor JSON: {error}")
    if type(value) is not dict:
        _fail("anchor JSON must be an object")
    expected = {"schemaVersion", "prNumber", "requestClass", "originalAuthorId", "originalAuthorLogin", "initialBodySha256", "initialRequest"}
    if set(value) != expected:
        _fail("anchor has invalid exact keys")
    schema_version = value["schemaVersion"]
    if type(schema_version) is not int or type(schema_version) is bool:
        _fail("anchor schemaVersion must be an exact integer")
    if schema_version != 2:
        _fail(
            "anchor schemaVersion must be exact integer 2 after multi-line versioning cutover; "
            "reopen the request under the Publication lines grammar"
        )
    try:
        request_class = next(item for item in _BODY_FIELDS if item.name.lower() == value["requestClass"])
    except (StopIteration, TypeError):
        _fail("anchor requestClass is invalid")
    request = _request_from_anchor_value(request_class, value["initialRequest"])
    return RequestAnchor(
        value["prNumber"], request_class, value["originalAuthorId"], value["originalAuthorLogin"], value["initialBodySha256"], request
    )


def body_sha256(body: str) -> str:
    _check_body_size(body, "request body")
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def verify_anchor_integrity(anchor: RequestAnchor, original_body: str) -> bool:
    return body_sha256(original_body) == anchor.initial_body_sha256


_ISSUE_REQUEST_ANCHOR_KEYS = frozenset({
    "schemaVersion",
    "issueNumber",
    "issueDatabaseId",
    "issueNodeId",
    "requestClass",
    "originalAuthorId",
    "originalAuthorLogin",
    "initialBodySha256",
    "initialRequest",
    "sourceId",
    "sourceRepositoryId",
    "sourceCanonicalFullName",
    "sourceIdentityKind",
    "anchorObservedLastEditedAt",
    "anchorObservedIncludesCreatedEdit",
})
_ISSUE_REQUEST_CLASSES = (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE)
_ISSUE_REQUEST_CLASS_VALUES = {item.value: item for item in _ISSUE_REQUEST_CLASSES}
_ISSUE_IDENTITY_KINDS = frozenset({"proposed", "accepted"})


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, UnicodeEncodeError):
        _fail("authority JSON value cannot be encoded canonically")


def effective_request_digest(request: Request) -> str:
    """Hash only the canonical effective Request body, never raw Issue formatting."""
    return hashlib.sha256(
        EFFECTIVE_REQUEST_DIGEST_PREFIX.encode("utf-8")
        + render_request_body(request).encode("utf-8")
    ).hexdigest()


def patch_projection_evidence_digest(entries: Iterable[Mapping[str, Any]]) -> str:
    """Hash the exact ordered source/projection evidence schema frozen for C1."""
    exact_keys = {
        "issueCommentId", "issueCommentBodySha256", "canonicalPatchSha256", "projectionSha256",
    }
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != exact_keys:
            _fail("PATCH projection evidence entry has invalid exact keys")
        comment_id = _issue_positive_int(entry["issueCommentId"], "issueCommentId")
        item: dict[str, Any] = {"issueCommentId": comment_id}
        for key in ("issueCommentBodySha256", "canonicalPatchSha256", "projectionSha256"):
            value = entry[key]
            if type(value) is not str or not _SHA256_RE.fullmatch(value):
                _fail(f"{key} must be lowercase 64-hex")
            item[key] = value
        normalized.append(item)
    normalized.sort(key=lambda item: item["issueCommentId"])
    ids = [item["issueCommentId"] for item in normalized]
    if len(ids) != len(set(ids)):
        _fail("PATCH projection evidence contains duplicate Issue comment IDs")
    return hashlib.sha256(
        (ISSUE_PATCH_PROJECTION_EVIDENCE_PREFIX + _canonical_json({"entries": normalized})).encode("utf-8")
    ).hexdigest()


def issue_patch_projection_evidence_digest(
    projections: Iterable[IssuePatchProjection],
) -> str:
    entries: list[dict[str, Any]] = []
    for projection in projections:
        if type(projection) is not IssuePatchProjection:
            _fail("PATCH projection evidence must contain IssuePatchProjection values")
        canonical_patch = render_patch(projection.patch).encode("utf-8")
        rendered_projection = projection.render().encode("utf-8")
        entries.append({
            "issueCommentId": projection.issue_comment_id,
            "issueCommentBodySha256": projection.issue_comment_body_sha256,
            "canonicalPatchSha256": hashlib.sha256(canonical_patch).hexdigest(),
            "projectionSha256": hashlib.sha256(rendered_projection).hexdigest(),
        })
    return patch_projection_evidence_digest(entries)


def normalize_target_evidence_digest(
    *,
    request_class: RequestClass,
    request_marker_blob_sha: str,
    target_tree_sha: str,
) -> str:
    if type(request_class) is not RequestClass or request_class not in _ISSUE_REQUEST_CLASSES:
        _fail("requestClass must be ADD, UPDATE, or REMOVE")
    for value, label in (
        (request_marker_blob_sha, "requestMarkerBlobSha"),
        (target_tree_sha, "targetTreeSha"),
    ):
        if type(value) is not str or not _SHA40_RE.fullmatch(value):
            _fail(f"{label} must be lowercase 40-hex")
    value = {
        "requestMarkerBlobSha": request_marker_blob_sha,
        "requestMarkerContentSha256": hashlib.sha256(
            f"{request_class.value}\n".encode("utf-8")
        ).hexdigest(),
        "targetTreeSha": target_tree_sha,
    }
    return hashlib.sha256(
        (NORMALIZE_TARGET_EVIDENCE_PREFIX + _canonical_json(value)).encode("utf-8")
    ).hexdigest()


def proposal_target_evidence_digest(
    *,
    candidate_tree_sha: str,
    changed: Iterable[Mapping[str, Any]],
    candidate_changed_paths: Iterable[str],
) -> str:
    if type(candidate_tree_sha) is not str or not _SHA40_RE.fullmatch(candidate_tree_sha):
        _fail("candidateTreeSha must be lowercase 40-hex")
    exact_keys = {"path", "state", "mode", "objectType", "blobSha", "contentSha256"}
    entries: list[dict[str, Any]] = []
    for entry in changed:
        if type(entry) is not dict or set(entry) != exact_keys:
            _fail("proposal target evidence entry has invalid exact keys")
        path = entry["path"]
        try:
            canonical_path = c02.validate_posix_relative_path(path, "proposal evidence path")
        except c02.FederationError as error:
            _fail(str(error))
        if canonical_path != path:
            _fail("proposal evidence path is not canonical")
        state = entry["state"]
        if type(state) is not str or state not in {"PRESENT", "ABSENT"}:
            _fail("proposal evidence state must be PRESENT or ABSENT")
        if state == "PRESENT":
            if type(entry["mode"]) is not str or entry["mode"] not in {"100644", "100755"}:
                _fail("proposal evidence PRESENT entry must use a regular file mode")
            if entry["objectType"] != "blob":
                _fail("proposal evidence PRESENT entry must be a regular blob")
            if type(entry["blobSha"]) is not str or not _SHA40_RE.fullmatch(entry["blobSha"]):
                _fail("proposal evidence blobSha must be lowercase 40-hex")
            if type(entry["contentSha256"]) is not str or not _SHA256_RE.fullmatch(entry["contentSha256"]):
                _fail("proposal evidence contentSha256 must be lowercase 64-hex")
        elif any(entry[key] is not None for key in ("mode", "objectType", "blobSha", "contentSha256")):
            _fail("proposal evidence ABSENT entry must have null object metadata")
        entries.append({
            "path": path,
            "state": state,
            "mode": entry["mode"],
            "objectType": entry["objectType"],
            "blobSha": entry["blobSha"],
            "contentSha256": entry["contentSha256"],
        })
    entries.sort(key=lambda item: item["path"])
    paths = [entry["path"] for entry in entries]
    if len(paths) != len(set(paths)):
        _fail("proposal target evidence contains duplicate paths")
    candidate_paths = tuple(candidate_changed_paths)
    if any(type(path) is not str for path in candidate_paths) or tuple(paths) != candidate_paths:
        _fail("proposal evidence paths must exactly equal candidate.changed_paths")
    value = {"candidateTreeSha": candidate_tree_sha, "changed": entries}
    return hashlib.sha256(
        (PROPOSAL_TARGET_EVIDENCE_PREFIX + _canonical_json(value)).encode("utf-8")
    ).hexdigest()


def _issue_bounded_text(value: Any, label: str, limit: int) -> str:
    if type(value) is not str or not value or len(value) > limit or c02.contains_control(value):
        _fail(f"invalid {label}")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _fail(f"invalid {label}")
    return value


def _issue_positive_int(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= 9_223_372_036_854_775_807:
        _fail(f"{label} must be a positive signed-64 integer")
    return value


def _issue_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    text = _issue_bounded_text(value, "anchorObservedLastEditedAt", 128)
    try:
        instant = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        _fail("anchorObservedLastEditedAt must be timezone-aware ISO-8601")
    if instant.tzinfo is None or instant.utcoffset() is None:
        _fail("anchorObservedLastEditedAt must be timezone-aware ISO-8601")
    return text


@dataclass(frozen=True)
class IssueRequestAnchor:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    request_class: RequestClass
    original_author_id: str
    original_author_login: str
    initial_body_sha256: str
    initial_request: Request
    source_id: str
    source_repository_id: int
    source_canonical_full_name: str
    source_identity_kind: str
    anchor_observed_last_edited_at: str | None
    anchor_observed_includes_created_edit: bool

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueRequestAnchor schemaVersion must be exact integer 1")
        _issue_positive_int(self.issue_number, "issueNumber")
        _issue_positive_int(self.issue_database_id, "issueDatabaseId")
        _issue_bounded_text(self.issue_node_id, "issueNodeId", 256)
        if type(self.request_class) is not RequestClass or self.request_class not in _ISSUE_REQUEST_CLASSES:
            _fail("IssueRequestAnchor requestClass must be ADD, UPDATE, or REMOVE")
        _issue_bounded_text(self.original_author_id, "originalAuthorId", 256)
        _issue_bounded_text(self.original_author_login, "originalAuthorLogin", 100)
        if type(self.initial_body_sha256) is not str or not _SHA256_RE.fullmatch(self.initial_body_sha256):
            _fail("initialBodySha256 must be lowercase 64-hex")
        _validate_anchor_request(self.request_class, self.initial_request)
        try:
            c02.validate_source_id(self.source_id)
        except c02.FederationError:
            _fail("sourceId is invalid")
        _issue_positive_int(self.source_repository_id, "sourceRepositoryId")
        full_name = _issue_bounded_text(self.source_canonical_full_name, "sourceCanonicalFullName", 256)
        if full_name.count("/") != 1 or any(not part for part in full_name.split("/")):
            _fail("sourceCanonicalFullName must contain exactly one owner/name separator")
        if type(self.source_identity_kind) is not str or self.source_identity_kind not in _ISSUE_IDENTITY_KINDS:
            _fail("sourceIdentityKind must be proposed or accepted")
        expected_kind = "proposed" if self.request_class is RequestClass.ADD else "accepted"
        if self.source_identity_kind != expected_kind:
            _fail("sourceIdentityKind does not match requestClass")
        _issue_timestamp(self.anchor_observed_last_edited_at)
        if type(self.anchor_observed_includes_created_edit) is not bool:
            _fail("anchorObservedIncludesCreatedEdit must be boolean")

    def as_value(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "requestClass": self.request_class.value,
            "originalAuthorId": self.original_author_id,
            "originalAuthorLogin": self.original_author_login,
            "initialBodySha256": self.initial_body_sha256,
            "initialRequest": self.initial_request.as_anchor_value(),
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "sourceCanonicalFullName": self.source_canonical_full_name,
            "sourceIdentityKind": self.source_identity_kind,
            "anchorObservedLastEditedAt": self.anchor_observed_last_edited_at,
            "anchorObservedIncludesCreatedEdit": self.anchor_observed_includes_created_edit,
        }

    def render(self) -> str:
        return f"{ISSUE_REQUEST_ANCHOR_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_issue_request_anchor(text: str) -> IssueRequestAnchor:
    lines = _normalized_lines(text, "IssueRequestAnchor")
    if not lines or lines[0] != ISSUE_REQUEST_ANCHOR_MARKER:
        _fail("IssueRequestAnchor marker is not exact")
    json_indices = [index for index in range(1, len(lines)) if lines[index] != ""]
    if len(json_indices) != 1:
        _fail("IssueRequestAnchor must contain exactly one nonempty JSON line")
    json_line = lines[json_indices[0]]
    try:
        value = c02.decode_json(json_line)
    except Exception as error:
        _fail(f"invalid IssueRequestAnchor JSON: {error}")
    if type(value) is not dict or set(value) != _ISSUE_REQUEST_ANCHOR_KEYS:
        _fail("IssueRequestAnchor has invalid exact keys")
    schema_version = value["schemaVersion"]
    if type(schema_version) is not int or schema_version != 1:
        _fail("IssueRequestAnchor schemaVersion must be exact integer 1")
    try:
        request_class = _ISSUE_REQUEST_CLASS_VALUES[value["requestClass"]]
    except (KeyError, TypeError):
        _fail("IssueRequestAnchor requestClass is invalid")
    request_value = value["initialRequest"]
    if type(request_value) is not dict:
        _fail("IssueRequestAnchor initialRequest must be an object")
    request = _request_from_anchor_value(request_class, request_value)
    anchor = IssueRequestAnchor(
        schema_version,
        value["issueNumber"],
        value["issueDatabaseId"],
        value["issueNodeId"],
        request_class,
        value["originalAuthorId"],
        value["originalAuthorLogin"],
        value["initialBodySha256"],
        request,
        value["sourceId"],
        value["sourceRepositoryId"],
        value["sourceCanonicalFullName"],
        value["sourceIdentityKind"],
        value["anchorObservedLastEditedAt"],
        value["anchorObservedIncludesCreatedEdit"],
    )
    if json_line != _canonical_json(anchor.as_value()) or text != anchor.render():
        _fail("IssueRequestAnchor representation is not canonical")
    return anchor


@dataclass(frozen=True)
class IssuePatchEvent:
    comment_id: int
    authorized: bool
    edited: bool
    body: str

    def __post_init__(self) -> None:
        if type(self.comment_id) is not int or self.comment_id <= 0:
            _fail("Issue PATCH comment ID must be a positive exact integer")
        if type(self.authorized) is not bool or type(self.edited) is not bool:
            _fail("Issue PATCH authorization/edit flags must be exact booleans")
        if type(self.body) is not str:
            _fail("Issue PATCH body must be text")
        _check_body_size(self.body, "Issue PATCH comment")


def _looks_like_patch_candidate(body: str) -> bool:
    normalized = body.replace("\r\n", "\n")
    return next((line for line in normalized.split("\n") if line != ""), None) == PATCH_SENTINEL


def fold_issue_patch_events(
    anchor: IssueRequestAnchor,
    events: Iterable[IssuePatchEvent],
    semantic_validator: Callable[[Request], bool] | None = None,
) -> PatchFoldResult:
    if type(anchor) is not IssueRequestAnchor:
        _fail("Issue PATCH fold requires an IssueRequestAnchor")
    event_list = list(events)
    ids: set[int] = set()
    for event in event_list:
        if type(event) is not IssuePatchEvent:
            _fail("Issue PATCH fold received an invalid event")
        if event.comment_id in ids:
            _fail("duplicate Issue PATCH comment ID")
        ids.add(event.comment_id)
    current = anchor.initial_request
    evidence: list[FoldEvidence] = []
    for event in sorted(event_list, key=lambda item: item.comment_id):
        try:
            patch = parse_patch(event.body)
        except RequestModelError:
            if _looks_like_patch_candidate(event.body):
                evidence.append(FoldEvidence(event.comment_id, "invalid"))
            continue
        if patch is None:
            continue
        if anchor.request_class not in {RequestClass.ADD, RequestClass.UPDATE} or event.edited:
            evidence.append(FoldEvidence(event.comment_id, "invalid"))
            continue
        if not event.authorized:
            evidence.append(FoldEvidence(event.comment_id, "unauthorized"))
            continue
        try:
            proposed = apply_patch(current, Patch(dict(patch.assignments)))
            if semantic_validator is not None and not semantic_validator(proposed):
                evidence.append(FoldEvidence(event.comment_id, "semantic-invalid"))
                continue
        except RequestModelError:
            evidence.append(FoldEvidence(event.comment_id, "invalid"))
            continue
        current = proposed
        evidence.append(FoldEvidence(event.comment_id, "applied"))
    return PatchFoldResult(current, tuple(evidence))


def _lease_sha(value: Any, label: str, *, git: bool = False) -> str:
    pattern = _SHA40_RE if git else _SHA256_RE
    if type(value) is not str or not pattern.fullmatch(value):
        _fail(f"{label} must be lowercase {'40' if git else '64'}-hex")
    return value


def _lease_node_id(value: Any, label: str, *, delimiter_free: bool = False) -> str:
    text = _issue_bounded_text(value, label, 256)
    if delimiter_free and ":" in text:
        _fail(f"{label} cannot contain ':'")
    return text


def _lease_decimal(value: Any, label: str) -> int:
    return _issue_positive_int(value, label)


def issue_owner_key(
    central_repository_node_id: str,
    issue_database_id: int,
    issue_node_id: str,
    issue_number: int,
) -> str:
    central = _lease_node_id(central_repository_node_id, "centralRepositoryNodeId", delimiter_free=True)
    database_id = _lease_decimal(issue_database_id, "issueDatabaseId")
    node_id = _lease_node_id(issue_node_id, "issueNodeId", delimiter_free=True)
    number = _lease_decimal(issue_number, "issueNumber")
    return f"{central}:{database_id}:{node_id}:{number}"


def parse_issue_owner_key(owner_key: str) -> tuple[str, int, str, int]:
    """Parse the canonical Issue owner key; the text alone grants no authority."""
    text = _issue_bounded_text(owner_key, "issueOwnerKey", 1_024)
    parts = text.split(":")
    if len(parts) != 4:
        _fail("issueOwnerKey must contain exactly four components")
    central_node_id, database_text, issue_node_id, number_text = parts
    _lease_node_id(central_node_id, "centralRepositoryNodeId", delimiter_free=True)
    _lease_node_id(issue_node_id, "issueNodeId", delimiter_free=True)
    if not re.fullmatch(r"[1-9][0-9]*", database_text):
        _fail("issueDatabaseId must use canonical positive decimal form")
    if not re.fullmatch(r"[1-9][0-9]*", number_text):
        _fail("issueNumber must use canonical positive decimal form")
    if len(database_text) > 19 or len(number_text) > 19:
        _fail("Issue owner-key integer exceeds signed-64 range")
    database_id = _lease_decimal(int(database_text), "issueDatabaseId")
    issue_number = _lease_decimal(int(number_text), "issueNumber")
    if issue_owner_key(central_node_id, database_id, issue_node_id, issue_number) != text:
        _fail("issueOwnerKey is not canonical")
    return central_node_id, database_id, issue_node_id, issue_number


class CarrierActivation(Enum):
    RESERVED_INACTIVE = "RESERVED_INACTIVE"
    ACTIVE = "ACTIVE"
    LEGACY_CUTOVER_QUARANTINE = "LEGACY_CUTOVER_QUARANTINE"
    UNCLAIMED_OUT_OF_FEDERATION = "UNCLAIMED_OUT_OF_FEDERATION"
    CONFLICTING = "CONFLICTING"


class CarrierRole(Enum):
    ISSUE_ACTIVE = "ISSUE_ACTIVE"
    ISSUE_FINALIZING = "ISSUE_FINALIZING"
    ISSUE_CANCEL = "ISSUE_CANCEL"
    MACHINE_PUBLICATION = "MACHINE_PUBLICATION"


class LegacyEvidenceDisposition(Enum):
    ABSENT = "ABSENT"
    QUARANTINE = "QUARANTINE"
    CONFLICTING = "CONFLICTING"


@dataclass(frozen=True)
class ShaCarrierResolution:
    """A PR-independent carrier classification for one exact commit SHA."""

    activation: CarrierActivation
    role: CarrierRole | None = None
    marker: ClaimedHeadMarker | None = None

    def __post_init__(self) -> None:
        if type(self.activation) is not CarrierActivation:
            _fail("carrier activation must be a closed CarrierActivation value")
        if self.role is not None and type(self.role) is not CarrierRole:
            _fail("carrier role must be a closed CarrierRole value")
        if self.marker is not None and type(self.marker) is not ClaimedHeadMarker:
            _fail("carrier marker must be a parsed ClaimedHeadMarker")
        if self.activation in (CarrierActivation.ACTIVE, CarrierActivation.RESERVED_INACTIVE):
            if self.role is None:
                _fail("active and reserved carrier resolutions require a role")
        elif self.role is not None:
            _fail("quarantine, unclaimed, and conflicting resolutions cannot carry a role")
        if self.marker is not None and self.role is not None and self.marker.role != self.role.value:
            _fail("carrier marker role does not match the resolution role")


class StatusClass(Enum):
    ISSUE_FINAL = "issue-final"
    CANCEL = "cancel"
    EXTERNAL = "external"
    LEGACY = "legacy"
    MAINTENANCE = "maintenance"


@dataclass(frozen=True)
class StatusEvidenceDescription:
    status_class: StatusClass
    evidence_digest: str

    def __post_init__(self) -> None:
        if type(self.status_class) is not StatusClass:
            _fail("status class must be a closed StatusClass value")
        _lease_sha(self.evidence_digest, "status evidence digest")

    def render(self) -> str:
        if self.status_class is StatusClass.MAINTENANCE:
            _fail("maintenance status descriptions are parse-only")
        return f"ssf:v1 {self.status_class.value} ev={self.evidence_digest}"


_STATUS_DESCRIPTION_RE = re.compile(
    r"ssf:v1 (issue-final|cancel|external|legacy|maintenance) ev=([0-9a-f]{64})"
)


class RequiredStatusEpochReason(Enum):
    ACTIVE_REVALIDATION = "ACTIVE_REVALIDATION"
    MAIN_ADVANCE_REVALIDATION = "MAIN_ADVANCE_REVALIDATION"
    REQUEST_PATCH_REVALIDATION = "REQUEST_PATCH_REVALIDATION"
    SOURCE_IDENTITY_REVALIDATION = "SOURCE_IDENTITY_REVALIDATION"
    FINALIZATION_INVALIDATED = "FINALIZATION_INVALIDATED"


_CANONICAL_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


def _canonical_utc_timestamp(value: Any, label: str) -> str:
    text = _issue_bounded_text(value, label, 64)
    if not _CANONICAL_TIMESTAMP_RE.fullmatch(text):
        _fail(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError:
        _fail(f"{label} must be a canonical UTC timestamp")
    if parsed.utcoffset() is None:
        _fail(f"{label} must be a canonical UTC timestamp")
    return text


@dataclass(frozen=True)
class ExactAppRequiredStatusEvidence:
    """Canonical corroborating evidence for a selected exact-App status."""

    status_id: int
    status_node_id: str | None
    state: str
    context: str
    description: str
    target_url: None
    creator_database_id: int
    creator_node_id: str
    creator_login: str
    creator_type: str
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        _issue_positive_int(self.status_id, "statusId")
        if self.status_node_id is not None:
            _lease_node_id(self.status_node_id, "statusNodeId", delimiter_free=True)
        if self.state != "success":
            _fail("prior required status state must be exact success")
        if self.context != "federation/trusted-validation":
            _fail("prior required status context must be exact federation/trusted-validation")
        parsed = parse_status_description(self.description)
        if parsed.status_class is not StatusClass.ISSUE_FINAL:
            _fail("prior required status description must use issue-final class")
        if self.target_url is not None:
            _fail("prior required status target_url must be null")
        _issue_positive_int(self.creator_database_id, "creatorDatabaseId")
        _lease_node_id(self.creator_node_id, "creatorNodeId", delimiter_free=True)
        _issue_bounded_text(self.creator_login, "creatorLogin", 256)
        if self.creator_type != "Bot":
            _fail("prior required status creator type must be exact Bot")
        _canonical_utc_timestamp(self.created_at, "createdAt")
        _canonical_utc_timestamp(self.updated_at, "updatedAt")

    def as_value(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "createdAt": self.created_at,
            "creatorDatabaseId": self.creator_database_id,
            "creatorLogin": self.creator_login,
            "creatorNodeId": self.creator_node_id,
            "creatorType": self.creator_type,
            "description": self.description,
            "state": self.state,
            "statusId": self.status_id,
            "statusNodeId": self.status_node_id,
            "targetUrl": self.target_url,
            "updatedAt": self.updated_at,
        }

    def render(self) -> str:
        return _canonical_json(self.as_value())

    def canonical_sha256(self) -> str:
        return hashlib.sha256(
            (EXACT_APP_REQUIRED_STATUS_EVIDENCE_PREFIX + self.render()).encode("utf-8")
        ).hexdigest()

    @classmethod
    def from_value(cls, value: Any) -> "ExactAppRequiredStatusEvidence":
        expected = {
            "statusId", "statusNodeId", "state", "context", "description", "targetUrl",
            "creatorDatabaseId", "creatorNodeId", "creatorLogin", "creatorType",
            "createdAt", "updatedAt",
        }
        if type(value) is not dict or set(value) != expected:
            _fail("prior required status evidence has invalid exact keys")
        return cls(
            value["statusId"], value["statusNodeId"], value["state"], value["context"],
            value["description"], value["targetUrl"], value["creatorDatabaseId"],
            value["creatorNodeId"], value["creatorLogin"], value["creatorType"],
            value["createdAt"], value["updatedAt"],
        )


def parse_status_description(text: str) -> StatusEvidenceDescription:
    if type(text) is not str:
        _fail("status description must be a string")
    try:
        encoded = text.encode("ascii")
    except UnicodeEncodeError:
        _fail("status description must be ASCII")
    if len(encoded) > 86 or any(char in text for char in "\r\n\x00"):
        _fail("status description has invalid length or control characters")
    match = _STATUS_DESCRIPTION_RE.fullmatch(text)
    if match is None:
        _fail("status description is not in canonical ssf:v1 form")
    status = StatusEvidenceDescription(
        StatusClass(match.group(1)), match.group(2)
    )
    if status.status_class is not StatusClass.MAINTENANCE and status.render() != text:
        _fail("status description is not canonical")
    return status


def render_status_description(status_class: StatusClass, evidence_digest: str) -> str:
    return StatusEvidenceDescription(status_class, evidence_digest).render()


def external_status_evidence_digest(
    central_repository_database_id: int,
    central_repository_node_id: str,
    central_repository_full_name: str,
    head_sha: str,
) -> str:
    database_id = _issue_positive_int(central_repository_database_id, "centralRepositoryDatabaseId")
    node_id = _lease_node_id(central_repository_node_id, "centralRepositoryNodeId")
    full_name = _issue_bounded_text(central_repository_full_name, "centralRepositoryFullName", 256)
    if full_name.count("/") != 1 or any(not part for part in full_name.split("/")):
        _fail("centralRepositoryFullName must be canonical owner/repo form")
    sha = _lease_sha(head_sha, "headSha", git=True)
    value = {
        "carrierRole": "UNCLAIMED_OUT_OF_FEDERATION",
        "carrierSchemaVersion": 1,
        "centralRepositoryDatabaseId": database_id,
        "centralRepositoryFullName": full_name,
        "centralRepositoryNodeId": node_id,
        "headSha": sha,
    }
    preimage = EXTERNAL_STATUS_EVIDENCE_PREFIX.encode("utf-8") + _canonical_json(value).encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


def issue_branch_ref(issue_number: int) -> str:
    number = _lease_decimal(issue_number, "issueNumber")
    value = f"refs/heads/bot/federation/request/issue-{number}"
    try:
        return validate_trusted_ref(value)
    except (c02.FederationError, WorkspaceError) as error:
        _fail(str(error))
    raise AssertionError("unreachable")


ISSUE_INTERNAL_PR_BINDING_MARKER = "<!-- swiftstream-federation-issue-pr-binding:v1 -->"
PR_ISSUE_ORIGIN_BINDING_MARKER = "<!-- swiftstream-federation-pr-issue-origin:v1 -->"
_ISSUE_PR_BRANCH_PREFIX = "bot/federation/request/"
_ISSUE_PR_BRANCH_RE = re.compile(r"^bot/federation/request/issue-([1-9][0-9]*)$")
_ISSUE_PR_BINDING_KEYS = frozenset({
    "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
    "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
    "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "sourceId",
    "sourceRepositoryId", "branchRef", "pullRequestNumber", "pullRequestDatabaseId",
    "pullRequestNodeId", "initialHeadSha", "baseRef", "centralRepositoryNodeId",
    "bindingId",
})


def reserved_issue_branch_number(head_ref: str) -> int | None:
    """Classify only the exact reserved short head-ref namespace."""
    if type(head_ref) is not str:
        _fail("PR head ref must be a string")
    if head_ref.startswith("refs/heads/" + _ISSUE_PR_BRANCH_PREFIX):
        _fail("reserved Issue PR head ref must be a short branch name")
    if not head_ref.startswith(_ISSUE_PR_BRANCH_PREFIX):
        return None
    if c02.contains_control(head_ref):
        _fail("reserved Issue PR head ref contains control data")
    match = _ISSUE_PR_BRANCH_RE.fullmatch(head_ref)
    if match is None:
        _fail("reserved Issue PR head ref is malformed")
    digits = match.group(1)
    if len(digits) > 19:
        _fail("reserved Issue PR number exceeds signed-64 range")
    number = int(digits)
    if number > 9_223_372_036_854_775_807:
        _fail("reserved Issue PR number exceeds signed-64 range")
    return number


def _binding_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IssuePRBinding:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    source_id: str
    source_repository_id: int
    branch_ref: str
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    initial_head_sha: str
    base_ref: str
    central_repository_node_id: str
    binding_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssuePRBinding schemaVersion must be exact integer 1")
        for name in (
            "issue_number", "issue_database_id", "issue_request_anchor_comment_database_id",
            "issue_branch_lease_comment_database_id", "source_repository_id",
            "pull_request_number", "pull_request_database_id",
        ):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_node_id", "pull_request_node_id", "central_repository_node_id"):
            text = _issue_bounded_text(getattr(self, name), name, 256)
            if ":" in text:
                _fail(f"{name} cannot contain ':'")
        for name in ("issue_request_anchor_sha256", "issue_branch_lease_sha256"):
            if type(getattr(self, name)) is not str or not _SHA256_RE.fullmatch(getattr(self, name)):
                _fail(f"{name} must be lowercase 64-hex")
        if type(self.initial_head_sha) is not str or not _SHA40_RE.fullmatch(self.initial_head_sha):
            _fail("initial_head_sha must be lowercase 40-hex")
        try:
            c02.validate_source_id(self.source_id)
        except c02.FederationError:
            _fail("source_id is invalid")
        if type(self.branch_ref) is not str or self.branch_ref != issue_branch_ref(self.issue_number):
            _fail("branch_ref must be the exact Issue branch for issue_number")
        if type(self.base_ref) is not str or self.base_ref != "main":
            _fail("base_ref must be exact main")
        if type(self.binding_id) is not str or not _SHA256_RE.fullmatch(self.binding_id):
            _fail("binding_id must be lowercase 64-hex")
        if self.binding_id != _binding_hash(self.as_value(include_binding_id=False)):
            _fail("binding_id does not match the immutable binding payload")

    def as_value(self, *, include_binding_id: bool = True) -> dict[str, Any]:
        value = {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256,
            "issueBranchLeaseCommentDatabaseId": self.issue_branch_lease_comment_database_id,
            "issueBranchLeaseSha256": self.issue_branch_lease_sha256,
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "branchRef": self.branch_ref,
            "pullRequestNumber": self.pull_request_number,
            "pullRequestDatabaseId": self.pull_request_database_id,
            "pullRequestNodeId": self.pull_request_node_id,
            "initialHeadSha": self.initial_head_sha,
            "baseRef": self.base_ref,
            "centralRepositoryNodeId": self.central_repository_node_id,
        }
        if include_binding_id:
            value["bindingId"] = self.binding_id
        return value

    @classmethod
    def create(
        cls,
        *,
        schema_version: int = 1,
        issue_number: int,
        issue_database_id: int,
        issue_node_id: str,
        issue_request_anchor_comment_database_id: int,
        issue_request_anchor_sha256: str,
        issue_branch_lease_comment_database_id: int,
        issue_branch_lease_sha256: str,
        source_id: str,
        source_repository_id: int,
        branch_ref: str,
        pull_request_number: int,
        pull_request_database_id: int,
        pull_request_node_id: str,
        initial_head_sha: str,
        base_ref: str,
        central_repository_node_id: str,
    ) -> "IssuePRBinding":
        value = {
            "schemaVersion": schema_version,
            "issueNumber": issue_number,
            "issueDatabaseId": issue_database_id,
            "issueNodeId": issue_node_id,
            "issueRequestAnchorCommentDatabaseId": issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": issue_request_anchor_sha256,
            "issueBranchLeaseCommentDatabaseId": issue_branch_lease_comment_database_id,
            "issueBranchLeaseSha256": issue_branch_lease_sha256,
            "sourceId": source_id,
            "sourceRepositoryId": source_repository_id,
            "branchRef": branch_ref,
            "pullRequestNumber": pull_request_number,
            "pullRequestDatabaseId": pull_request_database_id,
            "pullRequestNodeId": pull_request_node_id,
            "initialHeadSha": initial_head_sha,
            "baseRef": base_ref,
            "centralRepositoryNodeId": central_repository_node_id,
        }
        return cls(
            schema_version, issue_number, issue_database_id, issue_node_id,
            issue_request_anchor_comment_database_id, issue_request_anchor_sha256,
            issue_branch_lease_comment_database_id, issue_branch_lease_sha256,
            source_id, source_repository_id, branch_ref, pull_request_number,
            pull_request_database_id, pull_request_node_id, initial_head_sha,
            base_ref, central_repository_node_id, _binding_hash(value),
        )

    def render_issue_binding(self) -> str:
        return f"{ISSUE_INTERNAL_PR_BINDING_MARKER}\n{_canonical_json(self.as_value())}\n"

    def render_pr_origin_binding(self) -> str:
        return f"{PR_ISSUE_ORIGIN_BINDING_MARKER}\n{_canonical_json(self.as_value())}\n"

    def issue_comment_sha256(self) -> str:
        return hashlib.sha256(self.render_issue_binding().encode("utf-8")).hexdigest()

    def pr_comment_sha256(self) -> str:
        return hashlib.sha256(self.render_pr_origin_binding().encode("utf-8")).hexdigest()


def _parse_issue_pr_binding(text: str, marker: str) -> IssuePRBinding:
    lines = _normalized_lines(text, "IssuePRBinding")
    nonempty = [line for line in lines if line]
    if len(nonempty) != 2 or nonempty[0] != marker:
        _fail("IssuePRBinding marker or line shape is invalid")
    json_line = nonempty[1]
    try:
        value = c02.decode_json(json_line)
    except Exception as error:
        _fail(f"invalid IssuePRBinding JSON: {error}")
    if type(value) is not dict or set(value) != _ISSUE_PR_BINDING_KEYS:
        _fail("IssuePRBinding has invalid exact keys")
    if type(value.get("schemaVersion")) is not int or value["schemaVersion"] != 1:
        _fail("IssuePRBinding schemaVersion must be exact integer 1")
    binding = IssuePRBinding(
        value["schemaVersion"], value["issueNumber"], value["issueDatabaseId"],
        value["issueNodeId"], value["issueRequestAnchorCommentDatabaseId"],
        value["issueRequestAnchorSha256"], value["issueBranchLeaseCommentDatabaseId"],
        value["issueBranchLeaseSha256"], value["sourceId"], value["sourceRepositoryId"],
        value["branchRef"], value["pullRequestNumber"], value["pullRequestDatabaseId"],
        value["pullRequestNodeId"], value["initialHeadSha"], value["baseRef"],
        value["centralRepositoryNodeId"], value["bindingId"],
    )
    if json_line != _canonical_json(binding.as_value()) or text != f"{marker}\n{json_line}\n":
        _fail("IssuePRBinding representation is not canonical")
    return binding


def parse_issue_internal_pr_binding(text: str) -> IssuePRBinding:
    return _parse_issue_pr_binding(text, ISSUE_INTERNAL_PR_BINDING_MARKER)


def parse_pr_issue_origin_binding(text: str) -> IssuePRBinding:
    return _parse_issue_pr_binding(text, PR_ISSUE_ORIGIN_BINDING_MARKER)


@dataclass(frozen=True)
class ClaimedHeadMarker:
    claim_kind: str
    role: str
    owner_kind: str
    owner_key: str
    claim_generation_id: str
    carrier_nonce: str
    transition_kind: str

    def __post_init__(self) -> None:
        if type(self.claim_kind) is not str or self.claim_kind not in _CLAIM_KINDS:
            _fail("claimed-head marker claimKind is unknown")
        if type(self.role) is not str or self.role not in _CLAIM_ROLES:
            _fail("claimed-head marker role is unknown")
        if type(self.owner_kind) is not str or self.owner_kind not in _CLAIM_OWNER_KINDS:
            _fail("claimed-head marker ownerKind is unknown")
        _issue_bounded_text(self.owner_key, "ownerKey", 1_024)
        _lease_sha(self.claim_generation_id, "claimGenerationId")
        _lease_sha(self.carrier_nonce, "carrierNonce")
        if type(self.transition_kind) is not str or not _TRANSITION_RE.fullmatch(self.transition_kind):
            _fail("claimed-head marker transitionKind is invalid")

    def render(self) -> str:
        return (
            f"{CLAIMED_HEAD_MARKER_HEADER}\n"
            f"claim-kind={self.claim_kind}\n"
            f"role={self.role}\n"
            f"owner-kind={self.owner_kind}\n"
            f"owner-key={self.owner_key}\n"
            f"generation={self.claim_generation_id}\n"
            f"nonce={self.carrier_nonce}\n"
            f"transition={self.transition_kind}\n"
        )


def parse_claimed_head_marker(text: str) -> ClaimedHeadMarker:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("claimed-head marker must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    expected_labels = (
        CLAIMED_HEAD_MARKER_HEADER,
        "claim-kind=", "role=", "owner-kind=", "owner-key=", "generation=", "nonce=", "transition=",
    )
    if len(lines) != len(expected_labels) or lines[0] != expected_labels[0]:
        _fail("claimed-head marker has invalid line count or header")
    for line, label in zip(lines[1:], expected_labels[1:]):
        if not line.startswith(label) or len(line) == len(label):
            _fail("claimed-head marker fields are missing, extra, or out of order")
    marker = ClaimedHeadMarker(
        lines[1][len("claim-kind="):], lines[2][len("role="):],
        lines[3][len("owner-kind="):], lines[4][len("owner-key="):],
        lines[5][len("generation="):], lines[6][len("nonce="):],
        lines[7][len("transition="):],
    )
    if marker.render() != text:
        _fail("claimed-head marker is not canonical")
    return marker


def new_carrier_nonce() -> str:
    """Return a fresh trusted 256-bit nonce for a genuinely new lease."""
    return secrets.token_hex(32)


def issue_branch_lease_authority_digest(
    *,
    accepted_base_sha: str,
    accepted_base_tree_sha: str,
    branch_ref: str,
    central_repository_node_id: str,
    owner_key: str,
    issue_request_anchor_sha256: str,
    request_class: RequestClass,
    source_canonical_full_name: str,
    source_id: str,
    source_identity_kind: str,
    source_repository_id: int,
) -> str:
    _lease_sha(accepted_base_sha, "acceptedBaseSha", git=True)
    _lease_sha(accepted_base_tree_sha, "acceptedBaseTreeSha", git=True)
    _lease_sha(issue_request_anchor_sha256, "issueRequestAnchorSha256")
    if type(request_class) is not RequestClass or request_class not in _ISSUE_REQUEST_CLASSES:
        _fail("requestClass must be ADD, UPDATE, or REMOVE")
    if type(source_id) is not str:
        _fail("sourceId is invalid")
    try:
        c02.validate_source_id(source_id)
    except c02.FederationError:
        _fail("sourceId is invalid")
    _issue_positive_int(source_repository_id, "sourceRepositoryId")
    central = _lease_node_id(central_repository_node_id, "centralRepositoryNodeId", delimiter_free=True)
    owner_text = _issue_bounded_text(owner_key, "issueOwnerKey", 1_024)
    owner_parts = owner_text.split(":")
    if len(owner_parts) != 4:
        _fail("issueOwnerKey must contain exactly four canonical components")
    owner_central, database_text, issue_node_id, issue_number_text = owner_parts
    if owner_central != central:
        _fail("issueOwnerKey centralRepositoryNodeId does not match")

    def parse_owner_decimal(text: str, label: str) -> int:
        if not re.fullmatch(r"[1-9][0-9]{0,18}", text):
            _fail(f"{label} must be canonical positive decimal")
        return _lease_decimal(int(text), label)

    issue_database_id = parse_owner_decimal(database_text, "issueDatabaseId")
    issue_node_id = _lease_node_id(issue_node_id, "issueNodeId", delimiter_free=True)
    issue_number = parse_owner_decimal(issue_number_text, "issueNumber")
    if issue_owner_key(central, issue_database_id, issue_node_id, issue_number) != owner_text:
        _fail("issueOwnerKey is not canonical")

    branch = _issue_bounded_text(branch_ref, "branchRef", 1_024)
    if branch != issue_branch_ref(issue_number):
        _fail("branchRef does not match issueOwnerKey issueNumber")
    _issue_bounded_text(source_canonical_full_name, "sourceCanonicalFullName", 256)
    if source_canonical_full_name.count("/") != 1 or any(
        not part for part in source_canonical_full_name.split("/")
    ):
        _fail("sourceCanonicalFullName must contain one owner/name separator")
    if source_identity_kind not in _ISSUE_IDENTITY_KINDS:
        _fail("sourceIdentityKind is invalid")
    value = {
        "acceptedBaseSha": accepted_base_sha,
        "acceptedBaseTreeSha": accepted_base_tree_sha,
        "branchRef": branch_ref,
        "centralRepositoryNodeId": central,
        "issueOwnerKey": owner_key,
        "issueRequestAnchorSha256": issue_request_anchor_sha256,
        "requestClass": request_class.value,
        "sourceCanonicalFullName": source_canonical_full_name,
        "sourceId": source_id,
        "sourceIdentityKind": source_identity_kind,
        "sourceRepositoryId": source_repository_id,
    }
    return hashlib.sha256((ISSUE_BRANCH_LEASE_AUTHORITY_PREFIX + _canonical_json(value)).encode("utf-8")).hexdigest()


def claim_generation_id(
    *,
    authority_preimage_digest: str,
    carrier_nonce: str,
    central_repository_node_id: str,
    owner_key: str,
    from_head_sha: str,
    from_tree_sha: str,
    claim_kind: str = "ISSUE_BRANCH_LEASE",
    role: str = "ISSUE_ACTIVE",
    owner_kind: str = "ISSUE",
    transition_kind: str = "INITIAL",
) -> str:
    _lease_sha(authority_preimage_digest, "authorityPreimageDigest")
    _lease_sha(carrier_nonce, "carrierNonce")
    _lease_sha(from_head_sha, "fromHeadSha", git=True)
    _lease_sha(from_tree_sha, "fromTreeSha", git=True)
    central = _lease_node_id(central_repository_node_id, "centralRepositoryNodeId", delimiter_free=True)
    _issue_bounded_text(owner_key, "ownerKey", 1_024)
    if type(claim_kind) is not str or claim_kind not in _CLAIM_KINDS:
        _fail("claimKind is unknown")
    if type(role) is not str or role not in _CLAIM_ROLES:
        _fail("role is unknown")
    if type(owner_kind) is not str or owner_kind not in _CLAIM_OWNER_KINDS:
        _fail("ownerKind is unknown")
    if type(transition_kind) is not str or not _TRANSITION_RE.fullmatch(transition_kind):
        _fail("transitionKind is invalid")
    value = {
        "authorityPreimageDigest": authority_preimage_digest,
        "carrierNonce": carrier_nonce,
        "centralRepositoryNodeId": central,
        "claimKind": claim_kind,
        "fromHeadSha": from_head_sha,
        "fromTreeSha": from_tree_sha,
        "ownerKey": owner_key,
        "ownerKind": owner_kind,
        "role": role,
        "transitionKind": transition_kind,
    }
    return hashlib.sha256((CLAIM_GENERATION_PREFIX + _canonical_json(value)).encode("utf-8")).hexdigest()


_ISSUE_HEAD_CLAIM_TRANSITIONS = frozenset({
    "NORMALIZE", "PROPOSAL", "PATCH_REGENERATION", "MAIN_ADVANCE",
})
_ISSUE_HEAD_CLAIM_KEYS = frozenset({
    "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
    "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
    "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "bindingId",
    "sourceId", "sourceRepositoryId", "pullRequestNumber", "pullRequestDatabaseId",
    "pullRequestNodeId", "centralRepositoryNodeId", "branchRef", "requestClass",
    "acceptedBaseSha", "acceptedBaseTreeSha", "fromHeadSha", "fromTreeSha",
    "toHeadSha", "toTreeSha", "carrierRole", "claimKind", "claimGenerationId",
    "transitionKind", "carrierNonce", "effectiveRequestDigest",
    "patchProjectionEvidenceDigest", "targetEvidenceDigest", "authorityPreimageDigest",
    "markerDigest", "claimId",
})


def _issue_head_claim_preimage_from_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    request_class = fields["request_class"]
    if type(request_class) is not RequestClass:
        _fail("IssueHeadClaim requestClass must be ADD, UPDATE, or REMOVE")
    return {
        "schemaVersion": fields["schema_version"],
        "issueNumber": fields["issue_number"],
        "issueDatabaseId": fields["issue_database_id"],
        "issueNodeId": fields["issue_node_id"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"],
        "bindingId": fields["binding_id"],
        "sourceId": fields["source_id"],
        "sourceRepositoryId": fields["source_repository_id"],
        "pullRequestNumber": fields["pull_request_number"],
        "pullRequestDatabaseId": fields["pull_request_database_id"],
        "pullRequestNodeId": fields["pull_request_node_id"],
        "centralRepositoryNodeId": fields["central_repository_node_id"],
        "branchRef": fields["branch_ref"],
        "requestClass": request_class.value,
        "transitionKind": fields["transition_kind"],
        "acceptedBaseSha": fields["accepted_base_sha"],
        "acceptedBaseTreeSha": fields["accepted_base_tree_sha"],
        "fromHeadSha": fields["from_head_sha"],
        "fromTreeSha": fields["from_tree_sha"],
        "effectiveRequestDigest": fields["effective_request_digest"],
        "patchProjectionEvidenceDigest": fields["patch_projection_evidence_digest"],
        "targetEvidenceDigest": fields["target_evidence_digest"],
    }


def _issue_head_claim_authority_digest_from_fields(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (ISSUE_HEAD_CLAIM_AUTHORITY_PREFIX + _canonical_json(
            _issue_head_claim_preimage_from_fields(fields)
        )).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class IssueHeadClaim:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    binding_id: str
    source_id: str
    source_repository_id: int
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    central_repository_node_id: str
    branch_ref: str
    request_class: RequestClass
    accepted_base_sha: str
    accepted_base_tree_sha: str
    from_head_sha: str
    from_tree_sha: str
    to_head_sha: str
    to_tree_sha: str
    carrier_role: str
    claim_kind: str
    claim_generation_id: str
    transition_kind: str
    carrier_nonce: str
    effective_request_digest: str
    patch_projection_evidence_digest: str
    target_evidence_digest: str
    authority_preimage_digest: str
    marker_digest: str
    claim_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueHeadClaim schemaVersion must be exact integer 1")
        for name in (
            "issue_number", "issue_database_id", "issue_request_anchor_comment_database_id",
            "issue_branch_lease_comment_database_id", "source_repository_id",
            "pull_request_number", "pull_request_database_id",
        ):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_node_id", "pull_request_node_id", "central_repository_node_id"):
            _lease_node_id(getattr(self, name), name, delimiter_free=True)
        for name in (
            "issue_request_anchor_sha256", "issue_branch_lease_sha256", "binding_id",
            "claim_generation_id", "carrier_nonce", "effective_request_digest",
            "patch_projection_evidence_digest", "target_evidence_digest",
            "authority_preimage_digest", "marker_digest", "claim_id",
        ):
            value = getattr(self, name)
            if type(value) is not str or not _SHA256_RE.fullmatch(value):
                _fail(f"{name} must be lowercase 64-hex")
        try:
            c02.validate_source_id(self.source_id)
        except (TypeError, c02.FederationError):
            _fail("sourceId is invalid")
        if type(self.branch_ref) is not str or self.branch_ref != issue_branch_ref(self.issue_number):
            _fail("branchRef must be the exact Issue branch for issueNumber")
        if type(self.request_class) is not RequestClass or self.request_class not in _ISSUE_REQUEST_CLASSES:
            _fail("requestClass must be ADD, UPDATE, or REMOVE")
        for name in (
            "accepted_base_sha", "accepted_base_tree_sha", "from_head_sha", "from_tree_sha",
            "to_head_sha", "to_tree_sha",
        ):
            value = getattr(self, name)
            if type(value) is not str or not _SHA40_RE.fullmatch(value):
                _fail(f"{name} must be lowercase 40-hex")
        if self.carrier_role != "ISSUE_ACTIVE":
            _fail("IssueHeadClaim carrierRole must be ISSUE_ACTIVE")
        if self.claim_kind != "ISSUE_HEAD_CLAIM":
            _fail("IssueHeadClaim claimKind must be ISSUE_HEAD_CLAIM")
        if type(self.transition_kind) is not str or self.transition_kind not in _ISSUE_HEAD_CLAIM_TRANSITIONS:
            _fail("IssueHeadClaim transitionKind is invalid")
        fields = self._fields()
        expected_authority = _issue_head_claim_authority_digest_from_fields(fields)
        if self.authority_preimage_digest != expected_authority:
            _fail("IssueHeadClaim authorityPreimageDigest does not match stored immutable evidence")
        expected_generation = claim_generation_id(
            authority_preimage_digest=self.authority_preimage_digest,
            carrier_nonce=self.carrier_nonce,
            central_repository_node_id=self.central_repository_node_id,
            owner_key=issue_owner_key(
                self.central_repository_node_id,
                self.issue_database_id,
                self.issue_node_id,
                self.issue_number,
            ),
            from_head_sha=self.from_head_sha,
            from_tree_sha=self.from_tree_sha,
            claim_kind=self.claim_kind,
            role=self.carrier_role,
            owner_kind="ISSUE",
            transition_kind=self.transition_kind,
        )
        if self.claim_generation_id != expected_generation:
            _fail("IssueHeadClaim claimGenerationId does not match stored authority")
        marker = ClaimedHeadMarker(
            self.claim_kind,
            self.carrier_role,
            "ISSUE",
            issue_owner_key(
                self.central_repository_node_id,
                self.issue_database_id,
                self.issue_node_id,
                self.issue_number,
            ),
            self.claim_generation_id,
            self.carrier_nonce,
            self.transition_kind,
        )
        expected_marker_digest = hashlib.sha256(marker.render().encode("utf-8")).hexdigest()
        if self.marker_digest != expected_marker_digest:
            _fail("IssueHeadClaim markerDigest does not match deterministic marker bytes")
        expected_claim_id = hashlib.sha256(_canonical_json(self.as_value(include_claim_id=False)).encode("utf-8")).hexdigest()
        if self.claim_id != expected_claim_id:
            _fail("IssueHeadClaim claimId does not match canonical final claim JSON")

    def _fields(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "issue_number": self.issue_number,
            "issue_database_id": self.issue_database_id,
            "issue_node_id": self.issue_node_id,
            "issue_request_anchor_comment_database_id": self.issue_request_anchor_comment_database_id,
            "issue_request_anchor_sha256": self.issue_request_anchor_sha256,
            "issue_branch_lease_comment_database_id": self.issue_branch_lease_comment_database_id,
            "issue_branch_lease_sha256": self.issue_branch_lease_sha256,
            "binding_id": self.binding_id,
            "source_id": self.source_id,
            "source_repository_id": self.source_repository_id,
            "pull_request_number": self.pull_request_number,
            "pull_request_database_id": self.pull_request_database_id,
            "pull_request_node_id": self.pull_request_node_id,
            "central_repository_node_id": self.central_repository_node_id,
            "branch_ref": self.branch_ref,
            "request_class": self.request_class,
            "accepted_base_sha": self.accepted_base_sha,
            "accepted_base_tree_sha": self.accepted_base_tree_sha,
            "from_head_sha": self.from_head_sha,
            "from_tree_sha": self.from_tree_sha,
            "to_head_sha": self.to_head_sha,
            "to_tree_sha": self.to_tree_sha,
            "carrier_role": self.carrier_role,
            "claim_kind": self.claim_kind,
            "claim_generation_id": self.claim_generation_id,
            "transition_kind": self.transition_kind,
            "carrier_nonce": self.carrier_nonce,
            "effective_request_digest": self.effective_request_digest,
            "patch_projection_evidence_digest": self.patch_projection_evidence_digest,
            "target_evidence_digest": self.target_evidence_digest,
            "authority_preimage_digest": self.authority_preimage_digest,
            "marker_digest": self.marker_digest,
            "claim_id": self.claim_id,
        }

    def authority_preimage_value(self) -> dict[str, Any]:
        return _issue_head_claim_preimage_from_fields(self._fields())

    def as_value(self, *, include_claim_id: bool = True) -> dict[str, Any]:
        value = {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256,
            "issueBranchLeaseCommentDatabaseId": self.issue_branch_lease_comment_database_id,
            "issueBranchLeaseSha256": self.issue_branch_lease_sha256,
            "bindingId": self.binding_id,
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "pullRequestNumber": self.pull_request_number,
            "pullRequestDatabaseId": self.pull_request_database_id,
            "pullRequestNodeId": self.pull_request_node_id,
            "centralRepositoryNodeId": self.central_repository_node_id,
            "branchRef": self.branch_ref,
            "requestClass": self.request_class.value,
            "acceptedBaseSha": self.accepted_base_sha,
            "acceptedBaseTreeSha": self.accepted_base_tree_sha,
            "fromHeadSha": self.from_head_sha,
            "fromTreeSha": self.from_tree_sha,
            "toHeadSha": self.to_head_sha,
            "toTreeSha": self.to_tree_sha,
            "carrierRole": self.carrier_role,
            "claimKind": self.claim_kind,
            "claimGenerationId": self.claim_generation_id,
            "transitionKind": self.transition_kind,
            "carrierNonce": self.carrier_nonce,
            "effectiveRequestDigest": self.effective_request_digest,
            "patchProjectionEvidenceDigest": self.patch_projection_evidence_digest,
            "targetEvidenceDigest": self.target_evidence_digest,
            "authorityPreimageDigest": self.authority_preimage_digest,
            "markerDigest": self.marker_digest,
        }
        if include_claim_id:
            value["claimId"] = self.claim_id
        return value

    @classmethod
    def create(cls, **fields: Any) -> "IssueHeadClaim":
        body = dict(fields)
        body.setdefault("schema_version", 1)
        body.setdefault("carrier_role", "ISSUE_ACTIVE")
        body.setdefault("claim_kind", "ISSUE_HEAD_CLAIM")
        required = {
            "schema_version", "issue_number", "issue_database_id", "issue_node_id",
            "issue_request_anchor_comment_database_id", "issue_request_anchor_sha256",
            "issue_branch_lease_comment_database_id", "issue_branch_lease_sha256", "binding_id",
            "source_id", "source_repository_id", "pull_request_number", "pull_request_database_id",
            "pull_request_node_id", "central_repository_node_id", "branch_ref", "request_class",
            "accepted_base_sha", "accepted_base_tree_sha", "from_head_sha", "from_tree_sha",
            "to_head_sha", "to_tree_sha", "carrier_role", "claim_kind", "transition_kind",
            "carrier_nonce", "effective_request_digest", "patch_projection_evidence_digest",
            "target_evidence_digest",
        }
        if set(body) != required:
            _fail("IssueHeadClaim.create fields do not match the construction schema")
        authority = _issue_head_claim_authority_digest_from_fields(body)
        owner_key = issue_owner_key(
            body["central_repository_node_id"],
            body["issue_database_id"],
            body["issue_node_id"],
            body["issue_number"],
        )
        generation = claim_generation_id(
            authority_preimage_digest=authority,
            carrier_nonce=body["carrier_nonce"],
            central_repository_node_id=body["central_repository_node_id"],
            owner_key=owner_key,
            from_head_sha=body["from_head_sha"],
            from_tree_sha=body["from_tree_sha"],
            claim_kind=body["claim_kind"],
            role=body["carrier_role"],
            owner_kind="ISSUE",
            transition_kind=body["transition_kind"],
        )
        marker = ClaimedHeadMarker(
            body["claim_kind"], body["carrier_role"], "ISSUE", owner_key,
            generation, body["carrier_nonce"], body["transition_kind"],
        )
        values = dict(body)
        values["claim_generation_id"] = generation
        values["authority_preimage_digest"] = authority
        values["marker_digest"] = hashlib.sha256(marker.render().encode("utf-8")).hexdigest()
        final_value = {
            "schemaVersion": values["schema_version"],
            "issueNumber": values["issue_number"],
            "issueDatabaseId": values["issue_database_id"],
            "issueNodeId": values["issue_node_id"],
            "issueRequestAnchorCommentDatabaseId": values["issue_request_anchor_comment_database_id"],
            "issueRequestAnchorSha256": values["issue_request_anchor_sha256"],
            "issueBranchLeaseCommentDatabaseId": values["issue_branch_lease_comment_database_id"],
            "issueBranchLeaseSha256": values["issue_branch_lease_sha256"],
            "bindingId": values["binding_id"],
            "sourceId": values["source_id"],
            "sourceRepositoryId": values["source_repository_id"],
            "pullRequestNumber": values["pull_request_number"],
            "pullRequestDatabaseId": values["pull_request_database_id"],
            "pullRequestNodeId": values["pull_request_node_id"],
            "centralRepositoryNodeId": values["central_repository_node_id"],
            "branchRef": values["branch_ref"],
            "requestClass": values["request_class"].value,
            "acceptedBaseSha": values["accepted_base_sha"],
            "acceptedBaseTreeSha": values["accepted_base_tree_sha"],
            "fromHeadSha": values["from_head_sha"],
            "fromTreeSha": values["from_tree_sha"],
            "toHeadSha": values["to_head_sha"],
            "toTreeSha": values["to_tree_sha"],
            "carrierRole": values["carrier_role"],
            "claimKind": values["claim_kind"],
            "claimGenerationId": values["claim_generation_id"],
            "transitionKind": values["transition_kind"],
            "carrierNonce": values["carrier_nonce"],
            "effectiveRequestDigest": values["effective_request_digest"],
            "patchProjectionEvidenceDigest": values["patch_projection_evidence_digest"],
            "targetEvidenceDigest": values["target_evidence_digest"],
            "authorityPreimageDigest": values["authority_preimage_digest"],
            "markerDigest": values["marker_digest"],
        }
        values["claim_id"] = hashlib.sha256(_canonical_json(final_value).encode("utf-8")).hexdigest()
        return cls(**values)

    def render(self) -> str:
        return f"{ISSUE_HEAD_CLAIM_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def issue_head_claim_authority_digest(claim: IssueHeadClaim) -> str:
    if type(claim) is not IssueHeadClaim:
        _fail("historical authority digest requires an IssueHeadClaim")
    return _issue_head_claim_authority_digest_from_fields(claim._fields())


def parse_issue_head_claim(text: str) -> IssueHeadClaim:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("IssueHeadClaim must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    if len(lines) != 2 or lines[0] != ISSUE_HEAD_CLAIM_MARKER or not lines[1]:
        _fail("IssueHeadClaim marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid IssueHeadClaim JSON: {error}")
    if type(value) is not dict or set(value) != _ISSUE_HEAD_CLAIM_KEYS:
        _fail("IssueHeadClaim has invalid exact keys")
    try:
        request_class = _ISSUE_REQUEST_CLASS_VALUES[value["requestClass"]]
    except (KeyError, TypeError):
        _fail("IssueHeadClaim requestClass is invalid")
    claim = IssueHeadClaim(
        value["schemaVersion"], value["issueNumber"], value["issueDatabaseId"], value["issueNodeId"],
        value["issueRequestAnchorCommentDatabaseId"], value["issueRequestAnchorSha256"],
        value["issueBranchLeaseCommentDatabaseId"], value["issueBranchLeaseSha256"], value["bindingId"],
        value["sourceId"], value["sourceRepositoryId"], value["pullRequestNumber"],
        value["pullRequestDatabaseId"], value["pullRequestNodeId"], value["centralRepositoryNodeId"],
        value["branchRef"], request_class, value["acceptedBaseSha"], value["acceptedBaseTreeSha"],
        value["fromHeadSha"], value["fromTreeSha"], value["toHeadSha"], value["toTreeSha"],
        value["carrierRole"], value["claimKind"], value["claimGenerationId"],
        value["transitionKind"], value["carrierNonce"], value["effectiveRequestDigest"],
        value["patchProjectionEvidenceDigest"], value["targetEvidenceDigest"],
        value["authorityPreimageDigest"], value["markerDigest"], value["claimId"],
    )
    if lines[1] != _canonical_json(claim.as_value()) or text != claim.render():
        _fail("IssueHeadClaim representation is not canonical")
    return claim


_REQUIRED_STATUS_EPOCH_FROM_KINDS = frozenset({
    "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH", "ISSUE_FINALIZATION_EPOCH",
})
_REQUIRED_STATUS_EPOCH_KEYS = frozenset({
    "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
    "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
    "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "bindingId",
    "sourceId", "sourceRepositoryId", "pullRequestNumber", "pullRequestDatabaseId",
    "pullRequestNodeId", "centralRepositoryNodeId", "branchRef", "requestClass",
    "acceptedBaseSha", "acceptedBaseTreeSha", "baseRef", "fromHeadSha", "fromTreeSha",
    "toHeadSha", "toTreeSha", "carrierRole", "claimKind", "claimGenerationId",
    "transitionKind", "carrierNonce", "reasonClass", "fromProvenanceKind",
    "fromProvenanceId", "fromProvenanceSha256", "fromCarrierRole",
    "priorRequiredStatus", "authorityPreimageDigest", "markerDigest", "epochId",
})


def _required_status_epoch_preimage_from_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    reason = fields["reason_class"]
    request_class = fields["request_class"]
    if type(reason) is not RequiredStatusEpochReason:
        _fail("RequiredStatusEpoch reasonClass must be a closed RequiredStatusEpochReason")
    if type(request_class) is not RequestClass:
        _fail("RequiredStatusEpoch requestClass must be ADD, UPDATE, or REMOVE")
    prior = fields["prior_required_status"]
    if prior is not None and type(prior) is not ExactAppRequiredStatusEvidence:
        _fail("priorRequiredStatus must be exact App status evidence or null")
    return {
        "schemaVersion": fields["schema_version"],
        "issueNumber": fields["issue_number"],
        "issueDatabaseId": fields["issue_database_id"],
        "issueNodeId": fields["issue_node_id"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"],
        "bindingId": fields["binding_id"],
        "sourceId": fields["source_id"],
        "sourceRepositoryId": fields["source_repository_id"],
        "pullRequestNumber": fields["pull_request_number"],
        "pullRequestDatabaseId": fields["pull_request_database_id"],
        "pullRequestNodeId": fields["pull_request_node_id"],
        "centralRepositoryNodeId": fields["central_repository_node_id"],
        "branchRef": fields["branch_ref"],
        "requestClass": request_class.value,
        "acceptedBaseSha": fields["accepted_base_sha"],
        "acceptedBaseTreeSha": fields["accepted_base_tree_sha"],
        "baseRef": fields["base_ref"],
        "fromHeadSha": fields["from_head_sha"],
        "fromTreeSha": fields["from_tree_sha"],
        "transitionKind": reason.value,
        "reasonClass": reason.value,
        "fromProvenanceKind": fields["from_provenance_kind"],
        "fromProvenanceId": fields["from_provenance_id"],
        "fromProvenanceSha256": fields["from_provenance_sha256"],
        "fromCarrierRole": fields["from_carrier_role"],
        "priorRequiredStatus": prior.as_value() if prior is not None else None,
    }


def _required_status_epoch_authority_digest_from_fields(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (REQUIRED_STATUS_EPOCH_AUTHORITY_PREFIX + _canonical_json(
            _required_status_epoch_preimage_from_fields(fields)
        )).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class RequiredStatusEpoch:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    binding_id: str
    source_id: str
    source_repository_id: int
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    central_repository_node_id: str
    branch_ref: str
    request_class: RequestClass
    accepted_base_sha: str
    accepted_base_tree_sha: str
    base_ref: str
    from_head_sha: str
    from_tree_sha: str
    to_head_sha: str
    to_tree_sha: str
    carrier_role: str
    claim_kind: str
    claim_generation_id: str
    transition_kind: str
    carrier_nonce: str
    reason_class: RequiredStatusEpochReason
    from_provenance_kind: str
    from_provenance_id: str
    from_provenance_sha256: str
    from_carrier_role: str
    prior_required_status: ExactAppRequiredStatusEvidence | None
    authority_preimage_digest: str
    marker_digest: str
    epoch_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 2:
            _fail("RequiredStatusEpoch schemaVersion must be exact integer 2")
        for name in (
            "issue_number", "issue_database_id", "issue_request_anchor_comment_database_id",
            "issue_branch_lease_comment_database_id", "source_repository_id",
            "pull_request_number", "pull_request_database_id",
        ):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_node_id", "pull_request_node_id", "central_repository_node_id"):
            _lease_node_id(getattr(self, name), name, delimiter_free=True)
        for name in (
            "issue_request_anchor_sha256", "issue_branch_lease_sha256", "binding_id",
            "claim_generation_id", "carrier_nonce", "from_provenance_id",
            "from_provenance_sha256", "authority_preimage_digest", "marker_digest", "epoch_id",
        ):
            _lease_sha(getattr(self, name), name)
        try:
            c02.validate_source_id(self.source_id)
        except (TypeError, c02.FederationError):
            _fail("sourceId is invalid")
        if type(self.branch_ref) is not str or self.branch_ref != issue_branch_ref(self.issue_number):
            _fail("branchRef must be the exact Issue branch ref")
        if type(self.request_class) is not RequestClass or self.request_class not in _ISSUE_REQUEST_CLASSES:
            _fail("requestClass must be ADD, UPDATE, or REMOVE")
        for name in (
            "accepted_base_sha", "accepted_base_tree_sha", "from_head_sha", "from_tree_sha",
            "to_head_sha", "to_tree_sha",
        ):
            _lease_sha(getattr(self, name), name, git=True)
        if self.base_ref != "main":
            _fail("baseRef must be exact main")
        if self.to_tree_sha != self.from_tree_sha:
            _fail("RequiredStatusEpoch must preserve the exact from-tree")
        if self.carrier_role != "ISSUE_ACTIVE":
            _fail("RequiredStatusEpoch carrierRole must be ISSUE_ACTIVE")
        if self.claim_kind != "REQUIRED_STATUS_EPOCH":
            _fail("RequiredStatusEpoch claimKind must be REQUIRED_STATUS_EPOCH")
        if type(self.reason_class) is not RequiredStatusEpochReason:
            _fail("reasonClass must be a closed RequiredStatusEpochReason")
        if self.transition_kind != self.reason_class.value:
            _fail("RequiredStatusEpoch transitionKind must equal reasonClass")
        _lease_sha(self.carrier_nonce, "carrierNonce")
        if self.from_provenance_kind not in _REQUIRED_STATUS_EPOCH_FROM_KINDS:
            _fail("RequiredStatusEpoch fromProvenanceKind is unsupported")
        expected_role = (
            "ISSUE_FINALIZING"
            if self.from_provenance_kind == "ISSUE_FINALIZATION_EPOCH"
            else "ISSUE_ACTIVE"
        )
        if self.from_carrier_role != expected_role:
            _fail("fromCarrierRole does not match source provenance kind")
        if self.reason_class is RequiredStatusEpochReason.FINALIZATION_INVALIDATED and (
            self.from_provenance_kind != "ISSUE_FINALIZATION_EPOCH"
            or self.from_carrier_role != "ISSUE_FINALIZING"
        ):
            _fail("FINALIZATION_INVALIDATED requires an ISSUE_FINALIZATION_EPOCH predecessor")
        if self.prior_required_status is not None and type(self.prior_required_status) is not ExactAppRequiredStatusEvidence:
            _fail("priorRequiredStatus must be exact App status evidence or null")
        expected_authority = _required_status_epoch_authority_digest_from_fields(self._fields())
        if self.authority_preimage_digest != expected_authority:
            _fail("RequiredStatusEpoch authorityPreimageDigest does not match immutable authority")
        expected_generation = claim_generation_id(
            authority_preimage_digest=self.authority_preimage_digest,
            carrier_nonce=self.carrier_nonce,
            central_repository_node_id=self.central_repository_node_id,
            owner_key=issue_owner_key(
                self.central_repository_node_id, self.issue_database_id, self.issue_node_id, self.issue_number,
            ),
            from_head_sha=self.from_head_sha,
            from_tree_sha=self.from_tree_sha,
            claim_kind=self.claim_kind,
            role=self.carrier_role,
            owner_kind="ISSUE",
            transition_kind=self.transition_kind,
        )
        if self.claim_generation_id != expected_generation:
            _fail("RequiredStatusEpoch claimGenerationId does not match immutable authority")
        marker = ClaimedHeadMarker(
            self.claim_kind, self.carrier_role, "ISSUE",
            issue_owner_key(self.central_repository_node_id, self.issue_database_id, self.issue_node_id, self.issue_number),
            self.claim_generation_id, self.carrier_nonce, self.transition_kind,
        )
        if self.marker_digest != hashlib.sha256(marker.render().encode("utf-8")).hexdigest():
            _fail("RequiredStatusEpoch markerDigest does not match canonical generation marker")
        expected_epoch_id = hashlib.sha256(
            (REQUIRED_STATUS_EPOCH_ID_PREFIX + _canonical_json(self.as_value(include_epoch_id=False))).encode("utf-8")
        ).hexdigest()
        if self.epoch_id != expected_epoch_id:
            _fail("RequiredStatusEpoch epochId does not match canonical final body")

    def _fields(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "schema_version", "issue_number", "issue_database_id", "issue_node_id",
                "issue_request_anchor_comment_database_id", "issue_request_anchor_sha256",
                "issue_branch_lease_comment_database_id", "issue_branch_lease_sha256", "binding_id",
                "source_id", "source_repository_id", "pull_request_number", "pull_request_database_id",
                "pull_request_node_id", "central_repository_node_id", "branch_ref", "request_class",
                "accepted_base_sha", "accepted_base_tree_sha", "base_ref", "from_head_sha", "from_tree_sha",
                "to_head_sha", "to_tree_sha", "carrier_role", "claim_kind", "claim_generation_id",
                "transition_kind", "carrier_nonce", "reason_class", "from_provenance_kind",
                "from_provenance_id", "from_provenance_sha256", "from_carrier_role",
                "prior_required_status", "authority_preimage_digest", "marker_digest", "epoch_id",
            )
        }

    def authority_preimage_value(self) -> dict[str, Any]:
        return _required_status_epoch_preimage_from_fields(self._fields())

    def as_value(self, *, include_epoch_id: bool = True) -> dict[str, Any]:
        value = {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256,
            "issueBranchLeaseCommentDatabaseId": self.issue_branch_lease_comment_database_id,
            "issueBranchLeaseSha256": self.issue_branch_lease_sha256,
            "bindingId": self.binding_id,
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "pullRequestNumber": self.pull_request_number,
            "pullRequestDatabaseId": self.pull_request_database_id,
            "pullRequestNodeId": self.pull_request_node_id,
            "centralRepositoryNodeId": self.central_repository_node_id,
            "branchRef": self.branch_ref,
            "requestClass": self.request_class.value,
            "acceptedBaseSha": self.accepted_base_sha,
            "acceptedBaseTreeSha": self.accepted_base_tree_sha,
            "baseRef": self.base_ref,
            "fromHeadSha": self.from_head_sha,
            "fromTreeSha": self.from_tree_sha,
            "toHeadSha": self.to_head_sha,
            "toTreeSha": self.to_tree_sha,
            "carrierRole": self.carrier_role,
            "claimKind": self.claim_kind,
            "claimGenerationId": self.claim_generation_id,
            "transitionKind": self.transition_kind,
            "carrierNonce": self.carrier_nonce,
            "reasonClass": self.reason_class.value,
            "fromProvenanceKind": self.from_provenance_kind,
            "fromProvenanceId": self.from_provenance_id,
            "fromProvenanceSha256": self.from_provenance_sha256,
            "fromCarrierRole": self.from_carrier_role,
            "priorRequiredStatus": self.prior_required_status.as_value() if self.prior_required_status is not None else None,
            "authorityPreimageDigest": self.authority_preimage_digest,
            "markerDigest": self.marker_digest,
        }
        if include_epoch_id:
            value["epochId"] = self.epoch_id
        return value

    @classmethod
    def create(cls, **fields: Any) -> "RequiredStatusEpoch":
        body = dict(fields)
        body.setdefault("schema_version", 2)
        body.setdefault("carrier_role", "ISSUE_ACTIVE")
        body.setdefault("claim_kind", "REQUIRED_STATUS_EPOCH")
        if type(body.get("reason_class")) is not RequiredStatusEpochReason:
            _fail("RequiredStatusEpoch.create requires a RequiredStatusEpochReason")
        body.setdefault("transition_kind", body["reason_class"].value)
        required = {
            "schema_version", "issue_number", "issue_database_id", "issue_node_id",
            "issue_request_anchor_comment_database_id", "issue_request_anchor_sha256",
            "issue_branch_lease_comment_database_id", "issue_branch_lease_sha256", "binding_id",
            "source_id", "source_repository_id", "pull_request_number", "pull_request_database_id",
            "pull_request_node_id", "central_repository_node_id", "branch_ref", "request_class",
            "accepted_base_sha", "accepted_base_tree_sha", "base_ref", "from_head_sha", "from_tree_sha",
            "to_head_sha", "to_tree_sha", "carrier_role", "claim_kind", "transition_kind",
            "carrier_nonce", "reason_class", "from_provenance_kind", "from_provenance_id",
            "from_provenance_sha256", "from_carrier_role", "prior_required_status",
        }
        if set(body) != required:
            _fail("RequiredStatusEpoch.create fields do not match the construction schema")
        authority = _required_status_epoch_authority_digest_from_fields(body)
        generation = claim_generation_id(
            authority_preimage_digest=authority,
            carrier_nonce=body["carrier_nonce"],
            central_repository_node_id=body["central_repository_node_id"],
            owner_key=issue_owner_key(
                body["central_repository_node_id"], body["issue_database_id"],
                body["issue_node_id"], body["issue_number"],
            ),
            from_head_sha=body["from_head_sha"],
            from_tree_sha=body["from_tree_sha"],
            claim_kind=body["claim_kind"],
            role=body["carrier_role"],
            owner_kind="ISSUE",
            transition_kind=body["transition_kind"],
        )
        marker = ClaimedHeadMarker(
            body["claim_kind"], body["carrier_role"], "ISSUE",
            issue_owner_key(body["central_repository_node_id"], body["issue_database_id"], body["issue_node_id"], body["issue_number"]),
            generation, body["carrier_nonce"], body["transition_kind"],
        )
        marker_digest = hashlib.sha256(marker.render().encode("utf-8")).hexdigest()
        values = dict(body)
        values.update({"claim_generation_id": generation, "authority_preimage_digest": authority, "marker_digest": marker_digest})
        provisional = cls.__new__(cls)
        for name, value in values.items():
            object.__setattr__(provisional, name, value)
        epoch_without_id = provisional.as_value(include_epoch_id=False)
        epoch_id = hashlib.sha256(
            (REQUIRED_STATUS_EPOCH_ID_PREFIX + _canonical_json(epoch_without_id)).encode("utf-8")
        ).hexdigest()
        values["epoch_id"] = epoch_id
        return cls(**values)

    def render(self) -> str:
        return f"{REQUIRED_STATUS_EPOCH_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_required_status_epoch(text: str) -> RequiredStatusEpoch:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("RequiredStatusEpoch must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    if len(lines) != 2 or lines[0] != REQUIRED_STATUS_EPOCH_MARKER or not lines[1]:
        _fail("RequiredStatusEpoch marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid RequiredStatusEpoch JSON: {error}")
    if type(value) is not dict or set(value) != _REQUIRED_STATUS_EPOCH_KEYS:
        _fail("RequiredStatusEpoch has invalid exact keys")
    try:
        request_class = _ISSUE_REQUEST_CLASS_VALUES[value["requestClass"]]
        reason_class = RequiredStatusEpochReason(value["reasonClass"])
        prior = ExactAppRequiredStatusEvidence.from_value(value["priorRequiredStatus"]) if value["priorRequiredStatus"] is not None else None
    except (KeyError, TypeError, ValueError):
        _fail("RequiredStatusEpoch enum or nested evidence value is invalid")
    epoch = RequiredStatusEpoch(
        value["schemaVersion"], value["issueNumber"], value["issueDatabaseId"], value["issueNodeId"],
        value["issueRequestAnchorCommentDatabaseId"], value["issueRequestAnchorSha256"],
        value["issueBranchLeaseCommentDatabaseId"], value["issueBranchLeaseSha256"], value["bindingId"],
        value["sourceId"], value["sourceRepositoryId"], value["pullRequestNumber"],
        value["pullRequestDatabaseId"], value["pullRequestNodeId"], value["centralRepositoryNodeId"],
        value["branchRef"], request_class, value["acceptedBaseSha"], value["acceptedBaseTreeSha"],
        value["baseRef"], value["fromHeadSha"], value["fromTreeSha"], value["toHeadSha"], value["toTreeSha"],
        value["carrierRole"], value["claimKind"], value["claimGenerationId"], value["transitionKind"],
        value["carrierNonce"], reason_class, value["fromProvenanceKind"], value["fromProvenanceId"],
        value["fromProvenanceSha256"], value["fromCarrierRole"], prior, value["authorityPreimageDigest"],
        value["markerDigest"], value["epochId"],
    )
    if lines[1] != _canonical_json(epoch.as_value()) or text != epoch.render():
        _fail("RequiredStatusEpoch representation is not canonical")
    return epoch


_ISSUE_FINALIZATION_EPOCH_FROM_KINDS = frozenset({"ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH"})
_ISSUE_FINALIZATION_EPOCH_KEYS = frozenset({
    "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
    "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
    "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "bindingId",
    "sourceId", "sourceRepositoryId", "pullRequestNumber", "pullRequestDatabaseId",
    "pullRequestNodeId", "centralRepositoryNodeId", "branchRef", "requestClass",
    "acceptedBaseSha", "acceptedBaseTreeSha", "baseRef", "fromHeadSha", "fromTreeSha",
    "finalHeadSha", "finalTreeSha", "carrierRole", "claimKind", "claimGenerationId",
    "transitionKind", "carrierNonce", "fromAuthorityKind", "fromAuthorityCommentDatabaseId",
    "fromAuthorityArtifactId", "fromAuthorityArtifactSha256", "fromAuthorityRole",
    "proposalOriginClaimCommentDatabaseId", "proposalOriginClaimId", "proposalOriginClaimSha256",
    "effectiveRequestDigest", "patchProjectionEvidenceDigest", "claimedTargetEvidenceDigest",
    "freshProposalScopeEvidenceDigest", "authorityPreimageDigest", "finalizerEvidenceDigest",
    "requiredStatusContext", "requiredStatusClass", "requiredStatusState",
    "requiredStatusTargetUrl", "requiredStatusEvidenceDigest", "requiredStatusDescription",
    "markerDigest", "epochId",
})


def _issue_finalization_epoch_preimage_from_fields(fields: Mapping[str, Any]) -> dict[str, Any]:
    request_class = fields["request_class"]
    if type(request_class) is not RequestClass or request_class not in _ISSUE_REQUEST_CLASSES:
        _fail("IssueFinalizationEpoch requestClass must be ADD, UPDATE, or REMOVE")
    return {
        "schemaVersion": fields["schema_version"],
        "issueNumber": fields["issue_number"],
        "issueDatabaseId": fields["issue_database_id"],
        "issueNodeId": fields["issue_node_id"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"],
        "bindingId": fields["binding_id"],
        "sourceId": fields["source_id"],
        "sourceRepositoryId": fields["source_repository_id"],
        "pullRequestNumber": fields["pull_request_number"],
        "pullRequestDatabaseId": fields["pull_request_database_id"],
        "pullRequestNodeId": fields["pull_request_node_id"],
        "centralRepositoryNodeId": fields["central_repository_node_id"],
        "branchRef": fields["branch_ref"],
        "requestClass": request_class.value,
        "acceptedBaseSha": fields["accepted_base_sha"],
        "acceptedBaseTreeSha": fields["accepted_base_tree_sha"],
        "baseRef": fields["base_ref"],
        "fromHeadSha": fields["from_head_sha"],
        "fromTreeSha": fields["from_tree_sha"],
        "fromAuthorityKind": fields["from_authority_kind"],
        "fromAuthorityCommentDatabaseId": fields["from_authority_comment_database_id"],
        "fromAuthorityArtifactId": fields["from_authority_artifact_id"],
        "fromAuthorityArtifactSha256": fields["from_authority_artifact_sha256"],
        "fromAuthorityRole": fields["from_authority_role"],
        "proposalOriginClaimCommentDatabaseId": fields["proposal_origin_claim_comment_database_id"],
        "proposalOriginClaimId": fields["proposal_origin_claim_id"],
        "proposalOriginClaimSha256": fields["proposal_origin_claim_sha256"],
        "effectiveRequestDigest": fields["effective_request_digest"],
        "patchProjectionEvidenceDigest": fields["patch_projection_evidence_digest"],
        "claimedTargetEvidenceDigest": fields["claimed_target_evidence_digest"],
        "freshProposalScopeEvidenceDigest": fields["fresh_proposal_scope_evidence_digest"],
    }


def _issue_finalization_epoch_authority_digest_from_fields(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (ISSUE_FINALIZATION_EPOCH_AUTHORITY_PREFIX + _canonical_json(
            _issue_finalization_epoch_preimage_from_fields(fields)
        )).encode("utf-8")
    ).hexdigest()


def _issue_finalization_epoch_evidence_digest_from_fields(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (ISSUE_FINALIZATION_EPOCH_EVIDENCE_PREFIX + _canonical_json(
            _issue_finalization_epoch_preimage_from_fields(fields)
        )).encode("utf-8")
    ).hexdigest()


def _issue_final_status_evidence_value(fields: Mapping[str, Any]) -> dict[str, Any]:
    request_class = fields["request_class"]
    if type(request_class) is not RequestClass or request_class not in _ISSUE_REQUEST_CLASSES:
        _fail("issue-final evidence requestClass must be ADD, UPDATE, or REMOVE")
    return {
        "centralRepositoryNodeId": fields["central_repository_node_id"],
        "finalHeadSha": fields["final_head_sha"],
        "finalTreeSha": fields["final_tree_sha"],
        "claimGenerationId": fields["claim_generation_id"],
        "markerDigest": fields["marker_digest"],
        "issueNumber": fields["issue_number"],
        "issueDatabaseId": fields["issue_database_id"],
        "issueNodeId": fields["issue_node_id"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"],
        "bindingId": fields["binding_id"],
        "sourceId": fields["source_id"],
        "sourceRepositoryId": fields["source_repository_id"],
        "pullRequestNumber": fields["pull_request_number"],
        "pullRequestDatabaseId": fields["pull_request_database_id"],
        "pullRequestNodeId": fields["pull_request_node_id"],
        "branchRef": fields["branch_ref"],
        "acceptedBaseSha": fields["accepted_base_sha"],
        "acceptedBaseTreeSha": fields["accepted_base_tree_sha"],
        "baseRef": fields["base_ref"],
        "requestClass": request_class.value,
        "fromHeadSha": fields["from_head_sha"],
        "fromTreeSha": fields["from_tree_sha"],
        "fromAuthorityKind": fields["from_authority_kind"],
        "fromAuthorityCommentDatabaseId": fields["from_authority_comment_database_id"],
        "fromAuthorityArtifactId": fields["from_authority_artifact_id"],
        "fromAuthorityArtifactSha256": fields["from_authority_artifact_sha256"],
        "fromAuthorityRole": fields["from_authority_role"],
        "proposalOriginClaimCommentDatabaseId": fields["proposal_origin_claim_comment_database_id"],
        "proposalOriginClaimId": fields["proposal_origin_claim_id"],
        "proposalOriginClaimSha256": fields["proposal_origin_claim_sha256"],
        "effectiveRequestDigest": fields["effective_request_digest"],
        "patchProjectionEvidenceDigest": fields["patch_projection_evidence_digest"],
        "claimedTargetEvidenceDigest": fields["claimed_target_evidence_digest"],
        "freshProposalScopeEvidenceDigest": fields["fresh_proposal_scope_evidence_digest"],
        "finalizerEvidenceDigest": fields["finalizer_evidence_digest"],
        "requiredStatusContext": "federation/trusted-validation",
        "requiredStatusClass": "issue-final",
        "requiredStatusState": "success",
        "requiredStatusTargetUrl": None,
    }


def _issue_final_status_evidence_digest_from_fields(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        (ISSUE_FINAL_STATUS_EVIDENCE_PREFIX + _canonical_json(
            _issue_final_status_evidence_value(fields)
        )).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True)
class IssueFinalizationEpoch:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    binding_id: str
    source_id: str
    source_repository_id: int
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    central_repository_node_id: str
    branch_ref: str
    request_class: RequestClass
    accepted_base_sha: str
    accepted_base_tree_sha: str
    base_ref: str
    from_head_sha: str
    from_tree_sha: str
    final_head_sha: str
    final_tree_sha: str
    carrier_role: str
    claim_kind: str
    claim_generation_id: str
    transition_kind: str
    carrier_nonce: str
    from_authority_kind: str
    from_authority_comment_database_id: int
    from_authority_artifact_id: str
    from_authority_artifact_sha256: str
    from_authority_role: str
    proposal_origin_claim_comment_database_id: int
    proposal_origin_claim_id: str
    proposal_origin_claim_sha256: str
    effective_request_digest: str
    patch_projection_evidence_digest: str
    claimed_target_evidence_digest: str
    fresh_proposal_scope_evidence_digest: str
    authority_preimage_digest: str
    finalizer_evidence_digest: str
    required_status_context: str
    required_status_class: str
    required_status_state: str
    required_status_target_url: None
    required_status_evidence_digest: str
    required_status_description: str
    marker_digest: str
    epoch_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueFinalizationEpoch schemaVersion must be exact integer 1")
        for name in (
            "issue_number", "issue_database_id", "issue_request_anchor_comment_database_id",
            "issue_branch_lease_comment_database_id", "source_repository_id", "pull_request_number",
            "pull_request_database_id", "from_authority_comment_database_id",
            "proposal_origin_claim_comment_database_id",
        ):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_node_id", "pull_request_node_id", "central_repository_node_id"):
            _lease_node_id(getattr(self, name), name, delimiter_free=True)
        for name in (
            "issue_request_anchor_sha256", "issue_branch_lease_sha256", "binding_id",
            "claim_generation_id", "carrier_nonce", "from_authority_artifact_id",
            "from_authority_artifact_sha256", "proposal_origin_claim_id", "proposal_origin_claim_sha256",
            "effective_request_digest", "patch_projection_evidence_digest", "claimed_target_evidence_digest",
            "fresh_proposal_scope_evidence_digest", "authority_preimage_digest", "finalizer_evidence_digest",
            "required_status_evidence_digest", "marker_digest", "epoch_id",
        ):
            _lease_sha(getattr(self, name), name)
        try:
            c02.validate_source_id(self.source_id)
        except (TypeError, c02.FederationError):
            _fail("sourceId is invalid")
        if type(self.branch_ref) is not str or self.branch_ref != issue_branch_ref(self.issue_number):
            _fail("branchRef must be the exact Issue branch ref")
        if type(self.request_class) is not RequestClass or self.request_class not in _ISSUE_REQUEST_CLASSES:
            _fail("requestClass must be ADD, UPDATE, or REMOVE")
        for name in (
            "accepted_base_sha", "accepted_base_tree_sha", "from_head_sha", "from_tree_sha",
            "final_head_sha", "final_tree_sha",
        ):
            _lease_sha(getattr(self, name), name, git=True)
        if self.base_ref != "main":
            _fail("baseRef must be exact main")
        if self.final_tree_sha != self.from_tree_sha:
            _fail("IssueFinalizationEpoch must preserve the exact from-tree")
        if self.carrier_role != "ISSUE_FINALIZING":
            _fail("IssueFinalizationEpoch carrierRole must be ISSUE_FINALIZING")
        if self.claim_kind != "ISSUE_FINALIZATION_EPOCH":
            _fail("IssueFinalizationEpoch claimKind must be ISSUE_FINALIZATION_EPOCH")
        if self.transition_kind != "FINALIZE":
            _fail("IssueFinalizationEpoch transitionKind must be exact FINALIZE")
        _lease_sha(self.carrier_nonce, "carrierNonce")
        if self.from_authority_kind not in _ISSUE_FINALIZATION_EPOCH_FROM_KINDS:
            _fail("IssueFinalizationEpoch immediate authority kind is unsupported")
        _lease_sha(self.from_authority_artifact_id, "fromAuthorityArtifactId")
        _lease_sha(self.from_authority_artifact_sha256, "fromAuthorityArtifactSha256")
        if self.from_authority_role != "ISSUE_ACTIVE":
            _fail("IssueFinalizationEpoch immediate authority role must be ISSUE_ACTIVE")
        _lease_sha(self.proposal_origin_claim_id, "proposalOriginClaimId")
        _lease_sha(self.proposal_origin_claim_sha256, "proposalOriginClaimSha256")
        if self.from_authority_kind == "ISSUE_HEAD_CLAIM" and (
            self.from_authority_comment_database_id != self.proposal_origin_claim_comment_database_id
            or self.from_authority_artifact_id != self.proposal_origin_claim_id
            or self.from_authority_artifact_sha256 != self.proposal_origin_claim_sha256
        ):
            _fail("direct IssueHeadClaim authority must equal exact proposal-origin claim")
        if self.claimed_target_evidence_digest != self.fresh_proposal_scope_evidence_digest:
            _fail("claimed target evidence must equal freshly rederived proposal scope")
        if self.required_status_context != "federation/trusted-validation":
            _fail("required status context must be exact federation/trusted-validation")
        if self.required_status_class != "issue-final":
            _fail("required status class must be exact issue-final")
        if self.required_status_state != "success":
            _fail("required status state must be exact success")
        if self.required_status_target_url is not None:
            _fail("required status target_url must be null")
        expected_authority = _issue_finalization_epoch_authority_digest_from_fields(self._fields())
        if self.authority_preimage_digest != expected_authority:
            _fail("IssueFinalizationEpoch authorityPreimageDigest does not match finalizer authority")
        expected_finalizer_evidence = _issue_finalization_epoch_evidence_digest_from_fields(self._fields())
        if self.finalizer_evidence_digest != expected_finalizer_evidence:
            _fail("IssueFinalizationEpoch finalizerEvidenceDigest does not match exact pre-HF evidence")
        expected_generation = claim_generation_id(
            authority_preimage_digest=self.authority_preimage_digest,
            carrier_nonce=self.carrier_nonce,
            central_repository_node_id=self.central_repository_node_id,
            owner_key=issue_owner_key(
                self.central_repository_node_id, self.issue_database_id, self.issue_node_id, self.issue_number,
            ),
            from_head_sha=self.from_head_sha,
            from_tree_sha=self.from_tree_sha,
            claim_kind=self.claim_kind,
            role=self.carrier_role,
            owner_kind="ISSUE",
            transition_kind=self.transition_kind,
        )
        if self.claim_generation_id != expected_generation:
            _fail("IssueFinalizationEpoch claimGenerationId does not match finalizer authority")
        marker = ClaimedHeadMarker(
            self.claim_kind, self.carrier_role, "ISSUE",
            issue_owner_key(self.central_repository_node_id, self.issue_database_id, self.issue_node_id, self.issue_number),
            self.claim_generation_id, self.carrier_nonce, self.transition_kind,
        )
        if self.marker_digest != hashlib.sha256(marker.render().encode("utf-8")).hexdigest():
            _fail("IssueFinalizationEpoch markerDigest does not match canonical generation marker")
        expected_status_digest = _issue_final_status_evidence_digest_from_fields(self._fields())
        if self.required_status_evidence_digest != expected_status_digest:
            _fail("IssueFinalizationEpoch issue-final evidence digest does not match full provenance")
        expected_description = render_status_description(StatusClass.ISSUE_FINAL, expected_status_digest)
        if self.required_status_description != expected_description:
            _fail("IssueFinalizationEpoch required status description is not exact")
        if len(self.required_status_description.encode("ascii")) != 86:
            _fail("IssueFinalizationEpoch issue-final description must be exactly 86 ASCII bytes")
        expected_epoch_id = hashlib.sha256(
            (ISSUE_FINALIZATION_EPOCH_ID_PREFIX + _canonical_json(self.as_value(include_epoch_id=False))).encode("utf-8")
        ).hexdigest()
        if self.epoch_id != expected_epoch_id:
            _fail("IssueFinalizationEpoch epochId does not match canonical final body")

    def _fields(self) -> dict[str, Any]:
        return {
            name: getattr(self, name)
            for name in (
                "schema_version", "issue_number", "issue_database_id", "issue_node_id",
                "issue_request_anchor_comment_database_id", "issue_request_anchor_sha256",
                "issue_branch_lease_comment_database_id", "issue_branch_lease_sha256", "binding_id",
                "source_id", "source_repository_id", "pull_request_number", "pull_request_database_id",
                "pull_request_node_id", "central_repository_node_id", "branch_ref", "request_class",
                "accepted_base_sha", "accepted_base_tree_sha", "base_ref", "from_head_sha", "from_tree_sha",
                "final_head_sha", "final_tree_sha", "carrier_role", "claim_kind", "claim_generation_id",
                "transition_kind", "carrier_nonce", "from_authority_kind", "from_authority_comment_database_id",
                "from_authority_artifact_id", "from_authority_artifact_sha256", "from_authority_role",
                "proposal_origin_claim_comment_database_id", "proposal_origin_claim_id", "proposal_origin_claim_sha256",
                "effective_request_digest", "patch_projection_evidence_digest", "claimed_target_evidence_digest",
                "fresh_proposal_scope_evidence_digest", "authority_preimage_digest", "finalizer_evidence_digest",
                "required_status_context", "required_status_class", "required_status_state", "required_status_target_url",
                "required_status_evidence_digest", "required_status_description", "marker_digest", "epoch_id",
            )
        }

    def authority_preimage_value(self) -> dict[str, Any]:
        return _issue_finalization_epoch_preimage_from_fields(self._fields())

    def as_value(self, *, include_epoch_id: bool = True) -> dict[str, Any]:
        value = {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256,
            "issueBranchLeaseCommentDatabaseId": self.issue_branch_lease_comment_database_id,
            "issueBranchLeaseSha256": self.issue_branch_lease_sha256,
            "bindingId": self.binding_id,
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "pullRequestNumber": self.pull_request_number,
            "pullRequestDatabaseId": self.pull_request_database_id,
            "pullRequestNodeId": self.pull_request_node_id,
            "centralRepositoryNodeId": self.central_repository_node_id,
            "branchRef": self.branch_ref,
            "requestClass": self.request_class.value,
            "acceptedBaseSha": self.accepted_base_sha,
            "acceptedBaseTreeSha": self.accepted_base_tree_sha,
            "baseRef": self.base_ref,
            "fromHeadSha": self.from_head_sha,
            "fromTreeSha": self.from_tree_sha,
            "finalHeadSha": self.final_head_sha,
            "finalTreeSha": self.final_tree_sha,
            "carrierRole": self.carrier_role,
            "claimKind": self.claim_kind,
            "claimGenerationId": self.claim_generation_id,
            "transitionKind": self.transition_kind,
            "carrierNonce": self.carrier_nonce,
            "fromAuthorityKind": self.from_authority_kind,
            "fromAuthorityCommentDatabaseId": self.from_authority_comment_database_id,
            "fromAuthorityArtifactId": self.from_authority_artifact_id,
            "fromAuthorityArtifactSha256": self.from_authority_artifact_sha256,
            "fromAuthorityRole": self.from_authority_role,
            "proposalOriginClaimCommentDatabaseId": self.proposal_origin_claim_comment_database_id,
            "proposalOriginClaimId": self.proposal_origin_claim_id,
            "proposalOriginClaimSha256": self.proposal_origin_claim_sha256,
            "effectiveRequestDigest": self.effective_request_digest,
            "patchProjectionEvidenceDigest": self.patch_projection_evidence_digest,
            "claimedTargetEvidenceDigest": self.claimed_target_evidence_digest,
            "freshProposalScopeEvidenceDigest": self.fresh_proposal_scope_evidence_digest,
            "authorityPreimageDigest": self.authority_preimage_digest,
            "finalizerEvidenceDigest": self.finalizer_evidence_digest,
            "requiredStatusContext": self.required_status_context,
            "requiredStatusClass": self.required_status_class,
            "requiredStatusState": self.required_status_state,
            "requiredStatusTargetUrl": self.required_status_target_url,
            "requiredStatusEvidenceDigest": self.required_status_evidence_digest,
            "requiredStatusDescription": self.required_status_description,
            "markerDigest": self.marker_digest,
        }
        if include_epoch_id:
            value["epochId"] = self.epoch_id
        return value

    @classmethod
    def create(cls, **fields: Any) -> "IssueFinalizationEpoch":
        body = dict(fields)
        body.setdefault("schema_version", 1)
        body.setdefault("carrier_role", "ISSUE_FINALIZING")
        body.setdefault("claim_kind", "ISSUE_FINALIZATION_EPOCH")
        body.setdefault("transition_kind", "FINALIZE")
        required = {
            "schema_version", "issue_number", "issue_database_id", "issue_node_id",
            "issue_request_anchor_comment_database_id", "issue_request_anchor_sha256",
            "issue_branch_lease_comment_database_id", "issue_branch_lease_sha256", "binding_id",
            "source_id", "source_repository_id", "pull_request_number", "pull_request_database_id",
            "pull_request_node_id", "central_repository_node_id", "branch_ref", "request_class",
            "accepted_base_sha", "accepted_base_tree_sha", "base_ref", "from_head_sha", "from_tree_sha",
            "final_head_sha", "final_tree_sha", "carrier_role", "claim_kind", "transition_kind",
            "carrier_nonce", "from_authority_kind", "from_authority_comment_database_id",
            "from_authority_artifact_id", "from_authority_artifact_sha256", "from_authority_role",
            "proposal_origin_claim_comment_database_id", "proposal_origin_claim_id", "proposal_origin_claim_sha256",
            "effective_request_digest", "patch_projection_evidence_digest", "claimed_target_evidence_digest",
            "fresh_proposal_scope_evidence_digest",
        }
        if set(body) != required:
            _fail("IssueFinalizationEpoch.create fields do not match the construction schema")
        authority = _issue_finalization_epoch_authority_digest_from_fields(body)
        finalizer_digest = _issue_finalization_epoch_evidence_digest_from_fields(body)
        generation = claim_generation_id(
            authority_preimage_digest=authority,
            carrier_nonce=body["carrier_nonce"],
            central_repository_node_id=body["central_repository_node_id"],
            owner_key=issue_owner_key(
                body["central_repository_node_id"], body["issue_database_id"],
                body["issue_node_id"], body["issue_number"],
            ),
            from_head_sha=body["from_head_sha"],
            from_tree_sha=body["from_tree_sha"],
            claim_kind=body["claim_kind"],
            role=body["carrier_role"],
            owner_kind="ISSUE",
            transition_kind=body["transition_kind"],
        )
        marker = ClaimedHeadMarker(
            body["claim_kind"], body["carrier_role"], "ISSUE",
            issue_owner_key(body["central_repository_node_id"], body["issue_database_id"], body["issue_node_id"], body["issue_number"]),
            generation, body["carrier_nonce"], body["transition_kind"],
        )
        marker_digest = hashlib.sha256(marker.render().encode("utf-8")).hexdigest()
        values = dict(body)
        values.update({
            "claim_generation_id": generation,
            "authority_preimage_digest": authority,
            "finalizer_evidence_digest": finalizer_digest,
            "marker_digest": marker_digest,
            "required_status_context": "federation/trusted-validation",
            "required_status_class": "issue-final",
            "required_status_state": "success",
            "required_status_target_url": None,
        })
        values["required_status_evidence_digest"] = _issue_final_status_evidence_digest_from_fields(values)
        values["required_status_description"] = render_status_description(
            StatusClass.ISSUE_FINAL, values["required_status_evidence_digest"]
        )
        provisional = cls.__new__(cls)
        for name, value in values.items():
            object.__setattr__(provisional, name, value)
        epoch_id = hashlib.sha256(
            (ISSUE_FINALIZATION_EPOCH_ID_PREFIX + _canonical_json(provisional.as_value(include_epoch_id=False))).encode("utf-8")
        ).hexdigest()
        values["epoch_id"] = epoch_id
        return cls(**values)

    def render(self) -> str:
        return f"{ISSUE_FINALIZATION_EPOCH_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def issue_final_status_evidence_digest(epoch: IssueFinalizationEpoch) -> str:
    if type(epoch) is not IssueFinalizationEpoch:
        _fail("issue-final status evidence digest requires an IssueFinalizationEpoch")
    return _issue_final_status_evidence_digest_from_fields(epoch._fields())


def parse_issue_finalization_epoch(text: str) -> IssueFinalizationEpoch:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("IssueFinalizationEpoch must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    if len(lines) != 2 or lines[0] != ISSUE_FINALIZATION_EPOCH_MARKER or not lines[1]:
        _fail("IssueFinalizationEpoch marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid IssueFinalizationEpoch JSON: {error}")
    if type(value) is not dict or set(value) != _ISSUE_FINALIZATION_EPOCH_KEYS:
        _fail("IssueFinalizationEpoch has invalid exact keys")
    try:
        request_class = _ISSUE_REQUEST_CLASS_VALUES[value["requestClass"]]
    except (KeyError, TypeError):
        _fail("IssueFinalizationEpoch requestClass is invalid")
    epoch = IssueFinalizationEpoch(
        value["schemaVersion"], value["issueNumber"], value["issueDatabaseId"], value["issueNodeId"],
        value["issueRequestAnchorCommentDatabaseId"], value["issueRequestAnchorSha256"],
        value["issueBranchLeaseCommentDatabaseId"], value["issueBranchLeaseSha256"], value["bindingId"],
        value["sourceId"], value["sourceRepositoryId"], value["pullRequestNumber"],
        value["pullRequestDatabaseId"], value["pullRequestNodeId"], value["centralRepositoryNodeId"],
        value["branchRef"], request_class, value["acceptedBaseSha"], value["acceptedBaseTreeSha"],
        value["baseRef"], value["fromHeadSha"], value["fromTreeSha"], value["finalHeadSha"],
        value["finalTreeSha"], value["carrierRole"], value["claimKind"], value["claimGenerationId"],
        value["transitionKind"], value["carrierNonce"], value["fromAuthorityKind"],
        value["fromAuthorityCommentDatabaseId"], value["fromAuthorityArtifactId"],
        value["fromAuthorityArtifactSha256"], value["fromAuthorityRole"],
        value["proposalOriginClaimCommentDatabaseId"], value["proposalOriginClaimId"],
        value["proposalOriginClaimSha256"], value["effectiveRequestDigest"],
        value["patchProjectionEvidenceDigest"], value["claimedTargetEvidenceDigest"],
        value["freshProposalScopeEvidenceDigest"], value["authorityPreimageDigest"],
        value["finalizerEvidenceDigest"], value["requiredStatusContext"], value["requiredStatusClass"],
        value["requiredStatusState"], value["requiredStatusTargetUrl"], value["requiredStatusEvidenceDigest"],
        value["requiredStatusDescription"], value["markerDigest"], value["epochId"],
    )
    if lines[1] != _canonical_json(epoch.as_value()) or text != epoch.render():
        _fail("IssueFinalizationEpoch representation is not canonical")
    return epoch


def parse_exact_app_required_status_evidence(text: str) -> ExactAppRequiredStatusEvidence:
    if type(text) is not str or "\r" in text or "\x00" in text:
        _fail("prior required status evidence must be exact canonical JSON")
    try:
        value = c02.decode_json(text)
    except Exception as error:
        _fail(f"invalid prior required status evidence JSON: {error}")
    evidence = ExactAppRequiredStatusEvidence.from_value(value)
    if evidence.render() != text:
        _fail("prior required status evidence is not canonical")
    return evidence


def classify_issue_head_claim_progression(
    historical_claim: IssueHeadClaim,
    *,
    fresh_effective_request_digest: str,
    fresh_patch_projection_evidence_digest: str,
    fresh_accepted_base_sha: str,
    fresh_accepted_base_tree_sha: str,
    proposal_exists: bool,
) -> str | None:
    """Compare fresh progression authority to an immutable historical active claim."""
    if type(historical_claim) is not IssueHeadClaim:
        _fail("fresh progression comparison requires an IssueHeadClaim")
    for value, label in (
        (fresh_effective_request_digest, "effectiveRequestDigest"),
        (fresh_patch_projection_evidence_digest, "patchProjectionEvidenceDigest"),
    ):
        if type(value) is not str or not _SHA256_RE.fullmatch(value):
            _fail(f"fresh {label} must be lowercase 64-hex")
    for value, label in (
        (fresh_accepted_base_sha, "acceptedBaseSha"),
        (fresh_accepted_base_tree_sha, "acceptedBaseTreeSha"),
    ):
        if type(value) is not str or not _SHA40_RE.fullmatch(value):
            _fail(f"fresh {label} must be lowercase 40-hex")
    if type(proposal_exists) is not bool:
        _fail("proposal_exists must be boolean")
    if (
        fresh_effective_request_digest != historical_claim.effective_request_digest
        or fresh_patch_projection_evidence_digest != historical_claim.patch_projection_evidence_digest
    ):
        return "PATCH_REGENERATION"
    if (
        fresh_accepted_base_sha != historical_claim.accepted_base_sha
        or fresh_accepted_base_tree_sha != historical_claim.accepted_base_tree_sha
    ):
        return "MAIN_ADVANCE"
    if historical_claim.transition_kind == "NORMALIZE" and not proposal_exists:
        return "PROPOSAL"
    return None


@dataclass(frozen=True)
class IssueBranchLease:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    source_id: str
    source_repository_id: int
    central_repository_node_id: str
    branch_ref: str
    accepted_base_sha: str
    carrier_role: str
    claim_kind: str
    claim_generation_id: str
    carrier_nonce: str
    authority_preimage_digest: str
    initial_head_sha: str
    initial_head_tree_sha: str
    initial_head_parent_sha: str
    initial_head_marker_digest: str
    request_class: RequestClass
    lease_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueBranchLease schemaVersion must be exact integer 1")
        _lease_decimal(self.issue_number, "issueNumber")
        _lease_decimal(self.issue_database_id, "issueDatabaseId")
        _lease_node_id(self.issue_node_id, "issueNodeId", delimiter_free=True)
        _lease_decimal(self.issue_request_anchor_comment_database_id, "issueRequestAnchorCommentDatabaseId")
        _lease_sha(self.issue_request_anchor_sha256, "issueRequestAnchorSha256")
        try:
            c02.validate_source_id(self.source_id)
        except (TypeError, c02.FederationError):
            _fail("sourceId is invalid")
        _lease_decimal(self.source_repository_id, "sourceRepositoryId")
        _lease_node_id(self.central_repository_node_id, "centralRepositoryNodeId", delimiter_free=True)
        expected_ref = issue_branch_ref(self.issue_number)
        if type(self.branch_ref) is not str or self.branch_ref != expected_ref:
            _fail("branchRef must be the exact reserved Issue branch ref")
        _lease_sha(self.accepted_base_sha, "acceptedBaseSha", git=True)
        if self.carrier_role != "ISSUE_ACTIVE":
            _fail("carrierRole must be ISSUE_ACTIVE")
        if self.claim_kind != "ISSUE_BRANCH_LEASE":
            _fail("claimKind must be ISSUE_BRANCH_LEASE")
        _lease_sha(self.claim_generation_id, "claimGenerationId")
        _lease_sha(self.carrier_nonce, "carrierNonce")
        _lease_sha(self.authority_preimage_digest, "authorityPreimageDigest")
        _lease_sha(self.initial_head_sha, "initialHeadSha", git=True)
        _lease_sha(self.initial_head_tree_sha, "initialHeadTreeSha", git=True)
        _lease_sha(self.initial_head_parent_sha, "initialHeadParentSha", git=True)
        if self.initial_head_parent_sha != self.accepted_base_sha:
            _fail("initialHeadParentSha must equal acceptedBaseSha")
        _lease_sha(self.initial_head_marker_digest, "initialHeadMarkerDigest")
        if type(self.request_class) is not RequestClass or self.request_class not in _ISSUE_REQUEST_CLASSES:
            _fail("requestClass must be ADD, UPDATE, or REMOVE")
        _lease_sha(self.lease_id, "leaseId")
        expected_id = hashlib.sha256(_canonical_json(self._body_without_id()).encode("utf-8")).hexdigest()
        if self.lease_id != expected_id:
            _fail("IssueBranchLease leaseId does not match canonical body")

    def _body_without_id(self) -> dict[str, Any]:
        value = self.as_value()
        value.pop("leaseId", None)
        return value

    def as_value(self) -> dict[str, Any]:
        return {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256,
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "centralRepositoryNodeId": self.central_repository_node_id,
            "branchRef": self.branch_ref,
            "acceptedBaseSha": self.accepted_base_sha,
            "carrierRole": self.carrier_role,
            "claimKind": self.claim_kind,
            "claimGenerationId": self.claim_generation_id,
            "carrierNonce": self.carrier_nonce,
            "authorityPreimageDigest": self.authority_preimage_digest,
            "initialHeadSha": self.initial_head_sha,
            "initialHeadTreeSha": self.initial_head_tree_sha,
            "initialHeadParentSha": self.initial_head_parent_sha,
            "initialHeadMarkerDigest": self.initial_head_marker_digest,
            "requestClass": self.request_class.value,
            "leaseId": self.lease_id,
        }

    @classmethod
    def create(cls, **fields: Any) -> "IssueBranchLease":
        body = dict(fields)
        body["lease_id"] = hashlib.sha256(_canonical_json(_lease_fields_to_value(body, include_id=False)).encode("utf-8")).hexdigest()
        return cls(**body)

    def render(self) -> str:
        return f"{ISSUE_BRANCH_LEASE_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def _lease_fields_to_value(fields: Mapping[str, Any], *, include_id: bool) -> dict[str, Any]:
    key_map = {
        "schema_version": "schemaVersion", "issue_number": "issueNumber",
        "issue_database_id": "issueDatabaseId", "issue_node_id": "issueNodeId",
        "issue_request_anchor_comment_database_id": "issueRequestAnchorCommentDatabaseId",
        "issue_request_anchor_sha256": "issueRequestAnchorSha256", "source_id": "sourceId",
        "source_repository_id": "sourceRepositoryId", "central_repository_node_id": "centralRepositoryNodeId",
        "branch_ref": "branchRef", "accepted_base_sha": "acceptedBaseSha",
        "carrier_role": "carrierRole", "claim_kind": "claimKind",
        "claim_generation_id": "claimGenerationId", "carrier_nonce": "carrierNonce",
        "authority_preimage_digest": "authorityPreimageDigest", "initial_head_sha": "initialHeadSha",
        "initial_head_tree_sha": "initialHeadTreeSha", "initial_head_parent_sha": "initialHeadParentSha",
        "initial_head_marker_digest": "initialHeadMarkerDigest", "request_class": "requestClass",
        "lease_id": "leaseId",
    }
    result: dict[str, Any] = {}
    for key, value in fields.items():
        if key not in key_map or (key == "lease_id" and not include_id):
            continue
        result[key_map[key]] = value.value if isinstance(value, RequestClass) else value
    return result


def parse_issue_branch_lease(text: str) -> IssueBranchLease:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("IssueBranchLease must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    if len(lines) != 2 or lines[0] != ISSUE_BRANCH_LEASE_MARKER or not lines[1]:
        _fail("IssueBranchLease marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid IssueBranchLease JSON: {error}")
    if type(value) is not dict or set(value) != _LEASE_KEYS:
        _fail("IssueBranchLease has invalid exact keys")
    try:
        request_class = _ISSUE_REQUEST_CLASS_VALUES[value["requestClass"]]
    except (KeyError, TypeError):
        _fail("IssueBranchLease requestClass is invalid")
    lease = IssueBranchLease(
        value["schemaVersion"], value["issueNumber"], value["issueDatabaseId"], value["issueNodeId"],
        value["issueRequestAnchorCommentDatabaseId"], value["issueRequestAnchorSha256"], value["sourceId"],
        value["sourceRepositoryId"], value["centralRepositoryNodeId"], value["branchRef"],
        value["acceptedBaseSha"], value["carrierRole"], value["claimKind"], value["claimGenerationId"],
        value["carrierNonce"], value["authorityPreimageDigest"], value["initialHeadSha"],
        value["initialHeadTreeSha"], value["initialHeadParentSha"], value["initialHeadMarkerDigest"],
        request_class, value["leaseId"],
    )
    if lines[1] != _canonical_json(lease.as_value()) or text != lease.render():
        _fail("IssueBranchLease representation is not canonical")
    return lease

# G8 Wave 07 cancellation artifacts are transport-independent canonical models.
ISSUE_CANCELLATION_FENCE_MARKER = "<!-- swiftstream-federation-issue-cancellation-fence:v1 -->"
ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER = "<!-- swiftstream-federation-issue-cancellation-draft-witness:v1 -->"
ISSUE_TERMINAL_CANCELLED_RESULT_MARKER = "<!-- swiftstream-federation-terminal-cancelled-result:v1 -->"
ISSUE_NO_PR_CANCELLED_RESULT_MARKER = "<!-- swiftstream-federation-no-pr-cancelled-result:v1 -->"
ISSUE_CANCELLATION_FENCE_AUTHORITY_PREFIX = "swiftstream-federation:issue-cancellation-fence:authority:v1\n"
ISSUE_CANCELLATION_FENCE_ID_PREFIX = "swiftstream-federation:issue-cancellation-fence:id:v1\n"
CANCEL_STATUS_EVIDENCE_PREFIX = "swiftstream-federation:cancel-status-evidence:v1\n"
EXACT_APP_REQUIRED_STATUS_SNAPSHOT_PREFIX = "swiftstream-federation:exact-app-required-status-snapshot:v1\n"
EXACT_PR_STAGE_MUTATION_EVIDENCE_PREFIX = "swiftstream-federation:pr-stage-mutation-evidence:v1\n"
ISSUE_CANCELLATION_DRAFT_WITNESS_ID_PREFIX = "swiftstream-federation:issue-cancellation-draft-witness:v1\n"
ISSUE_TERMINAL_CANCELLED_CLOSE_RESPONSE_PREFIX = "swiftstream-federation:terminal-cancelled-close-response:v1\n"
ISSUE_TERMINAL_CANCELLED_RESULT_ID_PREFIX = "swiftstream-federation:terminal-cancelled-result:v1\n"
ISSUE_NO_PR_CANCELLED_RESULT_ID_PREFIX = "swiftstream-federation:no-pr-cancelled-result:v1\n"


def _cancel_binding_authority(value: Any) -> str:
    if value == "PRE_BINDING" and type(value) is str:
        return value
    if type(value) is str and _SHA256_RE.fullmatch(value):
        return value
    _fail("bindingAuthority must be PRE_BINDING or a lowercase bindingId")


def _cancel_source_id(value: Any) -> str:
    if type(value) is not str:
        _fail("sourceId is invalid")
    try:
        c02.validate_source_id(value)
    except (TypeError, c02.FederationError):
        _fail("sourceId is invalid")
    return value


def _cancel_optional_url(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _issue_bounded_text(value, label, 2_048)


def _cancel_parse_record(text: Any, marker: str, label: str, expected_keys: set[str] | frozenset[str]) -> dict[str, Any]:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail(f"{label} must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    if len(lines) != 2 or lines[0] != marker or not lines[1]:
        _fail(f"{label} marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid {label} JSON: {error}")
    if type(value) is not dict or set(value) != set(expected_keys):
        _fail(f"{label} has invalid exact keys")
    return value


def _cancel_status_fields_value(snapshot: "ExactAppRequiredStatusSnapshot") -> dict[str, Any]:
    return snapshot.as_value()


@dataclass(frozen=True)
class ExactAppRequiredStatusSnapshot:
    """Exact queried-route association and same-response App status snapshot."""

    disposition: str
    queried_sha: str
    status_id: int | None = None
    status_node_id: str | None = None
    creator_database_id: int | None = None
    creator_node_id: str | None = None
    creator_login: str | None = None
    creator_type: str | None = None
    context: str | None = None
    state: str | None = None
    description: str | None = None
    target_url: str | None = None
    created_at: str | None = None
    updated_at: str | None = None
    parsed_status_class: StatusClass | None = None
    parsed_evidence_digest: str | None = None

    def __post_init__(self) -> None:
        if self.disposition not in ("ABSENT", "PRESENT") or type(self.disposition) is not str:
            _fail("required status snapshot disposition must be ABSENT or PRESENT")
        _lease_sha(self.queried_sha, "queriedSha", git=True)
        names = (
            "status_id", "status_node_id", "creator_database_id", "creator_node_id",
            "creator_login", "creator_type", "context", "state", "description",
            "target_url", "created_at", "updated_at", "parsed_status_class", "parsed_evidence_digest",
        )
        if self.disposition == "ABSENT":
            if any(getattr(self, name) is not None for name in names):
                _fail("ABSENT required status snapshot must explicitly null every status field")
            return
        _issue_positive_int(self.status_id, "statusId")
        if self.status_node_id is not None:
            _lease_node_id(self.status_node_id, "statusNodeId", delimiter_free=True)
        _issue_positive_int(self.creator_database_id, "creatorDatabaseId")
        _lease_node_id(self.creator_node_id, "creatorNodeId", delimiter_free=True)
        _issue_bounded_text(self.creator_login, "creatorLogin", 256)
        if self.creator_type != "Bot":
            _fail("required status creator type must be exact Bot")
        if self.context != "federation/trusted-validation":
            _fail("required status context must be exact federation/trusted-validation")
        if self.state not in ("error", "failure", "pending", "success") or type(self.state) is not str:
            _fail("required status state is invalid")
        parsed = parse_status_description(self.description)
        if parsed.render() != self.description:
            _fail("required status description is not canonical")
        if type(self.parsed_status_class) is not StatusClass or self.parsed_status_class is not parsed.status_class:
            _fail("required status parsed StatusClass does not match description")
        _lease_sha(self.parsed_evidence_digest, "parsedEvidenceDigest")
        if self.parsed_evidence_digest != parsed.evidence_digest:
            _fail("required status parsed evidence digest does not match description")
        _cancel_optional_url(self.target_url, "targetUrl")
        _canonical_utc_timestamp(self.created_at, "createdAt")
        _canonical_utc_timestamp(self.updated_at, "updatedAt")

    @property
    def is_present(self) -> bool:
        return self.disposition == "PRESENT"

    @property
    def status_class(self) -> StatusClass | None:
        return self.parsed_status_class if self.is_present else None

    @property
    def evidence_digest(self) -> str | None:
        return self.parsed_evidence_digest if self.is_present else None

    @classmethod
    def absent(cls, queried_sha: str) -> "ExactAppRequiredStatusSnapshot":
        return cls("ABSENT", queried_sha)

    @classmethod
    def present_status(cls, **fields: Any) -> "ExactAppRequiredStatusSnapshot":
        parsed = parse_status_description(fields["description"])
        fields.setdefault("parsed_status_class", parsed.status_class)
        fields.setdefault("parsed_evidence_digest", parsed.evidence_digest)
        return cls("PRESENT", **fields)

    def as_value(self) -> dict[str, Any]:
        return {
            "context": self.context,
            "createdAt": self.created_at,
            "creatorDatabaseId": self.creator_database_id,
            "creatorLogin": self.creator_login,
            "creatorNodeId": self.creator_node_id,
            "creatorType": self.creator_type,
            "description": self.description,
            "disposition": self.disposition,
            "queriedSha": self.queried_sha,
            "parsedStatusClass": self.parsed_status_class.value if self.parsed_status_class else None,
            "parsedEvidenceDigest": self.parsed_evidence_digest,
            "state": self.state,
            "statusId": self.status_id,
            "statusNodeId": self.status_node_id,
            "targetUrl": self.target_url,
            "updatedAt": self.updated_at,
        }

    def render(self) -> str:
        return _canonical_json(self.as_value())

    def canonical_sha256(self) -> str:
        return hashlib.sha256((EXACT_APP_REQUIRED_STATUS_SNAPSHOT_PREFIX + self.render()).encode("utf-8")).hexdigest()

    @classmethod
    def from_value(cls, value: Any) -> "ExactAppRequiredStatusSnapshot":
        expected = {
            "disposition", "queriedSha", "statusId", "statusNodeId", "creatorDatabaseId",
            "creatorNodeId", "creatorLogin", "creatorType", "context", "state",
            "description", "targetUrl", "createdAt", "updatedAt",
            "parsedStatusClass", "parsedEvidenceDigest",
        }
        if type(value) is not dict or set(value) != expected:
            _fail("required status snapshot has invalid exact keys")
        try:
            parsed_class = StatusClass(value["parsedStatusClass"]) if value["parsedStatusClass"] is not None else None
        except (ValueError, TypeError):
            _fail("required status parsed StatusClass is invalid")
        return cls(
            value["disposition"], value["queriedSha"], value["statusId"], value["statusNodeId"],
            value["creatorDatabaseId"], value["creatorNodeId"], value["creatorLogin"],
            value["creatorType"], value["context"], value["state"], value["description"],
            value["targetUrl"], value["createdAt"], value["updatedAt"], parsed_class, value["parsedEvidenceDigest"],
        )


def parse_exact_app_required_status_snapshot(text: str) -> ExactAppRequiredStatusSnapshot:
    if type(text) is not str or "\r" in text or "\x00" in text:
        _fail("required status snapshot must be exact canonical JSON")
    try:
        value = c02.decode_json(text)
    except Exception as error:
        _fail(f"invalid required status snapshot JSON: {error}")
    snapshot = ExactAppRequiredStatusSnapshot.from_value(value)
    if snapshot.render() != text:
        _fail("required status snapshot representation is not canonical")
    return snapshot


class PullRequestStageMutationOperation(Enum):
    REOPEN = "REOPEN"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    CONVERT_TO_DRAFT = "CONVERT_TO_DRAFT"
    CLOSE = "CLOSE"


@dataclass(frozen=True)
class ExactPullRequestStageMutationEvidence:
    """Canonical transport-independent fields returned by one PR-stage mutation."""

    operation: PullRequestStageMutationOperation
    client_mutation_id: str
    pull_request_node_id: str
    pull_request_database_id: int
    pull_request_number: int
    state: str
    is_draft: bool
    merged: bool
    merged_at: str | None
    head_ref_oid: str
    base_ref_oid: str
    head_ref_name: str
    base_ref_name: str
    head_repository_node_id: str
    base_repository_node_id: str

    def __post_init__(self) -> None:
        if type(self.operation) is not PullRequestStageMutationOperation:
            _fail("stage mutation operation must be a closed operation enum")
        _issue_bounded_text(self.client_mutation_id, "clientMutationId", 256)
        _lease_node_id(self.pull_request_node_id, "pullRequestNodeId", delimiter_free=True)
        _issue_positive_int(self.pull_request_database_id, "pullRequestDatabaseId")
        _issue_positive_int(self.pull_request_number, "pullRequestNumber")
        if self.state not in ("OPEN", "CLOSED") or type(self.state) is not str:
            _fail("stage mutation state must be OPEN or CLOSED")
        if type(self.is_draft) is not bool or type(self.merged) is not bool:
            _fail("stage mutation draft/merged fields must be exact booleans")
        if self.merged_at is None:
            if self.merged:
                _fail("merged stage evidence requires mergedAt")
        else:
            _canonical_utc_timestamp(self.merged_at, "mergedAt")
            if not self.merged:
                _fail("unmerged stage evidence requires null mergedAt")
        _lease_sha(self.head_ref_oid, "headRefOid", git=True)
        _lease_sha(self.base_ref_oid, "baseRefOid", git=True)
        _issue_bounded_text(self.head_ref_name, "headRefName", 256)
        _issue_bounded_text(self.base_ref_name, "baseRefName", 256)
        _lease_node_id(self.head_repository_node_id, "headRepositoryNodeId", delimiter_free=True)
        _lease_node_id(self.base_repository_node_id, "baseRepositoryNodeId", delimiter_free=True)

    def as_value(self) -> dict[str, Any]:
        return {
            "baseRefName": self.base_ref_name,
            "baseRefOid": self.base_ref_oid,
            "baseRepositoryNodeId": self.base_repository_node_id,
            "clientMutationId": self.client_mutation_id,
            "headRefName": self.head_ref_name,
            "headRefOid": self.head_ref_oid,
            "headRepositoryNodeId": self.head_repository_node_id,
            "isDraft": self.is_draft,
            "merged": self.merged,
            "mergedAt": self.merged_at,
            "number": self.pull_request_number,
            "operation": self.operation.value,
            "pullRequestDatabaseId": self.pull_request_database_id,
            "pullRequestNodeId": self.pull_request_node_id,
            "state": self.state,
        }

    def render(self) -> str:
        return _canonical_json(self.as_value())

    def canonical_sha256(self) -> str:
        return hashlib.sha256((EXACT_PR_STAGE_MUTATION_EVIDENCE_PREFIX + self.render()).encode("utf-8")).hexdigest()

    @classmethod
    def from_value(cls, value: Any) -> "ExactPullRequestStageMutationEvidence":
        expected = {
            "operation", "clientMutationId", "pullRequestNodeId", "pullRequestDatabaseId", "number",
            "state", "isDraft", "merged", "mergedAt", "headRefOid", "baseRefOid", "headRefName",
            "baseRefName", "headRepositoryNodeId", "baseRepositoryNodeId",
        }
        if type(value) is not dict or set(value) != expected:
            _fail("stage mutation evidence has invalid exact keys")
        try:
            operation = PullRequestStageMutationOperation(value["operation"])
        except (ValueError, TypeError):
            _fail("stage mutation operation is invalid")
        return cls(
            operation, value["clientMutationId"], value["pullRequestNodeId"],
            value["pullRequestDatabaseId"], value["number"], value["state"], value["isDraft"],
            value["merged"], value["mergedAt"], value["headRefOid"], value["baseRefOid"],
            value["headRefName"], value["baseRefName"], value["headRepositoryNodeId"],
            value["baseRepositoryNodeId"],
        )


def cancel_status_evidence_digest(
    *, central_repository_node_id: str, issue_number: int, issue_database_id: int,
    issue_node_id: str, fence_id: str, cancellation_head_sha: str,
    binding_authority: str, pull_request_number: int, pull_request_database_id: int,
    pull_request_node_id: str,
) -> str:
    central = _lease_node_id(central_repository_node_id, "centralRepositoryNodeId", delimiter_free=True)
    issue_number = _issue_positive_int(issue_number, "issueNumber")
    issue_database_id = _issue_positive_int(issue_database_id, "issueDatabaseId")
    issue_node_id = _lease_node_id(issue_node_id, "issueNodeId", delimiter_free=True)
    _lease_sha(fence_id, "fenceId")
    _lease_sha(cancellation_head_sha, "cancellationHeadSha", git=True)
    authority = _cancel_binding_authority(binding_authority)
    pull_request_number = _issue_positive_int(pull_request_number, "pullRequestNumber")
    pull_request_database_id = _issue_positive_int(pull_request_database_id, "pullRequestDatabaseId")
    pull_request_node_id = _lease_node_id(pull_request_node_id, "pullRequestNodeId", delimiter_free=True)
    value = {
        "bindingAuthority": authority,
        "centralRepositoryNodeId": central,
        "context": "federation/trusted-validation",
        "fenceId": fence_id,
        "issueDatabaseId": issue_database_id,
        "issueNodeId": issue_node_id,
        "issueNumber": issue_number,
        "pullRequestDatabaseId": pull_request_database_id,
        "pullRequestNodeId": pull_request_node_id,
        "pullRequestNumber": pull_request_number,
        "state": "failure",
        "statusClass": "cancel",
        "cancellationHeadSha": cancellation_head_sha,
    }
    return hashlib.sha256((CANCEL_STATUS_EVIDENCE_PREFIX + _canonical_json(value)).encode("utf-8")).hexdigest()


def _cancellation_fence_authority_value(fields: Mapping[str, Any]) -> dict[str, Any]:
    snapshot = fields["pre_fence_required_status"]
    if type(snapshot) is not ExactAppRequiredStatusSnapshot:
        _fail("preFenceRequiredStatus must be an ExactAppRequiredStatusSnapshot")
    return {
        "baseRef": fields["base_ref"],
        "baseRepositoryNodeId": fields["base_repository_node_id"],
        "bindingAuthority": fields["binding_authority"],
        "branchRef": fields["branch_ref"],
        "centralRepositoryNodeId": fields["central_repository_node_id"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"],
        "issueDatabaseId": fields["issue_database_id"],
        "issueNodeId": fields["issue_node_id"],
        "issueNumber": fields["issue_number"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "originalHeadArtifactCommentDatabaseId": fields["original_head_artifact_comment_database_id"],
        "originalHeadArtifactId": fields["original_head_artifact_id"],
        "originalHeadArtifactSha256": fields["original_head_artifact_sha256"],
        "originalHeadClaimKind": fields["original_head_claim_kind"],
        "originalHeadClaimRole": fields["original_head_claim_role"],
        "originalHeadSha": fields["original_head_sha"],
        "originalHeadTreeSha": fields["original_head_tree_sha"],
        "preFenceRequiredStatus": snapshot.as_value(),
        "preFenceSuccessMayExist": fields["pre_fence_success_may_exist"],
        "pullRequestDatabaseId": fields["pull_request_database_id"],
        "pullRequestNodeId": fields["pull_request_node_id"],
        "pullRequestNumber": fields["pull_request_number"],
        "reason": fields["reason"],
        "schemaVersion": fields["schema_version"],
        "sourceId": fields["source_id"],
        "sourceRepositoryId": fields["source_repository_id"],
    }


def _cancellation_fence_authority_digest(fields: Mapping[str, Any]) -> str:
    return hashlib.sha256((ISSUE_CANCELLATION_FENCE_AUTHORITY_PREFIX + _canonical_json(_cancellation_fence_authority_value(fields))).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IssueCancellationFence:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    binding_authority: str
    source_id: str
    source_repository_id: int
    branch_ref: str
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    central_repository_node_id: str
    base_repository_node_id: str
    base_ref: str
    original_head_sha: str
    original_head_tree_sha: str
    original_head_claim_kind: str
    original_head_claim_role: str
    original_head_artifact_comment_database_id: int
    original_head_artifact_id: str
    original_head_artifact_sha256: str
    claim_kind: str
    claim_generation_id: str
    cancellation_carrier_nonce: str
    authority_preimage_digest: str
    cancellation_head_sha: str
    cancellation_head_tree_sha: str
    transition_kind: str
    pre_fence_required_status: ExactAppRequiredStatusSnapshot
    pre_fence_success_may_exist: bool
    reason: str
    marker_digest: str
    fence_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueCancellationFence schemaVersion must be exact integer 1")
        for name in (
            "issue_number", "issue_database_id", "issue_request_anchor_comment_database_id",
            "issue_branch_lease_comment_database_id", "source_repository_id", "pull_request_number",
            "pull_request_database_id", "original_head_artifact_comment_database_id",
        ):
            _issue_positive_int(getattr(self, name), name)
        for name in (
            "issue_node_id", "pull_request_node_id", "central_repository_node_id", "base_repository_node_id",
            "original_head_artifact_id",
        ):
            _lease_node_id(getattr(self, name), name, delimiter_free=True)
        for name in (
            "issue_request_anchor_sha256", "issue_branch_lease_sha256", "original_head_artifact_sha256",
            "claim_generation_id", "cancellation_carrier_nonce", "authority_preimage_digest",
            "marker_digest", "fence_id",
        ):
            _lease_sha(getattr(self, name), name)
        _cancel_binding_authority(self.binding_authority)
        _cancel_source_id(self.source_id)
        if self.branch_ref != issue_branch_ref(self.issue_number):
            _fail("branchRef must be the exact Issue branch ref")
        if self.base_ref != "main":
            _fail("baseRef must be exact main")
        for name in ("original_head_sha", "original_head_tree_sha", "cancellation_head_sha", "cancellation_head_tree_sha"):
            _lease_sha(getattr(self, name), name, git=True)
        allowed = {
            ("ISSUE_BRANCH_LEASE", "ISSUE_ACTIVE"),
            ("ISSUE_HEAD_CLAIM", "ISSUE_ACTIVE"),
            ("REQUIRED_STATUS_EPOCH", "ISSUE_ACTIVE"),
            ("ISSUE_FINALIZATION_EPOCH", "ISSUE_FINALIZING"),
        }
        if (self.original_head_claim_kind, self.original_head_claim_role) not in allowed:
            _fail("original head claim kind/role is unsupported")
        if self.binding_authority == "PRE_BINDING" and (self.original_head_claim_kind, self.original_head_claim_role) != ("ISSUE_BRANCH_LEASE", "ISSUE_ACTIVE"):
            _fail("PRE_BINDING fence must originate from ISSUE_BRANCH_LEASE/ISSUE_ACTIVE")
        if self.claim_kind != "ISSUE_CANCELLATION_FENCE" or self.transition_kind != "TERMINAL_CANCELLATION":
            _fail("fence claim kind or transition is invalid")
        if self.cancellation_head_sha == self.original_head_sha:
            _fail("cancellation head must be a fresh child SHA")
        if self.cancellation_head_tree_sha != self.original_head_tree_sha:
            _fail("cancellation head must preserve the exact original tree")
        if type(self.pre_fence_required_status) is not ExactAppRequiredStatusSnapshot:
            _fail("preFenceRequiredStatus must be an exact status snapshot")
        if self.pre_fence_required_status.queried_sha != self.original_head_sha:
            _fail("preFenceRequiredStatus must be queried on originalHeadSha")
        if type(self.pre_fence_success_may_exist) is not bool:
            _fail("preFenceSuccessMayExist must be an exact boolean")
        if self.original_head_claim_role == "ISSUE_FINALIZING" and not self.pre_fence_success_may_exist:
            _fail("ISSUE_FINALIZING fence must preserve possible success authority")
        if self.pre_fence_required_status.is_present and self.pre_fence_required_status.status_class is StatusClass.ISSUE_FINAL and self.pre_fence_required_status.state == "success" and not self.pre_fence_success_may_exist:
            _fail("visible issue-final success requires preFenceSuccessMayExist")
        if self.reason != "ISSUE_REQUEST_TERMINAL_CANCELLATION":
            _fail("fence reason is invalid")
        owner = issue_owner_key(self.central_repository_node_id, self.issue_database_id, self.issue_node_id, self.issue_number)
        expected_authority = _cancellation_fence_authority_digest(self._fields())
        if self.authority_preimage_digest != expected_authority:
            _fail("fence authorityPreimageDigest does not match canonical pre-SHA authority")
        expected_generation = claim_generation_id(
            authority_preimage_digest=self.authority_preimage_digest,
            carrier_nonce=self.cancellation_carrier_nonce,
            central_repository_node_id=self.central_repository_node_id,
            owner_key=owner,
            from_head_sha=self.original_head_sha,
            from_tree_sha=self.original_head_tree_sha,
            claim_kind=self.claim_kind,
            role="ISSUE_CANCEL",
            owner_kind="ISSUE",
            transition_kind=self.transition_kind,
        )
        if self.claim_generation_id != expected_generation:
            _fail("fence claimGenerationId does not match canonical pre-SHA generation")
        marker = ClaimedHeadMarker(self.claim_kind, "ISSUE_CANCEL", "ISSUE", owner, self.claim_generation_id, self.cancellation_carrier_nonce, self.transition_kind)
        if self.marker_digest != hashlib.sha256(marker.render().encode("utf-8")).hexdigest():
            _fail("fence markerDigest does not match canonical claimed-head marker")
        expected_fence_id = hashlib.sha256((ISSUE_CANCELLATION_FENCE_ID_PREFIX + _canonical_json(self.as_value(include_fence_id=False))).encode("utf-8")).hexdigest()
        if self.fence_id != expected_fence_id:
            _fail("fenceId does not match canonical final fence body")

    def _fields(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if hasattr(self, name)}

    def as_value(self, *, include_fence_id: bool = True) -> dict[str, Any]:
        value = {
            "schemaVersion": self.schema_version,
            "issueNumber": self.issue_number,
            "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id,
            "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256,
            "issueBranchLeaseCommentDatabaseId": self.issue_branch_lease_comment_database_id,
            "issueBranchLeaseSha256": self.issue_branch_lease_sha256,
            "bindingAuthority": self.binding_authority,
            "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id,
            "branchRef": self.branch_ref,
            "pullRequestNumber": self.pull_request_number,
            "pullRequestDatabaseId": self.pull_request_database_id,
            "pullRequestNodeId": self.pull_request_node_id,
            "centralRepositoryNodeId": self.central_repository_node_id,
            "baseRepositoryNodeId": self.base_repository_node_id,
            "baseRef": self.base_ref,
            "originalHeadSha": self.original_head_sha,
            "originalHeadTreeSha": self.original_head_tree_sha,
            "originalHeadClaimKind": self.original_head_claim_kind,
            "originalHeadClaimRole": self.original_head_claim_role,
            "originalHeadArtifactCommentDatabaseId": self.original_head_artifact_comment_database_id,
            "originalHeadArtifactId": self.original_head_artifact_id,
            "originalHeadArtifactSha256": self.original_head_artifact_sha256,
            "claimKind": self.claim_kind,
            "claimGenerationId": self.claim_generation_id,
            "cancellationCarrierNonce": self.cancellation_carrier_nonce,
            "authorityPreimageDigest": self.authority_preimage_digest,
            "cancellationHeadSha": self.cancellation_head_sha,
            "cancellationHeadTreeSha": self.cancellation_head_tree_sha,
            "transitionKind": self.transition_kind,
            "preFenceRequiredStatus": self.pre_fence_required_status.as_value(),
            "preFenceSuccessMayExist": self.pre_fence_success_may_exist,
            "reason": self.reason,
            "markerDigest": self.marker_digest,
        }
        if include_fence_id:
            value["fenceId"] = self.fence_id
        return value

    def authority_preimage_value(self) -> dict[str, Any]:
        return _cancellation_fence_authority_value(self._fields())

    @classmethod
    def create(cls, **fields: Any) -> "IssueCancellationFence":
        body = dict(fields)
        body.setdefault("schema_version", 1)
        body.setdefault("claim_kind", "ISSUE_CANCELLATION_FENCE")
        body.setdefault("transition_kind", "TERMINAL_CANCELLATION")
        body.setdefault("reason", "ISSUE_REQUEST_TERMINAL_CANCELLATION")
        body["authority_preimage_digest"] = _cancellation_fence_authority_digest(body)
        body["claim_generation_id"] = claim_generation_id(
            authority_preimage_digest=body["authority_preimage_digest"],
            carrier_nonce=body["cancellation_carrier_nonce"],
            central_repository_node_id=body["central_repository_node_id"],
            owner_key=issue_owner_key(body["central_repository_node_id"], body["issue_database_id"], body["issue_node_id"], body["issue_number"]),
            from_head_sha=body["original_head_sha"],
            from_tree_sha=body["original_head_tree_sha"],
            claim_kind=body["claim_kind"], role="ISSUE_CANCEL", owner_kind="ISSUE",
            transition_kind=body["transition_kind"],
        )
        marker = ClaimedHeadMarker(
            body["claim_kind"], "ISSUE_CANCEL", "ISSUE",
            issue_owner_key(body["central_repository_node_id"], body["issue_database_id"], body["issue_node_id"], body["issue_number"]),
            body["claim_generation_id"], body["cancellation_carrier_nonce"], body["transition_kind"],
        )
        body["marker_digest"] = hashlib.sha256(marker.render().encode("utf-8")).hexdigest()
        provisional = cls.__new__(cls)
        for name, value in body.items():
            object.__setattr__(provisional, name, value)
        body["fence_id"] = hashlib.sha256((ISSUE_CANCELLATION_FENCE_ID_PREFIX + _canonical_json(provisional.as_value(include_fence_id=False))).encode("utf-8")).hexdigest()
        return cls(**body)

    def render(self) -> str:
        return f"{ISSUE_CANCELLATION_FENCE_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_issue_cancellation_fence(text: str) -> IssueCancellationFence:
    keys = set(IssueCancellationFence.__dataclass_fields__)
    key_map = {name: name for name in keys}
    camel = {
        "schemaVersion": "schema_version", "issueNumber": "issue_number", "issueDatabaseId": "issue_database_id",
        "issueNodeId": "issue_node_id", "issueRequestAnchorCommentDatabaseId": "issue_request_anchor_comment_database_id",
        "issueRequestAnchorSha256": "issue_request_anchor_sha256", "issueBranchLeaseCommentDatabaseId": "issue_branch_lease_comment_database_id",
        "issueBranchLeaseSha256": "issue_branch_lease_sha256", "bindingAuthority": "binding_authority", "sourceId": "source_id",
        "sourceRepositoryId": "source_repository_id", "branchRef": "branch_ref", "pullRequestNumber": "pull_request_number",
        "pullRequestDatabaseId": "pull_request_database_id", "pullRequestNodeId": "pull_request_node_id",
        "centralRepositoryNodeId": "central_repository_node_id", "baseRepositoryNodeId": "base_repository_node_id", "baseRef": "base_ref",
        "originalHeadSha": "original_head_sha", "originalHeadTreeSha": "original_head_tree_sha", "originalHeadClaimKind": "original_head_claim_kind",
        "originalHeadClaimRole": "original_head_claim_role", "originalHeadArtifactCommentDatabaseId": "original_head_artifact_comment_database_id",
        "originalHeadArtifactId": "original_head_artifact_id", "originalHeadArtifactSha256": "original_head_artifact_sha256",
        "claimKind": "claim_kind", "claimGenerationId": "claim_generation_id", "cancellationCarrierNonce": "cancellation_carrier_nonce",
        "authorityPreimageDigest": "authority_preimage_digest", "cancellationHeadSha": "cancellation_head_sha",
        "cancellationHeadTreeSha": "cancellation_head_tree_sha", "transitionKind": "transition_kind",
        "preFenceRequiredStatus": "pre_fence_required_status", "preFenceSuccessMayExist": "pre_fence_success_may_exist",
        "reason": "reason", "markerDigest": "marker_digest", "fenceId": "fence_id",
    }
    value = _cancel_parse_record(text, ISSUE_CANCELLATION_FENCE_MARKER, "IssueCancellationFence", set(camel))
    body = {camel[key]: item for key, item in value.items()}
    body["pre_fence_required_status"] = ExactAppRequiredStatusSnapshot.from_value(body["pre_fence_required_status"])
    fence = IssueCancellationFence(**body)
    if text != fence.render():
        _fail("IssueCancellationFence representation is not canonical")
    return fence


def _stage_evidence_matches(
    evidence: ExactPullRequestStageMutationEvidence, *, operation: PullRequestStageMutationOperation,
    pull_request_node_id: str, pull_request_database_id: int, pull_request_number: int,
    cancellation_head_sha: str, branch_ref: str, base_repository_node_id: str,
    head_repository_node_id: str, base_ref: str = "main", expected_state: str = "OPEN",
) -> None:
    if type(evidence) is not ExactPullRequestStageMutationEvidence or evidence.operation is not operation:
        _fail("stage mutation evidence operation is invalid")
    exact = (
        evidence.pull_request_node_id == pull_request_node_id
        and evidence.pull_request_database_id == pull_request_database_id
        and evidence.pull_request_number == pull_request_number
        and evidence.head_ref_oid == cancellation_head_sha
        and evidence.head_ref_name == branch_ref.removeprefix("refs/heads/")
        and evidence.base_ref_name == base_ref
        and evidence.base_repository_node_id == base_repository_node_id
        and evidence.head_repository_node_id == head_repository_node_id
        and evidence.state == expected_state and evidence.merged is False and evidence.merged_at is None
    )
    if not exact:
        _fail("stage mutation evidence does not match exact PR/head/base authority")


def _cancel_witness_value(fields: Mapping[str, Any], *, include_id: bool = True) -> dict[str, Any]:
    values = {
        "schemaVersion": fields["schema_version"], "issueNumber": fields["issue_number"],
        "issueDatabaseId": fields["issue_database_id"], "issueNodeId": fields["issue_node_id"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"],
        "fenceCommentDatabaseId": fields["fence_comment_database_id"], "fenceSha256": fields["fence_sha256"],
        "fenceId": fields["fence_id"], "bindingAuthority": fields["binding_authority"],
        "sourceId": fields["source_id"], "sourceRepositoryId": fields["source_repository_id"],
        "branchRef": fields["branch_ref"], "pullRequestNumber": fields["pull_request_number"],
        "pullRequestDatabaseId": fields["pull_request_database_id"], "pullRequestNodeId": fields["pull_request_node_id"],
        "originalHeadSha": fields["original_head_sha"], "cancellationHeadSha": fields["cancellation_head_sha"],
        "anchoredAcceptedBaseSha": fields["anchored_accepted_base_sha"], "baseRepositoryNodeId": fields["base_repository_node_id"],
        "baseRef": fields["base_ref"], "returnedBaseRefOid": fields["returned_base_ref_oid"],
        "headRepositoryNodeId": fields["head_repository_node_id"],
        "reopenEvidence": fields["reopen_evidence"].as_value() if fields["reopen_evidence"] else None,
        "readyEvidence": fields["ready_evidence"].as_value() if fields["ready_evidence"] else None,
        "draftEvidence": fields["draft_evidence"].as_value(),
        "currentRequiredStatus": fields["current_required_status"].as_value(),
    }
    if include_id:
        values["witnessId"] = fields["witness_id"]
    return values


@dataclass(frozen=True)
class IssueCancellationDraftWitness:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    fence_comment_database_id: int
    fence_sha256: str
    fence_id: str
    binding_authority: str
    source_id: str
    source_repository_id: int
    branch_ref: str
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    original_head_sha: str
    cancellation_head_sha: str
    anchored_accepted_base_sha: str
    base_repository_node_id: str
    base_ref: str
    returned_base_ref_oid: str
    head_repository_node_id: str
    reopen_evidence: ExactPullRequestStageMutationEvidence | None
    ready_evidence: ExactPullRequestStageMutationEvidence | None
    draft_evidence: ExactPullRequestStageMutationEvidence
    current_required_status: ExactAppRequiredStatusSnapshot
    witness_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueCancellationDraftWitness schemaVersion must be exact integer 1")
        for name in ("issue_number", "issue_database_id", "issue_request_anchor_comment_database_id", "issue_branch_lease_comment_database_id", "fence_comment_database_id", "source_repository_id", "pull_request_number", "pull_request_database_id"):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_node_id", "pull_request_node_id", "base_repository_node_id", "head_repository_node_id"):
            _lease_node_id(getattr(self, name), name, delimiter_free=True)
        for name in ("issue_request_anchor_sha256", "issue_branch_lease_sha256", "fence_sha256", "fence_id", "witness_id"):
            _lease_sha(getattr(self, name), name)
        _cancel_binding_authority(self.binding_authority)
        _cancel_source_id(self.source_id)
        if self.branch_ref != issue_branch_ref(self.issue_number) or self.base_ref != "main":
            _fail("draft witness branch/base ref is invalid")
        for name in ("original_head_sha", "cancellation_head_sha", "anchored_accepted_base_sha", "returned_base_ref_oid"):
            _lease_sha(getattr(self, name), name, git=True)
        if type(self.current_required_status) is not ExactAppRequiredStatusSnapshot or not self.current_required_status.is_present:
            _fail("draft witness requires exact PRESENT current status evidence")
        if self.current_required_status.queried_sha != self.cancellation_head_sha:
            _fail("draft witness status must be queried on cancellationHeadSha")
        expected_digest = cancel_status_evidence_digest(
            central_repository_node_id=self.base_repository_node_id,
            issue_number=self.issue_number, issue_database_id=self.issue_database_id, issue_node_id=self.issue_node_id,
            fence_id=self.fence_id, cancellation_head_sha=self.cancellation_head_sha,
            binding_authority=self.binding_authority, pull_request_number=self.pull_request_number,
            pull_request_database_id=self.pull_request_database_id, pull_request_node_id=self.pull_request_node_id,
        )
        parsed = parse_status_description(self.current_required_status.description)
        if self.current_required_status.context != "federation/trusted-validation" or self.current_required_status.state != "failure" or parsed.status_class is not StatusClass.CANCEL or parsed.evidence_digest != expected_digest:
            _fail("draft witness current status does not prove exact cancel failure")
        _stage_evidence_matches(
            self.draft_evidence, operation=PullRequestStageMutationOperation.CONVERT_TO_DRAFT,
            pull_request_node_id=self.pull_request_node_id, pull_request_database_id=self.pull_request_database_id,
            pull_request_number=self.pull_request_number, cancellation_head_sha=self.cancellation_head_sha,
            branch_ref=self.branch_ref, base_repository_node_id=self.base_repository_node_id,
            head_repository_node_id=self.head_repository_node_id,
        )
        if not self.draft_evidence.is_draft or self.draft_evidence.base_ref_oid != self.returned_base_ref_oid:
            _fail("draft evidence must prove same-response OPEN draft at returned base OID")
        if self.reopen_evidence is not None:
            _stage_evidence_matches(
                self.reopen_evidence, operation=PullRequestStageMutationOperation.REOPEN,
                pull_request_node_id=self.pull_request_node_id, pull_request_database_id=self.pull_request_database_id,
                pull_request_number=self.pull_request_number, cancellation_head_sha=self.cancellation_head_sha,
                branch_ref=self.branch_ref, base_repository_node_id=self.base_repository_node_id,
                head_repository_node_id=self.head_repository_node_id,
            )
        if self.ready_evidence is not None:
            _stage_evidence_matches(
                self.ready_evidence, operation=PullRequestStageMutationOperation.READY_FOR_REVIEW,
                pull_request_node_id=self.pull_request_node_id, pull_request_database_id=self.pull_request_database_id,
                pull_request_number=self.pull_request_number, cancellation_head_sha=self.cancellation_head_sha,
                branch_ref=self.branch_ref, base_repository_node_id=self.base_repository_node_id,
                head_repository_node_id=self.head_repository_node_id,
            )
            if self.ready_evidence.is_draft:
                _fail("ready normalization evidence must return isDraft=false")
        if self.reopen_evidence is None and self.ready_evidence is not None:
            pass
        expected_id = hashlib.sha256((ISSUE_CANCELLATION_DRAFT_WITNESS_ID_PREFIX + _canonical_json(_cancel_witness_value(self._fields(), include_id=False))).encode("utf-8")).hexdigest()
        if self.witness_id != expected_id:
            _fail("draft witnessId does not match canonical witness")

    def _fields(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if hasattr(self, name)}

    def as_value(self, *, include_witness_id: bool = True) -> dict[str, Any]:
        return _cancel_witness_value(self._fields(), include_id=include_witness_id)

    @classmethod
    def create(cls, **fields: Any) -> "IssueCancellationDraftWitness":
        body = dict(fields)
        body.setdefault("schema_version", 1)
        provisional = cls.__new__(cls)
        for name, value in body.items():
            object.__setattr__(provisional, name, value)
        body["witness_id"] = hashlib.sha256((ISSUE_CANCELLATION_DRAFT_WITNESS_ID_PREFIX + _canonical_json(provisional.as_value(include_witness_id=False))).encode("utf-8")).hexdigest()
        return cls(**body)

    def render(self) -> str:
        return f"{ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_issue_cancellation_draft_witness(text: str) -> IssueCancellationDraftWitness:
    mapping = {
        "schemaVersion": "schema_version", "issueNumber": "issue_number", "issueDatabaseId": "issue_database_id", "issueNodeId": "issue_node_id",
        "issueRequestAnchorCommentDatabaseId": "issue_request_anchor_comment_database_id", "issueRequestAnchorSha256": "issue_request_anchor_sha256",
        "issueBranchLeaseCommentDatabaseId": "issue_branch_lease_comment_database_id", "issueBranchLeaseSha256": "issue_branch_lease_sha256",
        "fenceCommentDatabaseId": "fence_comment_database_id", "fenceSha256": "fence_sha256", "fenceId": "fence_id",
        "bindingAuthority": "binding_authority", "sourceId": "source_id", "sourceRepositoryId": "source_repository_id", "branchRef": "branch_ref",
        "pullRequestNumber": "pull_request_number", "pullRequestDatabaseId": "pull_request_database_id", "pullRequestNodeId": "pull_request_node_id",
        "originalHeadSha": "original_head_sha", "cancellationHeadSha": "cancellation_head_sha", "anchoredAcceptedBaseSha": "anchored_accepted_base_sha",
        "baseRepositoryNodeId": "base_repository_node_id", "baseRef": "base_ref", "returnedBaseRefOid": "returned_base_ref_oid",
        "headRepositoryNodeId": "head_repository_node_id", "reopenEvidence": "reopen_evidence", "readyEvidence": "ready_evidence",
        "draftEvidence": "draft_evidence", "currentRequiredStatus": "current_required_status", "witnessId": "witness_id",
    }
    value = _cancel_parse_record(text, ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER, "IssueCancellationDraftWitness", set(mapping))
    body = {mapping[key]: item for key, item in value.items()}
    for key in ("reopen_evidence", "ready_evidence", "draft_evidence"):
        body[key] = ExactPullRequestStageMutationEvidence.from_value(body[key]) if body[key] is not None else None
    body["current_required_status"] = ExactAppRequiredStatusSnapshot.from_value(body["current_required_status"])
    witness = IssueCancellationDraftWitness(**body)
    if text != witness.render():
        _fail("IssueCancellationDraftWitness representation is not canonical")
    return witness


class IssueTerminalCancelledProofKind(Enum):
    PR_BACKED_PRE_BINDING = "PR_BACKED_PRE_BINDING"
    PR_BACKED_FULL_BINDING = "PR_BACKED_FULL_BINDING"


def _terminal_cancelled_value(fields: Mapping[str, Any], *, include_id: bool = True) -> dict[str, Any]:
    value = {
        "schemaVersion": fields["schema_version"], "issueNumber": fields["issue_number"],
        "issueDatabaseId": fields["issue_database_id"], "issueNodeId": fields["issue_node_id"],
        "issueRequestAnchorCommentDatabaseId": fields["issue_request_anchor_comment_database_id"],
        "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
        "issueBranchLeaseCommentDatabaseId": fields["issue_branch_lease_comment_database_id"],
        "issueBranchLeaseSha256": fields["issue_branch_lease_sha256"], "bindingAuthority": fields["binding_authority"],
        "sourceId": fields["source_id"], "sourceRepositoryId": fields["source_repository_id"], "branchRef": fields["branch_ref"],
        "pullRequestNumber": fields["pull_request_number"], "pullRequestDatabaseId": fields["pull_request_database_id"],
        "pullRequestNodeId": fields["pull_request_node_id"], "originalHeadSha": fields["original_head_sha"],
        "cancellationHeadSha": fields["cancellation_head_sha"], "baseRepositoryNodeId": fields["base_repository_node_id"],
        "baseRef": fields["base_ref"], "fenceCommentDatabaseId": fields["fence_comment_database_id"],
        "fenceSha256": fields["fence_sha256"], "fenceId": fields["fence_id"],
        "draftWitnessCommentDatabaseId": fields["draft_witness_comment_database_id"],
        "draftWitnessSha256": fields["draft_witness_sha256"], "witnessId": fields["witness_id"],
        "currentFailureStatus": fields["current_failure_status"].as_value(),
        "closeEvidence": fields["close_evidence"].as_value(), "closeResponseDigest": fields["close_response_digest"],
        "outcome": fields["outcome"], "proofKind": fields["proof_kind"].value,
    }
    if include_id:
        value["terminalResultId"] = fields["terminal_result_id"]
    return value


@dataclass(frozen=True)
class IssueTerminalCancelledResult:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    issue_branch_lease_comment_database_id: int
    issue_branch_lease_sha256: str
    binding_authority: str
    source_id: str
    source_repository_id: int
    branch_ref: str
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    original_head_sha: str
    cancellation_head_sha: str
    base_repository_node_id: str
    base_ref: str
    fence_comment_database_id: int
    fence_sha256: str
    fence_id: str
    draft_witness_comment_database_id: int
    draft_witness_sha256: str
    witness_id: str
    current_failure_status: ExactAppRequiredStatusSnapshot
    close_evidence: ExactPullRequestStageMutationEvidence
    close_response_digest: str
    outcome: str
    proof_kind: IssueTerminalCancelledProofKind
    terminal_result_id: str

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueTerminalCancelledResult schemaVersion must be exact integer 1")
        for name in ("issue_number", "issue_database_id", "issue_request_anchor_comment_database_id", "issue_branch_lease_comment_database_id", "source_repository_id", "pull_request_number", "pull_request_database_id", "fence_comment_database_id", "draft_witness_comment_database_id"):
            _issue_positive_int(getattr(self, name), name)
        for name in ("issue_node_id", "pull_request_node_id", "base_repository_node_id"):
            _lease_node_id(getattr(self, name), name, delimiter_free=True)
        for name in ("issue_request_anchor_sha256", "issue_branch_lease_sha256", "fence_sha256", "fence_id", "draft_witness_sha256", "witness_id", "close_response_digest", "terminal_result_id"):
            _lease_sha(getattr(self, name), name)
        _cancel_binding_authority(self.binding_authority)
        _cancel_source_id(self.source_id)
        if self.branch_ref != issue_branch_ref(self.issue_number) or self.base_ref != "main":
            _fail("terminal result branch/base ref is invalid")
        _lease_sha(self.original_head_sha, "originalHeadSha", git=True)
        _lease_sha(self.cancellation_head_sha, "cancellationHeadSha", git=True)
        expected_kind = IssueTerminalCancelledProofKind.PR_BACKED_PRE_BINDING if self.binding_authority == "PRE_BINDING" else IssueTerminalCancelledProofKind.PR_BACKED_FULL_BINDING
        if type(self.proof_kind) is not IssueTerminalCancelledProofKind or self.proof_kind is not expected_kind:
            _fail("terminal result proofKind does not match bindingAuthority")
        if self.outcome != "CANCELLED":
            _fail("terminal result outcome must be CANCELLED")
        if type(self.current_failure_status) is not ExactAppRequiredStatusSnapshot or not self.current_failure_status.is_present or self.current_failure_status.queried_sha != self.cancellation_head_sha:
            _fail("terminal result requires PRESENT current failure evidence on HC")
        expected_status_digest = cancel_status_evidence_digest(
            central_repository_node_id=self.base_repository_node_id, issue_number=self.issue_number,
            issue_database_id=self.issue_database_id, issue_node_id=self.issue_node_id, fence_id=self.fence_id,
            cancellation_head_sha=self.cancellation_head_sha, binding_authority=self.binding_authority,
            pull_request_number=self.pull_request_number, pull_request_database_id=self.pull_request_database_id,
            pull_request_node_id=self.pull_request_node_id,
        )
        status = parse_status_description(self.current_failure_status.description)
        if self.current_failure_status.state != "failure" or self.current_failure_status.context != "federation/trusted-validation" or status.status_class is not StatusClass.CANCEL or status.evidence_digest != expected_status_digest:
            _fail("terminal result current failure status does not match exact cancellation authority")
        _stage_evidence_matches(
            self.close_evidence, operation=PullRequestStageMutationOperation.CLOSE,
            pull_request_node_id=self.pull_request_node_id, pull_request_database_id=self.pull_request_database_id,
            pull_request_number=self.pull_request_number, cancellation_head_sha=self.cancellation_head_sha,
            branch_ref=self.branch_ref, base_repository_node_id=self.base_repository_node_id,
            head_repository_node_id=self.close_evidence.head_repository_node_id, expected_state="CLOSED",
        )
        if self.close_evidence.state != "CLOSED" or self.close_evidence.merged or self.close_evidence.merged_at is not None:
            _fail("terminal result close evidence must be CLOSED and unmerged")
        expected_close_digest = hashlib.sha256((ISSUE_TERMINAL_CANCELLED_CLOSE_RESPONSE_PREFIX + self.close_evidence.render()).encode("utf-8")).hexdigest()
        if self.close_response_digest != expected_close_digest:
            _fail("terminal result closeResponseDigest does not match close evidence")
        expected_id = hashlib.sha256((ISSUE_TERMINAL_CANCELLED_RESULT_ID_PREFIX + _canonical_json(_terminal_cancelled_value(self._fields(), include_id=False))).encode("utf-8")).hexdigest()
        if self.terminal_result_id != expected_id:
            _fail("terminalResultId does not match canonical terminal result")

    def _fields(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if hasattr(self, name)}

    def as_value(self, *, include_terminal_result_id: bool = True) -> dict[str, Any]:
        return _terminal_cancelled_value(self._fields(), include_id=include_terminal_result_id)

    @classmethod
    def create(cls, **fields: Any) -> "IssueTerminalCancelledResult":
        body = dict(fields)
        body.setdefault("schema_version", 1)
        body.setdefault("outcome", "CANCELLED")
        if isinstance(body.get("proof_kind"), str):
            body["proof_kind"] = IssueTerminalCancelledProofKind(body["proof_kind"])
        body["close_response_digest"] = hashlib.sha256((ISSUE_TERMINAL_CANCELLED_CLOSE_RESPONSE_PREFIX + body["close_evidence"].render()).encode("utf-8")).hexdigest()
        provisional = cls.__new__(cls)
        for name, value in body.items():
            object.__setattr__(provisional, name, value)
        body["terminal_result_id"] = hashlib.sha256((ISSUE_TERMINAL_CANCELLED_RESULT_ID_PREFIX + _canonical_json(provisional.as_value(include_terminal_result_id=False))).encode("utf-8")).hexdigest()
        return cls(**body)

    def render(self) -> str:
        return f"{ISSUE_TERMINAL_CANCELLED_RESULT_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_issue_terminal_cancelled_result(text: str) -> IssueTerminalCancelledResult:
    mapping = {
        "schemaVersion": "schema_version", "issueNumber": "issue_number", "issueDatabaseId": "issue_database_id", "issueNodeId": "issue_node_id",
        "issueRequestAnchorCommentDatabaseId": "issue_request_anchor_comment_database_id", "issueRequestAnchorSha256": "issue_request_anchor_sha256",
        "issueBranchLeaseCommentDatabaseId": "issue_branch_lease_comment_database_id", "issueBranchLeaseSha256": "issue_branch_lease_sha256",
        "bindingAuthority": "binding_authority", "sourceId": "source_id", "sourceRepositoryId": "source_repository_id", "branchRef": "branch_ref",
        "pullRequestNumber": "pull_request_number", "pullRequestDatabaseId": "pull_request_database_id", "pullRequestNodeId": "pull_request_node_id",
        "originalHeadSha": "original_head_sha", "cancellationHeadSha": "cancellation_head_sha", "baseRepositoryNodeId": "base_repository_node_id", "baseRef": "base_ref",
        "fenceCommentDatabaseId": "fence_comment_database_id", "fenceSha256": "fence_sha256", "fenceId": "fence_id",
        "draftWitnessCommentDatabaseId": "draft_witness_comment_database_id", "draftWitnessSha256": "draft_witness_sha256", "witnessId": "witness_id",
        "currentFailureStatus": "current_failure_status", "closeEvidence": "close_evidence", "closeResponseDigest": "close_response_digest",
        "outcome": "outcome", "proofKind": "proof_kind", "terminalResultId": "terminal_result_id",
    }
    value = _cancel_parse_record(text, ISSUE_TERMINAL_CANCELLED_RESULT_MARKER, "IssueTerminalCancelledResult", set(mapping))
    body = {mapping[key]: item for key, item in value.items()}
    body["current_failure_status"] = ExactAppRequiredStatusSnapshot.from_value(body["current_failure_status"])
    body["close_evidence"] = ExactPullRequestStageMutationEvidence.from_value(body["close_evidence"])
    try:
        body["proof_kind"] = IssueTerminalCancelledProofKind(body["proof_kind"])
    except (ValueError, TypeError):
        _fail("terminal result proofKind is invalid")
    result = IssueTerminalCancelledResult(**body)
    if text != result.render():
        _fail("IssueTerminalCancelledResult representation is not canonical")
    return result


class IssueNoPRCancelledProofKind(Enum):
    ANCHOR_ONLY = "ANCHOR_ONLY"
    LEASE_REF_ABSENT = "LEASE_REF_ABSENT"
    LEASE_ZERO_PR_CAS = "LEASE_ZERO_PR_CAS"


@dataclass(frozen=True)
class IssueNoPRCancelledResult:
    schema_version: int
    issue_number: int
    issue_database_id: int
    issue_node_id: str
    issue_request_anchor_comment_database_id: int
    issue_request_anchor_sha256: str
    source_id: str
    source_repository_id: int
    outcome: str
    proof_kind: IssueNoPRCancelledProofKind
    lease_comment_database_id: int | None = None
    lease_sha256: str | None = None
    lease_id: str | None = None
    branch_ref: str | None = None
    lease_initial_head_sha: str | None = None
    required_status: ExactAppRequiredStatusSnapshot | None = None
    all_state_pr_enumeration_digest: str | None = None
    legacy_carrier_evidence_digest: str | None = None
    cleanup_before_oid: str | None = None
    cleanup_ref_absent_after: bool | None = None
    no_pr_result_id: str = ""

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            _fail("IssueNoPRCancelledResult schemaVersion must be exact integer 1")
        _issue_positive_int(self.issue_number, "issueNumber")
        _issue_positive_int(self.issue_database_id, "issueDatabaseId")
        _lease_node_id(self.issue_node_id, "issueNodeId", delimiter_free=True)
        _issue_positive_int(self.issue_request_anchor_comment_database_id, "issueRequestAnchorCommentDatabaseId")
        _lease_sha(self.issue_request_anchor_sha256, "issueRequestAnchorSha256")
        _cancel_source_id(self.source_id)
        _issue_positive_int(self.source_repository_id, "sourceRepositoryId")
        if self.outcome != "CANCELLED":
            _fail("no-PR result outcome must be CANCELLED")
        if type(self.proof_kind) is not IssueNoPRCancelledProofKind:
            _fail("no-PR proofKind must be a closed enum")
        lease_fields = (self.lease_comment_database_id, self.lease_sha256, self.lease_id, self.branch_ref, self.lease_initial_head_sha, self.all_state_pr_enumeration_digest)
        zero_fields = (self.required_status, self.legacy_carrier_evidence_digest, self.cleanup_before_oid, self.cleanup_ref_absent_after)
        if self.proof_kind is IssueNoPRCancelledProofKind.ANCHOR_ONLY:
            if any(item is not None for item in lease_fields + zero_fields):
                _fail("ANCHOR_ONLY result cannot carry lease/ref evidence")
        else:
            _issue_positive_int(self.lease_comment_database_id, "leaseCommentDatabaseId")
            _lease_sha(self.lease_sha256, "leaseSha256")
            _lease_sha(self.lease_id, "leaseId")
            if self.branch_ref != issue_branch_ref(self.issue_number):
                _fail("no-PR result branchRef must be the exact Issue branch")
            _lease_sha(self.lease_initial_head_sha, "leaseInitialHeadSha", git=True)
            _lease_sha(self.all_state_pr_enumeration_digest, "allStatePREnumerationDigest")
            if self.proof_kind is IssueNoPRCancelledProofKind.LEASE_REF_ABSENT:
                if any(item is not None for item in zero_fields):
                    _fail("LEASE_REF_ABSENT result cannot carry zero-PR CAS evidence")
            else:
                if type(self.required_status) is not ExactAppRequiredStatusSnapshot or self.required_status.queried_sha != self.lease_initial_head_sha:
                    _fail("LEASE_ZERO_PR_CAS requires status snapshot on the exact leased head")
                if self.required_status.is_present and self.required_status.state == "success":
                    _fail("LEASE_ZERO_PR_CAS cannot carry a merge-satisfying status")
                _lease_sha(self.legacy_carrier_evidence_digest, "legacyCarrierEvidenceDigest")
                _lease_sha(self.cleanup_before_oid, "cleanupBeforeOid", git=True)
                if self.cleanup_before_oid != self.lease_initial_head_sha or self.cleanup_ref_absent_after is not True:
                    _fail("LEASE_ZERO_PR_CAS cleanup must delete the exact initial head and verify absence")
        _lease_sha(self.no_pr_result_id, "noPrResultId")
        expected_id = hashlib.sha256((ISSUE_NO_PR_CANCELLED_RESULT_ID_PREFIX + _canonical_json(self._body_without_id())).encode("utf-8")).hexdigest()
        if self.no_pr_result_id != expected_id:
            _fail("noPrResultId does not match canonical body")

    def _body_without_id(self) -> dict[str, Any]:
        value = self.as_value(include_no_pr_result_id=False)
        return value

    def as_value(self, *, include_no_pr_result_id: bool = True) -> dict[str, Any]:
        value = {
            "schemaVersion": self.schema_version, "issueNumber": self.issue_number, "issueDatabaseId": self.issue_database_id,
            "issueNodeId": self.issue_node_id, "issueRequestAnchorCommentDatabaseId": self.issue_request_anchor_comment_database_id,
            "issueRequestAnchorSha256": self.issue_request_anchor_sha256, "sourceId": self.source_id,
            "sourceRepositoryId": self.source_repository_id, "outcome": self.outcome, "proofKind": self.proof_kind.value,
        }
        if self.proof_kind is not IssueNoPRCancelledProofKind.ANCHOR_ONLY:
            value.update({
                "leaseCommentDatabaseId": self.lease_comment_database_id, "leaseSha256": self.lease_sha256,
                "leaseId": self.lease_id, "branchRef": self.branch_ref, "leaseInitialHeadSha": self.lease_initial_head_sha,
                "allStatePREnumerationDigest": self.all_state_pr_enumeration_digest,
            })
        if self.proof_kind is IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS:
            value.update({
                "requiredStatus": self.required_status.as_value(),
                "legacyCarrierEvidenceDigest": self.legacy_carrier_evidence_digest,
                "cleanupBeforeOid": self.cleanup_before_oid,
                "cleanupRefAbsentAfter": self.cleanup_ref_absent_after,
            })
        if include_no_pr_result_id:
            value["noPrResultId"] = self.no_pr_result_id
        return value

    @classmethod
    def create(cls, **fields: Any) -> "IssueNoPRCancelledResult":
        body = dict(fields)
        body.setdefault("schema_version", 1)
        body.setdefault("outcome", "CANCELLED")
        if isinstance(body.get("proof_kind"), str):
            body["proof_kind"] = IssueNoPRCancelledProofKind(body["proof_kind"])
        provisional = cls.__new__(cls)
        for name, value in body.items():
            object.__setattr__(provisional, name, value)
        body["no_pr_result_id"] = hashlib.sha256((ISSUE_NO_PR_CANCELLED_RESULT_ID_PREFIX + _canonical_json(provisional._body_without_id())).encode("utf-8")).hexdigest()
        return cls(**body)

    def render(self) -> str:
        return f"{ISSUE_NO_PR_CANCELLED_RESULT_MARKER}\n{_canonical_json(self.as_value())}\n"

    def canonical_sha256(self) -> str:
        return hashlib.sha256(self.render().encode("utf-8")).hexdigest()


def parse_issue_no_pr_cancelled_result(text: str) -> IssueNoPRCancelledResult:
    if type(text) is not str or not text.endswith("\n") or "\r" in text or "\x00" in text:
        _fail("IssueNoPRCancelledResult must use exact LF-terminated lines")
    lines = text[:-1].split("\n")
    if len(lines) != 2 or lines[0] != ISSUE_NO_PR_CANCELLED_RESULT_MARKER or not lines[1]:
        _fail("IssueNoPRCancelledResult marker or JSON line is invalid")
    try:
        value = c02.decode_json(lines[1])
    except Exception as error:
        _fail(f"invalid IssueNoPRCancelledResult JSON: {error}")
    if type(value) is not dict or "proofKind" not in value:
        _fail("IssueNoPRCancelledResult has invalid schema")
    try:
        kind = IssueNoPRCancelledProofKind(value["proofKind"])
    except (ValueError, TypeError):
        _fail("IssueNoPRCancelledResult proofKind is invalid")
    common = {"schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId", "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256", "sourceId", "sourceRepositoryId", "outcome", "proofKind", "noPrResultId"}
    lease = {"leaseCommentDatabaseId", "leaseSha256", "leaseId", "branchRef", "leaseInitialHeadSha", "allStatePREnumerationDigest"}
    zero = {"requiredStatus", "legacyCarrierEvidenceDigest", "cleanupBeforeOid", "cleanupRefAbsentAfter"}
    expected = common | (lease if kind is not IssueNoPRCancelledProofKind.ANCHOR_ONLY else set()) | (zero if kind is IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS else set())
    if set(value) != expected:
        _fail("IssueNoPRCancelledResult has invalid exact conditional keys")
    kwargs = {
        "schema_version": value["schemaVersion"], "issue_number": value["issueNumber"],
        "issue_database_id": value["issueDatabaseId"], "issue_node_id": value["issueNodeId"],
        "issue_request_anchor_comment_database_id": value["issueRequestAnchorCommentDatabaseId"],
        "issue_request_anchor_sha256": value["issueRequestAnchorSha256"], "source_id": value["sourceId"],
        "source_repository_id": value["sourceRepositoryId"], "outcome": value["outcome"], "proof_kind": kind,
        "no_pr_result_id": value["noPrResultId"],
    }
    if kind is not IssueNoPRCancelledProofKind.ANCHOR_ONLY:
        kwargs.update({
            "lease_comment_database_id": value["leaseCommentDatabaseId"], "lease_sha256": value["leaseSha256"],
            "lease_id": value["leaseId"], "branch_ref": value["branchRef"],
            "lease_initial_head_sha": value["leaseInitialHeadSha"], "all_state_pr_enumeration_digest": value["allStatePREnumerationDigest"],
        })
    if kind is IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS:
        kwargs.update({
            "required_status": ExactAppRequiredStatusSnapshot.from_value(value["requiredStatus"]),
            "legacy_carrier_evidence_digest": value["legacyCarrierEvidenceDigest"],
            "cleanup_before_oid": value["cleanupBeforeOid"], "cleanup_ref_absent_after": value["cleanupRefAbsentAfter"],
        })
    result = IssueNoPRCancelledResult(**kwargs)
    if text != result.render():
        _fail("IssueNoPRCancelledResult representation is not canonical")
    return result
