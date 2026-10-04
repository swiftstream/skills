"""Strict request, anchor, and complete PATCH-fold models for federation R01."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from scripts import federate as c02
from automation.federation.workspace import WorkspaceError, validate_trusted_ref

MAX_BODY_BYTES = 16_384
ANCHOR_MARKER = "<!-- swiftstream-federation-request-anchor:v1 -->"
ISSUE_REQUEST_ANCHOR_MARKER = "<!-- swiftstream-federation-issue-request-anchor:v1 -->"
PATCH_SENTINEL = "Federation PATCH"
REQUEST_MARKER = ".federation-request"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")

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


def _check_body_size(body: str, context: str = "body") -> None:
    try:
        size = len(body.encode("utf-8"))
    except UnicodeEncodeError:
        _fail(f"{context} is not valid UTF-8")
    if size > MAX_BODY_BYTES:
        _fail(f"{context} exceeds {MAX_BODY_BYTES} UTF-8 bytes")


def _normalized_lines(body: str, context: str) -> list[str]:
    _check_body_size(body, context)
    if "\x00" in body:
        _fail(f"{context} contains NUL")
    normalized = body.replace("\r\n", "\n")
    if "\r" in normalized:
        _fail(f"{context} contains unsupported carriage return")
    return normalized.split("\n")


def _parse_blocks(body: str, allowed: tuple[str, ...], context: str) -> dict[str, str | None]:
    lines = _normalized_lines(body, context)
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


def parse_patch(comment: str) -> Patch | None:
    lines = _normalized_lines(comment, "PATCH comment")
    first_nonempty = next((line for line in lines if line != ""), None)
    if first_nonempty != PATCH_SENTINEL:
        return None
    sentinel_index = next(index for index, line in enumerate(lines) if line != "")
    remainder = "\n".join(lines[sentinel_index + 1 :])
    values = _parse_blocks(
        remainder,
        (
            "Description:",
            "Branch:",
            "Skills root:",
            "Skill prefixes:",
            "Publication lines:",
            "Dropped publication lines:",
        ),
        "PATCH",
    )
    if not values:
        _fail("PATCH must contain at least one field")
    for key in ("Description", "Branch", "Skills root", "Skill prefixes", "Reason"):
        if values.get(key) == "":
            values[key] = None
    return Patch({key: value for key, value in values.items()})


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


def issue_branch_ref(issue_number: int) -> str:
    number = _lease_decimal(issue_number, "issueNumber")
    value = f"refs/heads/bot/federation/request/issue-{number}"
    try:
        return validate_trusted_ref(value)
    except (c02.FederationError, WorkspaceError) as error:
        _fail(str(error))
    raise AssertionError("unreachable")


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
