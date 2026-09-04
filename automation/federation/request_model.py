"""Strict request, anchor, and complete PATCH-fold models for federation R01."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Callable, Iterable
from urllib.parse import urlsplit

from scripts import federate as c02
from automation.federation.workspace import WorkspaceError, validate_trusted_ref

MAX_BODY_BYTES = 16_384
ANCHOR_MARKER = "<!-- swiftstream-federation-request-anchor:v1 -->"
PATCH_SENTINEL = "Federation PATCH"
REQUEST_MARKER = ".federation-request"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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
    RequestClass.ADD: ("Repository URL:", "Description:", "Branch:", "Skills root:", "Skill prefixes:"),
    RequestClass.UPDATE: ("Repository URL:", "Description:", "Branch:", "Skills root:", "Skill prefixes:"),
    RequestClass.REMOVE: ("Repository URL:", "Reason:"),
    RequestClass.RECONCILE: ("Repository URL:",),
}
_REQUEST_KEYS = ("Repository URL", "Description", "Branch", "Skills root", "Skill prefixes", "Reason")


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
        values[label[:-1]] = value if value != "" else None
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
    _optional_text(request.reason, "Reason")
    if request_class in {RequestClass.ADD, RequestClass.UPDATE}:
        if request.reason is not None:
            _fail("ADD/UPDATE anchors cannot contain Reason")
    elif request_class is RequestClass.REMOVE:
        if any(getattr(request, name) is not None for name in ("description", "branch", "skills_root", "skill_prefixes")):
            _fail("REMOVE anchors cannot contain mutable ADD/UPDATE fields")
    elif request_class is RequestClass.RECONCILE:
        if any(getattr(request, name) is not None for name in ("description", "branch", "skills_root", "skill_prefixes", "reason")):
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
    reason: str | None = None

    def as_anchor_value(self) -> dict[str, Any]:
        return {
            "Repository URL": self.repository_url,
            "Description": self.description,
            "Branch": self.branch,
            "Skills root": self.skills_root,
            "Skill prefixes": list(self.skill_prefixes) if self.skill_prefixes is not None else None,
            "Reason": self.reason,
        }


def parse_request_body(request_class: RequestClass, body: str) -> Request:
    if request_class not in _BODY_FIELDS:
        _fail("machine or unrelated classes do not have a human request body")
    values = _parse_blocks(body, _BODY_FIELDS[request_class], "request body")
    repository = _repository_url(values.get("Repository URL"))
    description = _optional_text(values.get("Description"), "Description")
    branch = _branch(values.get("Branch"))
    skills_root = _skills_root(values.get("Skills root"))
    prefixes = _prefixes(values.get("Skill prefixes"))
    reason = _optional_text(values.get("Reason"), "Reason")
    if request_class is RequestClass.REMOVE:
        return Request(request_class, repository, reason=reason)
    if request_class is RequestClass.RECONCILE:
        return Request(request_class, repository)
    return Request(request_class, repository, description, branch, skills_root, prefixes)


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
    values = _parse_blocks(remainder, ("Description:", "Branch:", "Skills root:", "Skill prefixes:"), "PATCH")
    if not values:
        _fail("PATCH must contain at least one field")
    return Patch({key: value for key, value in values.items()})


def apply_patch(request: Request, patch: Patch) -> Request:
    assignments: dict[str, Any] = {}
    if "Description" in patch.assignments:
        assignments["description"] = _optional_text(patch.assignments["Description"], "Description")
    if "Branch" in patch.assignments:
        assignments["branch"] = _branch(patch.assignments["Branch"])
    if "Skills root" in patch.assignments:
        assignments["skills_root"] = _skills_root(patch.assignments["Skills root"])
    if "Skill prefixes" in patch.assignments:
        assignments["skill_prefixes"] = _prefixes(patch.assignments["Skill prefixes"])
    return replace(request, **assignments)


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
            "schemaVersion": 1,
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
    scalar_keys = {"Repository URL", "Description", "Branch", "Skills root", "Reason"}
    if any(value[key] is not None and type(value[key]) is not str for key in scalar_keys):
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
    request = Request(
        request_class,
        _repository_url(value["Repository URL"]),
        _optional_text(value["Description"], "Description"),
        _anchor_branch(value["Branch"]),
        _skills_root(value["Skills root"]),
        anchor_prefixes,
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
    if type(value["schemaVersion"]) is not int or type(value["schemaVersion"]) is bool or value["schemaVersion"] != 1:
        _fail("anchor schemaVersion must be exact integer 1")
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
