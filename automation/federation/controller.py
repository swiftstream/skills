"""Pure R01 controller seams; live GitHub lifecycle is intentionally phase-gated."""

from __future__ import annotations

import hashlib
import base64
import json
import os
import re
import subprocess
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from scripts import federate as c02

from .github_api import (
    AppMetadata,
    BotMetadata,
    CheckRun,
    GitHubAPIError,
    GitHubClient,
    GraphQLError,
    IssueComment,
    InvalidResponseError,
    MergeResult,
    NotFoundError,
    PullRequestMetadata,
    RefCASConflict,
    RefUpdate,
    RepositoryMetadata,
    ZERO_OID,
)
from .request_model import (
    ANCHOR_MARKER,
    PATCH_SENTINEL,
    REQUEST_MARKER,
    CommentEvent,
    PatchFoldResult,
    Request,
    RequestAnchor,
    RequestClass,
    RequestModelError,
    body_sha256,
    fold_patch_events,
    parse_anchor,
    parse_request_body,
    parse_patch,
    verify_anchor_integrity,
)
from .workspace import validate_trusted_ref
from . import workspace as r01_workspace

_MACHINE_BRANCH_RE = re.compile(r"^bot/federation/([a-z0-9]+(?:-[a-z0-9]+)*)$")
_GRAPHQL_DIAGNOSTIC_TYPE_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_GRAPHQL_DIAGNOSTIC_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_GRAPHQL_DIAGNOSTIC_INDEX_RE = re.compile(r"^[0-9]{1,6}$")
_GRAPHQL_GENERIC_DIAGNOSTIC = "GRAPHQL:UNKNOWN:unknown-path"


def _safe_graphql_diagnostic(error: GraphQLError) -> str:
    text = str(error)
    if len(text.encode("utf-8")) > 512 or not text.startswith("GRAPHQL:"):
        return _GRAPHQL_GENERIC_DIAGNOSTIC
    parts = text.split(":", 2)
    if len(parts) != 3 or parts[0] != "GRAPHQL" or not _GRAPHQL_DIAGNOSTIC_TYPE_RE.fullmatch(parts[1]):
        return _GRAPHQL_GENERIC_DIAGNOSTIC
    path = parts[2]
    if path == "unknown-path":
        return text
    segments = path.split(".")
    if not segments or len(segments) > 16:
        return _GRAPHQL_GENERIC_DIAGNOSTIC
    for segment in segments:
        if _GRAPHQL_DIAGNOSTIC_FIELD_RE.fullmatch(segment):
            continue
        if _GRAPHQL_DIAGNOSTIC_INDEX_RE.fullmatch(segment) and str(int(segment)) == segment and int(segment) <= 999_999:
            continue
        return _GRAPHQL_GENERIC_DIAGNOSTIC
    return text


class ControllerError(RuntimeError):
    pass


class PhaseNotImplementedError(ControllerError):
    """The requested operation belongs to a later frozen phase."""


@dataclass(frozen=True)
class CandidateDiff:
    paths: tuple[str, ...]
    accepted_base: str | None = None
    candidate_head: str | None = None


class R02Error(ControllerError):
    """Bounded, secret-free rejection of an R02 state transition."""


class StaleAuthorityError(R02Error):
    pass


class StaleTrustedCheckoutError(StaleAuthorityError):
    """The trusted code checkout cannot safely evaluate the current main."""


class DuplicateAnchorError(R02Error):
    pass


class DuplicateCheckRunError(R02Error):
    pass


class MissingTrustedCheckError(R02Error):
    """The finalizer may recover a missing check but may not create it."""


class ForkHeadError(R02Error):
    pass


class CandidateScopeError(R02Error):
    pass


@dataclass(frozen=True)
class AppIdentity:
    slug: str
    app_id: int
    app_node_id: str
    bot_id: int
    bot_node_id: str
    bot_login: str


@dataclass(frozen=True)
class AnchorComment:
    anchor: RequestAnchor
    comment: IssueComment


@dataclass(frozen=True)
class PublicSourceMetadata:
    repository_id: int
    full_name: str
    default_branch: str
    description: str | None


@dataclass(frozen=True)
class RequestSnapshot:
    head_oid: str
    body_sha256: str
    base_oid: str
    last_edited_at: str | None
    includes_created_edit: bool
    comments: tuple[tuple[int, str, str | None, str | None, str | None, bool], ...]
    anchor: AnchorComment


@dataclass(frozen=True)
class ProposalCandidate:
    commit_sha: str
    accepted_base_sha: str
    changed_paths: tuple[str, ...]
    request_class: RequestClass
    source_id: str | None = None
    repository_id: int | None = None
    marker_present: bool = False


@dataclass(frozen=True)
class MachinePRAuthority:
    number: int
    source_id: str
    repository_id: int
    head_sha: str
    valid: bool = True
    invalid_reason: str = ""


@dataclass(frozen=True)
class MachineReconcileResult:
    outcome: str
    source_id: str | None = None
    repository_id: int | None = None
    reason: str = ""


@dataclass(frozen=True)
class TrustedValidationResult:
    conclusion: str
    output: Mapping[str, str]
    snapshot: RequestSnapshot | None = None


class CandidateBuilder(Protocol):
    def __call__(self, request: Request, request_class: RequestClass, accepted_base_sha: str, head_sha: str) -> ProposalCandidate:
        ...


ANCHOR_IDEMPOTENCY_PREFIX = "<!-- swiftstream-federation-result:anchor -->"
RESULT_IDEMPOTENCY_PREFIX = "<!-- swiftstream-federation-result:"
TRUSTED_VALIDATION_NAME = "federation/trusted-validation"
FINALIZER_CONCURRENCY_GROUP = "swiftstream-skills-federation-state-finalizer"
MANUAL_CLASSES = frozenset({RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE})
GENERATED_PREFIXES = ("skills/",)
MACHINE_GENERATED_FILES = frozenset({"federation.lock.json", "README.md"})
MACHINE_WORK_LIMIT = 8

# These are trusted-code seams for deterministic local tests.  Production uses
# C02's public-source HTTP and Git implementations; the central App token never
# enters a source repository operation.
SOURCE_HTTP_GET = c02.stdlib_http_get
SOURCE_BRANCH_FETCHER = c02.git_fetch_configured_branch

_C02_CAPSULE_ACTIVE = False


@contextmanager
def trusted_c02_execution() -> Iterable[Path]:
    """Run live C02 process/source work under the already-audited R01 boundary."""
    global _C02_CAPSULE_ACTIVE
    if _C02_CAPSULE_ACTIVE:
        raise R02Error("nested trusted C02 execution capsule is forbidden")

    original_environment = dict(os.environ)
    original_run_process = c02.run_process
    disposable_root: Path | None = None
    disposable_identity: tuple[int, int] | None = None
    trusted_base: Path | None = None
    active = False
    try:
        verified_git = r01_workspace._verified_trusted_git()
        trusted_base = r01_workspace._resolve_trusted_temp_base(c02.ROOT)
        disposable_root, disposable_identity = r01_workspace._create_disposable_root(c02.ROOT, trusted_base)

        def capsule_run_process(
            argv: list[str],
            *,
            cwd: Path | None = None,
            text: bool = True,
            check: bool = True,
            network: bool = False,
            source_workspace: bool = False,
        ) -> subprocess.CompletedProcess[Any]:
            if type(argv) is not list or not argv or argv[0] != "git":
                c02.fail("trusted C02 process seam accepts only the Git executable token")
            child_environment = r01_workspace._trusted_child_environment()
            try:
                result = subprocess.run(
                    [str(verified_git), *argv[1:]],
                    cwd=str(cwd) if cwd is not None else None,
                    env=child_environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL if network else subprocess.PIPE,
                    stderr=subprocess.DEVNULL if network else subprocess.PIPE,
                    text=text,
                    shell=False,
                    check=False,
                    timeout=c02.NETWORK_GIT_TIMEOUT_SECONDS if network else None,
                )
            except subprocess.TimeoutExpired:
                if network:
                    c02.fail("network Git command timed out")
                raise
            if check and result.returncode != 0:
                if result.stderr:
                    stderr = result.stderr if text else result.stderr.decode("utf-8", errors="replace")
                    stderr = stderr.strip()
                else:
                    stderr = ""
                detail = f": {stderr}" if stderr else ""
                c02.fail(f"command failed ({' '.join(argv[:3])}){detail}")
            return result

        _C02_CAPSULE_ACTIVE = True
        active = True
        os.environ.clear()
        os.environ.update(r01_workspace._trusted_child_environment())
        c02.run_process = capsule_run_process
        yield disposable_root
    finally:
        if active:
            c02.run_process = original_run_process
        os.environ.clear()
        os.environ.update(original_environment)
        _C02_CAPSULE_ACTIVE = False
        if disposable_root is not None and disposable_identity is not None and trusted_base is not None:
            if r01_workspace._safe_owned_disposable_root(
                disposable_root,
                trusted_base,
                c02.ROOT,
                disposable_identity,
            ):
                import shutil

                shutil.rmtree(disposable_root, ignore_errors=True)


def _bounded_reason(reason: str) -> str:
    value = str(reason).replace("\x00", "\\0").replace("\n", " ")
    return value[:160]


def read_public_source_metadata(repository: str) -> PublicSourceMetadata:
    """Read source metadata through C02's public transport, never App auth."""
    try:
        response = SOURCE_HTTP_GET(
            c02.github_repository_api_url(repository),
            c02.github_headers(),
            c02.HTTP_TIMEOUT_SECONDS,
            c02.HTTP_MAX_RESPONSE_BYTES,
        )
        if response.status != 200:
            raise R02Error("public source repository metadata is unavailable")
        value = c02.decode_http_json_object(response, "public source repository metadata")
        repository_id = c02.validate_repository_id(value.get("id"))
        full_name = c02.validate_repository(value.get("full_name"))
        default_branch = value.get("default_branch")
        if type(default_branch) is not str or not default_branch or c02.contains_control(default_branch):
            raise R02Error("public source default branch is invalid")
        c02.validate_ref(f"refs/heads/{default_branch}")
        description = value.get("description")
        if description is not None and (type(description) is not str or len(description) > 1_000 or c02.contains_control(description)):
            raise R02Error("public source description is invalid")
        return PublicSourceMetadata(repository_id, full_name, default_branch, description)
    except (c02.FederationError, OSError, ValueError) as error:
        if isinstance(error, R02Error):
            raise
        raise R02Error(f"public source metadata is invalid: {_bounded_reason(error)}") from None


def resolve_app_identity(client: GitHubClient, token_action_app_slug: str) -> AppIdentity:
    """Bind the token-action hint to current App and Bot metadata."""
    if type(token_action_app_slug) is not str or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?", token_action_app_slug):
        raise R02Error("invalid trusted App slug hint")
    app = client.get_app_metadata(token_action_app_slug)
    bot = client.get_bot_metadata(token_action_app_slug)
    expected_login = f"{token_action_app_slug}[bot]"
    if app.slug != token_action_app_slug or bot.login != expected_login or bot.type != "Bot":
        raise R02Error("App and Bot metadata do not bind to the token-action App slug")
    return AppIdentity(token_action_app_slug, app.id, app.node_id, bot.id, bot.node_id, bot.login)


def marker_classes(marker_path: str, marker_value: str) -> RequestClass:
    if marker_path != REQUEST_MARKER or type(marker_value) is not str:
        raise R02Error("request marker path/value is not exact")
    try:
        return next(item for item in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE, RequestClass.RECONCILE) if item.value == marker_value)
    except StopIteration:
        raise R02Error("request marker value is not a human request class") from None


def require_same_repository_head(pr: PullRequestMetadata, central_repository: str) -> None:
    if pr.base_repository != central_repository or pr.head_repository != central_repository:
        raise ForkHeadError("Wave-1 requires a central-repository request head; fork heads are fail-closed")
    try:
        validate_trusted_ref(f"refs/heads/{pr.head_ref}")
    except Exception as error:
        raise ForkHeadError("request head branch is not a valid central branch") from error


def _comment_key(comment: IssueComment) -> tuple[int, str, str | None, str | None, str | None, bool]:
    return (comment.database_id, comment.body, comment.author_id, comment.editor_id, comment.last_edited_at, comment.includes_created_edit)


def _anchor_candidates(comments: Iterable[IssueComment]) -> list[AnchorComment]:
    found: list[AnchorComment] = []
    for comment in comments:
        if not comment.body.startswith(ANCHOR_MARKER):
            continue
        try:
            anchor = parse_anchor(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed RequestAnchor: {_bounded_reason(error)}") from None
        found.append(AnchorComment(anchor, comment))
    return found


def validate_unique_anchor(
    comments: Iterable[IssueComment],
    pr: PullRequestMetadata,
    request_class: RequestClass | None,
    app: AppIdentity,
) -> AnchorComment:
    found = _anchor_candidates(comments)
    if len(found) != 1:
        raise DuplicateAnchorError("exactly one immutable RequestAnchor is required")
    item = found[0]
    anchor = item.anchor
    comment = item.comment
    if anchor.pr_number != pr.number or anchor.original_author_id != pr.author_id or anchor.original_author_login != pr.author_login:
        raise R02Error("RequestAnchor PR/original-author identity mismatch")
    if request_class is not None and anchor.request_class is not request_class:
        raise R02Error("RequestAnchor request class mismatch")
    if comment.author_id != app.bot_node_id or comment.author_login != app.bot_login or comment.author_type not in {None, "Bot"}:
        raise R02Error("RequestAnchor is not authored by the designated App Bot")
    if comment.editor_id is not None or comment.last_edited_at is not None or comment.includes_created_edit:
        raise R02Error("RequestAnchor edit-integrity metadata is not immutable")
    if not verify_anchor_integrity(anchor, pr.body):
        raise R02Error("PR body hash no longer matches immutable RequestAnchor")
    return item


def create_anchor_once(
    client: GitHubClient,
    repository: str,
    pr: PullRequestMetadata,
    request_class: RequestClass,
    app: AppIdentity,
    comments: Iterable[IssueComment],
) -> AnchorComment:
    comment_list = list(comments)
    existing = list(_anchor_candidates(comment_list))
    if existing:
        return validate_unique_anchor(comment_list, pr, request_class, app)
    if pr.last_edited_at is not None or pr.includes_created_edit:
        raise R02Error("edited pre-anchor PR body cannot establish an immutable anchor")
    request = parse_request_body(request_class, pr.body)
    anchor = RequestAnchor(pr.number, request_class, pr.author_id, pr.author_login, body_sha256(pr.body), request)
    client.create_issue_comment(repository, pr.number, anchor.render())
    reread_pr = client.get_pull_request_metadata(repository, pr.number)
    reread_comments = client.list_issue_comments(repository, pr.number)
    if (
        reread_pr.head_oid != pr.head_oid
        or reread_pr.body != pr.body
        or reread_pr.last_edited_at != pr.last_edited_at
        or reread_pr.includes_created_edit != pr.includes_created_edit
    ):
        raise StaleAuthorityError("PR changed while creating RequestAnchor")
    return validate_unique_anchor(reread_comments, reread_pr, request_class, app)


def authorized_patch_events(client: GitHubClient, repository: str, anchor_comment: AnchorComment, comments: Iterable[IssueComment]) -> tuple[CommentEvent, ...]:
    events: list[CommentEvent] = []
    anchor_id = anchor_comment.comment.database_id
    for comment in comments:
        if comment.database_id <= anchor_id:
            continue
        authorized = comment.author_id == anchor_comment.anchor.original_author_id
        if not authorized and comment.author_login and comment.author_type != "Bot":
            try:
                permission = client.get_collaborator_permission(repository, comment.author_login)
            except GitHubAPIError:
                permission = "unknown"
            authorized = permission in {"admin", "maintain"}
        events.append(CommentEvent(comment.database_id, authorized, comment.body))
    return tuple(sorted(events, key=lambda item: item.comment_id))


def reconstruct_from_github(client: GitHubClient, repository: str, pr: PullRequestMetadata, anchor_comment: AnchorComment, comments: Iterable[IssueComment], semantic_validator: Callable[[Request], bool] | None = None) -> PatchFoldResult:
    if not verify_anchor_integrity(anchor_comment.anchor, pr.body):
        raise R02Error("PR body hash no longer matches immutable RequestAnchor")
    return fold_patch_events(anchor_comment.anchor, authorized_patch_events(client, repository, anchor_comment, comments), semantic_validator)


def capture_snapshot(pr: PullRequestMetadata, comments: Iterable[IssueComment], anchor: AnchorComment) -> RequestSnapshot:
    return RequestSnapshot(pr.head_oid, body_sha256(pr.body), pr.base_oid, pr.last_edited_at, pr.includes_created_edit, tuple(_comment_key(comment) for comment in sorted(comments, key=lambda item: item.database_id)), anchor)


def assert_snapshot_unchanged(before: RequestSnapshot, pr: PullRequestMetadata, comments: Iterable[IssueComment], anchor: AnchorComment) -> None:
    after = capture_snapshot(pr, comments, anchor)
    if after != before:
        raise StaleAuthorityError("PR head, body, comments, or anchor changed before mutation")


def replace_request_ref_cas(client: GitHubClient, repository_id: str, request_ref: str, before_oid: str, candidate: ProposalCandidate) -> None:
    if candidate.commit_sha == before_oid:
        return
    try:
        client.update_refs(repository_id, [RefUpdate(request_ref, before_oid, candidate.commit_sha, force=True)])
    except RefCASConflict:
        raise StaleAuthorityError("request branch GraphQL beforeOid CAS was rejected; recompute required") from None


def allowed_proposal_paths(request_class: RequestClass) -> frozenset[str]:
    if request_class is RequestClass.ADD:
        return frozenset({"federation.json"})
    if request_class in {RequestClass.UPDATE, RequestClass.REMOVE}:
        return frozenset({"federation.json", "federation.lock.json", "README.md", "skills/**"})
    raise CandidateScopeError("RECONCILE and MACHINE_PUBLICATION have no R02 proposal diff")


def validate_proposal_scope(request_class: RequestClass, paths: Iterable[str]) -> CandidateDiff:
    try:
        diff = validate_candidate_diff(paths)
    except ControllerError as error:
        raise CandidateScopeError(str(error)) from None
    allowed = allowed_proposal_paths(request_class)
    def permitted(path: str) -> bool:
        return path in allowed or ("skills/**" in allowed and path.startswith("skills/") and len(path) > len("skills/"))
    if not all(permitted(path) for path in diff.paths):
        raise CandidateScopeError("proposal changed a path outside the exact R02 class scope")
    if request_class is RequestClass.ADD and diff.paths != ("federation.json",):
        raise CandidateScopeError("ADD proposal must change exactly federation.json")
    return diff


def validate_existing_request_head(
    client: GitHubClient,
    central_repository: str,
    pr: PullRequestMetadata,
    request_class: RequestClass,
    accepted_base_sha: str,
) -> None:
    """Reject an unsafe request head before any C02 build or Git-object write."""
    base_tree_sha, base_entries = client.get_commit_tree(central_repository, accepted_base_sha)
    head_tree_sha, head_entries = client.get_commit_tree(central_repository, pr.head_oid)

    def parse_tree(entries: Iterable[Any]) -> tuple[dict[str, tuple[str, str, str]], dict[str, tuple[str, str, str]]]:
        all_entries: dict[str, tuple[str, str, str]] = {}
        directories: dict[str, tuple[str, str, str]] = {}
        for item in entries:
            try:
                path, mode, object_type, sha = item.path, item.mode, item.object_type, item.sha
            except AttributeError:
                raise CandidateScopeError("recursive Git tree entry is malformed") from None
            if (
                type(path) is not str
                or not path
                or path.startswith("/")
                or "\\" in path
                or c02.contains_control(path)
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or path in all_entries
            ):
                raise CandidateScopeError("recursive Git tree path is unsafe or duplicated")
            if type(mode) is not str or type(object_type) is not str or type(sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise CandidateScopeError("recursive Git tree entry identity is malformed")
            if object_type == "tree" and mode == "040000":
                directories[path] = (mode, object_type, sha)
            elif object_type == "blob" and mode in {"100644", "100755"}:
                pass
            elif object_type == "blob" and mode == "120000":
                raise CandidateScopeError("recursive Git tree contains a forbidden symlink")
            elif object_type == "commit" and mode == "160000":
                raise CandidateScopeError("recursive Git tree contains a forbidden gitlink")
            else:
                raise CandidateScopeError("recursive Git tree mode/type mismatch")
            all_entries[path] = (mode, object_type, sha)
        for path in all_entries:
            parts = path.split("/")
            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                if parent not in directories:
                    raise CandidateScopeError("recursive Git tree has an impossible ancestor structure")
        return all_entries, directories

    base, base_directories = parse_tree(base_entries)
    head, head_directories = parse_tree(head_entries)
    base_leaves = {path: value for path, value in base.items() if value[1] != "tree"}
    head_leaves = {path: value for path, value in head.items() if value[1] != "tree"}
    changed = tuple(sorted(path for path in set(base_leaves) | set(head_leaves) if base_leaves.get(path) != head_leaves.get(path)))
    validate_candidate_diff(changed)

    directory_paths = set(base_directories) | set(head_directories)
    changed_directories = {path for path in directory_paths if base_directories.get(path) != head_directories.get(path)}
    affected_directories = {
        "/".join(path.split("/")[:index])
        for path in changed
        for index in range(1, len(path.split("/")))
    }
    if changed_directories != affected_directories or (not changed and base_tree_sha != head_tree_sha):
        raise CandidateScopeError("recursive Git tree directory structure changed outside semantic leaves")
    if changed and base_tree_sha == head_tree_sha:
        raise CandidateScopeError("recursive Git tree root SHA did not reflect semantic leaf changes")

    marker = REQUEST_MARKER
    marker_entry = head_leaves.get(marker)
    if marker_entry is not None:
        if marker_entry[:2] != ("100644", "blob"):
            raise CandidateScopeError("request marker must be a regular 100644 blob")
        marker_data = client.get_blob(central_repository, marker_entry[2])
        if marker_data != (request_class.value + "\n").encode("ascii"):
            raise CandidateScopeError("request marker bytes do not match the anchored request class")
    if changed == (marker,):
        if marker in base_leaves or marker_entry is None:
            raise CandidateScopeError("initial request marker is missing from the request head")
        return
    if marker in changed:
        raise CandidateScopeError("request marker may not coexist with a regenerated proposal")
    allowed = allowed_proposal_paths(request_class)
    for path in changed:
        permitted = path in allowed or ("skills/**" in allowed and path.startswith("skills/") and len(path) > len("skills/"))
        if not permitted:
            raise CandidateScopeError("request head changed a path outside the exact R02 class scope")
        entry = head_leaves.get(path)
        if entry is not None and entry[:2] != ("100644", "blob") and not (path.startswith("skills/") and entry[:2] == ("100755", "blob")):
            raise CandidateScopeError("request head contains an unexpected generated path mode/type")


def validate_readme_managed_diff(before: bytes, after: bytes) -> None:
    """Require C02's README bytes to preserve every byte outside its catalog."""
    try:
        before_layout = c02.parse_readme_layout_bytes(before)
        after_layout = c02.parse_readme_layout_bytes(after)
    except Exception as error:
        raise CandidateScopeError(f"README managed-section validation failed: {_bounded_reason(error)}") from None
    if before_layout.prefix_through_begin != after_layout.prefix_through_begin or before_layout.suffix_from_end != after_layout.suffix_from_end:
        raise CandidateScopeError("README proposal changed bytes outside the C02 managed catalog")


def validate_trusted_pr_shape(pr: PullRequestMetadata, central_repository: str, accepted_base_sha: str, accepted_base_branch: str = "main") -> None:
    require_same_repository_head(pr, central_repository)
    if pr.base_repository != central_repository or pr.base_ref != accepted_base_branch or pr.base_oid != accepted_base_sha:
        raise StaleAuthorityError("trusted validation is not bound to the exact central base")


def bounded_check_output(request_class: RequestClass, head_sha: str, accepted_base_sha: str, source_id: str | None = None, repository_id: int | None = None, reason: str = "") -> dict[str, str]:
    output = {"class": request_class.value, "head": head_sha, "accepted_base": accepted_base_sha, "result": _bounded_reason(reason)}
    if source_id is not None:
        output["sourceId"] = source_id
    if repository_id is not None:
        output["repositoryId"] = str(repository_id)
    return output


def render_check_run_output(result: TrustedValidationResult) -> dict[str, str]:
    """Render bounded logical evidence into GitHub's required output object."""
    logical = dict(result.output)
    reason = _bounded_reason(logical.get("result", "UNKNOWN"))
    summary = _bounded_reason(
        "Trusted federation validation "
        + ("passed" if result.conclusion == "success" else "is blocking")
        + f": {reason}"
    )
    fields = ("class", "head", "accepted_base", "sourceId", "repositoryId", "result")
    text = "; ".join(
        f"{key}={_bounded_reason(logical[key])}"
        for key in fields
        if key in logical
    )
    return {"title": "Federation trusted validation", "summary": summary, "text": text[:1000]}


def verify_machine_check_identity(
    check: CheckRun,
    *,
    head_sha: str,
    accepted_base_sha: str,
    source_id: str,
    repository_id: int,
) -> None:
    """Require the exact bounded identity prefix emitted by trusted validation."""
    text = check.output
    if type(text) is not str or not text or len(text) > 4_096 or c02.contains_control(text):
        raise R02Error("machine trusted-validation check identity evidence is missing or malformed")
    fields = text.split("; ")
    expected = (
        f"class={RequestClass.MACHINE_PUBLICATION.value}",
        f"head={head_sha}",
        f"accepted_base={accepted_base_sha}",
        f"sourceId={source_id}",
        f"repositoryId={repository_id}",
    )
    if tuple(fields[:5]) != expected or len(fields) != 6:
        raise R02Error("machine trusted-validation check identity evidence does not match authority")
    result = fields[5]
    if not result.startswith("result=") or len(result) <= len("result=") or len(result) > 167:
        raise R02Error("machine trusted-validation check result evidence is malformed")
    if any(field.split("=", 1)[0] in {"class", "head", "accepted_base", "sourceId", "repositoryId"} for field in fields[5:]):
        raise R02Error("machine trusted-validation check identity evidence is duplicated")


def _machine_check_identity_invalid(
    checks: tuple[CheckRun, ...],
    head_sha: str,
    accepted_base_sha: str,
    source: c02.SourceDeclaration,
) -> bool:
    if len(checks) != 1:
        return True
    try:
        verify_machine_check_identity(
            checks[0],
            head_sha=head_sha,
            accepted_base_sha=accepted_base_sha,
            source_id=source.source_id,
            repository_id=source.repository_id,
        )
    except R02Error:
        return True
    return False


def upsert_trusted_validation_check(
    client: GitHubClient,
    repository: str,
    app: AppIdentity,
    result: TrustedValidationResult,
    *,
    allow_create: bool,
) -> CheckRun:
    """Write exactly one App-owned check, with creation owned by validation only."""
    if type(allow_create) is not bool:
        raise R02Error("check writer mode is invalid")
    if allow_create and result.conclusion == "success":
        raise R02Error("the validation writer cannot publish a green conclusion")
    head_sha = result.output.get("head")
    if type(head_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
        raise R02Error("trusted validation result has no exact head")
    checks = client.list_check_runs(repository, head_sha)
    matches = [item for item in checks if item.name == TRUSTED_VALIDATION_NAME and item.head_sha == head_sha and item.app_id == app.app_id]
    if len(matches) > 1:
        raise DuplicateCheckRunError("multiple App-owned trusted-validation checks exist for the exact head")
    if matches:
        check = client.update_check_run(
            repository,
            matches[0].id,
            head_sha=head_sha,
            conclusion=result.conclusion,
            output=render_check_run_output(result),
        )
    else:
        if not allow_create:
            raise MissingTrustedCheckError("the required App-owned trusted-validation check is missing")
        check = client.create_check_run(
            repository,
            TRUSTED_VALIDATION_NAME,
            head_sha,
            conclusion=result.conclusion,
            output=render_check_run_output(result),
        )
    if check.name != TRUSTED_VALIDATION_NAME or check.head_sha != head_sha or check.app_id != app.app_id:
        raise R02Error("trusted validation check response is not bound to the exact App/head")
    return check


def read_request_marker(client: GitHubClient, repository: str, head_sha: str) -> RequestClass:
    """Read only the exact marker blob from the exact untrusted PR head."""
    try:
        raw = client.read_commit_file(repository, head_sha, REQUEST_MARKER, expected_mode="100644")
        if len(raw) > 128 or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
            raise R02Error("request marker bytes are not exactly one value plus final newline")
        value = raw[:-1].decode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError):
        raise R02Error("request marker is not exact ASCII data") from None
    return marker_classes(REQUEST_MARKER, value)


def evaluate_trusted_validation(
    request_class: RequestClass,
    head_sha: str,
    accepted_base_sha: str,
    candidate_check: Callable[[], tuple[bool, str]],
    *,
    source_id: str | None = None,
    repository_id: int | None = None,
    allow_success: bool = False,
    authority_snapshot: RequestSnapshot | None = None,
) -> TrustedValidationResult:
    try:
        valid, candidate_reason = candidate_check()
    except StaleTrustedCheckoutError as error:
        return TrustedValidationResult("failure", bounded_check_output(request_class, head_sha, accepted_base_sha, source_id, repository_id, _bounded_reason(error)), authority_snapshot)
    except Exception:
        return TrustedValidationResult("failure", bounded_check_output(request_class, head_sha, accepted_base_sha, source_id, repository_id, "CANDIDATE_VALIDATION_FAILED"), authority_snapshot)
    if not valid:
        return TrustedValidationResult("failure", bounded_check_output(request_class, head_sha, accepted_base_sha, source_id, repository_id, candidate_reason), authority_snapshot)
    if not allow_success:
        return TrustedValidationResult("failure", bounded_check_output(request_class, head_sha, accepted_base_sha, source_id, repository_id, "FINALIZER_AUTHORITY_REQUIRED"), authority_snapshot)
    return TrustedValidationResult("success", bounded_check_output(request_class, head_sha, accepted_base_sha, source_id, repository_id, "READY"), authority_snapshot)


def assert_validation_snapshot_current(client: GitHubClient, repository: str, app: AppIdentity, result: TrustedValidationResult) -> PullRequestMetadata:
    """Re-read every authority before publishing evidence for one validation attempt."""
    snapshot = result.snapshot
    if snapshot is None:
        raise StaleAuthorityError("validation result has no bound authority snapshot")
    repository_metadata = client.get_repository_metadata(repository)
    current_main = client.get_ref_oid(repository, repository_metadata.default_branch)
    pr = client.get_pull_request_metadata(repository, snapshot.anchor.anchor.pr_number)
    comments = client.list_issue_comments(repository, pr.number)
    anchor = validate_unique_anchor(comments, pr, snapshot.anchor.anchor.request_class, app)
    if current_main != snapshot.base_oid or pr.base_oid != snapshot.base_oid or pr.head_oid != snapshot.head_oid:
        raise StaleAuthorityError("validation authority changed before check publication")
    assert_snapshot_unchanged(snapshot, pr, comments, anchor)
    return pr


def finalize_manual_trust_sweep(
    client: GitHubClient,
    repository: str,
    process_pr: Callable[[dict[str, Any]], None],
    *,
    wake_hints: Mapping[str, Any] | None = None,
    max_iterations: int = 3,
    self_wake: Callable[[], None] | None = None,
) -> str:
    """Global one-writer sweep; dispatch hints never select the work set."""
    del wake_hints
    if max_iterations <= 0:
        raise R02Error("finalizer iteration bound must be positive")
    for _ in range(max_iterations):
        before = client.get_repository_metadata(repository)
        before_main = client.get_ref_oid(repository, before.default_branch) if hasattr(client, "get_ref_oid") else None
        prs = client.list_open_pull_requests(repository)
        manual: list[dict[str, Any]] = []
        for pr in prs:
            number = pr.get("number")
            if type(number) is int and number > 0:
                manual.append(pr)
        for pr in sorted(manual, key=lambda item: item["number"]):
            try:
                process_pr(pr)
            except StaleTrustedCheckoutError:
                if self_wake is not None:
                    self_wake()
                    return "stale-trusted-checkout-self-wake-dispatched"
                return "stale-trusted-checkout-self-wake-required"
        after = client.get_repository_metadata(repository)
        after_main = client.get_ref_oid(repository, after.default_branch) if hasattr(client, "get_ref_oid") else None
        if before.id == after.id and before.default_branch == after.default_branch and before_main == after_main:
            return "swept-all-manual-trust-prs"
        if self_wake is not None:
            self_wake()
            return "central-main-advanced-self-wake-dispatched"
        return "central-main-advanced-self-wake-required"
    if self_wake is not None:
        self_wake()
        return "bounded-work-exhausted-self-wake-dispatched"
    return "bounded-work-exhausted-self-wake-required"


def phase_gate(request_class: RequestClass) -> str:
    if request_class is RequestClass.RECONCILE:
        return "RECONCILE_NOT_ENABLED_IN_R02"
    if request_class is RequestClass.MACHINE_PUBLICATION:
        return "MACHINE_PUBLICATION_R03_PHASE_BLOCKED"
    return "R02"


def result_idempotency_marker(kind: str, triggering_comment_id: int) -> str:
    if type(kind) is not str or not re.fullmatch(r"[a-z0-9-]{1,40}", kind) or type(triggering_comment_id) is not int or triggering_comment_id <= 0:
        raise R02Error("result idempotency identity is invalid")
    return f"{RESULT_IDEMPOTENCY_PREFIX}{kind}:{triggering_comment_id} -->"


def has_result_for_comment(comments: Iterable[IssueComment], kind: str, triggering_comment_id: int) -> bool:
    marker = result_idempotency_marker(kind, triggering_comment_id)
    return any(marker in item.body for item in comments)


def parse_repository_id_hint(value: Any) -> int:
    if type(value) is int and type(value) is not bool:
        result = value
    elif type(value) is str and re.fullmatch(r"[1-9][0-9]{0,18}", value):
        result = int(value)
    else:
        raise R02Error("repository_id wake hint is malformed")
    if not 1 <= result <= 9_223_372_036_854_775_807:
        raise R02Error("repository_id wake hint is out of range")
    return result


def validate_machine_generated_scope(client: GitHubClient, repository: str, accepted_base_sha: str, head_sha: str) -> tuple[str, ...]:
    """Compare only semantic leaves; all non-generated central paths are immutable."""
    _base_tree, base_entries = client.get_commit_tree(repository, accepted_base_sha)
    _head_tree, head_entries = client.get_commit_tree(repository, head_sha)
    def leaves(entries: Iterable[Any]) -> dict[str, tuple[str, str, str]]:
        result: dict[str, tuple[str, str, str]] = {}
        all_paths: set[str] = set()
        for item in entries:
            path, mode, object_type, sha = item.path, item.mode, item.object_type, item.sha
            if path in all_paths or not path or path.startswith("/") or "\\" in path or c02.contains_control(path) or any(part in {"", ".", ".."} for part in path.split("/")):
                raise CandidateScopeError("machine candidate tree path is unsafe")
            all_paths.add(path)
            if object_type == "tree":
                continue
            if object_type != "blob" or mode not in {"100644", "100755"}:
                raise CandidateScopeError("machine candidate contains forbidden tree entry")
            result[path] = (mode, object_type, sha)
        return result
    base = leaves(base_entries)
    head = leaves(head_entries)
    changed = tuple(sorted(path for path in set(base) | set(head) if base.get(path) != head.get(path)))
    if any(path not in MACHINE_GENERATED_FILES and not path.startswith("skills/") for path in changed):
        raise CandidateScopeError("machine candidate changed a forbidden path")
    return changed


def _machine_branch(source_id: str) -> str:
    try:
        c02.validate_source_id(source_id)
    except c02.FederationError:
        raise R02Error("accepted sourceId cannot form a machine branch") from None
    return f"bot/federation/{source_id}"


def manifest_value(manifest: c02.Manifest) -> dict[str, Any]:
    """Serialize a C02 Manifest without introducing a second validator."""
    return {
        "schemaVersion": 2,
        "sources": [
            {
                "sourceId": source.source_id,
                "repository": source.repository,
                "repositoryId": source.repository_id,
                "ref": source.ref,
                "skillsRoot": source.skills_root,
                "skillPrefixes": list(source.skill_prefixes),
                "description": source.description,
            }
            for source in manifest.sources
        ],
    }


def c02_source_candidate(
    request: Request,
    accepted_manifest: c02.Manifest,
    *,
    source_id: str,
    repository_id: int,
    default_branch: str,
    default_description: str,
    default_prefixes: tuple[str, ...],
) -> c02.Manifest:
    """Build only the data adapter; C02 validates the resulting manifest."""
    existing = accepted_manifest.by_source_id.get(source_id)
    if request.request_class is RequestClass.ADD:
        if existing is not None:
            raise R02Error("ADD sourceId is already accepted")
        repository = request.repository_url.removeprefix("https://github.com/")
        value = {
            "sourceId": source_id,
            "repository": repository,
            "repositoryId": repository_id,
            "ref": request.branch or f"refs/heads/{default_branch}",
            "skillsRoot": request.skills_root or "skills",
            "skillPrefixes": list(request.skill_prefixes or default_prefixes),
            "description": request.description or default_description,
        }
        candidate_sources = list(accepted_manifest.sources) + [c02.SourceDeclaration(
            source_id=value["sourceId"],
            repository=value["repository"],
            repository_id=value["repositoryId"],
            ref=value["ref"],
            skills_root=value["skillsRoot"],
            skill_prefixes=tuple(value["skillPrefixes"]),
            description=value["description"],
        )]
    elif request.request_class is RequestClass.UPDATE:
        if existing is None or existing.repository_id != repository_id:
            raise R02Error("UPDATE must resolve exactly one accepted source identity")
        candidate_sources = [source for source in accepted_manifest.sources if source.source_id != source_id]
        candidate_sources.append(c02.SourceDeclaration(
            source_id=source_id,
            repository=request.repository_url.removeprefix("https://github.com/"),
            repository_id=repository_id,
            ref=request.branch or existing.ref,
            skills_root=request.skills_root or existing.skills_root,
            skill_prefixes=request.skill_prefixes or existing.skill_prefixes,
            description=request.description or existing.description,
        ))
    elif request.request_class is RequestClass.REMOVE:
        if existing is None or existing.repository_id != repository_id:
            raise R02Error("REMOVE must resolve exactly one accepted source identity")
        candidate_sources = [source for source in accepted_manifest.sources if source.source_id != source_id]
    else:
        raise R02Error("only ADD/UPDATE/REMOVE have an R02 manifest candidate")
    return c02.load_manifest_from_value({"schemaVersion": 2, "sources": [
        {
            "sourceId": source.source_id,
            "repository": source.repository,
            "repositoryId": source.repository_id,
            "ref": source.ref,
            "skillsRoot": source.skills_root,
            "skillPrefixes": list(source.skill_prefixes),
            "description": source.description,
        } for source in sorted(candidate_sources, key=lambda item: item.source_id)
    ]}, "R02 candidate federation.json")


def _manifest_bytes(manifest: c02.Manifest) -> bytes:
    return (json.dumps(manifest_value(manifest), indent=2, ensure_ascii=False, sort_keys=False) + "\n").encode("utf-8")


def _source_locator(request: Request) -> str:
    return request.repository_url.removeprefix("https://github.com/")


def _derived_source_id(repository: str) -> str:
    candidate = repository.lower().replace("/", "-")
    candidate = re.sub(r"[^a-z0-9-]+", "-", candidate).strip("-")
    try:
        return c02.validate_source_id(candidate)
    except c02.FederationError:
        raise R02Error("source repository cannot produce a deterministic sourceId") from None


class C02CandidateBuilder:
    """Production adapter that delegates manifest/package/catalog semantics to C02."""

    def __init__(self, client: GitHubClient, central_repository: str, *, trusted_checkout_sha: str):
        self.client = client
        self.central_repository = central_repository
        self.trusted_checkout_sha = trusted_checkout_sha
        self._capsule_temp_root: Path | None = None

    def _current_base(self, accepted_base_sha: str) -> tuple[RepositoryMetadata, str]:
        if not _C02_CAPSULE_ACTIVE:
            raise R02Error("C02 authority read requires the trusted execution capsule")
        repository = self.client.get_repository_metadata(self.central_repository)
        if repository.full_name != self.central_repository:
            raise StaleAuthorityError("central repository identity changed")
        current = self.client.get_ref_oid(self.central_repository, repository.default_branch)
        if current != accepted_base_sha or self.trusted_checkout_sha != accepted_base_sha:
            raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_BASE_MISMATCH")
        try:
            local_head = c02.head_commit_oid()
        except Exception as error:
            raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_UNAVAILABLE") from error
        if local_head != accepted_base_sha:
            raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_CODE_STALE")
        return repository, current

    def _central_state(self, accepted_base_sha: str) -> tuple[c02.Manifest, c02.LockState, bytes, dict[str, tuple[str, str, str]]]:
        if not _C02_CAPSULE_ACTIVE:
            raise R02Error("C02 committed-state read requires the trusted execution capsule")
        manifest = c02.load_trusted_previous_manifest()
        lock = c02.load_trusted_previous_lock(manifest)
        readme = c02.committed_regular_blob_bytes("README.md", commit=accepted_base_sha)
        _tree_sha, entries = self.client.get_commit_tree(self.central_repository, accepted_base_sha)
        tree = {item.path: (item.mode, item.object_type, item.sha) for item in entries}
        return manifest, lock, readme, tree

    def _validate_add_source(self, source: c02.SourceDeclaration) -> None:
        if self._capsule_temp_root is None:
            raise R02Error("C02 source validation requires the trusted execution capsule")
        bound = c02.bind_source_snapshot(
            self._capsule_temp_root,
            source,
            http_get=SOURCE_HTTP_GET,
            branch_fetcher=SOURCE_BRANCH_FETCHER,
        )
        c02.discover_public_skills(bound)

    def _plan(self, request: Request, request_class: RequestClass, accepted_base_sha: str) -> tuple[dict[str, tuple[str, bytes]], dict[str, tuple[str, str, str]], str | None, int | None]:
        if self._capsule_temp_root is None:
            raise R02Error("C02 planning requires the trusted execution capsule")
        _repository, _ = self._current_base(accepted_base_sha)
        accepted_manifest, accepted_lock, accepted_readme, tree = self._central_state(accepted_base_sha)
        source_repo = read_public_source_metadata(_source_locator(request))
        if source_repo.full_name.lower() != _source_locator(request).lower():
            raise R02Error("resolved source repository identity does not match requested locator")
        source_id: str
        existing: c02.SourceDeclaration | None
        if request_class is RequestClass.ADD:
            source_id = _derived_source_id(_source_locator(request))
            existing = accepted_manifest.by_source_id.get(source_id)
            if existing is not None or source_repo.repository_id in accepted_manifest.by_repository_id:
                raise R02Error("ADD source identity is already accepted")
        else:
            existing = accepted_manifest.by_repository_id.get(source_repo.repository_id)
            if existing is None:
                raise R02Error("request repositoryId does not identify one accepted source")
            source_id = existing.source_id
        prefixes = request.skill_prefixes or (existing.skill_prefixes if existing else (_derived_source_id(_source_locator(request).split("/", 1)[-1]),))
        candidate_manifest = c02_source_candidate(
            request,
            accepted_manifest,
            source_id=source_id,
            repository_id=source_repo.repository_id,
            default_branch=source_repo.default_branch,
            default_description=source_repo.description or "Federated source repository",
            default_prefixes=tuple(prefixes),
        )
        if request_class is RequestClass.ADD:
            self._validate_add_source(candidate_manifest.sources[-1])
            return {"federation.json": ("100644", _manifest_bytes(candidate_manifest))}, tree, source_id, source_repo.repository_id

        bound_sources, discovered = c02.discover_manifest_skills(
            self._capsule_temp_root,
            candidate_manifest,
            accepted_manifest,
            http_get=SOURCE_HTTP_GET,
            branch_fetcher=SOURCE_BRANCH_FETCHER,
        )
        desired = c02.build_desired_publication_state(
            self._capsule_temp_root,
            candidate_manifest,
            accepted_manifest,
            accepted_lock,
            bound_sources,
            discovered,
        )
        desired_lock = desired.lock
        desired_packages = desired.packages
        layout = c02.parse_readme_layout_bytes(accepted_readme)
        readme = c02.render_full_readme(layout, c02.render_converged_catalog_content(candidate_manifest, desired_lock, desired_packages))
        c02.validate_readme_catalog(candidate_manifest, desired_lock, desired_packages, c02.parse_readme_layout_bytes(readme))
        validate_readme_managed_diff(accepted_readme, readme)
        desired_files: dict[str, tuple[str, bytes]] = {
            "federation.json": ("100644", _manifest_bytes(candidate_manifest)),
            "federation.lock.json": ("100644", c02.render_lock(desired_lock)),
            "README.md": ("100644", readme),
        }
        for name, package in desired_packages.items():
            for record in package.files:
                desired_files[f"skills/{name}/{record.path}"] = ("100755" if record.executable else "100644", record.data)
        for path, (mode, object_type, _sha) in tree.items():
            if path.startswith("skills/") and object_type == "blob" and path not in desired_files:
                desired_files[path] = ("", b"")
        return desired_files, tree, source_id, source_repo.repository_id

    def __call__(self, request: Request, request_class: RequestClass, accepted_base_sha: str, head_sha: str) -> ProposalCandidate:
        with trusted_c02_execution() as temp_root:
            self._capsule_temp_root = temp_root
            try:
                desired, tree, source_id, repository_id = self._plan(request, request_class, accepted_base_sha)
            finally:
                self._capsule_temp_root = None
        changed = tuple(sorted(path for path, (mode, data) in desired.items() if mode == "" or tree.get(path, (None, None, None))[0:2] != (mode, "blob") or (mode != "" and self.client.get_blob(self.central_repository, tree[path][2]) != data)))
        if request_class in {RequestClass.UPDATE, RequestClass.REMOVE} and "federation.json" not in changed:
            raise R02Error("UPDATE/REMOVE requires an actual federation.json trust/configuration change")
        if not changed:
            return ProposalCandidate(accepted_base_sha, accepted_base_sha, (), request_class, source_id, repository_id, False)
        base_tree, _entries = self.client.get_commit_tree(self.central_repository, accepted_base_sha)
        tree_updates: list[Mapping[str, Any]] = []
        for path in changed:
            mode, data = desired[path]
            if mode == "":
                tree_updates.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            else:
                blob = self.client.create_blob(self.central_repository, base64.b64encode(data).decode("ascii"))
                tree_updates.append({"path": path, "mode": mode, "type": "blob", "sha": blob.sha})
        tree_object = self.client.create_tree(self.central_repository, base_tree, tree_updates)
        commit = self.client.create_commit(self.central_repository, f"Swift Stream federation {request_class.value}\n", tree_object.sha, [accepted_base_sha])
        return ProposalCandidate(commit.sha, accepted_base_sha, changed, request_class, source_id, repository_id, False)

    def _machine_desired(self, accepted_base_sha: str, source_id: str) -> tuple[dict[str, tuple[str, bytes]], dict[str, tuple[str, str, str]], c02.SourceDeclaration]:
        """Compute machine bytes through C02, returning no trust/configuration bytes."""
        if self._capsule_temp_root is None:
            raise R02Error("C02 machine planning requires the trusted execution capsule")
        _repository, _ = self._current_base(accepted_base_sha)
        accepted_manifest, accepted_lock, accepted_readme, tree = self._central_state(accepted_base_sha)
        sources = [item for item in accepted_manifest.sources if item.source_id == source_id]
        if len(sources) != 1:
            raise R02Error("machine source identity is not singular in accepted manifest")
        bound_sources, discovered = c02.discover_manifest_skills(
            self._capsule_temp_root,
            accepted_manifest,
            accepted_manifest,
            http_get=SOURCE_HTTP_GET,
            branch_fetcher=SOURCE_BRANCH_FETCHER,
        )
        desired = c02.build_desired_publication_state(
            self._capsule_temp_root,
            accepted_manifest,
            accepted_manifest,
            accepted_lock,
            bound_sources,
            discovered,
        )
        layout = c02.parse_readme_layout_bytes(accepted_readme)
        readme = c02.render_full_readme(layout, c02.render_converged_catalog_content(accepted_manifest, desired.lock, desired.packages))
        c02.validate_readme_catalog(accepted_manifest, desired.lock, desired.packages, c02.parse_readme_layout_bytes(readme))
        files: dict[str, tuple[str, bytes]] = {
            "federation.lock.json": ("100644", c02.render_lock(desired.lock)),
            "README.md": ("100644", readme),
        }
        for name, package in desired.packages.items():
            for record in package.files:
                files[f"skills/{name}/{record.path}"] = ("100755" if record.executable else "100644", record.data)
        for path, (_mode, object_type, _sha) in tree.items():
            if path.startswith("skills/") and object_type == "blob" and path not in files:
                files[path] = ("", b"")
        return files, tree, sources[0]

    def _machine_plan(self, accepted_base_sha: str, source_id: str) -> tuple[dict[str, tuple[str, bytes]], dict[str, tuple[str, str, str]], c02.SourceDeclaration]:
        with trusted_c02_execution() as temp_root:
            self._capsule_temp_root = temp_root
            try:
                return self._machine_desired(accepted_base_sha, source_id)
            finally:
                self._capsule_temp_root = None

    def machine_candidate(self, accepted_base_sha: str, source_id: str) -> ProposalCandidate:
        desired, tree, source = self._machine_plan(accepted_base_sha, source_id)
        changed = tuple(sorted(path for path, (mode, data) in desired.items() if mode == "" or tree.get(path, (None, None, None))[:2] != (mode, "blob") or (mode != "" and path in tree and self.client.get_blob(self.central_repository, tree[path][2]) != data)))
        if not changed:
            return ProposalCandidate(accepted_base_sha, accepted_base_sha, (), RequestClass.MACHINE_PUBLICATION, source.source_id, source.repository_id, False)
        base_tree, _entries = self.client.get_commit_tree(self.central_repository, accepted_base_sha)
        updates: list[Mapping[str, Any]] = []
        for path in changed:
            mode, data = desired[path]
            if mode == "":
                updates.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
            else:
                blob = self.client.create_blob(self.central_repository, base64.b64encode(data).decode("ascii"))
                updates.append({"path": path, "mode": mode, "type": "blob", "sha": blob.sha})
        tree_object = self.client.create_tree(self.central_repository, base_tree, updates)
        commit = self.client.create_commit(self.central_repository, "Swift Stream federation machine publication\n", tree_object.sha, [accepted_base_sha])
        return ProposalCandidate(commit.sha, accepted_base_sha, changed, RequestClass.MACHINE_PUBLICATION, source.source_id, source.repository_id, False)

    def validate_machine_head(self, accepted_base_sha: str, source_id: str, head_sha: str) -> tuple[bool, str]:
        desired, base_tree, source = self._machine_plan(accepted_base_sha, source_id)
        if source.source_id != source_id:
            return False, "MACHINE_SOURCE_MISMATCH"
        _tree_sha, entries = self.client.get_commit_tree(self.central_repository, head_sha)
        actual = {}
        actual_directories: set[str] = set()
        all_paths: set[str] = set()
        for item in entries:
            if type(item.path) is not str or not item.path or item.path.startswith("/") or "\\" in item.path or c02.contains_control(item.path) or any(part in {"", ".", ".."} for part in item.path.split("/") ) or item.path in all_paths:
                return False, "MACHINE_CANDIDATE_UNSAFE_TREE_PATH"
            all_paths.add(item.path)
            if item.object_type == "tree":
                if item.mode != "040000":
                    return False, "MACHINE_CANDIDATE_TREE_STRUCTURE_MISMATCH"
                actual_directories.add(item.path)
            elif item.object_type == "blob" and item.mode in {"100644", "100755"}:
                actual[item.path] = (item.mode, item.object_type, item.sha)
            else:
                return False, "MACHINE_CANDIDATE_FORBIDDEN_TREE_ENTRY"
        base = {path: value for path, value in base_tree.items() if value[1] == "blob"}
        expected = dict(base)
        for path, (mode, data) in desired.items():
            if mode == "":
                expected.pop(path, None)
            else:
                expected[path] = (mode, "blob", "")
        allowed = set(MACHINE_GENERATED_FILES) | {path for path in set(base) | set(expected) if path.startswith("skills/")}
        changed_paths = {path for path in set(base) | set(actual) if base.get(path) != actual.get(path)}
        if any(path not in allowed for path in changed_paths):
            return False, "MACHINE_FORBIDDEN_PATH_CHANGE"
        if set(actual) != set(expected):
            return False, "MACHINE_CANDIDATE_DIFF_MISMATCH"
        expected_directories = {"/".join(path.split("/")[:index]) for path in expected for index in range(1, len(path.split("/")))}
        if actual_directories != expected_directories:
            return False, "MACHINE_CANDIDATE_TREE_STRUCTURE_MISMATCH"
        for path, (mode, object_type, _sha) in expected.items():
            if path not in actual or actual[path][0:2] != (mode, object_type):
                return False, "MACHINE_CANDIDATE_DIFF_MISMATCH"
            expected_bytes = desired[path][1] if path in desired and desired[path][0] != "" else self.client.get_blob(self.central_repository, base[path][2])
            if self.client.get_blob(self.central_repository, actual[path][2]) != expected_bytes:
                return False, "MACHINE_CANDIDATE_CONTENT_MISMATCH"
        metadata = self.client.get_commit_metadata(self.central_repository, head_sha)
        if metadata.parents != (accepted_base_sha,):
            return False, "MACHINE_CANDIDATE_PARENT_MISMATCH"
        return True, "MACHINE_CANDIDATE_MATCHES_C02"

    @staticmethod
    def _validate_recursive_tree(entries: Iterable[Any], expected_paths: set[str] | None = None) -> tuple[bool, str, dict[str, tuple[str, str]]]:
        """Validate Git's recursive tree shape while treating directories as structure."""
        leaves: dict[str, tuple[str, str]] = {}
        directories: set[str] = set()
        all_paths: set[str] = set()
        for item in entries:
            path = item.path if hasattr(item, "path") else item[0]
            mode = item.mode if hasattr(item, "mode") else item[1]
            object_type = item.object_type if hasattr(item, "object_type") else item[2]
            sha = item.sha if hasattr(item, "sha") else item[3]
            if type(path) is not str or not path or path.startswith("/") or "\\" in path or any(part in {"", ".", ".."} for part in path.split("/")) or path in all_paths:
                return False, "CANDIDATE_UNSAFE_TREE_PATH", {}
            all_paths.add(path)
            if object_type == "tree" and mode == "040000":
                directories.add(path)
            elif object_type == "blob" and mode in {"100644", "100755"}:
                leaves[path] = (mode, sha)
            elif object_type == "blob" and mode == "120000":
                return False, "CANDIDATE_SYMLINK_FORBIDDEN", {}
            elif object_type == "commit" and mode == "160000":
                return False, "CANDIDATE_GITLINK_FORBIDDEN", {}
            else:
                return False, "CANDIDATE_TREE_MODE_TYPE_MISMATCH", {}
        required_directories = {"/".join(path.split("/")[:index]) for path in leaves for index in range(1, len(path.split("/")))}
        if directories != required_directories:
            return False, "CANDIDATE_TREE_STRUCTURE_MISMATCH", {}
        if expected_paths is not None and set(leaves) != expected_paths:
            return False, "CANDIDATE_DIFF_MISMATCH", {}
        return True, "", leaves

    def validate_head(self, request: Request, request_class: RequestClass, accepted_base_sha: str, head_sha: str) -> tuple[bool, str]:
        with trusted_c02_execution() as temp_root:
            self._capsule_temp_root = temp_root
            try:
                desired, base_tree, _source_id, _repository_id = self._plan(request, request_class, accepted_base_sha)
            finally:
                self._capsule_temp_root = None
        _tree_sha, entries = self.client.get_commit_tree(self.central_repository, head_sha)
        base_ok, base_reason, base_leaves = self._validate_recursive_tree((path, mode, object_type, sha) for path, (mode, object_type, sha) in base_tree.items())
        if not base_ok:
            return False, "ACCEPTED_BASE_CONTAINS_NON_BLOB" if base_reason in {"CANDIDATE_GITLINK_FORBIDDEN", "CANDIDATE_SYMLINK_FORBIDDEN"} else base_reason
        actual_ok, actual_reason, actual_leaves = self._validate_recursive_tree(entries)
        if not actual_ok:
            return False, actual_reason
        expected: dict[str, tuple[str, bytes]] = {}
        for path, (mode, blob_sha) in base_leaves.items():
            expected[path] = (mode, self.client.get_blob(self.central_repository, blob_sha))
        for path, (mode, data) in desired.items():
            if mode == "":
                expected.pop(path, None)
            else:
                expected[path] = (mode, data)
        expected_paths = set(expected)
        if set(actual_leaves) != expected_paths:
            return False, "CANDIDATE_DIFF_MISMATCH"
        expected_directories = {"/".join(path.split("/")[:index]) for path in expected_paths for index in range(1, len(path.split("/")))}
        actual_directories = {item.path for item in entries if item.object_type == "tree"}
        if actual_directories != expected_directories:
            return False, "CANDIDATE_TREE_STRUCTURE_MISMATCH"
        for path, (mode, data) in expected.items():
            actual_mode, actual_sha = actual_leaves[path]
            if actual_mode != mode or self.client.get_blob(self.central_repository, actual_sha) != data:
                return False, "CANDIDATE_CONTENT_MISMATCH"
        metadata = self.client.get_commit_metadata(self.central_repository, head_sha)
        if metadata.parents != (accepted_base_sha,):
            return False, "CANDIDATE_PARENT_MISMATCH"
        return True, "CANDIDATE_MATCHES_C02"


class R02Controller:
    """Trusted central orchestration around the immutable R01/C02 authorities."""

    def __init__(self, client: GitHubClient, central_repository: str, app: AppIdentity, *, candidate_builder: CandidateBuilder | None = None, environ: Mapping[str, str] | None = None):
        self.client = client
        self.central_repository = central_repository
        self.app = app
        self.candidate_builder = candidate_builder
        self.environ = os.environ if environ is None else environ

    def current_accepted_main(self) -> tuple[RepositoryMetadata, str]:
        repository = self.client.get_repository_metadata(self.central_repository)
        if repository.full_name != self.central_repository:
            raise StaleAuthorityError("central repository metadata does not bind to configured repository")
        return repository, self.client.get_ref_oid(self.central_repository, repository.default_branch)

    def _accepted_sources(self, current_main: str | None = None) -> tuple[c02.SourceDeclaration, ...]:
        """Read accepted C02 authority only inside the audited capsule.

        The remote main SHA is supplied by the caller when it already has a
        bound operation snapshot.  A standalone call obtains that same
        snapshot first, then proves the trusted checkout is exactly at it
        before loading federation.json.
        """
        if current_main is None:
            _repository, current_main = self.current_accepted_main()
        try:
            with trusted_c02_execution():
                if c02.head_commit_oid() != current_main:
                    raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_CODE_STALE")
                manifest = c02.load_trusted_previous_manifest()
        except StaleTrustedCheckoutError:
            raise
        except Exception as error:
            raise R02Error(f"accepted federation manifest is unavailable: {_bounded_reason(error)}") from None
        return tuple(manifest.sources)

    def _machine_authority(self, summary: Mapping[str, Any], source: c02.SourceDeclaration, current_main: str, repository: RepositoryMetadata) -> MachinePRAuthority | None:
        number = summary.get("number")
        if type(number) is not int or number <= 0:
            return None
        try:
            pr = self.client.get_pull_request_metadata(self.central_repository, number)
        except GitHubAPIError:
            return None
        branch = _machine_branch(source.source_id)
        if (
            pr.author_id != self.app.bot_node_id
            or pr.author_login != self.app.bot_login
            or pr.head_repository != repository.full_name
            or pr.base_repository != repository.full_name
            or pr.head_repository_id != repository.node_id
            or pr.base_repository_id != repository.node_id
            or pr.head_ref != branch
            or pr.base_ref != repository.default_branch
        ):
            return None
        try:
            validate_machine_generated_scope(self.client, self.central_repository, current_main, pr.head_oid)
        except CandidateScopeError as error:
            return MachinePRAuthority(number, source.source_id, source.repository_id, pr.head_oid, False, _bounded_reason(error))
        return MachinePRAuthority(number, source.source_id, source.repository_id, pr.head_oid)

    def _machine_prs(self, current_main: str, repository: RepositoryMetadata, sources: Iterable[c02.SourceDeclaration]) -> dict[str, list[MachinePRAuthority]]:
        found: dict[str, list[MachinePRAuthority]] = {source.source_id: [] for source in sources}
        for summary in self.client.list_open_pull_requests(self.central_repository):
            for source in sources:
                authority = self._machine_authority(summary, source, current_main, repository)
                if authority is not None:
                    found[source.source_id].append(authority)
                    break
        return found

    def _bounded_machine_comment(self, number: int, result: str, reason: str) -> None:
        comments = self.client.list_issue_comments(self.central_repository, number)
        _post_bounded_result(self.client, self.central_repository, number, comments, kind="machine", identity=number, result=result, reason=reason)

    def _close_machine_pr(self, number: int, result: str, reason: str) -> None:
        self._bounded_machine_comment(number, result, reason)
        self.client.update_pull_request_state(self.central_repository, number, state="closed")

    def _close_machine_pr_guarded(
        self,
        number: int,
        result: str,
        reason: str,
        pre_mutation_guard: Callable[[], None] | None,
    ) -> None:
        """Apply a manual authority guard independently to each machine mutation."""
        if pre_mutation_guard is not None:
            pre_mutation_guard()
        self._bounded_machine_comment(number, result, reason)
        if pre_mutation_guard is not None:
            pre_mutation_guard()
        self.client.update_pull_request_state(self.central_repository, number, state="closed")

    def reconcile(
        self,
        repository_id: Any,
        *,
        pre_mutation_guard: Callable[[], None] | None = None,
        dispatch_finalizer: bool = True,
    ) -> MachineReconcileResult:
        """Reconcile one accepted source; the wake input never supplies source semantics."""
        hinted_id = parse_repository_id_hint(repository_id)
        for attempt in range(3):
            repository, current_main = self.current_accepted_main()
            sources = tuple(source for source in self._accepted_sources(current_main) if source.repository_id == hinted_id)
            if len(sources) == 0:
                return MachineReconcileResult("NOOP", repository_id=hinted_id, reason="UNKNOWN_REPOSITORY_ID")
            if len(sources) != 1:
                return MachineReconcileResult("FAIL", repository_id=hinted_id, reason="AMBIGUOUS_REPOSITORY_ID")
            if self.candidate_builder is None or not hasattr(self.candidate_builder, "machine_candidate"):
                raise R02Error("machine C02 candidate builder is unavailable")
            source = sources[0]
            branch = _machine_branch(source.source_id)
            try:
                candidate = self.candidate_builder.machine_candidate(current_main, source.source_id)  # type: ignore[attr-defined]
                validate_proposal_scope(RequestClass.UPDATE, candidate.changed_paths)
                if any(path == "federation.json" or path.startswith(".github/") or path.startswith("automation/") for path in candidate.changed_paths):
                    raise CandidateScopeError("machine candidate changed a forbidden path")
            except Exception as error:
                try:
                    machine_prs = self._machine_prs(current_main, repository, sources)[source.source_id]
                    if len(machine_prs) == 1:
                        self._close_machine_pr_guarded(
                            machine_prs[0].number,
                            "MACHINE_RECONCILE_FAILED",
                            _bounded_reason(error),
                            pre_mutation_guard,
                        )
                except StaleAuthorityError:
                    raise
                except Exception:
                    pass
                return MachineReconcileResult("FAIL", source.source_id, hinted_id, _bounded_reason(error))

            machine_prs = self._machine_prs(current_main, repository, sources)[source.source_id]
            if len(machine_prs) > 1:
                return MachineReconcileResult("FAIL", source.source_id, hinted_id, "DUPLICATE_MACHINE_PULL_REQUESTS")
            if len(machine_prs) == 1 and not machine_prs[0].valid:
                self._close_machine_pr_guarded(
                    machine_prs[0].number,
                    "MACHINE_RECONCILE_FAILED",
                    machine_prs[0].invalid_reason,
                    pre_mutation_guard,
                )
                return MachineReconcileResult("FAIL", source.source_id, hinted_id, machine_prs[0].invalid_reason)
            if not candidate.changed_paths:
                if len(machine_prs) == 1:
                    self._close_machine_pr_guarded(
                        machine_prs[0].number,
                        "MACHINE_RECONCILE_NOOP",
                        "CURRENT_STATE_ALREADY_MATCHES",
                        pre_mutation_guard,
                    )
                return MachineReconcileResult("NOOP", source.source_id, hinted_id, "CURRENT_STATE_ALREADY_MATCHES")

            try:
                try:
                    before_oid = self.client.get_ref_oid(self.central_repository, branch)
                except NotFoundError:
                    before_oid = ZERO_OID
                if candidate.commit_sha != before_oid:
                    if pre_mutation_guard is not None:
                        pre_mutation_guard()
                    self.client.update_refs(repository.node_id, [RefUpdate(f"refs/heads/{branch}", before_oid, candidate.commit_sha, force=before_oid != ZERO_OID)])
            except RefCASConflict:
                if attempt + 1 < 3:
                    continue
                return MachineReconcileResult("FAIL", source.source_id, hinted_id, "MACHINE_BRANCH_CAS_CONFLICT_RECOMPUTE_EXHAUSTED")
            if len(machine_prs) == 1:
                number = machine_prs[0].number
            else:
                if pre_mutation_guard is not None:
                    pre_mutation_guard()
                number = self.client.create_machine_pull_request(
                    self.central_repository,
                    head=branch,
                    base=repository.default_branch,
                    title=f"Federation publication: {source.source_id}",
                    body=f"Automated publication for accepted source {source.source_id}.",
                )
            if pre_mutation_guard is not None:
                pre_mutation_guard()
            if dispatch_finalizer:
                self.client.dispatch_workflow(self.central_repository, "federation-state-finalize.yml", "refs/heads/main", {"expected_source_id": source.source_id})
            return MachineReconcileResult("CHANGED", source.source_id, hinted_id, f"MACHINE_PR_{number}")
        raise AssertionError("bounded reconcile loop did not return")

    def reconcile_all(self) -> tuple[MachineReconcileResult, ...]:
        """Reconcile every currently accepted source in deterministic order."""
        _repository, current_main = self.current_accepted_main()
        sources = tuple(sorted(self._accepted_sources(current_main), key=lambda item: (item.source_id, item.repository_id)))
        results: list[MachineReconcileResult] = []
        for source in sources:
            # Each one-source operation re-reads current authority. A source
            # removed or moved during the sweep is therefore a bounded NOOP.
            results.append(self.reconcile(source.repository_id, dispatch_finalizer=False))
        if any(result.outcome == "CHANGED" for result in results):
            self.client.dispatch_workflow(self.central_repository, "federation-state-finalize.yml", "refs/heads/main", {})
        return tuple(results)

    def _manual_reconcile_guard(
        self,
        snapshot: RequestSnapshot,
        pr_number: int,
        accepted_base_sha: str,
        default_branch: str,
    ) -> Callable[[], None]:
        """Return a read-only guard for the immutable manual RECONCILE authority."""

        def guard() -> None:
            repository, current_main = self.current_accepted_main()
            if current_main != accepted_base_sha or repository.default_branch != default_branch:
                raise StaleAuthorityError("RECONCILE authority changed before machine mutation")
            latest_pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
            latest_comments = self.client.list_issue_comments(self.central_repository, pr_number)
            latest_anchor = validate_unique_anchor(latest_comments, latest_pr, RequestClass.RECONCILE, self.app)
            assert_snapshot_unchanged(snapshot, latest_pr, latest_comments, latest_anchor)

        return guard

    def reconcile_interactive_request(self, pr_number: int, accepted_base_sha: str) -> MachineReconcileResult:
        """Execute one immutable manual RECONCILE request and close its PR."""
        pr, anchor, fold, comments = self.anchor_and_reconstruct(pr_number, RequestClass.RECONCILE)
        if fold.request != anchor.anchor.initial_request:
            raise R02Error("RECONCILE request was changed by a mutable patch")
        repository, current_main = self.current_accepted_main()
        if accepted_base_sha != current_main or pr.base_ref != repository.default_branch or pr.base_oid != current_main:
            raise StaleAuthorityError("RECONCILE request is not bound to the exact accepted central base")
        snapshot = capture_snapshot(pr, comments, anchor)
        if has_result_for_comment(comments, "reconcile", anchor.comment.database_id):
            return MachineReconcileResult("NOOP", reason="RECONCILE_RESULT_ALREADY_EXISTS")
        request = anchor.anchor.initial_request
        source_repository = request.repository_url.removeprefix("https://github.com/")
        try:
            public_source = read_public_source_metadata(source_repository)
            if public_source.full_name != source_repository:
                raise R02Error("anchored source repository metadata does not match the request")
            accepted_sources = self._accepted_sources(current_main)
            matches = tuple(
                source
                for source in accepted_sources
                if source.repository_id == public_source.repository_id and source.repository == public_source.full_name
            )
            if len(matches) == 0:
                result = MachineReconcileResult("NOOP", repository_id=public_source.repository_id, reason="SOURCE_NOT_ACCEPTED_USE_ADD_SOURCE")
            elif len(matches) != 1:
                result = MachineReconcileResult("FAIL", repository_id=public_source.repository_id, reason="AMBIGUOUS_ACCEPTED_SOURCE_IDENTITY")
            else:
                latest_repository, latest_main = self.current_accepted_main()
                latest_pr = self.client.get_pull_request_metadata(self.central_repository, pr.number)
                latest_comments = self.client.list_issue_comments(self.central_repository, pr.number)
                latest_anchor = validate_unique_anchor(latest_comments, latest_pr, RequestClass.RECONCILE, self.app)
                if latest_main != current_main or latest_repository.default_branch != repository.default_branch:
                    raise StaleAuthorityError("RECONCILE accepted authority changed before source reconciliation")
                assert_snapshot_unchanged(snapshot, latest_pr, latest_comments, latest_anchor)
                result = self.reconcile(
                    public_source.repository_id,
                    pre_mutation_guard=self._manual_reconcile_guard(
                        snapshot,
                        pr.number,
                        accepted_base_sha,
                        repository.default_branch,
                    ),
                )
        except StaleAuthorityError:
            raise
        except Exception as error:
            result = MachineReconcileResult("FAIL", reason=_bounded_reason(error))

        # Re-read the immutable request authority before creating any result or
        # closing the technical request. A race cannot create machine work.
        reread_pr = self.client.get_pull_request_metadata(self.central_repository, pr.number)
        reread_comments = self.client.list_issue_comments(self.central_repository, pr.number)
        reread_anchor = validate_unique_anchor(reread_comments, reread_pr, RequestClass.RECONCILE, self.app)
        assert_snapshot_unchanged(snapshot, reread_pr, reread_comments, reread_anchor)
        if result.outcome == "NOOP":
            result_code = "RECONCILE_NOOP" if result.reason == "CURRENT_STATE_ALREADY_MATCHES" else "RECONCILE_UNKNOWN_SOURCE"
        elif result.outcome == "CHANGED":
            result_code = "RECONCILE_CHANGED"
        else:
            result_code = "RECONCILE_FAILED"
        _post_bounded_result(
            self.client,
            self.central_repository,
            pr.number,
            reread_comments,
            kind="reconcile",
            identity=reread_anchor.comment.database_id,
            result=result_code,
            reason=result.reason,
        )
        self.client.update_pull_request_state(self.central_repository, pr.number, state="closed")
        return result

    def anchor_and_reconstruct(self, pr_number: int, request_class: RequestClass, semantic_validator: Callable[[Request], bool] | None = None) -> tuple[PullRequestMetadata, AnchorComment, PatchFoldResult, tuple[IssueComment, ...]]:
        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        require_same_repository_head(pr, self.central_repository)
        comments = self.client.list_issue_comments(self.central_repository, pr.number)
        if _anchor_candidates(comments):
            anchor = validate_unique_anchor(comments, pr, request_class, self.app)
        else:
            anchor = create_anchor_once(self.client, self.central_repository, pr, request_class, self.app, comments)
            pr = self.client.get_pull_request_metadata(self.central_repository, pr.number)
            comments = self.client.list_issue_comments(self.central_repository, pr.number)
            anchor = validate_unique_anchor(comments, pr, request_class, self.app)
        return pr, anchor, reconstruct_from_github(self.client, self.central_repository, pr, anchor, comments, semantic_validator), comments

    def interactive_proposal(self, pr_number: int, request_class: RequestClass, accepted_base_sha: str, request_ref: str, *, semantic_validator: Callable[[Request], bool] | None = None) -> ProposalCandidate:
        if request_class not in MANUAL_CLASSES:
            raise R02Error("interactive proposal class is not an R02 manual class")
        if self.candidate_builder is None:
            raise R02Error("C02 candidate builder is not configured")
        repository, current_main = self.current_accepted_main()
        if accepted_base_sha != current_main:
            raise StaleAuthorityError("interactive proposal was not bound to current accepted main")
        pr, anchor, fold, comments = self.anchor_and_reconstruct(pr_number, request_class, semantic_validator)
        if pr.base_ref != repository.default_branch or pr.base_oid != current_main:
            raise StaleAuthorityError("PR base is not the exact accepted central base")
        validate_existing_request_head(self.client, self.central_repository, pr, request_class, current_main)
        snapshot = capture_snapshot(pr, comments, anchor)
        candidate = self.candidate_builder(fold.request, request_class, current_main, pr.head_oid)
        if candidate.marker_present:
            raise CandidateScopeError("valid proposal candidates must remove the transient request marker")
        validate_proposal_scope(request_class, candidate.changed_paths)
        reread_pr = self.client.get_pull_request_metadata(self.central_repository, pr.number)
        reread_comments = self.client.list_issue_comments(self.central_repository, pr.number)
        reread_anchor = validate_unique_anchor(reread_comments, reread_pr, request_class, self.app)
        assert_snapshot_unchanged(snapshot, reread_pr, reread_comments, reread_anchor)
        replace_request_ref_cas(self.client, repository.node_id, request_ref, snapshot.head_oid, candidate)
        return candidate

    def trusted_machine_validation(self, pr_number: int, accepted_base_sha: str, *, expected_head_sha: str | None = None) -> TrustedValidationResult:
        repository, current_main = self.current_accepted_main()
        if current_main != accepted_base_sha:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, expected_head_sha or "0" * 40, current_main, reason="ACCEPTED_BASE_MOVED"))
        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        if expected_head_sha is not None and pr.head_oid != expected_head_sha:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, expected_head_sha, current_main, reason="VALIDATION_HEAD_CHANGED"))
        if pr.base_oid != current_main or pr.base_ref != repository.default_branch:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, pr.head_oid, current_main, reason="MACHINE_PR_BASE_MISMATCH"))
        sources = self._accepted_sources(current_main)
        matches: list[c02.SourceDeclaration] = []
        invalid_reasons: list[str] = []
        for source in sources:
            try:
                authority = self._machine_authority({"number": pr_number}, source, current_main, repository)
                if authority is not None:
                    matches.append(source)
                    if not authority.valid:
                        invalid_reasons.append(authority.invalid_reason)
            except (GitHubAPIError, CandidateScopeError, R02Error):
                continue
        if len(matches) != 1:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, pr.head_oid, current_main, reason="MACHINE_PR_AUTHORITY_INVALID"))
        source = matches[0]
        if invalid_reasons:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, pr.head_oid, current_main, source.source_id, source.repository_id, invalid_reasons[0]))
        try:
            valid, reason = self.candidate_builder.validate_machine_head(current_main, source.source_id, pr.head_oid)  # type: ignore[attr-defined]
        except Exception:
            valid, reason = False, "MACHINE_CANDIDATE_VALIDATION_FAILED"
        return TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, pr.head_oid, current_main, source.source_id, source.repository_id, "FINALIZER_AUTHORITY_REQUIRED" if valid else reason))

    def trusted_validation(self, pr_number: int, accepted_base_sha: str, candidate_check: Callable[[], tuple[bool, str]], *, expected_head_sha: str | None = None, allow_success: bool = False) -> TrustedValidationResult:
        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        if expected_head_sha is not None and pr.head_oid != expected_head_sha:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.UNRELATED, expected_head_sha, accepted_base_sha, reason="VALIDATION_HEAD_CHANGED"))
        try:
            repository, current_main = self.current_accepted_main()
        except R02Error:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.UNRELATED, pr.head_oid, accepted_base_sha, reason="ACCEPTED_MAIN_UNAVAILABLE"))
        if accepted_base_sha != current_main:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.UNRELATED, pr.head_oid, current_main, reason="ACCEPTED_BASE_MOVED"))
        try:
            validate_trusted_pr_shape(pr, self.central_repository, current_main, repository.default_branch)
        except R02Error:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.UNRELATED, pr.head_oid, current_main, reason="ACCEPTED_BASE_MISMATCH"))
        classes = []
        comments = self.client.list_issue_comments(self.central_repository, pr_number)
        for item in _anchor_candidates(comments):
            classes.append(item.anchor.request_class)
        if len(classes) != 1:
            return TrustedValidationResult("failure", bounded_check_output(RequestClass.UNRELATED, pr.head_oid, current_main, reason="ANCHOR_AUTHORITY_INVALID"))
        request_class = classes[0]
        try:
            anchor = validate_unique_anchor(comments, pr, request_class, self.app)
        except R02Error as error:
            return TrustedValidationResult("failure", bounded_check_output(request_class, pr.head_oid, current_main, reason=_bounded_reason(error)))
        snapshot = capture_snapshot(pr, comments, anchor)
        result = evaluate_trusted_validation(request_class, pr.head_oid, current_main, candidate_check, allow_success=allow_success, authority_snapshot=snapshot)
        try:
            assert_validation_snapshot_current(self.client, self.central_repository, self.app, result)
        except (R02Error, GitHubAPIError):
            return TrustedValidationResult("failure", bounded_check_output(request_class, snapshot.head_oid, snapshot.base_oid, reason="VALIDATION_AUTHORITY_CHANGED"), snapshot)
        return result

    def production_candidate_check(self, pr_number: int, accepted_base_sha: str, *, expected_head_sha: str | None = None) -> Callable[[], tuple[bool, str]]:
        def check() -> tuple[bool, str]:
            trusted = self.environ.get("FEDERATION_TRUSTED_CHECKOUT_SHA")
            if trusted != accepted_base_sha:
                raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_BASE_MISMATCH")
            try:
                with trusted_c02_execution():
                    local_head = c02.head_commit_oid()
            except Exception:
                raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_UNAVAILABLE") from None
            if local_head != accepted_base_sha:
                raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_CODE_STALE")
            if self.candidate_builder is None or not hasattr(self.candidate_builder, "validate_head"):
                return False, "CANDIDATE_VALIDATOR_UNAVAILABLE"
            current_pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
            if expected_head_sha is not None and current_pr.head_oid != expected_head_sha:
                return False, "VALIDATION_HEAD_CHANGED"
            comments = self.client.list_issue_comments(self.central_repository, pr_number)
            anchors = _anchor_candidates(comments)
            if len(anchors) != 1:
                return False, "ANCHOR_AUTHORITY_INVALID"
            request_class = anchors[0].anchor.request_class
            pr, anchor, fold, _comments = self.anchor_and_reconstruct(pr_number, request_class)
            if expected_head_sha is not None and pr.head_oid != expected_head_sha:
                return False, "VALIDATION_HEAD_CHANGED"
            candidate_builder = self.candidate_builder
            return candidate_builder.validate_head(fold.request, request_class, accepted_base_sha, pr.head_oid)  # type: ignore[attr-defined]
        return check

    def publish_validation_result(self, result: TrustedValidationResult) -> CheckRun:
        if result.conclusion == "success":
            raise R02Error("trusted-validation writer cannot publish a green conclusion")
        if result.snapshot is not None:
            assert_validation_snapshot_current(self.client, self.central_repository, self.app, result)
        return upsert_trusted_validation_check(self.client, self.central_repository, self.app, result, allow_create=True)

    def publish_finalizer_result(self, result: TrustedValidationResult) -> CheckRun:
        if result.conclusion == "success" and result.snapshot is None:
            raise R02Error("finalizer success has no bound authority snapshot")
        assert_validation_snapshot_current(self.client, self.central_repository, self.app, result)
        return upsert_trusted_validation_check(self.client, self.central_repository, self.app, result, allow_create=False)

    def dispatch_trusted_validation_recovery(self, pr_number: int) -> None:
        if type(pr_number) is not int or pr_number <= 0:
            raise R02Error("trusted-validation recovery PR number is invalid")
        self.client.dispatch_workflow(
            self.central_repository,
            "federation-trusted-validation.yml",
            "refs/heads/main",
            {"pull_number": str(pr_number)},
        )

    def finalize_one_machine_pr(self, authority: MachinePRAuthority) -> str:
        """Finalize one exact machine PR; every merge decision is re-bound to current state."""
        repository, accepted_main = self.current_accepted_main()
        sources = tuple(source for source in self._accepted_sources(accepted_main) if source.source_id == authority.source_id and source.repository_id == authority.repository_id)
        if len(sources) != 1:
            return "invalid-source"
        source = sources[0]
        fresh_authority = self._machine_authority({"number": authority.number}, source, accepted_main, repository)
        if fresh_authority is None:
            return "stale"
        if not fresh_authority.valid:
            self._close_machine_pr(authority.number, "MACHINE_RECONCILE_FAILED", fresh_authority.invalid_reason)
            return "closed"
        pr = self.client.get_pull_request_metadata(self.central_repository, authority.number)
        if pr.head_oid != authority.head_sha or pr.base_oid != accepted_main or pr.base_ref != repository.default_branch:
            return "stale"
        if self.candidate_builder is None or not hasattr(self.candidate_builder, "machine_candidate"):
            return "builder-unavailable"
        try:
            candidate = self.candidate_builder.machine_candidate(accepted_main, source.source_id)  # type: ignore[attr-defined]
        except Exception as error:
            self._close_machine_pr(authority.number, "MACHINE_RECONCILE_FAILED", _bounded_reason(error))
            return "closed"
        if not candidate.changed_paths:
            self._close_machine_pr(authority.number, "MACHINE_RECONCILE_NOOP", "CURRENT_STATE_ALREADY_MATCHES")
            return "closed"
        branch = _machine_branch(source.source_id)
        try:
            branch_head = self.client.get_ref_oid(self.central_repository, branch)
            if branch_head != candidate.commit_sha:
                self.client.update_refs(repository.node_id, [RefUpdate(f"refs/heads/{branch}", branch_head, candidate.commit_sha, force=True)])
            refreshed = self.client.get_pull_request_metadata(self.central_repository, authority.number)
            if refreshed.head_oid != candidate.commit_sha:
                return "stale"
            validate_machine_generated_scope(self.client, self.central_repository, accepted_main, refreshed.head_oid)
        except (GitHubAPIError, CandidateScopeError, R02Error):
            return "stale"

        checks = tuple(item for item in self.client.list_check_runs(self.central_repository, candidate.commit_sha) if item.name == TRUSTED_VALIDATION_NAME and item.head_sha == candidate.commit_sha and item.app_id == self.app.app_id)
        if len(checks) > 1:
            return "duplicate-check"
        if not checks:
            self.dispatch_trusted_validation_recovery(authority.number)
            return "check-recovery-dispatched"
        try:
            verify_machine_check_identity(
                checks[0],
                head_sha=candidate.commit_sha,
                accepted_base_sha=accepted_main,
                source_id=source.source_id,
                repository_id=source.repository_id,
            )
        except R02Error:
            return "check-evidence-blocked"
        valid, reason = self.candidate_builder.validate_machine_head(accepted_main, source.source_id, candidate.commit_sha)  # type: ignore[attr-defined]
        if not valid:
            result = TrustedValidationResult("failure", bounded_check_output(RequestClass.MACHINE_PUBLICATION, candidate.commit_sha, accepted_main, source.source_id, source.repository_id, reason))
            self.client.update_check_run(self.central_repository, checks[0].id, head_sha=candidate.commit_sha, conclusion="failure", output=render_check_run_output(result))
            self._close_machine_pr(authority.number, "MACHINE_RECONCILE_FAILED", reason)
            return "closed"
        # The final explicit reads close the main/head TOCTOU window before the
        # API's expected-head merge gate is invoked.
        latest_repository, latest_main = self.current_accepted_main()
        latest_pr = self.client.get_pull_request_metadata(self.central_repository, authority.number)
        if latest_repository.default_branch != repository.default_branch or latest_main != accepted_main or latest_pr.head_oid != candidate.commit_sha or latest_pr.base_oid != latest_main or latest_pr.base_ref != latest_repository.default_branch:
            return "stale"
        ready_result = TrustedValidationResult("success", bounded_check_output(RequestClass.MACHINE_PUBLICATION, candidate.commit_sha, accepted_main, source.source_id, source.repository_id, "READY"))
        self.client.update_check_run(self.central_repository, checks[0].id, head_sha=candidate.commit_sha, conclusion="success", output=render_check_run_output(ready_result))
        final_repository, final_main = self.current_accepted_main()
        final_sources = tuple(item for item in self._accepted_sources(final_main) if item.source_id == source.source_id and item.repository_id == source.repository_id)
        final_pr = self.client.get_pull_request_metadata(self.central_repository, authority.number)
        final_source = final_sources[0] if len(final_sources) == 1 else None
        final_authority = self._machine_authority({"number": authority.number}, final_source, final_main, final_repository) if final_source is not None else None
        final_checks = tuple(item for item in self.client.list_check_runs(self.central_repository, candidate.commit_sha) if item.name == TRUSTED_VALIDATION_NAME and item.head_sha == candidate.commit_sha and item.app_id == self.app.app_id)
        final_check_evidence_invalid = _machine_check_identity_invalid(final_checks, candidate.commit_sha, accepted_main, source)
        try:
            final_app = resolve_app_identity(self.client, self.app.slug)
        except R02Error:
            final_app = None
        if (
            final_repository.default_branch != repository.default_branch
            or final_main != accepted_main
            or final_pr.head_oid != candidate.commit_sha
            or final_pr.base_ref != final_repository.default_branch
            or final_pr.base_oid != final_main
            or final_authority is None
            or not final_authority.valid
            or final_authority.head_sha != candidate.commit_sha
            or final_source != source
            or final_app != self.app
            or len(final_checks) != 1
            or final_checks[0].conclusion != "success"
            or final_check_evidence_invalid
        ):
            if final_check_evidence_invalid:
                return "check-evidence-blocked"
            return "stale"
        pre_merge_repository, pre_merge_main = self.current_accepted_main()
        pre_merge_pr = self.client.get_pull_request_metadata(self.central_repository, authority.number)
        pre_merge_checks = tuple(item for item in self.client.list_check_runs(self.central_repository, candidate.commit_sha) if item.name == TRUSTED_VALIDATION_NAME and item.head_sha == candidate.commit_sha and item.app_id == self.app.app_id)
        if (
            pre_merge_repository.default_branch != repository.default_branch
            or pre_merge_main != accepted_main
            or pre_merge_pr.head_oid != candidate.commit_sha
            or pre_merge_pr.base_oid != pre_merge_main
            or pre_merge_pr.base_ref != pre_merge_repository.default_branch
            or len(pre_merge_checks) != 1
            or pre_merge_checks[0].conclusion != "success"
            or _machine_check_identity_invalid(pre_merge_checks, candidate.commit_sha, accepted_main, source)
        ):
            return "check-evidence-blocked" if _machine_check_identity_invalid(pre_merge_checks, candidate.commit_sha, accepted_main, source) or len(pre_merge_checks) != 1 else "stale"
        try:
            merged = self.client.merge_machine_pull_request(self.central_repository, authority.number, expected_head_sha=candidate.commit_sha)
        except GitHubAPIError:
            return "merge-rejected"
        return "merged" if merged.merged else "merge-rejected"

    def _state_finalize_machine_sweep(self, *, max_iterations: int, self_wake: Callable[[], None] | None) -> str:
        if max_iterations <= 0:
            raise R02Error("finalizer iteration bound must be positive")
        for _ in range(max_iterations):
            repository, current_main = self.current_accepted_main()
            sources = self._accepted_sources(current_main)
            machine = self._machine_prs(current_main, repository, sources)
            restart = False
            for source_id in sorted(machine):
                authorities = machine[source_id]
                if len(authorities) > 1:
                    raise R02Error("multiple exact machine PRs exist for one accepted source")
                if not authorities:
                    continue
                result = self.finalize_one_machine_pr(authorities[0])
                if result in {"merged", "closed"}:
                    # A close or merge changes the sweep set; restart from a
                    # fresh main/PR enumeration instead of using stale data.
                    restart = True
                    break
                if result in {"stale", "merge-rejected"}:
                    # A race or platform rejection gets a bounded fresh
                    # enumeration/recompute.  Only exhaustion self-wakes.
                    restart = True
                    break
                if result in {"check-recovery-dispatched", "check-evidence-blocked"}:
                    return f"machine-{result}"
                if result in {"invalid-source", "builder-unavailable", "duplicate-check"}:
                    return f"machine-{result}"
            if restart:
                continue
            after_repository, after_main = self.current_accepted_main()
            if after_repository.default_branch != repository.default_branch or after_main != current_main:
                continue
            return "machine-sweep-complete"
        if self_wake is not None:
            self_wake()
            return "bounded-work-exhausted-self-wake-dispatched"
        return "bounded-work-exhausted-self-wake-required"

    def state_finalize(self, *, wake_hints: Mapping[str, Any] | None = None, max_iterations: int = 3, self_wake: Callable[[], None] | None = None, process_pr: Callable[[dict[str, Any]], None]) -> str:
        del wake_hints
        _repository, current_main = self.current_accepted_main()
        sources = self._accepted_sources(current_main)
        if not sources:
            return finalize_manual_trust_sweep(self.client, self.central_repository, process_pr, max_iterations=max_iterations, self_wake=self_wake)
        result = self._state_finalize_machine_sweep(max_iterations=max_iterations, self_wake=self_wake)
        if result != "machine-sweep-complete":
            return result
        return finalize_manual_trust_sweep(self.client, self.central_repository, process_pr, max_iterations=max_iterations, self_wake=self_wake)

    def main_advance(self) -> str:
        """Wake reconciliation/finalization from current main, never from event text."""
        repository, current_main = self.current_accepted_main()
        sources = self._accepted_sources(current_main)
        machine = self._machine_prs(current_main, repository, sources)
        wake_finalizer = False
        dispatched: set[str] = set()
        for source_id in sorted(machine):
            if machine[source_id]:
                source = next(source for source in sources if source.source_id == source_id)
                self.client.dispatch_workflow(self.central_repository, "federation-reconcile.yml", "refs/heads/main", {"repository_id": str(source.repository_id)})
                dispatched.add(source_id)
                wake_finalizer = True
        for summary in self.client.list_open_pull_requests(self.central_repository):
            number = summary.get("number")
            if type(number) is not int or number <= 0:
                continue
            try:
                pr = self.client.get_pull_request_metadata(self.central_repository, number)
                require_same_repository_head(pr, self.central_repository)
                if (
                    pr.base_repository != repository.full_name
                    or pr.base_repository_id != repository.node_id
                    or pr.head_repository_id != repository.node_id
                    or pr.base_ref != repository.default_branch
                    or pr.base_oid != current_main
                ):
                    continue
                comments = self.client.list_issue_comments(self.central_repository, number)
                anchors = _anchor_candidates(comments)
                if len(anchors) == 1 and anchors[0].anchor.request_class in MANUAL_CLASSES:
                    validate_unique_anchor(comments, pr, anchors[0].anchor.request_class, self.app)
                    wake_finalizer = True
            except (GitHubAPIError, R02Error):
                continue
        if wake_finalizer:
            self.client.dispatch_workflow(self.central_repository, "federation-state-finalize.yml", "refs/heads/main", {})
        return f"MAIN_ADVANCE_DISPATCHED:{len(dispatched)}" if (dispatched or wake_finalizer) else "MAIN_ADVANCE_NOOP"

    def finalize_one_manual_pr(self, summary: Mapping[str, Any]) -> None:
        """Re-derive one current manual PR; never treats an enumeration hint as authority."""
        number = summary.get("number")
        if type(number) is not int or number <= 0:
            raise R02Error("finalizer PR summary has an invalid number")
        pr = self.client.get_pull_request_metadata(self.central_repository, number)
        comments = self.client.list_issue_comments(self.central_repository, number)
        anchors = _anchor_candidates(comments)
        if len(anchors) != 1 or anchors[0].anchor.request_class not in MANUAL_CLASSES:
            return
        request_class = anchors[0].anchor.request_class
        repository, accepted_base = self.current_accepted_main()
        try:
            self.interactive_proposal(number, request_class, accepted_base, f"refs/heads/{pr.head_ref}")
            regenerated = self.client.get_pull_request_metadata(self.central_repository, number)
        except StaleTrustedCheckoutError:
            raise
        except Exception as error:
            regenerated = self.client.get_pull_request_metadata(self.central_repository, number)
            result = TrustedValidationResult("failure", bounded_check_output(request_class, regenerated.head_oid, accepted_base, reason=_bounded_reason(error)))
            try:
                upsert_trusted_validation_check(self.client, self.central_repository, self.app, result, allow_create=False)
            except MissingTrustedCheckError:
                self.dispatch_trusted_validation_recovery(number)
            return
        result = self.trusted_validation(number, accepted_base, self.production_candidate_check(number, accepted_base, expected_head_sha=regenerated.head_oid), expected_head_sha=regenerated.head_oid, allow_success=True)
        try:
            self.publish_finalizer_result(result)
        except MissingTrustedCheckError:
            self.dispatch_trusted_validation_recovery(number)
        if result.output.get("result", "").startswith("TRUSTED_CHECKOUT_"):
            raise StaleTrustedCheckoutError(result.output["result"])


def _event_pull_number(path: str | None) -> int | None:
    if not path:
        return None
    try:
        value = c02.decode_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    if type(value) is not dict:
        return None
    for container in (value.get("pull_request"), value.get("issue")):
        if isinstance(container, dict) and type(container.get("number")) is int and container["number"] > 0:
            return container["number"]
    return None


def _event_trigger(path: str | None) -> tuple[str | None, int | None]:
    """Return the event kind and immutable human issue-comment ID, if any."""
    if not path:
        return None, None
    try:
        value = c02.decode_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None, None
    if type(value) is not dict:
        return None, None
    event_name = value.get("action") if type(value.get("action")) is str else None
    comment_value = value.get("comment")
    if type(comment_value) is dict and type(comment_value.get("id")) is int and comment_value["id"] > 0:
        return "issue_comment", comment_value["id"]
    return event_name, None


def _trigger_result(evidence: Iterable[Any], triggering_comment_id: int) -> tuple[str, bool]:
    for item in evidence:
        if getattr(item, "comment_id", None) == triggering_comment_id:
            kind = getattr(item, "kind", "ordinary")
            return {
                "applied": ("PATCH_APPLIED", True),
                "invalid": ("PATCH_INVALID", False),
                "unauthorized": ("PATCH_UNAUTHORIZED", False),
                "semantic-invalid": ("PATCH_SEMANTIC_INVALID", False),
            }.get(kind, ("DISCUSSION", False))
    return "DISCUSSION", False


def _runtime_repository(environ: Mapping[str, str]) -> str:
    repository = environ.get("GITHUB_REPOSITORY")
    if type(repository) is not str or repository.count("/") != 1 or any(not item for item in repository.split("/")):
        raise R02Error("GITHUB_REPOSITORY is missing or malformed")
    return repository


def _result_comment(kind: str, identity: int, result: str, reason: str) -> str:
    return f"{result_idempotency_marker(kind, identity)}\nFederation controller result: {_bounded_reason(result)} ({_bounded_reason(reason)})\n"


def _post_bounded_result(client: GitHubClient, repository: str, pr_number: int, comments: Iterable[IssueComment], *, kind: str, identity: int, result: str, reason: str) -> None:
    if not has_result_for_comment(comments, kind, identity):
        client.create_issue_comment(repository, pr_number, _result_comment(kind, identity, result, reason))


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="Swift Stream trusted federation controller")
    parser.add_argument("command", choices=("interactive", "trusted-validation", "state-finalize", "reconcile", "main-advance"))
    args = parser.parse_args(argv)
    client: GitHubClient | None = None
    number: int | None = None
    result_kind = "proposal"
    result_identity: int | None = None
    fresh_wake_dispatched = False

    def wake_fresh_finalizer() -> None:
        nonlocal fresh_wake_dispatched
        if fresh_wake_dispatched or client is None:
            return
        client.dispatch_workflow(repository, "federation-state-finalize.yml", "refs/heads/main", {})
        fresh_wake_dispatched = True

    try:
        env = os.environ
        repository = _runtime_repository(env)
        token = env.get("FEDERATION_GITHUB_TOKEN")
        slug = env.get("FEDERATION_APP_SLUG")
        if not token or not slug:
            raise R02Error("trusted GitHub token/App slug environment is missing")
        client = GitHubClient(token)
        app = resolve_app_identity(client, slug)
        trusted_checkout_sha = env.get("FEDERATION_TRUSTED_CHECKOUT_SHA")
        if type(trusted_checkout_sha) is not str or not re.fullmatch(r"[0-9a-f]{40}", trusted_checkout_sha):
            raise R02Error("trusted checkout SHA environment is missing or malformed")
        controller = R02Controller(client, repository, app, candidate_builder=C02CandidateBuilder(client, repository, trusted_checkout_sha=trusted_checkout_sha), environ=env)
        number_text = env.get("FEDERATION_WAKE_PULL_NUMBER")
        number = int(number_text) if number_text and number_text.isdigit() else _event_pull_number(env.get("FEDERATION_EVENT_PATH"))
        event_kind, triggering_comment_id = _event_trigger(env.get("FEDERATION_EVENT_PATH"))
        if args.command == "reconcile":
            hint = env.get("FEDERATION_RECONCILE_REPOSITORY_ID")
            controller.reconcile_all() if hint is None or hint == "" else controller.reconcile(hint)
        elif args.command == "main-advance":
            controller.main_advance()
        elif args.command in {"interactive", "trusted-validation"}:
            if number is None:
                raise R02Error("authoritative PR number is unavailable")
            if args.command == "interactive":
                comments = client.list_issue_comments(repository, number)
                anchors = _anchor_candidates(comments)
                if anchors:
                    request_class = anchors[0].anchor.request_class
                else:
                    pr = client.get_pull_request_metadata(repository, number)
                    request_class = read_request_marker(client, repository, pr.head_oid)
                repository_metadata, accepted_main = controller.current_accepted_main()
                pr = client.get_pull_request_metadata(repository, number)
                if request_class is RequestClass.RECONCILE:
                    result_kind = "reconcile"
                    anchor = validate_unique_anchor(comments, pr, request_class, app) if anchors else None
                    if anchor is not None:
                        result_identity = anchor.comment.database_id
                    controller.reconcile_interactive_request(number, accepted_main)
                    return 0
                if event_kind == "issue_comment":
                    if triggering_comment_id is None:
                        raise R02Error("issue-comment trigger ID is unavailable")
                    result_kind = "patch"
                    result_identity = triggering_comment_id
                    trigger_comment = next((item for item in comments if item.database_id == triggering_comment_id), None)
                    if trigger_comment is None:
                        raise R02Error("triggering issue comment is not present in the authoritative comment fold")
                    _pr, trigger_anchor, trigger_fold, _fold_comments = controller.anchor_and_reconstruct(number, request_class)
                    trigger_result, should_apply = _trigger_result(trigger_fold.evidence, triggering_comment_id)
                    if has_result_for_comment(comments, result_kind, result_identity):
                        return 0
                    if not should_apply:
                        _post_bounded_result(client, repository, number, comments, kind=result_kind, identity=result_identity, result=trigger_result, reason="trigger-comment-not-applied")
                        return 0
                candidate = controller.interactive_proposal(number, request_class, accepted_main, f"refs/heads/{pr.head_ref}")
                updated_comments = client.list_issue_comments(repository, number)
                anchor = validate_unique_anchor(updated_comments, pr, request_class, app)
                if result_identity is None:
                    result_identity = anchor.comment.database_id
                _post_bounded_result(client, repository, number, updated_comments, kind=result_kind, identity=result_identity, result="PROPOSAL_UPDATED", reason=f"{request_class.value}:{len(candidate.changed_paths)}")
                client.dispatch_workflow(repository, "federation-state-finalize.yml", "refs/heads/main", {"pull_number": str(number)})
            else:
                _repo, accepted_main = controller.current_accepted_main()
                initial_pr = client.get_pull_request_metadata(repository, number)
                comments = client.list_issue_comments(repository, number)
                if not _anchor_candidates(comments) and _MACHINE_BRANCH_RE.fullmatch(initial_pr.head_ref):
                    result = controller.trusted_machine_validation(number, accepted_main, expected_head_sha=initial_pr.head_oid)
                    controller.publish_validation_result(result)
                    client.dispatch_workflow(repository, "federation-state-finalize.yml", "refs/heads/main", {"pull_number": str(number)})
                else:
                    result = controller.trusted_validation(number, accepted_main, controller.production_candidate_check(number, accepted_main, expected_head_sha=initial_pr.head_oid), expected_head_sha=initial_pr.head_oid)
                    controller.publish_validation_result(result)
                    client.dispatch_workflow(repository, "federation-state-finalize.yml", "refs/heads/main", {"pull_number": str(number)})
        elif args.command == "state-finalize":
            work_limit_text = env.get("FEDERATION_WORK_LIMIT", "3")
            if not re.fullmatch(r"[1-9][0-9]?", work_limit_text):
                raise R02Error("FEDERATION_WORK_LIMIT is malformed")
            work_limit = int(work_limit_text)
            if work_limit > 64:
                raise R02Error("FEDERATION_WORK_LIMIT is out of range")
            controller.state_finalize(
                wake_hints={"pull_number": number},
                max_iterations=work_limit,
                process_pr=controller.finalize_one_manual_pr,
                self_wake=wake_fresh_finalizer,
            )
        return 0
    except Exception as error:
        if isinstance(error, StaleAuthorityError) and client is not None:
            try:
                wake_fresh_finalizer()
            except Exception:
                pass
        if args.command == "interactive" and client is not None and number is not None:
            try:
                comments = client.list_issue_comments(repository, number)
                identity = result_identity
                if identity is None:
                    anchor = next(iter(_anchor_candidates(comments)), None)
                    identity = anchor.comment.database_id if anchor is not None else None
                if identity is not None:
                    _post_bounded_result(client, repository, number, comments, kind=result_kind, identity=identity, result="PROPOSAL_BLOCKED", reason=type(error).__name__)
            except Exception:
                pass
        if isinstance(error, GraphQLError):
            print(f"C03-R02 controller blocked: GraphQLError:{_safe_graphql_diagnostic(error)}", file=sys.stderr)
        else:
            print(f"C03-R02 controller blocked: {type(error).__name__}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())


def classify_request(
    *,
    marker_content: str | None = None,
    anchor: RequestAnchor | None = None,
    title: str = "",
    head_branch: str = "",
) -> RequestClass:
    if anchor is not None:
        if not isinstance(anchor, RequestAnchor):
            raise ControllerError("anchor input must be a validated RequestAnchor")
        return anchor.request_class
    if marker_content is not None:
        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE, RequestClass.RECONCILE):
            if marker_content == request_class.value:
                return request_class
    match = _MACHINE_BRANCH_RE.fullmatch(head_branch)
    if match:
        try:
            c02.validate_source_id(match.group(1))
        except c02.FederationError:
            pass
        else:
            return RequestClass.MACHINE_PUBLICATION
    del title
    return RequestClass.UNRELATED


def reconstruct_request(
    anchor: RequestAnchor,
    comments: Iterable[CommentEvent],
    semantic_validator: Any = None,
) -> PatchFoldResult:
    return fold_patch_events(anchor, comments, semantic_validator)


def parse_c02_manifest(value: Mapping[str, Any]) -> c02.Manifest:
    """Explicit adapter: C02 remains the sole source/manifest authority."""
    return c02.load_manifest_from_value(dict(value), "candidate federation.json")


def validate_candidate_diff(paths: Iterable[str]) -> CandidateDiff:
    normalized = tuple(sorted(set(paths)))
    for path in normalized:
        if not path or path.startswith("/") or "\\" in path or "\x00" in path or any(part in {"", ".", ".."} for part in path.split("/")):
            raise ControllerError("candidate diff contains an unsafe path")
    return CandidateDiff(normalized)


class R01Controller:
    """State-free coordinator surface, with every live action explicitly absent."""

    def classify(self, **inputs: Any) -> RequestClass:
        return classify_request(**inputs)

    def reconstruct(self, anchor: RequestAnchor, comments: Iterable[CommentEvent], semantic_validator: Any = None) -> PatchFoldResult:
        return reconstruct_request(anchor, comments, semantic_validator)

    def finalize_live_request(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise PhaseNotImplementedError("R02 live request lifecycle is not implemented in C03-R01")

    def mutate_github(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise PhaseNotImplementedError("R02+ GitHub mutation is not implemented in C03-R01")

    def reconcile(self, *args: Any, **kwargs: Any) -> None:
        del args, kwargs
        raise PhaseNotImplementedError("R03 reconciliation is not implemented in C03-R01")
