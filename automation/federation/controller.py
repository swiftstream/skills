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
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Protocol

from scripts import federate as c02

from .github_api import (
    AppMetadata,
    BotMetadata,
    CheckRun,
    CommitStatus,
    GitCommitObject,
    GitHubAPIError,
    GitHubClient,
    GraphQLError,
    IssueComment,
    IssueMetadata,
    InvalidResponseError,
    MergeResult,
    NotFoundError,
    PullRequestMetadata,
    PullRequestStageMutationReceipt,
    RefCASConflict,
    RefUpdate,
    RepositoryMetadata,
    StatusWriteReceipt,
    ZERO_OID,
)
from .request_model import (
    ANCHOR_MARKER,
    ISSUE_REQUEST_ANCHOR_MARKER,
    ISSUE_PATCH_PROJECTION_MARKER,
    ISSUE_HEAD_CLAIM_MARKER,
    REQUIRED_STATUS_EPOCH_MARKER,
    ISSUE_FINALIZATION_EPOCH_MARKER,
    ISSUE_CANCELLATION_FENCE_MARKER,
    ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER,
    ISSUE_TERMINAL_CANCELLED_RESULT_MARKER,
    ISSUE_NO_PR_CANCELLED_RESULT_MARKER,
    ISSUE_INTERNAL_PR_BINDING_MARKER,
    PR_ISSUE_ORIGIN_BINDING_MARKER,
    PATCH_SENTINEL,
    REQUEST_MARKER,
    CommentEvent,
    FoldEvidence,
    IssuePatchEvent,
    IssueBranchLease,
    IssueRequestAnchor,
    IssuePRBinding,
    IssueHeadClaim,
    RequiredStatusEpoch,
    RequiredStatusEpochReason,
    IssueFinalizationEpoch,
    IssueCancellationFence,
    IssueCancellationDraftWitness,
    IssueTerminalCancelledResult,
    IssueTerminalCancelledProofKind,
    IssueNoPRCancelledResult,
    IssueNoPRCancelledProofKind,
    ExactPullRequestStageMutationEvidence,
    PullRequestStageMutationOperation,
    ExactAppRequiredStatusSnapshot,
    ExactAppRequiredStatusEvidence,
    IssuePatchProjection,
    ClaimedHeadMarker,
    CLAIMED_HEAD_MARKER_HEADER,
    CarrierActivation,
    CarrierRole,
    LegacyEvidenceDisposition,
    ShaCarrierResolution,
    StatusClass,
    PatchFoldResult,
    Request,
    RequestAnchor,
    RequestClass,
    RequestModelError,
    body_sha256,
    classify_issue_head_claim_progression,
    effective_request_digest,
    fold_patch_events,
    fold_issue_patch_events,
    issue_branch_lease_authority_digest,
    issue_head_claim_authority_digest,
    issue_final_status_evidence_digest,
    issue_patch_projection_evidence_digest,
    normalize_target_evidence_digest,
    proposal_target_evidence_digest,
    issue_branch_ref,
    issue_owner_key,
    parse_issue_owner_key,
    external_status_evidence_digest,
    cancel_status_evidence_digest,
    claim_generation_id,
    new_carrier_nonce,
    parse_anchor,
    parse_issue_request_anchor,
    parse_issue_internal_pr_binding,
    parse_pr_issue_origin_binding,
    parse_issue_branch_lease,
    parse_issue_head_claim,
    parse_required_status_epoch,
    parse_issue_finalization_epoch,
    parse_issue_cancellation_fence,
    parse_issue_cancellation_draft_witness,
    parse_issue_terminal_cancelled_result,
    parse_issue_no_pr_cancelled_result,
    parse_issue_patch_projection,
    parse_claimed_head_marker,
    render_status_description,
    parse_status_description,
    parse_issue_request_body,
    parse_request_body,
    render_request_body,
    render_patch,
    parse_patch,
    proposed_line_refs,
    reserved_issue_branch_number,
    resolve_publication_lines,
    ISSUE_BRANCH_LEASE_MARKER,
    validate_drop_set,
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


class IssueManagedNoSemanticChange(R02Error):
    """A valid Issue request produces no trust/configuration semantic change."""

    reason = "NO_SEMANTIC_CHANGE"

    def __init__(self, request_class: RequestClass):
        if type(request_class) is not RequestClass or request_class not in {
            RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE,
        }:
            raise ValueError("Issue-managed no-change requires an exact manual RequestClass")
        self.request_class = request_class
        super().__init__(self.reason)


@dataclass(frozen=True)
class IssueManagedRouteResult:
    outcome: str
    reason: str
    request_class: RequestClass

    def __post_init__(self) -> None:
        if type(self.request_class) is not RequestClass or self.request_class not in {
            RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE,
        }:
            raise ValueError("Issue-managed route result requires an exact manual RequestClass")


class DuplicateAnchorError(R02Error):
    pass


class DuplicateCheckRunError(R02Error):
    pass


class MissingTrustedCheckError(R02Error):
    """A non-create writer cannot complete when the App check is missing; the finalizer may create it after revalidation."""


class ForkHeadError(R02Error):
    pass


class CandidateScopeError(R02Error):
    pass


class ReservedIssuePRPendingManagedAuthority(R02Error):
    """A reserved Issue PR is quarantined until its Wave 04 managed path exists."""


_RESERVED_ISSUE_PR_BRANCH_PREFIX = "bot/federation/request/"
_RESERVED_ISSUE_PR_FULL_REF_PREFIX = f"refs/heads/{_RESERVED_ISSUE_PR_BRANCH_PREFIX}"


def _is_reserved_issue_pr_head(head_ref: str) -> bool:
    """Fail closed for the reserved namespace, including malformed attempts."""
    try:
        return reserved_issue_branch_number(head_ref) is not None
    except RequestModelError:
        if head_ref.startswith((_RESERVED_ISSUE_PR_BRANCH_PREFIX, _RESERVED_ISSUE_PR_FULL_REF_PREFIX)):
            return True
        raise


def _raise_if_reserved_issue_pr(pr: PullRequestMetadata) -> None:
    if _is_reserved_issue_pr_head(pr.head_ref):
        raise ReservedIssuePRPendingManagedAuthority("reserved Issue PR is quarantined pending Wave 04 managed authority")


class Wave08DecisionKind(Enum):
    NO_MUTATION = "NO_MUTATION"
    RESERVED_OWNER_RECOVERY = "RESERVED_OWNER_RECOVERY"
    MACHINE_RECOVERY_DEFERRED = "MACHINE_RECOVERY_DEFERRED"
    ISSUE_OWNER_FINALIZER_RECOVERY = "ISSUE_OWNER_FINALIZER_RECOVERY"
    ISSUE_OWNER_CANCELLATION_RECOVERY = "ISSUE_OWNER_CANCELLATION_RECOVERY"
    MACHINE_VALIDATION_DISPATCH = "MACHINE_VALIDATION_DISPATCH"
    MACHINE_FINALIZER_DISPATCH = "MACHINE_FINALIZER_DISPATCH"
    EXTERNAL_STATUS = "EXTERNAL_STATUS"
    LEGACY_QUARANTINE_DEFERRED = "LEGACY_QUARANTINE_DEFERRED"
    CONFLICTING_BLOCKED = "CONFLICTING_BLOCKED"


class Wave08DispatchTarget(Enum):
    ISSUE_FINALIZER = "ISSUE_FINALIZER"
    ISSUE_CANCELLATION_RECOVERY = "ISSUE_CANCELLATION_RECOVERY"
    ISSUE_INTAKE_TERMINAL_RECOVERY = "ISSUE_INTAKE_TERMINAL_RECOVERY"
    MACHINE_VALIDATION = "MACHINE_VALIDATION"
    MACHINE_FINALIZER = "MACHINE_FINALIZER"


class Wave08DecisionReason(Enum):
    OWNER_NOT_PRESENT = "OWNER_NOT_PRESENT"
    ROLE_REQUIRES_NO_ACTION = "ROLE_REQUIRES_NO_ACTION"
    RESERVED_ROLE = "RESERVED_ROLE"
    ISSUE_FINALIZER_REQUIRED = "ISSUE_FINALIZER_REQUIRED"
    ISSUE_CANCELLATION_REQUIRED = "ISSUE_CANCELLATION_REQUIRED"
    MACHINE_VALIDATION_REQUIRED = "MACHINE_VALIDATION_REQUIRED"
    MACHINE_FINALIZER_REQUIRED = "MACHINE_FINALIZER_REQUIRED"
    EXPLICITLY_UNCLAIMED = "EXPLICITLY_UNCLAIMED"
    LEGACY_CLASSIFIER_DEFERRED = "LEGACY_CLASSIFIER_DEFERRED"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    MACHINE_AUTHORITY_PENDING = "MACHINE_AUTHORITY_PENDING"
    FRESH_AUTHORITY_FAILED = "FRESH_AUTHORITY_FAILED"
    DISPATCH_FAILED = "DISPATCH_FAILED"


class Wave08PermissionLevel(Enum):
    NONE = "none"
    READ = "read"
    WRITE = "write"


class Wave08PermissionLane(Enum):
    WG3_MANUAL_STATUS = "WG3_MANUAL_STATUS"
    WG3_MACHINE_VALIDATION = "WG3_MACHINE_VALIDATION"
    WG4_ISSUE_MANUAL_FINALIZER = "WG4_ISSUE_MANUAL_FINALIZER"
    WG4_MACHINE_FINALIZER = "WG4_MACHINE_FINALIZER"
    WG6_ORDINARY_RECOVERY = "WG6_ORDINARY_RECOVERY"


_WAVE08_PERMISSION_KEYS = ("actions", "statuses", "contents", "pull_requests", "issues", "checks")
_WAVE08_PERMISSION_VALUES = {
    Wave08PermissionLane.WG3_MANUAL_STATUS: ("write", "write", "read", "read", "read", "none"),
    Wave08PermissionLane.WG3_MACHINE_VALIDATION: ("write", "none", "read", "read", "read", "write"),
    Wave08PermissionLane.WG4_ISSUE_MANUAL_FINALIZER: ("write", "write", "write", "write", "read", "none"),
    Wave08PermissionLane.WG4_MACHINE_FINALIZER: ("write", "none", "write", "write", "read", "write"),
    Wave08PermissionLane.WG6_ORDINARY_RECOVERY: ("write", "write", "write", "write", "read", "none"),
}


@dataclass(frozen=True)
class Wave08PermissionProfile:
    lane: Wave08PermissionLane
    actions: Wave08PermissionLevel
    statuses: Wave08PermissionLevel
    contents: Wave08PermissionLevel
    pull_requests: Wave08PermissionLevel
    issues: Wave08PermissionLevel
    checks: Wave08PermissionLevel

    def __post_init__(self) -> None:
        if type(self.lane) is not Wave08PermissionLane:
            raise ValueError("Wave 08 permission lane must be closed")
        values = tuple(getattr(self, key) for key in _WAVE08_PERMISSION_KEYS)
        if any(type(value) is not Wave08PermissionLevel for value in values):
            raise ValueError("Wave 08 permission values must use the closed permission enum")
        expected = _WAVE08_PERMISSION_VALUES[self.lane]
        if tuple(value.value for value in values) != expected:
            raise ValueError("Wave 08 permission profile differs from its exact lane contract")

    def as_pairs(self) -> tuple[tuple[str, str], ...]:
        return tuple((key, getattr(self, key).value) for key in _WAVE08_PERMISSION_KEYS)


WAVE08_PERMISSION_PROFILES = tuple(
    Wave08PermissionProfile(lane, *(Wave08PermissionLevel(value) for value in values))
    for lane, values in _WAVE08_PERMISSION_VALUES.items()
)


@dataclass(frozen=True)
class Wave08Decision:
    head_sha: str
    resolution: ShaCarrierResolution
    pull_request_numbers: tuple[int, ...]
    owning_pr_number: int | None
    kind: Wave08DecisionKind
    reason: Wave08DecisionReason
    dispatch_target: Wave08DispatchTarget | None = None

    def __post_init__(self) -> None:
        if type(self.head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", self.head_sha) is None:
            raise ValueError("Wave 08 decision head must be exact lowercase 40-hex")
        if type(self.resolution) is not ShaCarrierResolution:
            raise ValueError("Wave 08 decision requires an exact SHA carrier resolution")
        if type(self.pull_request_numbers) is not tuple:
            raise ValueError("Wave 08 PR numbers must be a canonical tuple")
        if any(type(number) is not int or not 1 <= number <= 9_223_372_036_854_775_807 for number in self.pull_request_numbers):
            raise ValueError("Wave 08 PR numbers must be positive exact integers")
        if tuple(sorted(set(self.pull_request_numbers))) != self.pull_request_numbers:
            raise ValueError("Wave 08 PR numbers must be unique and deterministically sorted")
        if self.owning_pr_number is not None:
            if type(self.owning_pr_number) is not int or not 1 <= self.owning_pr_number <= 9_223_372_036_854_775_807:
                raise ValueError("Wave 08 owner PR number must be a positive exact integer")
            if self.owning_pr_number not in self.pull_request_numbers:
                raise ValueError("Wave 08 owner PR must belong to the shared-head group")
        if type(self.kind) is not Wave08DecisionKind or type(self.reason) is not Wave08DecisionReason:
            raise ValueError("Wave 08 decision kind/reason must use closed enums")
        if self.dispatch_target is not None and type(self.dispatch_target) is not Wave08DispatchTarget:
            raise ValueError("Wave 08 dispatch target must use a closed semantic enum")

        activation, role = self.resolution.activation, self.resolution.role
        marker = self.resolution.marker
        expected: dict[Wave08DecisionKind, tuple[set[tuple[CarrierActivation, CarrierRole | None]], Wave08DispatchTarget | None]] = {
            Wave08DecisionKind.NO_MUTATION: ({(item, role_value) for item in CarrierActivation for role_value in (None, *tuple(CarrierRole))}, None),
            Wave08DecisionKind.RESERVED_OWNER_RECOVERY: ({(CarrierActivation.RESERVED_INACTIVE, item) for item in CarrierRole if item is not CarrierRole.MACHINE_PUBLICATION}, None),
            Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY: ({(CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE), (CarrierActivation.ACTIVE, CarrierRole.ISSUE_FINALIZING)}, Wave08DispatchTarget.ISSUE_FINALIZER),
            Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY: ({(CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL)}, Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY),
            Wave08DecisionKind.MACHINE_VALIDATION_DISPATCH: ({(CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION)}, Wave08DispatchTarget.MACHINE_VALIDATION),
            Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH: ({(CarrierActivation.ACTIVE, CarrierRole.MACHINE_PUBLICATION)}, Wave08DispatchTarget.MACHINE_FINALIZER),
            Wave08DecisionKind.EXTERNAL_STATUS: ({(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION, None)}, None),
            Wave08DecisionKind.LEGACY_QUARANTINE_DEFERRED: ({(CarrierActivation.LEGACY_CUTOVER_QUARANTINE, None)}, None),
            Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED: ({(CarrierActivation.RESERVED_INACTIVE, CarrierRole.MACHINE_PUBLICATION)}, None),
            Wave08DecisionKind.CONFLICTING_BLOCKED: (
                {(item, role_value) for item in CarrierActivation for role_value in (None, *tuple(CarrierRole))}, None,
            ),
        }
        allowed_pairs, target = expected[self.kind]
        if (activation, role) not in allowed_pairs or self.dispatch_target is not target:
            raise ValueError("Wave 08 decision kind/target is incompatible with its SHA role")
        owner_actions = {
            Wave08DecisionKind.RESERVED_OWNER_RECOVERY,
            Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY,
            Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY,
            Wave08DecisionKind.MACHINE_VALIDATION_DISPATCH,
            Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH,
        }
        if self.kind in owner_actions and self.owning_pr_number is None:
            raise ValueError("owner action requires the exact owner PR in the shared-head group")
        if self.kind not in owner_actions and self.owning_pr_number is not None:
            raise ValueError("non-owner action cannot claim an owning PR")
        if self.kind is Wave08DecisionKind.RESERVED_OWNER_RECOVERY and (
            marker is None or marker.owner_kind != "ISSUE"
        ):
            raise ValueError("reserved owner recovery requires an exact Issue claim marker")
        if self.kind is Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED and (
            marker is None or marker.owner_kind != "MACHINE_SOURCE" or marker.claim_kind != "MACHINE_REF_CLAIM"
        ):
            raise ValueError("machine recovery deferral requires the exact reserved machine claim marker")
        if self.kind in {
            Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY,
            Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY,
        } and (marker is None or marker.owner_kind != "ISSUE"):
            raise ValueError("Issue action requires an exact Issue claim marker")
        if self.kind is Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY and (
            (role is CarrierRole.ISSUE_ACTIVE and marker.claim_kind not in {
                "ISSUE_BRANCH_LEASE", "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH",
            })
            or (role is CarrierRole.ISSUE_FINALIZING and marker.claim_kind != "ISSUE_FINALIZATION_EPOCH")
        ):
            raise ValueError("Issue finalizer action requires the exact role-specific marker kind")
        if self.kind is Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY and (
            role is not CarrierRole.ISSUE_CANCEL or marker.claim_kind != "ISSUE_CANCELLATION_FENCE"
        ):
            raise ValueError("Issue cancellation action requires an exact cancellation-fence marker")
        if self.kind in {
            Wave08DecisionKind.MACHINE_VALIDATION_DISPATCH,
            Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH,
        } and (
            marker is None or marker.owner_kind != "MACHINE_SOURCE" or marker.claim_kind != "MACHINE_REF_CLAIM"
        ):
            raise ValueError("machine action requires an exact supplied machine-claim marker")
        if self.kind is Wave08DecisionKind.EXTERNAL_STATUS and not self.pull_request_numbers:
            raise ValueError("external status action requires an OPEN-PR head group")


@dataclass(frozen=True)
class IssueOwnerPR:
    issue_number: int
    pull_request_number: int
    owner_key: str
    binding_authority: str

    def __post_init__(self) -> None:
        if type(self.issue_number) is not int or not 1 <= self.issue_number <= 9_223_372_036_854_775_807:
            raise ValueError("Issue owner number must be a positive exact integer")
        if type(self.pull_request_number) is not int or not 1 <= self.pull_request_number <= 9_223_372_036_854_775_807:
            raise ValueError("owner PR number must be a positive exact integer")
        if type(self.owner_key) is not str or not self.owner_key:
            raise ValueError("Issue owner key is required")
        if type(self.binding_authority) is not str or self.binding_authority not in {"FULL_BINDING", "PRE_BINDING"}:
            raise ValueError("Issue owner binding authority is unknown")


@dataclass(frozen=True)
class Wave08IssueRecoveryIntent:
    """Bounded Wg6-to-Wg1 semantic dispatch; it carries no mutation authority."""

    target: Wave08DispatchTarget
    central_repository_node_id: str
    issue_number: int
    reason: str

    def __post_init__(self) -> None:
        if self.target not in {
            Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY,
            Wave08DispatchTarget.ISSUE_INTAKE_TERMINAL_RECOVERY,
        }:
            raise ValueError("Issue recovery intent requires a closed Wg1 semantic target")
        if type(self.central_repository_node_id) is not str or not self.central_repository_node_id:
            raise ValueError("Issue recovery intent requires the exact central repository identity")
        if type(self.issue_number) is not int or not 1 <= self.issue_number <= 9_223_372_036_854_775_807:
            raise ValueError("Issue recovery intent requires a positive exact Issue number")
        if type(self.reason) is not str or not self.reason or len(self.reason.encode("utf-8")) > 256:
            raise ValueError("Issue recovery intent reason must be bounded text")


@dataclass(frozen=True)
class Wave08IssueRecoveryRecord:
    issue_number: int
    issue_database_id: int | None
    issue_node_id: str | None
    outcome: str
    reason: str


@dataclass(frozen=True)
class Wave08MachineRefRecord:
    ref: str
    source_id: str
    head_sha: str
    outcome: str
    reason: str


@dataclass(frozen=True)
class Wave08UniversalRecoveryResult:
    """Immutable bounded evidence from one complete or fail-closed recovery sweep."""

    complete: bool
    open_pr_inventory_count: int
    fresh_pr_count: int
    distinct_pr_head_count: int
    issue_inventory_count: int
    relevant_issue_count: int
    machine_ref_inventory_count: int
    decisions: tuple[Wave08Decision, ...]
    issue_recoveries: tuple[Wave08IssueRecoveryRecord, ...]
    machine_refs: tuple[Wave08MachineRefRecord, ...]
    dispatch_intents: tuple[Wave08IssueRecoveryIntent, ...]
    status_actions: tuple[tuple[str, str], ...]
    blocked_reasons: tuple[str, ...]
    deferred_count: int

    @property
    def blocked_count(self) -> int:
        return len(self.blocked_reasons)


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
class IssueAnchorComment:
    anchor: IssueRequestAnchor
    comment: IssueComment


@dataclass(frozen=True)
class PublicSourceMetadata:
    repository_id: int
    full_name: str
    default_branch: str
    description: str | None


class IssueSourceIdentityKind(Enum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"


@dataclass(frozen=True)
class IssueSourceAuthority:
    request_class: RequestClass
    source_id: str
    source_repository_id: int
    source_canonical_full_name: str
    source_identity_kind: IssueSourceIdentityKind
    source_default_branch: str
    source_description: str | None

    def __post_init__(self) -> None:
        if self.request_class not in MANUAL_CLASSES:
            raise R02Error("Issue source authority requires ADD, UPDATE, or REMOVE")
        if type(self.source_identity_kind) is not IssueSourceIdentityKind:
            raise R02Error("Issue source identity kind must use the closed authority enum")
        expected_kind = (
            IssueSourceIdentityKind.PROPOSED
            if self.request_class is RequestClass.ADD
            else IssueSourceIdentityKind.ACCEPTED
        )
        if self.source_identity_kind is not expected_kind:
            raise R02Error("Issue source identity kind does not match request class")


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
_LEGACY_UPDATE_REMOVE_NO_FEDERATION_ERROR = "UPDATE/REMOVE requires an actual federation.json trust/configuration change"
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


def _bounded_error_reason(error: BaseException) -> str:
    name = type(error).__name__
    message = _bounded_reason(str(error))
    return f"{name}:{message}"


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


_CLAIMED_HEAD_FAMILY = "swiftstream-federation-head:"
_EXTERNAL_STATUS_CONTEXT = "federation/trusted-validation"


def _is_canonical_wave08_source_id(value: Any) -> bool:
    if type(value) is not str:
        return False
    try:
        return c02.validate_source_id(value) == value
    except c02.FederationError:
        return False


def _conflicting_sha_carrier(marker: ClaimedHeadMarker | None = None) -> ShaCarrierResolution:
    return ShaCarrierResolution(CarrierActivation.CONFLICTING, marker=marker)


def wave08_legacy_disposition(
    head_sha: str,
    resolver: Callable[[str], LegacyEvidenceDisposition] | None,
) -> LegacyEvidenceDisposition:
    """Call the explicit trusted legacy classifier for exactly H; never infer ABSENT."""
    if type(head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None or not callable(resolver):
        return LegacyEvidenceDisposition.CONFLICTING
    try:
        disposition = resolver(head_sha)
    except Exception:
        return LegacyEvidenceDisposition.CONFLICTING
    return disposition if type(disposition) is LegacyEvidenceDisposition else LegacyEvidenceDisposition.CONFLICTING


def wave08_decision_for_resolution(
    head_sha: str,
    resolution: ShaCarrierResolution,
    pull_request_numbers: Iterable[int],
    *,
    owner_pr_number: int | None = None,
    machine_target: Wave08DispatchTarget = Wave08DispatchTarget.MACHINE_VALIDATION,
) -> Wave08Decision:
    """Pure closed SHA-role-to-action mapping for one deterministic shared-head group."""
    if type(head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
        raise ValueError("Wave 08 decision head must be exact lowercase 40-hex")
    if type(resolution) is not ShaCarrierResolution:
        raise ValueError("Wave 08 decision requires an exact SHA carrier resolution")
    if type(machine_target) is not Wave08DispatchTarget or machine_target not in {
        Wave08DispatchTarget.MACHINE_VALIDATION, Wave08DispatchTarget.MACHINE_FINALIZER,
    }:
        raise ValueError("machine action requires a closed machine semantic target")
    if isinstance(pull_request_numbers, (str, bytes)):
        raise ValueError("Wave 08 PR group must be an integer sequence")
    try:
        raw_numbers = tuple(pull_request_numbers)
    except TypeError:
        raise ValueError("Wave 08 PR group must be an integer sequence") from None
    if any(type(number) is not int or not 1 <= number <= 9_223_372_036_854_775_807 for number in raw_numbers):
        raise ValueError("Wave 08 PR group numbers must be positive exact integers")
    if len(set(raw_numbers)) != len(raw_numbers):
        raise ValueError("Wave 08 PR group contains duplicate PR numbers")
    numbers = tuple(sorted(raw_numbers))
    if owner_pr_number is not None and (
        type(owner_pr_number) is not int
        or not 1 <= owner_pr_number <= 9_223_372_036_854_775_807
    ):
        raise ValueError("Wave 08 owner PR number must be a positive exact integer")
    owner = owner_pr_number
    if owner is not None and owner not in numbers:
        raise ValueError("Wave 08 owner PR must belong to the shared-head group")
    owner_is_member = owner is not None and owner in numbers
    activation, role, marker = resolution.activation, resolution.role, resolution.marker
    if role is not CarrierRole.MACHINE_PUBLICATION and machine_target is not Wave08DispatchTarget.MACHINE_VALIDATION:
        raise ValueError("Issue and non-machine roles cannot select a machine dispatch lane")
    if activation in {
        CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION,
        CarrierActivation.LEGACY_CUTOVER_QUARANTINE,
        CarrierActivation.CONFLICTING,
    } and owner is not None:
        raise ValueError("unclaimed, quarantined, and conflicting heads cannot have an owner PR")

    def make(kind: Wave08DecisionKind, reason: Wave08DecisionReason, target: Wave08DispatchTarget | None = None, *, chosen_owner: int | None = None) -> Wave08Decision:
        return Wave08Decision(head_sha, resolution, numbers, chosen_owner, kind, reason, target)

    if activation is CarrierActivation.CONFLICTING:
        return make(Wave08DecisionKind.CONFLICTING_BLOCKED, Wave08DecisionReason.CONFLICTING_EVIDENCE)
    if activation is CarrierActivation.LEGACY_CUTOVER_QUARANTINE:
        return make(Wave08DecisionKind.LEGACY_QUARANTINE_DEFERRED, Wave08DecisionReason.LEGACY_CLASSIFIER_DEFERRED)
    if activation is CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION:
        if numbers:
            return make(Wave08DecisionKind.EXTERNAL_STATUS, Wave08DecisionReason.EXPLICITLY_UNCLAIMED)
        return make(Wave08DecisionKind.NO_MUTATION, Wave08DecisionReason.ROLE_REQUIRES_NO_ACTION)
    if activation is CarrierActivation.RESERVED_INACTIVE:
        if role is CarrierRole.MACHINE_PUBLICATION:
            if marker is not None and marker.owner_kind == "MACHINE_SOURCE" and marker.claim_kind == "MACHINE_REF_CLAIM":
                return make(Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED, Wave08DecisionReason.MACHINE_AUTHORITY_PENDING)
            return make(Wave08DecisionKind.NO_MUTATION, Wave08DecisionReason.OWNER_NOT_PRESENT)
        if owner_is_member and marker is not None and marker.owner_kind == "ISSUE":
            return make(
                Wave08DecisionKind.RESERVED_OWNER_RECOVERY,
                Wave08DecisionReason.RESERVED_ROLE,
                chosen_owner=owner,
            )
        return make(Wave08DecisionKind.NO_MUTATION, Wave08DecisionReason.OWNER_NOT_PRESENT)

    if activation is not CarrierActivation.ACTIVE or type(role) is not CarrierRole:
        return make(Wave08DecisionKind.CONFLICTING_BLOCKED, Wave08DecisionReason.CONFLICTING_EVIDENCE)
    if role in {CarrierRole.ISSUE_ACTIVE, CarrierRole.ISSUE_FINALIZING}:
        if not owner_is_member or marker is None or marker.owner_kind != "ISSUE":
            return make(Wave08DecisionKind.NO_MUTATION, Wave08DecisionReason.OWNER_NOT_PRESENT)
        return make(
            Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY,
            Wave08DecisionReason.ISSUE_FINALIZER_REQUIRED,
            Wave08DispatchTarget.ISSUE_FINALIZER,
            chosen_owner=owner,
        )
    if role is CarrierRole.ISSUE_CANCEL:
        if not owner_is_member or marker is None or marker.owner_kind != "ISSUE":
            return make(Wave08DecisionKind.NO_MUTATION, Wave08DecisionReason.OWNER_NOT_PRESENT)
        return make(
            Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY,
            Wave08DecisionReason.ISSUE_CANCELLATION_REQUIRED,
            Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY,
            chosen_owner=owner,
        )
    if role is CarrierRole.MACHINE_PUBLICATION:
        if not owner_is_member or marker is None or marker.owner_kind != "MACHINE_SOURCE" or marker.claim_kind != "MACHINE_REF_CLAIM":
            return make(Wave08DecisionKind.NO_MUTATION, Wave08DecisionReason.OWNER_NOT_PRESENT)
        if machine_target is Wave08DispatchTarget.MACHINE_VALIDATION:
            return make(
                Wave08DecisionKind.MACHINE_VALIDATION_DISPATCH,
                Wave08DecisionReason.MACHINE_VALIDATION_REQUIRED,
                machine_target,
                chosen_owner=owner,
            )
        return make(
            Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH,
            Wave08DecisionReason.MACHINE_FINALIZER_REQUIRED,
            machine_target,
            chosen_owner=owner,
        )
    return make(Wave08DecisionKind.CONFLICTING_BLOCKED, Wave08DecisionReason.CONFLICTING_EVIDENCE)


def _issue_pr_binding_matches_cancellation_identity(
    binding: IssuePRBinding,
    anchor: IssueAnchorComment,
    lease: IssueBranchLeaseComment,
    pr_number: int,
    pr_issue: IssueMetadata,
    central_repository_node_id: str,
) -> bool:
    actual = (
        binding.issue_number,
        binding.issue_database_id,
        binding.issue_node_id,
        binding.issue_request_anchor_comment_database_id,
        binding.issue_request_anchor_sha256,
        binding.issue_branch_lease_comment_database_id,
        binding.issue_branch_lease_sha256,
        binding.source_id,
        binding.source_repository_id,
        binding.branch_ref,
        binding.pull_request_number,
        binding.pull_request_database_id,
        binding.pull_request_node_id,
        binding.initial_head_sha,
        binding.base_ref,
        binding.central_repository_node_id,
    )
    expected = (
        anchor.anchor.issue_number,
        anchor.anchor.issue_database_id,
        anchor.anchor.issue_node_id,
        anchor.comment.database_id,
        anchor.anchor.canonical_sha256(),
        lease.comment.database_id,
        _binding_comment_sha256(lease.comment),
        anchor.anchor.source_id,
        anchor.anchor.source_repository_id,
        lease.lease.branch_ref,
        pr_number,
        pr_issue.database_id,
        pr_issue.node_id,
        lease.lease.initial_head_sha,
        "main",
        central_repository_node_id,
    )
    return actual == expected


def _fresh_issue_cancellation_authority(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    app: AppIdentity,
    *,
    require_prebinding_lease_root: bool = False,
    allow_pr_stage_state: bool = False,
) -> _IssueCancellationAuthority:
    cancellation_allows_closed_lifecycle = False
    central = client.get_repository_metadata(repository)
    if (
        type(central) is not RepositoryMetadata
        or central.full_name != repository
        or central.default_branch != "main"
        or not central.node_id
    ):
        raise R02Error("cancellation requires exact central repository identity and main default branch")
    intake = _read_issue_pr_intake(
        client, repository, issue_number, app, central.node_id,
        lambda _request, _request_class: None,
        validate_fresh_source_authority=False,
        require_open_lifecycle=cancellation_allows_closed_lifecycle,
    )
    owning_issue, _issue_comments, anchor, lease, _repo, issue_bindings = intake
    short_ref = lease.lease.branch_ref.removeprefix("refs/heads/")
    candidates = _enumerate_issue_pr_candidates(
        client, repository, short_ref, app, anchor, lease, central.node_id,
    )
    if len(candidates) != 1:
        raise R02Error("cancellation requires exactly one central App-created reserved-head PR")
    candidate = candidates[0]
    pr = candidate.pr
    try:
        pr_issue = client.get_issue_metadata(repository, pr.number)
        all_prs = tuple(client.list_pull_requests(repository, state="all"))
    except Exception as error:
        raise StaleAuthorityError(f"cancellation PR-as-Issue authority is unavailable: {_bounded_reason(error)}") from None
    raw_matches = [item for item in all_prs if type(item) is dict and item.get("number") == pr.number]
    if len(raw_matches) != 1:
        raise R02Error("cancellation PR enumeration did not uniquely identify the exact PR")
    raw = raw_matches[0]
    raw_state = raw.get("state")
    raw_merged = raw.get("merged")
    if type(raw_merged) is not bool and "merged_at" in raw:
        merged_at = raw.get("merged_at")
        if merged_at is None:
            raw_merged = False
        elif type(merged_at) is str and merged_at:
            raw_merged = True
        else:
            raw_merged = None
    if type(raw_state) is not str or raw_state not in {"open", "closed"} or type(raw_merged) is not bool:
        raise R02Error("cancellation PR enumeration omitted exact state/merged evidence")
    expected_body = render_request_body(anchor.anchor.initial_request)
    if (
        type(pr) is not PullRequestMetadata
        or pr.number != candidate.pr.number
        or pr.author_id != app.bot_node_id
        or pr.author_login != app.bot_login
        or pr.head_ref != short_ref
        or pr.head_repository_id != central.node_id
        or pr.head_repository != repository
        or pr.base_repository_id != central.node_id
        or pr.base_repository != repository
        or pr.base_ref != "main"
        or type(pr.draft) is not bool
        or (not allow_pr_stage_state and pr.draft is not False)
        or pr.body != expected_body
        or pr.last_edited_at is not None
        or pr.includes_created_edit is not False
        or type(pr_issue) is not IssueMetadata
        or pr_issue.is_pull_request is not True
        or pr_issue.number != pr.number
        or type(pr_issue.database_id) is not int
        or pr_issue.database_id <= 0
        or type(pr_issue.node_id) is not str
        or not pr_issue.node_id
        or pr_issue.author_id != app.bot_node_id
        or pr_issue.author_login != app.bot_login
        or pr_issue.body != pr.body
        or pr_issue.state != raw_state
    ):
        raise R02Error("cancellation PR is not the exact immutable central PR-as-Issue")
    pr_comments = tuple(client.list_issue_comments(repository, pr.number))
    _issue_pr_authority_fence(pr_comments, app, allow_cancellation_fence=True)
    pr_bindings = _binding_comment_candidates(
        pr_comments, app, PR_ISSUE_ORIGIN_BINDING_MARKER,
        parse_pr_issue_origin_binding, "PRIssueOriginBinding",
    )
    issue_binding = issue_bindings[0] if issue_bindings else None
    pr_binding = pr_bindings[0] if pr_bindings else None
    for item in (issue_binding, pr_binding):
        if item is not None and not _issue_pr_binding_matches_cancellation_identity(
            item.binding, anchor, lease, pr.number, pr_issue, central.node_id,
        ):
            raise R02Error("partial IssuePRBinding does not match the exact PR-as-Issue identity triple")
    if issue_binding is not None and pr_binding is not None:
        if issue_binding.binding != pr_binding.binding:
            raise R02Error("two-sided IssuePRBinding disagrees across Issue and PR comments")
        binding_state = _read_managed_issue_pr_binding_state(
            client, repository, issue_number, app, central.node_id,
            lambda _request, _request_class: None,
            validate_fresh_source_authority=False,
            require_open_lifecycle=cancellation_allows_closed_lifecycle,
            allow_cancellation_fence=True,
            allow_pr_stage_state=allow_pr_stage_state,
        )
        binding = binding_state.binding
        if (
            binding != issue_binding.binding
            or binding.pull_request_node_id != pr_issue.node_id
            or binding.pull_request_database_id != pr_issue.database_id
            or binding.pull_request_number != pr_issue.number
        ):
            raise R02Error("complete IssuePRBinding does not match central PR-as-Issue identity")
        binding_authority = "FULL_BINDING"
    else:
        binding = None
        binding_state = None
        binding_authority = "PRE_BINDING"
    authority = _IssueCancellationAuthority(
        issue_anchor=anchor,
        lease=lease,
        binding_authority=binding_authority,
        pull_request_number=pr.number,
        pull_request_database_id=pr_issue.database_id,
        pull_request_node_id=pr_issue.node_id,
        central_repository_node_id=central.node_id,
        base_repository_node_id=central.node_id,
        pr=pr,
        pr_issue=pr_issue,
        owning_issue=owning_issue,
        pr_comments=pr_comments,
        binding=binding,
        binding_state=binding_state,
        raw_pr_state=raw_state.upper(),
        raw_pr_merged=raw_merged,
    )
    if authority.binding_authority == "PRE_BINDING" and require_prebinding_lease_root:
        current_ref = _read_issue_branch_ref(client, repository, short_ref)
        if current_ref != lease.lease.initial_head_sha or pr.head_oid != lease.lease.initial_head_sha:
            raise R02Error("PRE_BINDING cancellation requires the exact lease-root PR/ref before fence activation")
    return authority


def resolve_sha_carrier_role(
    client: GitHubClient,
    repository: str,
    head_sha: str,
    app_slug: str,
    legacy_evidence_disposition: LegacyEvidenceDisposition | Callable[[], LegacyEvidenceDisposition],
) -> ShaCarrierResolution:
    """Resolve the role of exact commit H without consulting PR topology first."""
    try:
        commit = client.get_git_commit_object(repository, head_sha)
    except Exception:
        return _conflicting_sha_carrier()
    if type(commit) is not GitCommitObject or commit.sha != head_sha or type(commit.message) is not str:
        return _conflicting_sha_carrier()

    marker_count = commit.message.count(_CLAIMED_HEAD_FAMILY)
    if marker_count == 0:
        if type(legacy_evidence_disposition) is LegacyEvidenceDisposition:
            disposition = legacy_evidence_disposition
        elif callable(legacy_evidence_disposition):
            try:
                disposition = legacy_evidence_disposition()
            except Exception:
                return _conflicting_sha_carrier()
        else:
            raise R02Error("explicit trusted legacy evidence disposition is required")
        if type(disposition) is not LegacyEvidenceDisposition:
            return _conflicting_sha_carrier()
        if disposition is LegacyEvidenceDisposition.QUARANTINE:
            return ShaCarrierResolution(CarrierActivation.LEGACY_CUTOVER_QUARANTINE)
        if disposition is LegacyEvidenceDisposition.CONFLICTING:
            return _conflicting_sha_carrier()
        if disposition is LegacyEvidenceDisposition.ABSENT:
            return ShaCarrierResolution(CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION)
        return _conflicting_sha_carrier()

    # The whole literal namespace is reserved before any fallback. Only one exact
    # supported v2 marker occupying the entire commit message reaches provenance.
    if marker_count != 1 or not commit.message.startswith(CLAIMED_HEAD_MARKER_HEADER + "\n"):
        return _conflicting_sha_carrier()
    try:
        marker = parse_claimed_head_marker(commit.message)
    except RequestModelError:
        return _conflicting_sha_carrier()

    supported_roles = {
        "ISSUE_BRANCH_LEASE": CarrierRole.ISSUE_ACTIVE.value,
        "ISSUE_HEAD_CLAIM": CarrierRole.ISSUE_ACTIVE.value,
        "REQUIRED_STATUS_EPOCH": CarrierRole.ISSUE_ACTIVE.value,
        "ISSUE_FINALIZATION_EPOCH": CarrierRole.ISSUE_FINALIZING.value,
        "ISSUE_CANCELLATION_FENCE": CarrierRole.ISSUE_CANCEL.value,
    }
    if (
        marker.owner_kind != "ISSUE"
        or marker.claim_kind not in supported_roles
        or marker.role != supported_roles.get(marker.claim_kind)
    ):
        return _conflicting_sha_carrier(marker)

    try:
        central = client.get_repository_metadata(repository)
        if (
            type(central) is not RepositoryMetadata
            or central.full_name != repository
            or not central.node_id
        ):
            return _conflicting_sha_carrier(marker)
        owner_central_node_id, issue_database_id, issue_node_id, issue_number = parse_issue_owner_key(marker.owner_key)
        if owner_central_node_id != central.node_id:
            return _conflicting_sha_carrier(marker)
        app = resolve_app_identity(client, app_slug)
        issue = client.get_issue_metadata(repository, issue_number)
        if (
            type(issue) is not IssueMetadata
            or issue.number != issue_number
            or issue.database_id != issue_database_id
            or issue.node_id != issue_node_id
            or issue.is_pull_request
        ):
            return _conflicting_sha_carrier(marker)
        comments = tuple(client.list_issue_comments(repository, issue_number))
        anchor = validate_unique_issue_anchor(comments, issue, app)
        if issue_owner_key(
            central.node_id, anchor.anchor.issue_database_id,
            anchor.anchor.issue_node_id, anchor.anchor.issue_number,
        ) != marker.owner_key:
            return _conflicting_sha_carrier(marker)
        lease = _resolve_issue_branch_lease_class(
            client, repository, comments, app, anchor.anchor,
            anchor.comment.database_id, central.node_id,
        )
        if lease is None:
            return _conflicting_sha_carrier(marker)

        if marker.claim_kind == "ISSUE_BRANCH_LEASE":
            if lease.lease.initial_head_sha != head_sha or _lease_marker_for(lease.lease) != marker:
                return _conflicting_sha_carrier(marker)
            current_ref = _read_issue_branch_ref(
                client, repository, lease.lease.branch_ref.removeprefix("refs/heads/"),
            )
            activation = CarrierActivation.ACTIVE if current_ref == head_sha else CarrierActivation.RESERVED_INACTIVE
            return ShaCarrierResolution(activation, CarrierRole.ISSUE_ACTIVE, marker)

        if marker.claim_kind == "ISSUE_CANCELLATION_FENCE":
            return _resolve_issue_cancellation_carrier(
                client, repository, head_sha, app, marker,
            )

        state = _read_managed_issue_pr_binding_state(
            client,
            repository,
            issue_number,
            app,
            central.node_id,
            lambda _request, _request_class: None,
            validate_fresh_source_authority=False,
            require_open_lifecycle=False,
        )
        current_ref = _read_issue_branch_ref(
            client, repository, state.lease.lease.branch_ref.removeprefix("refs/heads/"),
        )
        pr_comments = tuple(client.list_issue_comments(repository, state.binding.pull_request_number))
        history = _issue_authority_history(
            client, repository, pr_comments, app, state, current_ref or ZERO_OID,
        )
        matches = [
            item for item in history
            if item.target_head_sha == head_sha
            and (
                (_issue_head_claim_marker(item.artifact) if item.claim_kind == "ISSUE_HEAD_CLAIM"
                 else _required_status_epoch_marker(item.artifact) if item.claim_kind == "REQUIRED_STATUS_EPOCH"
                 else _issue_finalization_epoch_marker(item.artifact) if item.claim_kind == "ISSUE_FINALIZATION_EPOCH"
                 else _lease_marker_for(item.artifact)) == marker
            )
        ]
        if len(matches) != 1:
            return _conflicting_sha_carrier(marker)
        activation_state = _read_managed_issue_pr_binding_state(
            client,
            repository,
            issue_number,
            app,
            central.node_id,
            lambda _request, _request_class: None,
            validate_fresh_source_authority=False,
            require_open_lifecycle=False,
        )
        _require_same_managed_issue_pr_binding(state, activation_state)
        activation_ref = _read_issue_branch_ref(
            client, repository, activation_state.lease.lease.branch_ref.removeprefix("refs/heads/"),
        )
        active = (
            activation_state.owning_issue.state == "open"
            and activation_state.pr_issue.state == "open"
            and activation_ref == head_sha
            and activation_state.pr.head_oid == head_sha
        )
        activation = CarrierActivation.ACTIVE if active else CarrierActivation.RESERVED_INACTIVE
        result_role = CarrierRole(supported_roles[marker.claim_kind])
        return ShaCarrierResolution(activation, result_role, marker)
    except Exception:
        return _conflicting_sha_carrier(marker)


def _resolve_issue_cancellation_carrier(
    client: GitHubClient,
    repository: str,
    head_sha: str,
    app: AppIdentity,
    marker: ClaimedHeadMarker,
) -> ShaCarrierResolution:
    try:
        owner_central_node_id, _issue_database_id, _issue_node_id, issue_number = parse_issue_owner_key(marker.owner_key)
        authority = _fresh_issue_cancellation_authority(
            client, repository, issue_number, app, allow_pr_stage_state=True,
        )
        if authority.central_repository_node_id != owner_central_node_id:
            return _conflicting_sha_carrier(marker)
        if authority.binding_authority == "PRE_BINDING" and (
            authority.pr.head_oid != authority.lease.lease.initial_head_sha
            and authority.pr.head_oid != head_sha
        ):
            return _conflicting_sha_carrier(marker)
        current_ref = _read_issue_branch_ref(
            client, repository, authority.lease.lease.branch_ref.removeprefix("refs/heads/"),
        )
        fences = _issue_cancellation_fence_comments(
            client, repository, authority.pr_comments, app, authority, current_ref or ZERO_OID,
        )
        if len(fences) != 1 or fences[0].fence.cancellation_head_sha != head_sha:
            return _conflicting_sha_carrier(marker)
        fence_item = fences[0]
        if _issue_cancellation_fence_marker(fence_item.fence) != marker:
            return _conflicting_sha_carrier(marker)
        if authority.binding_authority == "FULL_BINDING":
            assert authority.binding_state is not None
            history = _issue_authority_history(
                client, repository, authority.pr_comments, app,
                authority.binding_state, current_ref or ZERO_OID,
            )
            exact_nodes = tuple(
                node for node in history
                if node.target_head_sha == head_sha
                and node.claim_kind == "ISSUE_CANCELLATION_FENCE"
                and node.artifact == fence_item.fence
                and node.comment.database_id == fence_item.comment.database_id
            )
            if len(exact_nodes) != 1:
                return _conflicting_sha_carrier(marker)
        elif (
            fence_item.fence.binding_authority != "PRE_BINDING"
            or fence_item.fence.original_head_claim_kind != "ISSUE_BRANCH_LEASE"
            or fence_item.fence.original_head_claim_role != CarrierRole.ISSUE_ACTIVE.value
            or fence_item.fence.original_head_sha != authority.lease.lease.initial_head_sha
        ):
            return _conflicting_sha_carrier(marker)

        # Re-read every identity input after provenance. The resolver never uses
        # graph reachability alone as ACTIVE evidence.
        final_authority = _fresh_issue_cancellation_authority(
            client, repository, issue_number, app, allow_pr_stage_state=True,
        )
        if (
            final_authority.binding_authority != authority.binding_authority
            or final_authority.issue_anchor.anchor != authority.issue_anchor.anchor
            or final_authority.issue_anchor.comment.database_id != authority.issue_anchor.comment.database_id
            or final_authority.lease.lease != authority.lease.lease
            or final_authority.lease.comment.database_id != authority.lease.comment.database_id
            or final_authority.pull_request_number != authority.pull_request_number
            or final_authority.pull_request_database_id != authority.pull_request_database_id
            or final_authority.pull_request_node_id != authority.pull_request_node_id
            or final_authority.binding != authority.binding
        ):
            return _conflicting_sha_carrier(marker)
        final_ref = _read_issue_branch_ref(
            client, repository, final_authority.lease.lease.branch_ref.removeprefix("refs/heads/"),
        )
        active = (
            final_ref == head_sha
            and final_authority.pr.head_oid == head_sha
            and final_authority.raw_pr_state in {"OPEN", "CLOSED"}
            and final_authority.raw_pr_merged is False
            and final_authority.pr_issue.state == final_authority.raw_pr_state.lower()
        )
        activation = CarrierActivation.ACTIVE if active else CarrierActivation.RESERVED_INACTIVE
        return ShaCarrierResolution(activation, CarrierRole.ISSUE_CANCEL, marker)
    except Exception:
        return _conflicting_sha_carrier(marker)


def derive_issue_owner_pr(
    client: GitHubClient,
    repository: str,
    head_sha: str,
    resolution: ShaCarrierResolution,
    app_slug: str,
    *,
    role_already_resolved: bool = False,
) -> IssueOwnerPR:
    """Derive an Issue owner from validated claim history and exact current binding."""
    if (
        type(head_sha) is not str
        or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None
        or type(resolution) is not ShaCarrierResolution
        or resolution.activation not in {CarrierActivation.ACTIVE, CarrierActivation.RESERVED_INACTIVE}
        or type(resolution.marker) is not ClaimedHeadMarker
        or resolution.marker.owner_kind != "ISSUE"
    ):
        raise R02Error("exact Issue claimed-head resolution is required to derive its owner")
    if type(role_already_resolved) is not bool:
        raise R02Error("role_already_resolved must be an exact bool")
    if not role_already_resolved:
        fresh_resolution = resolve_sha_carrier_role(
            client, repository, head_sha, app_slug, LegacyEvidenceDisposition.CONFLICTING,
        )
        if fresh_resolution != resolution:
            raise StaleAuthorityError("Issue SHA role changed during owner derivation")
    try:
        central = client.get_repository_metadata(repository)
        central_node_id, issue_database_id, issue_node_id, issue_number = parse_issue_owner_key(
            resolution.marker.owner_key,
        )
        if (
            type(central) is not RepositoryMetadata
            or central.full_name != repository
            or central.default_branch != "main"
            or central.node_id != central_node_id
        ):
            raise R02Error("Issue owner key does not bind the exact central repository")
        app = resolve_app_identity(client, app_slug)
        issue = client.get_issue_metadata(repository, issue_number)
        comments = tuple(client.list_issue_comments(repository, issue_number))
        if (
            type(issue) is not IssueMetadata
            or issue.number != issue_number
            or issue.database_id != issue_database_id
            or issue.node_id != issue_node_id
            or issue.is_pull_request
        ):
            raise R02Error("claimed Issue owner does not match fresh Issue identity")
        anchor = validate_unique_issue_anchor(comments, issue, app)
        if issue_owner_key(
            central.node_id, anchor.anchor.issue_database_id,
            anchor.anchor.issue_node_id, anchor.anchor.issue_number,
        ) != resolution.marker.owner_key:
            raise R02Error("IssueRequestAnchor does not match the claimed owner key")
        lease = _resolve_issue_branch_lease_class(
            client, repository, comments, app, anchor.anchor,
            anchor.comment.database_id, central.node_id,
        )
        if lease is None:
            raise R02Error("exact IssueBranchLease is required to derive an Issue owner")
        if resolution.marker.claim_kind == "ISSUE_BRANCH_LEASE" and (
            lease.lease.initial_head_sha != head_sha or _lease_marker_for(lease.lease) != resolution.marker
        ):
            raise R02Error("Issue lease does not bind the exact claimed head")
        if resolution.marker.claim_kind == "ISSUE_CANCELLATION_FENCE":
            authority = _fresh_issue_cancellation_authority(
                client, repository, issue_number, app, allow_pr_stage_state=True,
            )
            current_ref = _read_issue_branch_ref(
                client, repository, authority.lease.lease.branch_ref.removeprefix("refs/heads/"),
            )
            fences = _issue_cancellation_fence_comments(
                client, repository, authority.pr_comments, app, authority, current_ref or ZERO_OID,
            )
            exact = tuple(
                item for item in fences
                if item.fence.cancellation_head_sha == head_sha
                and _issue_cancellation_fence_marker(item.fence) == resolution.marker
            )
            if len(exact) != 1 or (
                resolution.activation is CarrierActivation.ACTIVE
                and (current_ref != head_sha or authority.pr.head_oid != head_sha)
            ):
                raise R02Error("cancellation owner does not match the exact active fence/PR head")
            return IssueOwnerPR(
                issue_number, authority.pull_request_number, resolution.marker.owner_key,
                "PRE_BINDING" if authority.binding_authority == "PRE_BINDING" else "FULL_BINDING",
            )
        state = _read_managed_issue_pr_binding_state(
            client, repository, issue_number, app, central.node_id,
            lambda _request, _request_class: None,
            validate_fresh_source_authority=False,
            require_open_lifecycle=False,
        )
        current_ref = _read_issue_branch_ref(
            client, repository, state.binding.branch_ref.removeprefix("refs/heads/"),
        )
        pr_comments = tuple(client.list_issue_comments(repository, state.binding.pull_request_number))
        history = _issue_authority_history(
            client, repository, pr_comments, app, state, current_ref or ZERO_OID,
        )
        if not any(
            item.target_head_sha == head_sha
            and item.claim_kind == resolution.marker.claim_kind
            and (
                (_issue_head_claim_marker(item.artifact) if item.claim_kind == "ISSUE_HEAD_CLAIM"
                 else _required_status_epoch_marker(item.artifact) if item.claim_kind == "REQUIRED_STATUS_EPOCH"
                 else _issue_finalization_epoch_marker(item.artifact) if item.claim_kind == "ISSUE_FINALIZATION_EPOCH"
                 else _lease_marker_for(item.artifact)) == resolution.marker
            )
            for item in history
        ):
            raise R02Error("Issue authority history does not bind the claimed owner PR")
        if resolution.activation is CarrierActivation.ACTIVE and (
            current_ref != head_sha or state.pr.head_oid != head_sha
        ):
            raise R02Error("active Issue owner PR/ref no longer points at the exact resolved head")
        return IssueOwnerPR(issue_number, state.binding.pull_request_number, resolution.marker.owner_key, "FULL_BINDING")
    except R02Error:
        raise
    except Exception as error:
        raise StaleAuthorityError(f"exact Issue owner derivation failed: {_bounded_reason(error)}") from None


def publish_unclaimed_external_success(
    client: GitHubClient,
    repository: RepositoryMetadata,
    head_sha: str,
    resolution: ShaCarrierResolution,
    app: AppIdentity,
) -> StatusWriteReceipt:
    """Publish only the PR-independent external success tuple for proven-unclaimed H."""
    if type(repository) is not RepositoryMetadata:
        raise R02Error("exact central repository metadata is required for external status")
    if type(resolution) is not ShaCarrierResolution or resolution != ShaCarrierResolution(
        CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION,
    ):
        raise R02Error("external success requires exact UNCLAIMED_OUT_OF_FEDERATION resolution")
    if type(app) is not AppIdentity:
        raise R02Error("exact trusted App identity is required for external status")
    if (
        type(repository.id) is not int or repository.id <= 0
        or type(repository.node_id) is not str or not repository.node_id
        or type(repository.full_name) is not str or repository.full_name.count("/") != 1
        or not re.fullmatch(r"[0-9a-f]{40}", head_sha if type(head_sha) is str else "")
        or type(app.bot_id) is not int or app.bot_id <= 0
        or type(app.bot_node_id) is not str or not app.bot_node_id
        or type(app.bot_login) is not str or not app.bot_login
    ):
        raise R02Error("external status repository, SHA, or Bot identity is malformed")
    digest = external_status_evidence_digest(
        repository.id, repository.node_id, repository.full_name, head_sha,
    )
    description = render_status_description(StatusClass.EXTERNAL, digest)
    receipt = client.create_commit_status(
        repository.full_name,
        head_sha,
        "success",
        _EXTERNAL_STATUS_CONTEXT,
        description,
        None,
    )
    expected_route = f"/repos/{repository.full_name}/statuses/{head_sha}"
    if type(receipt) is not StatusWriteReceipt or (
        receipt.repository != repository.full_name
        or receipt.requested_sha != head_sha
        or receipt.method != "POST"
        or receipt.route != expected_route
        or receipt.requested_state != "success"
        or receipt.requested_context != _EXTERNAL_STATUS_CONTEXT
        or receipt.requested_description != description
        or receipt.requested_target_url is not None
    ):
        raise R02Error("external status write receipt does not match the exact requested tuple")
    status = receipt.returned_status
    if type(status) is not CommitStatus or (
        status.context != _EXTERNAL_STATUS_CONTEXT
        or status.state != "success"
        or status.description != description
        or status.target_url is not None
        or status.creator_database_id != app.bot_id
        or status.creator_node_id != app.bot_node_id
        or status.creator_login != app.bot_login
        or status.creator_type != "Bot"
    ):
        raise R02Error("external status response does not match the exact App Bot tuple")
    return receipt


def _latest_exact_issue_final_status_evidence(
    client: GitHubClient,
    repository: str,
    head_sha: str,
    app: AppIdentity,
) -> ExactAppRequiredStatusEvidence | None:
    """Select corroborating evidence only from the exact App's issue-final success rows."""
    try:
        statuses = tuple(client.list_commit_statuses(repository, head_sha))
    except Exception:
        # This evidence is corroborating only. Its absence or temporary
        # unavailability never suppresses a RequiredStatusEpoch transition.
        return None
    matching: list[CommitStatus] = []
    for status in statuses:
        if type(status) is not CommitStatus or (
            status.creator_database_id != app.bot_id
            or status.creator_node_id != app.bot_node_id
            or status.creator_login != app.bot_login
            or status.creator_type != "Bot"
            or status.state != "success"
            or status.context != "federation/trusted-validation"
            or status.target_url is not None
            or status.description is None
        ):
            continue
        try:
            description = parse_status_description(status.description)
        except RequestModelError:
            continue
        if description.status_class is StatusClass.ISSUE_FINAL:
            matching.append(status)
    if not matching:
        return None
    latest = max(matching, key=lambda item: (item.updated_at, item.created_at, item.id))
    try:
        return ExactAppRequiredStatusEvidence(
            latest.id, latest.node_id, latest.state, latest.context, latest.description or "",
            latest.target_url, latest.creator_database_id, latest.creator_node_id,
            latest.creator_login, latest.creator_type, latest.created_at, latest.updated_at,
        )
    except RequestModelError:
        return None


def _read_latest_exact_app_required_status_snapshot(
    client: GitHubClient,
    repository: str,
    head_sha: str,
    app: AppIdentity,
) -> tuple[ExactAppRequiredStatusSnapshot, bool, bool, CommitStatus | None]:
    try:
        statuses = tuple(client.list_commit_statuses(repository, head_sha))
    except Exception as error:
        raise StaleAuthorityError(f"exact-App status snapshot is unavailable: {_bounded_reason(error)}") from None
    matching = [
        status for status in statuses
        if type(status) is CommitStatus
        and status.creator_database_id == app.bot_id
        and status.creator_node_id == app.bot_node_id
        and status.creator_login == app.bot_login
        and status.creator_type == "Bot"
        and status.context == "federation/trusted-validation"
    ]
    issue_final_success = False
    exact_app_success = False
    for status in matching:
        if status.state != "success":
            continue
        exact_app_success = True
        if status.description is None:
            continue
        try:
            issue_final_success = issue_final_success or (
                parse_status_description(status.description).status_class is StatusClass.ISSUE_FINAL
            )
        except RequestModelError:
            continue
    if not matching:
        return ExactAppRequiredStatusSnapshot.absent(head_sha), issue_final_success, exact_app_success, None
    latest = max(matching, key=lambda item: (item.updated_at, item.created_at, item.id))
    if latest.description is None:
        raise R02Error("latest exact-App required status has no canonical description")
    try:
        parsed = parse_status_description(latest.description)
        snapshot = ExactAppRequiredStatusSnapshot.present_status(
            queried_sha=head_sha,
            status_id=latest.id,
            status_node_id=latest.node_id,
            creator_database_id=latest.creator_database_id,
            creator_node_id=latest.creator_node_id,
            creator_login=latest.creator_login,
            creator_type=latest.creator_type,
            context=latest.context,
            state=latest.state,
            description=latest.description,
            target_url=latest.target_url,
            created_at=latest.created_at,
            updated_at=latest.updated_at,
            parsed_status_class=parsed.status_class,
            parsed_evidence_digest=parsed.evidence_digest,
        )
    except RequestModelError as error:
        raise R02Error(f"latest exact-App required status is not snapshot-safe: {_bounded_reason(error)}") from None
    return snapshot, issue_final_success, exact_app_success, latest


def _latest_exact_cancel_status_evidence(
    client: GitHubClient,
    repository: str,
    fence: IssueCancellationFence,
    app: AppIdentity,
) -> ExactAppRequiredStatusSnapshot | None:
    snapshot, _issue_final_success, any_exact_app_success, latest = _read_latest_exact_app_required_status_snapshot(
        client, repository, fence.cancellation_head_sha, app,
    )
    if any_exact_app_success:
        raise StaleAuthorityError("any exact-App success on ISSUE_CANCEL blocks cancellation continuation")
    if not snapshot.is_present:
        return None
    desired_digest = cancel_status_evidence_digest(
        central_repository_node_id=fence.central_repository_node_id,
        issue_number=fence.issue_number,
        issue_database_id=fence.issue_database_id,
        issue_node_id=fence.issue_node_id,
        fence_id=fence.fence_id,
        cancellation_head_sha=fence.cancellation_head_sha,
        binding_authority=fence.binding_authority,
        pull_request_number=fence.pull_request_number,
        pull_request_database_id=fence.pull_request_database_id,
        pull_request_node_id=fence.pull_request_node_id,
    )
    if snapshot.state == "success":
        raise StaleAuthorityError("exact-App success on ISSUE_CANCEL blocks cancellation failure continuation")
    if snapshot.status_class is StatusClass.CANCEL:
        if (
            snapshot.state != "failure"
            or snapshot.evidence_digest != desired_digest
            or snapshot.target_url is not None
        ):
            raise StaleAuthorityError("latest exact-App cancel status does not match this fence")
        return snapshot
    return None


def _snapshot_required_status_row(
    status: CommitStatus,
    queried_sha: str,
) -> ExactAppRequiredStatusSnapshot:
    if type(status) is not CommitStatus or status.description is None:
        raise R02Error("exact required status row is missing or malformed")
    try:
        parsed = parse_status_description(status.description)
        return ExactAppRequiredStatusSnapshot.present_status(
            queried_sha=queried_sha,
            status_id=status.id,
            status_node_id=status.node_id,
            creator_database_id=status.creator_database_id,
            creator_node_id=status.creator_node_id,
            creator_login=status.creator_login,
            creator_type=status.creator_type,
            context=status.context,
            state=status.state,
            description=status.description,
            target_url=status.target_url,
            created_at=status.created_at,
            updated_at=status.updated_at,
            parsed_status_class=parsed.status_class,
            parsed_evidence_digest=parsed.evidence_digest,
        )
    except RequestModelError as error:
        raise R02Error(f"exact required status row cannot be snapshotted: {_bounded_reason(error)}") from None


def _validate_issue_cancel_status_receipt(
    receipt: StatusWriteReceipt,
    repository: RepositoryMetadata,
    fence: IssueCancellationFence,
    app: AppIdentity,
) -> CommitStatus:
    digest = cancel_status_evidence_digest(
        central_repository_node_id=repository.node_id,
        issue_number=fence.issue_number,
        issue_database_id=fence.issue_database_id,
        issue_node_id=fence.issue_node_id,
        fence_id=fence.fence_id,
        cancellation_head_sha=fence.cancellation_head_sha,
        binding_authority=fence.binding_authority,
        pull_request_number=fence.pull_request_number,
        pull_request_database_id=fence.pull_request_database_id,
        pull_request_node_id=fence.pull_request_node_id,
    )
    description = render_status_description(StatusClass.CANCEL, digest)
    if len(description.encode("ascii")) != 81:
        raise R02Error("canonical cancellation status description must be exactly 81 ASCII bytes")
    expected_route = f"/repos/{repository.full_name}/statuses/{fence.cancellation_head_sha}"
    if type(receipt) is not StatusWriteReceipt or (
        receipt.repository != repository.full_name
        or receipt.requested_sha != fence.cancellation_head_sha
        or receipt.method != "POST"
        or receipt.route != expected_route
        or receipt.requested_state != "failure"
        or receipt.requested_context != "federation/trusted-validation"
        or receipt.requested_description != description
        or receipt.requested_target_url is not None
    ):
        raise R02Error("cancel status receipt does not match the exact requested tuple")
    status = receipt.returned_status
    if type(status) is not CommitStatus or (
        status.state != "failure"
        or status.context != "federation/trusted-validation"
        or status.description != description
        or status.target_url is not None
        or status.creator_database_id != app.bot_id
        or status.creator_node_id != app.bot_node_id
        or status.creator_login != app.bot_login
        or status.creator_type != "Bot"
    ):
        raise R02Error("cancel status response does not match the exact App Bot failure tuple")
    return status


def _validate_issue_final_status_receipt(
    receipt: StatusWriteReceipt,
    repository: RepositoryMetadata,
    epoch: IssueFinalizationEpoch,
    app: AppIdentity,
) -> StatusWriteReceipt:
    expected_route = f"/repos/{repository.full_name}/statuses/{epoch.final_head_sha}"
    if type(receipt) is not StatusWriteReceipt or (
        receipt.repository != repository.full_name
        or receipt.requested_sha != epoch.final_head_sha
        or receipt.method != "POST"
        or receipt.route != expected_route
        or receipt.requested_state != "success"
        or receipt.requested_context != epoch.required_status_context
        or receipt.requested_description != epoch.required_status_description
        or receipt.requested_target_url is not None
    ):
        raise R02Error("issue-final status receipt does not match the exact epoch tuple")
    status = receipt.returned_status
    if type(status) is not CommitStatus or (
        status.context != epoch.required_status_context
        or status.state != "success"
        or status.description != epoch.required_status_description
        or status.target_url is not None
        or status.creator_database_id != app.bot_id
        or status.creator_node_id != app.bot_node_id
        or status.creator_login != app.bot_login
        or status.creator_type != "Bot"
    ):
        raise R02Error("issue-final response does not match the exact App Bot status tuple")
    return receipt


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


def _issue_anchor_candidates(comments: Iterable[IssueComment]) -> list[IssueAnchorComment]:
    found: list[IssueAnchorComment] = []
    for comment in comments:
        if not comment.body.startswith("<!-- swiftstream-federation-issue-request-anchor:v1 -->"):
            continue
        try:
            anchor = parse_issue_request_anchor(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueRequestAnchor: {_bounded_reason(error)}") from None
        found.append(IssueAnchorComment(anchor, comment))
    return found


def _validate_issue_source_authority(anchor: IssueRequestAnchor, authority: IssueSourceAuthority) -> None:
    if type(authority) is not IssueSourceAuthority:
        raise R02Error("fresh Issue source authority is required")
    if (
        authority.request_class is not anchor.request_class
        or authority.source_id != anchor.source_id
        or authority.source_repository_id != anchor.source_repository_id
        or authority.source_canonical_full_name != anchor.source_canonical_full_name
        or authority.source_identity_kind.value != anchor.source_identity_kind
    ):
        raise StaleAuthorityError("Issue source authority changed from immutable IssueRequestAnchor")


def validate_unique_issue_anchor(
    comments: Iterable[IssueComment],
    issue: IssueMetadata,
    app: AppIdentity,
) -> IssueAnchorComment:
    if type(issue) is not IssueMetadata or issue.is_pull_request:
        raise R02Error("IssueRequestAnchor requires an Issue metadata snapshot")
    found = _issue_anchor_candidates(comments)
    if len(found) != 1:
        raise DuplicateAnchorError("exactly one immutable IssueRequestAnchor comment is required")
    item = found[0]
    anchor, comment = item.anchor, item.comment
    if (
        anchor.issue_number != issue.number
        or anchor.issue_database_id != issue.database_id
        or anchor.issue_node_id != issue.node_id
        or anchor.original_author_id != issue.author_id
    ):
        raise R02Error("IssueRequestAnchor Issue/requester identity mismatch")
    if (
        comment.author_id != app.bot_node_id
        or comment.author_login != app.bot_login
        or comment.author_type not in {None, "Bot"}
    ):
        raise R02Error("IssueRequestAnchor is not authored by the designated App Bot")
    if (
        comment.editor_id is not None
        or comment.editor_login is not None
        or comment.editor_type is not None
        or comment.last_edited_at is not None
        or comment.includes_created_edit
    ):
        raise R02Error("IssueRequestAnchor comment edit-integrity metadata is not immutable")
    return item


def create_or_validate_issue_anchor(
    client: GitHubClient,
    repository: str,
    issue: IssueMetadata,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    source_authority: IssueSourceAuthority | None,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
) -> IssueAnchorComment:
    """Establish one immutable Issue anchor or validate its exact persisted evidence."""
    if type(issue) is not IssueMetadata or issue.is_pull_request:
        raise R02Error("Issue intake requires one Issue metadata snapshot")
    if not callable(source_authority_resolver):
        raise R02Error("a fresh Issue source-authority resolver is required")
    comment_list = list(comments)
    existing = _issue_anchor_candidates(comment_list)
    if existing:
        persisted = validate_unique_issue_anchor(comment_list, issue, app)
        try:
            fresh = source_authority_resolver(persisted.anchor.initial_request, persisted.anchor.request_class)
        except Exception as error:
            raise StaleAuthorityError(f"fresh Issue source authority is unavailable: {_bounded_reason(error)}") from None
        _validate_issue_source_authority(persisted.anchor, fresh)
        return persisted

    if type(source_authority) is not IssueSourceAuthority:
        raise R02Error("new IssueRequestAnchor requires a validated IssueSourceAuthority")
    try:
        initial_request = parse_issue_request_body(issue.body)
        initial_body_sha256 = body_sha256(issue.body)
    except RequestModelError as error:
        raise R02Error(f"Issue request body is invalid: {_bounded_reason(error)}") from None
    if initial_request.request_class is not source_authority.request_class:
        raise R02Error("Issue body request class does not match IssueSourceAuthority")
    _validate_issue_source_authority(
        IssueRequestAnchor(
            1,
            issue.number,
            issue.database_id,
            issue.node_id,
            initial_request.request_class,
            issue.author_id,
            issue.author_login,
            initial_body_sha256,
            initial_request,
            source_authority.source_id,
            source_authority.source_repository_id,
            source_authority.source_canonical_full_name,
            source_authority.source_identity_kind.value,
            issue.last_edited_at,
            issue.includes_created_edit,
        ),
        source_authority,
    )
    intended = IssueRequestAnchor(
        1,
        issue.number,
        issue.database_id,
        issue.node_id,
        initial_request.request_class,
        issue.author_id,
        issue.author_login,
        initial_body_sha256,
        initial_request,
        source_authority.source_id,
        source_authority.source_repository_id,
        source_authority.source_canonical_full_name,
        source_authority.source_identity_kind.value,
        issue.last_edited_at,
        issue.includes_created_edit,
    )
    client.create_issue_comment(repository, issue.number, intended.render())
    try:
        reread_issue = client.get_issue_metadata(repository, issue.number)
        reread_comments = client.list_issue_comments(repository, issue.number)
    except Exception as error:
        raise StaleAuthorityError(f"Issue anchor write could not be re-read: {_bounded_reason(error)}") from None
    if (
        reread_issue.number != issue.number
        or reread_issue.database_id != issue.database_id
        or reread_issue.node_id != issue.node_id
        or reread_issue.is_pull_request
        or reread_issue.author_id != issue.author_id
    ):
        raise StaleAuthorityError("Issue identity changed while creating IssueRequestAnchor")
    try:
        fresh_source_authority = source_authority_resolver(initial_request, initial_request.request_class)
    except Exception as error:
        raise StaleAuthorityError(f"fresh Issue source authority is unavailable after anchoring: {_bounded_reason(error)}") from None
    _validate_issue_source_authority(intended, fresh_source_authority)
    persisted = validate_unique_issue_anchor(reread_comments, reread_issue, app)
    if persisted.anchor != intended:
        raise StaleAuthorityError("persisted IssueRequestAnchor differs from intended authority")
    if (
        reread_issue.body != issue.body
        or reread_issue.last_edited_at != issue.last_edited_at
        or reread_issue.includes_created_edit != issue.includes_created_edit
    ):
        raise StaleAuthorityError("Issue body/edit metadata changed after the immutable anchor was created")
    return persisted


def _issue_comment_edited(comment: IssueComment) -> bool:
    return any((
        comment.editor_id is not None,
        comment.editor_login is not None,
        comment.editor_type is not None,
        comment.last_edited_at is not None,
        comment.includes_created_edit,
    ))


def _issue_patch_candidate(body: str) -> bool:
    normalized = body.replace("\r\n", "\n")
    return next((line for line in normalized.split("\n") if line != ""), None) == PATCH_SENTINEL


def authorized_issue_patch_events(
    client: GitHubClient,
    repository: str,
    anchor_comment: IssueAnchorComment,
    comments: Iterable[IssueComment],
) -> tuple[IssuePatchEvent, ...]:
    events: list[IssuePatchEvent] = []
    anchor_id = anchor_comment.comment.database_id
    for comment in comments:
        if comment.database_id <= anchor_id:
            continue
        if type(comment.body) is str and comment.body.startswith(ISSUE_PATCH_PROJECTION_MARKER):
            continue
        try:
            if len(comment.body.encode("utf-8")) > 16_384:
                # The Issue PATCH authority remains capped at 16 KiB. The only
                # wider machine comment is a projection and is skipped above.
                continue
        except (AttributeError, UnicodeEncodeError):
            raise R02Error("Issue comment body is not valid UTF-8 text") from None
        authorized = False
        if comment.author_type == "User" and comment.author_id is not None and _issue_patch_candidate(comment.body):
            if comment.author_id == anchor_comment.anchor.original_author_id:
                authorized = True
            elif comment.author_login is not None:
                try:
                    authorized = client.get_collaborator_permission(repository, comment.author_login) in {"admin", "maintain"}
                except Exception:
                    authorized = False
        try:
            events.append(IssuePatchEvent(comment.database_id, authorized, _issue_comment_edited(comment), comment.body))
        except RequestModelError as error:
            raise R02Error(f"Issue PATCH event is invalid: {_bounded_reason(error)}") from None
    return tuple(sorted(events, key=lambda item: item.comment_id))


def reconstruct_issue_from_github(
    client: GitHubClient,
    repository: str,
    anchor_comment: IssueAnchorComment,
    comments: Iterable[IssueComment],
    semantic_validator: Callable[[Request], bool] | None = None,
) -> PatchFoldResult:
    """Rebuild effective Issue request from its immutable anchor and later Issue comments."""
    events = authorized_issue_patch_events(client, repository, anchor_comment, comments)
    try:
        return fold_issue_patch_events(anchor_comment.anchor, events, semantic_validator)
    except RequestModelError as error:
        raise R02Error(f"Issue PATCH fold failed closed: {_bounded_reason(error)}") from None


@dataclass(frozen=True)
class IssueBranchLeaseComment:
    lease: IssueBranchLease
    comment: IssueComment


@dataclass(frozen=True)
class IssuePRBindingState:
    issue_anchor: IssueAnchorComment
    lease: IssueBranchLeaseComment
    binding: IssuePRBinding
    issue_binding_comment: IssueComment
    pr_binding_comment: IssueComment
    pr: PullRequestMetadata
    pr_issue: IssueMetadata
    owning_issue: IssueMetadata


@dataclass(frozen=True)
class IssueHeadClaimComment:
    claim: IssueHeadClaim
    comment: IssueComment
    active: bool


@dataclass(frozen=True)
class RequiredStatusEpochComment:
    epoch: RequiredStatusEpoch
    comment: IssueComment
    active: bool


@dataclass(frozen=True)
class IssueFinalizationEpochComment:
    epoch: IssueFinalizationEpoch
    comment: IssueComment
    active: bool


@dataclass(frozen=True)
class IssueCancellationFenceComment:
    fence: IssueCancellationFence
    comment: IssueComment
    active: bool


@dataclass(frozen=True)
class IssueCancellationDraftWitnessComment:
    witness: IssueCancellationDraftWitness
    comment: IssueComment


@dataclass(frozen=True)
class IssueTerminalCancelledResultComment:
    result: IssueTerminalCancelledResult
    comment: IssueComment


@dataclass(frozen=True)
class IssueNoPRCancelledResultComment:
    result: IssueNoPRCancelledResult
    comment: IssueComment


@dataclass(frozen=True)
class _IssueCancellationAuthority:
    """Fresh central ownership inputs; binding stays absent for PRE_BINDING."""

    issue_anchor: IssueAnchorComment
    lease: IssueBranchLeaseComment
    binding_authority: str
    pull_request_number: int
    pull_request_database_id: int
    pull_request_node_id: str
    central_repository_node_id: str
    base_repository_node_id: str
    pr: PullRequestMetadata
    pr_issue: IssueMetadata
    owning_issue: IssueMetadata
    pr_comments: tuple[IssueComment, ...]
    binding: IssuePRBinding | None
    binding_state: IssuePRBindingState | None
    raw_pr_state: str
    raw_pr_merged: bool


class IssueCancellationClass(Enum):
    A_ANCHOR_ONLY = "A_ANCHOR_ONLY"
    B_LEASE_REF_ABSENT = "B_LEASE_REF_ABSENT"
    C_LEASE_ZERO_PR = "C_LEASE_ZERO_PR"
    D_PRE_BINDING_ONE_PR = "D_PRE_BINDING_ONE_PR"
    E_FULL_BINDING = "E_FULL_BINDING"
    F_CONFLICTING = "F_CONFLICTING"


@dataclass(frozen=True)
class _IssueCancellationPRCandidate:
    pr: PullRequestMetadata
    pr_issue: IssueMetadata
    comments: tuple[IssueComment, ...]
    raw_state: str
    raw_merged: bool
    raw_merged_at: str | None
    issue_binding: _IssuePRBindingComment | None
    pr_binding: _IssuePRBindingComment | None


@dataclass(frozen=True)
class IssueCancellationState:
    """Fresh central-only classification and immutable cancellation evidence."""

    classification: IssueCancellationClass
    repository: RepositoryMetadata
    issue: IssueMetadata
    issue_comments: tuple[IssueComment, ...]
    issue_anchor: IssueAnchorComment
    lease: IssueBranchLeaseComment | None
    branch_ref_oid: str | None
    all_state_pr_enumeration_digest: str
    pr_candidates: tuple[_IssueCancellationPRCandidate, ...]
    cancellation_authority: _IssueCancellationAuthority | None
    fence_items: tuple[IssueCancellationFenceComment, ...]
    witness_items: tuple[IssueCancellationDraftWitnessComment, ...]
    terminal_result_items: tuple[IssueTerminalCancelledResultComment, ...]
    no_pr_results: tuple[IssueNoPRCancelledResult, ...]
    merge_observed: bool


def _cancellation_binding_authority_id(authority: _IssueCancellationAuthority) -> str:
    if authority.binding_authority == "PRE_BINDING":
        if authority.binding is not None or authority.binding_state is not None:
            raise R02Error("PRE_BINDING cancellation authority must not carry a fabricated IssuePRBinding")
        return "PRE_BINDING"
    if authority.binding_authority == "FULL_BINDING":
        if authority.binding is None or authority.binding_state is None or authority.binding_state.binding != authority.binding:
            raise R02Error("FULL_BINDING cancellation authority requires the exact persisted IssuePRBinding")
        return authority.binding.binding_id
    raise R02Error("IssueCancellationFence binding authority is unsupported")


@dataclass(frozen=True)
class _IssueAuthorityNode:
    claim_kind: str
    role: CarrierRole
    target_head_sha: str
    from_head_sha: str | None
    tree_sha: str
    transition_kind: str
    artifact_id: str
    artifact_sha256: str
    comment: IssueComment
    artifact: Any
    active: bool = False
    proposal_origin: Any | None = None


@dataclass(frozen=True)
class _IssueEpochSnapshot:
    state: IssuePRBindingState
    repository: RepositoryMetadata
    accepted_main_sha: str
    accepted_main_tree_sha: str
    accepted_main_entries: tuple[Any, ...]
    current_ref: str
    issue: IssueMetadata
    issue_comments: tuple[IssueComment, ...]
    pr_comments: tuple[IssueComment, ...]
    fold: PatchFoldResult
    projections: tuple[IssuePatchProjection, ...]
    fresh_source: IssueSourceAuthority | None
    source_error: str | None
    history: tuple[_IssueAuthorityNode, ...]
    current_authority: _IssueAuthorityNode
    resolution: ShaCarrierResolution


@dataclass(frozen=True)
class _IssuePRBindingComment:
    binding: IssuePRBinding
    comment: IssueComment


@dataclass(frozen=True)
class _IssuePRCandidate:
    pr: PullRequestMetadata
    comments: tuple[IssueComment, ...]
    binding: _IssuePRBindingComment | None


def _lease_sha40(value: Any, label: str) -> str:
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise R02Error(f"{label} is not a canonical Git object SHA")
    return value


def _fresh_issue_source_authority(
    resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
    anchor: IssueRequestAnchor,
) -> IssueSourceAuthority:
    try:
        authority = resolver(anchor.initial_request, anchor.request_class)
    except Exception as error:
        raise StaleAuthorityError(f"fresh Issue source authority is unavailable: {_bounded_reason(error)}") from None
    _validate_issue_source_authority(anchor, authority)
    return authority


def _lease_repo_snapshot(
    client: GitHubClient,
    repository: str,
    expected_node_id: str,
) -> tuple[RepositoryMetadata, str]:
    try:
        metadata = client.get_repository_metadata(repository)
        if metadata.node_id != expected_node_id or not metadata.default_branch:
            raise StaleAuthorityError("central repository identity/default branch changed")
        branch_sha = _lease_sha40(client.get_ref_oid(repository, metadata.default_branch), "central default-branch head")
    except R02Error:
        raise
    except Exception as error:
        raise StaleAuthorityError(f"central repository snapshot is unavailable: {_bounded_reason(error)}") from None
    return metadata, branch_sha


def _lease_tree_snapshot(
    client: GitHubClient,
    repository: str,
    commit_sha: str,
) -> tuple[Any, str, tuple[Any, ...]]:
    try:
        metadata = client.get_commit_metadata(repository, commit_sha)
        if metadata.sha != commit_sha:
            raise R02Error("commit metadata identity does not match requested SHA")
        tree_sha, entries = client.get_commit_tree(repository, commit_sha)
        if tree_sha != metadata.tree_sha:
            raise R02Error("commit tree response identity does not match commit metadata")
        _lease_sha40(tree_sha, "commit tree SHA")
        return metadata, tree_sha, entries
    except R02Error:
        raise
    except Exception as error:
        raise StaleAuthorityError(f"Git commit/tree provenance is unavailable: {_bounded_reason(error)}") from None


def _lease_leaf_map(entries: Iterable[Any]) -> dict[str, tuple[str, str, str]]:
    leaves: dict[str, tuple[str, str, str]] = {}
    for entry in entries:
        if entry.object_type == "tree":
            continue
        if entry.path in leaves:
            raise R02Error("Git tree contains duplicate leaf paths")
        leaves[entry.path] = (entry.mode, entry.object_type, entry.sha)
    return leaves


def _validate_marker_only_tree_delta(
    base_entries: Iterable[Any],
    head_entries: Iterable[Any],
    expected_blob_sha: str,
) -> None:
    base = _lease_leaf_map(base_entries)
    head = _lease_leaf_map(head_entries)
    changed = {path for path in set(base) | set(head) if base.get(path) != head.get(path)}
    if changed != {REQUEST_MARKER}:
        raise R02Error("initial claimed tree must change only .federation-request")
    if head.get(REQUEST_MARKER) != ("100644", "blob", expected_blob_sha):
        raise R02Error("initial claimed tree .federation-request entry is not the exact regular blob")


def _lease_marker_for(lease: IssueBranchLease) -> ClaimedHeadMarker:
    return ClaimedHeadMarker(
        lease.claim_kind,
        lease.carrier_role,
        "ISSUE",
        issue_owner_key(
            lease.central_repository_node_id,
            lease.issue_database_id,
            lease.issue_node_id,
            lease.issue_number,
        ),
        lease.claim_generation_id,
        lease.carrier_nonce,
        "INITIAL",
    )


def _expected_deterministic_commit_sha(tree_sha: str, parent_sha: str, message: str, author_date: str) -> str:
    if type(author_date) is not str or not author_date.endswith("Z"):
        raise R02Error("claimed commit author date is not deterministic UTC")
    try:
        instant = datetime.fromisoformat(author_date[:-1] + "+00:00")
    except ValueError:
        raise R02Error("claimed commit author date is malformed") from None
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise R02Error("claimed commit author date lacks a timezone")
    git_timestamp = f"{int(instant.timestamp())} +0000"
    body = (
        f"tree {tree_sha}\nparent {parent_sha}\n"
        f"author Swift Stream Federation <automation@swiftstream.invalid> {git_timestamp}\n"
        f"committer Swift Stream Federation <automation@swiftstream.invalid> {git_timestamp}\n\n"
    ).encode("utf-8") + message.encode("utf-8")
    return hashlib.sha1(b"commit " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()


def _validate_issue_branch_lease_history(
    client: GitHubClient,
    repository: str,
    anchor: IssueRequestAnchor,
    lease: IssueBranchLease,
) -> None:
    if (
        lease.issue_number != anchor.issue_number
        or lease.issue_database_id != anchor.issue_database_id
        or lease.issue_node_id != anchor.issue_node_id
        or lease.issue_request_anchor_sha256 != anchor.canonical_sha256()
        or lease.source_id != anchor.source_id
        or lease.source_repository_id != anchor.source_repository_id
        or lease.request_class is not anchor.request_class
        or lease.branch_ref != issue_branch_ref(anchor.issue_number)
    ):
        raise R02Error("IssueBranchLease does not match its immutable IssueRequestAnchor")
    try:
        _base, base_tree_sha, base_entries = _lease_tree_snapshot(client, repository, lease.accepted_base_sha)
        authority_digest = issue_branch_lease_authority_digest(
            accepted_base_sha=lease.accepted_base_sha,
            accepted_base_tree_sha=base_tree_sha,
            branch_ref=lease.branch_ref,
            central_repository_node_id=lease.central_repository_node_id,
            owner_key=issue_owner_key(lease.central_repository_node_id, anchor.issue_database_id, anchor.issue_node_id, anchor.issue_number),
            issue_request_anchor_sha256=anchor.canonical_sha256(),
            request_class=anchor.request_class,
            source_canonical_full_name=anchor.source_canonical_full_name,
            source_id=anchor.source_id,
            source_identity_kind=anchor.source_identity_kind,
            source_repository_id=anchor.source_repository_id,
        )
        if authority_digest != lease.authority_preimage_digest:
            raise R02Error("IssueBranchLease authority preimage digest does not recompute")
        owner_key = issue_owner_key(lease.central_repository_node_id, anchor.issue_database_id, anchor.issue_node_id, anchor.issue_number)
        generation = claim_generation_id(
            authority_preimage_digest=authority_digest,
            carrier_nonce=lease.carrier_nonce,
            central_repository_node_id=lease.central_repository_node_id,
            owner_key=owner_key,
            from_head_sha=lease.accepted_base_sha,
            from_tree_sha=base_tree_sha,
        )
        marker = _lease_marker_for(lease)
        if generation != lease.claim_generation_id or marker.claim_generation_id != generation:
            raise R02Error("IssueBranchLease claimed-head generation does not recompute")
        marker_text = marker.render()
        if hashlib.sha256(marker_text.encode("utf-8")).hexdigest() != lease.initial_head_marker_digest:
            raise R02Error("IssueBranchLease marker digest does not match canonical marker")
        head, head_tree_sha, head_entries = _lease_tree_snapshot(client, repository, lease.initial_head_sha)
        if head.parents != (lease.accepted_base_sha,) or head.tree_sha != lease.initial_head_tree_sha or head_tree_sha != lease.initial_head_tree_sha:
            raise R02Error("IssueBranchLease initial commit parent/tree provenance does not match")
        expected_sha = _expected_deterministic_commit_sha(head.tree_sha, lease.accepted_base_sha, marker_text, head.author_date)
        if expected_sha != lease.initial_head_sha:
            raise R02Error("IssueBranchLease commit SHA does not bind the exact claimed-head marker")
        expected_bytes = (anchor.request_class.value + "\n").encode("utf-8")
        expected_blob_sha = hashlib.sha1(b"blob " + str(len(expected_bytes)).encode("ascii") + b"\0" + expected_bytes).hexdigest()
        _validate_marker_only_tree_delta(base_entries, head_entries, expected_blob_sha)
        readback = client.read_commit_file(repository, lease.initial_head_sha, REQUEST_MARKER, expected_mode="100644")
        if readback != expected_bytes:
            raise R02Error("IssueBranchLease .federation-request readback differs from the exact request class bytes")
        if parse_claimed_head_marker(marker_text) != marker:
            raise R02Error("IssueBranchLease marker does not parse canonically")
    except R02Error:
        raise
    except Exception as error:
        raise R02Error(f"IssueBranchLease historical provenance is invalid: {_bounded_reason(error)}") from None


def _lease_comment_candidates(
    comments: Iterable[IssueComment],
    app: AppIdentity,
    anchor: IssueRequestAnchor,
    anchor_comment_database_id: int,
    central_repository_node_id: str,
) -> list[IssueBranchLeaseComment]:
    found: list[IssueBranchLeaseComment] = []
    for comment in comments:
        if not comment.body.startswith(ISSUE_BRANCH_LEASE_MARKER):
            continue
        try:
            lease = parse_issue_branch_lease(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueBranchLease comment: {_bounded_reason(error)}") from None
        if (
            comment.author_id != app.bot_node_id
            or comment.author_login != app.bot_login
            or comment.author_type not in {None, "Bot"}
            or comment.editor_id is not None
            or comment.editor_login is not None
            or comment.editor_type is not None
            or comment.last_edited_at is not None
            or comment.includes_created_edit
        ):
            raise R02Error("IssueBranchLease comment authorship/edit integrity is invalid")
        if (
            lease.issue_number != anchor.issue_number
            or lease.issue_database_id != anchor.issue_database_id
            or lease.issue_node_id != anchor.issue_node_id
            or lease.issue_request_anchor_sha256 != anchor.canonical_sha256()
            or lease.source_id != anchor.source_id
            or lease.source_repository_id != anchor.source_repository_id
            or lease.request_class is not anchor.request_class
            or lease.branch_ref != issue_branch_ref(anchor.issue_number)
            or lease.issue_request_anchor_comment_database_id != anchor_comment_database_id
            or lease.central_repository_node_id != central_repository_node_id
        ):
            raise R02Error("IssueBranchLease does not match its immutable IssueRequestAnchor")
        found.append(IssueBranchLeaseComment(lease, comment))
    return found


def _resolve_issue_branch_lease_class(
    client: GitHubClient,
    repository: str,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    anchor: IssueRequestAnchor,
    anchor_comment_database_id: int,
    central_repository_node_id: str,
) -> IssueBranchLeaseComment | None:
    candidates = _lease_comment_candidates(comments, app, anchor, anchor_comment_database_id, central_repository_node_id)
    if not candidates:
        return None
    by_payload: dict[str, list[IssueBranchLeaseComment]] = {}
    for item in candidates:
        _validate_issue_branch_lease_history(client, repository, anchor, item.lease)
        by_payload.setdefault(item.lease.render(), []).append(item)
    if len(by_payload) != 1:
        raise R02Error("conflicting immutable IssueBranchLease payloads block progression")
    equivalent = next(iter(by_payload.values()))
    return min(equivalent, key=lambda item: item.comment.database_id)


def _read_issue_anchor_for_lease(
    client: GitHubClient,
    repository: str,
    anchor_comment: IssueAnchorComment,
    app: AppIdentity,
) -> tuple[IssueMetadata, tuple[IssueComment, ...], IssueAnchorComment]:
    try:
        issue = client.get_issue_metadata(repository, anchor_comment.anchor.issue_number)
        comments = client.list_issue_comments(repository, anchor_comment.anchor.issue_number)
    except Exception as error:
        raise StaleAuthorityError(f"Issue anchor/comment state is unavailable: {_bounded_reason(error)}") from None
    persisted = validate_unique_issue_anchor(comments, issue, app)
    if (
        persisted.anchor != anchor_comment.anchor
        or persisted.comment.database_id != anchor_comment.comment.database_id
        or persisted.comment.body != anchor_comment.comment.body
    ):
        raise StaleAuthorityError("the supplied IssueRequestAnchor is not the current canonical anchor")
    return issue, comments, persisted


def _validate_new_claimed_commit(
    client: GitHubClient,
    repository: str,
    accepted_base_sha: str,
    accepted_base_entries: Iterable[Any],
    created_head_sha: str,
    created_tree_sha: str,
    created_blob_sha: str,
    marker: ClaimedHeadMarker,
    expected_bytes: bytes,
    timestamp: str,
) -> None:
    metadata, head_tree_sha, head_entries = _lease_tree_snapshot(client, repository, created_head_sha)
    if metadata.parents != (accepted_base_sha,) or metadata.tree_sha != created_tree_sha or head_tree_sha != created_tree_sha:
        raise R02Error("created claimed commit parent/tree readback is not exact")
    if metadata.author_date != timestamp:
        raise R02Error("created claimed commit timestamp readback is not exact")
    if _expected_deterministic_commit_sha(created_tree_sha, accepted_base_sha, marker.render(), timestamp) != created_head_sha:
        raise R02Error("created claimed commit SHA does not bind its exact marker")
    expected_blob_sha = hashlib.sha1(b"blob " + str(len(expected_bytes)).encode("ascii") + b"\0" + expected_bytes).hexdigest()
    if created_blob_sha != expected_blob_sha:
        raise R02Error("created request blob SHA does not bind exact request bytes")
    _validate_marker_only_tree_delta(accepted_base_entries, head_entries, created_blob_sha)
    try:
        file_bytes = client.read_commit_file(repository, created_head_sha, REQUEST_MARKER, expected_mode="100644")
    except Exception as error:
        raise R02Error(f"created request blob could not be read back as mode 100644: {_bounded_reason(error)}") from None
    if file_bytes != expected_bytes:
        raise R02Error("created request blob readback is not the exact RequestClass line")
    if parse_claimed_head_marker(marker.render()) != marker:
        raise R02Error("locally generated claimed-head marker failed exact parser roundtrip")


def create_or_validate_issue_branch_lease(
    client: GitHubClient,
    repository: str,
    anchor_comment: IssueAnchorComment,
    app: AppIdentity,
    central_repository_node_id: str,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
    *,
    nonce_factory: Callable[[], str] | None = None,
) -> IssueBranchLeaseComment:
    """Create one unreachable marker-only claim or reuse its immutable historical lease."""
    if type(anchor_comment) is not IssueAnchorComment:
        raise R02Error("IssueBranchLease requires one validated IssueRequestAnchor comment")
    if not callable(source_authority_resolver):
        raise R02Error("a fresh Issue source-authority resolver is required")
    try:
        issue, comments, persisted_anchor = _read_issue_anchor_for_lease(client, repository, anchor_comment, app)
    except RequestModelError as error:
        raise R02Error(f"IssueRequestAnchor is invalid: {_bounded_reason(error)}") from None
    try:
        canonical = _resolve_issue_branch_lease_class(
            client, repository, comments, app, persisted_anchor.anchor,
            persisted_anchor.comment.database_id, central_repository_node_id,
        )
    except RequestModelError as error:
        raise R02Error(f"IssueBranchLease evidence is invalid: {_bounded_reason(error)}") from None
    try:
        repo_snapshot, current_main = _lease_repo_snapshot(client, repository, central_repository_node_id)
    except R02Error:
        raise

    if canonical is not None:
        _fresh_issue_source_authority(source_authority_resolver, persisted_anchor.anchor)
        # A later central-main advance does not rewrite historical lease provenance.
        return canonical

    _fresh_issue_source_authority(source_authority_resolver, persisted_anchor.anchor)
    accepted_base_sha = current_main
    try:
        base_metadata, accepted_base_tree_sha, accepted_base_entries = _lease_tree_snapshot(client, repository, accepted_base_sha)
        if base_metadata.sha != accepted_base_sha:
            raise R02Error("accepted central base commit identity changed")
        branch_ref = issue_branch_ref(persisted_anchor.anchor.issue_number)
        owner_key = issue_owner_key(
            central_repository_node_id,
            persisted_anchor.anchor.issue_database_id,
            persisted_anchor.anchor.issue_node_id,
            persisted_anchor.anchor.issue_number,
        )
        nonce = (nonce_factory or new_carrier_nonce)()
        if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise R02Error("trusted carrier nonce factory did not return 64 lowercase hex")
        authority_digest = issue_branch_lease_authority_digest(
            accepted_base_sha=accepted_base_sha,
            accepted_base_tree_sha=accepted_base_tree_sha,
            branch_ref=branch_ref,
            central_repository_node_id=central_repository_node_id,
            owner_key=owner_key,
            issue_request_anchor_sha256=persisted_anchor.anchor.canonical_sha256(),
            request_class=persisted_anchor.anchor.request_class,
            source_canonical_full_name=persisted_anchor.anchor.source_canonical_full_name,
            source_id=persisted_anchor.anchor.source_id,
            source_identity_kind=persisted_anchor.anchor.source_identity_kind,
            source_repository_id=persisted_anchor.anchor.source_repository_id,
        )
        generation = claim_generation_id(
            authority_preimage_digest=authority_digest,
            carrier_nonce=nonce,
            central_repository_node_id=central_repository_node_id,
            owner_key=owner_key,
            from_head_sha=accepted_base_sha,
            from_tree_sha=accepted_base_tree_sha,
        )
        marker = ClaimedHeadMarker("ISSUE_BRANCH_LEASE", "ISSUE_ACTIVE", "ISSUE", owner_key, generation, nonce, "INITIAL")
        expected_bytes = (persisted_anchor.anchor.request_class.value + "\n").encode("utf-8")
        blob_content = base64.b64encode(expected_bytes).decode("ascii")
        blob = client.create_blob(repository, blob_content, encoding="base64")
        blob_sha = _lease_sha40(blob.sha, "created blob SHA")
        entry = {"path": REQUEST_MARKER, "mode": "100644", "type": "blob", "sha": blob_sha}
        tree = client.create_tree(repository, accepted_base_tree_sha, [entry])
        tree_sha = _lease_sha40(tree.sha, "created tree SHA")
        timestamp = client.bot_commit_timestamp_after(repository, accepted_base_sha)
        created_head = client.create_commit(repository, marker.render(), tree_sha, [accepted_base_sha], timestamp=timestamp)
        head_sha = _lease_sha40(created_head.sha, "created commit SHA")
        _validate_new_claimed_commit(
            client,
            repository,
            accepted_base_sha,
            accepted_base_entries,
            head_sha,
            tree_sha,
            blob_sha,
            marker,
            expected_bytes,
            timestamp,
        )
        lease = IssueBranchLease.create(
            schema_version=1,
            issue_number=persisted_anchor.anchor.issue_number,
            issue_database_id=persisted_anchor.anchor.issue_database_id,
            issue_node_id=persisted_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=persisted_anchor.comment.database_id,
            issue_request_anchor_sha256=persisted_anchor.anchor.canonical_sha256(),
            source_id=persisted_anchor.anchor.source_id,
            source_repository_id=persisted_anchor.anchor.source_repository_id,
            central_repository_node_id=central_repository_node_id,
            branch_ref=branch_ref,
            accepted_base_sha=accepted_base_sha,
            carrier_role="ISSUE_ACTIVE",
            claim_kind="ISSUE_BRANCH_LEASE",
            claim_generation_id=generation,
            carrier_nonce=nonce,
            authority_preimage_digest=authority_digest,
            initial_head_sha=head_sha,
            initial_head_tree_sha=tree_sha,
            initial_head_parent_sha=accepted_base_sha,
            initial_head_marker_digest=hashlib.sha256(marker.render().encode("utf-8")).hexdigest(),
            request_class=persisted_anchor.anchor.request_class,
        )
        client.create_issue_comment(repository, issue.number, lease.render())
        try:
            reread_issue, reread_comments, reread_anchor = _read_issue_anchor_for_lease(client, repository, persisted_anchor, app)
            persisted_lease = _resolve_issue_branch_lease_class(
                client, repository, reread_comments, app, reread_anchor.anchor,
                reread_anchor.comment.database_id, central_repository_node_id,
            )
        except (RequestModelError, R02Error) as error:
            raise StaleAuthorityError(f"persisted IssueBranchLease could not be validated: {_bounded_reason(error)}") from None
        if persisted_lease is None or persisted_lease.lease != lease:
            raise StaleAuthorityError("persisted IssueBranchLease differs from the intended immutable lease")
        _fresh_issue_source_authority(source_authority_resolver, reread_anchor.anchor)
        final_repo, final_main = _lease_repo_snapshot(client, repository, central_repository_node_id)
        if final_repo.full_name != repo_snapshot.full_name or final_repo.default_branch != repo_snapshot.default_branch:
            raise StaleAuthorityError("central repository identity/default branch changed during lease creation")
        if final_main != accepted_base_sha:
            raise StaleAuthorityError("central default branch advanced during new IssueBranchLease creation")
        return persisted_lease
    except (RequestModelError, R02Error):
        raise
    except Exception as error:
        raise R02Error(f"IssueBranchLease creation failed closed: {_bounded_reason(error)}") from None


def _issue_pr_authority_fence(
    comments: Iterable[IssueComment],
    app: AppIdentity,
    *,
    allow_cancellation_fence: bool = False,
) -> None:
    allowed = (
        ISSUE_REQUEST_ANCHOR_MARKER,
        ISSUE_BRANCH_LEASE_MARKER,
        ISSUE_INTERNAL_PR_BINDING_MARKER,
        ISSUE_PATCH_PROJECTION_MARKER,
        ISSUE_HEAD_CLAIM_MARKER,
        REQUIRED_STATUS_EPOCH_MARKER,
        ISSUE_FINALIZATION_EPOCH_MARKER,
    ) + ((
        ISSUE_CANCELLATION_FENCE_MARKER,
        ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER,
        ISSUE_TERMINAL_CANCELLED_RESULT_MARKER,
        ISSUE_NO_PR_CANCELLED_RESULT_MARKER,
    ) if allow_cancellation_fence else ())
    cancellation_markers = (
        ISSUE_CANCELLATION_FENCE_MARKER,
        ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER,
        ISSUE_TERMINAL_CANCELLED_RESULT_MARKER,
        ISSUE_NO_PR_CANCELLED_RESULT_MARKER,
    )
    reserved_prefix = "<!-- swiftstream-federation-issue-"
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(reserved_prefix):
            continue
        if any(comment.body.startswith(marker) for marker in cancellation_markers) and not allow_cancellation_fence:
            raise StaleAuthorityError(
                "persisted cancellation authority is a one-way gate for non-cancellation progression"
            )
        if (
            comment.author_id != app.bot_node_id
            or comment.author_login != app.bot_login
            or comment.author_type not in {None, "Bot"}
            or _issue_comment_edited(comment)
        ):
            continue
        permitted = allowed + (
            (
                ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER,
                ISSUE_TERMINAL_CANCELLED_RESULT_MARKER,
                ISSUE_NO_PR_CANCELLED_RESULT_MARKER,
            )
            if allow_cancellation_fence else ()
        )
        if not any(comment.body.startswith(marker) for marker in permitted):
            raise R02Error("unrecognized reserved Issue authority marker blocks Wave 03 progression")


def _binding_comment_candidates(
    comments: Iterable[IssueComment],
    app: AppIdentity,
    marker: str,
    parser: Callable[[str], IssuePRBinding],
    label: str,
) -> tuple[_IssuePRBindingComment, ...]:
    found: list[_IssuePRBindingComment] = []
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(marker):
            continue
        try:
            binding = parser(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed {label}: {_bounded_reason(error)}") from None
        if (
            comment.author_id != app.bot_node_id
            or comment.author_login != app.bot_login
            or comment.author_type not in {None, "Bot"}
            or _issue_comment_edited(comment)
        ):
            raise R02Error(f"{label} authorship/edit integrity is invalid")
        found.append(_IssuePRBindingComment(binding, comment))
    if len(found) > 1:
        raise R02Error(f"duplicate {label} comments block progression")
    return tuple(found)


def _binding_comment_sha256(comment: IssueComment) -> str:
    try:
        return hashlib.sha256(comment.body.encode("utf-8")).hexdigest()
    except (AttributeError, UnicodeEncodeError):
        raise R02Error("binding provenance comment body is not valid UTF-8 text") from None


def _issue_head_claim_marker(claim: IssueHeadClaim) -> ClaimedHeadMarker:
    return ClaimedHeadMarker(
        claim.claim_kind,
        claim.carrier_role,
        "ISSUE",
        issue_owner_key(
            claim.central_repository_node_id,
            claim.issue_database_id,
            claim.issue_node_id,
            claim.issue_number,
        ),
        claim.claim_generation_id,
        claim.carrier_nonce,
        claim.transition_kind,
    )


def _required_status_epoch_marker(epoch: RequiredStatusEpoch) -> ClaimedHeadMarker:
    if type(epoch) is not RequiredStatusEpoch:
        raise R02Error("RequiredStatusEpoch marker requires its exact parsed artifact")
    return ClaimedHeadMarker(
        epoch.claim_kind,
        epoch.carrier_role,
        "ISSUE",
        issue_owner_key(
            epoch.central_repository_node_id,
            epoch.issue_database_id,
            epoch.issue_node_id,
            epoch.issue_number,
        ),
        epoch.claim_generation_id,
        epoch.carrier_nonce,
        epoch.transition_kind,
    )


def _issue_finalization_epoch_marker(epoch: IssueFinalizationEpoch) -> ClaimedHeadMarker:
    if type(epoch) is not IssueFinalizationEpoch:
        raise R02Error("IssueFinalizationEpoch marker requires its exact parsed artifact")
    return ClaimedHeadMarker(
        epoch.claim_kind,
        epoch.carrier_role,
        "ISSUE",
        issue_owner_key(
            epoch.central_repository_node_id,
            epoch.issue_database_id,
            epoch.issue_node_id,
            epoch.issue_number,
        ),
        epoch.claim_generation_id,
        epoch.carrier_nonce,
        epoch.transition_kind,
    )


def _issue_head_claim_matches_binding(claim: IssueHeadClaim, state: IssuePRBindingState) -> None:
    anchor = state.issue_anchor
    lease = state.lease
    binding = state.binding
    expected = (
        anchor.anchor.issue_number,
        anchor.anchor.issue_database_id,
        anchor.anchor.issue_node_id,
        anchor.comment.database_id,
        anchor.anchor.canonical_sha256(),
        lease.comment.database_id,
        _binding_comment_sha256(lease.comment),
        binding.binding_id,
        anchor.anchor.source_id,
        anchor.anchor.source_repository_id,
        binding.pull_request_number,
        binding.pull_request_database_id,
        binding.pull_request_node_id,
        binding.central_repository_node_id,
        binding.branch_ref,
        anchor.anchor.request_class,
    )
    actual = (
        claim.issue_number,
        claim.issue_database_id,
        claim.issue_node_id,
        claim.issue_request_anchor_comment_database_id,
        claim.issue_request_anchor_sha256,
        claim.issue_branch_lease_comment_database_id,
        claim.issue_branch_lease_sha256,
        claim.binding_id,
        claim.source_id,
        claim.source_repository_id,
        claim.pull_request_number,
        claim.pull_request_database_id,
        claim.pull_request_node_id,
        claim.central_repository_node_id,
        claim.branch_ref,
        claim.request_class,
    )
    if actual != expected:
        raise R02Error("IssueHeadClaim does not bind the immutable Issue/lease/binding identities")


def _proposal_tree_evidence(
    client: GitHubClient,
    repository: str,
    base_entries: Iterable[Any],
    target_entries: Iterable[Any],
) -> tuple[tuple[str, ...], tuple[dict[str, Any], ...]]:
    _validate_claimed_regular_tree(base_entries, "accepted proposal base")
    _validate_claimed_regular_tree(target_entries, "proposal target")
    base = _lease_leaf_map(base_entries)
    target = _lease_leaf_map(target_entries)
    changed_paths = tuple(sorted(path for path in set(base) | set(target) if base.get(path) != target.get(path)))
    evidence: list[dict[str, Any]] = []
    for path in changed_paths:
        present = target.get(path)
        if present is None:
            evidence.append({
                "path": path, "state": "ABSENT", "mode": None, "objectType": None,
                "blobSha": None, "contentSha256": None,
            })
            continue
        mode, object_type, blob_sha = present
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise R02Error("claimed proposal target contains a nonregular tree object")
        content = client.get_blob(repository, blob_sha)
        evidence.append({
            "path": path,
            "state": "PRESENT",
            "mode": mode,
            "objectType": object_type,
            "blobSha": blob_sha,
            "contentSha256": hashlib.sha256(content).hexdigest(),
        })
    return changed_paths, tuple(evidence)


def _validate_claimed_regular_tree(entries: Iterable[Any], label: str) -> None:
    leaves: set[str] = set()
    directories: set[str] = set()
    for item in entries:
        if item.object_type == "tree" and item.mode == "040000":
            directories.add(item.path)
        elif item.object_type == "blob" and item.mode in {"100644", "100755"}:
            leaves.add(item.path)
        else:
            raise R02Error(f"{label} contains a nonregular Git object")
    expected_directories = {
        "/".join(path.split("/")[:index])
        for path in leaves
        for index in range(1, len(path.split("/")))
    }
    if directories != expected_directories:
        raise R02Error(f"{label} directory structure does not match its regular file paths")


def _validate_issue_head_claim_target(
    client: GitHubClient,
    repository: str,
    claim: IssueHeadClaim,
    lease: IssueBranchLease,
) -> None:
    marker = _issue_head_claim_marker(claim)
    marker_text = marker.render()
    if parse_claimed_head_marker(marker_text) != marker:
        raise R02Error("IssueHeadClaim marker does not parse canonically")
    if hashlib.sha256(marker_text.encode("utf-8")).hexdigest() != claim.marker_digest:
        raise R02Error("IssueHeadClaim marker digest does not match its stored claim")
    from_meta, from_tree_sha, _from_entries = _lease_tree_snapshot(client, repository, claim.from_head_sha)
    if from_meta.sha != claim.from_head_sha or from_tree_sha != claim.from_tree_sha:
        raise R02Error("IssueHeadClaim from-head tree provenance does not match stored evidence")
    base_meta, accepted_tree_sha, accepted_entries = _lease_tree_snapshot(client, repository, claim.accepted_base_sha)
    if base_meta.sha != claim.accepted_base_sha or accepted_tree_sha != claim.accepted_base_tree_sha:
        raise R02Error("IssueHeadClaim accepted-base tree provenance does not match stored evidence")
    target_meta, target_tree_sha, target_entries = _lease_tree_snapshot(client, repository, claim.to_head_sha)
    if (
        target_meta.sha != claim.to_head_sha
        or target_meta.parents != (claim.from_head_sha,)
        or target_meta.tree_sha != claim.to_tree_sha
        or target_tree_sha != claim.to_tree_sha
    ):
        raise R02Error("IssueHeadClaim target commit parent/tree provenance does not match")
    expected_sha = _expected_deterministic_commit_sha(
        target_tree_sha, claim.from_head_sha, marker_text, target_meta.author_date,
    )
    if expected_sha != claim.to_head_sha:
        raise R02Error("IssueHeadClaim target SHA does not bind its exact deterministic marker")
    if claim.transition_kind == "NORMALIZE":
        if claim.from_head_sha != lease.initial_head_sha:
            raise R02Error("NORMALIZE IssueHeadClaim must wrap the exact leased initial head")
        _validate_claimed_regular_tree(accepted_entries, "NORMALIZE accepted base")
        _validate_claimed_regular_tree(target_entries, "NORMALIZE target")
        request_bytes = (claim.request_class.value + "\n").encode("utf-8")
        expected_blob_sha = hashlib.sha1(
            b"blob " + str(len(request_bytes)).encode("ascii") + b"\0" + request_bytes
        ).hexdigest()
        _validate_marker_only_tree_delta(accepted_entries, target_entries, expected_blob_sha)
        actual_tree = _lease_leaf_map(target_entries)
        expected = _lease_leaf_map(accepted_entries)
        expected[REQUEST_MARKER] = ("100644", "blob", expected_blob_sha)
        if actual_tree != expected:
            raise R02Error("NORMALIZE target tree is not the exact accepted-base marker shell")
        marker_file = client.read_commit_file(repository, claim.to_head_sha, REQUEST_MARKER, expected_mode="100644")
        if marker_file != request_bytes:
            raise R02Error("NORMALIZE .federation-request readback differs from exact request class bytes")
        expected_target = normalize_target_evidence_digest(
            request_class=claim.request_class,
            request_marker_blob_sha=expected_blob_sha,
            target_tree_sha=target_tree_sha,
        )
    else:
        _validate_claimed_regular_tree(target_entries, "IssueHeadClaim proposal target")
        _changed, evidence = _proposal_tree_evidence(client, repository, accepted_entries, target_entries)
        expected_target = proposal_target_evidence_digest(
            candidate_tree_sha=target_tree_sha,
            changed=evidence,
            candidate_changed_paths=_changed,
        )
        if claim.transition_kind in {"PROPOSAL", "PATCH_REGENERATION", "MAIN_ADVANCE"}:
            if REQUEST_MARKER in _lease_leaf_map(target_entries):
                raise R02Error("proposal target must remove the transient request marker")
    if expected_target != claim.target_evidence_digest:
        raise R02Error("IssueHeadClaim target evidence digest does not match the stored target tree")


def _validate_required_status_epoch_binding(
    epoch: RequiredStatusEpoch,
    state: IssuePRBindingState,
) -> None:
    anchor = state.issue_anchor
    lease = state.lease
    binding = state.binding
    expected = (
        anchor.anchor.issue_number, anchor.anchor.issue_database_id, anchor.anchor.issue_node_id,
        anchor.comment.database_id, anchor.anchor.canonical_sha256(),
        lease.comment.database_id, _binding_comment_sha256(lease.comment), binding.binding_id,
        anchor.anchor.source_id, anchor.anchor.source_repository_id,
        binding.pull_request_number, binding.pull_request_database_id, binding.pull_request_node_id,
        binding.central_repository_node_id, binding.branch_ref, anchor.anchor.request_class,
    )
    actual = (
        epoch.issue_number, epoch.issue_database_id, epoch.issue_node_id,
        epoch.issue_request_anchor_comment_database_id, epoch.issue_request_anchor_sha256,
        epoch.issue_branch_lease_comment_database_id, epoch.issue_branch_lease_sha256, epoch.binding_id,
        epoch.source_id, epoch.source_repository_id,
        epoch.pull_request_number, epoch.pull_request_database_id, epoch.pull_request_node_id,
        epoch.central_repository_node_id, epoch.branch_ref, epoch.request_class,
    )
    if actual != expected:
        raise R02Error("RequiredStatusEpoch does not bind immutable Issue/lease/binding identities")


def _validate_issue_finalization_epoch_binding(
    epoch: IssueFinalizationEpoch,
    state: IssuePRBindingState,
) -> None:
    anchor = state.issue_anchor
    lease = state.lease
    binding = state.binding
    expected = (
        anchor.anchor.issue_number, anchor.anchor.issue_database_id, anchor.anchor.issue_node_id,
        anchor.comment.database_id, anchor.anchor.canonical_sha256(),
        lease.comment.database_id, _binding_comment_sha256(lease.comment), binding.binding_id,
        anchor.anchor.source_id, anchor.anchor.source_repository_id,
        binding.pull_request_number, binding.pull_request_database_id, binding.pull_request_node_id,
        binding.central_repository_node_id, binding.branch_ref, anchor.anchor.request_class,
    )
    actual = (
        epoch.issue_number, epoch.issue_database_id, epoch.issue_node_id,
        epoch.issue_request_anchor_comment_database_id, epoch.issue_request_anchor_sha256,
        epoch.issue_branch_lease_comment_database_id, epoch.issue_branch_lease_sha256, epoch.binding_id,
        epoch.source_id, epoch.source_repository_id,
        epoch.pull_request_number, epoch.pull_request_database_id, epoch.pull_request_node_id,
        epoch.central_repository_node_id, epoch.branch_ref, epoch.request_class,
    )
    if actual != expected:
        raise R02Error("IssueFinalizationEpoch does not bind immutable Issue/lease/binding identities")


def _validate_epoch_target_commit(
    client: GitHubClient,
    repository: str,
    *,
    target_sha: str,
    from_head_sha: str,
    from_tree_sha: str,
    target_tree_sha: str,
    accepted_base_sha: str,
    accepted_base_tree_sha: str,
    marker: ClaimedHeadMarker,
    marker_digest: str,
    label: str,
) -> None:
    marker_text = marker.render()
    if parse_claimed_head_marker(marker_text) != marker:
        raise R02Error(f"{label} marker does not parse canonically")
    if hashlib.sha256(marker_text.encode("utf-8")).hexdigest() != marker_digest:
        raise R02Error(f"{label} marker digest does not match immutable artifact")
    from_meta, actual_from_tree, _from_entries = _lease_tree_snapshot(client, repository, from_head_sha)
    if from_meta.sha != from_head_sha or actual_from_tree != from_tree_sha:
        raise R02Error(f"{label} from-head tree provenance does not match")
    base_meta, actual_base_tree, _base_entries = _lease_tree_snapshot(client, repository, accepted_base_sha)
    if base_meta.sha != accepted_base_sha or actual_base_tree != accepted_base_tree_sha:
        raise R02Error(f"{label} accepted-base tree provenance does not match")
    target_meta, actual_target_tree, _target_entries = _lease_tree_snapshot(client, repository, target_sha)
    if (
        target_meta.sha != target_sha
        or target_meta.parents != (from_head_sha,)
        or target_meta.tree_sha != target_tree_sha
        or actual_target_tree != target_tree_sha
        or actual_target_tree != from_tree_sha
    ):
        raise R02Error(f"{label} target is not an exact no-tree-change direct child")
    try:
        target_object = client.get_git_commit_object(repository, target_sha)
    except Exception as error:
        raise R02Error(f"{label} exact target commit object is unavailable: {_bounded_reason(error)}") from None
    if type(target_object) is not GitCommitObject or type(target_object.message) is not str:
        raise R02Error(f"{label} exact target commit object is malformed")
    try:
        parsed_target_marker = parse_claimed_head_marker(target_object.message)
    except RequestModelError as error:
        raise R02Error(f"{label} target marker is malformed: {_bounded_reason(error)}") from None
    if (
        type(target_object) is not GitCommitObject
        or target_object.sha != target_sha
        or target_object.message != marker_text
        or target_object.parents != (from_head_sha,)
        or target_object.tree_sha != target_tree_sha
        or parsed_target_marker != marker
    ):
        raise R02Error(f"{label} exact target commit message/parent/tree is invalid")
    expected_sha = _expected_deterministic_commit_sha(
        target_tree_sha, from_head_sha, marker_text, target_meta.author_date,
    )
    if expected_sha != target_sha:
        raise R02Error(f"{label} target SHA does not bind its canonical marker")


def _validate_required_status_epoch_target(
    client: GitHubClient,
    repository: str,
    epoch: RequiredStatusEpoch,
    state: IssuePRBindingState,
) -> None:
    _validate_required_status_epoch_binding(epoch, state)
    _validate_epoch_target_commit(
        client,
        repository,
        target_sha=epoch.to_head_sha,
        from_head_sha=epoch.from_head_sha,
        from_tree_sha=epoch.from_tree_sha,
        target_tree_sha=epoch.to_tree_sha,
        accepted_base_sha=epoch.accepted_base_sha,
        accepted_base_tree_sha=epoch.accepted_base_tree_sha,
        marker=_required_status_epoch_marker(epoch),
        marker_digest=epoch.marker_digest,
        label="RequiredStatusEpoch",
    )


def _validate_issue_finalization_epoch_target(
    client: GitHubClient,
    repository: str,
    epoch: IssueFinalizationEpoch,
    state: IssuePRBindingState,
) -> None:
    _validate_issue_finalization_epoch_binding(epoch, state)
    if issue_final_status_evidence_digest(epoch) != epoch.required_status_evidence_digest:
        raise R02Error("IssueFinalizationEpoch issue-final evidence digest does not recompute")
    _validate_epoch_target_commit(
        client,
        repository,
        target_sha=epoch.final_head_sha,
        from_head_sha=epoch.from_head_sha,
        from_tree_sha=epoch.from_tree_sha,
        target_tree_sha=epoch.final_tree_sha,
        accepted_base_sha=epoch.accepted_base_sha,
        accepted_base_tree_sha=epoch.accepted_base_tree_sha,
        marker=_issue_finalization_epoch_marker(epoch),
        marker_digest=epoch.marker_digest,
        label="IssueFinalizationEpoch",
    )


def _epoch_comment_authority(comment: IssueComment, app: AppIdentity, label: str) -> None:
    if (
        comment.author_id != app.bot_node_id
        or comment.author_login != app.bot_login
        or comment.author_type not in {None, "Bot"}
        or _issue_comment_edited(comment)
    ):
        raise R02Error(f"{label} comment authorship/edit integrity is invalid")


def _required_status_epoch_comments(
    client: GitHubClient,
    repository: str,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    state: IssuePRBindingState,
    current_ref: str,
) -> tuple[RequiredStatusEpochComment, ...]:
    grouped: dict[str, dict[str, list[tuple[RequiredStatusEpoch, IssueComment]]]] = {}
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(REQUIRED_STATUS_EPOCH_MARKER):
            continue
        try:
            epoch = parse_required_status_epoch(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed RequiredStatusEpoch comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "RequiredStatusEpoch")
        if epoch.prior_required_status is not None and (
            epoch.prior_required_status.creator_database_id != app.bot_id
            or epoch.prior_required_status.creator_node_id != app.bot_node_id
            or epoch.prior_required_status.creator_login != app.bot_login
            or epoch.prior_required_status.creator_type != "Bot"
        ):
            raise R02Error("RequiredStatusEpoch prior status evidence is not from the exact current App Bot")
        _validate_required_status_epoch_target(client, repository, epoch, state)
        grouped.setdefault(epoch.claim_generation_id, {}).setdefault(epoch.render(), []).append((epoch, comment))
    result: list[RequiredStatusEpochComment] = []
    for payloads in grouped.values():
        if len(payloads) != 1:
            raise R02Error("conflicting RequiredStatusEpoch payloads for one generation block resolution")
        equivalent = next(iter(payloads.values()))
        epoch, comment = min(equivalent, key=lambda item: item[1].database_id)
        result.append(RequiredStatusEpochComment(epoch, comment, current_ref == epoch.to_head_sha))
    return tuple(sorted(result, key=lambda item: (item.comment.database_id, item.epoch.claim_generation_id)))


def _issue_finalization_epoch_comments(
    client: GitHubClient,
    repository: str,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    state: IssuePRBindingState,
    current_ref: str,
) -> tuple[IssueFinalizationEpochComment, ...]:
    grouped: dict[str, dict[str, list[tuple[IssueFinalizationEpoch, IssueComment]]]] = {}
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER):
            continue
        try:
            epoch = parse_issue_finalization_epoch(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueFinalizationEpoch comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "IssueFinalizationEpoch")
        _validate_issue_finalization_epoch_target(client, repository, epoch, state)
        grouped.setdefault(epoch.claim_generation_id, {}).setdefault(epoch.render(), []).append((epoch, comment))
    result: list[IssueFinalizationEpochComment] = []
    for payloads in grouped.values():
        if len(payloads) != 1:
            raise R02Error("conflicting IssueFinalizationEpoch payloads for one generation block resolution")
        equivalent = next(iter(payloads.values()))
        epoch, comment = min(equivalent, key=lambda item: item[1].database_id)
        result.append(IssueFinalizationEpochComment(epoch, comment, current_ref == epoch.final_head_sha))
    return tuple(sorted(result, key=lambda item: (item.comment.database_id, item.epoch.claim_generation_id)))


def _issue_cancellation_fence_marker(fence: IssueCancellationFence) -> ClaimedHeadMarker:
    if type(fence) is not IssueCancellationFence:
        raise R02Error("IssueCancellationFence marker requires its exact parsed artifact")
    return ClaimedHeadMarker(
        "ISSUE_CANCELLATION_FENCE",
        "ISSUE_CANCEL",
        "ISSUE",
        issue_owner_key(
            fence.central_repository_node_id,
            fence.issue_database_id,
            fence.issue_node_id,
            fence.issue_number,
        ),
        fence.claim_generation_id,
        fence.cancellation_carrier_nonce,
        "TERMINAL_CANCELLATION",
    )


def _validate_issue_cancellation_fence_target(
    client: GitHubClient,
    repository: str,
    fence: IssueCancellationFence,
) -> None:
    marker = _issue_cancellation_fence_marker(fence)
    marker_text = marker.render()
    if parse_claimed_head_marker(marker_text) != marker:
        raise R02Error("IssueCancellationFence marker does not parse canonically")
    if hashlib.sha256(marker_text.encode("utf-8")).hexdigest() != fence.marker_digest:
        raise R02Error("IssueCancellationFence marker digest does not match")
    original, original_tree, _original_entries = _lease_tree_snapshot(
        client, repository, fence.original_head_sha,
    )
    if original.sha != fence.original_head_sha or original_tree != fence.original_head_tree_sha:
        raise R02Error("IssueCancellationFence original head/tree identity is invalid")
    target, target_tree, _target_entries = _lease_tree_snapshot(
        client, repository, fence.cancellation_head_sha,
    )
    if (
        target.sha != fence.cancellation_head_sha
        or target.parents != (fence.original_head_sha,)
        or target.tree_sha != fence.original_head_tree_sha
        or target_tree != fence.original_head_tree_sha
        or fence.cancellation_head_tree_sha != fence.original_head_tree_sha
    ):
        raise R02Error("IssueCancellationFence target is not an exact direct no-tree-change child")
    try:
        commit = client.get_git_commit_object(repository, fence.cancellation_head_sha)
    except Exception as error:
        raise R02Error(f"IssueCancellationFence exact target commit is unavailable: {_bounded_reason(error)}") from None
    if type(commit) is not GitCommitObject or (
        commit.sha != fence.cancellation_head_sha
        or commit.message != marker_text
        or commit.tree_sha != fence.original_head_tree_sha
        or commit.parents != (fence.original_head_sha,)
        or commit.author.name != "Swift Stream Federation"
        or commit.author.email != "automation@swiftstream.invalid"
        or commit.committer.name != "Swift Stream Federation"
        or commit.committer.email != "automation@swiftstream.invalid"
        or commit.author.date != commit.committer.date
    ):
        raise R02Error("IssueCancellationFence exact target marker/identity is invalid")
    try:
        parsed_marker = parse_claimed_head_marker(commit.message)
    except RequestModelError as error:
        raise R02Error(f"IssueCancellationFence target marker is malformed: {_bounded_reason(error)}") from None
    if parsed_marker != marker or _expected_deterministic_commit_sha(
        commit.tree_sha, fence.original_head_sha, marker_text, commit.author.date,
    ) != fence.cancellation_head_sha:
        raise R02Error("IssueCancellationFence target SHA does not bind its exact marker and Bot identity")


def _validate_issue_cancellation_fence_context(
    fence: IssueCancellationFence,
    authority: _IssueCancellationAuthority,
) -> None:
    anchor = authority.issue_anchor
    lease = authority.lease
    expected = (
        anchor.anchor.issue_number,
        anchor.anchor.issue_database_id,
        anchor.anchor.issue_node_id,
        anchor.comment.database_id,
        anchor.anchor.canonical_sha256(),
        lease.comment.database_id,
        _binding_comment_sha256(lease.comment),
        _cancellation_binding_authority_id(authority),
        anchor.anchor.source_id,
        anchor.anchor.source_repository_id,
        lease.lease.branch_ref,
        authority.pull_request_number,
        authority.pull_request_database_id,
        authority.pull_request_node_id,
        authority.central_repository_node_id,
        authority.base_repository_node_id,
        "main",
    )
    actual = (
        fence.issue_number,
        fence.issue_database_id,
        fence.issue_node_id,
        fence.issue_request_anchor_comment_database_id,
        fence.issue_request_anchor_sha256,
        fence.issue_branch_lease_comment_database_id,
        fence.issue_branch_lease_sha256,
        fence.binding_authority,
        fence.source_id,
        fence.source_repository_id,
        fence.branch_ref,
        fence.pull_request_number,
        fence.pull_request_database_id,
        fence.pull_request_node_id,
        fence.central_repository_node_id,
        fence.base_repository_node_id,
        fence.base_ref,
    )
    if actual != expected:
        raise R02Error("IssueCancellationFence does not match exact central Issue/lease/PR-as-Issue identity")
    if (
        authority.pr.number != authority.pull_request_number
        or authority.pr_issue.number != authority.pull_request_number
        or authority.pr_issue.database_id != authority.pull_request_database_id
        or authority.pr_issue.node_id != authority.pull_request_node_id
    ):
        raise R02Error("IssueCancellationFence PR node/database/number cross-check failed")
    if authority.binding_authority == "FULL_BINDING":
        binding = authority.binding
        state = authority.binding_state
        if binding is None or state is None or state.binding != binding:
            raise R02Error("FULL_BINDING cancellation authority requires the exact persisted two-sided binding")
        if (
            binding.pull_request_number != authority.pull_request_number
            or binding.pull_request_database_id != authority.pull_request_database_id
            or binding.pull_request_node_id != authority.pull_request_node_id
        ):
            raise R02Error("FULL_BINDING does not cross-check the exact PR-as-Issue identity triple")
    elif authority.binding_authority == "PRE_BINDING":
        if authority.binding is not None or authority.binding_state is not None:
            raise R02Error("PRE_BINDING cancellation authority must not fabricate an IssuePRBinding")
    else:
        raise R02Error("IssueCancellationFence binding authority is unsupported")


def _require_exact_cancellation_stage_receipt_identity(
    receipt: PullRequestStageMutationReceipt,
    authority: _IssueCancellationAuthority,
    fence: IssueCancellationFence,
) -> PullRequestStageMutationReceipt:
    if type(receipt) is not PullRequestStageMutationReceipt:
        raise R02Error("cancellation stage authority requires an exact PR-stage mutation receipt")
    expected = (
        authority.pull_request_node_id,
        authority.pull_request_database_id,
        authority.pull_request_number,
    )
    actual = (
        receipt.pull_request_node_id,
        receipt.pull_request_database_id,
        receipt.pull_request_number,
    )
    fence_identity = (
        fence.pull_request_node_id,
        fence.pull_request_database_id,
        fence.pull_request_number,
    )
    if actual != expected or expected != fence_identity:
        raise R02Error("stage mutation receipt PR node/database/number differs from exact PR-as-Issue and fence")
    return receipt


def _issue_cancellation_fence_comments(
    client: GitHubClient,
    repository: str,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    authority: _IssueCancellationAuthority,
    current_ref: str,
) -> tuple[IssueCancellationFenceComment, ...]:
    grouped: dict[str, list[tuple[IssueCancellationFence, IssueComment]]] = {}
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_CANCELLATION_FENCE_MARKER):
            continue
        try:
            fence = parse_issue_cancellation_fence(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueCancellationFence comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "IssueCancellationFence")
        _validate_issue_cancellation_fence_context(fence, authority)
        if fence.binding_authority == "PRE_BINDING":
            lease = authority.lease.lease
            if (
                fence.original_head_claim_kind != "ISSUE_BRANCH_LEASE"
                or fence.original_head_claim_role != CarrierRole.ISSUE_ACTIVE.value
                or fence.original_head_sha != lease.initial_head_sha
                or fence.original_head_tree_sha != lease.initial_head_tree_sha
                or fence.original_head_artifact_comment_database_id != authority.lease.comment.database_id
                or fence.original_head_artifact_id != lease.lease_id
                or fence.original_head_artifact_sha256 != _binding_comment_sha256(authority.lease.comment)
            ):
                raise R02Error("PRE_BINDING IssueCancellationFence must use the exact active lease-root predecessor")
        _validate_issue_cancellation_fence_target(client, repository, fence)
        grouped.setdefault(fence.fence_id, []).append((fence, comment))
    if len(grouped) > 1:
        raise R02Error("conflicting IssueCancellationFence payloads exist for one request attempt")
    result: list[IssueCancellationFenceComment] = []
    for equivalent in grouped.values():
        renders = {item.render() for item, _comment in equivalent}
        if len(renders) != 1:
            raise R02Error("IssueCancellationFence ID collision has non-identical payloads")
        fence, comment = min(equivalent, key=lambda item: item[1].database_id)
        result.append(IssueCancellationFenceComment(
            fence, comment, current_ref == fence.cancellation_head_sha,
        ))
    return tuple(result)


_CANCELLATION_STAGE_SPECS: Mapping[str, tuple[str, PullRequestStageMutationOperation]] = {
    "DRAFT_REOPEN": ("reopen_pull_request", PullRequestStageMutationOperation.REOPEN),
    "DRAFT_READY": ("mark_pull_request_ready_for_review", PullRequestStageMutationOperation.READY_FOR_REVIEW),
    "DRAFT_CONVERT": ("convert_pull_request_to_draft", PullRequestStageMutationOperation.CONVERT_TO_DRAFT),
    "CLOSE_REOPEN": ("reopen_pull_request", PullRequestStageMutationOperation.REOPEN),
    "TERMINAL_CLOSE": ("close_pull_request", PullRequestStageMutationOperation.CLOSE),
}


def _cancellation_stage_client_mutation_id(fence: IssueCancellationFence, stage: str) -> str:
    if stage not in _CANCELLATION_STAGE_SPECS:
        raise R02Error("cancellation PR mutation stage is unsupported")
    operation = _CANCELLATION_STAGE_SPECS[stage][1].value
    payload = {
        "cancellationHeadSha": fence.cancellation_head_sha,
        "fenceId": fence.fence_id,
        "operation": operation,
        "pullRequestNodeId": fence.pull_request_node_id,
        "stage": stage,
    }
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(
        ("swiftstream-federation:cancellation-pr-stage-mutation:v1\n" + encoded).encode("ascii"),
    ).hexdigest()
    client_mutation_id = f"g8w07-{digest}"
    if len(client_mutation_id.encode("ascii")) > 256:
        raise R02Error("deterministic cancellation clientMutationId exceeds the bounded transport limit")
    return client_mutation_id


def _exact_cancellation_stage_evidence(
    receipt: PullRequestStageMutationReceipt,
    authority: _IssueCancellationAuthority,
    fence: IssueCancellationFence,
    stage: str,
) -> ExactPullRequestStageMutationEvidence:
    try:
        _method_name, operation = _CANCELLATION_STAGE_SPECS[stage]
    except KeyError:
        raise R02Error("cancellation PR mutation stage is unsupported") from None
    _require_exact_cancellation_stage_receipt_identity(receipt, authority, fence)
    expected_id = _cancellation_stage_client_mutation_id(fence, stage)
    if (
        receipt.operation != operation.value
        or receipt.requested_pull_request_node_id != fence.pull_request_node_id
        or receipt.requested_client_mutation_id != expected_id
        or receipt.returned_client_mutation_id != expected_id
    ):
        raise R02Error("same-response PR-stage receipt operation or clientMutationId differs from the exact logical stage")
    try:
        evidence = ExactPullRequestStageMutationEvidence(
            operation=operation,
            client_mutation_id=receipt.returned_client_mutation_id,
            pull_request_node_id=receipt.pull_request_node_id,
            pull_request_database_id=receipt.pull_request_database_id,
            pull_request_number=receipt.pull_request_number,
            state=receipt.state,
            is_draft=receipt.is_draft,
            merged=receipt.merged,
            merged_at=receipt.merged_at,
            head_ref_oid=receipt.head_oid,
            base_ref_oid=receipt.base_oid,
            head_ref_name=receipt.head_ref,
            base_ref_name=receipt.base_ref,
            head_repository_node_id=receipt.head_repository_node_id,
            base_repository_node_id=receipt.base_repository_node_id,
        )
    except RequestModelError as error:
        raise R02Error(f"same-response PR-stage evidence is invalid: {_bounded_reason(error)}") from None
    expected_state = "CLOSED" if operation is PullRequestStageMutationOperation.CLOSE else "OPEN"
    expected_draft = {
        "DRAFT_READY": False,
        "DRAFT_CONVERT": True,
    }.get(stage)
    if (
        evidence.pull_request_node_id != authority.pull_request_node_id
        or evidence.pull_request_database_id != authority.pull_request_database_id
        or evidence.pull_request_number != authority.pull_request_number
        or evidence.pull_request_node_id != fence.pull_request_node_id
        or evidence.pull_request_database_id != fence.pull_request_database_id
        or evidence.pull_request_number != fence.pull_request_number
        or evidence.head_ref_oid != fence.cancellation_head_sha
        or evidence.head_ref_name != fence.branch_ref.removeprefix("refs/heads/")
        or evidence.base_ref_name != "main"
        or evidence.head_repository_node_id != fence.central_repository_node_id
        or evidence.base_repository_node_id != fence.base_repository_node_id
        or evidence.state != expected_state
        or (expected_draft is not None and evidence.is_draft is not expected_draft)
        or evidence.merged
        or evidence.merged_at is not None
    ):
        raise R02Error("same-response PR-stage evidence differs from exact cancellation PR/HC/base authority")
    return evidence


def _cancellation_witness_expected_fields(
    authority: _IssueCancellationAuthority,
    fence_item: IssueCancellationFenceComment,
    status: ExactAppRequiredStatusSnapshot,
) -> dict[str, Any]:
    anchor = authority.issue_anchor
    lease = authority.lease
    fence = fence_item.fence
    return {
        "issue_number": anchor.anchor.issue_number,
        "issue_database_id": anchor.anchor.issue_database_id,
        "issue_node_id": anchor.anchor.issue_node_id,
        "issue_request_anchor_comment_database_id": anchor.comment.database_id,
        "issue_request_anchor_sha256": anchor.anchor.canonical_sha256(),
        "issue_branch_lease_comment_database_id": lease.comment.database_id,
        "issue_branch_lease_sha256": _binding_comment_sha256(lease.comment),
        "fence_comment_database_id": fence_item.comment.database_id,
        "fence_sha256": _binding_comment_sha256(fence_item.comment),
        "fence_id": fence.fence_id,
        "binding_authority": _cancellation_binding_authority_id(authority),
        "source_id": anchor.anchor.source_id,
        "source_repository_id": anchor.anchor.source_repository_id,
        "branch_ref": lease.lease.branch_ref,
        "pull_request_number": authority.pull_request_number,
        "pull_request_database_id": authority.pull_request_database_id,
        "pull_request_node_id": authority.pull_request_node_id,
        "original_head_sha": fence.original_head_sha,
        "cancellation_head_sha": fence.cancellation_head_sha,
        "anchored_accepted_base_sha": lease.lease.accepted_base_sha,
        "base_repository_node_id": fence.base_repository_node_id,
        "base_ref": "main",
        "head_repository_node_id": fence.central_repository_node_id,
        "current_required_status": status,
    }


def _validate_cancellation_witness_stage_ids(
    witness: IssueCancellationDraftWitness,
    fence: IssueCancellationFence,
) -> None:
    stages = (
        (witness.reopen_evidence, "DRAFT_REOPEN"),
        (witness.ready_evidence, "DRAFT_READY"),
        (witness.draft_evidence, "DRAFT_CONVERT"),
    )
    for evidence, stage in stages:
        if evidence is not None and evidence.client_mutation_id != _cancellation_stage_client_mutation_id(fence, stage):
            raise R02Error("draft witness contains a noncanonical cancellation clientMutationId")


def _issue_cancellation_draft_witness_comments(
    comments: Iterable[IssueComment],
    app: AppIdentity,
    authority: _IssueCancellationAuthority,
    fence_item: IssueCancellationFenceComment,
    status: ExactAppRequiredStatusSnapshot,
) -> tuple[IssueCancellationDraftWitnessComment, ...]:
    grouped: dict[str, list[tuple[IssueCancellationDraftWitness, IssueComment]]] = {}
    expected = _cancellation_witness_expected_fields(authority, fence_item, status)
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER):
            continue
        try:
            witness = parse_issue_cancellation_draft_witness(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueCancellationDraftWitness comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "IssueCancellationDraftWitness")
        if any(getattr(witness, name) != value for name, value in expected.items()):
            raise R02Error("IssueCancellationDraftWitness does not match exact anchor/lease/fence/PR/status authority")
        _validate_cancellation_witness_stage_ids(witness, fence_item.fence)
        grouped.setdefault(witness.witness_id, []).append((witness, comment))
    if len(grouped) > 1:
        raise R02Error("conflicting IssueCancellationDraftWitness payloads exist")
    result: list[IssueCancellationDraftWitnessComment] = []
    for equivalent in grouped.values():
        if len({item.render() for item, _comment in equivalent}) != 1:
            raise R02Error("IssueCancellationDraftWitness ID collision has non-identical payloads")
        witness, comment = min(equivalent, key=lambda item: item[1].database_id)
        result.append(IssueCancellationDraftWitnessComment(witness, comment))
    return tuple(result)


def _cancellation_terminal_result_expected_fields(
    authority: _IssueCancellationAuthority,
    fence_item: IssueCancellationFenceComment,
    witness_item: IssueCancellationDraftWitnessComment,
    status: ExactAppRequiredStatusSnapshot,
) -> dict[str, Any]:
    anchor = authority.issue_anchor
    lease = authority.lease
    fence = fence_item.fence
    return {
        "issue_number": anchor.anchor.issue_number,
        "issue_database_id": anchor.anchor.issue_database_id,
        "issue_node_id": anchor.anchor.issue_node_id,
        "issue_request_anchor_comment_database_id": anchor.comment.database_id,
        "issue_request_anchor_sha256": anchor.anchor.canonical_sha256(),
        "issue_branch_lease_comment_database_id": lease.comment.database_id,
        "issue_branch_lease_sha256": _binding_comment_sha256(lease.comment),
        "binding_authority": _cancellation_binding_authority_id(authority),
        "source_id": anchor.anchor.source_id,
        "source_repository_id": anchor.anchor.source_repository_id,
        "branch_ref": lease.lease.branch_ref,
        "pull_request_number": authority.pull_request_number,
        "pull_request_database_id": authority.pull_request_database_id,
        "pull_request_node_id": authority.pull_request_node_id,
        "original_head_sha": fence.original_head_sha,
        "cancellation_head_sha": fence.cancellation_head_sha,
        "base_repository_node_id": fence.base_repository_node_id,
        "base_ref": "main",
        "fence_comment_database_id": fence_item.comment.database_id,
        "fence_sha256": _binding_comment_sha256(fence_item.comment),
        "fence_id": fence.fence_id,
        "draft_witness_comment_database_id": witness_item.comment.database_id,
        "draft_witness_sha256": _binding_comment_sha256(witness_item.comment),
        "witness_id": witness_item.witness.witness_id,
        "current_failure_status": status,
    }


def _issue_terminal_cancelled_result_comments(
    comments: Iterable[IssueComment],
    app: AppIdentity,
    authority: _IssueCancellationAuthority,
    fence_item: IssueCancellationFenceComment,
    witness_item: IssueCancellationDraftWitnessComment,
    status: ExactAppRequiredStatusSnapshot,
) -> tuple[IssueTerminalCancelledResultComment, ...]:
    grouped: dict[str, list[tuple[IssueTerminalCancelledResult, IssueComment]]] = {}
    expected = _cancellation_terminal_result_expected_fields(authority, fence_item, witness_item, status)
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_TERMINAL_CANCELLED_RESULT_MARKER):
            continue
        try:
            result = parse_issue_terminal_cancelled_result(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueTerminalCancelledResult comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "IssueTerminalCancelledResult")
        if any(getattr(result, name) != value for name, value in expected.items()):
            raise R02Error("IssueTerminalCancelledResult does not match exact fence/witness/status/PR authority")
        if (
            result.close_evidence.head_repository_node_id != fence_item.fence.central_repository_node_id
            or result.close_evidence.base_repository_node_id != fence_item.fence.base_repository_node_id
            or result.close_evidence.head_ref_name != fence_item.fence.branch_ref.removeprefix("refs/heads/")
            or result.close_evidence.base_ref_name != "main"
            or result.close_evidence.client_mutation_id != _cancellation_stage_client_mutation_id(
                fence_item.fence, "TERMINAL_CLOSE",
            )
        ):
            raise R02Error("terminal close evidence does not bind exact same-response PR stage authority")
        grouped.setdefault(result.terminal_result_id, []).append((result, comment))
    if len(grouped) > 1:
        raise R02Error("conflicting IssueTerminalCancelledResult payloads exist")
    result_items: list[IssueTerminalCancelledResultComment] = []
    for equivalent in grouped.values():
        if len({item.render() for item, _comment in equivalent}) != 1:
            raise R02Error("IssueTerminalCancelledResult ID collision has non-identical payloads")
        result, comment = min(equivalent, key=lambda item: item[1].database_id)
        result_items.append(IssueTerminalCancelledResultComment(result, comment))
    return tuple(result_items)


def _issue_no_pr_cancelled_result_comments(
    comments: Iterable[IssueComment],
    app: AppIdentity,
    anchor: IssueAnchorComment,
    lease: IssueBranchLeaseComment | None,
) -> tuple[IssueNoPRCancelledResultComment, ...]:
    grouped: dict[str, list[tuple[IssueNoPRCancelledResult, IssueComment]]] = {}
    for comment in comments:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_NO_PR_CANCELLED_RESULT_MARKER):
            continue
        try:
            result = parse_issue_no_pr_cancelled_result(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueNoPRCancelledResult comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "IssueNoPRCancelledResult")
        identity_matches = (
            result.issue_number == anchor.anchor.issue_number
            and result.issue_database_id == anchor.anchor.issue_database_id
            and result.issue_node_id == anchor.anchor.issue_node_id
            and result.issue_request_anchor_comment_database_id == anchor.comment.database_id
            and result.issue_request_anchor_sha256 == anchor.anchor.canonical_sha256()
            and result.source_id == anchor.anchor.source_id
            and result.source_repository_id == anchor.anchor.source_repository_id
        )
        if not identity_matches:
            raise R02Error("IssueNoPRCancelledResult does not match exact immutable IssueRequestAnchor")
        if lease is None:
            if result.proof_kind is not IssueNoPRCancelledProofKind.ANCHOR_ONLY:
                raise R02Error("lease-backed no-PR result exists without its exact IssueBranchLease")
        else:
            if (
                result.proof_kind is IssueNoPRCancelledProofKind.ANCHOR_ONLY
                or result.lease_comment_database_id != lease.comment.database_id
                or result.lease_sha256 != _binding_comment_sha256(lease.comment)
                or result.lease_id != lease.lease.lease_id
                or result.branch_ref != lease.lease.branch_ref
                or result.lease_initial_head_sha != lease.lease.initial_head_sha
            ):
                raise R02Error("lease-backed no-PR result does not match exact immutable IssueBranchLease")
        grouped.setdefault(result.no_pr_result_id, []).append((result, comment))
    if len(grouped) > 1:
        raise R02Error("conflicting immutable IssueNoPRCancelledResult payloads exist")
    result_items: list[IssueNoPRCancelledResultComment] = []
    for equivalent in grouped.values():
        if len({item.render() for item, _comment in equivalent}) != 1:
            raise R02Error("IssueNoPRCancelledResult ID collision has non-identical payloads")
        result, comment = min(equivalent, key=lambda item: item[1].database_id)
        result_items.append(IssueNoPRCancelledResultComment(result, comment))
    return tuple(result_items)


def _issue_cancellation_fence_predecessor_matches(
    node: _IssueAuthorityNode,
    fence: IssueCancellationFence,
) -> bool:
    return (
        fence.original_head_claim_kind == node.claim_kind
        and fence.original_head_claim_role == node.role.value
        and fence.original_head_sha == node.target_head_sha
        and fence.original_head_tree_sha == node.tree_sha
        and fence.original_head_artifact_comment_database_id == node.comment.database_id
        and fence.original_head_artifact_id == node.artifact_id
        and fence.original_head_artifact_sha256 == node.artifact_sha256
    )


def _resolve_issue_cancellation_original_node(
    client: GitHubClient,
    repository: str,
    authority: _IssueCancellationAuthority,
    app: AppIdentity,
    original_head_sha: str,
) -> _IssueAuthorityNode:
    if authority.binding_authority == "PRE_BINDING":
        lease = authority.lease.lease
        if original_head_sha != lease.initial_head_sha:
            raise R02Error("PRE_BINDING cancellation predecessor must be the exact lease root")
        marker = _lease_marker_for(lease)
        resolution = resolve_sha_carrier_role(
            client, repository, original_head_sha, app.slug, LegacyEvidenceDisposition.CONFLICTING,
        )
        if (
            resolution.role is not CarrierRole.ISSUE_ACTIVE
            or resolution.marker != marker
            or resolution.activation is not CarrierActivation.ACTIVE
        ):
            raise R02Error("PRE_BINDING lease-root predecessor is not the exact current ISSUE_ACTIVE carrier")
        return _IssueAuthorityNode(
            "ISSUE_BRANCH_LEASE", CarrierRole.ISSUE_ACTIVE, lease.initial_head_sha, None,
            lease.initial_head_tree_sha, "INITIAL", lease.lease_id,
            _binding_comment_sha256(authority.lease.comment), authority.lease.comment,
            lease, active=True,
        )
    state = authority.binding_state
    if state is None:
        raise R02Error("FULL_BINDING cancellation predecessor requires the exact persisted IssuePRBinding")
    comments = tuple(client.list_issue_comments(repository, authority.pull_request_number))
    current_ref = _read_issue_branch_ref(
        client, repository, authority.lease.lease.branch_ref.removeprefix("refs/heads/"),
    )
    if current_ref != original_head_sha or authority.pr.head_oid != original_head_sha:
        raise StaleAuthorityError("FULL_BINDING cancellation predecessor is not the exact current ref/PR head")
    history = _issue_authority_history(client, repository, comments, app, state, current_ref)
    matches = tuple(node for node in history if node.target_head_sha == original_head_sha)
    if len(matches) != 1:
        raise R02Error("FULL_BINDING cancellation has no unique real unified-history predecessor")
    node = matches[0]
    if (node.claim_kind, node.role) not in {
        ("ISSUE_HEAD_CLAIM", CarrierRole.ISSUE_ACTIVE),
        ("REQUIRED_STATUS_EPOCH", CarrierRole.ISSUE_ACTIVE),
        ("ISSUE_FINALIZATION_EPOCH", CarrierRole.ISSUE_FINALIZING),
        ("ISSUE_BRANCH_LEASE", CarrierRole.ISSUE_ACTIVE),
    }:
        raise R02Error("FULL_BINDING cancellation predecessor kind/role is unsupported")
    return node


def _issue_authority_history(
    client: GitHubClient,
    repository: str,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    state: IssuePRBindingState,
    current_ref: str,
) -> tuple[_IssueAuthorityNode, ...]:
    """Validate all Issue-owned claim/epoch nodes, then resolve one unified provenance graph."""
    comment_list = tuple(comments)
    claim_groups: dict[str, dict[str, list[tuple[IssueHeadClaim, IssueComment]]]] = {}
    for comment in comment_list:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_HEAD_CLAIM_MARKER):
            continue
        try:
            claim = parse_issue_head_claim(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssueHeadClaim comment: {_bounded_reason(error)}") from None
        _epoch_comment_authority(comment, app, "IssueHeadClaim")
        _issue_head_claim_matches_binding(claim, state)
        _validate_issue_head_claim_target(client, repository, claim, state.lease.lease)
        claim_groups.setdefault(claim.claim_generation_id, {}).setdefault(claim.render(), []).append((claim, comment))
    claims: list[IssueHeadClaimComment] = []
    for payloads in claim_groups.values():
        if len(payloads) != 1:
            raise R02Error("conflicting IssueHeadClaim payloads for one generation block progression")
        equivalent = next(iter(payloads.values()))
        claim, comment = min(equivalent, key=lambda item: item[1].database_id)
        claims.append(IssueHeadClaimComment(claim, comment, current_ref == claim.to_head_sha))
    required_epochs = _required_status_epoch_comments(client, repository, comment_list, app, state, current_ref)
    finalization_epochs = _issue_finalization_epoch_comments(client, repository, comment_list, app, state, current_ref)
    cancellation_authority = _IssueCancellationAuthority(
        issue_anchor=state.issue_anchor,
        lease=state.lease,
        binding_authority="FULL_BINDING",
        pull_request_number=state.binding.pull_request_number,
        pull_request_database_id=state.binding.pull_request_database_id,
        pull_request_node_id=state.binding.pull_request_node_id,
        central_repository_node_id=state.binding.central_repository_node_id,
        base_repository_node_id=state.binding.central_repository_node_id,
        pr=state.pr,
        pr_issue=state.pr_issue,
        owning_issue=state.owning_issue,
        pr_comments=comment_list,
        binding=state.binding,
        binding_state=state,
        raw_pr_state="OPEN",
        raw_pr_merged=False,
    )
    cancellation_fences = _issue_cancellation_fence_comments(
        client, repository, comment_list, app, cancellation_authority, current_ref,
    )

    lease = state.lease.lease
    root = _IssueAuthorityNode(
        "ISSUE_BRANCH_LEASE", CarrierRole.ISSUE_ACTIVE, lease.initial_head_sha, None,
        lease.initial_head_tree_sha, "INITIAL", lease.lease_id,
        _binding_comment_sha256(state.lease.comment), state.lease.comment, lease,
        active=current_ref == lease.initial_head_sha,
    )
    nodes: list[_IssueAuthorityNode] = [root]
    for item in claims:
        claim = item.claim
        nodes.append(_IssueAuthorityNode(
            claim.claim_kind, CarrierRole.ISSUE_ACTIVE, claim.to_head_sha, claim.from_head_sha,
            claim.to_tree_sha, claim.transition_kind, claim.claim_id,
            _binding_comment_sha256(item.comment), item.comment, claim, active=item.active,
        ))
    for item in required_epochs:
        epoch = item.epoch
        nodes.append(_IssueAuthorityNode(
            epoch.claim_kind, CarrierRole.ISSUE_ACTIVE, epoch.to_head_sha, epoch.from_head_sha,
            epoch.to_tree_sha, epoch.transition_kind, epoch.epoch_id,
            _binding_comment_sha256(item.comment), item.comment, epoch, active=item.active,
        ))
    for item in finalization_epochs:
        epoch = item.epoch
        nodes.append(_IssueAuthorityNode(
            epoch.claim_kind, CarrierRole.ISSUE_FINALIZING, epoch.final_head_sha, epoch.from_head_sha,
            epoch.final_tree_sha, epoch.transition_kind, epoch.epoch_id,
            _binding_comment_sha256(item.comment), item.comment, epoch, active=item.active,
        ))
    for item in cancellation_fences:
        fence = item.fence
        nodes.append(_IssueAuthorityNode(
            "ISSUE_CANCELLATION_FENCE", CarrierRole.ISSUE_CANCEL,
            fence.cancellation_head_sha, fence.original_head_sha,
            fence.cancellation_head_tree_sha, fence.transition_kind, fence.fence_id,
            _binding_comment_sha256(item.comment), item.comment, fence, active=item.active,
        ))

    by_target: dict[str, _IssueAuthorityNode] = {}
    for node in nodes:
        old = by_target.get(node.target_head_sha)
        if old is not None and (
            old.claim_kind != node.claim_kind
            or old.role is not node.role
            or old.artifact_id != node.artifact_id
            or old.artifact_sha256 != node.artifact_sha256
        ):
            raise R02Error("conflicting Issue-owned role/provenance for one claimed SHA")
        by_target[node.target_head_sha] = node

    reachable: dict[str, _IssueAuthorityNode] = {root.target_head_sha: root}
    unresolved = [node for node in nodes if node is not root]
    while unresolved:
        advanced = False
        remaining: list[_IssueAuthorityNode] = []
        for node in unresolved:
            parent = reachable.get(node.from_head_sha or "")
            if parent is None:
                remaining.append(node)
                continue
            if parent.claim_kind == "ISSUE_CANCELLATION_FENCE":
                raise R02Error("IssueCancellationFence is terminal and cannot have Issue authority descendants")
            if node.claim_kind == "ISSUE_HEAD_CLAIM":
                claim = node.artifact
                if parent.role is not CarrierRole.ISSUE_ACTIVE or parent.claim_kind == "ISSUE_FINALIZATION_EPOCH":
                    raise R02Error("IssueHeadClaim cannot descend directly from ISSUE_FINALIZING")
                if claim.transition_kind == "NORMALIZE":
                    if parent.claim_kind != "ISSUE_BRANCH_LEASE" or claim.from_head_sha != lease.initial_head_sha:
                        raise R02Error("NORMALIZE IssueHeadClaim must descend directly from the leased root")
                    origin = None
                elif claim.transition_kind in {"PROPOSAL", "PATCH_REGENERATION", "MAIN_ADVANCE"}:
                    if parent.claim_kind not in {
                        "ISSUE_BRANCH_LEASE", "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH",
                    }:
                        raise R02Error("proposal IssueHeadClaim has an unsupported ISSUE_ACTIVE predecessor")
                    origin = node
                else:
                    raise R02Error("IssueHeadClaim history has an unsupported transition kind")
            elif node.claim_kind == "REQUIRED_STATUS_EPOCH":
                epoch = node.artifact
                if (
                    epoch.from_provenance_kind != parent.claim_kind
                    or epoch.from_provenance_id != parent.artifact_id
                    or epoch.from_provenance_sha256 != parent.artifact_sha256
                    or epoch.from_carrier_role != parent.role.value
                ):
                    raise R02Error("RequiredStatusEpoch exact predecessor provenance does not match unified history")
                if epoch.reason_class is RequiredStatusEpochReason.FINALIZATION_INVALIDATED:
                    if parent.claim_kind != "ISSUE_FINALIZATION_EPOCH" or parent.role is not CarrierRole.ISSUE_FINALIZING:
                        raise R02Error("FINALIZATION_INVALIDATED must descend from exact ISSUE_FINALIZING provenance")
                elif parent.role is not CarrierRole.ISSUE_ACTIVE:
                    raise R02Error("non-finalization RequiredStatusEpoch must descend from ISSUE_ACTIVE")
                origin = parent.proposal_origin
            elif node.claim_kind == "ISSUE_FINALIZATION_EPOCH":
                epoch = node.artifact
                if parent.role is not CarrierRole.ISSUE_ACTIVE or parent.claim_kind not in {
                    "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH",
                }:
                    raise R02Error("IssueFinalizationEpoch must descend from exact ISSUE_ACTIVE claim/epoch authority")
                if (
                    epoch.from_authority_kind != parent.claim_kind
                    or epoch.from_authority_comment_database_id != parent.comment.database_id
                    or epoch.from_authority_artifact_id != parent.artifact_id
                    or epoch.from_authority_artifact_sha256 != parent.artifact_sha256
                    or epoch.from_authority_role != parent.role.value
                ):
                    raise R02Error("IssueFinalizationEpoch immediate authority identity/hash/comment mismatch")
                if parent.claim_kind == "ISSUE_HEAD_CLAIM":
                    origin = parent if parent.transition_kind in {"PROPOSAL", "PATCH_REGENERATION", "MAIN_ADVANCE"} else None
                else:
                    origin = parent.proposal_origin
                if origin is None or type(origin.artifact) is not IssueHeadClaim:
                    raise R02Error("IssueFinalizationEpoch ancestry has no proposal-bearing IssueHeadClaim origin")
                if origin.artifact.transition_kind == "NORMALIZE":
                    raise R02Error("IssueFinalizationEpoch proposal origin cannot be NORMALIZE")
                if (
                    epoch.proposal_origin_claim_comment_database_id != origin.comment.database_id
                    or epoch.proposal_origin_claim_id != origin.artifact.claim_id
                    or epoch.proposal_origin_claim_sha256 != _binding_comment_sha256(origin.comment)
                    or epoch.claimed_target_evidence_digest != origin.artifact.target_evidence_digest
                    or epoch.fresh_proposal_scope_evidence_digest != origin.artifact.target_evidence_digest
                ):
                    raise R02Error("IssueFinalizationEpoch proposal-origin/scope evidence mismatch")
            elif node.claim_kind == "ISSUE_CANCELLATION_FENCE":
                fence = node.artifact
                if parent.role not in {CarrierRole.ISSUE_ACTIVE, CarrierRole.ISSUE_FINALIZING} or parent.claim_kind not in {
                    "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH", "ISSUE_FINALIZATION_EPOCH", "ISSUE_BRANCH_LEASE",
                }:
                    raise R02Error("IssueCancellationFence predecessor is not an allowed active/finalizing authority")
                if fence.binding_authority != state.binding.binding_id:
                    raise R02Error("PRE_BINDING IssueCancellationFence cannot enter full-binding unified history")
                if not _issue_cancellation_fence_predecessor_matches(parent, fence):
                    raise R02Error("IssueCancellationFence does not bind the exact reachable predecessor provenance")
                if parent.role is CarrierRole.ISSUE_FINALIZING and fence.pre_fence_success_may_exist is not True:
                    raise R02Error("finalizing predecessor requires preFenceSuccessMayExist")
                origin = parent.proposal_origin
            else:
                raise R02Error("unsupported Issue-owned history node kind")
            if node.target_head_sha in reachable:
                existing = reachable[node.target_head_sha]
                if existing.claim_kind != node.claim_kind or existing.artifact_id != node.artifact_id:
                    raise R02Error("multiple Issue authority nodes claim the same target SHA")
            else:
                reachable[node.target_head_sha] = _IssueAuthorityNode(
                    node.claim_kind, node.role, node.target_head_sha, node.from_head_sha, node.tree_sha,
                    node.transition_kind, node.artifact_id, node.artifact_sha256, node.comment, node.artifact,
                    active=node.active, proposal_origin=origin,
                )
            advanced = True
        if not advanced:
            raise R02Error("unified Issue-owned history has missing or cyclic predecessor provenance")
        unresolved = remaining
    return tuple(sorted(reachable.values(), key=lambda node: (node.target_head_sha, node.claim_kind)))


def _issue_head_claim_comments(
    client: GitHubClient,
    repository: str,
    comments: Iterable[IssueComment],
    app: AppIdentity,
    state: IssuePRBindingState,
    current_ref: str,
) -> tuple[IssueHeadClaimComment, ...]:
    history = _issue_authority_history(client, repository, comments, app, state, current_ref)
    claims = tuple(
        IssueHeadClaimComment(node.artifact, node.comment, node.active)
        for node in history if node.claim_kind == "ISSUE_HEAD_CLAIM"
    )
    return tuple(sorted(claims, key=lambda item: (item.comment.database_id, item.claim.claim_generation_id)))


def _fresh_issue_projection_set(
    client: GitHubClient,
    repository: str,
    issue: IssueMetadata,
    anchor: IssueAnchorComment,
    binding: IssuePRBinding,
    source_comments: Iterable[IssueComment],
    pr_comments: Iterable[IssueComment],
    app: AppIdentity,
    semantic_validator: Callable[[Request], bool] | None,
    *,
    require_complete: bool = False,
) -> tuple[PatchFoldResult, tuple[IssuePatchProjection, ...]]:
    source_comment_list = tuple(source_comments)
    pr_comment_list = tuple(pr_comments)
    events = authorized_issue_patch_events(client, repository, anchor, source_comment_list)
    try:
        fold = fold_issue_patch_events(anchor.anchor, events, semantic_validator)
    except RequestModelError as error:
        raise R02Error(f"Issue PATCH fold failed closed: {_bounded_reason(error)}") from None
    by_id = {comment.database_id: comment for comment in source_comment_list}
    event_by_id = {event.comment_id: event for event in events}
    expected: dict[int, IssuePatchProjection] = {}
    for item in fold.evidence:
        if item.kind != "applied":
            continue
        event = event_by_id.get(item.comment_id)
        source = by_id.get(item.comment_id)
        if event is None or source is None:
            raise R02Error("accepted Issue PATCH evidence lost its exact source comment")
        try:
            patch = parse_patch(event.body)
            if patch is None:
                raise RequestModelError("accepted Issue PATCH evidence is not a PATCH")
            expected[item.comment_id] = IssuePatchProjection(
                1,
                issue.database_id,
                issue.number,
                anchor.comment.database_id,
                source.database_id,
                _binding_comment_sha256(source),
                binding.binding_id,
                patch,
            )
        except RequestModelError as error:
            raise R02Error(f"accepted Issue PATCH cannot render a canonical projection: {_bounded_reason(error)}") from None

    actual: dict[int, set[str]] = {}
    if any(
        type(comment.body) is str and comment.body.startswith(ISSUE_PATCH_PROJECTION_MARKER)
        for comment in source_comment_list
    ):
        raise R02Error("IssuePatchProjection comments must be stored on the generated Issue PR")
    if any(
        type(comment.body) is str and comment.body.startswith((
            ISSUE_HEAD_CLAIM_MARKER, REQUIRED_STATUS_EPOCH_MARKER, ISSUE_FINALIZATION_EPOCH_MARKER,
        ))
        for comment in source_comment_list
    ):
        raise R02Error("Issue-owned claim/epoch comments must be stored on the generated Issue PR")
    for comment in pr_comment_list:
        if type(comment.body) is not str or not comment.body.startswith(ISSUE_PATCH_PROJECTION_MARKER):
            continue
        try:
            projection = parse_issue_patch_projection(comment.body)
        except RequestModelError as error:
            raise R02Error(f"malformed IssuePatchProjection: {_bounded_reason(error)}") from None
        if (
            comment.author_id != app.bot_node_id
            or comment.author_login != app.bot_login
            or comment.author_type not in {None, "Bot"}
            or _issue_comment_edited(comment)
        ):
            raise R02Error("IssuePatchProjection comment authorship/edit integrity is invalid")
        expected_projection = expected.get(projection.issue_comment_id)
        source = by_id.get(projection.issue_comment_id)
        if (
            expected_projection is None
            or source is None
            or projection.issue_database_id != issue.database_id
            or projection.issue_number != issue.number
            or projection.issue_anchor_comment_id != anchor.comment.database_id
            or projection.issue_comment_body_sha256 != _binding_comment_sha256(source)
            or projection.binding_id != binding.binding_id
            or projection.render() != expected_projection.render()
        ):
            raise R02Error("IssuePatchProjection does not match the exact accepted Issue PATCH evidence")
        actual.setdefault(projection.issue_comment_id, set()).add(projection.render())
    if any(len(payloads) != 1 for payloads in actual.values()):
        raise R02Error("conflicting IssuePatchProjection equivalence classes block progression")
    if require_complete and set(actual) != set(expected):
        raise StaleAuthorityError("IssuePatchProjection evidence is incomplete after persistence")
    return fold, tuple(expected[key] for key in sorted(expected))


def _synchronize_issue_patch_projections(
    client: GitHubClient,
    repository: str,
    issue: IssueMetadata,
    anchor: IssueAnchorComment,
    binding: IssuePRBinding,
    source_comments: Iterable[IssueComment],
    pr_comments: Iterable[IssueComment],
    app: AppIdentity,
    semantic_validator: Callable[[Request], bool] | None,
) -> tuple[PatchFoldResult, tuple[IssuePatchProjection, ...], tuple[IssueComment, ...], tuple[IssueComment, ...]]:
    current_source_comments = tuple(source_comments)
    current_pr_comments = tuple(pr_comments)
    fold, expected = _fresh_issue_projection_set(
        client, repository, issue, anchor, binding,
        current_source_comments, current_pr_comments, app, semantic_validator,
    )
    present = {
        parse_issue_patch_projection(comment.body).issue_comment_id
        for comment in current_pr_comments
        if type(comment.body) is str and comment.body.startswith(ISSUE_PATCH_PROJECTION_MARKER)
    }
    for projection in expected:
        if projection.issue_comment_id in present:
            continue
        body = projection.render()
        try:
            client.create_issue_patch_projection_comment(repository, binding.pull_request_number, body)
        except GitHubAPIError as error:
            try:
                reread = tuple(client.list_issue_comments(repository, binding.pull_request_number))
                _fresh_issue_projection_set(
                    client, repository, issue, anchor, binding,
                    current_source_comments, reread, app, semantic_validator,
                    require_complete=True,
                )
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous IssuePatchProjection POST cannot be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            raise StaleAuthorityError(
                f"ambiguous IssuePatchProjection POST; stop and reread on a later invocation: {_bounded_reason(error)}"
            ) from None
        try:
            current_pr_comments = tuple(client.list_issue_comments(repository, binding.pull_request_number))
        except Exception as error:
            raise StaleAuthorityError(f"IssuePatchProjection write could not be reread: {_bounded_reason(error)}") from None
        _fresh_issue_projection_set(
            client, repository, issue, anchor, binding,
            current_source_comments, current_pr_comments, app, semantic_validator,
            require_complete=True,
        )
    if expected:
        # The expected set is a frozen accepted-fold snapshot. A source PATCH that
        # races projection POST is handled by the next fresh invocation.
        refreshed_issue = client.get_issue_metadata(repository, issue.number)
        refreshed_source_comments = tuple(client.list_issue_comments(repository, issue.number))
        refreshed_pr_comments = tuple(client.list_issue_comments(repository, binding.pull_request_number))
        if (
            refreshed_issue.number != issue.number
            or refreshed_issue.database_id != issue.database_id
            or refreshed_issue.node_id != issue.node_id
            or refreshed_issue.is_pull_request
            or refreshed_issue.state != "open"
        ):
            raise StaleAuthorityError("source Issue identity/lifecycle changed during projection synchronization")
        refreshed_anchor = validate_unique_issue_anchor(refreshed_source_comments, refreshed_issue, app)
        if refreshed_anchor.anchor != anchor.anchor or refreshed_anchor.comment.database_id != anchor.comment.database_id:
            raise StaleAuthorityError("source Issue anchor changed during projection synchronization")
        refreshed_fold, refreshed_expected = _fresh_issue_projection_set(
            client, repository, refreshed_issue, anchor, binding,
            refreshed_source_comments, refreshed_pr_comments, app, semantic_validator,
            require_complete=True,
        )
        if refreshed_fold != fold or tuple(item.render() for item in refreshed_expected) != tuple(item.render() for item in expected):
            raise StaleAuthorityError("Issue PATCH state changed during projection synchronization; fresh progression is required")
        current_source_comments = refreshed_source_comments
        current_pr_comments = refreshed_pr_comments
    return fold, expected, current_source_comments, current_pr_comments


def _require_semantic_issue_candidate(
    candidate: ProposalCandidate,
    request_class: RequestClass,
    accepted_base_sha: str,
) -> None:
    if type(candidate) is not ProposalCandidate:
        raise R02Error("C02 Issue candidate builder returned an invalid candidate")
    if candidate.request_class is not request_class or candidate.accepted_base_sha != accepted_base_sha:
        raise R02Error("C02 Issue candidate class/base does not match the fresh request snapshot")
    if candidate.commit_sha == accepted_base_sha or not candidate.changed_paths:
        raise IssueManagedNoSemanticChange(request_class)
    if request_class in {RequestClass.UPDATE, RequestClass.REMOVE} and "federation.json" not in candidate.changed_paths:
        raise IssueManagedNoSemanticChange(request_class)


def _plan_issue_managed_candidate(
    candidate_builder: CandidateBuilder,
    request: Request,
    request_class: RequestClass,
    accepted_base_sha: str,
    head_sha: str,
) -> ProposalCandidate:
    try:
        candidate = candidate_builder(request, request_class, accepted_base_sha, head_sha)
    except R02Error as error:
        if (
            type(error) is R02Error
            and request_class in {RequestClass.UPDATE, RequestClass.REMOVE}
            and str(error) == _LEGACY_UPDATE_REMOVE_NO_FEDERATION_ERROR
        ):
            raise IssueManagedNoSemanticChange(request_class) from None
        raise
    _require_semantic_issue_candidate(candidate, request_class, accepted_base_sha)
    return candidate


def _validate_issue_binding_cross_link(
    binding: IssuePRBinding,
    anchor: IssueAnchorComment,
    lease: IssueBranchLeaseComment,
    central_repository_node_id: str,
) -> None:
    expected = (
        anchor.anchor.issue_number,
        anchor.anchor.issue_database_id,
        anchor.anchor.issue_node_id,
        anchor.comment.database_id,
        anchor.anchor.canonical_sha256(),
        lease.comment.database_id,
        _binding_comment_sha256(lease.comment),
        anchor.anchor.source_id,
        anchor.anchor.source_repository_id,
        lease.lease.branch_ref,
        lease.lease.initial_head_sha,
        "main",
        central_repository_node_id,
    )
    actual = (
        binding.issue_number,
        binding.issue_database_id,
        binding.issue_node_id,
        binding.issue_request_anchor_comment_database_id,
        binding.issue_request_anchor_sha256,
        binding.issue_branch_lease_comment_database_id,
        binding.issue_branch_lease_sha256,
        binding.source_id,
        binding.source_repository_id,
        binding.branch_ref,
        binding.initial_head_sha,
        binding.base_ref,
        binding.central_repository_node_id,
    )
    if actual != expected:
        raise R02Error("IssuePRBinding does not cross-bind the exact Issue anchor and branch lease")


def _read_issue_pr_intake(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    app: AppIdentity,
    central_repository_node_id: str,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
    *,
    validate_fresh_source_authority: bool = True,
    require_open_lifecycle: bool = True,
) -> tuple[
    IssueMetadata,
    tuple[IssueComment, ...],
    IssueAnchorComment,
    IssueBranchLeaseComment,
    RepositoryMetadata,
    tuple[_IssuePRBindingComment, ...],
]:
    try:
        issue = client.get_issue_metadata(repository, issue_number)
        if (
            type(issue) is not IssueMetadata
            or issue.number != issue_number
            or issue.is_pull_request
            or (require_open_lifecycle and issue.state != "open")
        ):
            raise R02Error("Wave 03 requires the exact open Issue, not a PullRequest")
        comments = tuple(client.list_issue_comments(repository, issue_number))
        anchor = validate_unique_issue_anchor(comments, issue, app)
        leases = _resolve_issue_branch_lease_class(
            client,
            repository,
            comments,
            app,
            anchor.anchor,
            anchor.comment.database_id,
            central_repository_node_id,
        )
        if leases is None:
            raise R02Error("one canonical IssueBranchLease is required before Wave 03")
        if validate_fresh_source_authority:
            _fresh_issue_source_authority(source_authority_resolver, anchor.anchor)
        repo = client.get_repository_metadata(repository)
        if (
            type(repo) is not RepositoryMetadata
            or repo.node_id != central_repository_node_id
            or repo.full_name != repository
            or repo.default_branch != "main"
        ):
            raise StaleAuthorityError("central repository identity or default branch changed")
    except R02Error:
        raise
    except Exception as error:
        raise StaleAuthorityError(f"fresh Issue/lease/repository authority is unavailable: {_bounded_reason(error)}") from None

    _issue_pr_authority_fence(comments, app)
    binding_comments = _binding_comment_candidates(
        comments, app, ISSUE_INTERNAL_PR_BINDING_MARKER,
        parse_issue_internal_pr_binding, "IssueInternalPRBinding",
    )
    for item in binding_comments:
        _validate_issue_binding_cross_link(item.binding, anchor, leases, central_repository_node_id)
    return issue, comments, anchor, leases, repo, binding_comments


def _same_issue_pr_intake(
    initial: tuple[IssueMetadata, tuple[IssueComment, ...], IssueAnchorComment, IssueBranchLeaseComment, RepositoryMetadata, tuple[_IssuePRBindingComment, ...]],
    fresh: tuple[IssueMetadata, tuple[IssueComment, ...], IssueAnchorComment, IssueBranchLeaseComment, RepositoryMetadata, tuple[_IssuePRBindingComment, ...]],
) -> None:
    if (
        fresh[2].anchor != initial[2].anchor
        or fresh[2].comment.database_id != initial[2].comment.database_id
        or fresh[2].comment.body != initial[2].comment.body
        or fresh[3].lease != initial[3].lease
        or fresh[3].comment.database_id != initial[3].comment.database_id
        or fresh[3].comment.body != initial[3].comment.body
        or fresh[4].node_id != initial[4].node_id
        or fresh[4].full_name != initial[4].full_name
        or fresh[4].default_branch != initial[4].default_branch
    ):
        raise StaleAuthorityError("Issue anchor, lease, or central repository changed during Wave 03")


def _read_issue_branch_ref(client: GitHubClient, repository: str, short_ref: str) -> str | None:
    try:
        return _lease_sha40(client.get_ref_oid(repository, short_ref), "leased Issue branch head")
    except NotFoundError:
        return None
    except R02Error:
        raise
    except Exception as error:
        raise StaleAuthorityError(f"leased Issue branch ref is unavailable: {_bounded_reason(error)}") from None


def _enumerate_issue_pr_candidates(
    client: GitHubClient,
    repository: str,
    short_ref: str,
    app: AppIdentity,
    anchor: IssueAnchorComment,
    lease: IssueBranchLeaseComment,
    central_repository_node_id: str,
) -> tuple[_IssuePRCandidate, ...]:
    try:
        raw_items = client.list_pull_requests(repository, state="all")
        if type(raw_items) not in {tuple, list}:
            raise R02Error("all-state PR enumeration must return a sequence")
        seen_numbers: set[int] = set()
        candidates: list[_IssuePRCandidate] = []
        for raw in raw_items:
            if type(raw) is not dict or type(raw.get("number")) is not int or not 1 <= raw["number"] <= 9_223_372_036_854_775_807:
                raise R02Error("all-state PR enumeration contains an invalid number")
            number = raw["number"]
            if number in seen_numbers:
                raise R02Error("all-state PR enumeration contains duplicate numbers")
            seen_numbers.add(number)
            pr = client.get_pull_request_metadata(repository, number)
            if type(pr) is not PullRequestMetadata or pr.number != number:
                raise R02Error("composite PR metadata does not match the enumerated PR number")
            if pr.head_ref == short_ref and pr.head_repository_id != central_repository_node_id:
                raise R02Error("foreign repository PR collides with the reserved Issue branch name")
            if pr.head_ref != short_ref or pr.head_repository_id != central_repository_node_id:
                continue
            comments = tuple(client.list_issue_comments(repository, number))
            binding_comments = _binding_comment_candidates(
                comments, app, PR_ISSUE_ORIGIN_BINDING_MARKER,
                parse_pr_issue_origin_binding, "PRIssueOriginBinding",
            )
            binding_item = binding_comments[0] if binding_comments else None
            if binding_item is not None:
                _validate_issue_binding_cross_link(binding_item.binding, anchor, lease, central_repository_node_id)
                if binding_item.binding.pull_request_number != number:
                    raise R02Error("PRIssueOriginBinding names a different PR number")
            candidates.append(_IssuePRCandidate(pr, comments, binding_item))
        return tuple(candidates)
    except R02Error:
        raise
    except Exception as error:
        raise StaleAuthorityError(f"all-state reserved-head PR inventory failed: {_bounded_reason(error)}") from None


def _validate_generated_issue_pr(
    client: GitHubClient,
    repository: str,
    number: int,
    app: AppIdentity,
    central_repository_node_id: str,
    anchor: IssueAnchorComment,
    lease: IssueBranchLeaseComment,
) -> tuple[PullRequestMetadata, IssueMetadata, tuple[IssueComment, ...], tuple[_IssuePRBindingComment, ...]]:
    try:
        pr = client.get_pull_request_metadata(repository, number)
        pr_issue = client.get_issue_metadata(repository, number)
        comments = tuple(client.list_issue_comments(repository, number))
    except Exception as error:
        raise StaleAuthorityError(f"generated Issue PR composite state is unavailable: {_bounded_reason(error)}") from None
    expected_body = render_request_body(anchor.anchor.initial_request)
    short_ref = lease.lease.branch_ref.removeprefix("refs/heads/")
    if type(pr) is not PullRequestMetadata or pr.number != number:
        raise R02Error("reserved-head candidate has invalid composite PR identity")
    if (
        pr.author_id != app.bot_node_id
        or pr.author_login != app.bot_login
        or pr.head_oid != lease.lease.initial_head_sha
        or pr.head_ref != short_ref
        or pr.head_repository_id != central_repository_node_id
        or pr.head_repository != repository
        or pr.base_repository_id != central_repository_node_id
        or pr.base_repository != repository
        or pr.base_ref != "main"
        or pr.draft is not False
        or pr.body != expected_body
        or pr.last_edited_at is not None
        or pr.includes_created_edit is not False
    ):
        raise R02Error("reserved-head PR is not the exact open nondraft App-generated Issue PR")
    if (
        type(pr_issue) is not IssueMetadata
        or pr_issue.is_pull_request is not True
        or pr_issue.number != number
        or type(pr_issue.database_id) is not int
        or not 1 <= pr_issue.database_id <= 9_223_372_036_854_775_807
        or type(pr_issue.node_id) is not str
        or not pr_issue.node_id
        or c02.contains_control(pr_issue.node_id)
        or pr_issue.author_id != pr.author_id
        or pr_issue.author_login != pr.author_login
        or pr_issue.state != "open"
        or pr_issue.body != pr.body
    ):
        raise R02Error("PR-as-Issue identity/state/body does not match the generated PR")
    binding_comments = _binding_comment_candidates(
        comments, app, PR_ISSUE_ORIGIN_BINDING_MARKER,
        parse_pr_issue_origin_binding, "PRIssueOriginBinding",
    )
    return pr, pr_issue, comments, binding_comments


def _intended_issue_pr_binding(
    anchor: IssueAnchorComment,
    lease: IssueBranchLeaseComment,
    pr: PullRequestMetadata,
    pr_issue: IssueMetadata,
    central_repository_node_id: str,
) -> IssuePRBinding:
    return IssuePRBinding.create(
        schema_version=1,
        issue_number=anchor.anchor.issue_number,
        issue_database_id=anchor.anchor.issue_database_id,
        issue_node_id=anchor.anchor.issue_node_id,
        issue_request_anchor_comment_database_id=anchor.comment.database_id,
        issue_request_anchor_sha256=anchor.anchor.canonical_sha256(),
        issue_branch_lease_comment_database_id=lease.comment.database_id,
        issue_branch_lease_sha256=_binding_comment_sha256(lease.comment),
        source_id=anchor.anchor.source_id,
        source_repository_id=anchor.anchor.source_repository_id,
        branch_ref=lease.lease.branch_ref,
        pull_request_number=pr.number,
        pull_request_database_id=pr_issue.database_id,
        pull_request_node_id=pr_issue.node_id,
        initial_head_sha=lease.lease.initial_head_sha,
        base_ref="main",
        central_repository_node_id=central_repository_node_id,
    )


def _require_binding_equals(
    candidates: tuple[_IssuePRBindingComment, ...],
    intended: IssuePRBinding,
    label: str,
) -> IssueComment | None:
    if not candidates:
        return None
    if candidates[0].binding != intended:
        raise R02Error(f"existing {label} conflicts with the exact intended IssuePRBinding")
    return candidates[0].comment


def _fresh_issue_pr_binding_snapshot(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    app: AppIdentity,
    central_repository_node_id: str,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
    initial: tuple[IssueMetadata, tuple[IssueComment, ...], IssueAnchorComment, IssueBranchLeaseComment, RepositoryMetadata, tuple[_IssuePRBindingComment, ...]],
    pr_number: int,
    intended: IssuePRBinding,
) -> tuple[IssuePRBindingState | None, tuple[IssueMetadata, tuple[IssueComment, ...], IssueAnchorComment, IssueBranchLeaseComment, RepositoryMetadata, tuple[_IssuePRBindingComment, ...]], PullRequestMetadata, IssueMetadata, tuple[IssueComment, ...], tuple[_IssuePRBindingComment, ...]]:
    fresh = _read_issue_pr_intake(
        client, repository, issue_number, app, central_repository_node_id, source_authority_resolver,
    )
    _same_issue_pr_intake(initial, fresh)
    issue_binding_candidates = fresh[5]
    short_ref = fresh[3].lease.branch_ref.removeprefix("refs/heads/")
    if _read_issue_branch_ref(client, repository, short_ref) != fresh[3].lease.initial_head_sha:
        raise StaleAuthorityError("leased Issue branch ref moved during two-sided binding")
    _validate_issue_branch_lease_history(client, repository, fresh[2].anchor, fresh[3].lease)
    candidates = _enumerate_issue_pr_candidates(
        client, repository, short_ref, app, fresh[2], fresh[3], central_repository_node_id,
    )
    if len(candidates) != 1 or candidates[0].pr.number != pr_number:
        raise StaleAuthorityError("exact generated Issue PR is no longer the sole reserved-head candidate")
    pr, pr_issue, comments, pr_binding_candidates = _validate_generated_issue_pr(
        client, repository, pr_number, app, central_repository_node_id, fresh[2], fresh[3],
    )
    expected = _intended_issue_pr_binding(fresh[2], fresh[3], pr, pr_issue, central_repository_node_id)
    if expected != intended:
        raise StaleAuthorityError("intended IssuePRBinding changed during fresh revalidation")
    issue_binding_comment = _require_binding_equals(fresh[5], intended, "IssueInternalPRBinding")
    pr_binding_comment = _require_binding_equals(pr_binding_candidates, intended, "PRIssueOriginBinding")
    complete = None
    if issue_binding_comment is not None and pr_binding_comment is not None:
        complete = IssuePRBindingState(
            issue_anchor=fresh[2],
            lease=fresh[3],
            binding=intended,
            issue_binding_comment=issue_binding_comment,
            pr_binding_comment=pr_binding_comment,
            pr=pr,
            pr_issue=pr_issue,
            owning_issue=fresh[0],
        )
    return complete, fresh, pr, pr_issue, comments, pr_binding_candidates


def _write_issue_pr_binding_side(
    client: GitHubClient,
    repository: str,
    number: int,
    binding: IssuePRBinding,
    app: AppIdentity,
    *,
    issue_side: bool,
) -> IssueComment:
    marker = ISSUE_INTERNAL_PR_BINDING_MARKER if issue_side else PR_ISSUE_ORIGIN_BINDING_MARKER
    parser = parse_issue_internal_pr_binding if issue_side else parse_pr_issue_origin_binding
    label = "IssueInternalPRBinding" if issue_side else "PRIssueOriginBinding"
    body = binding.render_issue_binding() if issue_side else binding.render_pr_origin_binding()
    try:
        client.create_issue_comment(repository, number, body)
    except GitHubAPIError as error:
        try:
            comments = tuple(client.list_issue_comments(repository, number))
        except Exception as read_error:
            raise StaleAuthorityError(
                f"ambiguous {label} POST and target surface could not be diagnosed: {_bounded_reason(read_error)}"
            ) from None
        candidates = _binding_comment_candidates(comments, app, marker, parser, label)
        if candidates and candidates[0].binding != binding:
            raise R02Error(f"conflicting {label} evidence appeared after ambiguous POST") from None
        raise StaleAuthorityError(
            f"ambiguous {label} POST; stop this invocation and reread on a later invocation: {_bounded_reason(error)}"
        ) from None
    try:
        comments = tuple(client.list_issue_comments(repository, number))
    except Exception as error:
        raise StaleAuthorityError(f"persisted {label} could not be reread: {_bounded_reason(error)}") from None
    candidates = _binding_comment_candidates(comments, app, marker, parser, label)
    if not candidates or candidates[0].binding != binding:
        raise StaleAuthorityError(f"persisted {label} is absent or differs from the exact intended payload")
    return candidates[0].comment


def create_or_recover_issue_pr_binding(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    app: AppIdentity,
    central_repository_node_id: str,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
) -> IssuePRBindingState:
    """Expose exactly the historical leased head, recover one exact PR, and persist its immutable two-sided binding."""
    if type(issue_number) is not int or not 1 <= issue_number <= 9_223_372_036_854_775_807:
        raise R02Error("Issue number must be a positive signed-64 integer")
    if not callable(source_authority_resolver):
        raise R02Error("a fresh Issue source-authority resolver is required")
    initial = _read_issue_pr_intake(
        client, repository, issue_number, app, central_repository_node_id, source_authority_resolver,
    )
    issue, _comments, anchor, lease, _repo, issue_binding_candidates = initial
    short_ref = lease.lease.branch_ref.removeprefix("refs/heads/")
    if lease.lease.branch_ref != issue_branch_ref(issue_number):
        raise R02Error("canonical IssueBranchLease ref does not match the requested Issue")

    # Revalidate every authority input immediately before the ref ownership inventory.
    fresh = _read_issue_pr_intake(
        client, repository, issue_number, app, central_repository_node_id, source_authority_resolver,
    )
    _same_issue_pr_intake(initial, fresh)
    issue_binding_candidates = fresh[5]
    inventory = _enumerate_issue_pr_candidates(
        client, repository, short_ref, app, anchor, lease, central_repository_node_id,
    )
    if len(inventory) > 1:
        raise R02Error("duplicate exact reserved-head PR candidates block Wave 03")
    if issue_binding_candidates and not inventory:
        raise R02Error("IssueInternalPRBinding points to a missing reserved-head PR")
    if issue_binding_candidates and inventory and issue_binding_candidates[0].binding.pull_request_number != inventory[0].pr.number:
        raise R02Error("IssueInternalPRBinding PR number disagrees with reserved-head candidate")

    current_ref = _read_issue_branch_ref(client, repository, short_ref)
    if current_ref is None:
        if issue_binding_candidates:
            raise R02Error("an existing IssuePRBinding cannot recreate an absent leased ref")
        if inventory or any(candidate.binding is not None for candidate in inventory):
            raise R02Error("an existing reserved-head PR/binding blocks recreation of an absent leased ref")
        exact_create = RefUpdate(
            name=lease.lease.branch_ref,
            before_oid=ZERO_OID,
            after_oid=lease.lease.initial_head_sha,
            force=False,
        )
        try:
            client.update_refs(central_repository_node_id, [exact_create])
        except RefCASConflict as error:
            if _read_issue_branch_ref(client, repository, short_ref) != lease.lease.initial_head_sha:
                raise StaleAuthorityError(f"leased ref CAS conflicted without exact readback recovery: {_bounded_reason(error)}") from None
        except GitHubAPIError as error:
            if _read_issue_branch_ref(client, repository, short_ref) != lease.lease.initial_head_sha:
                raise StaleAuthorityError(f"ambiguous leased ref CAS did not read back the exact lease head: {_bounded_reason(error)}") from None
        if _read_issue_branch_ref(client, repository, short_ref) != lease.lease.initial_head_sha:
            raise StaleAuthorityError("leased ref create did not read back the exact initialHeadSha")
    elif current_ref != lease.lease.initial_head_sha:
        raise R02Error("leased Issue branch is already owned by a different head")

    # The historical lease remains valid even when current main has advanced.
    _validate_issue_branch_lease_history(client, repository, anchor.anchor, lease.lease)
    after_ref = _read_issue_pr_intake(
        client, repository, issue_number, app, central_repository_node_id, source_authority_resolver,
    )
    _same_issue_pr_intake(initial, after_ref)
    issue_binding_candidates = after_ref[5]
    if _read_issue_branch_ref(client, repository, short_ref) != lease.lease.initial_head_sha:
        raise StaleAuthorityError("leased Issue ref changed after exact create/recovery")
    inventory = _enumerate_issue_pr_candidates(
        client, repository, short_ref, app, anchor, lease, central_repository_node_id,
    )
    if len(inventory) > 1:
        raise R02Error("duplicate exact reserved-head PR candidates block Wave 03")
    if issue_binding_candidates and not inventory:
        raise R02Error("IssueInternalPRBinding points to a missing reserved-head PR")

    created_number: int | None = None
    create_error: GitHubAPIError | None = None
    if not inventory:
        before_create = _read_issue_pr_intake(
            client, repository, issue_number, app, central_repository_node_id, source_authority_resolver,
        )
        _same_issue_pr_intake(initial, before_create)
        issue_binding_candidates = before_create[5]
        if before_create[5]:
            raise R02Error("IssueInternalPRBinding appeared before PR creation")
        if _read_issue_branch_ref(client, repository, short_ref) != lease.lease.initial_head_sha:
            raise StaleAuthorityError("leased ref changed before exact Issue PR creation")
        _validate_issue_branch_lease_history(client, repository, anchor.anchor, lease.lease)
        latest_inventory = _enumerate_issue_pr_candidates(
            client, repository, short_ref, app, anchor, lease, central_repository_node_id,
        )
        if len(latest_inventory) > 1:
            raise R02Error("duplicate exact reserved-head PR candidates block Issue PR creation")
        if latest_inventory:
            inventory = latest_inventory
        else:
            title = f"Federation request #{issue_number}: {anchor.anchor.request_class.value}"
            body = render_request_body(anchor.anchor.initial_request)
            try:
                created_number = client.create_issue_pull_request(
                    repository, head=short_ref, base="main", title=title, body=body,
                )
            except GitHubAPIError as error:
                create_error = error
            inventory = _enumerate_issue_pr_candidates(
                client, repository, short_ref, app, anchor, lease, central_repository_node_id,
            )
            if len(inventory) != 1:
                if len(inventory) > 1:
                    raise R02Error("PR create response recovery found duplicate reserved-head candidates")
                reason = _bounded_reason(create_error) if create_error is not None else "successful response had no exact candidate"
                raise StaleAuthorityError(f"Issue PR create did not recover one exact candidate; no same-invocation retry: {reason}") from None
            if created_number is not None and inventory[0].pr.number != created_number:
                raise R02Error("created PR number does not match the sole exact reserved-head candidate")
    if len(inventory) != 1:
        raise R02Error("exactly one all-state reserved-head PR candidate is required")
    pr_number = inventory[0].pr.number
    if issue_binding_candidates and issue_binding_candidates[0].binding.pull_request_number != pr_number:
        raise R02Error("IssueInternalPRBinding PR number disagrees with its candidate")

    pr, pr_issue, _pr_comments, pr_binding_candidates = _validate_generated_issue_pr(
        client, repository, pr_number, app, central_repository_node_id, anchor, lease,
    )
    intended = _intended_issue_pr_binding(anchor, lease, pr, pr_issue, central_repository_node_id)
    issue_binding_comment = _require_binding_equals(issue_binding_candidates, intended, "IssueInternalPRBinding")
    pr_binding_comment = _require_binding_equals(pr_binding_candidates, intended, "PRIssueOriginBinding")
    # Ordered repair: when both are missing, persist the Issue side first.
    for issue_side in (True, False):
        fresh_result = _fresh_issue_pr_binding_snapshot(
            client, repository, issue_number, app, central_repository_node_id,
            source_authority_resolver, initial, pr_number, intended,
        )
        complete, fresh, fresh_pr, fresh_pr_issue, fresh_pr_comments, fresh_pr_bindings = fresh_result
        if complete is not None:
            return complete
        if issue_side:
            present = _require_binding_equals(fresh[5], intended, "IssueInternalPRBinding")
            if present is not None:
                continue
            _write_issue_pr_binding_side(
                client, repository, issue_number, intended, app, issue_side=True,
            )
        else:
            present = _require_binding_equals(fresh_pr_bindings, intended, "PRIssueOriginBinding")
            if present is not None:
                continue
            _write_issue_pr_binding_side(
                client, repository, pr_number, intended, app, issue_side=False,
            )

    final = _fresh_issue_pr_binding_snapshot(
        client, repository, issue_number, app, central_repository_node_id,
        source_authority_resolver, initial, pr_number, intended,
    )[0]
    if final is None:
        raise StaleAuthorityError("final cross-validation did not find the exact complete two-sided IssuePRBinding")
    return final


def _read_managed_issue_pr_binding_state(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    app: AppIdentity,
    central_repository_node_id: str,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
    *,
    validate_fresh_source_authority: bool = True,
    require_open_lifecycle: bool = True,
    allow_cancellation_fence: bool = False,
    allow_pr_stage_state: bool = False,
) -> IssuePRBindingState:
    intake = _read_issue_pr_intake(
        client, repository, issue_number, app, central_repository_node_id, source_authority_resolver,
        validate_fresh_source_authority=validate_fresh_source_authority,
        require_open_lifecycle=require_open_lifecycle,
    )
    issue, _issue_comments, anchor, lease, _repo, issue_bindings = intake
    if not issue_bindings:
        raise R02Error("IssueInternalPRBinding is required before managed Issue progression")
    by_payload: dict[str, list[_IssuePRBindingComment]] = {}
    for item in issue_bindings:
        by_payload.setdefault(item.binding.render_issue_binding(), []).append(item)
    if len(by_payload) != 1:
        raise R02Error("conflicting IssueInternalPRBinding payloads block managed Issue progression")
    binding_item = min(next(iter(by_payload.values())), key=lambda item: item.comment.database_id)
    binding = binding_item.binding
    pr_number = binding.pull_request_number
    try:
        pr = client.get_pull_request_metadata(repository, pr_number)
        pr_issue = client.get_issue_metadata(repository, pr_number)
        pr_comments = tuple(client.list_issue_comments(repository, pr_number))
    except Exception as error:
        raise StaleAuthorityError(f"bound Issue PR state is unavailable: {_bounded_reason(error)}") from None
    _issue_pr_authority_fence(
        pr_comments, app, allow_cancellation_fence=allow_cancellation_fence,
    )
    _validate_issue_binding_cross_link(binding, anchor, lease, central_repository_node_id)
    if (
        type(pr) is not PullRequestMetadata
        or pr.number != pr_number
        or pr.author_id != app.bot_node_id
        or pr.author_login != app.bot_login
        or pr.head_ref != lease.lease.branch_ref.removeprefix("refs/heads/")
        or pr.head_repository_id != central_repository_node_id
        or pr.head_repository != repository
        or pr.base_repository_id != central_repository_node_id
        or pr.base_repository != repository
        or pr.base_ref != "main"
        or type(pr.draft) is not bool
        or (not allow_pr_stage_state and pr.draft is not False)
        or pr.body != render_request_body(anchor.anchor.initial_request)
        or pr.last_edited_at is not None
        or pr.includes_created_edit is not False
    ):
        raise R02Error("bound Issue PR immutable identity/body/topology is invalid")
    if (
        type(pr_issue) is not IssueMetadata
        or pr_issue.is_pull_request is not True
        or pr_issue.number != pr_number
        or pr_issue.database_id != binding.pull_request_database_id
        or pr_issue.node_id != binding.pull_request_node_id
        or pr_issue.author_id != app.bot_node_id
        or pr_issue.author_login != app.bot_login
        or (require_open_lifecycle and pr_issue.state != "open")
        or pr_issue.body != pr.body
    ):
        raise R02Error("bound Issue PR composite identity/lifecycle/body is invalid")
    pr_binding_candidates = _binding_comment_candidates(
        pr_comments, app, PR_ISSUE_ORIGIN_BINDING_MARKER,
        parse_pr_issue_origin_binding, "PRIssueOriginBinding",
    )
    if not pr_binding_candidates or any(item.binding != binding for item in pr_binding_candidates):
        raise R02Error("PRIssueOriginBinding does not match the exact persisted Issue binding")
    pr_binding_comment = min(pr_binding_candidates, key=lambda item: item.comment.database_id).comment
    return IssuePRBindingState(
        issue_anchor=anchor,
        lease=lease,
        binding=binding,
        issue_binding_comment=binding_item.comment,
        pr_binding_comment=pr_binding_comment,
        pr=pr,
        pr_issue=pr_issue,
        owning_issue=issue,
    )


def _require_same_managed_issue_pr_binding(
    before: IssuePRBindingState,
    after: IssuePRBindingState,
) -> None:
    if (
        before.issue_anchor.anchor != after.issue_anchor.anchor
        or before.issue_anchor.comment.database_id != after.issue_anchor.comment.database_id
        or before.issue_anchor.comment.body != after.issue_anchor.comment.body
        or before.lease.lease != after.lease.lease
        or before.lease.comment.database_id != after.lease.comment.database_id
        or before.lease.comment.body != after.lease.comment.body
        or before.binding != after.binding
        or before.issue_binding_comment.database_id != after.issue_binding_comment.database_id
        or before.issue_binding_comment.body != after.issue_binding_comment.body
        or before.pr_binding_comment.database_id != after.pr_binding_comment.database_id
        or before.pr_binding_comment.body != after.pr_binding_comment.body
        or before.owning_issue.number != after.owning_issue.number
        or before.owning_issue.database_id != after.owning_issue.database_id
        or before.owning_issue.node_id != after.owning_issue.node_id
        or before.owning_issue.is_pull_request != after.owning_issue.is_pull_request
        or before.owning_issue.author_id != after.owning_issue.author_id
    ):
        raise StaleAuthorityError("Issue/lease/binding identities changed during managed progression")


def _validate_managed_issue_head_history(
    client: GitHubClient,
    repository: str,
    issue_number: int,
    app: AppIdentity,
    source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
) -> tuple[IssuePRBindingState, str, tuple[IssueComment, ...], tuple[IssueHeadClaimComment, ...]]:
    """Prove the current leased Issue head before consulting fresh mutable PATCH authority."""
    central = client.get_repository_metadata(repository)
    state = _read_managed_issue_pr_binding_state(
        client,
        repository,
        issue_number,
        app,
        central.node_id,
        source_authority_resolver,
        validate_fresh_source_authority=False,
    )
    branch_short = state.binding.branch_ref.removeprefix("refs/heads/")
    current_ref = _read_issue_branch_ref(client, repository, branch_short)
    if current_ref is None or state.pr.head_oid != current_ref:
        raise StaleAuthorityError("managed Issue PR head is not the exact current leased-ref head")
    pr_comments = tuple(client.list_issue_comments(repository, state.binding.pull_request_number))
    _issue_pr_authority_fence(pr_comments, app)
    history = _issue_authority_history(client, repository, pr_comments, app, state, current_ref)
    active = tuple(item for item in history if item.target_head_sha == current_ref)
    if len(active) != 1:
        raise R02Error("current generated Issue head has no unique validated Issue-owned authority")
    claims = tuple(
        IssueHeadClaimComment(item.artifact, item.comment, item.active)
        for item in history if item.claim_kind == "ISSUE_HEAD_CLAIM"
    )
    return state, current_ref, pr_comments, claims


def _ensure_managed_issue_pr_request_anchor(
    client: GitHubClient,
    repository: str,
    state: IssuePRBindingState,
    request_class: RequestClass,
    app: AppIdentity,
) -> AnchorComment:
    """Create or reuse the exact immutable PR RequestAnchor handed off from the Issue anchor."""
    pr = client.get_pull_request_metadata(repository, state.binding.pull_request_number)
    if pr.number != state.binding.pull_request_number or pr.head_oid != state.pr.head_oid or pr.body != state.pr.body:
        raise StaleAuthorityError("generated Issue PR head/body changed before RequestAnchor handoff")
    comments = tuple(client.list_issue_comments(repository, state.binding.pull_request_number))
    anchor = create_anchor_once(client, repository, pr, request_class, app, comments)
    if (
        anchor.anchor.initial_request != state.issue_anchor.anchor.initial_request
        or anchor.anchor.request_class is not state.issue_anchor.anchor.request_class
        or anchor.anchor.initial_body_sha256 != body_sha256(render_request_body(state.issue_anchor.anchor.initial_request))
    ):
        raise R02Error("generated PR RequestAnchor does not hand off the exact immutable Issue request")
    return anchor


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
    allow_green: bool = False,
) -> CheckRun:
    """Write exactly one App-owned check. Green is finalizer-grade only."""
    if type(allow_create) is not bool or type(allow_green) is not bool:
        raise R02Error("check writer mode is invalid")
    if result.conclusion == "success" and not allow_green:
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


def read_optional_request_marker(client: GitHubClient, repository: str, head_sha: str) -> RequestClass | None:
    """Treat an absent marker as unrelated while malformed present markers still fail closed."""
    raw = client.read_optional_commit_file(repository, head_sha, REQUEST_MARKER, expected_mode="100644")
    if raw is None:
        return None
    if len(raw) > 128 or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise R02Error("request marker bytes are not exactly one value plus final newline")
    try:
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
        "schemaVersion": 3,
        "sources": [
            {
                "sourceId": source.source_id,
                "repository": source.repository,
                "repositoryId": source.repository_id,
                "skillsRoot": source.skills_root,
                "description": source.description,
                "lines": [
                    {
                        "ref": line.ref,
                        "skillPrefixes": list(line.skill_prefixes),
                    }
                    for line in source.lines
                ],
            }
            for source in manifest.sources
        ],
    }


def _lines_from_request(
    request: Request,
    *,
    default_branch: str,
    default_prefixes: tuple[str, ...],
    existing: c02.SourceDeclaration | None,
) -> tuple[c02.LineDeclaration, ...]:
    if request.publication_lines is not None:
        lines = tuple(
            c02.LineDeclaration(ref=line.ref, skill_prefixes=tuple(sorted(line.skill_prefixes)))
            for line in request.publication_lines
        )
        return tuple(sorted(lines, key=lambda item: item.ref))
    if request.branch is None and request.skill_prefixes is None and existing is not None:
        return existing.lines
    fallback_branch = default_branch
    if request.branch is None and existing is not None and existing.lines:
        fallback_branch = existing.lines[0].ref
    resolved = resolve_publication_lines(
        request,
        default_branch=fallback_branch,
        default_prefixes=default_prefixes,
    )
    return tuple(
        c02.LineDeclaration(ref=line.ref, skill_prefixes=tuple(sorted(line.skill_prefixes)))
        for line in sorted(resolved, key=lambda item: item.ref)
    )


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
        lines = _lines_from_request(
            request,
            default_branch=default_branch if default_branch.startswith("refs/heads/") else f"refs/heads/{default_branch}",
            default_prefixes=default_prefixes,
            existing=None,
        )
        candidate_sources = list(accepted_manifest.sources) + [c02.SourceDeclaration(
            source_id=source_id,
            repository=repository,
            repository_id=repository_id,
            skills_root=request.skills_root or "skills",
            description=request.description or default_description,
            lines=lines,
        )]
    elif request.request_class is RequestClass.UPDATE:
        if existing is None or existing.repository_id != repository_id:
            raise R02Error("UPDATE must resolve exactly one accepted source identity")
        lines = _lines_from_request(
            request,
            default_branch=default_branch,
            default_prefixes=default_prefixes,
            existing=existing,
        )
        candidate_sources = [source for source in accepted_manifest.sources if source.source_id != source_id]
        candidate_sources.append(c02.SourceDeclaration(
            source_id=source_id,
            repository=request.repository_url.removeprefix("https://github.com/"),
            repository_id=repository_id,
            skills_root=request.skills_root or existing.skills_root,
            description=request.description or existing.description,
            lines=lines,
        ))
    elif request.request_class is RequestClass.REMOVE:
        if existing is None or existing.repository_id != repository_id:
            raise R02Error("REMOVE must resolve exactly one accepted source identity")
        candidate_sources = [source for source in accepted_manifest.sources if source.source_id != source_id]
    else:
        raise R02Error("only ADD/UPDATE/REMOVE have an R02 manifest candidate")
    return c02.load_manifest_from_value({"schemaVersion": 3, "sources": [
        {
            "sourceId": source.source_id,
            "repository": source.repository,
            "repositoryId": source.repository_id,
            "skillsRoot": source.skills_root,
            "description": source.description,
            "lines": [
                {"ref": line.ref, "skillPrefixes": list(line.skill_prefixes)}
                for line in source.lines
            ],
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


def resolve_issue_source_authority(
    request: Request,
    request_class: RequestClass,
    accepted_manifest: c02.Manifest,
    source_metadata: PublicSourceMetadata,
) -> IssueSourceAuthority:
    """Resolve stable source identity once for Issue preflight and C02 planning."""
    if type(request) is not Request:
        raise R02Error("source authority requires a validated Request")
    if request.request_class is not request_class:
        raise R02Error("request class does not match validated Request")
    if request_class not in MANUAL_CLASSES:
        raise R02Error("Issue source authority does not support this request class")
    if not isinstance(accepted_manifest, c02.Manifest):
        raise R02Error("source authority requires a validated accepted manifest")
    if type(source_metadata) is not PublicSourceMetadata:
        raise R02Error("source authority requires already-read public source metadata")

    locator = _source_locator(request)
    if source_metadata.full_name.lower() != locator.lower():
        raise R02Error("resolved source repository identity does not match requested locator")

    if request_class is RequestClass.ADD:
        source_id = _derived_source_id(locator)
        if (
            source_id in accepted_manifest.by_source_id
            or source_metadata.repository_id in accepted_manifest.by_repository_id
        ):
            raise R02Error("ADD source identity is already accepted")
        identity_kind = IssueSourceIdentityKind.PROPOSED
    else:
        matches = tuple(
            source
            for source in accepted_manifest.sources
            if source.repository_id == source_metadata.repository_id
        )
        if len(matches) != 1:
            raise R02Error("request repositoryId does not identify exactly one accepted source")
        source_id = matches[0].source_id
        identity_kind = IssueSourceIdentityKind.ACCEPTED

    return IssueSourceAuthority(
        request_class=request_class,
        source_id=source_id,
        source_repository_id=source_metadata.repository_id,
        source_canonical_full_name=source_metadata.full_name,
        source_identity_kind=identity_kind,
        source_default_branch=source_metadata.default_branch,
        source_description=source_metadata.description,
    )


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
        for line in source.lines:
            bound = c02.bind_source_snapshot(
                self._capsule_temp_root,
                source,
                line,
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
        authority = resolve_issue_source_authority(request, request_class, accepted_manifest, source_repo)
        source_id = authority.source_id
        source_repository_id = authority.source_repository_id
        existing = accepted_manifest.by_source_id.get(source_id)
        accepted_line_refs = tuple(line.ref for line in existing.lines) if existing is not None else ()
        default_prefixes = (
            request.skill_prefixes
            or (
                tuple(prefix for line in existing.lines for prefix in line.skill_prefixes)
                if existing is not None
                else (_derived_source_id(_source_locator(request).split("/", 1)[-1]),)
            )
        )
        try:
            proposed_refs = proposed_line_refs(
                request,
                default_branch=source_repo.default_branch,
                default_prefixes=default_prefixes,
                existing_refs=accepted_line_refs if existing is not None else None,
            )
        except RequestModelError as error:
            raise R02Error(str(error)) from None
        try:
            validate_drop_set(
                request_class,
                request,
                accepted_line_refs=accepted_line_refs,
                proposed_refs=proposed_refs,
            )
        except RequestModelError as error:
            raise R02Error(str(error)) from None
        candidate_manifest = c02_source_candidate(
            request,
            accepted_manifest,
            source_id=source_id,
            repository_id=source_repository_id,
            default_branch=authority.source_default_branch,
            default_description=authority.source_description or "Federated source repository",
            default_prefixes=tuple(default_prefixes),
        )
        if request_class is RequestClass.ADD:
            self._validate_add_source(candidate_manifest.sources[-1])
            return {"federation.json": ("100644", _manifest_bytes(candidate_manifest))}, tree, source_id, source_repository_id

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
        return desired_files, tree, source_id, source_repository_id

    def __call__(self, request: Request, request_class: RequestClass, accepted_base_sha: str, head_sha: str) -> ProposalCandidate:
        with trusted_c02_execution() as temp_root:
            self._capsule_temp_root = temp_root
            try:
                desired, tree, source_id, repository_id = self._plan(request, request_class, accepted_base_sha)
            finally:
                self._capsule_temp_root = None
        changed = tuple(sorted(path for path, (mode, data) in desired.items() if mode == "" or tree.get(path, (None, None, None))[0:2] != (mode, "blob") or (mode != "" and self.client.get_blob(self.central_repository, tree[path][2]) != data)))
        if not changed:
            return ProposalCandidate(
                accepted_base_sha,
                accepted_base_sha,
                (),
                request_class,
                source_id,
                repository_id,
                False,
            )
        if request_class in {RequestClass.UPDATE, RequestClass.REMOVE} and "federation.json" not in changed:
            raise R02Error(_LEGACY_UPDATE_REMOVE_NO_FEDERATION_ERROR)
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
        bot_timestamp = self.client.bot_commit_timestamp_after(self.central_repository, accepted_base_sha)
        commit = self.client.create_commit(self.central_repository, f"Swift Stream federation {request_class.value}\n", tree_object.sha, [accepted_base_sha], timestamp=bot_timestamp)
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
        bot_timestamp = self.client.bot_commit_timestamp_after(self.central_repository, accepted_base_sha)
        commit = self.client.create_commit(self.central_repository, "Swift Stream federation machine publication\n", tree_object.sha, [accepted_base_sha], timestamp=bot_timestamp)
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

    def current_issue_source_authority(self, request: Request, request_class: RequestClass) -> IssueSourceAuthority:
        """Resolve fresh Issue source identity only from the exact trusted accepted main."""
        repository, current_main = self.current_accepted_main()
        if repository.default_branch != "main":
            raise StaleAuthorityError("managed Issue source authority requires central default branch main")
        try:
            with trusted_c02_execution():
                if c02.head_commit_oid() != current_main:
                    raise StaleTrustedCheckoutError("TRUSTED_CHECKOUT_CODE_STALE")
                accepted_manifest = c02.load_trusted_previous_manifest()
                source_metadata = read_public_source_metadata(_source_locator(request))
                return resolve_issue_source_authority(
                    request, request_class, accepted_manifest, source_metadata,
                )
        except (StaleTrustedCheckoutError, StaleAuthorityError):
            raise
        except Exception as error:
            raise R02Error(f"fresh Issue source authority is unavailable: {_bounded_reason(error)}") from None

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
        pr, anchor, fold, comments = self.interactive_anchor_and_reconstruct(pr_number, RequestClass.RECONCILE)
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

    def anchor_and_reconstruct_existing(self, pr_number: int, request_class: RequestClass, semantic_validator: Callable[[Request], bool] | None = None) -> tuple[PullRequestMetadata, AnchorComment, PatchFoldResult, tuple[IssueComment, ...]]:
        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        require_same_repository_head(pr, self.central_repository)
        _raise_if_reserved_issue_pr(pr)
        comments = self.client.list_issue_comments(self.central_repository, pr.number)
        anchor = validate_unique_anchor(comments, pr, request_class, self.app)
        return pr, anchor, reconstruct_from_github(self.client, self.central_repository, pr, anchor, comments, semantic_validator), comments

    def interactive_anchor_and_reconstruct(self, pr_number: int, request_class: RequestClass, semantic_validator: Callable[[Request], bool] | None = None) -> tuple[PullRequestMetadata, AnchorComment, PatchFoldResult, tuple[IssueComment, ...]]:
        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        require_same_repository_head(pr, self.central_repository)
        _raise_if_reserved_issue_pr(pr)
        comments = self.client.list_issue_comments(self.central_repository, pr.number)
        if not _anchor_candidates(comments):
            create_anchor_once(self.client, self.central_repository, pr, request_class, self.app, comments)
            pr = self.client.get_pull_request_metadata(self.central_repository, pr.number)
            comments = self.client.list_issue_comments(self.central_repository, pr.number)
        anchor = validate_unique_anchor(comments, pr, request_class, self.app)
        return pr, anchor, reconstruct_from_github(self.client, self.central_repository, pr, anchor, comments, semantic_validator), comments

    def interactive_proposal(self, pr_number: int, request_class: RequestClass, accepted_base_sha: str, request_ref: str, *, semantic_validator: Callable[[Request], bool] | None = None) -> ProposalCandidate:
        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        require_same_repository_head(pr, self.central_repository)
        _raise_if_reserved_issue_pr(pr)
        if request_class not in MANUAL_CLASSES:
            raise R02Error("interactive proposal class is not an R02 manual class")
        if self.candidate_builder is None:
            raise R02Error("C02 candidate builder is not configured")
        repository, current_main = self.current_accepted_main()
        if accepted_base_sha != current_main:
            raise StaleAuthorityError("interactive proposal was not bound to current accepted main")
        pr, anchor, fold, comments = self.anchor_and_reconstruct_existing(pr_number, request_class, semantic_validator)
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

    def interactive_issue_managed_proposal(
        self,
        issue_number: int,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        *,
        semantic_validator: Callable[[Request], bool] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> IssueHeadClaim:
        """Advance one bound Issue PR through immutable claim, wrapper, and ref-CAS authority."""
        if not callable(source_authority_resolver):
            raise R02Error("a fresh Issue source-authority resolver is required")
        if self.candidate_builder is None:
            raise R02Error("C02 candidate builder is not configured")
        state, historical_ref, _historical_pr_comments, _historical_claims = _validate_managed_issue_head_history(
            self.client,
            self.central_repository,
            issue_number,
            self.app,
            source_authority_resolver,
        )
        self._require_no_issue_cancellation_fence(state, historical_ref)
        request_class = state.issue_anchor.anchor.request_class
        _ensure_managed_issue_pr_request_anchor(
            self.client, self.central_repository, state, request_class, self.app,
        )
        issue_comments = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
        pr_comments = tuple(self.client.list_issue_comments(self.central_repository, state.binding.pull_request_number))
        issue = self.client.get_issue_metadata(self.central_repository, issue_number)
        if issue.state != "open" or issue.is_pull_request:
            raise R02Error("managed Issue progression requires the exact open source Issue")
        fold, expected_projections = _fresh_issue_projection_set(
            self.client,
            self.central_repository,
            issue,
            state.issue_anchor,
            state.binding,
            issue_comments,
            pr_comments,
            self.app,
            semantic_validator,
        )
        try:
            fresh_source = source_authority_resolver(fold.request, request_class)
        except Exception as error:
            raise StaleAuthorityError(f"fresh ACTIVE_PRE_MERGE Issue source authority is unavailable: {_bounded_reason(error)}") from None
        _validate_issue_source_authority(state.issue_anchor.anchor, fresh_source)

        repository, current_main = self.current_accepted_main()
        if repository.node_id != state.binding.central_repository_node_id or repository.default_branch != "main":
            raise StaleAuthorityError("central repository identity/default branch changed during managed Issue progression")
        _main_meta, current_main_tree, _main_entries = _lease_tree_snapshot(
            self.client, self.central_repository, current_main,
        )
        branch_short = state.binding.branch_ref.removeprefix("refs/heads/")
        current_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if current_ref is None or current_ref != historical_ref:
            raise StaleAuthorityError("bound Issue branch ref is absent")
        pr = self.client.get_pull_request_metadata(self.central_repository, state.binding.pull_request_number)
        if pr.head_oid != current_ref or pr.base_oid != current_main:
            raise StaleAuthorityError("bound Issue PR head/base does not match the fresh ref/main snapshot")
        pr_comments = tuple(self.client.list_issue_comments(self.central_repository, pr.number))
        _issue_pr_authority_fence(pr_comments, self.app)
        verified_fold, verified_projections = _fresh_issue_projection_set(
            self.client,
            self.central_repository,
            issue,
            state.issue_anchor,
            state.binding,
            issue_comments,
            pr_comments,
            self.app,
            semantic_validator,
        )
        if (
            verified_fold != fold
            or tuple(item.render() for item in verified_projections)
            != tuple(item.render() for item in expected_projections)
        ):
            raise StaleAuthorityError("Issue PATCH/projection snapshot changed before claim progression")
        authority_history = _issue_authority_history(
            self.client, self.central_repository, pr_comments, self.app, state, current_ref,
        )
        historical = tuple(
            IssueHeadClaimComment(node.artifact, node.comment, node.active)
            for node in authority_history if node.claim_kind == "ISSUE_HEAD_CLAIM"
        )
        active = tuple(item for item in historical if item.active)
        if len(active) > 1:
            raise R02Error("multiple distinct IssueHeadClaims are active at the same generated ref")
        pending = tuple(item for item in historical if item.claim.from_head_sha == current_ref and not item.active)
        if pending:
            # Crash replay: the stored target/evidence/nonce is authoritative. Do not
            # rebuild it from mutable PATCH comments or create a second CAS here.
            replay = min(pending, key=lambda item: item.comment.database_id).claim
            latest_state = _read_managed_issue_pr_binding_state(
                self.client, self.central_repository, issue_number, self.app,
                state.binding.central_repository_node_id, source_authority_resolver,
            )
            _require_same_managed_issue_pr_binding(state, latest_state)
            latest_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
            if latest_ref != current_ref or latest_state.pr.head_oid != current_ref:
                raise StaleAuthorityError("pending IssueHeadClaim ref/PR authority changed before crash replay")
            state = latest_state
            self._apply_persisted_issue_head_claim(state, replay, current_ref)
            return replay

        fold, expected_projections, issue_comments, pr_comments = _synchronize_issue_patch_projections(
            self.client,
            self.central_repository,
            issue,
            state.issue_anchor,
            state.binding,
            issue_comments,
            pr_comments,
            self.app,
            semantic_validator,
        )
        try:
            fresh_source = source_authority_resolver(fold.request, request_class)
        except Exception as error:
            raise StaleAuthorityError(f"fresh ACTIVE_PRE_MERGE Issue source authority is unavailable: {_bounded_reason(error)}") from None
        _validate_issue_source_authority(state.issue_anchor.anchor, fresh_source)
        projection_digest = issue_patch_projection_evidence_digest(expected_projections)
        request_digest = effective_request_digest(fold.request)

        # Projection writes do not grant trust authority. Rebind the active ref and
        # accepted main after those POSTs before choosing a new claimed transition.
        latest_state = _read_managed_issue_pr_binding_state(
            self.client, self.central_repository, issue_number, self.app,
            state.binding.central_repository_node_id, source_authority_resolver,
        )
        _require_same_managed_issue_pr_binding(state, latest_state)
        state = latest_state
        repository, current_main = self.current_accepted_main()
        if repository.node_id != state.binding.central_repository_node_id or repository.default_branch != "main":
            raise StaleAuthorityError("central repository identity/default branch changed during projection synchronization")
        _main_meta, current_main_tree, main_entries = _lease_tree_snapshot(
            self.client, self.central_repository, current_main,
        )
        try:
            fresh_source = source_authority_resolver(fold.request, request_class)
        except Exception as error:
            raise StaleAuthorityError(f"fresh ACTIVE_PRE_MERGE Issue source authority is unavailable: {_bounded_reason(error)}") from None
        _validate_issue_source_authority(state.issue_anchor.anchor, fresh_source)
        current_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if current_ref is None:
            raise StaleAuthorityError("bound Issue branch ref disappeared during projection synchronization")
        pr = self.client.get_pull_request_metadata(self.central_repository, state.binding.pull_request_number)
        if pr.head_oid != current_ref or pr.base_oid != current_main:
            raise StaleAuthorityError("bound Issue PR/ref/main changed during projection synchronization")
        pr_comments = tuple(self.client.list_issue_comments(self.central_repository, pr.number))
        _issue_pr_authority_fence(pr_comments, self.app)
        verified_fold, verified_projections = _fresh_issue_projection_set(
            self.client,
            self.central_repository,
            issue,
            state.issue_anchor,
            state.binding,
            issue_comments,
            pr_comments,
            self.app,
            semantic_validator,
            require_complete=True,
        )
        if (
            verified_fold != fold
            or tuple(item.render() for item in verified_projections)
            != tuple(item.render() for item in expected_projections)
        ):
            raise StaleAuthorityError("Issue PATCH/projection snapshot changed before claim progression")
        authority_history = _issue_authority_history(
            self.client, self.central_repository, pr_comments, self.app, state, current_ref,
        )
        historical = tuple(
            IssueHeadClaimComment(node.artifact, node.comment, node.active)
            for node in authority_history if node.claim_kind == "ISSUE_HEAD_CLAIM"
        )
        active = tuple(item for item in historical if item.active)
        if len(active) > 1:
            raise R02Error("multiple distinct IssueHeadClaims are active at the same generated ref")
        pending = tuple(item for item in historical if item.claim.from_head_sha == current_ref and not item.active)
        if pending:
            replay = min(pending, key=lambda item: item.comment.database_id).claim
            latest_state = _read_managed_issue_pr_binding_state(
                self.client, self.central_repository, issue_number, self.app,
                state.binding.central_repository_node_id, source_authority_resolver,
            )
            _require_same_managed_issue_pr_binding(state, latest_state)
            latest_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
            if latest_ref != current_ref or latest_state.pr.head_oid != current_ref:
                raise StaleAuthorityError("pending IssueHeadClaim ref/PR authority changed before crash replay")
            state = latest_state
            self._apply_persisted_issue_head_claim(state, replay, current_ref)
            return replay

        current_authority = next(
            (node for node in authority_history if node.target_head_sha == current_ref), None,
        )
        if current_authority is None:
            compatibility_claims = _issue_head_claim_comments(
                self.client, self.central_repository, pr_comments, self.app, state, current_ref,
            )
            compatibility_claim = next((item for item in compatibility_claims if item.active), None)
            if compatibility_claim is not None:
                current_authority = _IssueAuthorityNode(
                    "ISSUE_HEAD_CLAIM", CarrierRole.ISSUE_ACTIVE,
                    compatibility_claim.claim.to_head_sha, compatibility_claim.claim.from_head_sha,
                    compatibility_claim.claim.to_tree_sha, compatibility_claim.claim.transition_kind,
                    compatibility_claim.claim.claim_id, _binding_comment_sha256(compatibility_claim.comment),
                    compatibility_claim.comment, compatibility_claim.claim, active=True,
                    proposal_origin=(compatibility_claim if compatibility_claim.claim.transition_kind != "NORMALIZE" else None),
                )
        if current_authority is None:
            raise StaleAuthorityError("current Issue ref has no active unified Issue authority")
        if current_authority.claim_kind == "ISSUE_HEAD_CLAIM":
            active_claim = current_authority.artifact
        elif current_authority.claim_kind == "REQUIRED_STATUS_EPOCH":
            origin = current_authority.proposal_origin
            active_claim = origin.artifact if origin is not None else None
        else:
            active_claim = None
        if active_claim is None:
            if current_authority.claim_kind == "ISSUE_BRANCH_LEASE":
                transition = (
                    "PROPOSAL"
                    if current_main == state.lease.lease.accepted_base_sha
                    else "NORMALIZE"
                )
            else:
                transition = (
                    "PROPOSAL"
                    if current_main == state.lease.lease.accepted_base_sha
                    else "MAIN_ADVANCE"
                )
        else:
            transition = classify_issue_head_claim_progression(
                active_claim,
                fresh_effective_request_digest=request_digest,
                fresh_patch_projection_evidence_digest=projection_digest,
                fresh_accepted_base_sha=current_main,
                fresh_accepted_base_tree_sha=current_main_tree,
                proposal_exists=active_claim.transition_kind != "NORMALIZE",
            )
            if transition is None:
                return active_claim

        candidate = _plan_issue_managed_candidate(
            self.candidate_builder, fold.request, request_class, current_main, current_ref,
        )
        if candidate.marker_present:
            raise CandidateScopeError("claimed proposal candidate must remove the transient request marker")
        validate_proposal_scope(request_class, candidate.changed_paths)
        candidate_meta, candidate_tree, candidate_entries = _lease_tree_snapshot(
            self.client, self.central_repository, candidate.commit_sha,
        )
        if candidate_meta.parents != (current_main,):
            raise CandidateScopeError("raw C02 candidate parent must be the exact accepted main")
        actual_changed, target_entries = _proposal_tree_evidence(
            self.client, self.central_repository, main_entries, candidate_entries,
        )
        if actual_changed != candidate.changed_paths:
            raise CandidateScopeError("raw C02 candidate tree does not match its exact changed_paths")
        if REQUEST_MARKER in _lease_leaf_map(candidate_entries):
            raise CandidateScopeError("raw C02 candidate retains the transient Issue request marker")

        from_meta, from_tree, _from_entries = _lease_tree_snapshot(
            self.client, self.central_repository, current_ref,
        )
        if from_meta.sha != current_ref:
            raise R02Error("current Issue ref commit identity changed")
        if transition == "NORMALIZE":
            request_bytes = (request_class.value + "\n").encode("utf-8")
            blob = self.client.create_blob(self.central_repository, base64.b64encode(request_bytes).decode("ascii"))
            expected_blob_sha = hashlib.sha1(
                b"blob " + str(len(request_bytes)).encode("ascii") + b"\0" + request_bytes
            ).hexdigest()
            if blob.sha != expected_blob_sha:
                raise R02Error("NORMALIZE request marker blob SHA does not bind the exact request class")
            created_tree_sha = self.client.create_tree(
                self.central_repository,
                current_main_tree,
                [{"path": REQUEST_MARKER, "mode": "100644", "type": "blob", "sha": blob.sha}],
            ).sha
            target_tree, target_entries = self.client.get_tree(
                self.central_repository, created_tree_sha,
            )
            if target_tree != created_tree_sha:
                raise R02Error("NORMALIZE tree readback identity does not match the created tree")
            _validate_marker_only_tree_delta(main_entries, target_entries, expected_blob_sha)
            target_digest = normalize_target_evidence_digest(
                request_class=request_class,
                request_marker_blob_sha=expected_blob_sha,
                target_tree_sha=target_tree,
            )
        else:
            target_tree = candidate_tree
            target_entries = candidate_entries
            target_digest = proposal_target_evidence_digest(
                candidate_tree_sha=target_tree,
                changed=target_entries,
                candidate_changed_paths=actual_changed,
            )

        nonce = (nonce_factory or new_carrier_nonce)()
        if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce):
            raise R02Error("IssueHeadClaim nonce must be lowercase 256-bit hex")
        common = dict(
            schema_version=1,
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=_binding_comment_sha256(state.lease.comment),
            binding_id=state.binding.binding_id,
            source_id=state.issue_anchor.anchor.source_id,
            source_repository_id=state.issue_anchor.anchor.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=request_class,
            accepted_base_sha=current_main,
            accepted_base_tree_sha=current_main_tree,
            from_head_sha=current_ref,
            from_tree_sha=from_tree,
            to_head_sha="0" * 40,
            to_tree_sha=target_tree,
            transition_kind=transition,
            carrier_nonce=nonce,
            effective_request_digest=request_digest,
            patch_projection_evidence_digest=projection_digest,
            target_evidence_digest=target_digest,
        )
        prepared = IssueHeadClaim.create(**common)
        marker_text = _issue_head_claim_marker(prepared).render()
        timestamp = self.client.bot_commit_timestamp_after(self.central_repository, current_ref)
        wrapper = self.client.create_commit(
            self.central_repository, marker_text, target_tree, [current_ref], timestamp=timestamp,
        )
        final = IssueHeadClaim.create(**{**common, "to_head_sha": wrapper.sha})
        _validate_issue_head_claim_target(self.client, self.central_repository, final, state.lease.lease)
        self._persist_issue_head_claim(state, final)
        latest_state = _read_managed_issue_pr_binding_state(
            self.client, self.central_repository, issue_number, self.app,
            state.binding.central_repository_node_id, source_authority_resolver,
        )
        _require_same_managed_issue_pr_binding(state, latest_state)
        latest_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if latest_ref != current_ref or latest_state.pr.head_oid != current_ref:
            raise StaleAuthorityError("Issue ref/PR head changed after claim persistence; stored claim remains historical")
        state = latest_state
        self._apply_persisted_issue_head_claim(state, final, current_ref)
        return final

    def validate_issue_managed_head_history(
        self,
        issue_number: int,
    ) -> tuple[IssuePRBindingState, str, tuple[IssueHeadClaimComment, ...]]:
        """Read-only history/provenance gate for the pre-green trusted-validation route."""
        state, current_ref, _comments, claims = _validate_managed_issue_head_history(
            self.client,
            self.central_repository,
            issue_number,
            self.app,
            lambda _request, _request_class: None,  # Deliberately not used in historical validation.
        )
        return state, current_ref, claims

    def interactive_issue_managed_route(
        self,
        issue_number: int,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        *,
        semantic_validator: Callable[[Request], bool] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> IssueManagedRouteResult:
        """Dedicated Wave 04 route boundary; semantic no-change is an exact NOOP."""
        try:
            claim = self.interactive_issue_managed_proposal(
                issue_number,
                source_authority_resolver,
                semantic_validator=semantic_validator,
                nonce_factory=nonce_factory,
            )
        except IssueManagedNoSemanticChange as error:
            return IssueManagedRouteResult("NOOP", error.reason, error.request_class)
        return IssueManagedRouteResult("CLAIM_READY", claim.transition_kind, claim.request_class)

    def _persist_issue_head_claim(self, state: IssuePRBindingState, claim: IssueHeadClaim) -> IssueHeadClaimComment:
        self._require_no_issue_cancellation_fence(state, claim.from_head_sha)
        body = claim.render()
        if len(body.encode("utf-8")) > 16_384:
            raise R02Error("IssueHeadClaim comment exceeds the generic Issue-comment bound")
        try:
            self.client.create_issue_comment(self.central_repository, state.binding.pull_request_number, body)
        except GitHubAPIError as error:
            try:
                comments = tuple(self.client.list_issue_comments(self.central_repository, state.binding.pull_request_number))
                current_ref = _read_issue_branch_ref(
                    self.client, self.central_repository,
                    state.binding.branch_ref.removeprefix("refs/heads/"),
                )
                _issue_head_claim_comments(self.client, self.central_repository, comments, self.app, state, current_ref or ZERO_OID)
            except Exception as read_error:
                raise StaleAuthorityError(f"ambiguous IssueHeadClaim POST could not be diagnosed: {_bounded_reason(read_error)}") from None
            raise StaleAuthorityError(f"ambiguous IssueHeadClaim POST; stop and reread on a later invocation: {_bounded_reason(error)}") from None
        try:
            comments = tuple(self.client.list_issue_comments(self.central_repository, state.binding.pull_request_number))
            current_ref = _read_issue_branch_ref(
                self.client, self.central_repository,
                state.binding.branch_ref.removeprefix("refs/heads/"),
            )
            claims = _issue_head_claim_comments(
                self.client, self.central_repository, comments, self.app, state, current_ref or ZERO_OID,
            )
        except Exception as error:
            raise StaleAuthorityError(f"persisted IssueHeadClaim could not be reread: {_bounded_reason(error)}") from None
        matches = [item for item in claims if item.claim.render() == body]
        if not matches:
            raise StaleAuthorityError("persisted IssueHeadClaim is absent or differs from the exact intended payload")
        return min(matches, key=lambda item: item.comment.database_id)

    def _apply_persisted_issue_head_claim(
        self,
        state: IssuePRBindingState,
        claim: IssueHeadClaim,
        expected_ref: str,
    ) -> None:
        self._require_no_issue_cancellation_fence(state, expected_ref)
        branch_short = state.binding.branch_ref.removeprefix("refs/heads/")
        before = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if before == claim.to_head_sha:
            return
        if before != expected_ref or before != claim.from_head_sha:
            raise StaleAuthorityError("persisted IssueHeadClaim lost its exact from-head ref CAS")
        try:
            self.client.update_refs(
                state.binding.central_repository_node_id,
                [RefUpdate(state.binding.branch_ref, before, claim.to_head_sha, force=False)],
            )
        except (RefCASConflict, GitHubAPIError) as error:
            after = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
            try:
                comments = tuple(self.client.list_issue_comments(self.central_repository, state.binding.pull_request_number))
                _issue_head_claim_comments(self.client, self.central_repository, comments, self.app, state, after or ZERO_OID)
            except Exception as read_error:
                raise StaleAuthorityError(f"ambiguous IssueHeadClaim CAS cannot be diagnosed: {_bounded_reason(read_error)}") from None
            if after == claim.to_head_sha:
                return
            raise StaleAuthorityError(f"IssueHeadClaim CAS did not reach its exact target; claim remains historical: {_bounded_reason(error)}") from None
        after = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if after != claim.to_head_sha:
            raise StaleAuthorityError("IssueHeadClaim CAS did not read back the exact target head")

    def _read_issue_epoch_snapshot(
        self,
        issue_number: int,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        semantic_validator: Callable[[Request], bool] | None,
        *,
        allow_source_mismatch: bool = False,
        allow_base_mismatch: bool = False,
    ) -> _IssueEpochSnapshot:
        if not callable(source_authority_resolver):
            raise R02Error("a fresh Issue source-authority resolver is required")
        repository, accepted_main = self.current_accepted_main()
        if (
            repository.full_name != self.central_repository
            or repository.default_branch != "main"
            or type(repository.node_id) is not str
            or not repository.node_id
        ):
            raise StaleAuthorityError("central repository identity/default branch is not the exact accepted main")
        state = _read_managed_issue_pr_binding_state(
            self.client, self.central_repository, issue_number, self.app,
            repository.node_id, lambda _request, _request_class: None,
            validate_fresh_source_authority=False,
        )
        if state.binding.central_repository_node_id != repository.node_id:
            raise StaleAuthorityError("managed Issue binding belongs to a different central repository identity")
        issue = self.client.get_issue_metadata(self.central_repository, issue_number)
        issue_comments = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
        pr_comments = tuple(self.client.list_issue_comments(self.central_repository, state.binding.pull_request_number))
        if (
            issue.number != state.owning_issue.number
            or issue.database_id != state.owning_issue.database_id
            or issue.node_id != state.owning_issue.node_id
            or issue.is_pull_request
            or issue.state != "open"
        ):
            raise StaleAuthorityError("owning Issue identity or lifecycle changed during epoch validation")
        fold, projections = _fresh_issue_projection_set(
            self.client, self.central_repository, issue, state.issue_anchor, state.binding,
            issue_comments, pr_comments, self.app, semantic_validator,
            require_complete=not allow_source_mismatch,
        )
        fresh_source: IssueSourceAuthority | None = None
        source_error: str | None = None
        try:
            fresh_source = source_authority_resolver(fold.request, state.issue_anchor.anchor.request_class)
        except Exception as error:
            source_error = f"UNAVAILABLE:{_bounded_reason(error)}"
        else:
            try:
                _validate_issue_source_authority(state.issue_anchor.anchor, fresh_source)
            except Exception as error:
                source_error = f"MISMATCH:{_bounded_reason(error)}"
        if source_error is not None and not allow_source_mismatch:
            raise StaleAuthorityError(
                f"fresh Issue source authority is unavailable or changed: {source_error}"
            ) from None

        main_meta, main_tree, main_entries = _lease_tree_snapshot(
            self.client, self.central_repository, accepted_main,
        )
        if main_meta.sha != accepted_main:
            raise StaleAuthorityError("accepted central main commit identity changed")
        branch_short = state.binding.branch_ref.removeprefix("refs/heads/")
        current_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        pr = self.client.get_pull_request_metadata(self.central_repository, state.binding.pull_request_number)
        if (
            current_ref is None
            or current_ref != pr.head_oid
            or (not allow_base_mismatch and pr.base_oid != accepted_main)
            or pr.base_ref != repository.default_branch
            or state.pr.head_oid != pr.head_oid
            or state.pr.base_oid != pr.base_oid
            or state.pr_issue.state != "open"
        ):
            raise StaleAuthorityError("bound Issue PR/ref/base is not the exact current accepted snapshot")
        _issue_pr_authority_fence(pr_comments, self.app)
        history = _issue_authority_history(
            self.client, self.central_repository, pr_comments, self.app, state, current_ref,
        )
        current_nodes = tuple(node for node in history if node.target_head_sha == current_ref)
        if len(current_nodes) != 1:
            raise StaleAuthorityError("current Issue ref has no unique validated authority node")
        current_authority = current_nodes[0]
        marker = (
            _issue_head_claim_marker(current_authority.artifact)
            if current_authority.claim_kind == "ISSUE_HEAD_CLAIM"
            else _required_status_epoch_marker(current_authority.artifact)
            if current_authority.claim_kind == "REQUIRED_STATUS_EPOCH"
            else _issue_finalization_epoch_marker(current_authority.artifact)
            if current_authority.claim_kind == "ISSUE_FINALIZATION_EPOCH"
            else _lease_marker_for(current_authority.artifact)
        )
        resolution = resolve_sha_carrier_role(
            self.client,
            self.central_repository,
            current_ref,
            self.app.slug,
            LegacyEvidenceDisposition.CONFLICTING,
        )
        if (
            resolution.activation is not CarrierActivation.ACTIVE
            or resolution.role is not current_authority.role
            or resolution.marker != marker
        ):
            raise StaleAuthorityError("current Issue head is not ACTIVE under the real SHA-global resolver")
        return _IssueEpochSnapshot(
            state, repository, accepted_main, main_tree, main_entries, current_ref,
            issue, issue_comments, pr_comments, fold, projections, fresh_source,
            source_error, history, current_authority, resolution,
        )

    def _derive_issue_proposal_scope(
        self,
        snapshot: _IssueEpochSnapshot,
        proposal_head_sha: str,
        proposal_origin: _IssueAuthorityNode,
    ) -> tuple[str, str, str]:
        if type(proposal_origin.artifact) is not IssueHeadClaim or proposal_origin.transition_kind == "NORMALIZE":
            raise R02Error("finalizer authority requires a proposal-bearing IssueHeadClaim origin")
        if self.candidate_builder is None:
            raise R02Error("fresh C02 proposal candidate builder is unavailable")
        request_class = snapshot.state.issue_anchor.anchor.request_class
        request_digest = effective_request_digest(snapshot.fold.request)
        projection_digest = issue_patch_projection_evidence_digest(snapshot.projections)
        candidate = _plan_issue_managed_candidate(
            self.candidate_builder,
            snapshot.fold.request,
            request_class,
            snapshot.accepted_main_sha,
            proposal_head_sha,
        )
        candidate_meta, candidate_tree, candidate_entries = _lease_tree_snapshot(
            self.client, self.central_repository, candidate.commit_sha,
        )
        if candidate_meta.parents != (snapshot.accepted_main_sha,):
            raise CandidateScopeError("fresh finalizer candidate is not an exact child of accepted main")
        actual_changed, candidate_evidence = _proposal_tree_evidence(
            self.client, self.central_repository,
            snapshot.accepted_main_entries, candidate_entries,
        )
        if actual_changed != candidate.changed_paths:
            raise CandidateScopeError("fresh finalizer candidate changed paths do not match its Git tree")
        validate_proposal_scope(request_class, actual_changed)
        if REQUEST_MARKER in _lease_leaf_map(candidate_entries):
            raise CandidateScopeError("fresh finalizer candidate retains the transient Issue request marker")
        target_meta, target_tree, target_entries = _lease_tree_snapshot(
            self.client, self.central_repository, proposal_head_sha,
        )
        if target_meta.sha != proposal_head_sha or target_tree != candidate_tree:
            raise CandidateScopeError("current proposal head tree differs from the freshly built accepted-base candidate")
        actual_target_changed, target_evidence = _proposal_tree_evidence(
            self.client, self.central_repository,
            snapshot.accepted_main_entries, target_entries,
        )
        if actual_target_changed != actual_changed:
            raise CandidateScopeError("current proposal head changed-path scope differs from the fresh candidate")
        candidate_digest = proposal_target_evidence_digest(
            candidate_tree_sha=candidate_tree,
            changed=candidate_evidence,
            candidate_changed_paths=actual_changed,
        )
        target_digest = proposal_target_evidence_digest(
            candidate_tree_sha=target_tree,
            changed=target_evidence,
            candidate_changed_paths=actual_target_changed,
        )
        origin_claim = proposal_origin.artifact
        if (
            candidate_digest != target_digest
            or target_digest != origin_claim.target_evidence_digest
            or request_digest != origin_claim.effective_request_digest
            or projection_digest != origin_claim.patch_projection_evidence_digest
        ):
            raise StaleAuthorityError("fresh request/projection/proposal evidence differs from the proposal-origin claim")
        return target_digest, request_digest, projection_digest

    def _persist_issue_epoch_artifact(
        self,
        state: IssuePRBindingState,
        artifact: IssueFinalizationEpoch | RequiredStatusEpoch,
        expected_ref: str,
    ) -> IssueComment:
        self._require_no_issue_cancellation_fence(state, expected_ref)
        body = artifact.render()
        if len(body.encode("utf-8")) > 16_384:
            raise R02Error("Issue epoch comment exceeds the generic Issue-comment bound")
        try:
            self.client.create_issue_comment(
                self.central_repository, state.binding.pull_request_number, body,
            )
        except Exception as error:
            # An ambiguous POST is diagnosed, then left for a later invocation to
            # replay. It never creates a replacement target in this invocation.
            try:
                comments = tuple(self.client.list_issue_comments(
                    self.central_repository, state.binding.pull_request_number,
                ))
                _issue_authority_history(
                    self.client, self.central_repository, comments, self.app, state, expected_ref,
                )
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous Issue epoch POST could not be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            raise StaleAuthorityError(
                f"ambiguous Issue epoch POST; exact artifact is reserved for a later invocation: {_bounded_reason(error)}"
            ) from None
        try:
            comments = tuple(self.client.list_issue_comments(
                self.central_repository, state.binding.pull_request_number,
            ))
            history = _issue_authority_history(
                self.client, self.central_repository, comments, self.app, state, expected_ref,
            )
        except Exception as error:
            raise StaleAuthorityError(f"persisted Issue epoch could not be validated: {_bounded_reason(error)}") from None
        marker = (
            ISSUE_FINALIZATION_EPOCH_MARKER
            if type(artifact) is IssueFinalizationEpoch else REQUIRED_STATUS_EPOCH_MARKER
        )
        matches = [
            node.comment for node in history
            if node.comment.body.startswith(marker)
            and node.artifact == artifact
            and node.artifact_sha256 == hashlib.sha256(body.encode("utf-8")).hexdigest()
        ]
        if not matches:
            raise StaleAuthorityError("persisted Issue epoch is absent or differs from the exact intended payload")
        return min(matches, key=lambda item: item.database_id)

    def _apply_persisted_issue_epoch_target(
        self,
        state: IssuePRBindingState,
        from_head_sha: str,
        target_head_sha: str,
        expected_ref: str,
    ) -> None:
        self._require_no_issue_cancellation_fence(state, expected_ref)
        branch_short = state.binding.branch_ref.removeprefix("refs/heads/")
        before = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if before == target_head_sha:
            return
        if before != expected_ref or before != from_head_sha:
            raise StaleAuthorityError("persisted Issue epoch lost its exact from-head ref CAS")
        try:
            self.client.update_refs(
                state.binding.central_repository_node_id,
                [RefUpdate(state.binding.branch_ref, before, target_head_sha, force=False)],
            )
        except (RefCASConflict, GitHubAPIError) as error:
            after = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
            try:
                comments = tuple(self.client.list_issue_comments(
                    self.central_repository, state.binding.pull_request_number,
                ))
                _issue_authority_history(
                    self.client, self.central_repository, comments, self.app, state, after or ZERO_OID,
                )
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous Issue epoch CAS cannot be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            if after == target_head_sha:
                return
            raise StaleAuthorityError(
                f"Issue epoch CAS did not reach its exact target; target remains historical: {_bounded_reason(error)}"
            ) from None
        after = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if after != target_head_sha:
            raise StaleAuthorityError("Issue epoch CAS did not read back the exact target head")

    def _require_no_issue_cancellation_fence(
        self,
        state: IssuePRBindingState,
        current_ref: str,
        comments: Iterable[IssueComment] | None = None,
    ) -> None:
        if comments is not None:
            # _read_issue_epoch_snapshot has already validated these exact
            # comments through the unified provenance reader.
            if any(
                type(comment.body) is str
                and comment.body.startswith(ISSUE_CANCELLATION_FENCE_MARKER)
                for comment in comments
            ):
                raise StaleAuthorityError("persisted IssueCancellationFence is a one-way gate for non-cancellation progression")
            return
        fresh_comments = tuple(
            self.client.list_issue_comments(self.central_repository, state.binding.pull_request_number)
        )
        if any(
            type(comment.body) is str
            and comment.body.startswith(ISSUE_CANCELLATION_FENCE_MARKER)
            for comment in fresh_comments
        ):
            raise StaleAuthorityError("persisted IssueCancellationFence is a one-way gate for non-cancellation progression")

    def _read_issue_cancellation_fences(
        self,
        authority: _IssueCancellationAuthority,
        current_ref: str,
    ) -> tuple[tuple[IssueCancellationFenceComment, ...], tuple[IssueComment, ...]]:
        comments = tuple(self.client.list_issue_comments(
            self.central_repository, authority.pull_request_number,
        ))
        _issue_pr_authority_fence(comments, self.app, allow_cancellation_fence=True)
        fences = _issue_cancellation_fence_comments(
            self.client, self.central_repository, comments, self.app, authority, current_ref,
        )
        if authority.binding_authority == "FULL_BINDING":
            if authority.binding_state is None:
                raise R02Error("FULL_BINDING cancellation history lost its exact binding state")
            history = _issue_authority_history(
                self.client, self.central_repository, comments, self.app,
                authority.binding_state, current_ref,
            )
            for item in fences:
                if sum(
                    node.claim_kind == "ISSUE_CANCELLATION_FENCE"
                    and node.artifact == item.fence
                    and node.comment.database_id == item.comment.database_id
                    for node in history
                ) != 1:
                    raise R02Error("persisted full-binding fence is not reachable from exact unified history")
        return fences, comments

    def _persist_issue_cancellation_fence(
        self,
        authority: _IssueCancellationAuthority,
        fence: IssueCancellationFence,
        expected_ref: str,
    ) -> IssueCancellationFenceComment:
        body = fence.render()
        existing, _existing_comments = self._read_issue_cancellation_fences(
            authority, expected_ref,
        )
        matches = tuple(item for item in existing if item.fence.render() == body)
        if matches:
            if len(matches) != 1:
                raise R02Error("equivalent cancellation fence comments did not collapse to one canonical record")
            return matches[0]
        try:
            self.client.create_issue_comment(
                self.central_repository, authority.pull_request_number, body,
            )
        except Exception as error:
            # An ambiguous POST is usable only when exact readback proves that
            # this same immutable fence was persisted.
            try:
                fences, _comments = self._read_issue_cancellation_fences(authority, expected_ref)
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous cancellation-fence POST cannot be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            matches = tuple(item for item in fences if item.fence.render() == body)
            if len(matches) == 1:
                return matches[0]
            raise StaleAuthorityError(
                f"cancellation-fence POST was not confirmed by exact readback: {_bounded_reason(error)}"
            ) from None
        fences, _comments = self._read_issue_cancellation_fences(authority, expected_ref)
        matches = tuple(item for item in fences if item.fence.render() == body)
        if len(matches) != 1:
            raise StaleAuthorityError("persisted cancellation fence is absent or differs from the exact intended payload")
        return matches[0]

    def prepare_issue_cancellation_fence(
        self,
        issue_number: int,
        *,
        classification: str | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> IssueCancellationFence:
        """Persist and activate one immutable D/E cancellation fence; publish no status."""
        if type(issue_number) is not int or not 1 <= issue_number <= 9_223_372_036_854_775_807:
            raise R02Error("cancellation Issue number must be a positive signed-64 integer")
        authority = _fresh_issue_cancellation_authority(
            self.client, self.central_repository, issue_number, self.app,
            require_prebinding_lease_root=True,
        )
        expected_classification = "D" if authority.binding_authority == "PRE_BINDING" else "E"
        if classification is not None and classification != expected_classification:
            raise R02Error("cancellation fence accepts only the exact PR-backed D/E classification")
        if authority.owning_issue.state != "closed":
            raise R02Error("PR-backed cancellation fence requires a terminal closed owning Issue")
        if authority.raw_pr_merged:
            raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED")
        if authority.raw_pr_state != "OPEN" or authority.pr_issue.state != "open":
            raise R02Error("new cancellation fence requires the exact open unmerged generated PR")
        branch_short = authority.lease.lease.branch_ref.removeprefix("refs/heads/")
        original_head_sha = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if original_head_sha is None or authority.pr.head_oid != original_head_sha:
            raise StaleAuthorityError("cancellation requires the exact current generated ref and PR head")
        if authority.binding_authority == "PRE_BINDING" and original_head_sha != authority.lease.lease.initial_head_sha:
            raise R02Error("PRE_BINDING cancellation must originate from the exact lease-root head")
        original = _resolve_issue_cancellation_original_node(
            self.client, self.central_repository, authority, self.app, original_head_sha,
        )
        if (original.claim_kind, original.role) not in {
            ("ISSUE_BRANCH_LEASE", CarrierRole.ISSUE_ACTIVE),
            ("ISSUE_HEAD_CLAIM", CarrierRole.ISSUE_ACTIVE),
            ("REQUIRED_STATUS_EPOCH", CarrierRole.ISSUE_ACTIVE),
            ("ISSUE_FINALIZATION_EPOCH", CarrierRole.ISSUE_FINALIZING),
        }:
            raise R02Error("cancellation original authority has an unsupported exact kind/role")

        # Existing immutable evidence is inspected before taking a new status
        # snapshot or nonce. This makes crash replay reuse the original tuple.
        persisted, _comments = self._read_issue_cancellation_fences(authority, original_head_sha)
        fence: IssueCancellationFence | None = None
        if persisted:
            fence = persisted[0].fence
            if (
                fence.original_head_sha != original_head_sha
                or not _issue_cancellation_fence_predecessor_matches(original, fence)
                or fence.binding_authority != _cancellation_binding_authority_id(authority)
            ):
                raise StaleAuthorityError("persisted cancellation fence belongs to a different original authority")
            current_ref = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
            if current_ref == fence.cancellation_head_sha:
                resolution = resolve_sha_carrier_role(
                    self.client, self.central_repository, fence.cancellation_head_sha,
                    self.app.slug, LegacyEvidenceDisposition.CONFLICTING,
                )
                if resolution != ShaCarrierResolution(
                    CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL,
                    _issue_cancellation_fence_marker(fence),
                ):
                    raise StaleAuthorityError("persisted cancellation fence is not ACTIVE under the real resolver")
                return fence
            if current_ref != original_head_sha:
                raise StaleAuthorityError("persisted cancellation fence lost to a different generated ref head")
        else:
            current_ref = original_head_sha

        if fence is None:
            pre_fence_status, visible_issue_final_success, _any_exact_app_success, _latest_status = _read_latest_exact_app_required_status_snapshot(
                self.client, self.central_repository, original_head_sha, self.app,
            )
            success_may_exist = (
                original.role is CarrierRole.ISSUE_FINALIZING
                or visible_issue_final_success
                or (
                    pre_fence_status.is_present
                    and pre_fence_status.state == "success"
                    and pre_fence_status.status_class is StatusClass.ISSUE_FINAL
                )
            )
            # Fence read immediately before nonce generation closes the POST race.
            latest_persisted, _latest_comments = self._read_issue_cancellation_fences(
                authority, original_head_sha,
            )
            if latest_persisted:
                fence = latest_persisted[0].fence
                if (
                    fence.original_head_sha != original_head_sha
                    or fence.pre_fence_required_status != pre_fence_status
                    or not _issue_cancellation_fence_predecessor_matches(original, fence)
                ):
                    raise StaleAuthorityError("concurrent cancellation fence does not match this exact status/predecessor")
            else:
                nonce = (nonce_factory or new_carrier_nonce)()
                if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce):
                    raise R02Error("IssueCancellationFence nonce must be lowercase 256-bit hex")
                anchor = authority.issue_anchor
                lease = authority.lease
                fields = dict(
                    schema_version=1,
                    issue_number=anchor.anchor.issue_number,
                    issue_database_id=anchor.anchor.issue_database_id,
                    issue_node_id=anchor.anchor.issue_node_id,
                    issue_request_anchor_comment_database_id=anchor.comment.database_id,
                    issue_request_anchor_sha256=anchor.anchor.canonical_sha256(),
                    issue_branch_lease_comment_database_id=lease.comment.database_id,
                    issue_branch_lease_sha256=_binding_comment_sha256(lease.comment),
                    binding_authority=_cancellation_binding_authority_id(authority),
                    source_id=anchor.anchor.source_id,
                    source_repository_id=anchor.anchor.source_repository_id,
                    branch_ref=lease.lease.branch_ref,
                    pull_request_number=authority.pull_request_number,
                    pull_request_database_id=authority.pull_request_database_id,
                    pull_request_node_id=authority.pull_request_node_id,
                    central_repository_node_id=authority.central_repository_node_id,
                    base_repository_node_id=authority.base_repository_node_id,
                    base_ref="main",
                    original_head_sha=original_head_sha,
                    original_head_tree_sha=original.tree_sha,
                    original_head_claim_kind=original.claim_kind,
                    original_head_claim_role=original.role.value,
                    original_head_artifact_comment_database_id=original.comment.database_id,
                    original_head_artifact_id=original.artifact_id,
                    original_head_artifact_sha256=original.artifact_sha256,
                    cancellation_carrier_nonce=nonce,
                    cancellation_head_sha=("f" * 40 if original_head_sha != "f" * 40 else "e" * 40),
                    cancellation_head_tree_sha=original.tree_sha,
                    pre_fence_required_status=pre_fence_status,
                    pre_fence_success_may_exist=success_may_exist,
                )
                prepared = IssueCancellationFence.create(**fields)
                marker_text = _issue_cancellation_fence_marker(prepared).render()
                timestamp = self.client.bot_commit_timestamp_after(
                    self.central_repository, original_head_sha,
                )
                wrapper = self.client.create_commit(
                    self.central_repository, marker_text, original.tree_sha,
                    [original_head_sha], timestamp=timestamp,
                )
                fence = IssueCancellationFence.create(**{
                    **fields,
                    "cancellation_head_sha": wrapper.sha,
                })
                _validate_issue_cancellation_fence_target(
                    self.client, self.central_repository, fence,
                )

        assert fence is not None
        self._persist_issue_cancellation_fence(authority, fence, original_head_sha)
        latest_authority = _fresh_issue_cancellation_authority(
            self.client, self.central_repository, issue_number, self.app,
            require_prebinding_lease_root=True,
        )
        if (
            latest_authority.binding_authority != authority.binding_authority
            or latest_authority.issue_anchor.anchor != authority.issue_anchor.anchor
            or latest_authority.issue_anchor.comment.database_id != authority.issue_anchor.comment.database_id
            or latest_authority.lease.lease != authority.lease.lease
            or latest_authority.pull_request_number != authority.pull_request_number
            or latest_authority.pull_request_database_id != authority.pull_request_database_id
            or latest_authority.pull_request_node_id != authority.pull_request_node_id
            or latest_authority.binding != authority.binding
            or latest_authority.raw_pr_state != "OPEN"
            or latest_authority.raw_pr_merged
            or latest_authority.owning_issue.state != "closed"
        ):
            raise StaleAuthorityError("central cancellation ownership/PR lifecycle changed after fence persistence")
        before_cas = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if before_cas != original_head_sha or latest_authority.pr.head_oid != original_head_sha:
            raise StaleAuthorityError("cancellation fence was persisted but original ref/PR head changed before CAS")
        persisted_again, _comments = self._read_issue_cancellation_fences(
            latest_authority, original_head_sha,
        )
        if not persisted_again or persisted_again[0].fence != fence:
            raise StaleAuthorityError("exact persisted cancellation fence changed before ref exposure")
        _fresh_original = _resolve_issue_cancellation_original_node(
            self.client, self.central_repository, latest_authority, self.app, original_head_sha,
        )
        if not _issue_cancellation_fence_predecessor_matches(_fresh_original, fence):
            raise StaleAuthorityError("cancellation predecessor changed before ref exposure")

        update = RefUpdate(fence.branch_ref, original_head_sha, fence.cancellation_head_sha, force=False)
        try:
            self.client.update_refs(fence.central_repository_node_id, [update])
        except Exception as first_error:
            after_error = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
            if after_error == fence.cancellation_head_sha:
                pass
            elif after_error == original_head_sha:
                try:
                    # Retry only the byte-identical persisted target.
                    self.client.update_refs(fence.central_repository_node_id, [update])
                except Exception as second_error:
                    after_retry = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
                    if after_retry != fence.cancellation_head_sha:
                        raise StaleAuthorityError(
                            f"same-target cancellation CAS did not activate: {_bounded_reason(second_error)}"
                        ) from None
                else:
                    after_retry = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
                    if after_retry != fence.cancellation_head_sha:
                        raise StaleAuthorityError("same-target cancellation CAS did not read back exact HC")
            else:
                raise StaleAuthorityError(
                    f"cancellation CAS lost to a different ref head: {_bounded_reason(first_error)}"
                ) from None
        after_cas = _read_issue_branch_ref(self.client, self.central_repository, branch_short)
        if after_cas != fence.cancellation_head_sha:
            raise StaleAuthorityError("cancellation CAS did not read back exact cancellationHeadSha")
        final_authority = _fresh_issue_cancellation_authority(
            self.client, self.central_repository, issue_number, self.app,
        )
        if (
            final_authority.binding_authority != authority.binding_authority
            or final_authority.binding != authority.binding
            or final_authority.pr.head_oid != fence.cancellation_head_sha
            or final_authority.raw_pr_state != "OPEN"
            or final_authority.raw_pr_merged
        ):
            raise StaleAuthorityError("post-CAS cancellation PR/ownership readback is not the exact unmerged HC")
        final_resolution = resolve_sha_carrier_role(
            self.client, self.central_repository, fence.cancellation_head_sha,
            self.app.slug, LegacyEvidenceDisposition.CONFLICTING,
        )
        if final_resolution != ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL,
            _issue_cancellation_fence_marker(fence),
        ):
            raise StaleAuthorityError("cancellation HC is not ACTIVE under the real SHA-global resolver")
        return fence

    def publish_issue_cancel_failure(
        self,
        issue_number: int,
        fence: IssueCancellationFence,
    ) -> ExactAppRequiredStatusSnapshot:
        """Publish/reuse only the exact App failure tuple for an ACTIVE cancellation fence."""
        if type(fence) is not IssueCancellationFence or fence.issue_number != issue_number:
            raise R02Error("cancel status publication requires the exact IssueCancellationFence")
        authority = _fresh_issue_cancellation_authority(
            self.client, self.central_repository, issue_number, self.app,
        )
        current_ref = _read_issue_branch_ref(
            self.client, self.central_repository, fence.branch_ref.removeprefix("refs/heads/"),
        )
        fences, _comments = self._read_issue_cancellation_fences(authority, current_ref or ZERO_OID)
        if not fences or fences[0].fence != fence or current_ref != fence.cancellation_head_sha:
            raise StaleAuthorityError("cancel status requires the exact persisted current HC fence")
        if (
            _cancellation_binding_authority_id(authority) != fence.binding_authority
            or authority.pull_request_number != fence.pull_request_number
            or authority.pull_request_database_id != fence.pull_request_database_id
            or authority.pull_request_node_id != fence.pull_request_node_id
            or authority.pr.head_oid != fence.cancellation_head_sha
            or authority.raw_pr_state != "OPEN"
            or authority.raw_pr_merged
        ):
            raise StaleAuthorityError("cancel status requires exact current unmerged central PR authority")
        resolution = resolve_sha_carrier_role(
            self.client, self.central_repository, fence.cancellation_head_sha,
            self.app.slug, LegacyEvidenceDisposition.CONFLICTING,
        )
        if resolution != ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL,
            _issue_cancellation_fence_marker(fence),
        ):
            raise StaleAuthorityError("cancel status requires ACTIVE(ISSUE_CANCEL) under the real resolver")
        reused = _latest_exact_cancel_status_evidence(
            self.client, self.central_repository, fence, self.app,
        )
        if reused is not None:
            return reused
        repository = self.client.get_repository_metadata(self.central_repository)
        if (
            type(repository) is not RepositoryMetadata
            or repository.full_name != self.central_repository
            or repository.node_id != fence.central_repository_node_id
        ):
            raise StaleAuthorityError("cancel status central repository identity changed")
        digest = cancel_status_evidence_digest(
            central_repository_node_id=repository.node_id,
            issue_number=fence.issue_number,
            issue_database_id=fence.issue_database_id,
            issue_node_id=fence.issue_node_id,
            fence_id=fence.fence_id,
            cancellation_head_sha=fence.cancellation_head_sha,
            binding_authority=fence.binding_authority,
            pull_request_number=fence.pull_request_number,
            pull_request_database_id=fence.pull_request_database_id,
            pull_request_node_id=fence.pull_request_node_id,
        )
        description = render_status_description(StatusClass.CANCEL, digest)
        if len(description.encode("ascii")) != 81:
            raise R02Error("canonical cancel description must be exactly 81 ASCII bytes")
        receipt = self.client.create_commit_status(
            self.central_repository,
            fence.cancellation_head_sha,
            "failure",
            "federation/trusted-validation",
            description,
            None,
        )
        status = _validate_issue_cancel_status_receipt(receipt, repository, fence, self.app)
        return _snapshot_required_status_row(status, fence.cancellation_head_sha)

    def _fresh_cancellation_fence_state(
        self,
        issue_number: int,
        expected_fence: IssueCancellationFence | None = None,
    ) -> tuple[_IssueCancellationAuthority, IssueCancellationFenceComment, tuple[IssueComment, ...], str | None]:
        authority = _fresh_issue_cancellation_authority(
            self.client, self.central_repository, issue_number, self.app,
            allow_pr_stage_state=True,
        )
        current_ref = _read_issue_branch_ref(
            self.client, self.central_repository,
            authority.lease.lease.branch_ref.removeprefix("refs/heads/"),
        )
        fences, comments = self._read_issue_cancellation_fences(
            authority, current_ref or ZERO_OID,
        )
        if len(fences) != 1:
            raise StaleAuthorityError("exact persisted IssueCancellationFence is required")
        fence_item = fences[0]
        fence = fence_item.fence
        if expected_fence is not None and fence != expected_fence:
            raise StaleAuthorityError("persisted IssueCancellationFence differs from the requested fence")
        if _cancellation_binding_authority_id(authority) != fence.binding_authority:
            raise StaleAuthorityError("current cancellation binding authority differs from its exact fence")
        if not authority.raw_pr_merged and (
            current_ref != fence.cancellation_head_sha
            or authority.pr.head_oid != fence.cancellation_head_sha
        ):
            raise StaleAuthorityError("exact cancellation fence is not the current generated ref and PR head")
        return authority, fence_item, comments, current_ref

    def _require_current_cancel_failure(
        self,
        fence: IssueCancellationFence,
        expected: ExactAppRequiredStatusSnapshot | None = None,
    ) -> ExactAppRequiredStatusSnapshot:
        status = _latest_exact_cancel_status_evidence(
            self.client, self.central_repository, fence, self.app,
        )
        if status is None:
            raise StaleAuthorityError("latest exact-App status is not the exact cancellation failure for this fence")
        if expected is not None and status != expected:
            raise StaleAuthorityError("latest exact-App cancellation failure changed during cancellation progression")
        return status

    def _require_active_issue_cancel(self, fence: IssueCancellationFence) -> None:
        resolution = resolve_sha_carrier_role(
            self.client, self.central_repository, fence.cancellation_head_sha,
            self.app.slug, LegacyEvidenceDisposition.CONFLICTING,
        )
        if resolution != ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_CANCEL,
            _issue_cancellation_fence_marker(fence),
        ):
            raise StaleAuthorityError("cancellation stage mutation requires ACTIVE(ISSUE_CANCEL) authority")

    def _run_cancellation_pr_stage(
        self,
        authority: _IssueCancellationAuthority,
        fence: IssueCancellationFence,
        stage: str,
    ) -> ExactPullRequestStageMutationEvidence:
        try:
            method_name, _operation = _CANCELLATION_STAGE_SPECS[stage]
        except KeyError:
            raise R02Error("cancellation PR mutation stage is unsupported") from None
        method = getattr(self.client, method_name, None)
        if not callable(method):
            raise R02Error("fixed PR-stage transport method is unavailable")
        client_mutation_id = _cancellation_stage_client_mutation_id(fence, stage)
        try:
            receipt = method(fence.pull_request_node_id, client_mutation_id)
        except Exception as error:
            # A later read may classify a merge race, but can never replace the
            # missing same-response receipt or create witness/terminal evidence.
            try:
                observed = _fresh_issue_cancellation_authority(
                    self.client, self.central_repository, fence.issue_number,
                    self.app, allow_pr_stage_state=True,
                )
            except Exception:
                observed = None
            if observed is not None and observed.raw_pr_merged:
                raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED") from None
            raise StaleAuthorityError(
                f"same-response cancellation {stage} receipt is unavailable: {_bounded_reason(error)}"
            ) from None
        return _exact_cancellation_stage_evidence(receipt, authority, fence, stage)

    def _persist_issue_cancellation_draft_witness(
        self,
        authority: _IssueCancellationAuthority,
        fence_item: IssueCancellationFenceComment,
        status: ExactAppRequiredStatusSnapshot,
        witness: IssueCancellationDraftWitness,
    ) -> IssueCancellationDraftWitnessComment:
        body = witness.render()
        comments = tuple(self.client.list_issue_comments(
            self.central_repository, authority.pull_request_number,
        ))
        existing = _issue_cancellation_draft_witness_comments(
            comments, self.app, authority, fence_item, status,
        )
        if existing:
            if existing[0].witness.render() != body:
                raise StaleAuthorityError("a different immutable cancellation draft witness is already persisted")
            return existing[0]
        try:
            self.client.create_issue_comment(
                self.central_repository, authority.pull_request_number, body,
            )
        except Exception as error:
            try:
                readback = tuple(self.client.list_issue_comments(
                    self.central_repository, authority.pull_request_number,
                ))
                witnesses = _issue_cancellation_draft_witness_comments(
                    readback, self.app, authority, fence_item, status,
                )
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous draft witness POST cannot be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            if len(witnesses) == 1 and witnesses[0].witness.render() == body:
                return witnesses[0]
            raise StaleAuthorityError(
                f"draft witness POST lacks exact same-response authority: {_bounded_reason(error)}"
            ) from None
        readback = tuple(self.client.list_issue_comments(
            self.central_repository, authority.pull_request_number,
        ))
        witnesses = _issue_cancellation_draft_witness_comments(
            readback, self.app, authority, fence_item, status,
        )
        if len(witnesses) != 1 or witnesses[0].witness.render() != body:
            raise StaleAuthorityError("persisted cancellation draft witness is absent or differs from exact payload")
        return witnesses[0]

    def _persist_issue_terminal_cancelled_result(
        self,
        authority: _IssueCancellationAuthority,
        fence_item: IssueCancellationFenceComment,
        witness_item: IssueCancellationDraftWitnessComment,
        status: ExactAppRequiredStatusSnapshot,
        result: IssueTerminalCancelledResult,
    ) -> IssueTerminalCancelledResultComment:
        body = result.render()
        comments = tuple(self.client.list_issue_comments(
            self.central_repository, authority.pull_request_number,
        ))
        existing = _issue_terminal_cancelled_result_comments(
            comments, self.app, authority, fence_item, witness_item, status,
        )
        if existing:
            if existing[0].result.render() != body:
                raise StaleAuthorityError("a different immutable terminal cancellation result is already persisted")
            return existing[0]
        try:
            self.client.create_issue_comment(
                self.central_repository, authority.pull_request_number, body,
            )
        except Exception as error:
            try:
                readback = tuple(self.client.list_issue_comments(
                    self.central_repository, authority.pull_request_number,
                ))
                results = _issue_terminal_cancelled_result_comments(
                    readback, self.app, authority, fence_item, witness_item, status,
                )
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous terminal result POST cannot be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            if len(results) == 1 and results[0].result.render() == body:
                return results[0]
            raise StaleAuthorityError(
                f"terminal result POST lacks exact canonical readback: {_bounded_reason(error)}"
            ) from None
        readback = tuple(self.client.list_issue_comments(
            self.central_repository, authority.pull_request_number,
        ))
        results = _issue_terminal_cancelled_result_comments(
            readback, self.app, authority, fence_item, witness_item, status,
        )
        if len(results) != 1 or results[0].result.render() != body:
            raise StaleAuthorityError("persisted terminal cancellation result is absent or differs from exact payload")
        return results[0]

    def establish_issue_cancellation_draft_witness(
        self,
        issue_number: int,
    ) -> IssueCancellationDraftWitness:
        """Normalize the exact cancellation PR to draft using only same-response proof."""
        authority, fence_item, comments, current_ref = self._fresh_cancellation_fence_state(issue_number)
        fence = fence_item.fence
        if authority.raw_pr_merged:
            raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED")
        if current_ref != fence.cancellation_head_sha or authority.pr.head_oid != fence.cancellation_head_sha:
            raise StaleAuthorityError("draft witness requires exact current HC ref and PR head")
        self._require_active_issue_cancel(fence)
        status = self._require_current_cancel_failure(fence)
        witnesses = _issue_cancellation_draft_witness_comments(
            comments, self.app, authority, fence_item, status,
        )
        if witnesses:
            # A replayed witness survives PR ready/close state changes. Only a
            # merge or immutable identity/head drift can make it unusable.
            latest_authority, latest_fence, _latest_comments, latest_ref = self._fresh_cancellation_fence_state(
                issue_number, fence,
            )
            if latest_authority.raw_pr_merged:
                raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED")
            if latest_ref != fence.cancellation_head_sha or latest_authority.pr.head_oid != fence.cancellation_head_sha:
                raise StaleAuthorityError("persisted draft witness no longer matches exact current HC")
            if self._require_current_cancel_failure(fence) != status:
                raise StaleAuthorityError("current cancellation failure changed during witness replay")
            return witnesses[0].witness

        reopen_evidence: ExactPullRequestStageMutationEvidence | None = None
        ready_evidence: ExactPullRequestStageMutationEvidence | None = None
        is_draft = authority.pr.draft
        if authority.raw_pr_state == "CLOSED":
            reopen_evidence = self._run_cancellation_pr_stage(authority, fence, "DRAFT_REOPEN")
            is_draft = reopen_evidence.is_draft
            self._require_active_issue_cancel(fence)
        elif authority.raw_pr_state != "OPEN":
            raise R02Error("cancellation draft normalization requires exact OPEN or CLOSED PR state")
        if is_draft:
            ready_evidence = self._run_cancellation_pr_stage(authority, fence, "DRAFT_READY")
            is_draft = ready_evidence.is_draft
        if authority.raw_pr_state == "CLOSED" and reopen_evidence is None:
            raise R02Error("closed PR normalization lacks its exact same-response reopen receipt")
        if is_draft:
            raise StaleAuthorityError("draft PR did not return to OPEN ready state before draft conversion")
        status_before_convert = self._require_current_cancel_failure(fence, status)
        draft_evidence = self._run_cancellation_pr_stage(authority, fence, "DRAFT_CONVERT")
        try:
            witness = IssueCancellationDraftWitness.create(
                schema_version=1,
                **_cancellation_witness_expected_fields(authority, fence_item, status_before_convert),
                returned_base_ref_oid=draft_evidence.base_ref_oid,
                reopen_evidence=reopen_evidence,
                ready_evidence=ready_evidence,
                draft_evidence=draft_evidence,
            )
        except RequestModelError as error:
            raise R02Error(f"same-response cancellation draft witness is invalid: {_bounded_reason(error)}") from None
        persisted = self._persist_issue_cancellation_draft_witness(
            authority, fence_item, status_before_convert, witness,
        )
        latest_authority, latest_fence, latest_comments, latest_ref = self._fresh_cancellation_fence_state(
            issue_number, fence,
        )
        if latest_authority.raw_pr_merged:
            raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED")
        if latest_ref != fence.cancellation_head_sha:
            raise StaleAuthorityError("persisted draft witness lost exact generated ref HC")
        latest_status = self._require_current_cancel_failure(fence, status_before_convert)
        witnesses = _issue_cancellation_draft_witness_comments(
            latest_comments, self.app, latest_authority, latest_fence, latest_status,
        )
        if len(witnesses) != 1 or witnesses[0].witness != persisted.witness:
            raise StaleAuthorityError("draft witness readback differs from the exact same-response evidence")
        return persisted.witness

    def establish_issue_terminal_cancelled_result(
        self,
        issue_number: int,
    ) -> IssueTerminalCancelledResult:
        """Close the witnessed unmerged PR and persist exact same-response terminal proof."""
        authority, fence_item, comments, current_ref = self._fresh_cancellation_fence_state(issue_number)
        fence = fence_item.fence
        if current_ref != fence.cancellation_head_sha:
            raise StaleAuthorityError("terminal cancellation requires exact current ref HC")
        status = self._require_current_cancel_failure(fence)
        witnesses = _issue_cancellation_draft_witness_comments(
            comments, self.app, authority, fence_item, status,
        )
        if len(witnesses) != 1:
            raise StaleAuthorityError("exact persisted cancellation draft witness is required before terminal close")
        witness_item = witnesses[0]
        results = _issue_terminal_cancelled_result_comments(
            comments, self.app, authority, fence_item, witness_item, status,
        )
        if results:
            if authority.pr.head_oid != fence.cancellation_head_sha:
                raise StaleAuthorityError("persisted terminal result PR head no longer matches HC")
            if self._require_current_cancel_failure(fence) != status:
                raise StaleAuthorityError("current cancellation failure changed during terminal-result replay")
            return results[0].result
        if authority.raw_pr_merged:
            raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED")
        if authority.pr.head_oid != fence.cancellation_head_sha:
            raise StaleAuthorityError("terminal close requires exact current PR head HC")
        reopen_evidence: ExactPullRequestStageMutationEvidence | None = None
        if authority.raw_pr_state == "CLOSED":
            reopen_evidence = self._run_cancellation_pr_stage(authority, fence, "CLOSE_REOPEN")
        elif authority.raw_pr_state != "OPEN":
            raise R02Error("terminal close normalization requires exact OPEN or CLOSED PR state")
        current_status = self._require_current_cancel_failure(fence, status)
        close_evidence = self._run_cancellation_pr_stage(authority, fence, "TERMINAL_CLOSE")
        if close_evidence.state != "CLOSED":
            raise StaleAuthorityError("terminal close same-response evidence did not return CLOSED")
        # The exact close response is the proof. A fresh merged read can veto
        # cancellation, but it can never replace a missing or contradictory receipt.
        latest_authority, latest_fence, latest_comments, latest_ref = self._fresh_cancellation_fence_state(
            issue_number, fence,
        )
        if latest_authority.raw_pr_merged:
            raise StaleAuthorityError("CANCELLATION_MERGED_OBSERVED")
        if latest_ref != fence.cancellation_head_sha or latest_authority.pr.head_oid != fence.cancellation_head_sha:
            raise StaleAuthorityError("post-close cancellation authority/ref no longer matches exact HC")
        latest_status = self._require_current_cancel_failure(fence, current_status)
        latest_witnesses = _issue_cancellation_draft_witness_comments(
            latest_comments, self.app, latest_authority, latest_fence, latest_status,
        )
        if len(latest_witnesses) != 1 or latest_witnesses[0].witness != witness_item.witness:
            raise StaleAuthorityError("draft witness changed during terminal close")
        try:
            proof_kind = (
                IssueTerminalCancelledProofKind.PR_BACKED_PRE_BINDING
                if _cancellation_binding_authority_id(latest_authority) == "PRE_BINDING"
                else IssueTerminalCancelledProofKind.PR_BACKED_FULL_BINDING
            )
            result = IssueTerminalCancelledResult.create(
                schema_version=1,
                **_cancellation_terminal_result_expected_fields(
                    latest_authority, latest_fence, latest_witnesses[0], latest_status,
                ),
                close_evidence=close_evidence,
                proof_kind=proof_kind,
            )
        except RequestModelError as error:
            raise R02Error(f"same-response terminal close result is invalid: {_bounded_reason(error)}") from None
        persisted = self._persist_issue_terminal_cancelled_result(
            latest_authority, latest_fence, latest_witnesses[0], latest_status, result,
        )
        final_authority, final_fence, final_comments, final_ref = self._fresh_cancellation_fence_state(
            issue_number, fence,
        )
        if final_ref != fence.cancellation_head_sha:
            raise StaleAuthorityError("terminal result readback no longer has exact generated ref HC")
        final_status = self._require_current_cancel_failure(fence, latest_status)
        final_witnesses = _issue_cancellation_draft_witness_comments(
            final_comments, self.app, final_authority, final_fence, final_status,
        )
        if len(final_witnesses) != 1:
            raise StaleAuthorityError("terminal-result replay lost the exact persisted draft witness")
        final_results = _issue_terminal_cancelled_result_comments(
            final_comments, self.app, final_authority, final_fence, final_witnesses[0], final_status,
        )
        if len(final_results) != 1 or final_results[0].result != persisted.result:
            raise StaleAuthorityError("terminal cancellation result readback differs from exact close receipt")
        return persisted.result

    def _persist_issue_no_pr_cancelled_result(
        self,
        issue_number: int,
        anchor: IssueAnchorComment,
        lease: IssueBranchLeaseComment | None,
        result: IssueNoPRCancelledResult,
    ) -> IssueNoPRCancelledResult:
        body = result.render()
        try:
            comments = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
        except Exception as error:
            raise StaleAuthorityError(f"no-PR result target Issue comments are unavailable: {_bounded_reason(error)}") from None
        existing = _issue_no_pr_cancelled_result_comments(comments, self.app, anchor, lease)
        if existing:
            if existing[0].result != result:
                raise StaleAuthorityError("a different immutable no-PR cancellation result is already persisted")
            return existing[0].result
        try:
            self.client.create_issue_comment(self.central_repository, issue_number, body)
        except Exception as error:
            try:
                readback = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
                persisted = _issue_no_pr_cancelled_result_comments(readback, self.app, anchor, lease)
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"ambiguous no-PR result POST cannot be diagnosed: {_bounded_reason(read_error)}"
                ) from None
            if len(persisted) == 1 and persisted[0].result.render() == body:
                return persisted[0].result
            raise StaleAuthorityError(
                f"no-PR result POST lacks exact canonical readback: {_bounded_reason(error)}"
            ) from None
        try:
            readback = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
            persisted = _issue_no_pr_cancelled_result_comments(readback, self.app, anchor, lease)
        except Exception as error:
            raise StaleAuthorityError(f"persisted no-PR result could not be verified: {_bounded_reason(error)}") from None
        if len(persisted) != 1 or persisted[0].result.render() != body:
            raise StaleAuthorityError("persisted no-PR result is absent or differs from exact canonical payload")
        return persisted[0].result

    @staticmethod
    def _no_pr_cancelled_result_fields(
        state: IssueCancellationState,
        proof_kind: IssueNoPRCancelledProofKind,
        *,
        status: ExactAppRequiredStatusSnapshot | None = None,
        legacy_digest: str | None = None,
        cleanup_before_oid: str | None = None,
        cleanup_ref_absent_after: bool | None = None,
    ) -> dict[str, Any]:
        anchor = state.issue_anchor
        fields: dict[str, Any] = {
            "schema_version": 1,
            "issue_number": anchor.anchor.issue_number,
            "issue_database_id": anchor.anchor.issue_database_id,
            "issue_node_id": anchor.anchor.issue_node_id,
            "issue_request_anchor_comment_database_id": anchor.comment.database_id,
            "issue_request_anchor_sha256": anchor.anchor.canonical_sha256(),
            "source_id": anchor.anchor.source_id,
            "source_repository_id": anchor.anchor.source_repository_id,
            "proof_kind": proof_kind,
        }
        if proof_kind is not IssueNoPRCancelledProofKind.ANCHOR_ONLY:
            if state.lease is None:
                raise R02Error("lease-backed no-PR result requires the exact IssueBranchLease")
            fields.update({
                "lease_comment_database_id": state.lease.comment.database_id,
                "lease_sha256": _binding_comment_sha256(state.lease.comment),
                "lease_id": state.lease.lease.lease_id,
                "branch_ref": state.lease.lease.branch_ref,
                "lease_initial_head_sha": state.lease.lease.initial_head_sha,
                "all_state_pr_enumeration_digest": state.all_state_pr_enumeration_digest,
            })
        if proof_kind is IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS:
            fields.update({
                "required_status": status,
                "legacy_carrier_evidence_digest": legacy_digest,
                "cleanup_before_oid": cleanup_before_oid,
                "cleanup_ref_absent_after": cleanup_ref_absent_after,
            })
        return fields

    def cancel_issue_without_pr(self, issue_number: int) -> IssueNoPRCancelledResult:
        """Persist exact A/B no-PR terminal evidence or CAS-delete an exact zero-PR lease root."""
        state = self._read_issue_cancellation_state(issue_number)
        if state.classification not in {
            IssueCancellationClass.A_ANCHOR_ONLY,
            IssueCancellationClass.B_LEASE_REF_ABSENT,
            IssueCancellationClass.C_LEASE_ZERO_PR,
        }:
            raise StaleAuthorityError("no-PR cancellation is limited to exact classes A/B/C")
        if state.pr_candidates:
            raise R02Error("no-PR cancellation cannot proceed while any exact reserved-branch PR exists")

        existing = state.no_pr_results
        if len(existing) > 1:
            raise R02Error("conflicting no-PR terminal results block cancellation")
        if existing:
            result = existing[0]
            if state.classification is IssueCancellationClass.A_ANCHOR_ONLY:
                expected = IssueNoPRCancelledProofKind.ANCHOR_ONLY
            elif state.classification is IssueCancellationClass.B_LEASE_REF_ABSENT:
                expected = result.proof_kind
                if expected not in {
                    IssueNoPRCancelledProofKind.LEASE_REF_ABSENT,
                    IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS,
                }:
                    raise R02Error("existing no-PR result proof kind does not match the absent-ref class")
            else:
                raise R02Error("lease root was restored after a durable no-PR terminal result")
            if result.proof_kind is not expected:
                raise R02Error("existing no-PR result proof kind differs from exact current cancellation class")
            return result

        if state.issue.state != "closed":
            raise StaleAuthorityError("a fresh no-PR cancellation result requires the exact Issue to be closed")

        if state.classification is IssueCancellationClass.A_ANCHOR_ONLY:
            result = IssueNoPRCancelledResult.create(**self._no_pr_cancelled_result_fields(
                state, IssueNoPRCancelledProofKind.ANCHOR_ONLY,
            ))
            latest = self._read_issue_cancellation_state(issue_number)
            if (
                latest.classification is not IssueCancellationClass.A_ANCHOR_ONLY
                or latest.issue.state != "closed"
                or latest.issue_anchor != state.issue_anchor
                or latest.no_pr_results
            ):
                raise StaleAuthorityError("anchor-only cancellation classification changed before result persistence")
            return self._persist_issue_no_pr_cancelled_result(
                issue_number, latest.issue_anchor, latest.lease, result,
            )

        if state.classification is IssueCancellationClass.B_LEASE_REF_ABSENT:
            result = IssueNoPRCancelledResult.create(**self._no_pr_cancelled_result_fields(
                state, IssueNoPRCancelledProofKind.LEASE_REF_ABSENT,
            ))
            latest = self._read_issue_cancellation_state(issue_number)
            if (
                latest.classification is not IssueCancellationClass.B_LEASE_REF_ABSENT
                or latest.issue.state != "closed"
                or latest.issue_anchor != state.issue_anchor
                or latest.lease != state.lease
                or latest.no_pr_results
            ):
                raise StaleAuthorityError("absent-ref cancellation classification changed before result persistence")
            result = IssueNoPRCancelledResult.create(**self._no_pr_cancelled_result_fields(
                latest, IssueNoPRCancelledProofKind.LEASE_REF_ABSENT,
            ))
            return self._persist_issue_no_pr_cancelled_result(
                issue_number, latest.issue_anchor, latest.lease, result,
            )

        if state.lease is None:
            raise R02Error("zero-PR lease-root cancellation has no exact IssueBranchLease")
        lease = state.lease.lease
        lease_head = lease.initial_head_sha
        lease_marker = _lease_marker_for(lease)
        resolution = resolve_sha_carrier_role(
            self.client, self.central_repository, lease_head, self.app.slug,
            LegacyEvidenceDisposition.CONFLICTING,
        )
        if resolution != ShaCarrierResolution(
            CarrierActivation.ACTIVE, CarrierRole.ISSUE_ACTIVE, lease_marker,
        ):
            raise StaleAuthorityError("unbound lease root is not the exact active IssueBranchLease carrier")
        if any(
            type(comment.body) is str
            and comment.body.startswith(ISSUE_FINALIZATION_EPOCH_MARKER)
            for comment in state.issue_comments
        ):
            raise StaleAuthorityError("IssueFinalizationEpoch provenance forbids no-PR lease-root cleanup")

        status, issue_final_success, _any_exact_app_success, _latest_status = (
            _read_latest_exact_app_required_status_snapshot(
                self.client, self.central_repository, lease_head, self.app,
            )
        )
        if status.is_present and status.state == "success":
            raise StaleAuthorityError("latest exact-App required status success blocks lease-root cancellation")
        if issue_final_success:
            raise StaleAuthorityError("exact-App success provenance blocks no-PR lease-root cleanup")
        try:
            raw_checks = tuple(self.client.list_check_runs(self.central_repository, lease_head))
        except Exception as error:
            raise StaleAuthorityError(f"lease-root legacy Check Run inventory is unavailable: {_bounded_reason(error)}") from None
        if any(type(check) is not CheckRun for check in raw_checks):
            raise R02Error("lease-root Check Run inventory contains a malformed record")
        exact_checks = tuple(sorted((
            check for check in raw_checks
            if check.name == TRUSTED_VALIDATION_NAME
            and check.head_sha == lease_head
            and check.app_id == self.app.app_id
        ), key=lambda check: check.id))
        if len(exact_checks) > 1:
            raise StaleAuthorityError("multiple exact-App legacy trusted-validation Check Runs are ambiguous")
        if status.is_present and exact_checks:
            raise StaleAuthorityError("commit status and Check Run carriers are mixed on the unbound lease root")
        for check in exact_checks:
            if check.conclusion in {"success", "neutral", "skipped"}:
                raise StaleAuthorityError("merge-satisfying exact-App legacy Check Run blocks lease-root cancellation")
            if check.status not in {"queued", "in_progress", "completed", "waiting", "pending", "requested"}:
                raise R02Error("legacy trusted-validation Check Run has an unknown state")
            if check.status == "completed" and check.conclusion is None:
                raise R02Error("completed legacy trusted-validation Check Run lacks a conclusion")
        legacy_digest_payload = {
            "checks": [
                {
                    "appId": check.app_id,
                    "conclusion": check.conclusion,
                    "headSha": check.head_sha,
                    "id": check.id,
                    "name": check.name,
                    "status": check.status,
                }
                for check in exact_checks
            ],
            "issueFinalSuccess": issue_final_success,
            "latestStatus": status.as_value(),
        }
        legacy_digest = hashlib.sha256(json.dumps(
            legacy_digest_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")).hexdigest()

        # This second all-state inventory is intentionally the last authority
        # read before the exact non-force ref deletion.
        latest = self._read_issue_cancellation_state(issue_number)
        if (
            latest.classification is not IssueCancellationClass.C_LEASE_ZERO_PR
            or latest.issue.state != "closed"
            or latest.issue_anchor != state.issue_anchor
            or latest.lease != state.lease
            or latest.branch_ref_oid != lease_head
            or latest.pr_candidates
            or latest.no_pr_results
        ):
            raise StaleAuthorityError("zero-PR lease-root proof changed immediately before exact CAS cleanup")
        update = RefUpdate(lease.branch_ref, lease_head, ZERO_OID, force=False)
        try:
            self.client.update_refs(latest.repository.node_id, [update])
        except Exception as error:
            try:
                self._read_issue_cancellation_state(issue_number)
            except Exception as reclassify_error:
                raise StaleAuthorityError(
                    f"lease-root CAS failed and fresh reclassification is unavailable: {_bounded_reason(reclassify_error)}"
                ) from None
            raise StaleAuthorityError(
                f"lease-root exact CAS did not produce terminal proof: {_bounded_reason(error)}"
            ) from None
        if _read_issue_branch_ref(
            self.client, self.central_repository, lease.branch_ref.removeprefix("refs/heads/"),
        ) is not None:
            raise StaleAuthorityError("exact lease-root CAS returned without verifying branch-ref absence")
        result = IssueNoPRCancelledResult.create(**self._no_pr_cancelled_result_fields(
            latest,
            IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS,
            status=status,
            legacy_digest=legacy_digest,
            cleanup_before_oid=lease_head,
            cleanup_ref_absent_after=True,
        ))
        return self._persist_issue_no_pr_cancelled_result(
            issue_number, latest.issue_anchor, latest.lease, result,
        )

    def _validated_pr_cancellation_cleanup(
        self,
        state: IssueCancellationState,
    ) -> tuple[_IssueCancellationAuthority, IssueCancellationFenceComment,
               IssueCancellationDraftWitnessComment, IssueTerminalCancelledResult]:
        if state.classification not in {
            IssueCancellationClass.D_PRE_BINDING_ONE_PR,
            IssueCancellationClass.E_FULL_BINDING,
        } or state.cancellation_authority is None or len(state.pr_candidates) != 1:
            raise StaleAuthorityError("PR-backed cleanup requires exact classified D/E central ownership")
        if state.merge_observed or state.cancellation_authority.raw_pr_merged:
            if state.classification is IssueCancellationClass.E_FULL_BINDING:
                raise StaleAuthorityError("MERGE_OBSERVED_POST_MERGE_REQUIRED")
            raise StaleAuthorityError("MERGED_PRE_BINDING_PRESERVE_WITHOUT_POST_MERGE_AUTHORITY")
        if len(state.fence_items) != 1 or len(state.witness_items) != 1 or len(state.terminal_result_items) != 1:
            raise StaleAuthorityError("PR-backed cleanup requires exact fence, witness, and terminal result")
        authority = state.cancellation_authority
        candidate = state.pr_candidates[0]
        fence_item = state.fence_items[0]
        witness_item = state.witness_items[0]
        terminal = state.terminal_result_items[0].result
        fence = fence_item.fence
        expected_kind = (
            IssueTerminalCancelledProofKind.PR_BACKED_PRE_BINDING
            if state.classification is IssueCancellationClass.D_PRE_BINDING_ONE_PR
            else IssueTerminalCancelledProofKind.PR_BACKED_FULL_BINDING
        )
        if (
            terminal.proof_kind is not expected_kind
            or terminal.binding_authority != fence.binding_authority
            or terminal.pull_request_number != authority.pull_request_number
            or terminal.pull_request_database_id != authority.pull_request_database_id
            or terminal.pull_request_node_id != authority.pull_request_node_id
            or candidate.pr.head_oid != fence.cancellation_head_sha
            or candidate.pr.base_ref != "main"
            or candidate.pr.base_repository_id != state.repository.node_id
        ):
            raise StaleAuthorityError("terminal cancellation result differs from exact current D/E fence/PR authority")
        if state.classification is IssueCancellationClass.D_PRE_BINDING_ONE_PR:
            if (
                authority.binding_authority != "PRE_BINDING"
                or authority.binding is not None
                or authority.binding_state is not None
                or fence.binding_authority != "PRE_BINDING"
                or fence.original_head_sha != authority.lease.lease.initial_head_sha
            ):
                raise StaleAuthorityError("PRE_BINDING Mode B cleanup gained complete binding or lost exact lease-root authority")
        elif (
            authority.binding_authority != "FULL_BINDING"
            or authority.binding is None
            or fence.binding_authority != authority.binding.binding_id
        ):
            raise StaleAuthorityError("Mode A cleanup requires the exact full two-sided binding")
        current_failure = self._require_current_cancel_failure(fence, terminal.current_failure_status)
        if current_failure != terminal.current_failure_status:
            raise StaleAuthorityError("current exact-App cancellation failure differs from terminal result snapshot")
        if state.branch_ref_oid not in {None, fence.cancellation_head_sha}:
            raise StaleAuthorityError("reserved branch ref moved from exact cancellation HC")
        if state.branch_ref_oid is None and candidate.pr.head_oid != fence.cancellation_head_sha:
            raise StaleAuthorityError("absent-ref terminal cleanup no longer matches exact PR head HC")
        return authority, fence_item, witness_item, terminal

    def cleanup_issue_cancelled_branch(self, issue_number: int) -> IssueTerminalCancelledResult | str:
        """Delete only an exact terminal D/E cancellation head with non-force compare-and-swap."""
        state = self._read_issue_cancellation_state(issue_number)
        if state.merge_observed:
            if state.classification is IssueCancellationClass.E_FULL_BINDING:
                return "MERGE_OBSERVED_POST_MERGE_REQUIRED"
            if state.classification is IssueCancellationClass.D_PRE_BINDING_ONE_PR:
                raise StaleAuthorityError("MERGED_PRE_BINDING_PRESERVE_WITHOUT_POST_MERGE_AUTHORITY")
            raise StaleAuthorityError("merged cancellation state is not an exact PR-backed D/E class")
        _authority, fence_item, _witness_item, terminal = self._validated_pr_cancellation_cleanup(state)
        fence = fence_item.fence
        if state.branch_ref_oid is None:
            return terminal
        if state.branch_ref_oid != fence.cancellation_head_sha:
            raise StaleAuthorityError("PR-backed branch cleanup ref differs from exact cancellation HC")

        # Re-read every central proof and the exact current cancellation failure
        # immediately before deleting the one named branch ref.
        latest = self._read_issue_cancellation_state(issue_number)
        _latest_authority, latest_fence_item, _latest_witness, latest_terminal = (
            self._validated_pr_cancellation_cleanup(latest)
        )
        if (
            latest.classification is not state.classification
            or latest_fence_item.fence != fence
            or latest_terminal != terminal
            or latest.branch_ref_oid != fence.cancellation_head_sha
        ):
            raise StaleAuthorityError("PR-backed terminal cancellation authority changed immediately before CAS cleanup")
        update = RefUpdate(fence.branch_ref, fence.cancellation_head_sha, ZERO_OID, force=False)
        try:
            self.client.update_refs(latest.repository.node_id, [update])
        except Exception as error:
            try:
                after_error = self._read_issue_cancellation_state(issue_number)
                _after_authority, _after_fence, _after_witness, after_terminal = (
                    self._validated_pr_cancellation_cleanup(after_error)
                )
            except Exception as reclassify_error:
                raise StaleAuthorityError(
                    f"terminal cleanup CAS failed and fresh reclassification is unavailable: {_bounded_reason(reclassify_error)}"
                ) from None
            if after_error.branch_ref_oid is None and after_terminal == terminal:
                return terminal
            raise StaleAuthorityError(
                f"terminal cleanup exact CAS did not remove the authorized HC: {_bounded_reason(error)}"
            ) from None
        if _read_issue_branch_ref(
            self.client, self.central_repository, fence.branch_ref.removeprefix("refs/heads/"),
        ) is not None:
            raise StaleAuthorityError("terminal cleanup CAS returned without verifying branch-ref absence")
        final_state = self._read_issue_cancellation_state(issue_number)
        _final_authority, _final_fence, _final_witness, final_terminal = (
            self._validated_pr_cancellation_cleanup(final_state)
        )
        if final_state.branch_ref_oid is not None or final_terminal != terminal:
            raise StaleAuthorityError("terminal cleanup readback lost exact terminal proof or ref absence")
        return final_terminal

    def _read_issue_cancellation_state(self, issue_number: int) -> IssueCancellationState:
        """Classify a terminal Issue from fresh central authority without source lookup."""
        if type(issue_number) is not int or not 1 <= issue_number <= 9_223_372_036_854_775_807:
            raise R02Error("cancellation Issue number must be a positive signed-64 integer")
        try:
            repository = self.client.get_repository_metadata(self.central_repository)
            current_app = resolve_app_identity(self.client, self.app.slug)
            issue = self.client.get_issue_metadata(self.central_repository, issue_number)
            issue_comments = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
        except Exception as error:
            raise StaleAuthorityError(f"central cancellation classification authority is unavailable: {_bounded_reason(error)}") from None
        if (
            type(repository) is not RepositoryMetadata
            or repository.full_name != self.central_repository
            or repository.default_branch != "main"
            or not repository.node_id
            or current_app != self.app
            or type(issue) is not IssueMetadata
            or issue.number != issue_number
            or issue.is_pull_request
        ):
            raise StaleAuthorityError("exact central repository/App/Issue identity changed during cancellation classification")
        anchor = validate_unique_issue_anchor(issue_comments, issue, self.app)
        _issue_pr_authority_fence(issue_comments, self.app, allow_cancellation_fence=True)
        lease = _resolve_issue_branch_lease_class(
            self.client, self.central_repository, issue_comments, self.app,
            anchor.anchor, anchor.comment.database_id, repository.node_id,
        )
        issue_bindings = _binding_comment_candidates(
            issue_comments, self.app, ISSUE_INTERNAL_PR_BINDING_MARKER,
            parse_issue_internal_pr_binding, "IssueInternalPRBinding",
        )
        binding_conflict = lease is None and bool(issue_bindings)
        for binding_item in issue_bindings:
            if lease is None:
                binding_conflict = True
                continue
            try:
                _validate_issue_binding_cross_link(binding_item.binding, anchor, lease, repository.node_id)
            except R02Error:
                binding_conflict = True
        no_pr_results = tuple(
            item.result for item in _issue_no_pr_cancelled_result_comments(
                issue_comments, self.app, anchor, lease,
            )
        )

        branch_ref = issue_branch_ref(issue_number)
        short_ref = branch_ref.removeprefix("refs/heads/")
        current_ref = _read_issue_branch_ref(self.client, self.central_repository, short_ref)
        try:
            inventory = self.client.list_pull_requests(self.central_repository, state="all")
        except Exception as error:
            raise StaleAuthorityError(f"bounded all-state PR enumeration failed: {_bounded_reason(error)}") from None
        if type(inventory) not in {tuple, list}:
            raise R02Error("all-state PR enumeration must return a sequence")
        numbers: list[int] = []
        seen_numbers: set[int] = set()
        candidates: list[_IssueCancellationPRCandidate] = []
        topology_conflict = False
        for raw in inventory:
            if (
                type(raw) is not dict
                or type(raw.get("number")) is not int
                or not 1 <= raw["number"] <= 9_223_372_036_854_775_807
                or raw["number"] in seen_numbers
            ):
                raise R02Error("all-state PR enumeration contains an invalid or duplicate PR number")
            number = raw["number"]
            numbers.append(number)
            seen_numbers.add(number)
            try:
                pr = self.client.get_pull_request_metadata(self.central_repository, number)
            except Exception as error:
                raise StaleAuthorityError(f"all-state PR metadata is unavailable: {_bounded_reason(error)}") from None
            if type(pr) is not PullRequestMetadata or pr.number != number:
                raise R02Error("all-state PR metadata differs from its enumerated number")
            if pr.head_ref != short_ref:
                continue
            if pr.head_repository_id != repository.node_id:
                topology_conflict = True
                continue
            if (
                pr.head_repository != self.central_repository
                or pr.base_repository_id != repository.node_id
                or pr.base_repository != self.central_repository
                or pr.base_ref != "main"
                or pr.author_id != self.app.bot_node_id
                or pr.author_login != self.app.bot_login
                or pr.body != render_request_body(anchor.anchor.initial_request)
                or pr.last_edited_at is not None
                or pr.includes_created_edit is not False
                or type(pr.draft) is not bool
            ):
                topology_conflict = True
                continue
            raw_state = raw.get("state")
            raw_merged = raw.get("merged")
            raw_merged_at = raw.get("merged_at")
            if type(raw_merged) is not bool and "merged_at" in raw:
                if raw_merged_at is None:
                    raw_merged = False
                elif type(raw_merged_at) is str and raw_merged_at:
                    raw_merged = True
                else:
                    raw_merged = None
            if (
                type(raw_state) is not str
                or raw_state not in {"open", "closed"}
                or type(raw_merged) is not bool
                or (raw_merged and (type(raw_merged_at) is not str or not raw_merged_at))
                or (not raw_merged and raw_merged_at is not None)
            ):
                topology_conflict = True
                continue
            try:
                pr_issue = self.client.get_issue_metadata(self.central_repository, number)
                pr_comments = tuple(self.client.list_issue_comments(self.central_repository, number))
            except Exception as error:
                raise StaleAuthorityError(f"reserved-branch PR-as-Issue authority is unavailable: {_bounded_reason(error)}") from None
            if (
                type(pr_issue) is not IssueMetadata
                or pr_issue.is_pull_request is not True
                or pr_issue.number != number
                or type(pr_issue.database_id) is not int
                or pr_issue.database_id <= 0
                or type(pr_issue.node_id) is not str
                or not pr_issue.node_id
                or pr_issue.author_id != self.app.bot_node_id
                or pr_issue.author_login != self.app.bot_login
                or pr_issue.body != pr.body
                or pr_issue.state != raw_state
            ):
                topology_conflict = True
                continue
            _issue_pr_authority_fence(pr_comments, self.app, allow_cancellation_fence=True)
            pr_bindings = _binding_comment_candidates(
                pr_comments, self.app, PR_ISSUE_ORIGIN_BINDING_MARKER,
                parse_pr_issue_origin_binding, "PRIssueOriginBinding",
            )
            issue_binding = issue_bindings[0] if issue_bindings else None
            pr_binding = pr_bindings[0] if pr_bindings else None
            for item in (issue_binding, pr_binding):
                if item is not None:
                    if lease is None:
                        binding_conflict = True
                    else:
                        try:
                            _validate_issue_binding_cross_link(item.binding, anchor, lease, repository.node_id)
                        except R02Error:
                            binding_conflict = True
                    if (
                        item.binding.pull_request_number != number
                        or item.binding.pull_request_database_id != pr_issue.database_id
                        or item.binding.pull_request_node_id != pr_issue.node_id
                    ):
                        binding_conflict = True
            if issue_binding is not None and pr_binding is not None and issue_binding.binding != pr_binding.binding:
                binding_conflict = True
            candidates.append(_IssueCancellationPRCandidate(
                pr, pr_issue, pr_comments, raw_state.upper(), raw_merged,
                raw_merged_at, issue_binding, pr_binding,
            ))

        enum_payload = {
            "branchRef": branch_ref,
            "centralRepositoryNodeId": repository.node_id,
            "listedPullRequestNumbers": sorted(numbers),
            "reservedBranchCandidates": [
                {
                    "baseRef": item.pr.base_ref,
                    "headRef": item.pr.head_ref,
                    "headSha": item.pr.head_oid,
                    "merged": item.raw_merged,
                    "mergedAt": item.raw_merged_at,
                    "number": item.pr.number,
                    "state": item.raw_state,
                }
                for item in sorted(candidates, key=lambda candidate: candidate.pr.number)
            ],
        }
        enumeration_digest = hashlib.sha256(json.dumps(
            enum_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")).hexdigest()

        def conflicting_state() -> IssueCancellationState:
            return IssueCancellationState(
                IssueCancellationClass.F_CONFLICTING, repository, issue, issue_comments,
                anchor, lease, current_ref, enumeration_digest, tuple(candidates), None,
                (), (), (), no_pr_results, any(item.raw_merged for item in candidates),
            )

        if binding_conflict or topology_conflict:
            return conflicting_state()

        if lease is None:
            if current_ref is not None or candidates:
                return conflicting_state()
            if any(result.proof_kind is not IssueNoPRCancelledProofKind.ANCHOR_ONLY for result in no_pr_results):
                raise R02Error("anchor-only cancellation has a lease-backed no-PR result")
            return IssueCancellationState(
                IssueCancellationClass.A_ANCHOR_ONLY, repository, issue, issue_comments,
                anchor, None, None, enumeration_digest, (), None, (), (), (), no_pr_results, False,
            )

        if not candidates:
            if current_ref is None:
                if any(result.proof_kind not in {
                    IssueNoPRCancelledProofKind.LEASE_REF_ABSENT,
                    IssueNoPRCancelledProofKind.LEASE_ZERO_PR_CAS,
                } for result in no_pr_results):
                    raise R02Error("absent-ref cancellation has an incompatible no-PR proof kind")
                return IssueCancellationState(
                    IssueCancellationClass.B_LEASE_REF_ABSENT, repository, issue, issue_comments,
                    anchor, lease, None, enumeration_digest, (), None, (), (), (), no_pr_results, False,
                )
            if current_ref == lease.lease.initial_head_sha:
                if issue_bindings:
                    return conflicting_state()
                if no_pr_results:
                    return conflicting_state()
                return IssueCancellationState(
                    IssueCancellationClass.C_LEASE_ZERO_PR, repository, issue, issue_comments,
                    anchor, lease, current_ref, enumeration_digest, (), None, (), (), (), no_pr_results, False,
                )
            return conflicting_state()
        if no_pr_results:
            return conflicting_state()
        if len(candidates) != 1:
            return conflicting_state()

        candidate = candidates[0]
        full_binding = (
            candidate.issue_binding is not None
            and candidate.pr_binding is not None
            and candidate.issue_binding.binding == candidate.pr_binding.binding
        )
        authority = _fresh_issue_cancellation_authority(
            self.client, self.central_repository, issue_number, self.app,
            allow_pr_stage_state=True,
        )
        if (
            authority.issue_anchor.anchor != anchor.anchor
            or authority.issue_anchor.comment.database_id != anchor.comment.database_id
            or authority.lease.lease != lease.lease
            or authority.lease.comment.database_id != lease.comment.database_id
            or authority.pull_request_number != candidate.pr.number
            or authority.pull_request_database_id != candidate.pr_issue.database_id
            or authority.pull_request_node_id != candidate.pr_issue.node_id
            or authority.raw_pr_state != candidate.raw_state
            or authority.raw_pr_merged is not candidate.raw_merged
            or (authority.binding_authority == "FULL_BINDING") != full_binding
        ):
            raise StaleAuthorityError("fresh cancellation PR/anchor/lease/binding identity changed during classification")
        refreshed_ref = _read_issue_branch_ref(self.client, self.central_repository, short_ref)
        if refreshed_ref != current_ref:
            raise StaleAuthorityError("reserved Issue branch ref changed during cancellation classification")

        history_ref = current_ref or candidate.pr.head_oid
        fence_items, pr_comments = self._read_issue_cancellation_fences(authority, history_ref)
        if len(fence_items) > 1:
            raise R02Error("conflicting IssueCancellationFence comments block classification")
        if fence_items:
            fence = fence_items[0].fence
            if candidate.pr.head_oid not in {fence.original_head_sha, fence.cancellation_head_sha}:
                raise R02Error("reserved PR head differs from exact fence original/HC")
            if current_ref not in {None, fence.original_head_sha, fence.cancellation_head_sha}:
                raise R02Error("reserved branch ref differs from exact fence original/HC")
        elif candidate.pr.head_oid != current_ref:
            raise R02Error("reserved PR head and exact branch ref differ")

        witness_items: tuple[IssueCancellationDraftWitnessComment, ...] = ()
        terminal_items: tuple[IssueTerminalCancelledResultComment, ...] = ()
        if fence_items:
            current_status = _latest_exact_cancel_status_evidence(
                self.client, self.central_repository, fence_items[0].fence, self.app,
            )
            has_witness_marker = any(
                type(item.body) is str and item.body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER)
                for item in pr_comments
            )
            has_terminal_marker = any(
                type(item.body) is str and item.body.startswith(ISSUE_TERMINAL_CANCELLED_RESULT_MARKER)
                for item in pr_comments
            )
            if has_witness_marker and current_status is None:
                raise R02Error("persisted draft witness has no exact current cancellation failure")
            if current_status is not None:
                witness_items = _issue_cancellation_draft_witness_comments(
                    pr_comments, self.app, authority, fence_items[0], current_status,
                )
            if has_terminal_marker and (current_status is None or len(witness_items) != 1):
                raise R02Error("persisted terminal result lacks exact current failure or draft witness")
            if has_terminal_marker:
                terminal_items = _issue_terminal_cancelled_result_comments(
                    pr_comments, self.app, authority, fence_items[0], witness_items[0], current_status,
                )

        merge_observed = candidate.raw_merged
        if merge_observed:
            classification = IssueCancellationClass.E_FULL_BINDING if full_binding else IssueCancellationClass.D_PRE_BINDING_ONE_PR
        else:
            if current_ref is None:
                if not terminal_items or candidate.pr.head_oid != terminal_items[0].result.cancellation_head_sha:
                    raise R02Error("reserved PR branch is absent without durable terminal cancellation authority")
            elif candidate.pr.head_oid != current_ref:
                raise R02Error("reserved PR head and exact branch ref differ")
            if not full_binding:
                valid_prebinding_head = candidate.pr.head_oid == lease.lease.initial_head_sha
                if fence_items:
                    valid_prebinding_head = valid_prebinding_head or candidate.pr.head_oid == fence_items[0].fence.cancellation_head_sha
                    valid_prebinding_head = valid_prebinding_head or (
                        current_ref == fence_items[0].fence.original_head_sha == candidate.pr.head_oid
                    )
                if not valid_prebinding_head:
                    raise R02Error("PRE_BINDING PR head exceeds exact lease-root/fence authority")
                classification = IssueCancellationClass.D_PRE_BINDING_ONE_PR
            else:
                classification = IssueCancellationClass.E_FULL_BINDING
        return IssueCancellationState(
            classification, repository, issue, issue_comments, anchor, lease,
            current_ref, enumeration_digest, tuple(candidates), authority,
            fence_items, witness_items, terminal_items, no_pr_results, merge_observed,
        )

    def prepare_issue_finalization_epoch(
        self,
        issue_number: int,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        *,
        semantic_validator: Callable[[Request], bool] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> IssueFinalizationEpoch:
        """Persist and CAS one exact HA -> HF finalization epoch; publish no status."""
        snapshot = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
        )
        self._require_no_issue_cancellation_fence(
            snapshot.state, snapshot.current_ref, snapshot.pr_comments,
        )
        current = snapshot.current_authority

        # A retry after a completed CAS returns the already active exact epoch.
        if current.claim_kind == "ISSUE_FINALIZATION_EPOCH":
            epoch = current.artifact
            origin = current.proposal_origin
            if origin is None:
                raise StaleAuthorityError("active finalization has no unique proposal-origin claim")
            scope_digest, request_digest, projection_digest = self._derive_issue_proposal_scope(
                snapshot, epoch.from_head_sha, origin,
            )
            if (
                type(epoch) is not IssueFinalizationEpoch
                or epoch.from_head_sha not in {node.target_head_sha for node in snapshot.history}
                or epoch.accepted_base_sha != snapshot.accepted_main_sha
                or epoch.accepted_base_tree_sha != snapshot.accepted_main_tree_sha
                or epoch.claimed_target_evidence_digest != scope_digest
                or epoch.fresh_proposal_scope_evidence_digest != scope_digest
                or epoch.effective_request_digest != request_digest
                or epoch.patch_projection_evidence_digest != projection_digest
            ):
                raise StaleAuthorityError("active finalization epoch no longer matches fresh finalizer authority")
            return epoch

        if (
            current.role is not CarrierRole.ISSUE_ACTIVE
            or current.claim_kind not in {"ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH"}
        ):
            raise StaleAuthorityError("only an active IssueHeadClaim or RequiredStatusEpoch can enter finalization")
        origin = current.proposal_origin
        if origin is None or type(origin.artifact) is not IssueHeadClaim:
            raise StaleAuthorityError("current Issue head has no unique proposal-bearing IssueHeadClaim ancestry")
        if origin.transition_kind == "NORMALIZE":
            raise StaleAuthorityError("normalization-only Issue history cannot enter finalization")
        target_digest, request_digest, projection_digest = self._derive_issue_proposal_scope(
            snapshot, snapshot.current_ref, origin,
        )
        state = snapshot.state
        immediate = current
        stable_fields = dict(
            schema_version=1,
            issue_number=state.issue_anchor.anchor.issue_number,
            issue_database_id=state.issue_anchor.anchor.issue_database_id,
            issue_node_id=state.issue_anchor.anchor.issue_node_id,
            issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
            issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
            issue_branch_lease_comment_database_id=state.lease.comment.database_id,
            issue_branch_lease_sha256=_binding_comment_sha256(state.lease.comment),
            binding_id=state.binding.binding_id,
            source_id=state.issue_anchor.anchor.source_id,
            source_repository_id=state.issue_anchor.anchor.source_repository_id,
            pull_request_number=state.binding.pull_request_number,
            pull_request_database_id=state.binding.pull_request_database_id,
            pull_request_node_id=state.binding.pull_request_node_id,
            central_repository_node_id=state.binding.central_repository_node_id,
            branch_ref=state.binding.branch_ref,
            request_class=state.issue_anchor.anchor.request_class,
            accepted_base_sha=snapshot.accepted_main_sha,
            accepted_base_tree_sha=snapshot.accepted_main_tree_sha,
            base_ref="main",
            from_head_sha=snapshot.current_ref,
            from_tree_sha=immediate.tree_sha,
            final_head_sha="0" * 40,
            final_tree_sha=immediate.tree_sha,
            carrier_nonce="0" * 64,
            from_authority_kind=immediate.claim_kind,
            from_authority_comment_database_id=immediate.comment.database_id,
            from_authority_artifact_id=immediate.artifact_id,
            from_authority_artifact_sha256=immediate.artifact_sha256,
            from_authority_role=immediate.role.value,
            proposal_origin_claim_comment_database_id=origin.comment.database_id,
            proposal_origin_claim_id=origin.artifact.claim_id,
            proposal_origin_claim_sha256=origin.artifact_sha256,
            effective_request_digest=request_digest,
            patch_projection_evidence_digest=projection_digest,
            claimed_target_evidence_digest=target_digest,
            fresh_proposal_scope_evidence_digest=target_digest,
        )

        pending = tuple(
            node for node in snapshot.history
            if node.claim_kind == "ISSUE_FINALIZATION_EPOCH"
            and node.from_head_sha == snapshot.current_ref
        )
        replay_pending = bool(pending)
        if len(pending) > 1:
            raise R02Error("multiple pending finalization epochs from the current HA conflict")
        if pending:
            epoch = pending[0].artifact
            expected = stable_fields.copy()
            for name in ("final_head_sha", "carrier_nonce"):
                expected.pop(name)
            actual = {
                "schema_version": epoch.schema_version,
                "issue_number": epoch.issue_number,
                "issue_database_id": epoch.issue_database_id,
                "issue_node_id": epoch.issue_node_id,
                "issue_request_anchor_comment_database_id": epoch.issue_request_anchor_comment_database_id,
                "issue_request_anchor_sha256": epoch.issue_request_anchor_sha256,
                "issue_branch_lease_comment_database_id": epoch.issue_branch_lease_comment_database_id,
                "issue_branch_lease_sha256": epoch.issue_branch_lease_sha256,
                "binding_id": epoch.binding_id,
                "source_id": epoch.source_id,
                "source_repository_id": epoch.source_repository_id,
                "pull_request_number": epoch.pull_request_number,
                "pull_request_database_id": epoch.pull_request_database_id,
                "pull_request_node_id": epoch.pull_request_node_id,
                "central_repository_node_id": epoch.central_repository_node_id,
                "branch_ref": epoch.branch_ref,
                "request_class": epoch.request_class,
                "accepted_base_sha": epoch.accepted_base_sha,
                "accepted_base_tree_sha": epoch.accepted_base_tree_sha,
                "base_ref": epoch.base_ref,
                "from_head_sha": epoch.from_head_sha,
                "from_tree_sha": epoch.from_tree_sha,
                "final_tree_sha": epoch.final_tree_sha,
                "from_authority_kind": epoch.from_authority_kind,
                "from_authority_comment_database_id": epoch.from_authority_comment_database_id,
                "from_authority_artifact_id": epoch.from_authority_artifact_id,
                "from_authority_artifact_sha256": epoch.from_authority_artifact_sha256,
                "from_authority_role": epoch.from_authority_role,
                "proposal_origin_claim_comment_database_id": epoch.proposal_origin_claim_comment_database_id,
                "proposal_origin_claim_id": epoch.proposal_origin_claim_id,
                "proposal_origin_claim_sha256": epoch.proposal_origin_claim_sha256,
                "effective_request_digest": epoch.effective_request_digest,
                "patch_projection_evidence_digest": epoch.patch_projection_evidence_digest,
                "claimed_target_evidence_digest": epoch.claimed_target_evidence_digest,
                "fresh_proposal_scope_evidence_digest": epoch.fresh_proposal_scope_evidence_digest,
            }
            if actual != expected:
                raise StaleAuthorityError("pending finalization epoch does not match the freshly resolved HA authority")
        else:
            nonce = (nonce_factory or new_carrier_nonce)()
            if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce):
                raise R02Error("IssueFinalizationEpoch nonce must be lowercase 256-bit hex")
            stable_fields["carrier_nonce"] = nonce
            prepared = IssueFinalizationEpoch.create(**stable_fields)
            marker_text = _issue_finalization_epoch_marker(prepared).render()
            timestamp = self.client.bot_commit_timestamp_after(
                self.central_repository, snapshot.current_ref,
            )
            wrapper = self.client.create_commit(
                self.central_repository, marker_text, immediate.tree_sha,
                [snapshot.current_ref], timestamp=timestamp,
            )
            epoch = IssueFinalizationEpoch.create(**{
                **stable_fields,
                "final_head_sha": wrapper.sha,
            })
            _validate_issue_finalization_epoch_target(
                self.client, self.central_repository, epoch, state,
            )

        if not replay_pending:
            self._persist_issue_epoch_artifact(state, epoch, snapshot.current_ref)
        before_cas = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
        )
        self._require_no_issue_cancellation_fence(
            before_cas.state, before_cas.current_ref, before_cas.pr_comments,
        )
        _require_same_managed_issue_pr_binding(state, before_cas.state)
        if (
            before_cas.current_ref != snapshot.current_ref
            or before_cas.current_authority.claim_kind != immediate.claim_kind
            or before_cas.current_authority.artifact_id != immediate.artifact_id
            or before_cas.accepted_main_sha != epoch.accepted_base_sha
        ):
            raise StaleAuthorityError("HA, accepted main, or immediate authority changed before finalization CAS")
        fresh_scope, fresh_request, fresh_projection = self._derive_issue_proposal_scope(
            before_cas, snapshot.current_ref, before_cas.current_authority.proposal_origin,
        )
        if (
            fresh_scope != epoch.fresh_proposal_scope_evidence_digest
            or fresh_request != epoch.effective_request_digest
            or fresh_projection != epoch.patch_projection_evidence_digest
        ):
            raise StaleAuthorityError("finalizer-grade proposal evidence changed before finalization CAS")
        self._apply_persisted_issue_epoch_target(
            before_cas.state, epoch.from_head_sha, epoch.final_head_sha, snapshot.current_ref,
        )
        final_snapshot = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
        )
        _require_same_managed_issue_pr_binding(state, final_snapshot.state)
        if (
            final_snapshot.current_ref != epoch.final_head_sha
            or final_snapshot.current_authority.claim_kind != "ISSUE_FINALIZATION_EPOCH"
            or final_snapshot.current_authority.artifact != epoch
        ):
            raise StaleAuthorityError("finalization CAS is not the exact active HF")
        origin = final_snapshot.current_authority.proposal_origin
        if origin is None:
            raise StaleAuthorityError("active HF lost its exact proposal-origin ancestry")
        fresh_scope, fresh_request, fresh_projection = self._derive_issue_proposal_scope(
            final_snapshot, epoch.from_head_sha, origin,
        )
        if (
            fresh_scope != epoch.fresh_proposal_scope_evidence_digest
            or fresh_request != epoch.effective_request_digest
            or fresh_projection != epoch.patch_projection_evidence_digest
        ):
            raise StaleAuthorityError("finalizer-grade authority changed after finalization CAS")
        return epoch

    def publish_issue_final_success(
        self,
        issue_number: int,
        epoch: IssueFinalizationEpoch,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        *,
        semantic_validator: Callable[[Request], bool] | None = None,
    ) -> StatusWriteReceipt:
        """Append only the exact success tuple authorized by the active HF epoch."""
        if type(epoch) is not IssueFinalizationEpoch:
            raise R02Error("issue-final publication requires an exact IssueFinalizationEpoch")
        snapshot = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
        )
        node = snapshot.current_authority
        if (
            node.claim_kind != "ISSUE_FINALIZATION_EPOCH"
            or node.role is not CarrierRole.ISSUE_FINALIZING
            or node.artifact != epoch
            or snapshot.resolution.activation is not CarrierActivation.ACTIVE
        ):
            raise StaleAuthorityError("issue-final success requires the exact ACTIVE(ISSUE_FINALIZING) epoch")
        if (
            epoch.issue_number != issue_number
            or epoch.final_head_sha != snapshot.current_ref
            or snapshot.state.pr.head_oid != epoch.final_head_sha
            or snapshot.state.owning_issue.state != "open"
            or snapshot.state.pr_issue.state != "open"
            or epoch.accepted_base_sha != snapshot.accepted_main_sha
            or epoch.accepted_base_tree_sha != snapshot.accepted_main_tree_sha
        ):
            raise StaleAuthorityError("issue-final epoch, accepted base, or live managed state changed")
        origin = node.proposal_origin
        if origin is None:
            raise StaleAuthorityError("active finalization epoch has no proposal-origin IssueHeadClaim")
        scope_digest, request_digest, projection_digest = self._derive_issue_proposal_scope(
            snapshot, epoch.from_head_sha, origin,
        )
        if (
            scope_digest != epoch.claimed_target_evidence_digest
            or scope_digest != epoch.fresh_proposal_scope_evidence_digest
            or request_digest != epoch.effective_request_digest
            or projection_digest != epoch.patch_projection_evidence_digest
        ):
            raise StaleAuthorityError("fresh finalizer-grade authority no longer matches the exact HF epoch")
        receipt = self.client.create_commit_status(
            self.central_repository,
            epoch.final_head_sha,
            "success",
            epoch.required_status_context,
            epoch.required_status_description,
            None,
        )
        return _validate_issue_final_status_receipt(receipt, snapshot.repository, epoch, self.app)

    def revoke_required_status_epoch(
        self,
        issue_number: int,
        reason: RequiredStatusEpochReason,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        *,
        semantic_validator: Callable[[Request], bool] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> RequiredStatusEpoch:
        """Move invalidated current Issue semantics to a fresh no-tree-change HV."""
        if type(reason) is not RequiredStatusEpochReason:
            raise R02Error("RequiredStatusEpoch revocation requires an exact closed reason")
        snapshot = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
            allow_source_mismatch=True,
            allow_base_mismatch=True,
        )
        self._require_no_issue_cancellation_fence(
            snapshot.state, snapshot.current_ref, snapshot.pr_comments,
        )
        current = snapshot.current_authority
        if current.claim_kind == "REQUIRED_STATUS_EPOCH":
            epoch = current.artifact
            if epoch.reason_class is reason:
                return epoch
            raise StaleAuthorityError("current active RequiredStatusEpoch already represents a different reason")
        if current.claim_kind not in {
            "ISSUE_HEAD_CLAIM", "REQUIRED_STATUS_EPOCH", "ISSUE_FINALIZATION_EPOCH",
        }:
            raise StaleAuthorityError("only an active Wave 06 Issue-owned claim/epoch can be revoked")
        if current.role is CarrierRole.ISSUE_FINALIZING:
            if (
                reason is not RequiredStatusEpochReason.FINALIZATION_INVALIDATED
                or current.claim_kind != "ISSUE_FINALIZATION_EPOCH"
            ):
                raise R02Error("an active finalization epoch requires FINALIZATION_INVALIDATED revocation")
        elif reason is RequiredStatusEpochReason.FINALIZATION_INVALIDATED:
            raise R02Error("FINALIZATION_INVALIDATED requires an exact active ISSUE_FINALIZING predecessor")

        artifact = current.artifact
        if reason is RequiredStatusEpochReason.MAIN_ADVANCE_REVALIDATION:
            if getattr(artifact, "accepted_base_sha", None) == snapshot.accepted_main_sha:
                raise R02Error("MAIN_ADVANCE_REVALIDATION requires accepted main to have advanced")
        elif reason is RequiredStatusEpochReason.REQUEST_PATCH_REVALIDATION:
            origin = current.proposal_origin
            if origin is None or type(origin.artifact) is not IssueHeadClaim:
                raise R02Error("REQUEST_PATCH_REVALIDATION requires proposal-bearing claim ancestry")
            if (
                effective_request_digest(snapshot.fold.request) == origin.artifact.effective_request_digest
                and issue_patch_projection_evidence_digest(snapshot.projections)
                == origin.artifact.patch_projection_evidence_digest
            ):
                raise R02Error("REQUEST_PATCH_REVALIDATION requires changed request or PATCH evidence")
        elif reason is RequiredStatusEpochReason.SOURCE_IDENTITY_REVALIDATION:
            if snapshot.source_error is None or not snapshot.source_error.startswith("MISMATCH:"):
                raise R02Error("SOURCE_IDENTITY_REVALIDATION requires a detected source-identity mismatch")
        elif reason is RequiredStatusEpochReason.ACTIVE_REVALIDATION:
            if snapshot.source_error is not None:
                raise R02Error("ACTIVE_REVALIDATION cannot conceal unresolved source identity drift")
        elif reason is not RequiredStatusEpochReason.FINALIZATION_INVALIDATED and snapshot.source_error is not None:
            raise R02Error("this revocation reason cannot conceal unresolved source identity drift")

        prior_status = (
            _latest_exact_issue_final_status_evidence(
                self.client, self.central_repository, snapshot.current_ref, self.app,
            )
            if current.role is CarrierRole.ISSUE_FINALIZING else None
        )
        pending = tuple(
            node for node in snapshot.history
            if node.claim_kind == "REQUIRED_STATUS_EPOCH"
            and node.from_head_sha == snapshot.current_ref
        )
        replay_pending = bool(pending)
        if len(pending) > 1:
            raise R02Error("multiple pending RequiredStatusEpoch artifacts from the current head conflict")
        if pending:
            epoch = pending[0].artifact
            if (
                epoch.reason_class is not reason
                or epoch.from_provenance_kind != current.claim_kind
                or epoch.from_provenance_id != current.artifact_id
                or epoch.from_provenance_sha256 != current.artifact_sha256
                or epoch.from_carrier_role != current.role.value
                or epoch.accepted_base_sha != snapshot.accepted_main_sha
                or epoch.accepted_base_tree_sha != snapshot.accepted_main_tree_sha
            ):
                raise StaleAuthorityError("pending RequiredStatusEpoch does not match the fresh revocation authority")
        else:
            nonce = (nonce_factory or new_carrier_nonce)()
            if type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce):
                raise R02Error("RequiredStatusEpoch nonce must be lowercase 256-bit hex")
            state = snapshot.state
            epoch_fields = dict(
                schema_version=2,
                issue_number=state.issue_anchor.anchor.issue_number,
                issue_database_id=state.issue_anchor.anchor.issue_database_id,
                issue_node_id=state.issue_anchor.anchor.issue_node_id,
                issue_request_anchor_comment_database_id=state.issue_anchor.comment.database_id,
                issue_request_anchor_sha256=state.issue_anchor.anchor.canonical_sha256(),
                issue_branch_lease_comment_database_id=state.lease.comment.database_id,
                issue_branch_lease_sha256=_binding_comment_sha256(state.lease.comment),
                binding_id=state.binding.binding_id,
                source_id=state.issue_anchor.anchor.source_id,
                source_repository_id=state.issue_anchor.anchor.source_repository_id,
                pull_request_number=state.binding.pull_request_number,
                pull_request_database_id=state.binding.pull_request_database_id,
                pull_request_node_id=state.binding.pull_request_node_id,
                central_repository_node_id=state.binding.central_repository_node_id,
                branch_ref=state.binding.branch_ref,
                request_class=state.issue_anchor.anchor.request_class,
                accepted_base_sha=snapshot.accepted_main_sha,
                accepted_base_tree_sha=snapshot.accepted_main_tree_sha,
                base_ref="main",
                from_head_sha=snapshot.current_ref,
                from_tree_sha=current.tree_sha,
                to_head_sha="0" * 40,
                to_tree_sha=current.tree_sha,
                carrier_nonce=nonce,
                reason_class=reason,
                from_provenance_kind=current.claim_kind,
                from_provenance_id=current.artifact_id,
                from_provenance_sha256=current.artifact_sha256,
                from_carrier_role=current.role.value,
                prior_required_status=prior_status,
            )
            prepared = RequiredStatusEpoch.create(**epoch_fields)
            marker_text = _required_status_epoch_marker(prepared).render()
            timestamp = self.client.bot_commit_timestamp_after(
                self.central_repository, snapshot.current_ref,
            )
            wrapper = self.client.create_commit(
                self.central_repository, marker_text, current.tree_sha,
                [snapshot.current_ref], timestamp=timestamp,
            )
            epoch = RequiredStatusEpoch.create(**{
                **epoch_fields,
                "to_head_sha": wrapper.sha,
            })
            _validate_required_status_epoch_target(
                self.client, self.central_repository, epoch, state,
            )

        if not replay_pending:
            self._persist_issue_epoch_artifact(snapshot.state, epoch, snapshot.current_ref)
        before_cas = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
            allow_source_mismatch=True,
            allow_base_mismatch=True,
        )
        self._require_no_issue_cancellation_fence(
            before_cas.state, before_cas.current_ref, before_cas.pr_comments,
        )
        _require_same_managed_issue_pr_binding(snapshot.state, before_cas.state)
        if (
            before_cas.current_ref != snapshot.current_ref
            or before_cas.current_authority.claim_kind != current.claim_kind
            or before_cas.current_authority.artifact_id != current.artifact_id
            or before_cas.accepted_main_sha != epoch.accepted_base_sha
        ):
            raise StaleAuthorityError("current head, accepted main, or predecessor changed before revocation CAS")
        self._apply_persisted_issue_epoch_target(
            before_cas.state, epoch.from_head_sha, epoch.to_head_sha, snapshot.current_ref,
        )
        after_cas = self._read_issue_epoch_snapshot(
            issue_number, source_authority_resolver, semantic_validator,
            allow_source_mismatch=True,
            allow_base_mismatch=True,
        )
        _require_same_managed_issue_pr_binding(snapshot.state, after_cas.state)
        if (
            after_cas.current_ref != epoch.to_head_sha
            or after_cas.current_authority.claim_kind != "REQUIRED_STATUS_EPOCH"
            or after_cas.current_authority.artifact != epoch
            or after_cas.resolution.role is not CarrierRole.ISSUE_ACTIVE
        ):
            raise StaleAuthorityError("revocation CAS is not the exact ACTIVE(ISSUE_ACTIVE) HV")
        return epoch

    def trusted_validation_role_first(
        self,
        pr_number: int,
        legacy_disposition_resolver: Callable[[str], LegacyEvidenceDisposition] | None,
        *,
        central_recovery_dispatcher: Callable[[Wave08Decision, IssueOwnerPR, IssueCancellationFence | None], Any] | None = None,
        machine_validation_dispatcher: Callable[[Wave08Decision, MachinePRAuthority], Any] | None = None,
    ) -> Wave08Decision:
        """Resolve the fresh PR head's SHA role before reading PR-specific authority."""
        if type(pr_number) is not int or not 1 <= pr_number <= 9_223_372_036_854_775_807:
            raise R02Error("role-first validation requires a positive exact PR number")
        if central_recovery_dispatcher is not None and not callable(central_recovery_dispatcher):
            raise R02Error("central recovery dispatcher must be a semantic callable")
        if machine_validation_dispatcher is not None and not callable(machine_validation_dispatcher):
            raise R02Error("machine validation dispatcher must be a semantic callable")

        pr = self.client.get_pull_request_metadata(self.central_repository, pr_number)
        if type(pr) is not PullRequestMetadata or pr.number != pr_number:
            raise StaleAuthorityError("fresh role-first PR identity is malformed")
        head_sha = pr.head_oid
        if type(head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
            raise StaleAuthorityError("fresh role-first PR head is not exact lowercase 40-hex")

        def exact_legacy_disposition() -> LegacyEvidenceDisposition:
            return wave08_legacy_disposition(head_sha, legacy_disposition_resolver)

        resolution = resolve_sha_carrier_role(
            self.client, self.central_repository, head_sha, self.app.slug,
            exact_legacy_disposition,
        )
        pull_request_numbers = (pr_number,)

        def blocked(reason: Wave08DecisionReason) -> Wave08Decision:
            return Wave08Decision(
                head_sha, resolution, pull_request_numbers, None,
                Wave08DecisionKind.CONFLICTING_BLOCKED, reason,
            )

        if resolution.activation in {
            CarrierActivation.CONFLICTING,
            CarrierActivation.LEGACY_CUTOVER_QUARANTINE,
            CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION,
        }:
            decision = wave08_decision_for_resolution(head_sha, resolution, pull_request_numbers)
            if decision.kind is Wave08DecisionKind.EXTERNAL_STATUS:
                central = self.client.get_repository_metadata(self.central_repository)
                fresh_app = resolve_app_identity(self.client, self.app.slug)
                if (
                    type(central) is not RepositoryMetadata
                    or central.full_name != self.central_repository
                    or central.default_branch != "main"
                    or fresh_app != self.app
                ):
                    return blocked(Wave08DecisionReason.FRESH_AUTHORITY_FAILED)
                publish_unclaimed_external_success(
                    self.client, central, head_sha, resolution, fresh_app,
                )
            return decision

        if resolution.role is CarrierRole.MACHINE_PUBLICATION:
            if resolution.activation is CarrierActivation.RESERVED_INACTIVE:
                return wave08_decision_for_resolution(head_sha, resolution, pull_request_numbers)
            marker = resolution.marker
            if (
                resolution.activation is not CarrierActivation.ACTIVE
                or marker is None
                or marker.owner_kind != "MACHINE_SOURCE"
                or marker.claim_kind != "MACHINE_REF_CLAIM"
            ):
                return blocked(Wave08DecisionReason.FRESH_AUTHORITY_FAILED)
            try:
                repository, accepted_main = self.current_accepted_main()
                if repository.default_branch != "main":
                    raise StaleAuthorityError("machine role requires central main")
                accepted_sources = self._accepted_sources(accepted_main)
                owner_key_matches = tuple(
                    source for source in accepted_sources
                    if marker.owner_key == f"{repository.node_id}:{source.source_id}"
                )
                if len(owner_key_matches) != 1:
                    raise StaleAuthorityError("machine claim owner is not one exact accepted source")
                source = owner_key_matches[0]
                authority = self._machine_authority(
                    {"number": pr_number}, source, accepted_main, repository,
                )
                current_machine_ref = self.client.get_ref_oid(
                    self.central_repository, f"bot/federation/{source.source_id}",
                )
                if (
                    authority is None
                    or not authority.valid
                    or authority.number != pr_number
                    or authority.source_id != source.source_id
                    or authority.repository_id != source.repository_id
                    or authority.head_sha != head_sha
                    or current_machine_ref != head_sha
                    or pr.head_ref != _machine_branch(source.source_id)
                    or pr.head_repository != repository.full_name
                    or pr.head_repository_id != repository.node_id
                    or pr.base_repository != repository.full_name
                    or pr.base_repository_id != repository.node_id
                    or pr.base_oid != accepted_main
                ):
                    raise StaleAuthorityError("machine PR/ref/source owner does not bind the exact role head")
                decision = wave08_decision_for_resolution(
                    head_sha, resolution, pull_request_numbers, owner_pr_number=pr_number,
                    machine_target=Wave08DispatchTarget.MACHINE_VALIDATION,
                )
            except Exception:
                return blocked(Wave08DecisionReason.FRESH_AUTHORITY_FAILED)
            if machine_validation_dispatcher is not None:
                try:
                    machine_validation_dispatcher(decision, authority)
                except Exception:
                    return blocked(Wave08DecisionReason.DISPATCH_FAILED)
            return decision

        if resolution.role not in {
            CarrierRole.ISSUE_ACTIVE,
            CarrierRole.ISSUE_FINALIZING,
            CarrierRole.ISSUE_CANCEL,
        }:
            return blocked(Wave08DecisionReason.FRESH_AUTHORITY_FAILED)
        try:
            owner = derive_issue_owner_pr(
                self.client, self.central_repository, head_sha, resolution, self.app.slug,
            )
        except Exception:
            return blocked(Wave08DecisionReason.FRESH_AUTHORITY_FAILED)
        if owner.pull_request_number != pr_number:
            return wave08_decision_for_resolution(head_sha, resolution, pull_request_numbers)

        fence: IssueCancellationFence | None = None
        if (
            resolution.role is CarrierRole.ISSUE_CANCEL
            and resolution.activation is CarrierActivation.ACTIVE
        ):
            try:
                cancellation = _fresh_issue_cancellation_authority(
                    self.client, self.central_repository, owner.issue_number, self.app,
                    allow_pr_stage_state=True,
                )
                current_ref = _read_issue_branch_ref(
                    self.client, self.central_repository,
                    cancellation.lease.lease.branch_ref.removeprefix("refs/heads/"),
                )
                fences, _comments = self._read_issue_cancellation_fences(
                    cancellation, current_ref or ZERO_OID,
                )
                exact_fences = tuple(
                    item.fence for item in fences
                    if item.fence.cancellation_head_sha == head_sha
                    and _issue_cancellation_fence_marker(item.fence) == resolution.marker
                )
                if (
                    len(exact_fences) != 1
                    or cancellation.pull_request_number != pr_number
                    or current_ref != head_sha
                    or cancellation.pr.head_oid != head_sha
                    or cancellation.raw_pr_state != "OPEN"
                    or cancellation.raw_pr_merged
                ):
                    raise StaleAuthorityError("current cancellation fence/owner PR is not exact")
                fence = exact_fences[0]
                self.publish_issue_cancel_failure(owner.issue_number, fence)
            except Exception:
                return blocked(Wave08DecisionReason.FRESH_AUTHORITY_FAILED)

        decision = wave08_decision_for_resolution(
            head_sha, resolution, pull_request_numbers, owner_pr_number=pr_number,
        )
        if central_recovery_dispatcher is not None:
            try:
                central_recovery_dispatcher(decision, owner, fence)
            except Exception:
                return blocked(Wave08DecisionReason.DISPATCH_FAILED)
        return decision

    def recover_issue_first_authority(
        self,
        issue_number: int,
        source_authority_resolver: Callable[[Request, RequestClass], IssueSourceAuthority],
        *,
        semantic_validator: Callable[[Request], bool] | None = None,
        nonce_factory: Callable[[], str] | None = None,
    ) -> Wave08IssueRecoveryRecord:
        """Wg1-like explicit Issue intake/terminal recovery using Wave 02-07 authorities."""
        if type(issue_number) is not int or not 1 <= issue_number <= 9_223_372_036_854_775_807:
            raise R02Error("Issue recovery requires a positive exact Issue number")
        if not callable(source_authority_resolver):
            raise R02Error("Issue recovery requires a fresh source-authority resolver")

        # The cancellation classifier is deliberately the first authority path.
        # A missing anchor is the sole expected reason to fall through to open intake.
        terminal_state: IssueCancellationState | None = None
        try:
            terminal_state = self._read_issue_cancellation_state(issue_number)
        except DuplicateAnchorError as error:
            try:
                snapshot = self.client.get_issue_metadata(self.central_repository, issue_number)
            except Exception as read_error:
                raise StaleAuthorityError(
                    f"Issue identity is unavailable after anchor classification: {_bounded_reason(read_error)}"
                ) from None
            if (
                type(snapshot) is not IssueMetadata
                or snapshot.number != issue_number
                or snapshot.is_pull_request
            ):
                raise StaleAuthorityError("fresh Issue identity is malformed after anchor classification") from None
            if snapshot.state != "open":
                return Wave08IssueRecoveryRecord(
                    issue_number, snapshot.database_id, snapshot.node_id,
                    "BLOCKED", f"CLOSED_ISSUE_REQUIRES_UNIQUE_ANCHOR:{_bounded_reason(error)}",
                )
            terminal_state = None
        except Exception as error:
            # A closed Issue with malformed/ambiguous cancellation authority must
            # not be reinterpreted through live source-registry eligibility.
            try:
                snapshot = self.client.get_issue_metadata(self.central_repository, issue_number)
            except Exception:
                raise StaleAuthorityError(
                    f"Issue cancellation authority is unavailable: {_bounded_reason(error)}"
                ) from None
            if type(snapshot) is not IssueMetadata or snapshot.number != issue_number or snapshot.is_pull_request:
                raise StaleAuthorityError("fresh Issue identity is malformed during cancellation recovery") from None
            if snapshot.state != "open":
                raise StaleAuthorityError(
                    f"closed Issue cancellation classification is blocked: {_bounded_reason(error)}"
                ) from None
            # Open unanchored Issues do not yet have cancellation provenance.
            terminal_state = None

        if terminal_state is not None and terminal_state.issue.state == "closed":
            state = terminal_state
            if state.classification in {
                IssueCancellationClass.A_ANCHOR_ONLY,
                IssueCancellationClass.B_LEASE_REF_ABSENT,
                IssueCancellationClass.C_LEASE_ZERO_PR,
            }:
                result = self.cancel_issue_without_pr(issue_number)
                return Wave08IssueRecoveryRecord(
                    issue_number, state.issue.database_id, state.issue.node_id,
                    "CANCELLED_NO_PR", result.proof_kind.value,
                )
            if state.classification is IssueCancellationClass.F_CONFLICTING:
                return Wave08IssueRecoveryRecord(
                    issue_number, state.issue.database_id, state.issue.node_id,
                    "BLOCKED", "CANCELLATION_CLASS_F_CONFLICTING",
                )
            if state.classification not in {
                IssueCancellationClass.D_PRE_BINDING_ONE_PR,
                IssueCancellationClass.E_FULL_BINDING,
            }:
                return Wave08IssueRecoveryRecord(
                    issue_number, state.issue.database_id, state.issue.node_id,
                    "BLOCKED", "UNKNOWN_CANCELLATION_CLASS",
                )
            if state.merge_observed:
                if state.classification is IssueCancellationClass.E_FULL_BINDING:
                    return Wave08IssueRecoveryRecord(
                        issue_number, state.issue.database_id, state.issue.node_id,
                        "MERGE_WINS", "POST_MERGE_RECOVERY_REQUIRED",
                    )
                return Wave08IssueRecoveryRecord(
                    issue_number, state.issue.database_id, state.issue.node_id,
                    "PRESERVED", "MERGED_PRE_BINDING_HAS_NO_CANCELLATION_DELETE_AUTHORITY",
                )

            fence = self.prepare_issue_cancellation_fence(
                issue_number,
                classification="D" if state.classification is IssueCancellationClass.D_PRE_BINDING_ONE_PR else "E",
                nonce_factory=nonce_factory,
            )
            try:
                self._require_current_cancel_failure(fence)
            except Exception as error:
                return Wave08IssueRecoveryRecord(
                    issue_number, state.issue.database_id, state.issue.node_id,
                    "DEFERRED", f"WAITING_FOR_WG6_CANCEL_FAILURE:{_bounded_reason(error)}",
                )
            self.establish_issue_cancellation_draft_witness(issue_number)
            self.establish_issue_terminal_cancelled_result(issue_number)
            terminal = self.cleanup_issue_cancelled_branch(issue_number)
            return Wave08IssueRecoveryRecord(
                issue_number, state.issue.database_id, state.issue.node_id,
                "CANCELLED_PR_BACKED", "EXACT_TERMINAL_RESULT_AND_REF_CAS_VERIFIED",
            )

        if terminal_state is not None:
            if terminal_state.classification is IssueCancellationClass.F_CONFLICTING:
                return Wave08IssueRecoveryRecord(
                    issue_number, terminal_state.issue.database_id, terminal_state.issue.node_id,
                    "BLOCKED", "OPEN_ISSUE_CANCELLATION_PROVENANCE_CONFLICT",
                )
            if (
                terminal_state.issue.state == "open"
                and terminal_state.classification in {
                    IssueCancellationClass.D_PRE_BINDING_ONE_PR,
                    IssueCancellationClass.E_FULL_BINDING,
                }
            ):
                authority = terminal_state.cancellation_authority
                head_sha = authority.pr.head_oid if authority is not None else None
                if type(head_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", head_sha) is None:
                    return Wave08IssueRecoveryRecord(
                        issue_number, terminal_state.issue.database_id, terminal_state.issue.node_id,
                        "DEFERRED", "CURRENT_ISSUE_CARRIER_ROLE_UNAVAILABLE_FOR_WG1",
                    )
                try:
                    current_resolution = resolve_sha_carrier_role(
                        self.client, self.central_repository, head_sha, self.app.slug,
                        LegacyEvidenceDisposition.CONFLICTING,
                    )
                except Exception:
                    current_resolution = _conflicting_sha_carrier()
                if current_resolution.role is CarrierRole.ISSUE_FINALIZING and current_resolution.activation in {
                    CarrierActivation.ACTIVE,
                    CarrierActivation.RESERVED_INACTIVE,
                }:
                    return Wave08IssueRecoveryRecord(
                        issue_number, terminal_state.issue.database_id, terminal_state.issue.node_id,
                        "DEFERRED", "ISSUE_FINALIZER_OWNED_BY_WG4",
                    )
                if current_resolution.activation not in {
                    CarrierActivation.ACTIVE,
                    CarrierActivation.RESERVED_INACTIVE,
                }:
                    return Wave08IssueRecoveryRecord(
                        issue_number, terminal_state.issue.database_id, terminal_state.issue.node_id,
                        "DEFERRED", "CURRENT_ISSUE_CARRIER_ROLE_UNRESOLVED_FOR_WG1",
                    )
            issue = terminal_state.issue
            comments = terminal_state.issue_comments
        else:
            try:
                issue = self.client.get_issue_metadata(self.central_repository, issue_number)
                comments = tuple(self.client.list_issue_comments(self.central_repository, issue_number))
            except Exception as error:
                raise StaleAuthorityError(f"fresh open Issue intake authority is unavailable: {_bounded_reason(error)}") from None
        if (
            type(issue) is not IssueMetadata
            or issue.number != issue_number
            or issue.is_pull_request
            or issue.state != "open"
        ):
            return Wave08IssueRecoveryRecord(
                issue_number,
                issue.database_id if type(issue) is IssueMetadata else None,
                issue.node_id if type(issue) is IssueMetadata else None,
                "NOOP", "ISSUE_NOT_OPEN",
            )

        try:
            repository = self.client.get_repository_metadata(self.central_repository)
            current_app = resolve_app_identity(self.client, self.app.slug)
            if (
                type(repository) is not RepositoryMetadata
                or repository.full_name != self.central_repository
                or repository.default_branch != "main"
                or not repository.node_id
                or current_app != self.app
            ):
                raise StaleAuthorityError("central repository/App identity is not the exact current main")
        except Exception as error:
            raise StaleAuthorityError(f"Issue intake central authority is unavailable: {_bounded_reason(error)}") from None

        try:
            anchors = _issue_anchor_candidates(comments)
            if len(anchors) > 1:
                raise R02Error("duplicate IssueRequestAnchor comments block intake")
            if anchors:
                anchor = validate_unique_issue_anchor(comments, issue, current_app)
                fresh_source = source_authority_resolver(
                    anchor.anchor.initial_request, anchor.anchor.request_class,
                )
                _validate_issue_source_authority(anchor.anchor, fresh_source)
                anchor = create_or_validate_issue_anchor(
                    self.client, self.central_repository, issue, comments,
                    current_app, fresh_source, source_authority_resolver,
                )
            else:
                try:
                    request = parse_issue_request_body(issue.body)
                except RequestModelError as error:
                    if type(issue.body) is str and issue.body.lstrip().startswith("### Federation request type"):
                        return Wave08IssueRecoveryRecord(
                            issue_number, issue.database_id, issue.node_id,
                            "BLOCKED", f"MALFORMED_RECOGNIZED_ISSUE_REQUEST:{_bounded_reason(error)}",
                        )
                    return Wave08IssueRecoveryRecord(
                        issue_number, issue.database_id, issue.node_id,
                        "NOOP", "UNRELATED_OPEN_ISSUE",
                    )
                source_authority = source_authority_resolver(request, request.request_class)
                anchor = create_or_validate_issue_anchor(
                    self.client, self.central_repository, issue, comments,
                    current_app, source_authority, source_authority_resolver,
                )
            lease = create_or_validate_issue_branch_lease(
                self.client, self.central_repository, anchor, current_app,
                repository.node_id, source_authority_resolver,
                nonce_factory=nonce_factory,
            )
            binding_state = create_or_recover_issue_pr_binding(
                self.client, self.central_repository, issue_number, current_app,
                repository.node_id, source_authority_resolver,
            )
            if binding_state.lease != lease.lease or binding_state.issue_anchor != anchor:
                raise StaleAuthorityError("recovered Issue lease/binding differs from the exact anchor authority")
            if self.candidate_builder is None:
                return Wave08IssueRecoveryRecord(
                    issue_number, issue.database_id, issue.node_id,
                    "BINDING_READY", "EXACT_ANCHOR_LEASE_AND_PR_BINDING_RECOVERED",
                )
            route = self.interactive_issue_managed_route(
                issue_number, source_authority_resolver,
                semantic_validator=semantic_validator,
                nonce_factory=nonce_factory,
            )
            return Wave08IssueRecoveryRecord(
                issue_number, issue.database_id, issue.node_id,
                route.outcome, route.reason,
            )
        except Exception as error:
            return Wave08IssueRecoveryRecord(
                issue_number, issue.database_id, issue.node_id,
                "BLOCKED", _bounded_reason(error),
            )

    def recover_universal_role_first(
        self,
        legacy_disposition_resolver: Callable[[str], LegacyEvidenceDisposition] | None,
        *,
        issue_intake_terminal_dispatcher: Callable[[Wave08IssueRecoveryIntent], Any] | None = None,
        issue_finalizer_dispatcher: Callable[[Wave08Decision, IssueOwnerPR], Any] | None = None,
        machine_validation_dispatcher: Callable[[Wave08Decision, MachinePRAuthority], Any] | None = None,
        machine_finalizer_dispatcher: Callable[[Wave08Decision, MachinePRAuthority], Any] | None = None,
        max_pages: int = 100,
    ) -> Wave08UniversalRecoveryResult:
        """Wg6-like bounded inventory, SHA-role-first dispatch and status recovery."""
        if type(max_pages) is not int or not 1 <= max_pages <= 100:
            raise R02Error("universal recovery max_pages must be an exact integer from 1 to 100")
        callbacks = (
            issue_intake_terminal_dispatcher,
            issue_finalizer_dispatcher,
            machine_validation_dispatcher,
            machine_finalizer_dispatcher,
        )
        if any(callback is not None and not callable(callback) for callback in callbacks):
            raise R02Error("universal recovery callbacks must be semantic callables")

        # Complete every required bounded inventory before any write or dispatch.
        inventories: dict[str, tuple[Any, ...]] = {}
        inventory_errors: list[str] = []
        for key, reader in (
            ("open_prs", lambda: self.client.list_open_pull_requests(self.central_repository, max_pages=max_pages)),
            ("issues", lambda: self.client.list_repository_issues(self.central_repository, state="all", max_pages=max_pages)),
            ("machine_refs", lambda: self.client.list_machine_refs(self.central_repository, max_pages=max_pages)),
        ):
            try:
                value = reader()
                if type(value) not in {tuple, list}:
                    raise R02Error(f"{key} bounded inventory did not return a sequence")
                inventories[key] = tuple(value)
            except Exception as error:
                inventory_errors.append(f"{key}:{_bounded_reason(error)}")
        if inventory_errors:
            return Wave08UniversalRecoveryResult(
                False, len(inventories.get("open_prs", ())), 0, 0,
                len(inventories.get("issues", ())), 0,
                len(inventories.get("machine_refs", ())), (), (), (), (), (),
                tuple(inventory_errors), 0,
            )

        raw_prs = inventories["open_prs"]
        raw_issues = inventories["issues"]
        raw_machine_refs = inventories["machine_refs"]
        blocked: list[str] = []
        deferred_count = 0
        machine_inventory_ambiguous = False
        seen_pr_numbers: set[int] = set()
        seen_issue_numbers: set[int] = set()
        seen_machine_refs: set[str] = set()
        pr_inventory_valid = True
        for row in raw_prs:
            if (
                type(row) is not dict
                or type(row.get("number")) is not int
                or not 1 <= row["number"] <= 9_223_372_036_854_775_807
                or row["number"] in seen_pr_numbers
            ):
                pr_inventory_valid = False
                break
            seen_pr_numbers.add(row["number"])
        if not pr_inventory_valid:
            blocked.append("OPEN_PR_INVENTORY_ROWS_MALFORMED_OR_DUPLICATE")
        issue_inventory_valid = True
        for row in raw_issues:
            if (
                type(row) is not dict
                or type(row.get("number")) is not int
                or not 1 <= row["number"] <= 9_223_372_036_854_775_807
                or row["number"] in seen_issue_numbers
            ):
                issue_inventory_valid = False
                break
            seen_issue_numbers.add(row["number"])
        if not issue_inventory_valid:
            blocked.append("ISSUE_INVENTORY_ROWS_MALFORMED_OR_DUPLICATE")

        machine_rows: list[dict[str, str]] = []
        for row in raw_machine_refs:
            if (
                type(row) is not dict
                or type(row.get("ref")) is not str
                or type(row.get("source_id")) is not str
                or type(row.get("sha")) is not str
                or re.fullmatch(r"refs/heads/bot/federation/[a-z0-9]+(?:-[a-z0-9]+)*", row["ref"]) is None
                or row["ref"] != f"refs/heads/bot/federation/{row['source_id']}"
                or not _is_canonical_wave08_source_id(row["source_id"])
                or re.fullmatch(r"[0-9a-f]{40}", row["sha"]) is None
                or row["ref"] in seen_machine_refs
            ):
                blocked.append("MACHINE_REF_ROW_MALFORMED_OR_DUPLICATE")
                machine_inventory_ambiguous = True
                continue
            seen_machine_refs.add(row["ref"])
            machine_rows.append({"ref": row["ref"], "source_id": row["source_id"], "sha": row["sha"]})

        try:
            central = self.client.get_repository_metadata(self.central_repository)
            current_app = resolve_app_identity(self.client, self.app.slug)
            if (
                type(central) is not RepositoryMetadata
                or central.full_name != self.central_repository
                or central.default_branch != "main"
                or not central.node_id
                or current_app != self.app
            ):
                raise StaleAuthorityError("central repository/App identity is not the exact current main")
        except Exception as error:
            blocked.append(f"CENTRAL_APP_AUTHORITY_UNAVAILABLE:{_bounded_reason(error)}")
            central = None
            current_app = None

        fresh_prs: dict[int, PullRequestMetadata] = {}
        head_groups: dict[str, list[PullRequestMetadata]] = {}
        failed_fresh_pr_numbers: set[int] = set()
        global_head_ambiguous = not pr_inventory_valid
        for row in sorted((item for item in raw_prs if type(item) is dict), key=lambda item: item.get("number", 0) if type(item.get("number")) is int else 0):
            number = row.get("number")
            if type(number) is not int:
                continue
            try:
                pr = self.client.get_pull_request_metadata(self.central_repository, number)
                if (
                    type(pr) is not PullRequestMetadata
                    or pr.number != number
                    or type(pr.head_oid) is not str
                    or re.fullmatch(r"[0-9a-f]{40}", pr.head_oid) is None
                ):
                    raise R02Error("fresh PR metadata/head is malformed")
            except Exception as error:
                failed_fresh_pr_numbers.add(number)
                blocked.append(f"PR_{number}_FRESH_METADATA_UNAVAILABLE:{_bounded_reason(error)}")
                continue
            fresh_prs[number] = pr
            head_groups.setdefault(pr.head_oid, []).append(pr)
        for group in head_groups.values():
            group.sort(key=lambda item: item.number)

        fresh_issues: dict[int, tuple[IssueMetadata, tuple[IssueComment, ...], str | None]] = {}
        issue_inventory_records: dict[int, Wave08IssueRecoveryRecord] = {}
        relevant_issue_numbers: set[int] = set()
        if current_app is None:
            issue_app = None
        else:
            issue_app = current_app
        recognized_markers = (
            ISSUE_REQUEST_ANCHOR_MARKER,
            ISSUE_BRANCH_LEASE_MARKER,
            ISSUE_INTERNAL_PR_BINDING_MARKER,
            ISSUE_CANCELLATION_FENCE_MARKER,
            ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER,
            ISSUE_TERMINAL_CANCELLED_RESULT_MARKER,
            ISSUE_NO_PR_CANCELLED_RESULT_MARKER,
            ISSUE_PATCH_PROJECTION_MARKER,
            ISSUE_HEAD_CLAIM_MARKER,
            REQUIRED_STATUS_EPOCH_MARKER,
            ISSUE_FINALIZATION_EPOCH_MARKER,
        )
        for row in sorted((item for item in raw_issues if type(item) is dict), key=lambda item: item.get("number", 0) if type(item.get("number")) is int else 0):
            number = row.get("number")
            if type(number) is not int:
                continue
            try:
                issue = self.client.get_issue_metadata(self.central_repository, number)
                if (
                    type(issue) is not IssueMetadata
                    or issue.number != number
                    or issue.is_pull_request
                ):
                    raise R02Error("fresh Issue metadata differs from exact Issue inventory identity")
                comments = tuple(self.client.list_issue_comments(self.central_repository, number))
                if any(type(comment) is not IssueComment for comment in comments):
                    raise R02Error("Issue comment inventory contains a malformed record")
            except Exception as error:
                reason = f"FRESH_AUTHORITY_UNAVAILABLE:{_bounded_reason(error)}"
                blocked.append(f"ISSUE_{number}_{reason}")
                issue_inventory_records[number] = Wave08IssueRecoveryRecord(
                    number, None, None, "BLOCKED", reason,
                )
                continue

            relevant = False
            issue_reason: str | None = None
            recognized = [comment for comment in comments if any(
                type(comment.body) is str and comment.body.startswith(marker)
                for marker in recognized_markers
            )]
            if recognized:
                relevant = True
                if issue_app is None:
                    issue_reason = "APP_IDENTITY_UNAVAILABLE_FOR_RECOGNIZED_ARTIFACT"
                else:
                    try:
                        anchors = _issue_anchor_candidates(comments)
                        if anchors:
                            validate_unique_issue_anchor(comments, issue, issue_app)
                        elif any(comment.body.startswith(ISSUE_REQUEST_ANCHOR_MARKER) for comment in recognized):
                            raise R02Error("IssueRequestAnchor was recognized but not parsed")
                        # Parse every recognized marker and validate its immutable
                        # App-authored comment envelope before retaining relevance.
                        for comment in recognized:
                            body = comment.body
                            if body.startswith(ISSUE_REQUEST_ANCHOR_MARKER):
                                parse_issue_request_anchor(body)
                                _epoch_comment_authority(comment, issue_app, "IssueRequestAnchor")
                            elif body.startswith(ISSUE_BRANCH_LEASE_MARKER):
                                parse_issue_branch_lease(body)
                                _epoch_comment_authority(comment, issue_app, "IssueBranchLease")
                            elif body.startswith(ISSUE_INTERNAL_PR_BINDING_MARKER):
                                parse_issue_internal_pr_binding(body)
                                _epoch_comment_authority(comment, issue_app, "IssueInternalPRBinding")
                            elif body.startswith(ISSUE_CANCELLATION_FENCE_MARKER):
                                parse_issue_cancellation_fence(body)
                                _epoch_comment_authority(comment, issue_app, "IssueCancellationFence")
                            elif body.startswith(ISSUE_CANCELLATION_DRAFT_WITNESS_MARKER):
                                parse_issue_cancellation_draft_witness(body)
                                _epoch_comment_authority(comment, issue_app, "IssueCancellationDraftWitness")
                            elif body.startswith(ISSUE_TERMINAL_CANCELLED_RESULT_MARKER):
                                parse_issue_terminal_cancelled_result(body)
                                _epoch_comment_authority(comment, issue_app, "IssueTerminalCancelledResult")
                            elif body.startswith(ISSUE_NO_PR_CANCELLED_RESULT_MARKER):
                                parse_issue_no_pr_cancelled_result(body)
                                _epoch_comment_authority(comment, issue_app, "IssueNoPRCancelledResult")
                            elif body.startswith(ISSUE_PATCH_PROJECTION_MARKER):
                                parse_issue_patch_projection(body)
                                _epoch_comment_authority(comment, issue_app, "IssuePatchProjection")
                                raise R02Error("IssuePatchProjection is not valid on the owning Issue")
                            else:
                                # Claimed-head artifacts belong on the generated
                                # PR, so their appearance on an Issue blocks it.
                                parser = (
                                    parse_issue_head_claim if body.startswith(ISSUE_HEAD_CLAIM_MARKER)
                                    else parse_required_status_epoch if body.startswith(REQUIRED_STATUS_EPOCH_MARKER)
                                    else parse_issue_finalization_epoch
                                )
                                parser(body)
                                _epoch_comment_authority(comment, issue_app, "IssueHeadAuthority")
                                raise R02Error("claimed-head epoch artifact is misplaced on the owning Issue")
                        if anchors and central is not None:
                            _resolve_issue_branch_lease_class(
                                self.client, self.central_repository, comments, issue_app,
                                anchors[0].anchor, anchors[0].comment.database_id, central.node_id,
                            )
                    except Exception as error:
                        issue_reason = f"RECOGNIZED_ARTIFACT_BLOCKED:{_bounded_reason(error)}"
            if issue.state == "open" and not recognized:
                try:
                    parse_issue_request_body(issue.body)
                    relevant = True
                except RequestModelError as error:
                    if type(issue.body) is str and issue.body.lstrip().startswith("### Federation request type"):
                        relevant = True
                        issue_reason = f"MALFORMED_RECOGNIZED_ISSUE_REQUEST:{_bounded_reason(error)}"
            if relevant:
                relevant_issue_numbers.add(number)
            fresh_issues[number] = (issue, comments, issue_reason)

        # Load accepted-source authority once, after the complete inventories and
        # fresh central identity are known. Failure defers machine routing only.
        machine_sources: tuple[c02.SourceDeclaration, ...] | None = None
        machine_main: str | None = None
        if machine_rows and central is not None:
            try:
                machine_main = self.client.get_ref_oid(self.central_repository, "main")
                machine_sources = self._accepted_sources(machine_main)
            except Exception as error:
                blocked.append(f"ACCEPTED_MACHINE_SOURCE_AUTHORITY_UNAVAILABLE:{_bounded_reason(error)}")

        machine_refs_by_sha: dict[str, list[dict[str, str]]] = {}
        for row in machine_rows:
            machine_refs_by_sha.setdefault(row["sha"], []).append(row)

        decisions: list[Wave08Decision] = []
        issue_intents_by_key: dict[tuple[str, int], Wave08IssueRecoveryIntent] = {}
        finalizer_owned_issue_keys: set[tuple[str, int]] = set()
        finalizer_work: list[tuple[Wave08Decision, IssueOwnerPR]] = []
        machine_work: list[tuple[Wave08Decision, MachinePRAuthority, Wave08DispatchTarget]] = []
        status_actions: list[tuple[str, str]] = []
        issue_records_by_number: dict[int, Wave08IssueRecoveryRecord] = dict(issue_inventory_records)

        for number in sorted(relevant_issue_numbers):
            issue, _comments, reason = fresh_issues[number]
            if reason is not None:
                issue_records_by_number[number] = Wave08IssueRecoveryRecord(
                    number, issue.database_id, issue.node_id, "BLOCKED", reason,
                )
                blocked.append(f"ISSUE_{number}:{reason}")
                continue
            if central is None:
                reason = "CENTRAL_REPOSITORY_IDENTITY_UNAVAILABLE"
                issue_records_by_number[number] = Wave08IssueRecoveryRecord(
                    number, issue.database_id, issue.node_id, "BLOCKED", reason,
                )
                blocked.append(f"ISSUE_{number}:{reason}")
                continue
            target = (
                Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY
                if issue.state == "closed"
                else Wave08DispatchTarget.ISSUE_INTAKE_TERMINAL_RECOVERY
            )
            intent = Wave08IssueRecoveryIntent(
                target, central.node_id,
                number, "ALL_ISSUE_RECOVERY_INVENTORY",
            )
            issue_intents_by_key[(intent.central_repository_node_id, number)] = intent
            issue_records_by_number[number] = Wave08IssueRecoveryRecord(
                number, issue.database_id, issue.node_id, "DISPATCH_INTENT", intent.target.value,
            )

        if global_head_ambiguous:
            blocked.append("FRESH_PR_HEAD_UNAVAILABLE_OR_GROUPING_AMBIGUOUS; SHA ACTIONS SUPPRESSED")
        elif central is not None and current_app is not None:
            for head_sha in sorted(head_groups):
                prs = head_groups[head_sha]
                numbers = tuple(pr.number for pr in prs)
                resolution = resolve_sha_carrier_role(
                    self.client, self.central_repository, head_sha, self.app.slug,
                    lambda exact_sha=head_sha: wave08_legacy_disposition(
                        exact_sha, legacy_disposition_resolver,
                    ),
                )
                machine_rows_for_head = machine_refs_by_sha.get(head_sha, [])
                if resolution.activation is CarrierActivation.UNCLAIMED_OUT_OF_FEDERATION and (
                    machine_rows_for_head or machine_inventory_ambiguous
                ):
                    decision = Wave08Decision(
                        head_sha, resolution, numbers, None,
                        Wave08DecisionKind.CONFLICTING_BLOCKED,
                        Wave08DecisionReason.CONFLICTING_EVIDENCE,
                    )
                    decisions.append(decision)
                    blocked.append(f"{head_sha}:UNCLAIMED_SUPPRESSED_BY_MACHINE_REF_NAMESPACE")
                    continue
                if (
                    resolution.role is CarrierRole.MACHINE_PUBLICATION
                    and resolution.activation in {CarrierActivation.ACTIVE, CarrierActivation.RESERVED_INACTIVE}
                ):
                    marker = resolution.marker
                    if (
                        marker is None or marker.owner_kind != "MACHINE_SOURCE"
                        or marker.claim_kind != "MACHINE_REF_CLAIM"
                    ):
                        decisions.append(Wave08Decision(
                            head_sha, ShaCarrierResolution(CarrierActivation.CONFLICTING, marker=marker),
                            numbers, None, Wave08DecisionKind.CONFLICTING_BLOCKED,
                            Wave08DecisionReason.CONFLICTING_EVIDENCE,
                        ))
                        blocked.append(f"{head_sha}:MACHINE_MARKER_NOT_EXACT")
                        continue
                    if resolution.activation is CarrierActivation.RESERVED_INACTIVE:
                        decisions.append(wave08_decision_for_resolution(head_sha, resolution, numbers))
                        deferred_count += 1
                        continue
                    owner_key_prefix = f"{central.node_id}:"
                    source_id = marker.owner_key[len(owner_key_prefix):] if marker.owner_key.startswith(owner_key_prefix) else ""
                    sources = tuple(
                        source for source in (machine_sources or ())
                        if source.source_id == source_id and marker.owner_key == f"{central.node_id}:{source.source_id}"
                    )
                    matching_refs = tuple(
                        row for row in machine_rows_for_head
                        if row["source_id"] == source_id
                        and row["ref"] == f"refs/heads/bot/federation/{source_id}"
                    )
                    matching_prs = tuple(
                        pr for pr in prs
                        if source_id and pr.head_ref == _machine_branch(source_id)
                        and pr.head_repository_id == central.node_id
                        and pr.head_repository == central.full_name
                        and pr.base_repository_id == central.node_id
                        and pr.base_repository == central.full_name
                        and pr.base_ref == "main"
                    )
                    if len(sources) != 1 or len(matching_refs) != 1 or len(matching_prs) != 1:
                        decisions.append(Wave08Decision(
                            head_sha, ShaCarrierResolution(CarrierActivation.CONFLICTING, marker=marker),
                            numbers, None, Wave08DecisionKind.CONFLICTING_BLOCKED,
                            Wave08DecisionReason.FRESH_AUTHORITY_FAILED,
                        ))
                        blocked.append(f"{head_sha}:MACHINE_OWNER_SOURCE_REF_OR_PR_NOT_EXACT")
                        continue
                    try:
                        authority = self._machine_authority(
                            {"number": matching_prs[0].number}, sources[0],
                            machine_main or "", central,
                        )
                        if (
                            authority is None or not authority.valid
                            or authority.head_sha != head_sha
                            or matching_refs[0]["sha"] != head_sha
                        ):
                            raise StaleAuthorityError("machine PR/ref/source does not bind exact active H")
                        decision = wave08_decision_for_resolution(
                            head_sha, resolution, numbers,
                            owner_pr_number=authority.number,
                            machine_target=Wave08DispatchTarget.MACHINE_VALIDATION,
                        )
                        decisions.append(decision)
                        machine_work.append((decision, authority, Wave08DispatchTarget.MACHINE_VALIDATION))
                    except Exception as error:
                        decisions.append(Wave08Decision(
                            head_sha, ShaCarrierResolution(CarrierActivation.CONFLICTING, marker=marker),
                            numbers, None, Wave08DecisionKind.CONFLICTING_BLOCKED,
                            Wave08DecisionReason.FRESH_AUTHORITY_FAILED,
                        ))
                        blocked.append(f"{head_sha}:MACHINE_AUTHORITY_FAILED:{_bounded_reason(error)}")
                    continue

                owner: IssueOwnerPR | None = None
                if resolution.role in {
                    CarrierRole.ISSUE_ACTIVE,
                    CarrierRole.ISSUE_FINALIZING,
                    CarrierRole.ISSUE_CANCEL,
                } and resolution.activation in {
                    CarrierActivation.ACTIVE,
                    CarrierActivation.RESERVED_INACTIVE,
                }:
                    try:
                        owner = derive_issue_owner_pr(
                            self.client, self.central_repository, head_sha, resolution,
                            self.app.slug, role_already_resolved=True,
                        )
                    except Exception as error:
                        decisions.append(Wave08Decision(
                            head_sha, ShaCarrierResolution(CarrierActivation.CONFLICTING, marker=resolution.marker),
                            numbers, None, Wave08DecisionKind.CONFLICTING_BLOCKED,
                            Wave08DecisionReason.FRESH_AUTHORITY_FAILED,
                        ))
                        blocked.append(f"{head_sha}:ISSUE_OWNER_AUTHORITY_FAILED:{_bounded_reason(error)}")
                        continue

                active_issue_finalizer = (
                    owner is not None
                    and resolution.activation is CarrierActivation.ACTIVE
                    and resolution.role in {
                        CarrierRole.ISSUE_ACTIVE,
                        CarrierRole.ISSUE_FINALIZING,
                    }
                )
                if active_issue_finalizer:
                    # Exact active role plus exact derived owner proves finalizer
                    # ownership independently of first-pass group membership.
                    finalizer_owned_issue_keys.add((central.node_id, owner.issue_number))

                    owner_number = owner.pull_request_number
                    if owner_number not in numbers:
                        if owner_number not in seen_pr_numbers:
                            blocked.append(
                                f"{head_sha}:ISSUE_OWNER_PR_NOT_IN_OPEN_PR_INVENTORY"
                            )
                        elif owner_number not in failed_fresh_pr_numbers:
                            blocked.append(
                                f"{head_sha}:ISSUE_OWNER_PR_NOT_IN_CURRENT_H_GROUP"
                            )
                        else:
                            try:
                                revalidated_owner_pr = self.client.get_pull_request_metadata(
                                    self.central_repository, owner_number,
                                )
                                if (
                                    type(revalidated_owner_pr) is not PullRequestMetadata
                                    or revalidated_owner_pr.number != owner_number
                                    or type(revalidated_owner_pr.head_oid) is not str
                                    or re.fullmatch(r"[0-9a-f]{40}", revalidated_owner_pr.head_oid) is None
                                ):
                                    raise R02Error("owner PR revalidation metadata is malformed")
                                if revalidated_owner_pr.head_oid != head_sha:
                                    blocked.append(
                                        f"{head_sha}:ISSUE_OWNER_PR_HEAD_CHANGED"
                                    )
                                else:
                                    # Re-admit only the explicit fresh current-H
                                    # read. The failed inventory row remains a hint.
                                    group = head_groups.get(head_sha)
                                    if group is None:
                                        raise R02Error("current H group disappeared before owner re-admission")
                                    if all(item.number != owner_number for item in group):
                                        group.append(revalidated_owner_pr)
                                        group.sort(key=lambda item: item.number)
                                    fresh_prs[owner_number] = revalidated_owner_pr
                                    prs = group
                                    numbers = tuple(item.number for item in group)
                            except Exception as error:
                                blocked.append(
                                    f"{head_sha}:ISSUE_OWNER_PR_REVALIDATION_UNAVAILABLE:{_bounded_reason(error)}"
                                )

                owner_number = owner.pull_request_number if owner is not None and owner.pull_request_number in numbers else None
                decision = wave08_decision_for_resolution(
                    head_sha, resolution, numbers, owner_pr_number=owner_number,
                )
                decisions.append(decision)
                if decision.kind is Wave08DecisionKind.EXTERNAL_STATUS:
                    try:
                        latest_central = self.client.get_repository_metadata(self.central_repository)
                        latest_app = resolve_app_identity(self.client, self.app.slug)
                        if (
                            type(latest_central) is not RepositoryMetadata
                            or latest_central.full_name != self.central_repository
                            or latest_central.default_branch != "main"
                            or latest_central.node_id != central.node_id
                            or latest_app != current_app
                        ):
                            raise StaleAuthorityError("external status central/App identity changed before write")
                        publish_unclaimed_external_success(
                            self.client, latest_central, head_sha, resolution, latest_app,
                        )
                        status_actions.append((head_sha, "EXTERNAL_SUCCESS"))
                    except Exception as error:
                        decisions[-1] = Wave08Decision(
                            head_sha, ShaCarrierResolution(CarrierActivation.CONFLICTING),
                            numbers, None, Wave08DecisionKind.CONFLICTING_BLOCKED,
                            Wave08DecisionReason.FRESH_AUTHORITY_FAILED,
                        )
                        blocked.append(f"{head_sha}:UNCLAIMED_EXTERNAL_STATUS_FAILED:{_bounded_reason(error)}")
                    continue
                if decision.kind is Wave08DecisionKind.LEGACY_QUARANTINE_DEFERRED:
                    deferred_count += 1
                    continue
                if decision.kind in {
                    Wave08DecisionKind.CONFLICTING_BLOCKED,
                    Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED,
                }:
                    if decision.kind is Wave08DecisionKind.MACHINE_RECOVERY_DEFERRED:
                        deferred_count += 1
                    else:
                        blocked.append(f"{head_sha}:CONFLICTING_SHA_ROLE")
                    continue
                if owner_number is None or owner is None:
                    continue
                if decision.kind is Wave08DecisionKind.ISSUE_OWNER_FINALIZER_RECOVERY:
                    finalizer_work.append((decision, owner))
                elif decision.kind is Wave08DecisionKind.ISSUE_OWNER_CANCELLATION_RECOVERY:
                    try:
                        cancellation = _fresh_issue_cancellation_authority(
                            self.client, self.central_repository, owner.issue_number,
                            current_app, allow_pr_stage_state=True,
                        )
                        current_ref = _read_issue_branch_ref(
                            self.client, self.central_repository,
                            cancellation.lease.lease.branch_ref.removeprefix("refs/heads/"),
                        )
                        fences, _ = self._read_issue_cancellation_fences(
                            cancellation, current_ref or ZERO_OID,
                        )
                        exact_fences = tuple(
                            item.fence for item in fences
                            if item.fence.cancellation_head_sha == head_sha
                            and _issue_cancellation_fence_marker(item.fence) == resolution.marker
                        )
                        if (
                            len(exact_fences) != 1
                            or cancellation.pull_request_number != owner.pull_request_number
                            or current_ref != head_sha
                            or cancellation.pr.head_oid != head_sha
                            or cancellation.raw_pr_state != "OPEN"
                            or cancellation.raw_pr_merged
                        ):
                            raise StaleAuthorityError("exact active cancellation owner/ref/PR/H changed")
                        self.publish_issue_cancel_failure(owner.issue_number, exact_fences[0])
                        status_actions.append((head_sha, "ISSUE_CANCEL_FAILURE"))
                        intent = Wave08IssueRecoveryIntent(
                            Wave08DispatchTarget.ISSUE_CANCELLATION_RECOVERY,
                            central.node_id, owner.issue_number, "ACTIVE_ISSUE_CANCEL_EXACT_HC",
                        )
                        issue_intents_by_key[(central.node_id, owner.issue_number)] = intent
                        issue_records_by_number[owner.issue_number] = Wave08IssueRecoveryRecord(
                            owner.issue_number, None, None, "DISPATCH_INTENT", "ACTIVE_ISSUE_CANCEL_EXACT_HC",
                        )
                    except Exception as error:
                        decisions[-1] = Wave08Decision(
                            head_sha, ShaCarrierResolution(CarrierActivation.CONFLICTING, marker=resolution.marker),
                            numbers, None, Wave08DecisionKind.CONFLICTING_BLOCKED,
                            Wave08DecisionReason.FRESH_AUTHORITY_FAILED,
                        )
                        blocked.append(f"{head_sha}:WG6_CANCEL_FAILURE_RECOVERY_FAILED:{_bounded_reason(error)}")
                elif decision.kind is Wave08DecisionKind.RESERVED_OWNER_RECOVERY:
                    intent = Wave08IssueRecoveryIntent(
                        Wave08DispatchTarget.ISSUE_INTAKE_TERMINAL_RECOVERY,
                        central.node_id, owner.issue_number, "RESERVED_ISSUE_OWNER_RECOVERY",
                    )
                    issue_intents_by_key[(central.node_id, owner.issue_number)] = intent

        # Exact active finalizer ownership supersedes only the provisional generic
        # all-Issue Wg1 intake intent for that same central repository and Issue.
        # Explicit cancellation and RESERVED owner-recovery intents remain intact.
        for key in sorted(finalizer_owned_issue_keys):
            intent = issue_intents_by_key.get(key)
            if (
                intent is None
                or intent.target is not Wave08DispatchTarget.ISSUE_INTAKE_TERMINAL_RECOVERY
                or intent.reason != "ALL_ISSUE_RECOVERY_INVENTORY"
            ):
                continue
            del issue_intents_by_key[key]
            issue = fresh_issues[key[1]][0]
            issue_records_by_number[key[1]] = Wave08IssueRecoveryRecord(
                key[1], issue.database_id, issue.node_id,
                "DEFERRED", "EXACT_ACTIVE_ISSUE_FINALIZER_OWNS_WG4_DISPATCH",
            )

        # Correction 01: active Issue role recovery dispatches only the closed
        # ISSUE_FINALIZER semantic to Wg4. Wg1 gets a separate intake/terminal intent.
        for decision, owner in finalizer_work:
            if decision.dispatch_target is not Wave08DispatchTarget.ISSUE_FINALIZER:
                blocked.append(f"{decision.head_sha}:ISSUE_FINALIZER_TARGET_DRIFT")
                continue
            if issue_finalizer_dispatcher is not None:
                try:
                    issue_finalizer_dispatcher(decision, owner)
                except Exception as error:
                    blocked.append(f"{decision.head_sha}:ISSUE_FINALIZER_DISPATCH_FAILED:{_bounded_reason(error)}")

        for intent in sorted(
            issue_intents_by_key.values(),
            key=lambda item: (item.central_repository_node_id, item.issue_number, item.target.value),
        ):
            if issue_intake_terminal_dispatcher is not None:
                try:
                    issue_intake_terminal_dispatcher(intent)
                except Exception as error:
                    blocked.append(f"ISSUE_{intent.issue_number}:WG1_DISPATCH_FAILED:{_bounded_reason(error)}")

        for decision, authority, target in machine_work:
            callback = (
                machine_finalizer_dispatcher
                if target is Wave08DispatchTarget.MACHINE_FINALIZER
                else machine_validation_dispatcher
            )
            if callback is not None:
                try:
                    callback(decision, authority)
                except Exception as error:
                    blocked.append(f"{decision.head_sha}:MACHINE_DISPATCH_FAILED:{_bounded_reason(error)}")

        machine_records: list[Wave08MachineRefRecord] = []
        accepted_source_ids = {source.source_id for source in (machine_sources or ())}
        for row in sorted(machine_rows, key=lambda item: (item["source_id"], item["ref"])):
            head = row["sha"]
            if row["source_id"] not in accepted_source_ids:
                outcome, reason = "DEFERRED_ORPHANED_SOURCE", "SOURCE_ID_NOT_CURRENTLY_ACCEPTED"
                deferred_count += 1
            elif not head_groups.get(head):
                outcome, reason = "DEFERRED_NO_OPEN_PR", "MACHINE_REF_IS_DISCOVERY_ONLY"
                deferred_count += 1
            elif any(
                decision.head_sha == head and decision.resolution.role is CarrierRole.MACHINE_PUBLICATION
                and decision.kind in {
                    Wave08DecisionKind.MACHINE_VALIDATION_DISPATCH,
                    Wave08DecisionKind.MACHINE_FINALIZER_DISPATCH,
                }
                for decision in decisions
            ):
                outcome, reason = "DISPATCHED", "EXACT_MACHINE_ROLE_AND_OWNER_PR_VALIDATED"
            elif any(decision.head_sha == head for decision in decisions):
                outcome, reason = "BLOCKED", "SHA_ROLE_DOES_NOT_AUTHORIZE_MACHINE_RECOVERY"
                blocked.append(f"{row['ref']}:SHA_ROLE_DOES_NOT_AUTHORIZE_MACHINE_RECOVERY")
            else:
                outcome, reason = "DEFERRED", "SHA_ROLE_NOT_RESOLVED"
                deferred_count += 1
            machine_records.append(Wave08MachineRefRecord(row["ref"], row["source_id"], head, outcome, reason))
        for row in raw_machine_refs:
            if type(row) is not dict or not all(type(row.get(key)) is str for key in ("ref", "source_id", "sha")):
                machine_records.append(Wave08MachineRefRecord(
                    "INVALID", "INVALID", "0" * 40, "BLOCKED", "MALFORMED_MACHINE_REF_INVENTORY_ROW",
                ))

        issue_records = tuple(
            issue_records_by_number[number]
            for number in sorted(issue_records_by_number)
        )
        decisions.sort(key=lambda item: item.head_sha)
        return Wave08UniversalRecoveryResult(
            True,
            len(raw_prs),
            len(fresh_prs),
            len(head_groups),
            len(raw_issues),
            len(relevant_issue_numbers),
            len(raw_machine_refs),
            tuple(decisions),
            issue_records,
            tuple(machine_records),
            tuple(sorted(
                issue_intents_by_key.values(),
                key=lambda item: (item.central_repository_node_id, item.issue_number, item.target.value),
            )),
            tuple(status_actions),
            tuple(blocked),
            deferred_count,
        )

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
        _raise_if_reserved_issue_pr(pr)
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
            pr, anchor, fold, _comments = self.anchor_and_reconstruct_existing(pr_number, request_class)
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
        return upsert_trusted_validation_check(self.client, self.central_repository, self.app, result, allow_create=True, allow_green=False)

    def publish_finalizer_result(self, result: TrustedValidationResult) -> CheckRun:
        if result.conclusion == "success" and result.snapshot is None:
            raise R02Error("finalizer success has no bound authority snapshot")
        assert_validation_snapshot_current(self.client, self.central_repository, self.app, result)
        return upsert_trusted_validation_check(self.client, self.central_repository, self.app, result, allow_create=True, allow_green=True)

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
        if checks:
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
            if checks:
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
        if checks:
            self.client.update_check_run(self.central_repository, checks[0].id, head_sha=candidate.commit_sha, conclusion="success", output=render_check_run_output(ready_result))
        else:
            try:
                created = upsert_trusted_validation_check(
                    self.client,
                    self.central_repository,
                    self.app,
                    ready_result,
                    allow_create=True,
                    allow_green=True,
                )
            except DuplicateCheckRunError:
                return "duplicate-check"
            except Exception:
                self.dispatch_trusted_validation_recovery(authority.number)
                return "check-recovery-dispatched"
            if created.name != TRUSTED_VALIDATION_NAME or created.head_sha != candidate.commit_sha or created.app_id != self.app.app_id:
                return "check-evidence-blocked"
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

    def main_advance(self) -> str | IssueManagedRouteResult:
        """Wake reconciliation/finalization from current main, never from event text."""
        repository, current_main = self.current_accepted_main()
        sources = self._accepted_sources(current_main)
        machine = self._machine_prs(current_main, repository, sources)
        wake_finalizer = False
        updated_manual = 0
        dispatched: set[str] = set()
        managed_issue_noop: IssueManagedRouteResult | None = None
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
                ):
                    continue
                if _is_reserved_issue_pr_head(pr.head_ref):
                    # Wave 04 advances only the exact bound Issue head. It never
                    # asks GitHub to merge main into this reserved branch.
                    try:
                        issue_number = reserved_issue_branch_number(pr.head_ref)
                    except RequestModelError:
                        continue
                    if issue_number is not None:
                        route_result = self.interactive_issue_managed_route(
                            issue_number, self.current_issue_source_authority,
                        )
                        if route_result.outcome == "NOOP":
                            managed_issue_noop = route_result
                    continue
                comments = self.client.list_issue_comments(self.central_repository, number)
                anchors = _anchor_candidates(comments)
                if pr.base_oid != current_main:
                    # Initial marker-only manual requests are safe to normalize
                    # automatically when main advances.  The trusted main-advance
                    # and interactive workflows share one repository-wide GitHub
                    # Actions concurrency group, so RequestAnchor creation cannot
                    # overlap this no-anchor classification/update authority
                    # window.  Validate the request head against the PR's own
                    # accepted historical base first, then let GitHub merge
                    # current main into the head with an expected-head CAS.  The
                    # resulting synchronize event wakes the ordinary
                    # interactive/trusted-validation cloud path.
                    if anchors:
                        continue
                    request_class = read_request_marker(self.client, self.central_repository, pr.head_oid)
                    if request_class not in MANUAL_CLASSES:
                        continue
                    validate_existing_request_head(self.client, self.central_repository, pr, request_class, pr.base_oid)
                    self.client.update_pull_request_branch(self.central_repository, number, expected_head_sha=pr.head_oid)
                    updated_manual += 1
                    continue
                if len(anchors) == 1 and anchors[0].anchor.request_class in MANUAL_CLASSES:
                    validate_unique_anchor(comments, pr, anchors[0].anchor.request_class, self.app)
                    wake_finalizer = True
            except (GitHubAPIError, R02Error, RequestModelError):
                continue
        if wake_finalizer:
            self.client.dispatch_workflow(self.central_repository, "federation-state-finalize.yml", "refs/heads/main", {})
        if not (dispatched or wake_finalizer or updated_manual) and managed_issue_noop is not None:
            return managed_issue_noop
        return f"MAIN_ADVANCE_DISPATCHED:{len(dispatched)}" if (dispatched or wake_finalizer or updated_manual) else "MAIN_ADVANCE_NOOP"

    def finalize_one_manual_pr(self, summary: Mapping[str, Any]) -> IssueManagedRouteResult | None:
        """Re-derive one current manual PR; never treats an enumeration hint as authority."""
        number = summary.get("number")
        if type(number) is not int or number <= 0:
            raise R02Error("finalizer PR summary has an invalid number")
        pr = self.client.get_pull_request_metadata(self.central_repository, number)
        if _is_reserved_issue_pr_head(pr.head_ref):
            try:
                issue_number = reserved_issue_branch_number(pr.head_ref)
                if issue_number is not None:
                    return self.interactive_issue_managed_route(
                        issue_number, self.current_issue_source_authority,
                    )
            except StaleTrustedCheckoutError:
                raise
            except (GitHubAPIError, R02Error, RequestModelError):
                # Reserved Issue PRs remain pre-green; failed recovery cannot
                # create validation evidence or enter legacy finalization.
                return
            return
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
                upsert_trusted_validation_check(self.client, self.central_repository, self.app, result, allow_create=True)
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


def _event_trigger(path: str | None) -> tuple[str | None, int | None, str | None]:
    """Return the event kind, immutable issue-comment ID, and comment author login if any."""
    if not path:
        return None, None, None
    try:
        value = c02.decode_json(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None, None, None
    if type(value) is not dict:
        return None, None, None
    event_name = value.get("action") if type(value.get("action")) is str else None
    comment_value = value.get("comment")
    if type(comment_value) is dict and type(comment_value.get("id")) is int and comment_value["id"] > 0:
        author_login = None
        user_value = comment_value.get("user")
        if type(user_value) is dict and type(user_value.get("login")) is str:
            author_login = user_value["login"]
        return "issue_comment", comment_value["id"], author_login
    return event_name, None, None


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


PRIVILEGED_PATH_PREFIXES = ("automation/", ".github/", "skills/", "scripts/")
PRIVILEGED_PATHS = frozenset({
    "federation.json",
    "federation.lock.json",
    "docs/MECHANICS.md",
})


def markerless_maintenance_scope(paths) -> str:
    normalized = tuple(sorted(set(paths)))
    if not normalized:
        return "OUT_OF_FEDERATION_SCOPE"
    for path in normalized:
        if path in PRIVILEGED_PATHS or path.startswith(PRIVILEGED_PATH_PREFIXES):
            return "OUT_OF_FEDERATION_SCOPE"
    return "MAINTENANCE_SCOPE_OK"


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
    reserved_issue_pr = False
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
        event_kind, triggering_comment_id, triggering_comment_author = _event_trigger(env.get("FEDERATION_EVENT_PATH"))
        if event_kind == "issue_comment" and triggering_comment_author == app.bot_login:
            # App-authored result/anchor comments must never re-enter as PATCH triggers.
            return 0
        if args.command == "reconcile":
            hint = env.get("FEDERATION_RECONCILE_REPOSITORY_ID")
            controller.reconcile_all() if hint is None or hint == "" else controller.reconcile(hint)
        elif args.command == "main-advance":
            controller.main_advance()
        elif args.command in {"interactive", "trusted-validation"}:
            if number is None:
                raise R02Error("authoritative PR number is unavailable")
            if args.command == "interactive":
                initial_pr = client.get_pull_request_metadata(repository, number)
                if _is_reserved_issue_pr_head(initial_pr.head_ref):
                    reserved_issue_pr = True
                    issue_number = reserved_issue_branch_number(initial_pr.head_ref)
                    if issue_number is None:
                        raise ReservedIssuePRPendingManagedAuthority("reserved Issue PR has no exact Issue number")
                    controller.interactive_issue_managed_route(
                        issue_number, controller.current_issue_source_authority,
                    )
                    return 0
                comments = client.list_issue_comments(repository, number)
                anchors = _anchor_candidates(comments)
                if anchors:
                    request_class = anchors[0].anchor.request_class
                else:
                    pr = client.get_pull_request_metadata(repository, number)
                    request_class = read_optional_request_marker(client, repository, pr.head_oid)
                    if request_class is None:
                        return 0
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
                    _pr, trigger_anchor, trigger_fold, _fold_comments = controller.interactive_anchor_and_reconstruct(number, request_class)
                    trigger_result, should_apply = _trigger_result(trigger_fold.evidence, triggering_comment_id)
                    if has_result_for_comment(comments, result_kind, result_identity):
                        return 0
                    if not should_apply:
                        _post_bounded_result(client, repository, number, comments, kind=result_kind, identity=result_identity, result=trigger_result, reason="trigger-comment-not-applied")
                        return 0
                if event_kind != "issue_comment":
                    controller.interactive_anchor_and_reconstruct(number, request_class)
                candidate = controller.interactive_proposal(number, request_class, accepted_main, f"refs/heads/{pr.head_ref}")
                updated_comments = client.list_issue_comments(repository, number)
                anchor = validate_unique_anchor(updated_comments, pr, request_class, app)
                if result_identity is None:
                    result_identity = anchor.comment.database_id
                _post_bounded_result(client, repository, number, updated_comments, kind=result_kind, identity=result_identity, result="PROPOSAL_UPDATED", reason=f"{request_class.value}:{len(candidate.changed_paths)}")
                client.dispatch_workflow(repository, "federation-state-finalize.yml", "refs/heads/main", {"pull_number": str(number)})
            else:
                initial_pr = client.get_pull_request_metadata(repository, number)
                if _is_reserved_issue_pr_head(initial_pr.head_ref):
                    reserved_issue_pr = True
                    try:
                        issue_number = reserved_issue_branch_number(initial_pr.head_ref)
                        if issue_number is not None:
                            controller.validate_issue_managed_head_history(issue_number)
                    except (GitHubAPIError, R02Error, RequestModelError):
                        pass
                    return 0
                _repo, accepted_main = controller.current_accepted_main()
                comments = client.list_issue_comments(repository, number)
                if not _anchor_candidates(comments) and _MACHINE_BRANCH_RE.fullmatch(initial_pr.head_ref):
                    result = controller.trusted_machine_validation(number, accepted_main, expected_head_sha=initial_pr.head_oid)
                    controller.publish_validation_result(result)
                    client.dispatch_workflow(repository, "federation-state-finalize.yml", "refs/heads/main", {"pull_number": str(number)})
                else:
                    if not _anchor_candidates(comments) and read_optional_request_marker(client, repository, initial_pr.head_oid) is None:
                        try:
                            require_same_repository_head(initial_pr, repository)
                        except ForkHeadError:
                            result = TrustedValidationResult(
                                "failure",
                                bounded_check_output(RequestClass.UNRELATED, initial_pr.head_oid, accepted_main, reason="OUT_OF_FEDERATION_SCOPE"),
                            )
                            controller.publish_validation_result(result)
                            return 0
                        files = client.list_pull_request_files(repository, number)
                        paths = tuple(item.get("filename") for item in files if type(item) is dict and type(item.get("filename")) is str)
                        scope = markerless_maintenance_scope(paths)
                        if scope == "MAINTENANCE_SCOPE_OK":
                            result = TrustedValidationResult(
                                "skipped",
                                bounded_check_output(RequestClass.UNRELATED, initial_pr.head_oid, accepted_main, reason="MAINTENANCE_SCOPE_OK"),
                            )
                        else:
                            result = TrustedValidationResult(
                                "failure",
                                bounded_check_output(RequestClass.UNRELATED, initial_pr.head_oid, accepted_main, reason="OUT_OF_FEDERATION_SCOPE"),
                            )
                        controller.publish_validation_result(result)
                        return 0
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
        if args.command == "interactive" and client is not None and number is not None and not reserved_issue_pr:
            try:
                comments = client.list_issue_comments(repository, number)
                identity = result_identity
                if identity is None:
                    anchor = next(iter(_anchor_candidates(comments)), None)
                    identity = anchor.comment.database_id if anchor is not None else None
                if identity is not None:
                    _post_bounded_result(client, repository, number, comments, kind=result_kind, identity=identity, result="PROPOSAL_BLOCKED", reason=_bounded_error_reason(error))
            except Exception:
                pass
        if isinstance(error, GraphQLError):
            print(f"C03-R02 controller blocked: GraphQLError:{_safe_graphql_diagnostic(error)}", file=sys.stderr)
        else:
            print(f"C03-R02 controller blocked: {type(error).__name__}", file=sys.stderr)
        return 1


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


if __name__ == "__main__":
    raise SystemExit(main())
