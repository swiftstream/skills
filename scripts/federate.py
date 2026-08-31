#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "federation.json"
LOCK_PATH = ROOT / "federation.lock.json"
README_PATH = ROOT / "README.md"
SKILLS_ROOT = ROOT / "skills"
DIGEST_ALGORITHM = "sha256-file-manifest-v1"
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
MAX_REPOSITORY_ID = 9223372036854775807
GITHUB_API_BASE = "https://api.github.com"
GITHUB_ACCEPT = "application/vnd.github+json"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
HTTP_TIMEOUT_SECONDS = 15.0
HTTP_MAX_RESPONSE_BYTES = 1024 * 1024
NETWORK_GIT_TIMEOUT_SECONDS = 15.0
MAX_NETWORK_ATTEMPTS = 3
README_BEGIN_MARKER = b"<!-- BEGIN FEDERATED SKILLS CATALOG -->"
README_END_MARKER = b"<!-- END FEDERATED SKILLS CATALOG -->"
EMPTY_CATALOG_PLACEHOLDER = "_No repositories have published skills through the federation yet._"
EMPTY_SOURCE_SKILLS = "_No published skills._"


class FederationError(Exception):
    pass


class HttpTransportError(FederationError):
    pass


class HistoricalAttemptAmbiguous(Exception):
    pass


@dataclass(frozen=True)
class SourceDeclaration:
    source_id: str
    repository: str
    repository_id: int
    ref: str
    skills_root: str
    skill_prefixes: tuple[str, ...]
    description: str


@dataclass(frozen=True)
class Manifest:
    sources: tuple[SourceDeclaration, ...]

    @property
    def by_source_id(self) -> dict[str, SourceDeclaration]:
        return {source.source_id: source for source in self.sources}

    @property
    def by_repository_id(self) -> dict[int, SourceDeclaration]:
        return {source.repository_id: source for source in self.sources}


@dataclass(frozen=True)
class LockEntry:
    source_id: str
    resolved_commit: str
    content_sha256: str


@dataclass(frozen=True)
class LockState:
    published_source_ids: tuple[str, ...]
    skills: dict[str, LockEntry]


@dataclass(frozen=True)
class HttpResponse:
    status: int
    final_url: str
    body: bytes


@dataclass(frozen=True)
class BoundSource:
    source: SourceDeclaration
    path: Path
    commit: str


class HistoricalCommitResult(Enum):
    RETRIEVED = "RETRIEVED"
    DEFINITIVELY_MISSING = "DEFINITIVELY_MISSING"
    AMBIGUOUS_FAIL = "AMBIGUOUS_FAIL"


@dataclass(frozen=True)
class HistoricalCommitAccess:
    result: HistoricalCommitResult
    path: Path | None


@dataclass(frozen=True)
class DiscoveredSkill:
    source_id: str
    repository_id: int
    repository: str
    ref: str
    skills_root: str
    skill_name: str
    resolved_commit: str
    package: Package


@dataclass(frozen=True)
class FileRecord:
    path: str
    executable: bool
    data: bytes


@dataclass(frozen=True)
class Package:
    name: str
    files: tuple[FileRecord, ...]
    digest: str


@dataclass(frozen=True)
class PackageDeclarationIdentity:
    source_id: str
    repository_id: int
    repository: str
    ref: str
    skills_root: str
    skill_name: str


@dataclass(frozen=True)
class PreviousPublication:
    declaration: PackageDeclarationIdentity
    lock_entry: LockEntry
    package: Package


@dataclass(frozen=True)
class DesiredPublicationState:
    lock: LockState
    packages: dict[str, Package]


@dataclass(frozen=True)
class ReadmeLayout:
    prefix_through_begin: bytes
    managed: bytes
    suffix_from_end: bytes


@dataclass(frozen=True)
class CommittedLocalProof:
    head_commit: str
    manifest: Manifest
    lock: LockState
    committed_packages: dict[str, Package]
    readme_layout: ReadmeLayout
    readme_bytes: bytes


def fail(message: str) -> None:
    raise FederationError(message)


def is_exact_int(value: Any, expected: int) -> bool:
    return type(value) is int and value == expected


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value.keys())
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        details: list[str] = []
        if missing:
            details.append(f"missing keys: {', '.join(missing)}")
        if extra:
            details.append(f"unknown keys: {', '.join(extra)}")
        fail(f"{context} has invalid shape ({'; '.join(details)})")


def strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON object key: {key!r}")
        value[key] = item
    return value


def reject_json_constant(value: str) -> None:
    fail(f"non-standard JSON numeric constant is forbidden: {value}")


def decode_json(text: str) -> Any:
    return json.loads(
        text,
        object_pairs_hook=strict_json_object,
        parse_constant=reject_json_constant,
    )


def load_json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        fail(f"missing {context}: {path.relative_to(ROOT)}")
    try:
        value = decode_json(raw.decode("utf-8"))
    except UnicodeDecodeError:
        fail(f"{context} is not UTF-8: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as error:
        fail(f"invalid JSON in {path.relative_to(ROOT)}: {error.msg}")
    if type(value) is not dict:
        fail(f"{context} must be a JSON object")
    return value


def contains_control(value: str) -> bool:
    return bool(CONTROL_RE.search(value))


def validate_repository(value: Any) -> str:
    if type(value) is not str or not value:
        fail("repository must be a nonempty string")
    if contains_control(value):
        fail(f"repository contains a control character: {value!r}")
    if not REPOSITORY_RE.fullmatch(value):
        fail(f"repository must be exact OWNER/REPO syntax: {value!r}")
    return value


def run_process(
    argv: list[str],
    *,
    cwd: Path | None = None,
    text: bool = True,
    check: bool = True,
    network: bool = False,
    source_workspace: bool = False,
) -> subprocess.CompletedProcess[Any]:
    env = os.environ.copy()
    if network or source_workspace:
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
    if source_workspace:
        for key in (
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_DIR",
            "GIT_COMMON_DIR",
            "GIT_WORK_TREE",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS",
        ):
            env.pop(key, None)
        for key in list(env):
            if key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
                env.pop(key, None)
    try:
        result = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if network else subprocess.PIPE,
            stderr=subprocess.DEVNULL if network else subprocess.PIPE,
            text=text,
            shell=False,
            check=False,
            timeout=NETWORK_GIT_TIMEOUT_SECONDS if network else None,
        )
    except subprocess.TimeoutExpired as error:
        if network:
            fail("network Git command timed out")
        raise error
    if check and result.returncode != 0:
        if result.stderr:
            stderr = result.stderr if text else result.stderr.decode("utf-8", errors="replace")
            stderr = stderr.strip()
        else:
            stderr = ""
        detail = f": {stderr}" if stderr else ""
        fail(f"command failed ({' '.join(argv[:3])}){detail}")
    return result


def run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    text: bool = True,
    check: bool = True,
    network: bool = False,
    source_workspace: bool = False,
) -> subprocess.CompletedProcess[Any]:
    return run_process(
        ["git", "-c", f"core.hooksPath={os.devnull}", "-c", "init.templateDir=", *args],
        cwd=cwd,
        text=text,
        check=check,
        network=network,
        source_workspace=source_workspace,
    )


def validate_ref(value: Any) -> str:
    if type(value) is not str or not value:
        fail("ref must be a nonempty string")
    if contains_control(value):
        fail(f"ref contains a control character: {value!r}")
    if not value.startswith("refs/heads/") or value == "refs/heads/":
        fail(f"ref must be a full branch ref under refs/heads/**: {value!r}")
    result = run_git(["check-ref-format", value], check=False)
    if result.returncode != 0:
        fail(f"Git rejects configured ref spelling: {value!r}")
    return value


def validate_lower_hyphen_identifier(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        fail(f"{context} must be a nonempty string")
    if contains_control(value):
        fail(f"{context} contains a control character: {value!r}")
    if len(value) > 64 or not NAME_RE.fullmatch(value):
        fail(f"invalid {context}: {value!r}")
    return value


def validate_name(value: Any) -> str:
    return validate_lower_hyphen_identifier(value, "Agent Skill name")


def validate_source_id(value: Any) -> str:
    return validate_lower_hyphen_identifier(value, "sourceId")


def validate_repository_id(value: Any) -> int:
    if type(value) is not int or not (1 <= value <= MAX_REPOSITORY_ID):
        fail(f"repositoryId must be an integer in 1...{MAX_REPOSITORY_ID}")
    return value


def validate_description(value: Any) -> str:
    if type(value) is not str or not value:
        fail("description must be a nonempty string")
    if len(value) > 500:
        fail("description must contain at most 500 Unicode code points")
    if contains_control(value):
        fail("description contains a C0/DEL control character")
    if value != value.strip():
        fail("description must not contain leading/trailing Unicode whitespace")
    return value


def validate_posix_relative_path(value: Any, context: str) -> str:
    if type(value) is not str or not value:
        fail(f"{context} must be a nonempty string")
    if contains_control(value):
        fail(f"{context} contains a control character: {value!r}")
    if "\\" in value:
        fail(f"{context} must use POSIX separators only: {value!r}")
    if value.startswith("/"):
        fail(f"{context} must be repository-relative: {value!r}")
    path = PurePosixPath(value)
    if str(path) != value:
        fail(f"{context} is not in canonical POSIX spelling: {value!r}")
    if value == "." or not path.parts:
        fail(f"{context} cannot be '.': {value!r}")
    if any(part in {"", ".", ".."} for part in path.parts):
        fail(f"{context} contains an invalid path component: {value!r}")
    return value


HttpRequester = Callable[[str, dict[str, str], float, int], HttpResponse]


def github_headers() -> dict[str, str]:
    headers = {
        "Accept": GITHUB_ACCEPT,
        "User-Agent": "swiftstream-skills-federator",
    }
    token = os.environ.get(GITHUB_TOKEN_ENV)
    if token:
        if "\r" in token or "\n" in token:
            fail(f"{GITHUB_TOKEN_ENV} contains forbidden header control characters")
        headers["Authorization"] = f"Bearer {token}"
    return headers


def read_bounded_http_body(stream: Any, max_bytes: int) -> bytes:
    body = stream.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise HttpTransportError("GitHub response exceeds configured size bound")
    return body


def stdlib_http_get(
    url: str,
    headers: dict[str, str],
    timeout: float,
    max_bytes: int,
) -> HttpResponse:
    request = urllib_request.Request(url, headers=headers, method="GET")
    try:
        with urllib_request.urlopen(request, timeout=timeout) as response:
            final_url = response.geturl()
            if final_url != url:
                raise HttpTransportError("unexpected GitHub HTTP redirect")
            return HttpResponse(
                status=int(response.status),
                final_url=final_url,
                body=read_bounded_http_body(response, max_bytes),
            )
    except urllib_error.HTTPError as error:
        final_url = error.geturl()
        if final_url != url:
            raise HttpTransportError("unexpected GitHub HTTP redirect") from error
        return HttpResponse(
            status=int(error.code),
            final_url=final_url,
            body=read_bounded_http_body(error, max_bytes),
        )
    except (urllib_error.URLError, TimeoutError, OSError) as error:
        raise HttpTransportError("GitHub HTTP transport failure") from error


def decode_http_json_object(response: HttpResponse, context: str) -> dict[str, Any]:
    try:
        text = response.body.decode("utf-8")
    except UnicodeDecodeError:
        fail(f"{context} response is not UTF-8")
    try:
        value = decode_json(text)
    except json.JSONDecodeError as error:
        fail(f"{context} response is invalid JSON: {error.msg}")
    if type(value) is not dict:
        fail(f"{context} response must be a JSON object")
    return value


def github_repository_api_url(repository: str) -> str:
    repository = validate_repository(repository)
    owner, name = repository.split("/", 1)
    return (
        f"{GITHUB_API_BASE}/repos/"
        f"{urllib_parse.quote(owner, safe='')}/{urllib_parse.quote(name, safe='')}"
    )


def github_ref_api_url(source: SourceDeclaration) -> str:
    ref_suffix = source.ref.removeprefix("refs/")
    return f"{github_repository_api_url(source.repository)}/git/ref/{urllib_parse.quote(ref_suffix, safe='/')}"


def github_commit_api_url(source: SourceDeclaration, commit: str) -> str:
    if not HEX40_RE.fullmatch(commit):
        fail(f"historical commit must be lowercase 40-hex: {commit!r}")
    return f"{github_repository_api_url(source.repository)}/git/commits/{commit}"


def github_get(
    url: str,
    *,
    headers: dict[str, str],
    http_get: HttpRequester,
) -> HttpResponse:
    response = http_get(url, headers, HTTP_TIMEOUT_SECONDS, HTTP_MAX_RESPONSE_BYTES)
    if type(response.status) is not int or not (100 <= response.status <= 599):
        raise HttpTransportError("GitHub HTTP seam returned invalid status")
    if response.final_url != url:
        raise HttpTransportError("unexpected GitHub HTTP redirect")
    if type(response.body) is not bytes or len(response.body) > HTTP_MAX_RESPONSE_BYTES:
        raise HttpTransportError("GitHub HTTP seam violated response body bound")
    return response


def read_repository_identity(
    source: SourceDeclaration,
    *,
    headers: dict[str, str],
    http_get: HttpRequester,
) -> None:
    response = github_get(
        github_repository_api_url(source.repository),
        headers=headers,
        http_get=http_get,
    )
    if response.status != 200:
        fail(f"GitHub repository metadata returned HTTP {response.status}")
    value = decode_http_json_object(response, "GitHub repository metadata")
    repository_id = value.get("id")
    full_name = value.get("full_name")
    if type(repository_id) is not int or repository_id != source.repository_id:
        fail("GitHub repository id does not match accepted repositoryId")
    if type(full_name) is not str or full_name != source.repository:
        fail("GitHub repository full_name does not match accepted repository locator")


def read_exact_ref_commit(
    source: SourceDeclaration,
    *,
    headers: dict[str, str],
    http_get: HttpRequester,
) -> str:
    response = github_get(github_ref_api_url(source), headers=headers, http_get=http_get)
    if response.status != 200:
        fail(f"GitHub exact configured ref returned HTTP {response.status}")
    value = decode_http_json_object(response, "GitHub exact configured ref")
    if value.get("ref") != source.ref:
        fail("GitHub exact ref response does not match configured ref")
    object_value = value.get("object")
    if type(object_value) is not dict:
        fail("GitHub exact ref response object must be a JSON object")
    if object_value.get("type") != "commit":
        fail("GitHub exact configured ref must resolve to a commit object")
    commit = object_value.get("sha")
    if type(commit) is not str or not HEX40_RE.fullmatch(commit):
        fail("GitHub exact configured ref commit must be lowercase 40-hex")
    return commit


def load_manifest_from_value(value: dict[str, Any], context: str) -> Manifest:
    require_exact_keys(value, {"schemaVersion", "sources"}, context)
    if not is_exact_int(value["schemaVersion"], 2):
        fail(f"{context}.schemaVersion must be integer 2")
    sources_value = value["sources"]
    if type(sources_value) is not list:
        fail(f"{context}.sources must be an array")

    sources: list[SourceDeclaration] = []
    source_ids: set[str] = set()
    repository_ids: set[int] = set()
    root_namespaces: set[str] = set()

    for source_index, source_value in enumerate(sources_value):
        source_context = f"{context}.sources[{source_index}]"
        if type(source_value) is not dict:
            fail(f"{source_context} must be an object")
        require_exact_keys(
            source_value,
            {"sourceId", "repository", "repositoryId", "ref", "skillsRoot", "skillPrefixes", "description"},
            source_context,
        )
        source_id = validate_source_id(source_value["sourceId"])
        repository = validate_repository(source_value["repository"])
        repository_id = validate_repository_id(source_value["repositoryId"])
        ref = validate_ref(source_value["ref"])
        skills_root = validate_posix_relative_path(source_value["skillsRoot"], f"{source_context}.skillsRoot")
        prefixes_value = source_value["skillPrefixes"]
        if type(prefixes_value) is not list or not prefixes_value:
            fail(f"{source_context}.skillPrefixes must be a nonempty array")
        prefixes = tuple(
            validate_lower_hyphen_identifier(prefix, f"{source_context}.skillPrefixes[{index}]")
            for index, prefix in enumerate(prefixes_value)
        )
        if list(prefixes) != sorted(prefixes):
            fail(f"{source_context}.skillPrefixes must already be lexically sorted")
        if len(set(prefixes)) != len(prefixes):
            fail(f"{source_context}.skillPrefixes contains duplicates")
        for prefix in prefixes:
            root_namespace = prefix.split("-", 1)[0]
            if root_namespace in root_namespaces:
                fail(f"duplicate global root namespace: {root_namespace}")
            root_namespaces.add(root_namespace)
        description = validate_description(source_value["description"])
        if source_id in source_ids:
            fail(f"duplicate sourceId: {source_id}")
        if repository_id in repository_ids:
            fail(f"duplicate repositoryId: {repository_id}")
        source_ids.add(source_id)
        repository_ids.add(repository_id)
        sources.append(
            SourceDeclaration(
                source_id=source_id,
                repository=repository,
                repository_id=repository_id,
                ref=ref,
                skills_root=skills_root,
                skill_prefixes=prefixes,
                description=description,
            )
        )

    source_order = [source.source_id for source in sources]
    if source_order != sorted(source_order):
        fail(f"{context}.sources must already be lexically sorted by sourceId")
    return Manifest(sources=tuple(sources))


def load_manifest(path: Path = MANIFEST_PATH) -> Manifest:
    return load_manifest_from_value(load_json_object(path, "federation manifest"), "federation.json")


def load_lock_from_value(value: dict[str, Any], manifest: Manifest, context: str) -> LockState:
    require_exact_keys(value, {"schemaVersion", "contentDigestAlgorithm", "publishedSourceIds", "skills"}, context)
    if not is_exact_int(value["schemaVersion"], 2):
        fail(f"{context}.schemaVersion must be integer 2")
    if type(value["contentDigestAlgorithm"]) is not str or value["contentDigestAlgorithm"] != DIGEST_ALGORITHM:
        fail(f"{context}.contentDigestAlgorithm must be {DIGEST_ALGORITHM!r}")
    published_value = value["publishedSourceIds"]
    if type(published_value) is not list:
        fail(f"{context}.publishedSourceIds must be an array")
    published_source_ids = tuple(validate_source_id(item) for item in published_value)
    if list(published_source_ids) != sorted(published_source_ids):
        fail(f"{context}.publishedSourceIds must already be lexically sorted")
    if len(set(published_source_ids)) != len(published_source_ids):
        fail(f"{context}.publishedSourceIds contains duplicates")
    manifest_source_ids = set(manifest.by_source_id)
    for source_id in published_source_ids:
        if source_id not in manifest_source_ids:
            fail(f"{context}.publishedSourceIds contains unknown sourceId: {source_id}")

    skills_value = value["skills"]
    if type(skills_value) is not dict:
        fail(f"{context}.skills must be an object")
    entries: dict[str, LockEntry] = {}
    for name_value, entry_value in skills_value.items():
        name = validate_name(name_value)
        if type(entry_value) is not dict:
            fail(f"lock entry for {name} must be an object")
        require_exact_keys(entry_value, {"sourceId", "resolvedCommit", "contentSha256"}, f"lock entry {name}")
        source_id = validate_source_id(entry_value["sourceId"])
        if source_id not in manifest_source_ids:
            fail(f"lock entry {name}.sourceId is not present in manifest: {source_id}")
        if source_id not in published_source_ids:
            fail(f"lock entry {name}.sourceId is not present in publishedSourceIds: {source_id}")
        resolved_commit = entry_value["resolvedCommit"]
        content_sha = entry_value["contentSha256"]
        if type(resolved_commit) is not str or not HEX40_RE.fullmatch(resolved_commit):
            fail(f"lock entry {name}.resolvedCommit must be lowercase 40-hex")
        if type(content_sha) is not str or not HEX64_RE.fullmatch(content_sha):
            fail(f"lock entry {name}.contentSha256 must be lowercase 64-hex")
        entries[name] = LockEntry(source_id=source_id, resolved_commit=resolved_commit, content_sha256=content_sha)
    return LockState(published_source_ids=published_source_ids, skills=entries)


def load_lock(manifest: Manifest, path: Path = LOCK_PATH) -> LockState:
    return load_lock_from_value(load_json_object(path, "federation lock"), manifest, "federation.lock.json")


def render_lock(lock: LockState) -> bytes:
    skills: dict[str, Any] = {}
    for name in sorted(lock.skills):
        entry = lock.skills[name]
        skills[name] = {
            "sourceId": entry.source_id,
            "resolvedCommit": entry.resolved_commit,
            "contentSha256": entry.content_sha256,
        }
    value = {
        "schemaVersion": 2,
        "contentDigestAlgorithm": DIGEST_ALGORITHM,
        "publishedSourceIds": sorted(lock.published_source_ids),
        "skills": skills,
    }
    return (json.dumps(value, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def repository_git_url(repository: str) -> str:
    return f"https://github.com/{validate_repository(repository)}.git"


def assert_source_workspace_isolated(repo_path: Path) -> None:
    for alternate_name in ("alternates", "http-alternates"):
        alternate = repo_path / "objects" / "info" / alternate_name
        if alternate.exists() or alternate.is_symlink():
            fail(f"source Git workspace must not use objects/info/{alternate_name}")


def initialize_source_repository(repo_path: Path, source: SourceDeclaration) -> None:
    if repo_path.exists() or repo_path.is_symlink():
        fail("source Git workspace path must not already exist")
    repo_path.parent.mkdir(parents=True, exist_ok=True)
    run_git(["init", "--bare", str(repo_path)], source_workspace=True)
    run_git(
        ["-C", str(repo_path), "remote", "add", "origin", repository_git_url(source.repository)],
        source_workspace=True,
    )
    assert_source_workspace_isolated(repo_path)


def git_commit_exists(repo_path: Path, commit: str) -> bool:
    if not HEX40_RE.fullmatch(commit):
        fail(f"commit must be lowercase 40-hex: {commit!r}")
    assert_source_workspace_isolated(repo_path)
    result = run_git(
        ["-C", str(repo_path), "cat-file", "-e", f"{commit}^{{commit}}"],
        check=False,
        source_workspace=True,
    )
    return result.returncode == 0


def git_fetch_configured_branch(repo_path: Path, source: SourceDeclaration) -> str:
    assert_source_workspace_isolated(repo_path)
    result = run_git(
        ["-C", str(repo_path), "fetch", "--no-tags", "--force", "origin", source.ref],
        check=False,
        network=True,
        source_workspace=True,
    )
    if result.returncode != 0:
        fail("configured source branch Git fetch failed")
    commit = run_git(
        ["-C", str(repo_path), "rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        source_workspace=True,
    ).stdout.strip()
    if not HEX40_RE.fullmatch(commit):
        fail("configured source branch Git fetch did not resolve lowercase 40-hex commit")
    return commit


def git_fetch_exact_commit(repo_path: Path, source: SourceDeclaration, commit: str) -> None:
    if not HEX40_RE.fullmatch(commit):
        fail(f"historical commit must be lowercase 40-hex: {commit!r}")
    assert_source_workspace_isolated(repo_path)
    result = run_git(
        ["-C", str(repo_path), "fetch", "--no-tags", "--force", "origin", commit],
        check=False,
        network=True,
        source_workspace=True,
    )
    if result.returncode != 0:
        fail("exact historical commit Git materialization failed")
    if not git_commit_exists(repo_path, commit):
        fail("exact historical commit fetch completed without materializing a commit object")


BranchFetcher = Callable[[Path, SourceDeclaration], str]
ExactCommitFetcher = Callable[[Path, SourceDeclaration, str], None]


def bind_source_snapshot(
    temp_root: Path,
    source: SourceDeclaration,
    *,
    http_get: HttpRequester = stdlib_http_get,
    branch_fetcher: BranchFetcher = git_fetch_configured_branch,
) -> BoundSource:
    headers = github_headers()
    binding_root = Path(tempfile.mkdtemp(prefix=f"source-{source.source_id}-binding-", dir=temp_root))
    last_error = "repository identity/ref/fetch binding did not converge"
    for attempt in range(1, MAX_NETWORK_ATTEMPTS + 1):
        repo_path = binding_root / f"attempt-{attempt}.git"
        try:
            read_repository_identity(source, headers=headers, http_get=http_get)
            api_commit_before = read_exact_ref_commit(source, headers=headers, http_get=http_get)
            initialize_source_repository(repo_path, source)
            git_fetched_commit = branch_fetcher(repo_path, source)
            if not HEX40_RE.fullmatch(git_fetched_commit) or not git_commit_exists(repo_path, git_fetched_commit):
                fail("configured source branch fetch did not materialize the reported commit")
            read_repository_identity(source, headers=headers, http_get=http_get)
            api_commit_after = read_exact_ref_commit(source, headers=headers, http_get=http_get)
            if api_commit_before != api_commit_after:
                fail("configured source ref moved during identity-bound fetch")
            if git_fetched_commit != api_commit_after:
                fail("Git-fetched source commit does not match post-fetch GitHub exact ref")
            assert_source_workspace_isolated(repo_path)
            return BoundSource(source=source, path=repo_path, commit=git_fetched_commit)
        except FederationError as error:
            last_error = str(error)
            if repo_path.exists():
                shutil.rmtree(repo_path)
    fail(
        f"unable to establish identity-bound source snapshot after {MAX_NETWORK_ATTEMPTS} attempts: "
        f"{last_error}"
    )


def retrieve_historical_commit(
    temp_root: Path,
    bound_source: BoundSource,
    requested_commit: str,
    *,
    http_get: HttpRequester = stdlib_http_get,
    exact_commit_fetcher: ExactCommitFetcher = git_fetch_exact_commit,
) -> HistoricalCommitAccess:
    if not HEX40_RE.fullmatch(requested_commit):
        fail(f"historical commit must be lowercase 40-hex: {requested_commit!r}")
    if git_commit_exists(bound_source.path, requested_commit):
        return HistoricalCommitAccess(HistoricalCommitResult.RETRIEVED, bound_source.path)

    source = bound_source.source
    headers = github_headers()
    classifier_root = Path(
        tempfile.mkdtemp(
            prefix=f"source-{source.source_id}-historical-{requested_commit}-",
            dir=temp_root,
        )
    )
    for attempt in range(1, MAX_NETWORK_ATTEMPTS + 1):
        attempt_path = classifier_root / f"attempt-{attempt}.git"
        try:
            read_repository_identity(source, headers=headers, http_get=http_get)
            witness_ref_before = read_exact_ref_commit(source, headers=headers, http_get=http_get)
            response = github_get(
                github_commit_api_url(source, requested_commit),
                headers=headers,
                http_get=http_get,
            )

            if response.status == 200:
                value = decode_http_json_object(response, "GitHub historical commit object")
                sha = value.get("sha")
                if type(sha) is not str or sha != requested_commit or not HEX40_RE.fullmatch(sha):
                    raise HistoricalAttemptAmbiguous()
                initialize_source_repository(attempt_path, source)
                exact_commit_fetcher(attempt_path, source, requested_commit)
                if not git_commit_exists(attempt_path, requested_commit):
                    raise HistoricalAttemptAmbiguous()
            elif response.status == 404:
                pass
            else:
                raise HistoricalAttemptAmbiguous()

            read_repository_identity(source, headers=headers, http_get=http_get)
            witness_ref_after = read_exact_ref_commit(source, headers=headers, http_get=http_get)
            if witness_ref_before != witness_ref_after:
                raise HistoricalAttemptAmbiguous()

            if response.status == 404:
                if attempt_path.exists():
                    shutil.rmtree(attempt_path)
                return HistoricalCommitAccess(HistoricalCommitResult.DEFINITIVELY_MISSING, None)

            assert_source_workspace_isolated(attempt_path)
            return HistoricalCommitAccess(HistoricalCommitResult.RETRIEVED, attempt_path)
        except (FederationError, HistoricalAttemptAmbiguous, OSError):
            if attempt_path.exists():
                shutil.rmtree(attempt_path)
            continue

    return HistoricalCommitAccess(HistoricalCommitResult.AMBIGUOUS_FAIL, None)


def parse_ls_tree_records(raw: bytes, root: str) -> tuple[list[tuple[str, str, str, str]], bool]:
    root_seen_as_tree = False
    prefix = root + "/"
    records: list[tuple[str, str, str, str]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        try:
            metadata, path_bytes = item.split(b"\t", 1)
            mode_bytes, type_bytes, object_bytes = metadata.split(b" ", 2)
        except ValueError:
            fail("unexpected git ls-tree record shape")
        try:
            mode = mode_bytes.decode("ascii")
            object_type = type_bytes.decode("ascii")
            object_id = object_bytes.decode("ascii")
            full_path = path_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("non-UTF-8 path found in Git tree")
        if full_path == root:
            if mode != "040000" or object_type != "tree":
                fail(f"declared package root is not a Git tree: {root}")
            root_seen_as_tree = True
            continue
        if root.startswith(full_path + "/"):
            if mode != "040000" or object_type != "tree":
                fail(f"ancestor of package root is not a Git tree: {full_path}")
            continue
        if not full_path.startswith(prefix):
            fail(f"git ls-tree escaped requested package root: {full_path!r}")
        relative = full_path[len(prefix):]
        validate_posix_relative_path(relative, "package path")
        records.append((mode, object_type, object_id, relative))
    return records, root_seen_as_tree


def enumerate_git_package(
    repo_path: Path,
    commit: str,
    root: str,
    name: str,
    *,
    source_workspace: bool = False,
) -> Package:
    validate_posix_relative_path(root, "package root")
    root_result = run_git(
        ["-C", str(repo_path), "ls-tree", "-z", commit, "--", root],
        text=False,
        source_workspace=source_workspace,
    )
    root_records, root_seen = parse_ls_tree_records(root_result.stdout, root)
    if root_records:
        fail(f"unexpected non-root entry while checking package root {root}")
    if not root_seen:
        fail(f"package root does not exist as a Git tree: {root}")

    recursive = run_git(
        ["-C", str(repo_path), "ls-tree", "-r", "-t", "-z", commit, "--", root],
        text=False,
        source_workspace=source_workspace,
    )
    records, _ = parse_ls_tree_records(recursive.stdout, root)
    files: list[FileRecord] = []
    for mode, object_type, object_id, relative in records:
        if mode == "040000":
            if object_type != "tree":
                fail(f"mode/type mismatch for tree {relative}")
            continue
        if mode in {"100644", "100755"}:
            if object_type != "blob":
                fail(f"mode/type mismatch for blob {relative}")
            data = run_git(
                ["-C", str(repo_path), "cat-file", "blob", object_id],
                text=False,
                source_workspace=source_workspace,
            ).stdout
            files.append(FileRecord(path=relative, executable=(mode == "100755"), data=data))
            continue
        if mode == "120000":
            fail(f"symlink is forbidden in skill package: {relative}")
        if mode == "160000":
            fail(f"gitlink/submodule is forbidden in skill package: {relative}")
        fail(f"unexpected Git mode {mode} in skill package: {relative}")

    package = package_from_files(name, files)
    validate_package(package)
    return package


def discover_public_skills(bound_source: BoundSource) -> tuple[DiscoveredSkill, ...]:
    source = bound_source.source
    repo_path = bound_source.path
    commit = bound_source.commit
    assert_source_workspace_isolated(repo_path)

    root_result = run_git(
        ["-C", str(repo_path), "ls-tree", "-z", commit, "--", source.skills_root],
        text=False,
        source_workspace=True,
    )
    root_records, root_seen = parse_ls_tree_records(root_result.stdout, source.skills_root)
    if root_records:
        fail(f"unexpected non-root entry while checking skillsRoot {source.skills_root}")
    if not root_seen:
        fail(f"skillsRoot does not exist as a Git tree: {source.skills_root}")

    direct = run_git(
        ["-C", str(repo_path), "ls-tree", "-z", f"{commit}:{source.skills_root}"],
        text=False,
        source_workspace=True,
    )
    prefix_bytes = tuple((prefix + "-").encode("ascii") for prefix in source.skill_prefixes)
    discovered: list[DiscoveredSkill] = []

    for item in direct.stdout.split(b"\0"):
        if not item:
            continue
        try:
            metadata, name_bytes = item.split(b"\t", 1)
            mode_bytes, type_bytes, object_bytes = metadata.split(b" ", 2)
            mode = mode_bytes.decode("ascii")
            object_type = type_bytes.decode("ascii")
            object_id = object_bytes.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            fail("unexpected direct-child git ls-tree record shape")

        matches_public_prefix = any(name_bytes.startswith(prefix) for prefix in prefix_bytes)
        if not matches_public_prefix:
            continue
        try:
            name = name_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            fail("non-UTF-8 public skill candidate found under skillsRoot")
        if "/" in name or name in {"", ".", ".."}:
            fail(f"invalid direct public skill child name: {name!r}")
        validate_name(name)
        if mode != "040000" or object_type != "tree":
            fail(f"public skill candidate must be a Git tree: {name}")
        if not HEX40_RE.fullmatch(object_id):
            fail(f"public skill candidate tree object id is not lowercase 40-hex: {name}")

        package_root = f"{source.skills_root}/{name}"
        package = enumerate_git_package(
            repo_path,
            commit,
            package_root,
            name,
            source_workspace=True,
        )
        discovered.append(
            DiscoveredSkill(
                source_id=source.source_id,
                repository_id=source.repository_id,
                repository=source.repository,
                ref=source.ref,
                skills_root=source.skills_root,
                skill_name=name,
                resolved_commit=commit,
                package=package,
            )
        )

    return tuple(sorted(discovered, key=lambda skill: skill.skill_name.encode("utf-8")))


def bind_manifest_sources(
    temp_root: Path,
    manifest: Manifest,
    previous_manifest: Manifest,
    *,
    http_get: HttpRequester = stdlib_http_get,
    branch_fetcher: BranchFetcher = git_fetch_configured_branch,
) -> dict[str, BoundSource]:
    validate_stable_identity_continuity(previous_manifest, manifest)
    bound_sources: dict[str, BoundSource] = {}
    for source in manifest.sources:
        bound_sources[source.source_id] = bind_source_snapshot(
            temp_root,
            source,
            http_get=http_get,
            branch_fetcher=branch_fetcher,
        )
    return bound_sources


def discover_manifest_skills(
    temp_root: Path,
    manifest: Manifest,
    previous_manifest: Manifest,
    *,
    http_get: HttpRequester = stdlib_http_get,
    branch_fetcher: BranchFetcher = git_fetch_configured_branch,
) -> tuple[dict[str, BoundSource], tuple[DiscoveredSkill, ...]]:
    bound_sources = bind_manifest_sources(
        temp_root,
        manifest,
        previous_manifest,
        http_get=http_get,
        branch_fetcher=branch_fetcher,
    )
    discovered: list[DiscoveredSkill] = []
    skill_names: set[str] = set()

    for source in manifest.sources:
        bound = bound_sources[source.source_id]
        for skill in discover_public_skills(bound):
            if skill.skill_name in skill_names:
                fail(f"duplicate discovered public skill name across sources: {skill.skill_name}")
            skill_names.add(skill.skill_name)
            discovered.append(skill)

    discovered.sort(key=lambda skill: skill.skill_name.encode("utf-8"))
    return bound_sources, tuple(discovered)


def skill_matches_source_prefix(source: SourceDeclaration, skill_name: str) -> bool:
    validate_name(skill_name)
    return any(skill_name.startswith(prefix + "-") for prefix in source.skill_prefixes)


def declaration_identity(source: SourceDeclaration, skill_name: str) -> PackageDeclarationIdentity:
    return PackageDeclarationIdentity(
        source_id=source.source_id,
        repository_id=source.repository_id,
        repository=source.repository,
        ref=source.ref,
        skills_root=source.skills_root,
        skill_name=skill_name,
    )


def discovered_declaration_identity(skill: DiscoveredSkill) -> PackageDeclarationIdentity:
    return PackageDeclarationIdentity(
        source_id=skill.source_id,
        repository_id=skill.repository_id,
        repository=skill.repository,
        ref=skill.ref,
        skills_root=skill.skills_root,
        skill_name=skill.skill_name,
    )


def packages_equivalent(left: Package, right: Package) -> bool:
    if left.name != right.name or left.digest != right.digest or len(left.files) != len(right.files):
        return False
    return all(
        left_record.path == right_record.path
        and left_record.executable == right_record.executable
        and left_record.data == right_record.data
        for left_record, right_record in zip(left.files, right.files)
    )


def digest_files(files: Iterable[FileRecord]) -> str:
    digest = hashlib.sha256()
    ordered = sorted(files, key=lambda record: record.path.encode("utf-8"))
    for record in ordered:
        path_bytes = record.path.encode("utf-8")
        file_hash = hashlib.sha256(record.data).digest()
        digest.update(struct.pack(">Q", len(path_bytes)))
        digest.update(path_bytes)
        digest.update(b"\x01" if record.executable else b"\x00")
        digest.update(struct.pack(">Q", len(record.data)))
        digest.update(file_hash)
    return digest.hexdigest()


def package_from_files(name: str, files: Iterable[FileRecord]) -> Package:
    file_tuple = tuple(sorted(files, key=lambda record: record.path.encode("utf-8")))
    seen: set[str] = set()
    for record in file_tuple:
        validate_posix_relative_path(record.path, "package path")
        if record.path in seen:
            fail(f"duplicate package path: {record.path}")
        seen.add(record.path)
    return Package(name=name, files=file_tuple, digest=digest_files(file_tuple))


def parse_simple_frontmatter_scalar(raw: str, key: str) -> str:
    value = raw.strip()
    if not value or value in {"|", ">"} or value.startswith("[") or value.startswith("{"):
        fail(f"SKILL.md field {key!r} must use a simple scalar")
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            fail(f"SKILL.md field {key!r} has invalid quoted scalar")
        if type(parsed) is not str:
            fail(f"SKILL.md field {key!r} must be a string")
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            fail(f"SKILL.md field {key!r} has invalid single-quoted scalar")
        return value[1:-1].replace("''", "'")
    return value


def parse_frontmatter(skill_md: bytes) -> dict[str, str]:
    try:
        text = skill_md.decode("utf-8")
    except UnicodeDecodeError:
        fail("SKILL.md must be UTF-8")
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        fail("SKILL.md must begin with YAML frontmatter delimiter '---'")
    try:
        end_index = lines.index("---", 1)
    except ValueError:
        fail("SKILL.md frontmatter is missing closing '---'")
    frontmatter_lines = lines[1:end_index]
    values: dict[str, str] = {}
    inside_metadata = False
    for line in frontmatter_lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if indent == 0:
            inside_metadata = False
            if ":" not in line:
                fail("unsupported SKILL.md frontmatter syntax")
            key, raw_value = line.split(":", 1)
            key = key.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
                fail(f"unsupported SKILL.md frontmatter key spelling: {key!r}")
            if key.startswith("metadata.github-"):
                fail(f"committed upstream provenance field is forbidden: {key}")
            if key == "metadata":
                inside_metadata = True
                if raw_value.strip() not in {"", "{}"}:
                    fail("unsupported inline metadata syntax in SKILL.md")
                continue
            if key in {"name", "description", "license"}:
                if key in values:
                    fail(f"duplicate SKILL.md field: {key}")
                values[key] = parse_simple_frontmatter_scalar(raw_value, key)
        elif inside_metadata:
            if ":" not in stripped:
                fail("unsupported metadata syntax in SKILL.md")
            nested_key = stripped.split(":", 1)[0].strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", nested_key):
                fail(f"unsupported metadata key spelling: {nested_key!r}")
            if nested_key.startswith("github-"):
                fail(f"committed GitHub install provenance is forbidden: metadata.{nested_key}")
    return values


def validate_package(package: Package) -> None:
    files = {record.path: record for record in package.files}
    if "SKILL.md" not in files:
        fail(f"skill package {package.name} is missing regular SKILL.md")
    fields = parse_frontmatter(files["SKILL.md"].data)
    name = fields.get("name")
    description = fields.get("description")
    if name is None or not name.strip():
        fail(f"skill package {package.name} is missing nonempty frontmatter name")
    if description is None or not description.strip():
        fail(f"skill package {package.name} is missing nonempty frontmatter description")
    validate_name(name)
    if name != package.name:
        fail(f"SKILL.md name {name!r} does not match package name {package.name!r}")
    license_value = fields.get("license")
    if license_value is not None:
        license_path = validate_posix_relative_path(license_value, "SKILL.md license")
        if license_path not in files:
            fail(f"SKILL.md license file is missing from package: {license_path}")


def package_description(package: Package) -> str:
    validate_package(package)
    files = {record.path: record for record in package.files}
    fields = parse_frontmatter(files["SKILL.md"].data)
    description = fields.get("description")
    if description is None or not description.strip():
        fail(f"skill package {package.name} is missing nonempty frontmatter description")
    return description


MARKDOWN_ESCAPE_CHARS = frozenset("\\`*_{}[]()#+-.!|>")


def render_markdown_inline(value: str) -> str:
    if type(value) is not str:
        fail("README display value must be a string")
    normalized_chars: list[str] = []
    pending_space = False
    for char in value:
        if char.isspace():
            pending_space = bool(normalized_chars)
            continue
        if pending_space:
            normalized_chars.append(" ")
            pending_space = False
        normalized_chars.append(char)
    normalized = "".join(normalized_chars)
    normalized = normalized.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    rendered: list[str] = []
    for char in normalized:
        if char in MARKDOWN_ESCAPE_CHARS:
            rendered.append("\\")
        rendered.append(char)
    return "".join(rendered)


def parse_readme_layout_bytes(data: bytes) -> ReadmeLayout:
    if type(data) is not bytes:
        fail("README layout parser requires bytes")
    if data.count(README_BEGIN_MARKER) != 1:
        fail("README.md must contain exactly one federation catalog BEGIN marker")
    if data.count(README_END_MARKER) != 1:
        fail("README.md must contain exactly one federation catalog END marker")
    begin_index = data.index(README_BEGIN_MARKER)
    begin_end = begin_index + len(README_BEGIN_MARKER)
    end_index = data.index(README_END_MARKER)
    if begin_end >= end_index:
        fail("README.md federation catalog markers are reordered or ambiguous")
    return ReadmeLayout(
        prefix_through_begin=data[:begin_end],
        managed=data[begin_end:end_index],
        suffix_from_end=data[end_index:],
    )


def read_readme_layout(path: Path = README_PATH) -> ReadmeLayout:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail("README.md must be a regular non-symlink file")
    return parse_readme_layout_bytes(path.read_bytes())


def full_readme_bytes_from_layout(layout: ReadmeLayout) -> bytes:
    return layout.prefix_through_begin + layout.managed + layout.suffix_from_end


def canonical_managed_readme_bytes(content: str) -> bytes:
    if type(content) is not str or "\r" in content:
        fail("generated README catalog content must be LF-only text")
    return b"\n\n" + content.encode("utf-8") + b"\n\n"


def render_full_readme(layout: ReadmeLayout, managed_content: str) -> bytes:
    return layout.prefix_through_begin + canonical_managed_readme_bytes(managed_content) + layout.suffix_from_end


def source_owned_skill_names(source: SourceDeclaration, lock: LockState) -> tuple[str, ...]:
    names = [name for name, entry in lock.skills.items() if entry.source_id == source.source_id]
    return tuple(sorted(names, key=lambda value: value.encode("utf-8")))


def render_source_catalog_section(
    source: SourceDeclaration,
    lock: LockState,
    packages: dict[str, Package],
    *,
    force_zero_skills: bool = False,
) -> str:
    repository_display = render_markdown_inline(source.repository)
    repository_url = repository_git_url(source.repository).removesuffix(".git")
    description = render_markdown_inline(source.description)
    lines = [f"### [{repository_display}]({repository_url})", "", description]
    skill_names = () if force_zero_skills else source_owned_skill_names(source, lock)
    if not skill_names:
        lines.extend(["", EMPTY_SOURCE_SKILLS])
        return "\n".join(lines)
    lines.extend(["", "| Skill | Description |", "| --- | --- |"])
    for skill_name in skill_names:
        entry = lock.skills.get(skill_name)
        package = packages.get(skill_name)
        if entry is None or entry.source_id != source.source_id:
            fail(f"README catalog skill ownership mismatch: {skill_name}")
        if package is None or package.name != skill_name or package.digest != entry.content_sha256:
            fail(f"README catalog package/lock mismatch: {skill_name}")
        lines.append(
            f"| {render_markdown_inline(skill_name)} | "
            f"{render_markdown_inline(package_description(package))} |"
        )
    return "\n".join(lines)


def render_converged_catalog_content(
    manifest: Manifest,
    lock: LockState,
    packages: dict[str, Package],
) -> str:
    if not manifest.sources:
        if lock.published_source_ids or lock.skills or packages:
            fail("empty README catalog manifest requires empty publication/package state")
        return EMPTY_CATALOG_PLACEHOLDER
    ordered_sources = tuple(sorted(manifest.sources, key=lambda source: source.source_id.encode("utf-8")))
    expected_published = tuple(source.source_id for source in ordered_sources)
    if lock.published_source_ids != expected_published:
        fail("converged README rendering requires every candidate source to be published")
    if set(packages) != set(lock.skills):
        fail("converged README rendering requires exact lock/package coverage")
    return "\n\n".join(render_source_catalog_section(source, lock, packages) for source in ordered_sources)


def read_canonical_managed_content(layout: ReadmeLayout) -> str:
    managed = layout.managed
    if not managed.startswith(b"\n\n") or not managed.endswith(b"\n\n") or len(managed) < 4:
        fail("README.md generated catalog must use canonical blank lines around managed content")
    try:
        content = managed[2:-2].decode("utf-8")
    except UnicodeDecodeError:
        fail("README.md generated catalog content must be UTF-8")
    if "\r" in content:
        fail("README.md generated catalog content must use LF newlines")
    return content


def validate_readme_catalog(
    manifest: Manifest,
    lock: LockState,
    packages: dict[str, Package],
    layout: ReadmeLayout,
) -> None:
    if set(packages) != set(lock.skills):
        fail("README validation requires exact lock/package coverage")
    manifest_sources = manifest.by_source_id
    published = set(lock.published_source_ids)
    for source_id in published:
        if source_id not in manifest_sources:
            fail(f"README publication marker references unknown sourceId: {source_id}")
    for skill_name, entry in lock.skills.items():
        source = manifest_sources.get(entry.source_id)
        package = packages.get(skill_name)
        if source is None or entry.source_id not in published:
            fail(f"README lock skill lacks published manifest owner: {skill_name}")
        if package is None or package.name != skill_name or package.digest != entry.content_sha256:
            fail(f"README lock/package identity mismatch: {skill_name}")
        if not skill_matches_source_prefix(source, skill_name):
            fail(f"README lock skill no longer matches accepted source prefix: {skill_name}")
    ordered_sources = tuple(sorted(manifest.sources, key=lambda source: source.source_id.encode("utf-8")))
    for source in ordered_sources:
        if source.source_id not in published and source_owned_skill_names(source, lock):
            fail(f"pending README source owns lock skills: {source.source_id}")

    content = read_canonical_managed_content(layout)
    if not manifest.sources:
        if content != EMPTY_CATALOG_PLACEHOLDER:
            fail("empty federation README catalog must equal deterministic placeholder")
        return
    if content == EMPTY_CATALOG_PLACEHOLDER:
        if published:
            fail("README placeholder cannot represent a published source")
        return
    if not content.startswith("### "):
        fail("nonempty README catalog must begin with a generated source section")

    raw_sections = content.split("\n\n### ")
    sections = [raw_sections[0], *("### " + section for section in raw_sections[1:])]
    possible_indices: set[int] = {0}
    for source in ordered_sources:
        is_published = source.source_id in published
        expected = render_source_catalog_section(
            source,
            lock,
            packages,
            force_zero_skills=not is_published,
        )
        next_indices: set[int] = set()
        for section_index in possible_indices:
            if is_published:
                if section_index < len(sections) and sections[section_index] == expected:
                    next_indices.add(section_index + 1)
            else:
                next_indices.add(section_index)
                if section_index < len(sections) and sections[section_index] == expected:
                    next_indices.add(section_index + 1)
        if not next_indices:
            fail(f"README source section is missing, reordered, or noncanonical: {source.source_id}")
        possible_indices = next_indices
    if len(sections) not in possible_indices:
        fail("README catalog contains unknown, duplicated, reordered, or noncanonical source section")


def validate_materialized_tree(root: Path) -> None:
    try:
        root_stat = os.lstat(root)
    except FileNotFoundError:
        fail(f"materialized package is missing: {root}")
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        fail(f"materialized package root must be a real directory: {root}")
    for current_root, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_root)
        for name in list(dirs):
            path = current / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                fail(f"non-directory/symlink found in package tree: {path}")
        for name in files:
            path = current / name
            info = os.lstat(path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                fail(f"non-regular/symlink file found in package tree: {path}")


def materialize_package(package: Package, target: Path) -> None:
    if target.exists() or target.is_symlink():
        fail(f"staging target already exists: {target}")
    target.mkdir(parents=True)
    for record in package.files:
        destination = target.joinpath(*PurePosixPath(record.path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(record.data)
        destination.chmod(0o755 if record.executable else 0o644)
    validate_materialized_tree(target)
    materialized = package_from_worktree(package.name, target)
    validate_package(materialized)
    if materialized.digest != package.digest:
        fail(f"materialized package digest mismatch for {package.name}")


def package_from_worktree(name: str, root: Path) -> Package:
    validate_materialized_tree(root)
    files: list[FileRecord] = []
    for current_root, dirs, filenames in os.walk(root, topdown=True, followlinks=False):
        dirs.sort()
        filenames.sort()
        current = Path(current_root)
        for filename in filenames:
            path = current / filename
            info = os.lstat(path)
            relative = path.relative_to(root).as_posix()
            validate_posix_relative_path(relative, "package path")
            executable = bool(info.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            files.append(FileRecord(path=relative, executable=executable, data=path.read_bytes()))
    package = package_from_files(name, files)
    validate_package(package)
    return package


def git_head_exists() -> bool:
    return run_git(["rev-parse", "--verify", "HEAD"], cwd=ROOT, check=False).returncode == 0


def head_commit_oid() -> str:
    result = run_git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=ROOT)
    commit = result.stdout.strip()
    if not HEX40_RE.fullmatch(commit):
        fail("HEAD must resolve to lowercase 40-hex commit")
    return commit


def parse_single_ls_tree_entry(raw: bytes, expected_path: str, *, allow_absent: bool = False) -> tuple[str, str, str] | None:
    records = [record for record in raw.split(b"\0") if record]
    if not records:
        if allow_absent:
            return None
        fail(f"missing committed Git tree entry: {expected_path}")
    if len(records) != 1:
        fail(f"unexpected committed Git tree entry multiplicity for {expected_path}")
    try:
        metadata, path_bytes = records[0].split(b"\t", 1)
        mode_bytes, type_bytes, object_bytes = metadata.split(b" ", 2)
        path = path_bytes.decode("utf-8", errors="strict")
        mode = mode_bytes.decode("ascii")
        object_type = type_bytes.decode("ascii")
        object_id = object_bytes.decode("ascii")
    except (ValueError, UnicodeDecodeError):
        fail(f"invalid committed Git tree entry encoding for {expected_path}")
    if path != expected_path:
        fail(f"committed Git tree entry path mismatch: expected {expected_path!r}, got {path!r}")
    if not HEX40_RE.fullmatch(object_id):
        fail(f"committed Git tree object id is not lowercase 40-hex: {expected_path}")
    return mode, object_type, object_id


def committed_entry(
    relative_path: str,
    *,
    commit: str = "HEAD",
    allow_absent: bool = False,
) -> tuple[str, str, str] | None:
    validate_posix_relative_path(relative_path, "committed proof path")
    if commit != "HEAD" and not HEX40_RE.fullmatch(commit):
        fail(f"committed proof commit must be lowercase 40-hex: {commit!r}")
    result = run_git(["ls-tree", "-z", commit, "--", relative_path], cwd=ROOT, text=False)
    return parse_single_ls_tree_entry(result.stdout, relative_path, allow_absent=allow_absent)


def committed_regular_blob_bytes(relative_path: str, *, commit: str = "HEAD") -> bytes:
    entry = committed_entry(relative_path, commit=commit)
    if entry is None:
        fail(f"missing committed proof blob: {relative_path}")
    mode, object_type, _ = entry
    if mode != "100644" or object_type != "blob":
        fail(f"committed proof file must be mode 100644 blob: {relative_path}")
    return run_git(["show", f"{commit}:{relative_path}"], cwd=ROOT, text=False).stdout


def require_worktree_regular_file_equal_head(
    path: Path,
    relative_path: str,
    *,
    commit: str,
    require_mode_0644: bool,
) -> bytes:
    expected = committed_regular_blob_bytes(relative_path, commit=commit)
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        fail(f"committed proof file is missing from worktree: {relative_path}")
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        fail(f"committed proof file must be a regular non-symlink file: {relative_path}")
    if require_mode_0644 and stat.S_IMODE(info.st_mode) != 0o644:
        fail(f"committed proof file must use filesystem mode 0644: {relative_path}")
    actual = path.read_bytes()
    if actual != expected:
        fail(f"worktree proof file differs byte-for-byte from HEAD: {relative_path}")
    return actual


def load_trusted_head_json(relative_path: str, context: str) -> dict[str, Any]:
    if not git_head_exists():
        fail("trusted accepted-base reads require Git HEAD")
    result = run_git(["show", f"HEAD:{relative_path}"], cwd=ROOT, check=False)
    if result.returncode != 0:
        fail(f"missing trusted accepted {context} in HEAD: {relative_path}")
    try:
        value = decode_json(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"invalid JSON in trusted accepted {context}: {error.msg}")
    if type(value) is not dict:
        fail(f"trusted accepted {context} must be a JSON object")
    return value


def load_trusted_previous_manifest() -> Manifest:
    value = load_trusted_head_json("federation.json", "federation manifest")
    if is_exact_int(value.get("schemaVersion"), 2):
        return load_manifest_from_value(value, "HEAD:federation.json")
    require_exact_keys(value, {"schemaVersion", "sources"}, "HEAD:federation.json legacy bootstrap")
    if not is_exact_int(value["schemaVersion"], 1) or type(value["sources"]) is not list or value["sources"] != []:
        fail("HEAD:federation.json legacy compatibility accepts only exact empty schema-v1 bootstrap")
    return Manifest(sources=())


def load_trusted_previous_lock(manifest: Manifest) -> LockState:
    value = load_trusted_head_json("federation.lock.json", "federation lock")
    if is_exact_int(value.get("schemaVersion"), 2):
        return load_lock_from_value(value, manifest, "HEAD:federation.lock.json")
    require_exact_keys(
        value,
        {"schemaVersion", "contentDigestAlgorithm", "skills"},
        "HEAD:federation.lock.json legacy bootstrap",
    )
    if not is_exact_int(value["schemaVersion"], 1):
        fail("HEAD:federation.lock.json legacy compatibility accepts only schemaVersion integer 1")
    if type(value["contentDigestAlgorithm"]) is not str or value["contentDigestAlgorithm"] != DIGEST_ALGORITHM:
        fail("HEAD:federation.lock.json legacy bootstrap has unexpected digest algorithm")
    if type(value["skills"]) is not dict or value["skills"] != {}:
        fail("HEAD:federation.lock.json legacy compatibility accepts only exact empty schema-v1 bootstrap")
    return LockState(published_source_ids=(), skills={})


def validate_stable_identity_continuity(previous: Manifest, candidate: Manifest) -> None:
    previous_by_source_id = previous.by_source_id
    candidate_by_source_id = candidate.by_source_id
    for source_id in sorted(set(previous_by_source_id) & set(candidate_by_source_id)):
        previous_source = previous_by_source_id[source_id]
        candidate_source = candidate_by_source_id[source_id]
        if candidate_source.repository_id != previous_source.repository_id:
            fail(
                f"stable sourceId {source_id!r} cannot rebind repositoryId "
                f"{previous_source.repository_id} -> {candidate_source.repository_id}"
            )

    previous_by_repository_id = previous.by_repository_id
    candidate_by_repository_id = candidate.by_repository_id
    for repository_id in sorted(set(previous_by_repository_id) & set(candidate_by_repository_id)):
        previous_source = previous_by_repository_id[repository_id]
        candidate_source = candidate_by_repository_id[repository_id]
        if candidate_source.source_id != previous_source.source_id:
            fail(
                f"stable repositoryId {repository_id} cannot rebind sourceId "
                f"{previous_source.source_id!r} -> {candidate_source.source_id!r}"
            )


def list_worktree_skill_targets() -> dict[str, Path]:
    if not SKILLS_ROOT.exists() and not SKILLS_ROOT.is_symlink():
        return {}
    info = os.lstat(SKILLS_ROOT)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("skills must be a real directory when present")
    result: dict[str, Path] = {}
    for child in SKILLS_ROOT.iterdir():
        info = os.lstat(child)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            fail(f"unexpected non-directory entry directly under skills/: {child.name}")
        validate_name(child.name)
        result[child.name] = child
    return result


def assert_generated_paths_clean() -> None:
    result = run_git(
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--",
            "federation.json",
            "federation.lock.json",
            "README.md",
            "skills",
        ],
        cwd=ROOT,
    )
    if result.stdout.strip():
        fail("--check-local/--verify-upstream require committed clean manifest/lock/README/generated paths")


def list_committed_skill_targets(commit: str) -> tuple[str, ...]:
    if not HEX40_RE.fullmatch(commit):
        fail(f"committed skills proof commit must be lowercase 40-hex: {commit!r}")
    root_entry = committed_entry("skills", commit=commit, allow_absent=True)
    if root_entry is None:
        return ()
    root_mode, root_type, _ = root_entry
    if root_mode != "040000" or root_type != "tree":
        fail("committed skills root must be a Git tree")
    result = run_git(["ls-tree", "-z", f"{commit}:skills"], cwd=ROOT, text=False)
    names: list[str] = []
    for raw_record in result.stdout.split(b"\0"):
        if not raw_record:
            continue
        try:
            metadata, name_bytes = raw_record.split(b"\t", 1)
            mode_bytes, type_bytes, object_bytes = metadata.split(b" ", 2)
            mode = mode_bytes.decode("ascii")
            object_type = type_bytes.decode("ascii")
            object_id = object_bytes.decode("ascii")
            name = name_bytes.decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            fail("invalid direct committed skills/ Git tree record")
        validate_name(name)
        if "/" in name:
            fail(f"committed skills/ direct child contains slash: {name!r}")
        if mode != "040000" or object_type != "tree":
            fail(f"committed generated target must be a Git tree: {name}")
        if not HEX40_RE.fullmatch(object_id):
            fail(f"committed generated target tree id is not lowercase 40-hex: {name}")
        names.append(name)
    if len(set(names)) != len(names):
        fail("duplicate committed generated skill target name")
    return tuple(sorted(names, key=lambda value: value.encode("utf-8")))


def enumerate_committed_package(name: str, *, commit: str = "HEAD") -> Package:
    if commit == "HEAD":
        if not git_head_exists():
            fail("committed package validation requires HEAD")
    elif not HEX40_RE.fullmatch(commit):
        fail(f"committed package proof commit must be lowercase 40-hex: {commit!r}")
    return enumerate_git_package(ROOT, commit, f"skills/{name}", name)


def prove_committed_local_state() -> CommittedLocalProof:
    head_before = head_commit_oid()
    assert_generated_paths_clean()
    manifest_bytes = require_worktree_regular_file_equal_head(
        MANIFEST_PATH, "federation.json", commit=head_before, require_mode_0644=False
    )
    lock_bytes = require_worktree_regular_file_equal_head(
        LOCK_PATH, "federation.lock.json", commit=head_before, require_mode_0644=True
    )
    readme_bytes = require_worktree_regular_file_equal_head(
        README_PATH, "README.md", commit=head_before, require_mode_0644=True
    )
    try:
        manifest_value = decode_json(manifest_bytes.decode("utf-8"))
        lock_value = decode_json(lock_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        fail("committed manifest/lock proof files must be UTF-8")
    except json.JSONDecodeError as error:
        fail(f"committed manifest/lock proof file is invalid JSON: {error.msg}")
    if type(manifest_value) is not dict or type(lock_value) is not dict:
        fail("committed manifest/lock proof files must be JSON objects")
    manifest = load_manifest_from_value(manifest_value, "HEAD/current federation.json")
    lock = load_lock_from_value(lock_value, manifest, "HEAD/current federation.lock.json")
    if lock_bytes != render_lock(lock):
        fail("committed federation.lock.json is not in deterministic schema-v2 rendering")

    committed_names = list_committed_skill_targets(head_before)
    if set(committed_names) != set(lock.skills):
        fail("committed lock/generated target coverage mismatch")
    worktree_targets = list_worktree_skill_targets()
    if set(worktree_targets) != set(committed_names):
        fail("worktree/committed generated target coverage mismatch")

    committed_packages: dict[str, Package] = {}
    published = set(lock.published_source_ids)
    manifest_sources = manifest.by_source_id
    for name in committed_names:
        entry = lock.skills[name]
        source = manifest_sources.get(entry.source_id)
        if source is None or entry.source_id not in published:
            fail(f"committed lock skill lacks published manifest owner: {name}")
        if not skill_matches_source_prefix(source, name):
            fail(f"committed lock skill no longer matches accepted source prefix: {name}")
        committed_package = enumerate_committed_package(name, commit=head_before)
        if committed_package.digest != entry.content_sha256:
            fail(f"committed package digest does not match lock: {name}")
        worktree_package = package_from_worktree(name, worktree_targets[name])
        if not packages_equivalent(committed_package, worktree_package):
            fail(f"worktree generated package differs from committed HEAD package: {name}")
        committed_packages[name] = committed_package

    for source in manifest.sources:
        if source.source_id not in published and source_owned_skill_names(source, lock):
            fail(f"pending source owns committed lock/package state: {source.source_id}")

    readme_layout = parse_readme_layout_bytes(readme_bytes)
    validate_readme_catalog(manifest, lock, committed_packages, readme_layout)
    assert_generated_paths_clean()
    head_after = head_commit_oid()
    if head_after != head_before:
        fail("HEAD changed during committed local proof")
    return CommittedLocalProof(
        head_commit=head_before,
        manifest=manifest,
        lock=lock,
        committed_packages=committed_packages,
        readme_layout=readme_layout,
        readme_bytes=readme_bytes,
    )


def load_trusted_previous_publications(
    previous_manifest: Manifest,
    previous_lock: LockState,
) -> dict[str, PreviousPublication]:
    previous_sources = previous_manifest.by_source_id
    publications: dict[str, PreviousPublication] = {}
    for skill_name in sorted(previous_lock.skills, key=lambda value: value.encode("utf-8")):
        entry = previous_lock.skills[skill_name]
        source = previous_sources.get(entry.source_id)
        if source is None:
            fail(f"trusted previous lock skill {skill_name} has unknown sourceId {entry.source_id}")
        if not skill_matches_source_prefix(source, skill_name):
            fail(f"trusted previous lock skill no longer matches accepted source prefix: {skill_name}")
        package = enumerate_committed_package(skill_name)
        if package.digest != entry.content_sha256:
            fail(f"trusted HEAD package digest does not match trusted previous lock: {skill_name}")
        publications[skill_name] = PreviousPublication(
            declaration=declaration_identity(source, skill_name),
            lock_entry=entry,
            package=package,
        )
    return publications


def list_reconcilable_worktree_target_names() -> set[str]:
    if not SKILLS_ROOT.exists() and not SKILLS_ROOT.is_symlink():
        return set()
    info = os.lstat(SKILLS_ROOT)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        fail("skills must be a real directory when reconciling generated output")
    return {child.name for child in SKILLS_ROOT.iterdir()}


def worktree_package_matches_desired(name: str, desired: Package) -> bool:
    target = SKILLS_ROOT / name
    if not target.exists() and not target.is_symlink():
        return False
    try:
        current = package_from_worktree(name, target)
    except (FederationError, OSError):
        return False
    return packages_equivalent(current, desired)


def validate_desired_publication_state(manifest: Manifest, desired: DesiredPublicationState) -> None:
    expected_published = tuple(source.source_id for source in manifest.sources)
    if desired.lock.published_source_ids != expected_published:
        fail("desired publishedSourceIds must equal all candidate manifest sourceIds")
    if set(desired.lock.skills) != set(desired.packages):
        fail("desired lock/package skill coverage mismatch")
    parsed_lock = load_lock_from_value(
        decode_json(render_lock(desired.lock).decode("utf-8")),
        manifest,
        "desired federation lock",
    )
    if parsed_lock != desired.lock:
        fail("desired federation lock does not round-trip through schema-v2 validation")
    for name, package in desired.packages.items():
        entry = desired.lock.skills[name]
        if package.name != name or package.digest != entry.content_sha256:
            fail(f"desired package/lock digest identity mismatch for {name}")


def build_desired_publication_state(
    network_root: Path,
    manifest: Manifest,
    previous_manifest: Manifest,
    previous_lock: LockState,
    bound_sources: dict[str, BoundSource],
    discovered: tuple[DiscoveredSkill, ...],
) -> DesiredPublicationState:
    validate_stable_identity_continuity(previous_manifest, manifest)
    expected_source_ids = set(manifest.by_source_id)
    if set(bound_sources) != expected_source_ids:
        fail("R03 bound source set must exactly cover all candidate manifest sources")
    previous_publications = load_trusted_previous_publications(previous_manifest, previous_lock)
    desired_entries: dict[str, LockEntry] = {}
    desired_packages: dict[str, Package] = {}

    for skill in discovered:
        if skill.skill_name in desired_entries:
            fail(f"duplicate discovered skill reached R03 desired-state builder: {skill.skill_name}")
        source = manifest.by_source_id.get(skill.source_id)
        if source is None:
            fail(f"discovered skill references unknown candidate sourceId: {skill.source_id}")
        if (
            skill.repository_id != source.repository_id
            or skill.repository != source.repository
            or skill.ref != source.ref
            or skill.skills_root != source.skills_root
        ):
            fail(f"discovered skill declaration does not match accepted candidate source: {skill.skill_name}")
        if not skill_matches_source_prefix(source, skill.skill_name):
            fail(f"discovered skill no longer matches candidate source prefix: {skill.skill_name}")
        bound_source = bound_sources.get(skill.source_id)
        if bound_source is None:
            fail(f"discovered skill is missing successfully bound source: {skill.skill_name}")
        if bound_source.source != source or skill.resolved_commit != bound_source.commit:
            fail(f"discovered skill is not anchored to its successfully bound source commit: {skill.skill_name}")
        if skill.package.name != skill.skill_name:
            fail(f"discovered package name does not match discovered skill name: {skill.skill_name}")

        previous = previous_publications.get(skill.skill_name)
        current_identity = discovered_declaration_identity(skill)
        if previous is None:
            desired_entry = LockEntry(
                source_id=skill.source_id,
                resolved_commit=skill.resolved_commit,
                content_sha256=skill.package.digest,
            )
            desired_package = skill.package
        elif previous.package.digest != previous.lock_entry.content_sha256:
            fail(f"trusted previous package/lock mismatch for {skill.skill_name}")
        elif skill.package.digest != previous.lock_entry.content_sha256:
            desired_entry = LockEntry(
                source_id=skill.source_id,
                resolved_commit=skill.resolved_commit,
                content_sha256=skill.package.digest,
            )
            desired_package = skill.package
        elif previous.declaration != current_identity:
            desired_entry = LockEntry(
                source_id=skill.source_id,
                resolved_commit=skill.resolved_commit,
                content_sha256=previous.lock_entry.content_sha256,
            )
            desired_package = skill.package
        else:
            access = retrieve_historical_commit(
                network_root,
                bound_source,
                previous.lock_entry.resolved_commit,
            )
            if access.result is HistoricalCommitResult.RETRIEVED:
                desired_entry = previous.lock_entry
                desired_package = previous.package
            elif access.result is HistoricalCommitResult.DEFINITIVELY_MISSING:
                desired_entry = LockEntry(
                    source_id=previous.lock_entry.source_id,
                    resolved_commit=skill.resolved_commit,
                    content_sha256=previous.lock_entry.content_sha256,
                )
                desired_package = previous.package
            elif access.result is HistoricalCommitResult.AMBIGUOUS_FAIL:
                fail(f"historical provenance retrieval is ambiguous for {skill.skill_name}")
            else:
                fail(f"unexpected historical provenance result for {skill.skill_name}")

        desired_entries[skill.skill_name] = desired_entry
        desired_packages[skill.skill_name] = desired_package

    desired = DesiredPublicationState(
        lock=LockState(
            published_source_ids=tuple(source.source_id for source in manifest.sources),
            skills=desired_entries,
        ),
        packages=desired_packages,
    )
    validate_desired_publication_state(manifest, desired)
    return desired


def validate_empty_pre_r03_state(manifest: Manifest, lock: LockState) -> None:
    if manifest.sources:
        fail("nonempty federation state requires later C02 bounded phases")
    if lock.published_source_ids or lock.skills:
        fail("empty federation candidate must have an empty schema-v2 publication lock")
    targets = list_worktree_skill_targets()
    if targets:
        fail("empty federation candidate must not contain generated skills/** targets")
    if LOCK_PATH.read_bytes() != render_lock(lock):
        fail("federation.lock.json is not in deterministic schema-v2 rendering")


def atomic_write_file(path: Path, data: bytes, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def apply_update_transaction(
    staged_packages: dict[str, Path],
    delete_names: set[str],
    new_lock_bytes: bytes,
    expected_readme_before: bytes,
    new_readme_bytes: bytes,
    validator: Callable[[], None],
) -> None:
    SKILLS_ROOT.mkdir(parents=True, exist_ok=True) if (staged_packages or delete_names) else None
    with tempfile.TemporaryDirectory(prefix=".federation-transaction-", dir=ROOT) as temp_name:
        backup_root = Path(temp_name) / "backup"
        backup_root.mkdir()
        lock_existed = LOCK_PATH.exists() or LOCK_PATH.is_symlink()
        old_lock: bytes | None = None
        old_lock_mode: int | None = None
        if lock_existed:
            lock_info = os.lstat(LOCK_PATH)
            if stat.S_ISLNK(lock_info.st_mode) or not stat.S_ISREG(lock_info.st_mode):
                fail("federation.lock.json must be a regular file before transactional replacement")
            old_lock = LOCK_PATH.read_bytes()
            old_lock_mode = stat.S_IMODE(lock_info.st_mode)
        readme_info = os.lstat(README_PATH)
        if stat.S_ISLNK(readme_info.st_mode) or not stat.S_ISREG(readme_info.st_mode):
            fail("README.md must be a regular file before transactional replacement")
        old_readme = README_PATH.read_bytes()
        old_readme_mode = stat.S_IMODE(readme_info.st_mode)
        if old_readme != expected_readme_before:
            fail("README.md changed after marker/layout validation; refusing to clobber concurrent hand-authored edits")

        changed_names = sorted(set(staged_packages) | delete_names)
        moved_existing: set[str] = set()
        installed_new: set[str] = set()

        def bounded_error_summary(error: BaseException) -> str:
            detail = str(error).replace("\x00", "\\0").replace("\n", "\\n")
            if len(detail) > 160:
                detail = detail[:157] + "..."
            return type(error).__name__ + (f": {detail}" if detail else "")

        def attempt_rollback(
            errors: list[str],
            action: str,
            operation: Callable[[], None],
        ) -> None:
            try:
                operation()
            except BaseException as error:
                errors.append(f"{action}: {bounded_error_summary(error)}")

        def rollback_live_state() -> list[str]:
            errors: list[str] = []
            for name in reversed(changed_names):
                target = SKILLS_ROOT / name
                backup = backup_root / name
                if name in installed_new:
                    attempt_rollback(
                        errors,
                        f"remove installed package {name}",
                        lambda target=target: (
                            target.unlink()
                            if target.is_symlink() or not target.is_dir()
                            else shutil.rmtree(target)
                        )
                        if target.exists() or target.is_symlink()
                        else None,
                    )
                if name in moved_existing:
                    attempt_rollback(
                        errors,
                        f"restore package {name}",
                        lambda target=target, backup=backup: os.replace(backup, target)
                        if backup.exists() or backup.is_symlink()
                        else None,
                    )
            if old_lock is not None:
                attempt_rollback(
                    errors,
                    "restore federation.lock.json",
                    lambda: atomic_write_file(
                        LOCK_PATH,
                        old_lock,
                        mode=old_lock_mode if old_lock_mode is not None else 0o644,
                    ),
                )
            else:
                attempt_rollback(
                    errors,
                    "remove newly created federation.lock.json",
                    lambda: LOCK_PATH.unlink()
                    if LOCK_PATH.exists() or LOCK_PATH.is_symlink()
                    else None,
                )
            attempt_rollback(
                errors,
                "restore README.md",
                lambda: atomic_write_file(README_PATH, old_readme, mode=old_readme_mode),
            )
            return errors

        def cleanup_empty_skills_root() -> None:
            if SKILLS_ROOT.exists() and not any(SKILLS_ROOT.iterdir()):
                SKILLS_ROOT.rmdir()

        try:
            for name in changed_names:
                target = SKILLS_ROOT / name
                if target.exists() or target.is_symlink():
                    backup = backup_root / name
                    moved_existing.add(name)
                    os.replace(target, backup)
                if name in staged_packages:
                    installed_new.add(name)
                    os.replace(staged_packages[name], target)
            atomic_write_file(LOCK_PATH, new_lock_bytes)
            atomic_write_file(README_PATH, new_readme_bytes)
            validator()
        except BaseException as original_error:
            rollback_errors = rollback_live_state()
            try:
                cleanup_empty_skills_root()
            except BaseException as error:
                rollback_errors.append(f"clean up empty skills root: {bounded_error_summary(error)}")
            if rollback_errors:
                detail = "; ".join(rollback_errors)
                raise FederationError(
                    "transaction failed with "
                    f"{bounded_error_summary(original_error)}; incomplete rollback: {detail}"
                ) from original_error
            raise
        else:
            try:
                cleanup_empty_skills_root()
            except BaseException as error:
                raise FederationError(
                    f"transaction cleanup failed: {bounded_error_summary(error)}"
                ) from error


def validate_r03_live_state(manifest: Manifest, desired: DesiredPublicationState) -> None:
    lock_info = os.lstat(LOCK_PATH)
    if stat.S_ISLNK(lock_info.st_mode) or not stat.S_ISREG(lock_info.st_mode):
        fail("post-R03 federation.lock.json must be a regular file")
    if stat.S_IMODE(lock_info.st_mode) != 0o644:
        fail("post-R03 federation.lock.json must use mode 0644")
    live_lock = load_lock(manifest)
    if live_lock != desired.lock:
        fail("post-R03 live lock does not equal complete desired lock")
    if LOCK_PATH.read_bytes() != render_lock(desired.lock):
        fail("post-R03 live lock bytes are not deterministic desired rendering")

    live_names = list_reconcilable_worktree_target_names()
    desired_names = set(desired.packages)
    if live_names != desired_names:
        fail(
            "post-R03 generated target coverage mismatch: "
            f"live={sorted(live_names)} desired={sorted(desired_names)}"
        )
    for name in sorted(desired_names, key=lambda value: value.encode("utf-8")):
        live_package = package_from_worktree(name, SKILLS_ROOT / name)
        desired_package = desired.packages[name]
        if not packages_equivalent(live_package, desired_package):
            fail(f"post-R03 generated package differs from desired package: {name}")
        entry = live_lock.skills.get(name)
        if entry is None or entry != desired.lock.skills[name]:
            fail(f"post-R03 live lock entry differs from desired provenance: {name}")


def validate_r04_live_state(
    manifest: Manifest,
    desired: DesiredPublicationState,
    desired_readme_bytes: bytes,
    retained_layout: ReadmeLayout,
) -> None:
    validate_r03_live_state(manifest, desired)
    readme_info = os.lstat(README_PATH)
    if stat.S_ISLNK(readme_info.st_mode) or not stat.S_ISREG(readme_info.st_mode):
        fail("post-R04 README.md must be a regular file")
    if stat.S_IMODE(readme_info.st_mode) != 0o644:
        fail("post-R04 README.md must use mode 0644")
    live_readme = README_PATH.read_bytes()
    if live_readme != desired_readme_bytes:
        fail("post-R04 README.md bytes differ from complete desired README")
    live_layout = parse_readme_layout_bytes(live_readme)
    if live_layout.prefix_through_begin != retained_layout.prefix_through_begin:
        fail("post-R04 README prefix outside managed catalog changed")
    if live_layout.suffix_from_end != retained_layout.suffix_from_end:
        fail("post-R04 README suffix outside managed catalog changed")
    validate_readme_catalog(manifest, desired.lock, desired.packages, live_layout)


def apply_r04_desired_state(
    manifest: Manifest,
    desired: DesiredPublicationState,
    retained_layout: ReadmeLayout,
    desired_readme_bytes: bytes,
) -> None:
    validate_desired_publication_state(manifest, desired)
    desired_layout = parse_readme_layout_bytes(desired_readme_bytes)
    if desired_layout.prefix_through_begin != retained_layout.prefix_through_begin:
        fail("desired README prefix does not preserve retained outside bytes")
    if desired_layout.suffix_from_end != retained_layout.suffix_from_end:
        fail("desired README suffix does not preserve retained outside bytes")
    validate_readme_catalog(manifest, desired.lock, desired.packages, desired_layout)
    current_names = list_reconcilable_worktree_target_names()
    desired_names = set(desired.packages)
    delete_names = current_names - desired_names
    desired_lock_bytes = render_lock(desired.lock)

    with tempfile.TemporaryDirectory(prefix=".federation-stage-", dir=ROOT) as stage_temp_name:
        stage_root = Path(stage_temp_name)
        staged_paths: dict[str, Path] = {}
        for name in sorted(desired_names, key=lambda value: value.encode("utf-8")):
            package = desired.packages[name]
            if worktree_package_matches_desired(name, package):
                continue
            staged_path = stage_root / name
            materialize_package(package, staged_path)
            staged_paths[name] = staged_path

        lock_already_desired = False
        if LOCK_PATH.exists() and not LOCK_PATH.is_symlink():
            lock_info = os.lstat(LOCK_PATH)
            lock_already_desired = (
                stat.S_ISREG(lock_info.st_mode)
                and stat.S_IMODE(lock_info.st_mode) == 0o644
                and LOCK_PATH.read_bytes() == desired_lock_bytes
            )
        readme_already_desired = False
        if README_PATH.exists() and not README_PATH.is_symlink():
            readme_info = os.lstat(README_PATH)
            readme_already_desired = (
                stat.S_ISREG(readme_info.st_mode)
                and stat.S_IMODE(readme_info.st_mode) == 0o644
                and README_PATH.read_bytes() == desired_readme_bytes
            )
        if not staged_paths and not delete_names and lock_already_desired and readme_already_desired:
            validate_r04_live_state(manifest, desired, desired_readme_bytes, retained_layout)
            return

        apply_update_transaction(
            staged_paths,
            delete_names,
            desired_lock_bytes,
            full_readme_bytes_from_layout(retained_layout),
            desired_readme_bytes,
            lambda: validate_r04_live_state(manifest, desired, desired_readme_bytes, retained_layout),
        )


def load_r01_validated_state() -> tuple[Manifest, LockState, Manifest, LockState]:
    manifest = load_manifest()
    lock = load_lock(manifest)
    previous_manifest = load_trusted_previous_manifest()
    previous_lock = load_trusted_previous_lock(previous_manifest)
    validate_stable_identity_continuity(previous_manifest, manifest)
    return manifest, lock, previous_manifest, previous_lock


def load_update_authority_state() -> tuple[Manifest, Manifest, LockState]:
    manifest = load_manifest()
    previous_manifest = load_trusted_previous_manifest()
    previous_lock = load_trusted_previous_lock(previous_manifest)
    validate_stable_identity_continuity(previous_manifest, manifest)
    return manifest, previous_manifest, previous_lock


def mode_update() -> None:
    manifest, previous_manifest, previous_lock = load_update_authority_state()
    retained_layout = read_readme_layout()
    with tempfile.TemporaryDirectory(prefix="federation-r04-update-") as temp_name:
        network_root = Path(temp_name)
        if manifest.sources:
            bound_sources, discovered = discover_manifest_skills(
                network_root,
                manifest,
                previous_manifest,
            )
        else:
            bound_sources, discovered = {}, ()
        desired = build_desired_publication_state(
            network_root,
            manifest,
            previous_manifest,
            previous_lock,
            bound_sources,
            discovered,
        )
        managed_content = render_converged_catalog_content(manifest, desired.lock, desired.packages)
        desired_readme_bytes = render_full_readme(retained_layout, managed_content)
        desired_layout = parse_readme_layout_bytes(desired_readme_bytes)
        validate_readme_catalog(manifest, desired.lock, desired.packages, desired_layout)
        apply_r04_desired_state(manifest, desired, retained_layout, desired_readme_bytes)


def verify_published_upstream(initial_proof: CommittedLocalProof) -> None:
    source_ids = sorted(
        {entry.source_id for entry in initial_proof.lock.skills.values()},
        key=lambda value: value.encode("utf-8"),
    )
    with tempfile.TemporaryDirectory(prefix="federation-r05-verify-") as temp_name:
        network_root = Path(temp_name)
        for source_id in source_ids:
            source = initial_proof.manifest.by_source_id.get(source_id)
            if source is None:
                fail(f"published lock owner disappeared from committed manifest: {source_id}")
            bound_source = bind_source_snapshot(network_root, source)
            owned_names = sorted(
                [name for name, entry in initial_proof.lock.skills.items() if entry.source_id == source_id],
                key=lambda value: value.encode("utf-8"),
            )
            for name in owned_names:
                entry = initial_proof.lock.skills[name]
                if not skill_matches_source_prefix(source, name):
                    fail(f"published lock skill no longer matches accepted source prefix: {name}")
                access = retrieve_historical_commit(network_root, bound_source, entry.resolved_commit)
                if access.result is HistoricalCommitResult.DEFINITIVELY_MISSING:
                    fail(f"published locked commit is definitively missing from accepted repository: {name}")
                if access.result is HistoricalCommitResult.AMBIGUOUS_FAIL:
                    fail(f"published locked commit retrieval is ambiguous: {name}")
                if access.result is not HistoricalCommitResult.RETRIEVED or access.path is None:
                    fail(f"published locked commit retrieval did not produce usable repository state: {name}")
                upstream = enumerate_git_package(
                    access.path,
                    entry.resolved_commit,
                    f"{source.skills_root}/{name}",
                    name,
                    source_workspace=True,
                )
                if upstream.digest != entry.content_sha256:
                    fail(f"locked upstream package digest mismatch: {name}")
                committed = initial_proof.committed_packages.get(name)
                if committed is None or not packages_equivalent(upstream, committed):
                    fail(f"committed central package differs from exact locked upstream package: {name}")


def mode_check_local() -> None:
    prove_committed_local_state()


def mode_verify_upstream() -> None:
    initial_proof = prove_committed_local_state()
    verify_published_upstream(initial_proof)
    final_proof = prove_committed_local_state()
    if final_proof.head_commit != initial_proof.head_commit:
        fail("HEAD changed during upstream verification")
    if final_proof.manifest != initial_proof.manifest or final_proof.lock != initial_proof.lock:
        fail("committed manifest/lock authority changed during upstream verification")
    if final_proof.readme_bytes != initial_proof.readme_bytes:
        fail("committed README authority changed during upstream verification")
    if final_proof.committed_packages != initial_proof.committed_packages:
        fail("committed package authority changed during upstream verification")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Federate source-owned Agent Skills into this central collection.")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--update", action="store_true", help="Resolve sources and update generated packages/lock/catalog.")
    modes.add_argument("--check-local", action="store_true", help="Validate committed local generated state against the lock.")
    modes.add_argument("--verify-upstream", action="store_true", help="Verify committed generated state against locked upstream commits.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.update:
            mode_update()
        elif args.check_local:
            mode_check_local()
        elif args.verify_upstream:
            mode_verify_upstream()
        else:
            fail("no federation mode selected")
        return 0
    except FederationError as error:
        print(f"federate: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"federate: filesystem/process error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("federate: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
