"""Disposable synthetic workspaces built from trusted Git and allowlisted data."""

from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from scripts import federate as c02

SHA40 = r"^[0-9a-f]{40}$"
_ALLOWED_MODES = {"100644", "100755"}
TRUSTED_GIT_PATH = Path("/usr/bin/git")
TRUSTED_TEMP_BASE = Path("/tmp")
_TRUSTED_GIT_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "TZ": "UTC",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": "/dev/null",
}
_COMMIT_METADATA_KEYS = (
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_DATE",
)
_ALLOWED_GIT_COMMANDS = {
    "--version",
    "check-ref-format",
    "diff",
    "ls-tree",
    "show",
    "init",
    "archive",
    "add",
    "write-tree",
    "commit-tree",
    "checkout",
}


class WorkspaceError(RuntimeError):
    pass


@dataclass(frozen=True)
class CandidateDiffEntry:
    path: str
    mode: str | None
    status: str


@dataclass
class SyntheticWorkspace:
    root: Path
    synthetic_commit: str
    tree: str
    candidate_entries: tuple[CandidateDiffEntry, ...]
    _real_repository: Path
    _disposable_root: Path
    _trusted_temp_base: Path
    _disposable_identity: tuple[int, int]

    def cleanup(self) -> None:
        if not _safe_owned_disposable_root(
            self._disposable_root,
            self._trusted_temp_base,
            self._real_repository,
            self._disposable_identity,
        ):
            return
        shutil.rmtree(self._disposable_root, ignore_errors=True)

    def __enter__(self) -> "SyntheticWorkspace":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.cleanup()


def _assert_safe_git_environment() -> None:
    inherited_git_keys = sorted(key for key in os.environ if key.startswith("GIT_"))
    if inherited_git_keys:
        raise WorkspaceError(
            "inherited Git environment is forbidden: " + ", ".join(inherited_git_keys)
        )


def _sha(value: str, label: str) -> str:
    if type(value) is not str or len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
        raise WorkspaceError(f"{label} must be lowercase 40-hex")
    return value


def _verified_trusted_git() -> Path:
    configured = TRUSTED_GIT_PATH
    if configured != Path("/usr/bin/git") or not configured.is_absolute():
        raise WorkspaceError("trusted Git executable configuration is invalid")
    try:
        resolved = configured.resolve(strict=True)
        info = resolved.stat()
    except OSError:
        raise WorkspaceError("trusted Git executable cannot be resolved") from None
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise WorkspaceError("trusted Git executable is not a regular executable file")
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise WorkspaceError("trusted Git executable ownership or mode is unsafe")
    return resolved


def _trusted_child_environment(commit_metadata: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = dict(_TRUSTED_GIT_ENV)
    if commit_metadata is None:
        return environment
    if not isinstance(commit_metadata, Mapping):
        raise WorkspaceError("commit metadata must be a mapping")
    for key in ("author", "email", "timestamp"):
        if type(commit_metadata.get(key, "")) is not str:
            raise WorkspaceError(f"commit metadata {key} must be a string")
    author = commit_metadata.get("author", "Swift Stream Federation")
    email = commit_metadata.get("email", "automation@swiftstream.invalid")
    timestamp = commit_metadata.get("timestamp", "2000-01-01T00:00:00Z")
    environment.update(
        {
            "GIT_AUTHOR_NAME": author,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": author,
            "GIT_COMMITTER_EMAIL": email,
            "GIT_AUTHOR_DATE": timestamp,
            "GIT_COMMITTER_DATE": timestamp,
        }
    )
    return environment


def _run_trusted_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    text: bool = True,
    check: bool = True,
    input_data: bytes | str | None = None,
    commit_metadata: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[object]:
    if not args or args[0] not in _ALLOWED_GIT_COMMANDS:
        raise WorkspaceError("Git command is not allowlisted")
    if (args[0] == "commit-tree") != (commit_metadata is not None):
        raise WorkspaceError("commit metadata is valid only for commit-tree")
    executable = _verified_trusted_git()
    argv = [str(executable), "-c", "core.hooksPath=/dev/null", "-c", "init.templateDir=", *args]
    try:
        result = subprocess.run(
            argv,
            cwd=str(cwd) if cwd is not None else None,
            env=_trusted_child_environment(commit_metadata),
            input=input_data,
            stdin=subprocess.DEVNULL if input_data is None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=text,
            shell=False,
            check=False,
        )
    except (OSError, ValueError, TypeError) as error:
        raise WorkspaceError(f"trusted Git execution failed: {type(error).__name__}") from None
    if check and result.returncode != 0:
        stderr = result.stderr if text else bytes(result.stderr or b"").decode("utf-8", errors="replace")
        detail = f": {str(stderr).strip()}" if stderr else ""
        raise WorkspaceError(f"command failed ({' '.join(argv[:3])}){detail}")
    return result


def _git(repo: Path, args: list[str], *, text: bool = True, check: bool = True) -> subprocess.CompletedProcess[object]:
    _assert_safe_git_environment()
    return _run_trusted_git(args, cwd=repo, text=text, check=check)


def validate_trusted_ref(value: object) -> str:
    if type(value) is not str or not value:
        c02.fail("ref must be a nonempty string")
    if c02.contains_control(value):
        c02.fail(f"ref contains a control character: {value!r}")
    if not value.startswith("refs/heads/") or value == "refs/heads/":
        c02.fail(f"ref must be a full branch ref under refs/heads/**: {value!r}")
    result = _run_trusted_git(["check-ref-format", value], check=False)
    if result.returncode != 0:
        c02.fail(f"Git rejects configured ref spelling: {value!r}")
    return value


def _resolve_trusted_temp_base(repository: Path) -> Path:
    configured = TRUSTED_TEMP_BASE
    if configured != Path("/tmp") or not configured.is_absolute():
        raise WorkspaceError("trusted temp base configuration is invalid")
    try:
        base = configured.resolve(strict=True)
        repo = repository.resolve(strict=True)
    except OSError:
        raise WorkspaceError("trusted temp base cannot be resolved") from None
    if not base.is_dir() or base == repo or base in repo.parents or repo in base.parents:
        raise WorkspaceError("trusted temp base is unsafe for the real repository")
    return base


def _safe_owned_disposable_root(
    root: Path,
    trusted_base: Path,
    real_repository: Path,
    identity: tuple[int, int],
) -> bool:
    if not _cleanup_eligible_disposable_root(root, trusted_base, real_repository, identity):
        return False
    try:
        info = root.lstat()
    except OSError:
        return False
    return not (info.st_mode & 0o077)


def _cleanup_eligible_disposable_root(
    root: Path,
    trusted_base: Path,
    real_repository: Path,
    identity: tuple[int, int],
) -> bool:
    """Prove that *root* is the exact owned direct child safe to remove."""
    try:
        base = trusted_base.resolve(strict=True)
        repository = real_repository.resolve(strict=True)
        info = root.lstat()
        resolved_root = root.resolve(strict=True)
    except OSError:
        return False
    if not stat.S_ISDIR(info.st_mode):
        return False
    if (info.st_dev, info.st_ino) != identity or resolved_root != root:
        return False
    if root.parent != base or root == repository or root in repository.parents or repository in root.parents:
        return False
    if info.st_uid != os.geteuid():
        return False
    return True


def _create_disposable_root(repository: Path, trusted_base: Path) -> tuple[Path, tuple[int, int]]:
    try:
        root = Path(tempfile.mkdtemp(prefix="swiftstream-federation-workspace-", dir=str(trusted_base)))
        info = root.lstat()
    except (OSError, ValueError):
        raise WorkspaceError("trusted disposable workspace root could not be created") from None
    identity = (info.st_dev, info.st_ino)
    if not _safe_owned_disposable_root(root, trusted_base, repository, identity):
        if _cleanup_eligible_disposable_root(root, trusted_base, repository, identity):
            shutil.rmtree(root, ignore_errors=True)
        raise WorkspaceError("trusted disposable workspace root failed validation")
    return root, identity


def _path_safe(path: str) -> bool:
    return bool(path) and not path.startswith("/") and "\\" not in path and "\x00" not in path and all(part not in {"", ".", ".."} for part in path.split("/"))


def _parse_ls_tree(raw: bytes) -> dict[str, tuple[str, str]]:
    result: dict[str, tuple[str, str]] = {}
    for record in raw.split(b"\0"):
        if not record:
            continue
        try:
            header, path_bytes = record.split(b"\t", 1)
            mode, object_type, _object_id = header.decode("ascii").split(" ", 2)
            path = path_bytes.decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise WorkspaceError("candidate tree has malformed entry") from None
        if not _path_safe(path):
            raise WorkspaceError("candidate tree contains unsafe path")
        result[path] = (mode, object_type)
    return result


def inspect_candidate_diff(repository: Path, accepted_base: str, candidate_head: str) -> tuple[CandidateDiffEntry, ...]:
    base = _sha(accepted_base, "accepted base")
    head = _sha(candidate_head, "candidate head")
    names = _git(repository, ["diff", "--name-status", "--no-renames", "-z", base, head], text=False).stdout
    entries: list[CandidateDiffEntry] = []
    records = bytes(names).split(b"\0")
    index = 0
    candidate_tree = _parse_ls_tree(bytes(_git(repository, ["ls-tree", "-r", "-z", "--full-tree", head], text=False).stdout))
    while index < len(records):
        if not records[index]:
            index += 1
            continue
        try:
            if b"\t" in records[index]:
                status, path_bytes = records[index].split(b"\t", 1)
                index += 1
            else:
                status = records[index]
                if index + 1 >= len(records):
                    raise ValueError
                path_bytes = records[index + 1]
                index += 2
            path = path_bytes.decode("utf-8")
            status_text = status.decode("ascii")
        except (ValueError, UnicodeDecodeError):
            raise WorkspaceError("candidate diff has malformed entry") from None
        if len(status_text) != 1 or not _path_safe(path):
            raise WorkspaceError("candidate diff has an unsafe status or path")
        mode = candidate_tree.get(path, (None, ""))[0]
        entries.append(CandidateDiffEntry(path, mode, status_text))
    for entry in entries:
        if entry.path == ".github" or entry.path.startswith(".github/"):
            raise WorkspaceError("candidate .github data is never trusted or materialized")
        if entry.status != "D" and entry.mode not in _ALLOWED_MODES:
            raise WorkspaceError(f"candidate path {entry.path!r} has forbidden mode {entry.mode!r}")
    return tuple(sorted(entries, key=lambda item: item.path))


def _safe_extract_archive(raw: bytes, destination: Path) -> None:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
    except tarfile.TarError:
        raise WorkspaceError("trusted base archive is malformed") from None
    with archive:
        for member in archive.getmembers():
            target = destination / member.name
            try:
                target.relative_to(destination)
            except ValueError:
                raise WorkspaceError("trusted base archive contains unsafe path") from None
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                data = archive.extractfile(member)
                if data is None:
                    raise WorkspaceError("trusted base archive file cannot be read")
                target.write_bytes(data.read())
                target.chmod(stat.S_IMODE(member.mode) or 0o644)
            else:
                raise WorkspaceError("trusted base archive contains non-regular entry")


def _overlay_candidate(repository: Path, candidate: str, path: str, destination: Path) -> None:
    result = _git(repository, ["show", f"{candidate}:{path}"], text=False)
    target = destination / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(bytes(result.stdout))


def _commit_tree_deterministically(workspace: Path, metadata: Mapping[str, str]) -> tuple[str, str]:
    tree_result = _git(workspace, ["add", "--all"], text=True)
    del tree_result
    tree = str(_git(workspace, ["write-tree"], text=True).stdout).strip()
    message = metadata.get("message", "Swift Stream federation synthetic workspace\n")
    author = metadata.get("author", "Swift Stream Federation")
    email = metadata.get("email", "automation@swiftstream.invalid")
    timestamp = metadata.get("timestamp", "2000-01-01T00:00:00Z")
    result = _run_trusted_git(
        ["commit-tree", tree],
        cwd=workspace,
        text=False,
        check=False,
        input_data=message.encode("utf-8"),
        commit_metadata={"author": author, "email": email, "timestamp": timestamp},
    )
    if result.returncode != 0:
        raise WorkspaceError("synthetic commit creation failed")
    commit = result.stdout.decode("ascii", errors="strict").strip()
    if len(commit) != 40 or any(char not in "0123456789abcdef" for char in commit):
        raise WorkspaceError("synthetic commit identity is invalid")
    _git(workspace, ["checkout", "--detach", commit], text=True)
    return tree, commit


def create_synthetic_workspace(
    repository: Path,
    accepted_base: str,
    candidate_head: str,
    allowlisted_paths: Iterable[str],
    metadata: Mapping[str, str] | None = None,
) -> SyntheticWorkspace:
    base = _sha(accepted_base, "accepted base")
    candidate = _sha(candidate_head, "candidate head")
    try:
        repository = repository.resolve(strict=True)
    except OSError:
        raise WorkspaceError("repository must be an existing local Git repository") from None
    _assert_safe_git_environment()
    if not repository.is_dir() or not (repository / ".git").exists():
        raise WorkspaceError("repository must be an existing local Git repository")
    allowed = set(allowlisted_paths)
    if any(not _path_safe(path) or path == ".github" or path.startswith(".github/") for path in allowed):
        raise WorkspaceError("allowlisted path is unsafe")
    entries = inspect_candidate_diff(repository, base, candidate)
    changed = {entry.path for entry in entries}
    if not changed <= allowed:
        raise WorkspaceError("candidate changed a path outside the caller allowlist")
    trusted_base = _resolve_trusted_temp_base(repository)
    parent, parent_identity = _create_disposable_root(repository, trusted_base)
    workspace = parent / "worktree"
    try:
        workspace.mkdir()
        _git(workspace, ["init", "--quiet"], text=True)
        archive = _git(repository, ["archive", base], text=False)
        _safe_extract_archive(bytes(archive.stdout), workspace)
        for entry in entries:
            if entry.status != "D":
                _overlay_candidate(repository, candidate, entry.path, workspace)
                (workspace / entry.path).chmod(0o755 if entry.mode == "100755" else 0o644)
            elif (workspace / entry.path).exists():
                (workspace / entry.path).unlink()
        tree, commit = _commit_tree_deterministically(workspace, metadata or {})
        return SyntheticWorkspace(workspace, commit, tree, entries, repository, parent, trusted_base, parent_identity)
    except Exception:
        if _safe_owned_disposable_root(parent, trusted_base, repository, parent_identity):
            shutil.rmtree(parent, ignore_errors=True)
        raise
