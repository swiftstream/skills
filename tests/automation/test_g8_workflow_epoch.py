from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
FEDERATION_PYTHON = ROOT / "automation" / "federation"

OLD_WRITER_PATHS = (
    ".github/workflows/federation-interactive.yml",
    ".github/workflows/federation-trusted-validation.yml",
    ".github/workflows/federation-state-finalize.yml",
    ".github/workflows/federation-main-advance.yml",
    ".github/workflows/federation-reconcile.yml",
)
NEW_WRITER_PATHS = (
    ".github/workflows/federation-g8-issue-intake.yml",
    ".github/workflows/federation-g8-interactive.yml",
    ".github/workflows/federation-g8-trusted-validation.yml",
    ".github/workflows/federation-g8-state-finalize.yml",
    ".github/workflows/federation-g8-main-advance.yml",
    ".github/workflows/federation-g8-reconcile.yml",
)
CONTRACT_PATH = ".github/federation/g8-activation-contract.json"
MANIFEST_PATH = ".github/federation/g8-authority-surface.json"
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
APP_TOKEN_ACTION = "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1"
MANUAL_AUTHORITY_GROUP = "swiftstream-skills-federation-manual-authority"
TRUSTED_VALIDATION_GROUP = (
    "swiftstream-skills-federation-trusted-validation-"
    + "$"
    + "{{ github.event.pull_request.number || inputs.pull_number }}"
)
EXPECTED_CONTRACT_KEYS = {
    "activationRef",
    "activationStatusContext",
    "authoritySurfaceManifestPath",
    "baseRef",
    "centralRepositoryNodeId",
    "contractVersion",
    "exactNewWriterPaths",
    "implementationHeadRef",
    "implementationPrDatabaseId",
    "implementationPrNodeId",
    "implementationPrNumber",
    "predecessorImplementationPrDatabaseId",
    "predecessorImplementationPrNodeId",
    "predecessorImplementationPrNumber",
    "predecessorMergedResultOid",
    "predecessorReviewedHeadSha",
    "schemaVersion",
}
EXPECTED_MANIFEST_PATHS = (
    ".github/federation/g8-activation-contract.json",
    ".github/federation/g8-authority-surface.json",
    ".github/workflows/federation-g8-interactive.yml",
    ".github/workflows/federation-g8-issue-intake.yml",
    ".github/workflows/federation-g8-main-advance.yml",
    ".github/workflows/federation-g8-reconcile.yml",
    ".github/workflows/federation-g8-state-finalize.yml",
    ".github/workflows/federation-g8-trusted-validation.yml",
    "automation/federation/__init__.py",
    "automation/federation/controller.py",
    "automation/federation/github_api.py",
    "automation/federation/request_model.py",
    "automation/federation/workspace.py",
    "scripts/federate.py",
)

EXPECTED_TRIGGERS = {
    "federation-g8-issue-intake.yml": """on:
  issues:
    types: [opened, edited, reopened, closed]
  issue_comment:
    types: [created]
  pull_request_target:
    types: [closed]
  workflow_dispatch:
    inputs:
      issue_number:
        required: false
        type: number
  schedule:
    - cron: '2,17,32,47 * * * *'""",
    "federation-g8-interactive.yml": """on:
  pull_request_target:
    types: [opened, reopened, synchronize, edited]
  issue_comment:
    types: [created]
  workflow_dispatch:
    inputs:
      pull_number:
        required: true
        type: number""",
    "federation-g8-trusted-validation.yml": """on:
  pull_request_target:
    types: [opened, reopened, synchronize]
  workflow_dispatch:
    inputs:
      pull_number:
        required: true
        type: number""",
    "federation-g8-state-finalize.yml": """on:
  workflow_dispatch:
    inputs:
      pull_number:
        required: false
        type: number
      expected_source_id:
        required: false
        type: string""",
    "federation-g8-main-advance.yml": """on:
  push:
    branches: [main]""",
    "federation-g8-reconcile.yml": """on:
  schedule:
    - cron: '7,22,37,52 * * * *'
  workflow_dispatch:
    inputs:
      mode:
        required: true
        type: choice
        options:
          - recover
          - activate-g8
      repository_id:
        required: false
        type: string""",
}

# This mirrors the frozen Wave12 Task01 guard transport. The $ placeholders are
# replaced with a literal dollar sign after the test file is written.
FROZEN_GUARD_WRAPPER = r"""set -euo pipefail
guard_stdout="${RUNNER_TEMP}/g8-wave12-activation-guard.out"
: > "${guard_stdout}"
PYTHONDONTWRITEBYTECODE=1 python3 -B -m automation.federation.controller activation-guard > "${guard_stdout}"
python3 - "${guard_stdout}" "${GITHUB_OUTPUT}" <<'PY'
import json
import pathlib
import sys

def reject_constant(value):
    raise ValueError(f"non-standard JSON constant: {value}")

def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result

raw = pathlib.Path(sys.argv[1]).read_bytes()
if not raw or raw.count(b"\n") != 1 or not raw.endswith(b"\n") or b"\r" in raw:
    raise SystemExit("invalid activation guard framing")

body = raw[:-1]
try:
    text = body.decode("utf-8")
except UnicodeDecodeError as exc:
    raise SystemExit("invalid activation guard utf8") from exc

try:
    value = json.loads(
        text,
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
except (json.JSONDecodeError, ValueError) as exc:
    raise SystemExit("invalid activation guard json") from exc

expected_keys = {
    "activationWriteAllowed",
    "ordinaryWriteAllowed",
    "reason",
    "runtimeState",
}
if type(value) is not dict or set(value) != expected_keys:
    raise SystemExit("invalid activation guard shape")

if type(value["activationWriteAllowed"]) is not bool:
    raise SystemExit("invalid activationWriteAllowed type")
if type(value["ordinaryWriteAllowed"]) is not bool:
    raise SystemExit("invalid ordinaryWriteAllowed type")
if type(value["reason"]) is not str:
    raise SystemExit("invalid reason type")
if type(value["runtimeState"]) is not str:
    raise SystemExit("invalid runtimeState type")

allowed = {
    "ACTIVE_G8": (True, False, "ACTIVE_G8_EPOCH_PROVEN"),
    "MERGED_UNPROVEN": (False, True, "MERGED_UNPROVEN_NO_VALID_EPOCH"),
    "BLOCKED_POST_MERGE": (False, False, "BLOCKED_POST_MERGE_CONFLICT"),
    "PRE_G8_NOT_APPLICABLE": (False, False, "PRE_G8_NOT_APPLICABLE"),
}
runtime_state = value["runtimeState"]
if runtime_state not in allowed:
    raise SystemExit("unexpected activation guard runtime state")
ordinary_expected, activation_expected, reason_expected = allowed[runtime_state]
if value["ordinaryWriteAllowed"] is not ordinary_expected:
    raise SystemExit("ordinaryWriteAllowed does not match runtime state")
if value["activationWriteAllowed"] is not activation_expected:
    raise SystemExit("activationWriteAllowed does not match runtime state")
if value["reason"] != reason_expected:
    raise SystemExit("activation guard reason does not match runtime state")

canonical = (
    json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    + b"\n"
)
if canonical != raw:
    raise SystemExit("non-canonical activation guard bytes")

with pathlib.Path(sys.argv[2]).open("a", encoding="utf-8", newline="\n") as output:
    output.write("runtime_state=" + value["runtimeState"] + "\n")
    output.write("ordinary_write_allowed=" + ("true" if value["ordinaryWriteAllowed"] else "false") + "\n")
    output.write("activation_write_allowed=" + ("true" if value["activationWriteAllowed"] else "false") + "\n")
PY
"""


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def _line_body(line: str) -> str:
    return line[:-1] if line.endswith("\n") else line


def scan_workflow_top_level_keys(raw: bytes) -> tuple[tuple[str, int], ...]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AssertionError("workflow is not strict UTF-8") from exc
    if b"\r" in raw:
        raise AssertionError("workflow contains CR")
    if b"\t" in raw:
        raise AssertionError("workflow contains TAB")

    found: list[tuple[str, int]] = []
    seen: set[str] = set()
    for number, source_line in enumerate(text.splitlines(keepends=True), start=1):
        line = _line_body(source_line)
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0].isspace():
            continue
        if ":" not in line:
            raise AssertionError(f"non-mapping column-zero line {number}")
        source_key = line.split(":", 1)[0]
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", source_key):
            raise AssertionError(f"non-bare top-level key on line {number}")
        if source_key in seen:
            raise AssertionError(f"duplicate top-level key {source_key!r}")
        seen.add(source_key)
        found.append((source_key, number))
    return tuple(found)


def extract_exact_on_block(raw: bytes) -> str:
    text = raw.decode("utf-8", errors="strict")
    top_keys = scan_workflow_top_level_keys(raw)
    on_lines = [number for key, number in top_keys if key == "on"]
    if len(on_lines) != 1:
        raise AssertionError("semantic on key must occur exactly once")

    lines = text.splitlines(keepends=True)
    start = on_lines[0] - 1
    if _line_body(lines[start]) != "on:":
        raise AssertionError("semantic on source line must equal exact on:")
    end = len(lines)
    for index in range(start + 1, len(lines)):
        line = _line_body(lines[index])
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            end = index
            break

    while end > start + 1 and not _line_body(lines[end - 1]).strip():
        end -= 1
    block = "".join(lines[start:end])
    if not block.endswith("\n"):
        block += "\n"
    return block


def validate_trigger_contract(raw: bytes, filename: str) -> None:
    if filename not in EXPECTED_TRIGGERS:
        raise AssertionError("unknown workflow")
    block = extract_exact_on_block(raw)
    expected = EXPECTED_TRIGGERS[filename] + "\n"
    if block != expected:
        raise AssertionError("workflow on block differs from frozen canonical block")


def _full_workflow(trigger_block: str) -> str:
    return trigger_block + "\n\npermissions:\n  contents: read\n\njobs:\n  noop:\n    runs-on: ubuntu-latest\n"


def _replace_once(text: str, old: str, new: str) -> str:
    if text.count(old) != 1:
        raise AssertionError(f"mutation anchor is not unique: {old!r}")
    return text.replace(old, new, 1)


def _trigger_mutations() -> tuple[tuple[str, str, str, str], ...]:
    w1 = EXPECTED_TRIGGERS["federation-g8-issue-intake.yml"]
    w2 = EXPECTED_TRIGGERS["federation-g8-interactive.yml"]
    w3 = EXPECTED_TRIGGERS["federation-g8-trusted-validation.yml"]
    w4 = EXPECTED_TRIGGERS["federation-g8-state-finalize.yml"]
    w5 = EXPECTED_TRIGGERS["federation-g8-main-advance.yml"]
    w6 = EXPECTED_TRIGGERS["federation-g8-reconcile.yml"]

    def mutate(block: str, old: str, new: str, filename: str) -> tuple[str, str, str, str]:
        return filename, block, old, new

    cases: list[tuple[str, str, str, str, str]] = []

    def add(case_id: str, filename: str, block: str, old: str, new: str) -> None:
        cases.append((case_id, filename, block, old, new))

    add("T01", "federation-g8-issue-intake.yml", w1, "[opened, edited, reopened, closed]", "[opened, edited, reopened, closed, labeled]")
    add("T02", "federation-g8-issue-intake.yml", w1, "[opened, edited, reopened, closed]", "[opened, edited, reopened, closed, deleted]")
    add("T03", "federation-g8-issue-intake.yml", w1, "  pull_request_target:\n    types: [closed]", "  pull_request_target:\n    types: [closed, synchronize]")
    add("T04", "federation-g8-issue-intake.yml", w1, "  issue_comment:\n    types: [created]", "  issue_comment:\n    types: [created]\n  pull_request:\n    types: [opened]")
    add("T05", "federation-g8-issue-intake.yml", w1, "      issue_number:\n        required: false\n        type: number", "      issue_number:\n        required: false\n        type: number\n      repository_id:\n        required: false\n        type: string")
    add("T06", "federation-g8-issue-intake.yml", w1, "'2,17,32,47 * * * *'", "'2,12,22,32,42,52 * * * *'")
    add("T07", "federation-g8-interactive.yml", w2, "[opened, reopened, synchronize, edited]", "[opened, reopened, synchronize, edited, ready_for_review]")
    add("T08", "federation-g8-interactive.yml", w2, "  issue_comment:\n    types: [created]", "  issue_comment:\n    types: [created]\n  pull_request:\n    types: [opened]")
    add("T09", "federation-g8-interactive.yml", w2, "        type: number", "        type: number\n      mode:\n        required: false\n        type: string")
    add("T10", "federation-g8-interactive.yml", w2, "[opened, reopened, synchronize, edited]", "[opened, reopened, synchronize]")
    add("T11", "federation-g8-trusted-validation.yml", w3, "[opened, reopened, synchronize]", "[opened, reopened, synchronize, edited]")
    add("T12", "federation-g8-trusted-validation.yml", w3, "  workflow_dispatch:", "  issue_comment:\n    types: [created]\n  workflow_dispatch:")
    add("T13", "federation-g8-trusted-validation.yml", w3, "        type: number", "        type: number\n      expected_source_id:\n        required: false\n        type: string")
    add("T14", "federation-g8-state-finalize.yml", w4, "  workflow_dispatch:", "  schedule:\n    - cron: '0 * * * *'\n  workflow_dispatch:")
    add("T15", "federation-g8-state-finalize.yml", w4, "  workflow_dispatch:", "  pull_request_target:\n    types: [closed]\n  workflow_dispatch:")
    add("T16", "federation-g8-state-finalize.yml", w4, "      expected_source_id:\n        required: false\n        type: string", "      expected_source_id:\n        required: false\n        type: string\n      mode:\n        required: false\n        type: string")
    add("T17", "federation-g8-main-advance.yml", w5, "on:\n  push:", "on:\n  workflow_dispatch:\n  push:")
    add("T18", "federation-g8-main-advance.yml", w5, "branches: [main]", "branches: [main, develop]")
    add("T19", "federation-g8-main-advance.yml", w5, "  push:\n    branches: [main]", "  push:\n    branches: [main]\n    paths: ['**']")
    add("T20", "federation-g8-main-advance.yml", w5, "  push:\n    branches: [main]", "  push:\n    branches: [main]\n    paths-ignore: ['**']")
    add("T21", "federation-g8-main-advance.yml", w5, "branches: [main]", "branches: [main, release]")
    add("T22", "federation-g8-reconcile.yml", w6, "    - cron: '7,22,37,52 * * * *'", "    - cron: '7,22,37,52 * * * *'\n    - cron: '0 * * * *'")
    add("T23", "federation-g8-reconcile.yml", w6, "'7,22,37,52 * * * *'", "'0,15,30,45 * * * *'")
    add("T24", "federation-g8-reconcile.yml", w6, "  workflow_dispatch:", "  push:\n    branches: [main]\n  workflow_dispatch:")
    add("T25", "federation-g8-reconcile.yml", w6, "          - activate-g8", "          - activate-g8\n          - dry-run")
    add("T26", "federation-g8-reconcile.yml", w6, "      repository_id:\n", "      mode:\n        default: activate-g8\n      repository_id:\n")
    add("T27", "federation-g8-reconcile.yml", w6, "      repository_id:\n", "      pull_number:\n        required: false\n        type: number\n      repository_id:\n")
    add("T28", "federation-g8-issue-intake.yml", w1, "  issue_comment:\n    types: [created]", "  issue_comment:\n    types: [created]\n  issue_comment:\n    types: [created]")
    add("T29", "federation-g8-issue-intake.yml", w1, "on:\n", "on:\n")
    add("T30", "federation-g8-issue-intake.yml", w1, "on:\n", "on: &trigger\n")
    add("T31", "federation-g8-issue-intake.yml", w1, "on:\n", "on:\n  <<: *defaults\n")
    add("T32", "federation-g8-issue-intake.yml", w1, "[opened, edited, reopened, closed]", "[opened, edited, reopened, closed, '*']")

    # Correction 02 whole-workflow top-level source-spelling cases.
    add("T33", "federation-g8-issue-intake.yml", w1, "on:\n", "on:\n")
    add("T34", "federation-g8-issue-intake.yml", w1, "on:\n", "\"on\":\n")
    add("T35", "federation-g8-issue-intake.yml", w1, "on:\n", "'on':\n")
    add("T36", "federation-g8-issue-intake.yml", w1, "on:\n", "on :\n")
    add("T37", "federation-g8-issue-intake.yml", w1, "on:\n", "on: {}\n")
    add("T38", "federation-g8-issue-intake.yml", w1, "on:\n", "on: []\n")
    add("T39", "federation-g8-issue-intake.yml", w1, "on:\n", "on: &trigger\n")
    add("T40", "federation-g8-issue-intake.yml", w1, "on:\n", "? on\n")
    add("T41", "federation-g8-issue-intake.yml", w1, "jobs:\n", "jobs:\n")
    add("T42", "federation-g8-issue-intake.yml", w1, "jobs:\n", "\"jobs\":\n")
    add("T43", "federation-g8-issue-intake.yml", w1, "permissions:\n", "<<:\npermissions:\n")
    add("T44", "federation-g8-issue-intake.yml", w1, "jobs:\n", "\tjobs:\n")

    results: list[tuple[str, str, str]] = []
    for case_id, filename, block, old, new in cases:
        if case_id in {"T29", "T33"}:
            candidate = _full_workflow(block) + "\non: # duplicate\n  push:\n    branches: [main]\n"
        elif case_id == "T41":
            candidate = _full_workflow(block) + "\njobs:\n  duplicate: {}\n"
        elif case_id == "T43":
            candidate = _replace_once(_full_workflow(block), "permissions:\n", "<<:\npermissions:\n")
        elif case_id == "T44":
            candidate = _replace_once(_full_workflow(block), "jobs:\n", "\tjobs:\n")
        else:
            candidate = _replace_once(_full_workflow(block), old, new)
        results.append((case_id, filename, candidate))
    return tuple(results)


def _top_level_job_blocks(text: str) -> tuple[tuple[str, str], ...]:
    lines = text.splitlines(keepends=True)
    jobs_headers = [index for index, line in enumerate(lines) if _line_body(line) == "jobs:"]
    if len(jobs_headers) != 1:
        raise AssertionError("workflow must have exactly one jobs mapping")
    start = jobs_headers[0] + 1
    headers: list[tuple[int, str]] = []
    for index in range(start, len(lines)):
        body = _line_body(lines[index])
        if re.fullmatch(r"  [A-Za-z_][A-Za-z0-9_-]*:", body):
            headers.append((index, body.strip()[:-1]))
    if not headers:
        raise AssertionError("workflow has no top-level jobs")
    blocks: list[tuple[str, str]] = []
    for offset, (index, name) in enumerate(headers):
        end = headers[offset + 1][0] if offset + 1 < len(headers) else len(lines)
        blocks.append((name, "".join(lines[index:end])))
    return tuple(blocks)


def _extract_guard_wrapper(job_text: str) -> str:
    marker = "        name: Validate Wave12 activation guard output\n"
    if job_text.count(marker) != 1:
        raise AssertionError("activation guard parser step is not unique")
    after_marker = job_text.split(marker, 1)[1]
    run_prefix = (
        "        env:\n"
        "          FEDERATION_GITHUB_TOKEN: ${{ steps.guard-token.outputs.token }}\n"
        "          FEDERATION_APP_SLUG: ${{ steps.guard-token.outputs.app-slug }}\n"
        "          FEDERATION_TRUSTED_CHECKOUT_SHA: ${{ steps.trusted-checkout.outputs.sha }}\n"
        "        run: |\n"
    )
    if not after_marker.startswith(run_prefix):
        raise AssertionError("activation guard parser run block is ambiguous")
    remaining = after_marker[len(run_prefix):]
    collected: list[str] = []
    for line in remaining.splitlines(keepends=True):
        if line.strip() and len(line) - len(line.lstrip(" ")) < 10:
            break
        if line.strip() and not line.startswith(" " * 10):
            raise AssertionError("activation guard run indentation is ambiguous")
        collected.append(line[10:] if line.startswith(" " * 10) else line)
    wrapper = "".join(collected)
    if not wrapper:
        raise AssertionError("activation guard wrapper is empty")
    return wrapper


def _resolve_exact_module(module_name: str) -> tuple[bool, tuple[Path, ...]]:
    parts = module_name.split(".") if module_name else []
    if not parts:
        return False, ()

    module_path = ROOT.joinpath(*parts).with_suffix(".py")
    package_init = ROOT.joinpath(*parts, "__init__.py")
    module_exists = module_path.is_file()
    package_exists = package_init.is_file()
    if module_exists and package_exists:
        raise AssertionError(f"ambiguous repo-local module: {module_name}")
    local_directory = ROOT.joinpath(*parts).is_dir()
    local = module_exists or package_exists or local_directory
    if not local:
        # A partially-resolved repo-local prefix with a missing target is still an error.
        for depth in range(1, len(parts)):
            prefix = ROOT.joinpath(*parts[:depth])
            if prefix.is_dir() or prefix.with_suffix(".py").is_file():
                raise AssertionError(f"missing repo-local import target: {module_name}")
        return False, ()

    result: set[Path] = set()
    if module_exists:
        result.add(module_path)
        for depth in range(1, len(parts)):
            init = ROOT.joinpath(*parts[:depth], "__init__.py")
            if init.is_file():
                result.add(init)
    elif package_exists:
        result.add(package_init)
        for depth in range(1, len(parts)):
            init = ROOT.joinpath(*parts[:depth], "__init__.py")
            if init.is_file():
                result.add(init)
    # A namespace package has no file of its own. Existing parent initializers still execute.
    for depth in range(1, len(parts)):
        init = ROOT.joinpath(*parts[:depth], "__init__.py")
        if init.is_file():
            result.add(init)
    return True, tuple(sorted(result))


def _resolve_import_from(node: ast.ImportFrom, current_path: Path) -> tuple[Path, ...]:
    if node.level:
        current_module_parts = list(current_path.relative_to(ROOT).with_suffix("").parts)
        if current_module_parts and current_module_parts[-1] == "__init__":
            current_module_parts.pop()
        else:
            current_module_parts.pop()
        package_parts = current_module_parts
        trim = node.level - 1
        if trim > len(package_parts):
            raise AssertionError("relative import escapes repository package")
        base_parts = package_parts[: len(package_parts) - trim]
        if node.module:
            base_parts.extend(node.module.split("."))
        base_name = ".".join(base_parts)
    else:
        base_name = node.module or ""

    included: set[Path] = set()
    if base_name:
        is_local, paths = _resolve_exact_module(base_name)
        if is_local:
            included.update(paths)

    for alias in node.names:
        if alias.name == "*":
            continue
        candidate = ".".join(part for part in (base_name, alias.name) if part)
        candidate_parts = candidate.split(".") if candidate else []
        if candidate_parts:
            candidate_path = ROOT.joinpath(*candidate_parts)
            exact_candidate_exists = (
                candidate_path.with_suffix(".py").is_file()
                or (candidate_path / "__init__.py").is_file()
                or candidate_path.is_dir()
            )
            if exact_candidate_exists:
                is_local, paths = _resolve_exact_module(candidate)
                if is_local:
                    included.update(paths)
    return tuple(sorted(included))


def _resolve_dynamic_import(call: ast.Call) -> tuple[Path, ...]:
    function = call.func
    is_importlib = (
        isinstance(function, ast.Attribute)
        and function.attr == "import_module"
        and isinstance(function.value, ast.Name)
        and function.value.id == "importlib"
    )
    is_builtin = isinstance(function, ast.Name) and function.id == "__import__"
    if not (is_importlib or is_builtin):
        return ()
    if not call.args or not isinstance(call.args[0], ast.Constant) or type(call.args[0].value) is not str:
        raise AssertionError("non-literal dynamic import prevents authority closure")
    name = call.args[0].value
    is_local, paths = _resolve_exact_module(name)
    return paths if is_local else ()


def compute_python_authority_closure() -> tuple[str, ...]:
    seeds = tuple(sorted(FEDERATION_PYTHON.rglob("*.py")))
    if not seeds:
        raise AssertionError("automation/federation Python seed set is empty")
    included: set[Path] = set(seeds)
    pending = list(seeds)

    while pending:
        path = pending.pop()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise AssertionError(f"cannot parse authority module {path}") from exc

        discovered: set[Path] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    is_local, paths = _resolve_exact_module(alias.name)
                    if is_local:
                        discovered.update(paths)
            elif isinstance(node, ast.ImportFrom):
                discovered.update(_resolve_import_from(node, path))
            elif isinstance(node, ast.Call):
                discovered.update(_resolve_dynamic_import(node))

        for candidate in discovered - included:
            if not candidate.is_file() or candidate.suffix != ".py":
                raise AssertionError(f"closure contains non-source path: {candidate}")
            included.add(candidate)
            pending.append(candidate)

    relative = {path.relative_to(ROOT).as_posix() for path in included}
    return tuple(sorted(relative))


def _guard_json_value() -> dict[str, object]:
    return {
        "activationWriteAllowed": True,
        "ordinaryWriteAllowed": False,
        "reason": "MERGED_UNPROVEN_NO_VALID_EPOCH",
        "runtimeState": "MERGED_UNPROVEN",
    }


def _guard_positive_values() -> tuple[dict[str, object], ...]:
    return (
        {
            "activationWriteAllowed": False,
            "ordinaryWriteAllowed": True,
            "reason": "ACTIVE_G8_EPOCH_PROVEN",
            "runtimeState": "ACTIVE_G8",
        },
        _guard_json_value(),
        {
            "activationWriteAllowed": False,
            "ordinaryWriteAllowed": False,
            "reason": "BLOCKED_POST_MERGE_CONFLICT",
            "runtimeState": "BLOCKED_POST_MERGE",
        },
        {
            "activationWriteAllowed": False,
            "ordinaryWriteAllowed": False,
            "reason": "PRE_G8_NOT_APPLICABLE",
            "runtimeState": "PRE_G8_NOT_APPLICABLE",
        },
    )


def _guard_negative_fixtures() -> tuple[tuple[str, bytes], ...]:
    good = _guard_json_value()
    canonical = canonical_json(good)
    keys_without = lambda key: {name: value for name, value in good.items() if name != key}
    duplicate_key_fixtures = {
        "G17": b'{"activationWriteAllowed":true,"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":"MERGED_UNPROVEN"}\n',
        "G18": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":"MERGED_UNPROVEN"}\n',
        "G19": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":"MERGED_UNPROVEN"}\n',
        "G20": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":"MERGED_UNPROVEN","runtimeState":"MERGED_UNPROVEN"}\n',
    }
    values: dict[str, bytes] = {
        "G01": b"",
        "G02": b"\n",
        "G03": canonical[:-1],
        "G04": canonical + canonical,
        "G05": canonical + b"\n",
        "G06": b"\n" + canonical,
        "G07": canonical.replace(b"\n", b"\r\n"),
        "G08": b"\xff\n",
        "G09": b"{\n",
        "G10": b"[]\n",
        "G11": b'"not an object"\n',
        "G12": canonical_json(keys_without("activationWriteAllowed")),
        "G13": canonical_json(keys_without("ordinaryWriteAllowed")),
        "G14": canonical_json(keys_without("reason")),
        "G15": canonical_json(keys_without("runtimeState")),
        "G16": canonical_json({**good, "extra": False}),
        **duplicate_key_fixtures,
        "G21": canonical_json({**good, "activationWriteAllowed": False}),
        "G22": b'{"activationWriteAllowed":0,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":"MERGED_UNPROVEN"}\n',
        "G23": canonical_json({**good, "ordinaryWriteAllowed": True}),
        "G24": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":0,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":"MERGED_UNPROVEN"}\n',
        "G25": canonical_json({**good, "reason": "OTHER"}),
        "G26": canonical_json({**good, "reason": 1}),
        "G27": canonical_json({**good, "runtimeState": "ACTIVE_G8"}),
        "G28": canonical_json({**good, "runtimeState": "BLOCKED_POST_MERGE"}),
        "G29": canonical_json({**good, "runtimeState": "PRE_G8_NOT_APPLICABLE"}),
        "G30": canonical_json({**good, "runtimeState": "UNKNOWN"}),
        "G31": canonical_json({**good, "runtimeState": 1}),
        "G32": b'{"runtimeState":"MERGED_UNPROVEN","reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","ordinaryWriteAllowed":false,"activationWriteAllowed":true}\n',
        "G33": b'{"activationWriteAllowed": true, "ordinaryWriteAllowed": false, "reason": "MERGED_UNPROVEN_NO_VALID_EPOCH", "runtimeState": "MERGED_UNPROVEN"}\n',
        "G34": b" " + canonical,
        "G35": canonical[:-1] + b" \n",
        "G36": canonical[:-1] + b" trailing text\n",
        "G37": canonical + b'{"fallback":"first line only"}\n',
        "G38": b"runtimeState=MERGED_UNPROVEN\n",
        "G39": canonical_json({**good, "runtimeState": "FALLBACK_TO_ACTIVE_G8"}),
        "G40": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":NaN}\n',
        "G41": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":Infinity}\n',
        "G42": b'{"activationWriteAllowed":true,"ordinaryWriteAllowed":false,"reason":"MERGED_UNPROVEN_NO_VALID_EPOCH","runtimeState":-Infinity}\n',
    }
    if set(values) != {f"G{number:02}" for number in range(1, 43)}:
        raise AssertionError("guard fixture IDs are incomplete")
    return tuple((f"G{number:02}", values[f"G{number:02}"]) for number in range(1, 43))


def _write_candidate_fixture(text: str, filename: str) -> bytes:
    block = EXPECTED_TRIGGERS[filename]
    candidate = _replace_once(_full_workflow(block), block, text)
    return candidate.encode("utf-8")


class G8WorkflowEpochTests(unittest.TestCase):
    def test_exact_workflow_epoch_and_automation_test_filter(self):
        files = {path.relative_to(ROOT).as_posix() for path in WORKFLOWS.glob("*.yml")}
        self.assertTrue(set(OLD_WRITER_PATHS).isdisjoint(files))
        self.assertTrue(set(NEW_WRITER_PATHS).issubset(files))
        self.assertEqual(
            {path for path in files if Path(path).name.startswith("federation-g8-")},
            set(NEW_WRITER_PATHS),
        )
        self.assertIn(".github/workflows/federation-automation-tests.yml", files)

        automation_text = (WORKFLOWS / "federation-automation-tests.yml").read_text(encoding="utf-8")
        self.assertIn("on:\n  pull_request:\n  push:\n", automation_text)
        self.assertIn('      - ".github/federation/g8-activation-contract.json"\n', automation_text)
        self.assertIn('      - ".github/federation/g8-authority-surface.json"\n', automation_text)
        self.assertIn("actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955", automation_text)
        self.assertIn("python3 -B -m unittest discover -s tests/automation -p 'test_*.py' -v", automation_text)

    def test_activation_contract_is_canonical_exact_and_bound_to_frozen_pr_identity(self):
        raw = (ROOT / CONTRACT_PATH).read_bytes()
        value = json.loads(raw.decode("utf-8", errors="strict"))
        self.assertEqual(canonical_json(value), raw)
        self.assertIs(type(value), dict)
        self.assertEqual(set(value), EXPECTED_CONTRACT_KEYS)
        self.assertIs(type(value["schemaVersion"]), int)
        self.assertEqual(value["schemaVersion"], 2)
        self.assertEqual(value["centralRepositoryNodeId"], "R_kgDOUId1Tw")
        self.assertEqual(value["implementationPrNumber"], 28)
        self.assertIs(type(value["implementationPrNumber"]), int)
        self.assertEqual(value["implementationPrDatabaseId"], 4853644304)
        self.assertIs(type(value["implementationPrDatabaseId"]), int)
        self.assertEqual(value["implementationPrNodeId"], "PR_kwDOUId1T88AAAABIUy8EA")
        self.assertEqual(value["implementationHeadRef"], "g8/postmerge-activation-repair-01")
        self.assertEqual(value["predecessorImplementationPrNumber"], 27)
        self.assertEqual(value["predecessorImplementationPrDatabaseId"], 4780363432)
        self.assertEqual(value["predecessorImplementationPrNodeId"], "PR_kwDOUId1T88AAAABHO6OqA")
        self.assertEqual(value["predecessorReviewedHeadSha"], "5120141c3d26148d8471c161acfa6d540d412519")
        self.assertEqual(value["predecessorMergedResultOid"], "85530496699d5456af8962c1e1f80bc81dbe83ef")
        self.assertEqual(value["baseRef"], "main")
        self.assertEqual(value["activationRef"], "refs/heads/bot/federation-g8-activation")
        self.assertEqual(value["activationStatusContext"], "federation/g8-activation")
        self.assertEqual(value["authoritySurfaceManifestPath"], MANIFEST_PATH)
        self.assertEqual(value["contractVersion"], "postmerge-activation-repair-01")
        self.assertEqual(value["exactNewWriterPaths"], list(NEW_WRITER_PATHS))
        self.assertEqual(len(value["exactNewWriterPaths"]), len(set(value["exactNewWriterPaths"])))
        for key in ("implementationPrNumber", "implementationPrDatabaseId"):
            self.assertGreater(value[key], 0)
            self.assertLessEqual(value[key], 2**63 - 1)
        for key in ("centralRepositoryNodeId", "implementationPrNodeId"):
            self.assertIs(type(value[key]), str)
            self.assertTrue(value[key])
            self.assertLessEqual(len(value[key]), 200)
            self.assertFalse(any(ord(char) < 32 or ord(char) == 127 for char in value[key]))
        forbidden = {
            "implementationHeadSha",
            "implementationFinalHeadSha",
            "mergedResultOid",
            "merged_result_oid",
            "cutoverNonce",
            "cutoverId",
            "activationEpochTargetSha",
            "activationRecordSha",
        }
        self.assertTrue(forbidden.isdisjoint(value))

    def test_authority_manifest_is_canonical_exact_path_only(self):
        raw = (ROOT / MANIFEST_PATH).read_bytes()
        value = json.loads(raw.decode("utf-8", errors="strict"))
        self.assertEqual(canonical_json(value), raw)
        self.assertIs(type(value), dict)
        self.assertEqual(set(value), {"schemaVersion", "paths"})
        self.assertIs(type(value["schemaVersion"]), int)
        self.assertEqual(value["schemaVersion"], 2)
        self.assertIs(type(value["paths"]), list)
        self.assertTrue(all(type(item) is str for item in value["paths"]))
        self.assertEqual(value["paths"], sorted(value["paths"]))
        self.assertEqual(len(value["paths"]), len(set(value["paths"])))
        for item in value["paths"]:
            self.assertTrue(item)
            self.assertFalse(item.startswith("/"))
            self.assertNotIn("\\", item)
            self.assertNotIn("//", item)
            self.assertTrue(all(segment not in {"", ".", ".."} for segment in item.split("/")))
            self.assertFalse(any(char in item for char in "*?[]{}"))
            self.assertFalse(item.endswith("/"))
        self.assertEqual(tuple(value["paths"]), EXPECTED_MANIFEST_PATHS)

    def test_mechanical_python_authority_closure_matches_manifest(self):
        closure = compute_python_authority_closure()
        self.assertIn("scripts/federate.py", closure)
        expected = tuple(
            sorted(
                set(closure)
                | set(NEW_WRITER_PATHS)
                | {CONTRACT_PATH, MANIFEST_PATH}
            )
        )
        raw = (ROOT / MANIFEST_PATH).read_bytes()
        manifest = json.loads(raw.decode("utf-8"))
        self.assertEqual(tuple(manifest["paths"]), expected)
        self.assertEqual(len(expected), 14)
        self.assertEqual(tuple(manifest["paths"]), EXPECTED_MANIFEST_PATHS)

    def test_whole_workflow_top_level_lexical_scan_and_exact_trigger_closure(self):
        for filename in (Path(path).name for path in NEW_WRITER_PATHS):
            with self.subTest(workflow=filename):
                raw = (WORKFLOWS / filename).read_bytes()
                keys = scan_workflow_top_level_keys(raw)
                self.assertEqual(sum(key == "on" for key, _ in keys), 1)
                self.assertEqual(extract_exact_on_block(raw), EXPECTED_TRIGGERS[filename] + "\n")
                validate_trigger_contract(raw, filename)

    def test_trigger_mutation_cases_reject_individually(self):
        cases = _trigger_mutations()
        self.assertEqual(len(cases), 44)
        self.assertEqual(tuple(case_id for case_id, _, _ in cases), tuple(f"T{number:02}" for number in range(1, 45)))
        for case_id, filename, candidate in cases:
            with self.subTest(case=case_id, workflow=filename):
                with self.assertRaises(AssertionError):
                    validate_trigger_contract(candidate.encode("utf-8"), filename)

    def test_literal_guard_wrapper_is_exact_in_all_six_workflows(self):
        for relative_path in NEW_WRITER_PATHS:
            filename = Path(relative_path).name
            with self.subTest(workflow=filename):
                text = (ROOT / relative_path).read_text(encoding="utf-8")
                jobs = _top_level_job_blocks(text)
                self.assertEqual(jobs[0][0], "activation-guard")
                guard = jobs[0][1]
                self.assertIn("permissions:\n      contents: read\n", guard)
                self.assertEqual(guard.count(APP_TOKEN_ACTION), 1)
                for permission in ("contents", "issues", "pull-requests", "statuses"):
                    self.assertEqual(guard.count(f"permission-{permission}: read"), 1)
                    self.assertNotIn(f"permission-{permission}: write", guard)
                self.assertNotIn("permission-actions:", guard)
                self.assertNotIn("permission-checks:", guard)
                self.assertIn(f"uses: {CHECKOUT_ACTION}", guard)
                self.assertIn("ref: refs/heads/main", guard)
                self.assertIn("persist-credentials: false", guard)
                self.assertIn("submodules: false", guard)
                self.assertIn("lfs: false", guard)
                self.assertIn("FEDERATION_GITHUB_TOKEN: ${{ steps.guard-token.outputs.token }}", guard)
                self.assertIn("FEDERATION_APP_SLUG: ${{ steps.guard-token.outputs.app-slug }}", guard)
                self.assertIn("FEDERATION_TRUSTED_CHECKOUT_SHA: ${{ steps.trusted-checkout.outputs.sha }}", guard)
                self.assertIn("automation.federation.controller activation-guard", guard)
                self.assertNotRegex(guard, r"\b(?:grep|sed|awk|jq|head|tail|cut)\b")
                wrapper = _extract_guard_wrapper(guard)
                self.assertEqual(wrapper, FROZEN_GUARD_WRAPPER)
                self.assertEqual(wrapper.count("<<'PY'"), 1)
                self.assertEqual(wrapper.count('output.write("runtime_state='), 1)
                self.assertEqual(wrapper.count('output.write("ordinary_write_allowed='), 1)
                self.assertEqual(wrapper.count('output.write("activation_write_allowed='), 1)
                self.assertEqual(guard.count("GITHUB_OUTPUT"), 2)
                self.assertEqual(wrapper.count("GITHUB_OUTPUT"), 1)

    def test_actual_workflow_parser_executes_positive_and_all_negative_fixtures(self):
        wrappers = []
        for relative_path in NEW_WRITER_PATHS:
            jobs = _top_level_job_blocks((ROOT / relative_path).read_text(encoding="utf-8"))
            wrappers.append(_extract_guard_wrapper(jobs[0][1]))
        self.assertEqual(len(wrappers), 6)
        self.assertEqual(len(set(wrappers)), 1)
        wrapper = wrappers[0]
        start = "python3 - \"${guard_stdout}\" \"${GITHUB_OUTPUT}\" <<'PY'\n"
        end_marker = "\nPY\n"
        self.assertEqual(wrapper.count(start), 1)
        self.assertEqual(wrapper.count(end_marker), 1)
        parser_start = wrapper.index(start) + len(start)
        parser_end = wrapper.index(end_marker, parser_start)
        parser_body = wrapper[parser_start:parser_end + 1]
        self.assertTrue(parser_body.endswith("\n"))

        negatives = _guard_negative_fixtures()
        self.assertEqual(len(negatives), 42)
        self.assertEqual(
            tuple(case_id for case_id, _ in negatives),
            tuple(f"G{number:02}" for number in range(1, 43)),
        )
        python3 = shutil.which("python3") or sys.executable

        with tempfile.TemporaryDirectory(prefix="g8-actual-parser-") as temp_dir:
            temp = Path(temp_dir)
            parser_path = temp / "actual_workflow_parser.py"
            parser_path.write_text(parser_body, encoding="utf-8", newline="\n")

            strict_matrix = (
                'runtime_state = value["runtimeState"]\n'
                'if runtime_state not in allowed:\n'
                '    raise SystemExit("unexpected activation guard runtime state")\n'
                'ordinary_expected, activation_expected, reason_expected = allowed[runtime_state]\n'
                'if value["ordinaryWriteAllowed"] is not ordinary_expected:\n'
                '    raise SystemExit("ordinaryWriteAllowed does not match runtime state")\n'
                'if value["activationWriteAllowed"] is not activation_expected:\n'
                '    raise SystemExit("activationWriteAllowed does not match runtime state")\n'
                'if value["reason"] != reason_expected:\n'
                '    raise SystemExit("activation guard reason does not match runtime state")\n'
            )
            fallback_matrix = (
                'runtime_state = value["runtimeState"]\n'
                'if runtime_state == "FALLBACK_TO_ACTIVE_G8":\n'
                '    ordinary_expected = value["ordinaryWriteAllowed"]\n'
                '    activation_expected = value["activationWriteAllowed"]\n'
                '    reason_expected = value["reason"]\n'
                'elif runtime_state not in allowed:\n'
                '    raise SystemExit("unexpected activation guard runtime state")\n'
                'else:\n'
                '    ordinary_expected, activation_expected, reason_expected = allowed[runtime_state]\n'
                'if value["ordinaryWriteAllowed"] is not ordinary_expected:\n'
                '    raise SystemExit("ordinaryWriteAllowed does not match runtime state")\n'
                'if value["activationWriteAllowed"] is not activation_expected:\n'
                '    raise SystemExit("activationWriteAllowed does not match runtime state")\n'
                'if value["reason"] != reason_expected:\n'
                '    raise SystemExit("activation guard reason does not match runtime state")\n'
            )
            fallback_mutant_body = _replace_once(parser_body, strict_matrix, fallback_matrix)
            fallback_mutant_body = _replace_once(
                fallback_mutant_body,
                'if canonical != raw:\n'
                '    raise SystemExit("non-canonical activation guard bytes")\n',
                'if canonical != raw:\n'
                '    raise SystemExit("non-canonical activation guard bytes")\n'
                'if value["runtimeState"] == "FALLBACK_TO_ACTIVE_G8":\n'
                '    value["runtimeState"] = "ACTIVE_G8"\n',
            )
            self.assertNotEqual(fallback_mutant_body, parser_body)
            fallback_mutant_path = temp / "controlled_fallback_mutant.py"
            fallback_mutant_path.write_text(fallback_mutant_body, encoding="utf-8", newline="\n")

            def execute(
                raw: bytes,
                index: str,
                *,
                parser: Path = parser_path,
            ) -> tuple[subprocess.CompletedProcess[bytes], Path]:
                stdout_path = temp / f"{index}.stdout"
                output_path = temp / f"{index}.github_output"
                stdout_path.write_bytes(raw)
                output_path.write_bytes(b"")
                result = subprocess.run(
                    [python3, str(parser), str(stdout_path), str(output_path)],
                    capture_output=True,
                    check=False,
                    timeout=10,
                )
                return result, output_path

            for index, value in enumerate(_guard_positive_values(), start=1):
                with self.subTest(positive=value["runtimeState"]):
                    accepted, output_path = execute(canonical_json(value), f"positive-{index}")
                    self.assertEqual(
                        accepted.returncode,
                        0,
                        accepted.stderr.decode("utf-8", "replace"),
                    )
                    self.assertEqual(accepted.stdout, b"")
                    expected_output = (
                        f'runtime_state={value["runtimeState"]}\n'
                        f'ordinary_write_allowed={"true" if value["ordinaryWriteAllowed"] else "false"}\n'
                        f'activation_write_allowed={"true" if value["activationWriteAllowed"] else "false"}\n'
                    ).encode()
                    self.assertEqual(output_path.read_bytes(), expected_output)

            for case_id, raw in negatives:
                with self.subTest(case=case_id):
                    rejected, output_path = execute(raw, case_id)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(output_path.read_bytes(), b"")

            g39_raw = dict(negatives)["G39"]
            g39_strict_output = temp / "G39.github_output"
            self.assertEqual(g39_strict_output.read_bytes(), b"")
            fallback_result, fallback_output = execute(
                g39_raw,
                "G39-fallback-mutant",
                parser=fallback_mutant_path,
            )
            self.assertEqual(
                fallback_result.returncode,
                0,
                fallback_result.stderr.decode("utf-8", "replace"),
            )
            self.assertEqual(fallback_result.stdout, b"")
            self.assertEqual(
                fallback_output.read_bytes(),
                b"runtime_state=ACTIVE_G8\n"
                b"ordinary_write_allowed=false\n"
                b"activation_write_allowed=true\n",
            )
        self.assertEqual(len(negatives), 42)

    def test_workflow_set_guard_dominance_token_permissions_and_concurrency(self):
        expected_permissions = {
            "federation-g8-issue-intake.yml": {
                "issue-intake": {"actions": "write", "statuses": "write", "contents": "write", "issues": "write", "pull-requests": "write"},
            },
            "federation-g8-interactive.yml": {
                "interactive": {"actions": "write", "contents": "write", "pull-requests": "write", "issues": "read"},
            },
            "federation-g8-trusted-validation.yml": {
                "role-router": {"contents": "read", "pull-requests": "read", "issues": "read", "checks": "read", "statuses": "read"},
                "manual-status-validation": {"actions": "write", "statuses": "write", "contents": "read", "pull-requests": "read", "issues": "read"},
                "machine-validation": {"actions": "write", "checks": "write", "contents": "read", "pull-requests": "read", "issues": "read"},
            },
            "federation-g8-state-finalize.yml": {
                "role-router": {"contents": "read", "pull-requests": "read", "issues": "read", "checks": "read", "statuses": "read"},
                "issue-manual-finalizer": {"actions": "write", "statuses": "write", "contents": "write", "pull-requests": "write", "issues": "read"},
                "machine-finalizer": {"actions": "write", "checks": "write", "contents": "write", "pull-requests": "write", "issues": "read"},
            },
            "federation-g8-main-advance.yml": {
                "main-advance": {"actions": "write", "contents": "write", "pull-requests": "write", "issues": "read"},
            },
            "federation-g8-reconcile.yml": {
                "recover": {"actions": "write", "statuses": "write", "contents": "write", "issues": "read", "pull-requests": "write"},
                "activation-preflight": {"actions": "read", "contents": "read", "statuses": "read", "issues": "read", "pull-requests": "read"},
                "activate-g8": {"actions": "write", "statuses": "write", "contents": "write", "issues": "write", "pull-requests": "write"},
            },
        }
        for relative_path in NEW_WRITER_PATHS:
            filename = Path(relative_path).name
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            jobs = _top_level_job_blocks(text)
            self.assertEqual(jobs[0][0], "activation-guard")
            guard = jobs[0][1]
            self.assertEqual(guard.count(APP_TOKEN_ACTION), 1)
            self.assertIn("permissions:\n      contents: read\n", guard)
            for permission in ("contents", "issues", "pull-requests", "statuses"):
                self.assertEqual(guard.count(f"permission-{permission}: read"), 1)
                self.assertNotIn(f"permission-{permission}: write", guard)
            self.assertNotIn("permission-actions:", guard)
            self.assertNotIn("permission-checks:", guard)
            self.assertIn("FEDERATION_GITHUB_TOKEN: ${{ steps.guard-token.outputs.token }}", guard)
            self.assertIn("FEDERATION_APP_SLUG: ${{ steps.guard-token.outputs.app-slug }}", guard)
            self.assertIn("FEDERATION_TRUSTED_CHECKOUT_SHA: ${{ steps.trusted-checkout.outputs.sha }}", guard)
            for job_name, job_text in jobs[1:]:
                token_count = job_text.count(APP_TOKEN_ACTION)
                if token_count:
                    self.assertEqual(token_count, 1)
                    if filename == "federation-g8-reconcile.yml" and job_name == "activation-preflight":
                        self.assertIn("needs: activation-guard\n", job_text)
                        self.assertIn("inputs.mode == 'activate-g8'", job_text)
                        self.assertIn("github.ref == 'refs/heads/main'", job_text)
                        self.assertIn("activation-preflight", job_text)
                        self.assertNotRegex(job_text, r"^\s+permission-[a-z-]+:\s+write\s*$")
                    elif filename == "federation-g8-reconcile.yml" and job_name == "activate-g8":
                        self.assertIn("needs: activation-preflight\n", job_text)
                        self.assertIn("needs.activation-preflight.outputs.decision == 'READY'", job_text)
                        self.assertIn("github.event_name == 'workflow_dispatch'", job_text)
                        self.assertIn("inputs.mode == 'activate-g8'", job_text)
                        self.assertIn("github.ref == 'refs/heads/main'", job_text)
                    elif filename == "federation-g8-trusted-validation.yml" and job_name != "role-router":
                        self.assertIn("needs: [activation-guard, role-router]\n", job_text)
                        route = "MANUAL_STATUS" if job_name == "manual-status-validation" else "MACHINE_VALIDATION"
                        self.assertIn(
                            f"if: needs.activation-guard.outputs.runtime_state == 'ACTIVE_G8' && needs.role-router.outputs.route == '{route}'",
                            job_text,
                        )
                    elif filename == "federation-g8-state-finalize.yml" and job_name == "role-router":
                        self.assertIn("needs: activation-guard\n", job_text)
                        self.assertIn("if: needs.activation-guard.outputs.runtime_state == 'ACTIVE_G8'", job_text)
                    elif filename == "federation-g8-state-finalize.yml":
                        self.assertIn("needs: [activation-guard, role-router]\n", job_text)
                        lane = "issue_manual_needed" if job_name == "issue-manual-finalizer" else "machine_needed"
                        self.assertIn(f"needs.role-router.outputs.{lane} == 'true'", job_text)
                        self.assertIn("needs.role-router.outputs.blocked == 'false'", job_text)
                        self.assertIn("needs.activation-guard.outputs.runtime_state == 'ACTIVE_G8'", job_text)
                    else:
                        self.assertIn("needs: activation-guard\n", job_text)
                        self.assertIn("if: needs.activation-guard.outputs.runtime_state == 'ACTIVE_G8'", job_text)
                    workflow_permissions = re.search(r"\n    permissions:\n((?:      [^\n]+\n)+)", job_text)
                    self.assertIsNotNone(workflow_permissions)
                    self.assertEqual(workflow_permissions.group(1), "      contents: read\n")
                    permission_lines = re.findall(
                        r"^\s+permission-([a-z-]+):\s+(read|write)\s*$",
                        job_text,
                        flags=re.MULTILINE,
                    )
                    self.assertEqual(len(permission_lines), len(expected_permissions[filename][job_name]))
                    self.assertEqual(dict(permission_lines), expected_permissions[filename][job_name])
                else:
                    self.assertNotIn(APP_TOKEN_ACTION, job_text)
            observed = {
                name: dict(
                    re.findall(
                        r"^\s+permission-([a-z-]+):\s+(read|write)\s*$",
                        block,
                        flags=re.MULTILINE,
                    )
                )
                for name, block in jobs[1:]
                if APP_TOKEN_ACTION in block
            }
            self.assertEqual(observed, expected_permissions[filename])
            if filename == "federation-g8-reconcile.yml":
                self.assertNotIn("activate-g8-wave10-blocked", text)
                activate_job = dict(jobs)["activate-g8"]
                self.assertIn("automation.federation.controller activate-g8", activate_job)
                self.assertNotIn("permission-checks:", activate_job)
                self.assertNotIn("PAT", activate_job)

            if filename == "federation-g8-trusted-validation.yml":
                self.assertIn(
                    f"group: {TRUSTED_VALIDATION_GROUP}",
                    text,
                )
                self.assertNotIn("federation-trusted-validation-pr-", text)
                self.assertNotIn(MANUAL_AUTHORITY_GROUP, text)
                jobs = dict(jobs)
                router = jobs["role-router"]
                self.assertNotRegex(router, r"^\s*permission-[a-z-]+:\s+write\s*$")
                self.assertIn("trusted-validation-route", router)
                self.assertIn("non-canonical Wg3 route bytes", router)
                self.assertNotIn("&& false", text)
                self.assertIn("trusted-validation-manual", jobs["manual-status-validation"])
                self.assertIn("trusted-validation-machine", jobs["machine-validation"])
                self.assertNotIn("controller trusted-validation\n", text)
            if filename == "federation-g8-state-finalize.yml":
                jobs = dict(jobs)
                self.assertIn("state-finalize-route", jobs["role-router"])
                self.assertIn("state-finalize-manual", jobs["issue-manual-finalizer"])
                self.assertIn("state-finalize-machine", jobs["machine-finalizer"])
                self.assertNotIn("permission-checks:", jobs["issue-manual-finalizer"])
                self.assertNotIn("permission-statuses:", jobs["machine-finalizer"])
                self.assertNotIn("controller state-finalize\n", text)
            elif filename != "federation-g8-trusted-validation.yml":
                self.assertIn(f"group: {MANUAL_AUTHORITY_GROUP}", text)
            self.assertIn("cancel-in-progress: false", text)

    def test_actions_are_full_sha_pinned_and_workflows_use_only_reviewed_local_entrypoint(self):
        allowed = {CHECKOUT_ACTION, APP_TOKEN_ACTION}
        for relative_path in NEW_WRITER_PATHS:
            text = (ROOT / relative_path).read_text(encoding="utf-8")
            uses_values = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
            self.assertTrue(uses_values)
            for action in uses_values:
                self.assertNotIn(action, {"./", "./local-action"})
                self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")
                self.assertIn(action, allowed)
            self.assertNotRegex(text, re.compile(r"^\s*uses:\s*\./", re.MULTILINE))
            self.assertNotRegex(text, re.compile(r"^\s*(?:source|\.)\s+\S+", re.MULTILINE))
            self.assertNotRegex(text, re.compile(r"\beval\s+[^#\n]*", re.MULTILINE))
            self.assertNotIn("PYTHONPATH=", text)
            self.assertNotRegex(text, r"\bpython3?\s+(?:scripts|automation)/[^ \n]+")
            for command in re.findall(r"^\s*run:\s*\|\n((?:\s{10,}[^\n]*\n|\n)+)", text, flags=re.MULTILINE):
                for line in command.splitlines():
                    if "automation.federation.controller" in line:
                        self.assertRegex(
                            line,
                            r"^\s*PYTHONDONTWRITEBYTECODE=1 python3 -B -m automation\.federation\.controller(?:\s|$)",
                        )

    def test_old_dispatch_targets_and_activation_writer_reachability_remain_absent(self):
        request_model_path = ROOT / "automation" / "federation" / "request_model.py"
        production_without_historic_identity = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted((ROOT / "automation" / "federation").rglob("*.py"))
            if path != request_model_path
        )
        retired_names = tuple(Path(path).name for path in OLD_WRITER_PATHS)
        for retired in retired_names:
            self.assertNotIn(retired, production_without_historic_identity)

        request_model = request_model_path.read_text(encoding="utf-8")
        for retired in retired_names:
            self.assertEqual(request_model.count(retired), 1)

        request_model_tree = ast.parse(request_model)
        old_writer_assignments = [
            node
            for node in request_model_tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "G8_OLD_WRITERS" for target in node.targets)
        ]
        self.assertEqual(len(old_writer_assignments), 1)
        old_writer_identities = ast.literal_eval(old_writer_assignments[0].value)
        expected_old_writer_identities = (
            (".github/workflows/federation-interactive.yml", 350485971),
            (".github/workflows/federation-trusted-validation.yml", 350485976),
            (".github/workflows/federation-state-finalize.yml", 350485975),
            (".github/workflows/federation-main-advance.yml", 350485973),
            (".github/workflows/federation-reconcile.yml", 350485974),
        )
        self.assertEqual(old_writer_identities, expected_old_writer_identities)
        self.assertEqual(tuple(path for path, _workflow_id in old_writer_identities), OLD_WRITER_PATHS)
        self.assertEqual(len({path for path, _workflow_id in old_writer_identities}), 5)
        self.assertEqual(len({_workflow_id for _path, _workflow_id in old_writer_identities}), 5)

        controller = (ROOT / "automation" / "federation" / "controller.py").read_text(encoding="utf-8")
        controller_tree = ast.parse(controller)
        dispatch_targets = []
        for node in ast.walk(controller_tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if not (isinstance(function, ast.Attribute) and function.attr == "dispatch_workflow"):
                continue
            self.assertGreaterEqual(len(node.args), 2)
            workflow_argument = node.args[1]
            self.assertIsInstance(workflow_argument, ast.Constant)
            self.assertIsInstance(workflow_argument.value, str)
            dispatch_targets.append(workflow_argument.value)
        self.assertTrue(dispatch_targets)
        for retired in retired_names:
            self.assertNotIn(retired, dispatch_targets)

        self.assertIn("def derive_g8_activation_guard(", controller)
        self.assertNotIn("wave10_inert_activation_guard", controller)
        activation_authority = next(
            node for node in ast.walk(controller_tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "_require_g8_activation_run_authority"
        )
        activation_authority_source = ast.get_source_segment(controller, activation_authority)
        self.assertIn('if mode != "activate-g8":', activation_authority_source)
        self.assertIn('"activate-g8"', controller)
        for path in NEW_WRITER_PATHS:
            text = (ROOT / path).read_text(encoding="utf-8")
            if Path(path).name != "federation-g8-reconcile.yml":
                self.assertNotIn("activate-g8", text)
        reconcile = (ROOT / ".github" / "workflows" / "federation-g8-reconcile.yml").read_text(encoding="utf-8")
        self.assertIn("activate-g8", reconcile)
        self.assertNotIn("activate-g8-wave10-blocked", reconcile)
        self.assertIn("federation-g8-reconcile.yml", controller)

    def test_wg3_route_transport_parser_rejects_noncanonical_outputs(self):
        workflow = (WORKFLOWS / "federation-g8-trusted-validation.yml").read_text(encoding="utf-8")
        marker = 'python3 - "${route_stdout}" "${GITHUB_OUTPUT}" <<\'PY\'\n'
        start = workflow.index(marker) + len(marker)
        end = workflow.index("\n          PY\n", start)
        parser = textwrap.dedent(workflow[start:end])
        cases = (
            (b'{"route":"MANUAL_STATUS"}\n', True),
            (b'{"route":"UNKNOWN"}\n', False),
            (b'{"route":"NOOP","route":"MANUAL_STATUS"}\n', False),
            (b'{"route":"NOOP"}\nextra\n', False),
            (b'{ "route": "NOOP" }\n', False),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            route_file = root / "route.out"
            output_file = root / "github-output"
            for payload, expected_success in cases:
                with self.subTest(payload=payload):
                    route_file.write_bytes(payload)
                    output_file.write_bytes(b"")
                    result = subprocess.run(
                        [sys.executable, "-c", parser, str(route_file), str(output_file)],
                        capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode == 0, expected_success, result.stderr.decode("utf-8", "replace"))
                    self.assertEqual(
                        output_file.read_bytes(),
                        b"route=MANUAL_STATUS\n" if expected_success else b"",
                    )

    def test_wg1_issue_comment_semantic_suppression_remains_in_controller(self):
        controller = (ROOT / "automation" / "federation" / "controller.py").read_text(encoding="utf-8")
        self.assertIn(
            'if event_kind == "issue_comment" and triggering_comment_author == app.bot_login:',
            controller,
        )
        self.assertIn("# App-authored result/anchor comments must never re-enter as PATCH triggers.", controller)
        issue_intake = (ROOT / NEW_WRITER_PATHS[0]).read_text(encoding="utf-8")
        self.assertIn("  issue_comment:\n    types: [created]\n", issue_intake)
        self.assertIn("  pull_request_target:\n    types: [closed]\n", issue_intake)


if __name__ == "__main__":
    unittest.main()
