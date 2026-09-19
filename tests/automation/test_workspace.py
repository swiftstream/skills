import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import federate

from automation.federation import workspace as workspace_module
from automation.federation.workspace import (
    TRUSTED_GIT_PATH,
    TRUSTED_TEMP_BASE,
    WorkspaceError,
    _TRUSTED_GIT_ENV,
    _commit_tree_deterministically,
    _cleanup_eligible_disposable_root,
    _run_trusted_git,
    _safe_owned_disposable_root,
    _verified_trusted_git,
    create_synthetic_workspace,
    inspect_candidate_diff,
)


ROOT = Path(__file__).resolve().parents[2]


def git(repo, args, *, text=True):
    return federate.run_git(args, cwd=repo, text=text, source_workspace=True)


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self._ambient_git = {key: os.environ.pop(key) for key in list(os.environ) if key.startswith("GIT_")}
        self.addCleanup(os.environ.update, self._ambient_git)

    def fixture(self):
        temp = tempfile.TemporaryDirectory(dir=str(ROOT.parent))
        repo = Path(temp.name) / "repo"
        repo.mkdir()
        git(repo, ["init", "--quiet"])
        git(repo, ["config", "user.name", "Fixture"])
        git(repo, ["config", "user.email", "fixture@example.invalid"])
        (repo / "trusted.txt").write_text("trusted\n")
        git(repo, ["add", "."])
        git(repo, ["commit", "--quiet", "-m", "base"])
        base = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
        (repo / "data.txt").write_text("candidate\n")
        git(repo, ["add", "."])
        git(repo, ["commit", "--quiet", "-m", "candidate"])
        head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
        return temp, repo, base, head

    def test_allowlisted_overlay_is_disposable_and_deterministic(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        original = (repo / "data.txt").read_bytes() if (repo / "data.txt").exists() else None
        with create_synthetic_workspace(repo, base, head, ["data.txt"], {"timestamp": "2000-01-01T00:00:00Z"}) as first:
            first_tree, first_commit = first.tree, first.synthetic_commit
            self.assertNotIn(str(repo), str(first.root))
            self.assertEqual((first.root / "data.txt").read_text(), "candidate\n")
            self.assertFalse((first.root / ".git").resolve() == (repo / ".git").resolve())
        with create_synthetic_workspace(repo, base, head, ["data.txt"], {"timestamp": "2000-01-01T00:00:00Z"}) as second:
            self.assertEqual((first_tree, first_commit), (second.tree, second.synthetic_commit))
        self.assertEqual(original, (repo / "data.txt").read_bytes())
        self.assertEqual(inspect_candidate_diff(repo, base, head)[0].path, "data.txt")

    def test_candidate_forbidden_paths_modes_and_allowlist(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        (repo / ".github").mkdir()
        (repo / ".github" / "workflow.yml").write_text("bad")
        git(repo, ["add", "."])
        git(repo, ["commit", "--quiet", "-m", "workflow"])
        workflow_head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
        with self.assertRaises(WorkspaceError):
            create_synthetic_workspace(repo, base, workflow_head, [".github/workflow.yml"])
        with self.assertRaises(WorkspaceError):
            create_synthetic_workspace(repo, base, head, [])

    def test_sha_and_allowlist_path_validation(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        for value in ("0" * 39, "g" * 40, None):
            with self.subTest(value=value), self.assertRaises(WorkspaceError):
                inspect_candidate_diff(repo, value, head)
        for value in ("0" * 39, "G" * 40, None):
            with self.subTest(value=value), self.assertRaises(WorkspaceError):
                inspect_candidate_diff(repo, base, value)
        for path in ("../data.txt", "/data.txt", "a\\b", "a//b", "", ".github/workflow.yml"):
            with self.subTest(path=path), self.assertRaises(WorkspaceError):
                create_synthetic_workspace(repo, base, head, [path])

    def test_symlink_gitlink_and_unexpected_modes_rejected(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        (repo / "link").symlink_to("trusted.txt")
        git(repo, ["add", "link"])
        git(repo, ["commit", "--quiet", "-m", "symlink"])
        symlink_head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
        with self.assertRaises(WorkspaceError):
            inspect_candidate_diff(repo, base, symlink_head)
        git(repo, ["update-index", "--add", "--cacheinfo", f"160000,{head},gitlink"])
        git(repo, ["commit", "--quiet", "-m", "gitlink"])
        gitlink_head = git(repo, ["rev-parse", "HEAD"]).stdout.strip()
        with self.assertRaises(WorkspaceError):
            inspect_candidate_diff(repo, base, gitlink_head)
        with patch("automation.federation.workspace._parse_ls_tree", return_value={"data.txt": ("100600", "blob")}):
            with self.assertRaises(WorkspaceError):
                inspect_candidate_diff(repo, base, head)

    def test_inherited_git_environment_matrix_fails_closed_before_git_and_creation(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        inherited_git_values = {
            "GIT_TRACE": "1",
            "GIT_TRACE_PACKET": "1",
            "GIT_EXTERNAL_DIFF": "/bin/false",
            "GIT_INDEX_FILE": str(temp.name) + "/external-index",
            "GIT_DIR": str(repo / "missing.git"),
            "GIT_WORK_TREE": str(repo / "missing-worktree"),
            "GIT_OBJECT_DIRECTORY": str(repo / "missing-objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repo / "missing-alternates"),
            "GIT_CONFIG_COUNT": "1",
            "GIT_SSH_COMMAND": "false",
            "GIT_ASKPASS": "/bin/false",
            "GIT_NAMESPACE": "attacker",
        }
        for key, value in inherited_git_values.items():
            with self.subTest(key=key):
                workspaces = set(Path(tempfile.gettempdir()).glob("swiftstream-federation-workspace-*"))
                with patch.dict(os.environ, {key: value}, clear=False):
                    with patch("automation.federation.workspace.c02.run_git", wraps=federate.run_git) as run_git:
                        with self.assertRaisesRegex(WorkspaceError, "inherited Git environment is forbidden"):
                            create_synthetic_workspace(repo, base, head, ["data.txt"])
                        self.assertEqual(run_git.call_count, 0)
                self.assertEqual(workspaces, set(Path(tempfile.gettempdir()).glob("swiftstream-federation-workspace-*")))

    def test_git_trace_external_path_and_fixture_data_remain_unchanged_on_rejection(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        external_trace = Path(temp.name) / "external-trace.log"
        fixture_index = repo / ".git" / "index"
        fixture_index_before = fixture_index.read_bytes()
        fixture_data = repo / "data.txt"
        fixture_data_before = fixture_data.read_bytes()
        workspaces = set(Path(tempfile.gettempdir()).glob("swiftstream-federation-workspace-*"))
        with patch.dict(os.environ, {"GIT_TRACE": str(external_trace)}, clear=False):
            with patch("automation.federation.workspace.c02.run_git", wraps=federate.run_git) as run_git:
                with self.assertRaises(WorkspaceError):
                    create_synthetic_workspace(repo, base, head, ["data.txt"])
                self.assertEqual(run_git.call_count, 0)
        self.assertFalse(external_trace.exists())
        self.assertEqual(fixture_index_before, fixture_index.read_bytes())
        self.assertEqual(fixture_data_before, fixture_data.read_bytes())
        self.assertEqual(workspaces, set(Path(tempfile.gettempdir()).glob("swiftstream-federation-workspace-*")))

    def test_inherited_git_index_file_fails_closed_before_git_and_preserves_indexes(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        external = Path(temp.name) / "external-index"
        external.write_bytes(b"external sentinel index\n")
        external_before = external.read_bytes()
        fixture_index = repo / ".git" / "index"
        fixture_before = fixture_index.read_bytes()
        workspaces = set(Path(tempfile.gettempdir()).glob("swiftstream-federation-workspace-*"))
        with patch.dict(os.environ, {"GIT_INDEX_FILE": str(external)}, clear=False):
            with patch("automation.federation.workspace.c02.run_git", wraps=federate.run_git) as run_git:
                with self.assertRaisesRegex(WorkspaceError, "GIT_INDEX_FILE"):
                    create_synthetic_workspace(repo, base, head, ["data.txt"])
                self.assertEqual(run_git.call_count, 0)
        self.assertEqual(external_before, external.read_bytes())
        self.assertEqual(fixture_before, fixture_index.read_bytes())
        self.assertEqual(workspaces, set(Path(tempfile.gettempdir()).glob("swiftstream-federation-workspace-*")))

    def test_commit_tree_environment_contains_only_trusted_git_metadata(self):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["argv"] = args[0]
            captured.update(kwargs)
            return type("Result", (), {"returncode": 0, "stdout": b"0" * 40 + b"\n"})()

        git_result = type("Result", (), {"stdout": "tree\n"})()
        ambient_git = {
            "GIT_TRACE": "/outside/trace",
            "GIT_EXTERNAL_DIFF": "/outside/diff",
            "GIT_INDEX_FILE": "/outside/index",
            "GIT_DIR": "/outside/git",
        }
        with patch.dict(os.environ, ambient_git, clear=False):
            with patch("automation.federation.workspace._assert_safe_git_environment"):
                with patch("automation.federation.workspace._git", side_effect=[git_result, git_result, git_result]) as git_call:
                    with patch("automation.federation.workspace.subprocess.run", side_effect=fake_run):
                        workspace_module._commit_tree_deterministically(Path("/tmp/worktree"), {})
        self.assertEqual(git_call.call_count, 3)
        trusted_git_keys = {
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
            "GIT_AUTHOR_DATE",
            "GIT_COMMITTER_DATE",
        }
        child_git_keys = {key for key in captured.get("env", {}) if key.startswith("GIT_")}
        self.assertEqual(child_git_keys, {key for key in _TRUSTED_GIT_ENV if key.startswith("GIT_")} | trusted_git_keys)
        self.assertTrue(child_git_keys.isdisjoint(ambient_git))

    def test_workspace_git_calls_are_local_only(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        with patch("automation.federation.workspace._run_trusted_git", wraps=_run_trusted_git) as run_git:
            with create_synthetic_workspace(repo, base, head, ["data.txt"]):
                pass
        self.assertTrue(run_git.call_count > 0)
        for call in run_git.call_args_list:
            self.assertIn(call.args[0][0], workspace_module._ALLOWED_GIT_COMMANDS)

    def test_trusted_git_is_absolute_root_owned_and_verified(self):
        resolved = _verified_trusted_git()
        info = resolved.stat()
        self.assertEqual(TRUSTED_GIT_PATH, Path("/usr/bin/git"))
        self.assertEqual(resolved, TRUSTED_GIT_PATH.resolve(strict=True))
        self.assertTrue(stat.S_ISREG(info.st_mode))
        self.assertTrue(os.access(resolved, os.X_OK))
        self.assertEqual(info.st_uid, 0)
        self.assertEqual(info.st_mode & 0o022, 0)

    def test_exact_ordinary_child_environment_and_absolute_argv(self):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["argv"] = args[0]
            captured["env"] = kwargs["env"]
            return type("Result", (), {"returncode": 0, "stdout": b"git version test\n", "stderr": b""})()

        hostile = {
            "PATH": "/attacker",
            "HOME": "/attacker/home",
            "DYLD_INSERT_LIBRARIES": "/attacker/lib.dylib",
            "LD_PRELOAD": "/attacker/lib.so",
            "SSH_AUTH_SOCK": "/attacker/socket",
            "PAGER": "/attacker/pager",
            "EDITOR": "/attacker/editor",
            "PYTHONPATH": "/attacker/python",
            "VIRTUAL_ENV": "/attacker/venv",
        }
        with patch.dict(os.environ, hostile, clear=False):
            with patch("automation.federation.workspace.subprocess.run", side_effect=fake_run):
                _run_trusted_git(["--version"])
        self.assertEqual(captured["argv"][0], str(TRUSTED_GIT_PATH.resolve(strict=True)))
        self.assertEqual(captured["env"], _TRUSTED_GIT_ENV)

    def test_hostile_path_never_executes_fake_git_in_workspace(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        attacker = Path(temp.name) / "attacker"
        attacker.mkdir()
        sentinel = attacker / "fake-git-ran"
        fake_git = attacker / "git"
        fake_git.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 99\n")
        fake_git.chmod(0o755)
        with patch.dict(os.environ, {"PATH": str(attacker)}, clear=False):
            with create_synthetic_workspace(repo, base, head, ["data.txt"]) as workspace:
                self.assertEqual(workspace.root.parent, workspace._disposable_root)
        self.assertFalse(sentinel.exists())

    def test_hostile_temp_variables_cannot_place_workspace_in_repository(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        before = {path: path.read_bytes() for path in repo.rglob("*") if path.is_file()}
        for variables in (
            {"TMPDIR": str(repo)},
            {"TEMP": str(repo / "temp")},
            {"TMP": str(repo / "tmp")},
            {"TMPDIR": str(repo), "TEMP": str(repo), "TMP": str(repo)},
        ):
            with self.subTest(variables=variables), patch.dict(os.environ, variables, clear=False):
                with create_synthetic_workspace(repo, base, head, ["data.txt"]) as workspace:
                    self.assertEqual(workspace._disposable_root.parent, TRUSTED_TEMP_BASE.resolve(strict=True))
                    self.assertNotIn(repo, workspace._disposable_root.parents)
                    self.assertNotEqual(workspace._disposable_root, repo)
            self.assertFalse(any(repo.glob("swiftstream-federation-workspace-*")))
        self.assertEqual(before, {path: path.read_bytes() for path in repo.rglob("*") if path.is_file()})

    def test_invalid_trusted_temp_base_fails_before_materialization(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        with patch.object(workspace_module, "TRUSTED_TEMP_BASE", repo):
            with self.assertRaisesRegex(WorkspaceError, "trusted temp base"):
                create_synthetic_workspace(repo, base, head, ["data.txt"])
        self.assertFalse(any(repo.glob("swiftstream-federation-workspace-*")))

    def test_commit_tree_environment_is_exact_profile_plus_six_metadata(self):
        captured = {}

        def fake_run(*args, **kwargs):
            captured["argv"] = args[0]
            captured.update(kwargs)
            return type("Result", (), {"returncode": 0, "stdout": b"0" * 40 + b"\n", "stderr": b""})()

        with patch("automation.federation.workspace.subprocess.run", side_effect=fake_run):
            with patch("automation.federation.workspace._git", side_effect=[type("Result", (), {"stdout": "tree\n"})()] * 3):
                _commit_tree_deterministically(Path("/tmp/worktree"), {})
        expected = dict(_TRUSTED_GIT_ENV)
        expected.update(
            {
                "GIT_AUTHOR_NAME": "Swift Stream Federation",
                "GIT_AUTHOR_EMAIL": "automation@swiftstream.invalid",
                "GIT_COMMITTER_NAME": "Swift Stream Federation",
                "GIT_COMMITTER_EMAIL": "automation@swiftstream.invalid",
                "GIT_AUTHOR_DATE": "2000-01-01T00:00:00Z",
                "GIT_COMMITTER_DATE": "2000-01-01T00:00:00Z",
            }
        )
        self.assertEqual(captured["env"], expected)
        self.assertEqual(captured["argv"][0], str(TRUSTED_GIT_PATH.resolve(strict=True)))

    def test_cleanup_removes_exact_disposable_parent_preserving_real_repository(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        trusted_before = (repo / "trusted.txt").read_bytes()
        with create_synthetic_workspace(repo, base, head, ["data.txt"]) as workspace:
            disposable_parent = workspace._disposable_root
            worktree = workspace.root
            self.assertTrue(disposable_parent.is_dir())
            self.assertTrue(worktree.is_dir())
            self.assertNotIn(str(repo), str(disposable_parent))
        self.assertFalse(worktree.exists())
        self.assertFalse(disposable_parent.exists())
        self.assertEqual(trusted_before, (repo / "trusted.txt").read_bytes())
        self.assertTrue(repo.is_dir())

    def test_post_creation_unsafe_mode_cleans_exact_root_and_preserves_siblings(self):
        temp, repo, base, head = self.fixture()
        self.addCleanup(temp.cleanup)
        trusted_base = TRUSTED_TEMP_BASE.resolve(strict=True)
        sibling = Path(tempfile.mkdtemp(prefix="swiftstream-correction-05-sibling-", dir=str(trusted_base)))
        self.addCleanup(lambda: sibling.exists() and shutil.rmtree(sibling))
        (sibling / "sentinel").write_text("preserve\n")
        repository_before = {path: path.read_bytes() for path in repo.rglob("*") if path.is_file()}
        created = []
        real_mkdtemp = tempfile.mkdtemp

        def create_unsafe_root(*args, **kwargs):
            root = Path(real_mkdtemp(*args, **kwargs))
            root.chmod(0o755)
            created.append(root)
            info = root.lstat()
            self.assertNotEqual(info.st_mode & 0o077, 0)
            identity = (info.st_dev, info.st_ino)
            self.assertFalse(_safe_owned_disposable_root(root, trusted_base, repo, identity))
            self.assertTrue(_cleanup_eligible_disposable_root(root, trusted_base, repo, identity))
            return str(root)

        with patch.object(workspace_module.tempfile, "mkdtemp", side_effect=create_unsafe_root):
            with self.assertRaisesRegex(WorkspaceError, "failed validation"):
                create_synthetic_workspace(repo, base, head, ["data.txt"])

        self.assertEqual(len(created), 1)
        self.assertFalse(created[0].exists())
        self.assertTrue(trusted_base.is_dir())
        self.assertTrue(sibling.is_dir())
        self.assertEqual((sibling / "sentinel").read_text(), "preserve\n")
        self.assertEqual(repository_before, {path: path.read_bytes() for path in repo.rglob("*") if path.is_file()})

    def test_cleanup_proof_refuses_identity_symlink_outside_and_repository_paths(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        container = Path(temp.name).resolve(strict=True)
        trusted_base = container / "base"
        trusted_base.mkdir()
        repository = container / "repo"
        repository.mkdir()

        matching = trusted_base / "matching"
        matching.mkdir()
        matching_identity = (matching.stat().st_dev, matching.stat().st_ino)
        self.assertTrue(_cleanup_eligible_disposable_root(matching, trusted_base, repository, matching_identity))

        mismatch = trusted_base / "mismatch"
        mismatch.mkdir()
        mismatch_identity = (mismatch.stat().st_dev, mismatch.stat().st_ino)
        self.assertFalse(
            _cleanup_eligible_disposable_root(
                mismatch, trusted_base, repository, (mismatch_identity[0], mismatch_identity[1] + 1)
            )
        )
        self.assertTrue(mismatch.exists())

        target = trusted_base / "target"
        target.mkdir()
        symlink = trusted_base / "symlink"
        symlink.symlink_to(target, target_is_directory=True)
        symlink_identity = (target.stat().st_dev, target.stat().st_ino)
        self.assertFalse(_cleanup_eligible_disposable_root(symlink, trusted_base, repository, symlink_identity))
        self.assertTrue(target.is_dir())
        self.assertTrue(symlink.is_symlink())

        outside = container / "outside"
        outside.mkdir()
        outside_identity = (outside.stat().st_dev, outside.stat().st_ino)
        self.assertFalse(_cleanup_eligible_disposable_root(outside, trusted_base, repository, outside_identity))
        self.assertTrue(outside.exists())

        repository_related = trusted_base / "repository-related"
        repository_related.mkdir()
        related_repository = repository_related / "repo"
        related_repository.mkdir()
        repository_identity = (repository_related.stat().st_dev, repository_related.stat().st_ino)
        self.assertFalse(
            _cleanup_eligible_disposable_root(repository_related, trusted_base, related_repository, repository_identity)
        )
        self.assertTrue(repository_related.is_dir())
        self.assertTrue(related_repository.is_dir())


if __name__ == "__main__":
    unittest.main()
