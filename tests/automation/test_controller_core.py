import ast
from pathlib import Path
import unittest
from unittest.mock import patch

import automation.federation.controller as controller_module
from automation.federation.controller import PhaseNotImplementedError, R01Controller, classify_request, parse_c02_manifest
from automation.federation.request_model import CommentEvent, RequestClass, RequestAnchor, parse_request_body, body_sha256


class ControllerCoreTests(unittest.TestCase):
    def test_authority_and_structural_classification(self):
        self.assertEqual(classify_request(marker_content="add-source"), RequestClass.ADD)
        self.assertEqual(classify_request(marker_content="unexpected", head_branch="bot/federation/swifql"), RequestClass.MACHINE_PUBLICATION)
        self.assertEqual(classify_request(head_branch="bot/federation/not valid"), RequestClass.UNRELATED)
        self.assertEqual(classify_request(title="add-source", head_branch="feature"), RequestClass.UNRELATED)
        body = "Repository URL:\nhttps://github.com/O/R\n"
        request = parse_request_body(RequestClass.RECONCILE, body)
        anchor = RequestAnchor(1, RequestClass.RECONCILE, "id", "login", body_sha256(body), request)
        self.assertEqual(classify_request(title="anything", anchor=anchor), RequestClass.RECONCILE)

    def test_c02_adapter_and_phase_boundary(self):
        manifest = parse_c02_manifest({"schemaVersion": 2, "sources": []})
        self.assertEqual(manifest.sources, ())
        controller = R01Controller()
        with self.assertRaises(PhaseNotImplementedError):
            controller.finalize_live_request()
        with self.assertRaises(PhaseNotImplementedError):
            controller.mutate_github()
        with self.assertRaises(PhaseNotImplementedError):
            controller.reconcile()

    def test_all_structural_classes_and_anchor_authority(self):
        bodies = {
            RequestClass.ADD: "Repository URL:\nhttps://github.com/O/R\nDescription:\nd\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n",
            RequestClass.UPDATE: "Repository URL:\nhttps://github.com/O/R\nDescription:\nd\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n",
            RequestClass.REMOVE: "Repository URL:\nhttps://github.com/O/R\nReason:\nwhy\n",
            RequestClass.RECONCILE: "Repository URL:\nhttps://github.com/O/R\n",
        }
        for index, (request_class, body) in enumerate(bodies.items(), 1):
            request = parse_request_body(request_class, body)
            anchor = RequestAnchor(index, request_class, "id", "login", body_sha256(body), request)
            self.assertEqual(classify_request(marker_content=None, title="remove-source", head_branch="main", anchor=anchor), request_class)
            self.assertEqual(classify_request(marker_content=request_class.value), request_class)
        self.assertEqual(classify_request(marker_content="machine-publication"), RequestClass.UNRELATED)
        self.assertEqual(classify_request(marker_content="unexpected", head_branch="bot/federation/swifql"), RequestClass.MACHINE_PUBLICATION)
        for branch in ("bot/federation/SwifQL", "bot/federation/not_valid", "bot/federation/foo/bar", "bot/federation/"):
            with self.subTest(branch=branch):
                self.assertEqual(classify_request(head_branch=branch), RequestClass.UNRELATED)
        self.assertEqual(classify_request(title="add-source", head_branch="feature"), RequestClass.UNRELATED)

    def test_complete_patch_reconstruction_uses_pure_fold(self):
        body = "Repository URL:\nhttps://github.com/O/R\nDescription:\nd\nBranch:\nmain\nSkills root:\nskills\nSkill prefixes:\nfoo\n"
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(1, RequestClass.ADD, "id", "login", body_sha256(body), request)
        controller = R01Controller()
        result = controller.reconstruct(anchor, [CommentEvent(2, True, "Federation PATCH\n\nDescription:\nupdated\n")])
        self.assertEqual(result.request.description, "updated")

    def test_c02_adapter_is_reused_without_duplicate_semantics(self):
        with patch("automation.federation.controller.c02.load_manifest_from_value", return_value=object()) as loader:
            self.assertIs(parse_c02_manifest({"schemaVersion": 2, "sources": []}), loader.return_value)
            loader.assert_called_once_with({"schemaVersion": 2, "sources": []}, "candidate federation.json")

    def test_r02_plus_live_methods_are_explicitly_phase_blocked(self):
        controller = R01Controller()
        for method in (controller.finalize_live_request, controller.mutate_github, controller.reconcile):
            with self.subTest(method=method), self.assertRaises(PhaseNotImplementedError):
                method()

    def test_controller_has_no_live_network_or_mutation_seam(self):
        controller = R01Controller()
        self.assertEqual(controller.classify(marker_content="unrelated"), RequestClass.UNRELATED)
        with self.assertRaises(PhaseNotImplementedError):
            controller.mutate_github("would mutate")

    def test_module_entrypoint_guard_follows_all_top_level_definitions(self):
        path = Path(controller_module.__file__).resolve()
        module = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        def is_main_guard(node):
            return (
                isinstance(node, ast.If)
                and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name)
                and node.test.left.id == "__name__"
                and len(node.test.ops) == 1
                and isinstance(node.test.ops[0], ast.Eq)
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == "__main__"
            )

        guard_indices = [index for index, node in enumerate(module.body) if is_main_guard(node)]
        self.assertEqual(guard_indices, [len(module.body) - 1])
        guard_index = guard_indices[0]
        definitions = {
            node.name: index
            for index, node in enumerate(module.body)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        self.assertLess(definitions["main"], guard_index)
        self.assertLess(definitions["validate_candidate_diff"], guard_index)
        self.assertFalse(
            any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) for node in module.body[guard_index + 1:])
        )


if __name__ == "__main__":
    unittest.main()
