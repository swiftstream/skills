import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import federate as c02
from automation.federation.request_model import (
    ANCHOR_MARKER,
    PATCH_SENTINEL,
    CommentEvent,
    Request,
    RequestAnchor,
    RequestClass,
    RequestModelError,
    body_sha256,
    fold_patch_events,
    parse_anchor,
    parse_patch,
    parse_request_body,
)
from automation.federation.workspace import validate_trusted_ref


def add_body(description="A source", branch="main", root="skills", prefixes="swifql"):
    return f"Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\n{description}\nBranch:\n{branch}\nSkills root:\n{root}\nSkill prefixes:\n{prefixes}\n"


class RequestModelTests(unittest.TestCase):
    def test_all_markers_and_bodies(self):
        for cls in RequestClass:
            if cls in {RequestClass.MACHINE_PUBLICATION, RequestClass.UNRELATED}:
                continue
            self.assertEqual(cls.value, {RequestClass.ADD: "add-source", RequestClass.UPDATE: "update-source", RequestClass.REMOVE: "remove-source", RequestClass.RECONCILE: "reconcile-source"}[cls])
        self.assertEqual(parse_request_body(RequestClass.ADD, add_body()).repository_url, "https://github.com/Owner/Repo")
        self.assertEqual(parse_request_body(RequestClass.UPDATE, add_body()).branch, "refs/heads/main")
        self.assertEqual(parse_request_body(RequestClass.REMOVE, "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\ncleanup\n").reason, "cleanup")
        self.assertEqual(parse_request_body(RequestClass.RECONCILE, "Repository URL:\nhttps://github.com/Owner/Repo\n").request_class, RequestClass.RECONCILE)

    def test_url_and_field_strictness(self):
        for url in ("http://github.com/O/R", "https://gitlab.com/O/R", "https://github.com/O/R.git", "https://github.com/O/R/", "https://github.com/O/R?q=1", "https://github.com/O/R#x", "https://u:p@github.com/O/R", "https://github.com/O/R/x"):
            with self.subTest(url=url):
                with self.assertRaises(RequestModelError):
                    parse_request_body(RequestClass.ADD, f"Repository URL:\n{url}\n")
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, "Description:\nx\n")
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, "Repository URL:\n\n")
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/O/R\nBranch:\nrefs/heads/../x\n")
        self.assertIsNone(parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/O/R\nDescription:\n\n").description)
        self.assertEqual(parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/O/R\nSkill prefixes:\nfoo, bar\n").skill_prefixes, ("foo", "bar"))
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/O/R\nSkill prefixes:\nfoo,foo\n")

    def test_hostile_path_cannot_execute_fake_git_for_request_branch_validation(self):
        with tempfile.TemporaryDirectory() as temp_name:
            attacker = Path(temp_name) / "attacker"
            attacker.mkdir()
            sentinel = attacker / "fake-git-ran"
            fake_git = attacker / "git"
            fake_git.write_text(f"#!/bin/sh\ntouch {sentinel}\nexit 99\n")
            fake_git.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(attacker)}, clear=False):
                request = parse_request_body(RequestClass.ADD, add_body())
            self.assertEqual(request.branch, "refs/heads/main")
            self.assertFalse(sentinel.exists())

    def test_trusted_ref_adapter_is_differentially_compatible_with_c02(self):
        corpus = (
            "refs/heads/main",
            "refs/heads/release/x",
            "",
            None,
            123,
            "refs/heads/",
            "main",
            "refs/tags/x",
            "refs/heads/a\x00b",
            "refs/heads/../x",
            "refs/heads/a..b",
            "refs/heads/a.lock",
        )

        def outcome(function, value):
            try:
                return ("accepted", function(value))
            except Exception as error:
                return ("rejected", str(error))

        with patch.dict(os.environ, {"PATH": "/usr/bin:/bin"}, clear=False):
            for value in corpus:
                with self.subTest(value=value):
                    self.assertEqual(outcome(validate_trusted_ref, value), outcome(c02.validate_ref, value))

    def test_marker_branch_root_order_and_size_boundaries(self):
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.MACHINE_PUBLICATION, "")
        self.assertIsNone(parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/O/R\nSkills root:\n\n" ).skills_root)
        for root in (".", "../skills", "/skills", "a//b", "a\\b", "a/../b"):
            with self.subTest(root=root), self.assertRaises(RequestModelError):
                parse_request_body(RequestClass.ADD, f"Repository URL:\nhttps://github.com/O/R\nSkills root:\n{root}\n")
        self.assertEqual(parse_request_body(RequestClass.ADD, add_body(branch="refs/heads/release")).branch, "refs/heads/release")
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, add_body(branch="refs/heads/"))
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, add_body(description="x" * 501))
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, add_body() + "x" * 16385)
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, "Description:\nx\nRepository URL:\nhttps://github.com/O/R\n")
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/O/R\nDescription:\nx\nDescription:\ny\n")

    def test_patch_fold_is_complete_and_deterministic(self):
        initial = parse_request_body(RequestClass.ADD, add_body())
        anchor = RequestAnchor(7, RequestClass.ADD, "42", "alice", body_sha256(add_body()), initial)
        ordinary = CommentEvent(10, True, "ordinary discussion")
        later = CommentEvent(20, True, f"{PATCH_SENTINEL}\n\nBranch:\nrelease\n")
        earlier = CommentEvent(15, False, f"{PATCH_SENTINEL}\n\nDescription:\nnot allowed\n")
        first = fold_patch_events(anchor, [later, ordinary, earlier])
        second = fold_patch_events(anchor, [ordinary, earlier, later])
        self.assertEqual(first, second)
        self.assertEqual(first.request.branch, "refs/heads/release")
        self.assertEqual([(e.comment_id, e.kind) for e in first.evidence], [(15, "unauthorized"), (20, "applied")])
        with self.assertRaises(RequestModelError):
            fold_patch_events(anchor, [CommentEvent(0, True, "x")])
        with self.assertRaises(RequestModelError):
            fold_patch_events(anchor, [CommentEvent(1, True, "x"), CommentEvent(1, True, "y")])

    def test_patch_invalid_and_semantic_rejection_continue(self):
        initial = parse_request_body(RequestClass.ADD, add_body())
        anchor = RequestAnchor(7, RequestClass.ADD, "42", "alice", body_sha256(add_body()), initial)
        invalid = CommentEvent(2, True, f"{PATCH_SENTINEL}\n\nUnknown:\nx\n")
        semantic = CommentEvent(3, True, f"{PATCH_SENTINEL}\n\nBranch:\nblocked\n")
        valid = CommentEvent(4, True, f"{PATCH_SENTINEL}\n\nDescription:\nnew\n")
        result = fold_patch_events(anchor, [valid, semantic, invalid], lambda request: request.branch != "refs/heads/blocked")
        self.assertEqual(result.request.description, "new")
        self.assertEqual([item.kind for item in result.evidence], ["invalid", "semantic-invalid", "applied"])
        self.assertIsNone(parse_patch("ordinary\ncomment"))
        clear = parse_patch(f"{PATCH_SENTINEL}\n\nDescription:\n\n")
        self.assertEqual(clear.assignments["Description"], None)

    def test_patch_grammar_rejects_wrong_fields_and_is_bounded(self):
        invalid_comments = (
            f"{PATCH_SENTINEL}\n\nRepository URL:\nhttps://github.com/O/R\n",
            f"{PATCH_SENTINEL}\n\nDescription:\nx\nDescription:\ny\n",
            f"{PATCH_SENTINEL}\n\nUnknown:\nx\n",
            f"{PATCH_SENTINEL}\n\nDescription\nx\n",
        )
        for comment in invalid_comments:
            with self.subTest(comment=comment), self.assertRaises(RequestModelError):
                parse_patch(comment)
        with self.assertRaises(RequestModelError):
            parse_patch(f"{PATCH_SENTINEL}\n\nDescription:\n{'x' * 16385}\n")
        with self.assertRaises(RequestModelError):
            parse_patch(f"{PATCH_SENTINEL}\n\nDescription:\nx\nBranch:\nmain\nDescription:\ny\n")

    def test_anchor_round_trip_and_integrity(self):
        body = add_body()
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(9223372036854775807, RequestClass.ADD, "42", "alice", hashlib.sha256(body.encode()).hexdigest(), request)
        rendered = anchor.render()
        self.assertTrue(rendered.startswith(ANCHOR_MARKER + "\n"))
        self.assertEqual(parse_anchor(rendered), anchor)
        self.assertEqual(parse_anchor(rendered).initial_request.skill_prefixes, ("swifql",))
        value = json.loads(rendered.splitlines()[1])
        value["extra"] = True
        with self.assertRaises(RequestModelError):
            parse_anchor(ANCHOR_MARKER + "\n" + json.dumps(value) + "\n")
        with self.assertRaises(RequestModelError):
            parse_anchor(rendered + "prose\n")
        self.assertNotEqual(body_sha256(body.replace("\n", "\r\n")), body_sha256(body))

    def test_anchor_strict_shape_types_marker_and_class_consistency(self):
        body = add_body()
        anchor = RequestAnchor(7, RequestClass.ADD, "42", "alice", body_sha256(body), parse_request_body(RequestClass.ADD, body))
        rendered = anchor.render()
        value = json.loads(rendered.splitlines()[1])
        for key, replacement in (("schemaVersion", 2), ("prNumber", True), ("initialBodySha256", "bad"), ("originalAuthorId", 4), ("originalAuthorLogin", "a\x00b")):
            candidate = dict(value)
            candidate[key] = replacement
            with self.subTest(key=key), self.assertRaises(RequestModelError):
                parse_anchor(ANCHOR_MARKER + "\n" + json.dumps(candidate) + "\n")
        with self.assertRaises(RequestModelError):
            parse_anchor("swiftstream-federation-request-anchor:v1\n" + rendered.splitlines()[1] + "\n")
        with self.assertRaises(RequestModelError):
            parse_anchor(rendered + "extra\n")
        duplicate_json = rendered.splitlines()[1].replace('"schemaVersion":1', '"schemaVersion":1,"schemaVersion":1', 1)
        with self.assertRaises(RequestModelError):
            parse_anchor(ANCHOR_MARKER + "\n" + duplicate_json + "\n")
        initial = value["initialRequest"]
        initial["Branch"] = "main"
        with self.assertRaises(RequestModelError):
            parse_anchor(ANCHOR_MARKER + "\n" + json.dumps(dict(value, initialRequest=initial)) + "\n")
        initial["Branch"] = "refs/heads/main"
        reparsed = parse_anchor(ANCHOR_MARKER + "\n" + json.dumps(dict(value, initialRequest=initial)) + "\n")
        self.assertEqual(reparsed.initial_request.branch, "refs/heads/main")
        self.assertEqual(reparsed.as_value()["initialRequest"]["Branch"], "refs/heads/main")

    def test_direct_anchor_construction_validates_full_request_invariant(self):
        body = add_body()
        request = parse_request_body(RequestClass.ADD, body)
        cases = (
            Request(RequestClass.ADD, request.repository_url, request.description, "main", request.skills_root, request.skill_prefixes),
            Request(RequestClass.ADD, request.repository_url, request.description, request.branch, request.skills_root, request.skill_prefixes, "reason"),
            Request(RequestClass.ADD, "https://github.com/O/R/", request.description, request.branch, request.skills_root, request.skill_prefixes),
            Request(RequestClass.ADD, request.repository_url, " bad", request.branch, request.skills_root, request.skill_prefixes),
            Request(RequestClass.ADD, request.repository_url, request.description, request.branch, "../bad", request.skill_prefixes),
            Request(RequestClass.ADD, request.repository_url, request.description, request.branch, request.skills_root, ("foo", "foo")),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(RequestModelError):
                RequestAnchor(1, RequestClass.ADD, "id", "login", "0" * 64, candidate).render()
        for cls, body_text, bad_request in (
            (RequestClass.ADD, body, Request(RequestClass.UPDATE, request.repository_url)),
            (RequestClass.UPDATE, add_body(), Request(RequestClass.ADD, request.repository_url)),
            (RequestClass.REMOVE, "Repository URL:\nhttps://github.com/O/R\nReason:\nwhy\n", Request(RequestClass.REMOVE, request.repository_url, description="not allowed")),
            (RequestClass.RECONCILE, "Repository URL:\nhttps://github.com/O/R\n", Request(RequestClass.RECONCILE, request.repository_url, reason="not allowed")),
        ):
            with self.subTest(cls=cls), self.assertRaises(RequestModelError):
                RequestAnchor(1, cls, "id", "login", "0" * 64, bad_request)

    def test_remove_and_reconcile_patch_cannot_mutate_anchored_state(self):
        for cls, body, assignments in (
            (RequestClass.REMOVE, "Repository URL:\nhttps://github.com/O/R\nReason:\nwhy\n", ("Description", "Branch", "Skills root", "Skill prefixes")),
            (RequestClass.RECONCILE, "Repository URL:\nhttps://github.com/O/R\n", ("Description", "Branch", "Skills root", "Skill prefixes")),
        ):
            request = parse_request_body(cls, body)
            anchor = RequestAnchor(1, cls, "id", "login", body_sha256(body), request)
            events = [CommentEvent(index + 1, True, f"{PATCH_SENTINEL}\n\n{field}:\nvalue\n") for index, field in enumerate(assignments)]
            result = fold_patch_events(anchor, events)
            self.assertEqual(result.request, request)
            self.assertEqual([item.kind for item in result.evidence], ["invalid"] * len(events))


if __name__ == "__main__":
    unittest.main()
