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
    ISSUE_REQUEST_ANCHOR_MARKER,
    ISSUE_INTERNAL_PR_BINDING_MARKER,
    ISSUE_PATCH_PROJECTION_MARKER,
    ISSUE_HEAD_CLAIM_MARKER,
    PR_ISSUE_ORIGIN_BINDING_MARKER,
    PATCH_SENTINEL,
    MAX_BODY_BYTES,
    MAX_CANONICAL_PATCH_BYTES,
    MAX_ISSUE_PATCH_PROJECTION_ENVELOPE_BYTES,
    MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES,
    MAX_PATCH_CANONICAL_EXPANSION_BYTES,
    CommentEvent,
    IssuePatchEvent,
    IssuePatchProjection,
    IssueHeadClaim,
    IssueBranchLease,
    IssueRequestAnchor,
    IssuePRBinding,
    ClaimedHeadMarker,
    Request,
    Patch,
    RequestAnchor,
    RequestClass,
    RequestModelError,
    body_sha256,
    fold_patch_events,
    fold_issue_patch_events,
    CLAIMED_HEAD_MARKER_HEADER,
    ISSUE_BRANCH_LEASE_MARKER,
    CLAIM_GENERATION_PREFIX,
    issue_owner_key,
    issue_branch_ref,
    reserved_issue_branch_number,
    render_request_body,
    issue_branch_lease_authority_digest,
    effective_request_digest,
    issue_patch_projection_evidence_digest,
    patch_projection_evidence_digest,
    normalize_target_evidence_digest,
    proposal_target_evidence_digest,
    issue_head_claim_authority_digest,
    classify_issue_head_claim_progression,
    claim_generation_id,
    parse_claimed_head_marker,
    parse_issue_branch_lease,
    parse_issue_patch_projection,
    parse_issue_head_claim,
    parse_anchor,
    parse_issue_request_body,
    parse_issue_request_anchor,
    parse_patch,
    render_patch,
    parse_request_body,
    parse_issue_internal_pr_binding,
    parse_pr_issue_origin_binding,
    proposed_line_refs,
    validate_drop_set,
)
from automation.federation.workspace import validate_trusted_ref


def add_body(description="A source", branch="main", root="skills", prefixes="swifql"):
    return f"Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\n{description}\nBranch:\n{branch}\nSkills root:\n{root}\nSkill prefixes:\n{prefixes}\n"


def _prefix_value_exact_length(length):
    count = (length + 65) // 65
    if count <= 0:
        raise ValueError("prefix value must be nonempty")
    lengths = [1] * count
    remaining = length - (count - 1) - count
    for index in range(count):
        added = min(63, remaining)
        lengths[index] += added
        remaining -= added
    if remaining != 0 or any(size > 64 for size in lengths):
        raise ValueError("requested prefix length is not representable")
    prefixes = []
    for index, size in enumerate(lengths):
        identity = f"p{index}"
        if len(identity) > size:
            raise ValueError("generated prefix token is too short")
        prefixes.append(identity + "x" * (size - len(identity)))
    value = ",".join(prefixes)
    if len(value.encode("utf-8")) != length:
        raise AssertionError("prefix generator produced the wrong length")
    return value


def _patch_body_of_exact_size(size, *, leading_newlines=0):
    lines = [
        PATCH_SENTINEL,
        "Description:", "d",
        "Branch:", "main",
        "Skills root:", "skills",
        "Skill prefixes:", "",
        "Publication lines:", "refs/heads/main=foo",
        "Dropped publication lines:", "refs/heads/old",
    ]
    empty_prefix_body = "\n".join(lines)
    prefix_length = size - leading_newlines - len(empty_prefix_body.encode("utf-8"))
    lines[8] = _prefix_value_exact_length(prefix_length)
    body = "\n" * leading_newlines + "\n".join(lines)
    if len(body.encode("utf-8")) != size:
        raise AssertionError("PATCH generator produced the wrong size")
    return body


class RequestModelTests(unittest.TestCase):
    @staticmethod
    def issue_body(request_type, fields):
        sections = [("Federation request type", request_type), *fields]
        return "\n\n".join(f"### {heading}\n\n{value}" for heading, value in sections) + "\n"

    def test_issue_add_body_maps_to_the_existing_request_model(self):
        issue_body = self.issue_body(
            "add-source",
            [
                ("Repository URL", "https://github.com/Owner/Repo"),
                ("Description", "A source"),
                ("Branch", "main"),
                ("Skills root", "skills"),
                ("Skill prefixes", "swifql"),
                ("Publication lines", "refs/heads/main=swifql"),
            ],
        )
        canonical_body = (
            "Repository URL:\nhttps://github.com/Owner/Repo\n"
            "Description:\nA source\n"
            "Branch:\nmain\n"
            "Skills root:\nskills\n"
            "Skill prefixes:\nswifql\n"
            "Publication lines:\nrefs/heads/main=swifql\n"
        )
        self.assertEqual(
            parse_issue_request_body(issue_body),
            parse_request_body(RequestClass.ADD, canonical_body),
        )

    def test_issue_update_body_preserves_publication_and_dropped_lines(self):
        issue_body = self.issue_body(
            "update-source",
            [
                ("Repository URL", "https://github.com/vapor/vapor"),
                ("Description", "Framework"),
                ("Branch", "main"),
                ("Skills root", "skills"),
                ("Skill prefixes", "vapor5"),
                ("Publication lines", "refs/heads/main=vapor5"),
                ("Dropped publication lines", "refs/heads/release/4"),
            ],
        )
        request = parse_issue_request_body(issue_body)
        self.assertEqual(request.request_class, RequestClass.UPDATE)
        self.assertEqual([(line.ref, line.skill_prefixes) for line in request.publication_lines], [("refs/heads/main", ("vapor5",))])
        self.assertEqual(request.dropped_publication_lines, ("refs/heads/release/4",))

    def test_issue_remove_body_maps_url_and_reason(self):
        issue_body = self.issue_body(
            "remove-source",
            [
                ("Repository URL", "https://github.com/Owner/Repo"),
                ("Reason", "retired"),
            ],
        )
        self.assertEqual(
            parse_issue_request_body(issue_body),
            parse_request_body(
                RequestClass.REMOVE,
                "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\nretired\n",
            ),
        )

    def test_issue_no_response_removes_optional_values(self):
        issue_body = self.issue_body(
            "add-source",
            [
                ("Repository URL", "https://github.com/Owner/Repo"),
                ("Description", "_No response_"),
                ("Branch", "_No response_"),
                ("Skills root", "_No response_"),
                ("Skill prefixes", "_No response_"),
                ("Publication lines", "_No response_"),
            ],
        )
        request = parse_issue_request_body(issue_body)
        self.assertEqual(request, parse_request_body(RequestClass.ADD, "Repository URL:\nhttps://github.com/Owner/Repo\n"))

    def test_issue_no_response_is_rejected_for_request_type_and_repository_url(self):
        for request_type, url in (("_No response_", "https://github.com/Owner/Repo"), ("add-source", "_No response_")):
            issue_body = self.issue_body(
                request_type,
                [
                    ("Repository URL", url),
                    ("Description", "_No response_"),
                    ("Branch", "_No response_"),
                    ("Skills root", "_No response_"),
                    ("Skill prefixes", "_No response_"),
                    ("Publication lines", "_No response_"),
                ],
            )
            with self.subTest(request_type=request_type, url=url), self.assertRaises(RequestModelError):
                parse_issue_request_body(issue_body)

    def test_issue_request_type_is_closed_and_excludes_reconcile(self):
        fields = [
            ("Repository URL", "https://github.com/Owner/Repo"),
            ("Description", "_No response_"),
            ("Branch", "_No response_"),
            ("Skills root", "_No response_"),
            ("Skill prefixes", "_No response_"),
            ("Publication lines", "_No response_"),
        ]
        for value in ("reconcile-source", "add", "No response", "_no response_", "none", "null"):
            with self.subTest(value=value), self.assertRaises(RequestModelError):
                parse_issue_request_body(self.issue_body(value, fields))

    def test_issue_optional_fields_reject_loose_empty_sentinels(self):
        for value in ("No response", "_no response_", "none", "null"):
            fields = [
                ("Repository URL", "https://github.com/Owner/Repo"),
                ("Description", value),
                ("Branch", "_No response_"),
                ("Skills root", "_No response_"),
                ("Skill prefixes", "_No response_"),
                ("Publication lines", "_No response_"),
            ]
            with self.subTest(value=value), self.assertRaises(RequestModelError):
                parse_issue_request_body(self.issue_body("add-source", fields))

    def test_issue_heading_duplicates_unknowns_missing_and_order_are_rejected(self):
        valid_fields = [
            ("Repository URL", "https://github.com/Owner/Repo"),
            ("Description", "source"),
            ("Branch", "main"),
            ("Skills root", "skills"),
            ("Skill prefixes", "foo"),
            ("Publication lines", "_No response_"),
        ]
        valid = self.issue_body("add-source", valid_fields)
        malformed = (
            valid.replace("### Repository URL", "### Repository URL", 1).replace(
                "### Publication lines", "### Repository URL\n\nhttps://github.com/Owner/Repo\n\n### Publication lines", 1
            ),
            valid + "\n### Unrecognized field\n\nvalue\n",
            self.issue_body("remove-source", [("Repository URL", "https://github.com/Owner/Repo")]),
            self.issue_body("add-source", [valid_fields[0], valid_fields[2], valid_fields[1], *valid_fields[3:]]),
        )
        for body in malformed:
            with self.subTest(body=body), self.assertRaises(RequestModelError):
                parse_issue_request_body(body)

    def test_issue_body_rejects_multiline_values_and_free_form_prose(self):
        base = self.issue_body(
            "add-source",
            [
                ("Repository URL", "https://github.com/Owner/Repo"),
                ("Description", "first line"),
                ("Branch", "main"),
                ("Skills root", "skills"),
                ("Skill prefixes", "foo"),
                ("Publication lines", "_No response_"),
            ],
        )
        multiline = base.replace("first line\n\n### Branch", "first line\nsecond line\n\n### Branch")
        prose = base.replace("### Repository URL", "authority prose\n\n### Repository URL", 1)
        for body in (multiline, prose):
            with self.subTest(body=body), self.assertRaises(RequestModelError):
                parse_issue_request_body(body)

    def test_issue_body_bounds_utf8_size_and_rejects_control_data(self):
        body = self.issue_body(
            "add-source",
            [
                ("Repository URL", "https://github.com/Owner/Repo"),
                ("Description", "source"),
                ("Branch", "main"),
                ("Skills root", "skills"),
                ("Skill prefixes", "foo"),
                ("Publication lines", "_No response_"),
            ],
        )
        for invalid in (
            body.replace("source", "x" * 16_384, 1),
            body.replace("source", "bad\x00value", 1),
            body.replace("source", "bad\rvalue", 1),
            body.replace("source", "bad\tvalue", 1),
        ):
            with self.subTest(sample=invalid[:80]), self.assertRaises(RequestModelError):
                parse_issue_request_body(invalid)

    def test_issue_parser_is_body_only_and_uses_no_form_metadata(self):
        import inspect

        self.assertEqual(tuple(inspect.signature(parse_issue_request_body).parameters), ("body",))
        with self.assertRaises(TypeError):
            parse_issue_request_body("", title="add-source")

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

    def test_patch_render_is_semantic_canonical_and_boundary_domain_is_split(self):
        patch = parse_patch(
            f"{PATCH_SENTINEL}\nDescription:\nA description\nBranch:\nmain\n"
            "Skill prefixes:\nfoo, bar\nPublication lines:\nrefs/heads/main=foo,bar\n"
            "Dropped publication lines:\nrefs/heads/old"
        )
        self.assertIsNotNone(patch)
        rendered = render_patch(patch)
        self.assertEqual(
            rendered,
            f"{PATCH_SENTINEL}\n\nDescription:\nA description\n\n"
            "Branch:\nrefs/heads/main\n\nSkill prefixes:\nfoo,bar\n\n"
            "Publication lines:\nrefs/heads/main=foo,bar\n\n"
            "Dropped publication lines:\nrefs/heads/old\n",
        )
        self.assertEqual(render_patch(parse_patch(rendered)), rendered)
        clear = parse_patch(f"{PATCH_SENTINEL}\nDescription:\n")
        self.assertEqual(render_patch(clear), f"{PATCH_SENTINEL}\n\nDescription:\n\n")
        with self.assertRaises(RequestModelError):
            render_patch(type(patch)({"Description": "x" * 501}))

        self.assertEqual(MAX_BODY_BYTES, 16_384)
        self.assertEqual(MAX_PATCH_CANONICAL_EXPANSION_BYTES, 18)
        self.assertEqual(MAX_CANONICAL_PATCH_BYTES, 16_402)
        from automation.federation.request_model import _parse_projection_canonical_patch

        for leading_newlines, expected_canonical_size in ((16, 16_386), (0, 16_402)):
            raw = _patch_body_of_exact_size(MAX_BODY_BYTES, leading_newlines=leading_newlines)
            accepted = parse_patch(raw)
            self.assertIsNotNone(accepted)
            canonical = render_patch(accepted)
            self.assertEqual(len(raw.encode("utf-8")), MAX_BODY_BYTES)
            self.assertEqual(len(canonical.encode("utf-8")), expected_canonical_size)
            self.assertLessEqual(
                len(canonical.encode("utf-8")),
                len(raw.encode("utf-8")) + MAX_PATCH_CANONICAL_EXPANSION_BYTES,
            )
            with self.subTest(leading_newlines=leading_newlines):
                self.assertEqual(render_patch(_parse_projection_canonical_patch(canonical)), canonical)
        with self.assertRaises(RequestModelError):
            parse_patch(_patch_body_of_exact_size(MAX_CANONICAL_PATCH_BYTES))

    def test_all_patch_field_subsets_obey_the_canonical_expansion_bound(self):
        fields = (
            ("Description", "description"),
            ("Branch", "main"),
            ("Skills root", "skills"),
            ("Skill prefixes", "foo,bar"),
            ("Publication lines", "refs/heads/main=foo,bar"),
            ("Dropped publication lines", "refs/heads/old"),
        )
        for mask in range(1, 1 << len(fields)):
            selected = [item for index, item in enumerate(fields) if mask & (1 << index)]
            raw = PATCH_SENTINEL + "\n" + "\n".join(
                line for field, value in selected for line in (f"{field}:", value)
            )
            for target_size in {len(raw.encode("utf-8")), MAX_BODY_BYTES}:
                sized = "\n" * (target_size - len(raw.encode("utf-8"))) + raw
                parsed = parse_patch(sized)
                self.assertIsNotNone(parsed)
                canonical = render_patch(parsed)
                canonical_bytes = len(canonical.encode("utf-8"))
                with self.subTest(mask=mask, target_size=target_size):
                    self.assertLessEqual(canonical_bytes, target_size + MAX_PATCH_CANONICAL_EXPANSION_BYTES)
                    self.assertLessEqual(canonical_bytes, MAX_CANONICAL_PATCH_BYTES)

    def test_projection_only_parser_accepts_maximum_canonical_patch_and_projection_bounds(self):
        from automation.federation.request_model import _parse_projection_canonical_patch

        raw = _patch_body_of_exact_size(MAX_BODY_BYTES)
        patch = parse_patch(raw)
        canonical = render_patch(patch)
        projected_patch = _parse_projection_canonical_patch(canonical)
        self.assertEqual(len(canonical.encode("utf-8")), MAX_CANONICAL_PATCH_BYTES)
        self.assertEqual(render_patch(projected_patch), canonical)
        with self.assertRaises(RequestModelError):
            parse_patch(canonical)

        maximum_id = 9_223_372_036_854_775_807
        projection = IssuePatchProjection(
            1, maximum_id, maximum_id, maximum_id, maximum_id,
            "a" * 64, "b" * 64, projected_patch,
        )
        projection_text = projection.render()
        envelope, embedded = projection_text.split("\n\n", 1)
        self.assertEqual(len((envelope + "\n\n").encode("utf-8")), 402)
        self.assertLessEqual(402, MAX_ISSUE_PATCH_PROJECTION_ENVELOPE_BYTES)
        self.assertEqual(len(embedded.encode("utf-8")), MAX_CANONICAL_PATCH_BYTES)
        self.assertEqual(
            len(projection_text.encode("utf-8")),
            MAX_CANONICAL_PATCH_BYTES + 402,
        )
        self.assertEqual(len(projection_text.encode("utf-8")), 16_804)
        self.assertLessEqual(
            len(projection_text.encode("utf-8")),
            MAX_ISSUE_PATCH_PROJECTION_COMMENT_BYTES,
        )
        self.assertTrue(projection_text.startswith(ISSUE_PATCH_PROJECTION_MARKER + "\n"))
        self.assertEqual(parse_issue_patch_projection(projection_text), projection)

        oversized_envelope = {
            "schemaVersion": 1,
            "issueDatabaseId": 1,
            "issueNumber": 1,
            "issueAnchorCommentId": 1,
            "issueCommentId": 1,
            "issueCommentBodySha256": "a" * 1_100,
            "bindingId": "b" * 64,
        }
        over_envelope = (
            ISSUE_PATCH_PROJECTION_MARKER + "\n"
            + json.dumps(oversized_envelope, sort_keys=True, separators=(",", ":"))
            + "\n\n" + render_patch(Patch({"Description": "small"}))
        )
        with self.assertRaises(RequestModelError):
            parse_issue_patch_projection(over_envelope)
        with self.assertRaises(RequestModelError):
            parse_issue_patch_projection(projection_text + "x" * 605 + "\n")

    def test_frozen_digest_schemas_and_ordering(self):
        request = parse_request_body(RequestClass.ADD, add_body())
        expected_request = hashlib.sha256(
            "swiftstream-federation-effective-request:v1\n".encode()
            + render_request_body(request).encode("utf-8")
        ).hexdigest()
        self.assertEqual(effective_request_digest(request), expected_request)

        entries = [
            {
                "issueCommentId": 20,
                "issueCommentBodySha256": "b" * 64,
                "canonicalPatchSha256": "c" * 64,
                "projectionSha256": "d" * 64,
            },
            {
                "issueCommentId": 10,
                "issueCommentBodySha256": "e" * 64,
                "canonicalPatchSha256": "f" * 64,
                "projectionSha256": "0" * 64,
            },
        ]
        canonical_entries = sorted(entries, key=lambda item: item["issueCommentId"])
        expected_projection_digest = hashlib.sha256(
            (
                "swiftstream-federation-issue-patch-projection-evidence:v1\n"
                + json.dumps({"entries": canonical_entries}, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False)
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(patch_projection_evidence_digest(entries), expected_projection_digest)
        self.assertEqual(patch_projection_evidence_digest(entries), patch_projection_evidence_digest(reversed(entries)))
        with self.assertRaises(RequestModelError):
            patch_projection_evidence_digest([entries[0], entries[0]])
        projected_patch = parse_patch(f"{PATCH_SENTINEL}\nDescription:\nprojected\n")
        projection = IssuePatchProjection(
            1, 700, 7, 101, 11, "e" * 64, "f" * 64, projected_patch,
        )
        projection_entry = {
            "issueCommentId": 11,
            "issueCommentBodySha256": "e" * 64,
            "canonicalPatchSha256": hashlib.sha256(render_patch(projected_patch).encode()).hexdigest(),
            "projectionSha256": hashlib.sha256(projection.render().encode()).hexdigest(),
        }
        self.assertEqual(
            issue_patch_projection_evidence_digest([projection]),
            patch_projection_evidence_digest([projection_entry]),
        )

        expected_normalize = hashlib.sha256(
            (
                "swiftstream-federation-issue-head-normalize-target:v1\n"
                + json.dumps({
                    "requestMarkerBlobSha": "1" * 40,
                    "requestMarkerContentSha256": hashlib.sha256(b"add-source\n").hexdigest(),
                    "targetTreeSha": "2" * 40,
                }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            normalize_target_evidence_digest(
                request_class=RequestClass.ADD,
                request_marker_blob_sha="1" * 40,
                target_tree_sha="2" * 40,
            ),
            expected_normalize,
        )

        changed = [
            {
                "path": "skills/a",
                "state": "PRESENT",
                "mode": "100644",
                "objectType": "blob",
                "blobSha": "3" * 40,
                "contentSha256": "4" * 64,
            },
            {
                "path": "skills/b",
                "state": "ABSENT",
                "mode": None,
                "objectType": None,
                "blobSha": None,
                "contentSha256": None,
            },
        ]
        expected_proposal = hashlib.sha256(
            (
                "swiftstream-federation-issue-head-proposal-target:v1\n"
                + json.dumps({"candidateTreeSha": "5" * 40, "changed": changed},
                             ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            proposal_target_evidence_digest(
                candidate_tree_sha="5" * 40,
                changed=changed,
                candidate_changed_paths=("skills/a", "skills/b"),
            ),
            expected_proposal,
        )
        with self.assertRaises(RequestModelError):
            proposal_target_evidence_digest(
                candidate_tree_sha="5" * 40,
                changed=changed,
                candidate_changed_paths=("skills/b", "skills/a"),
            )

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
        for key, replacement in (("schemaVersion", 1), ("schemaVersion", 3), ("prNumber", True), ("initialBodySha256", "bad"), ("originalAuthorId", 4), ("originalAuthorLogin", "a\x00b")):
            candidate = dict(value)
            candidate[key] = replacement
            with self.subTest(key=key, replacement=replacement), self.assertRaises(RequestModelError):
                parse_anchor(ANCHOR_MARKER + "\n" + json.dumps(candidate) + "\n")
        with self.assertRaises(RequestModelError):
            parse_anchor("swiftstream-federation-request-anchor:v1\n" + rendered.splitlines()[1] + "\n")
        with self.assertRaises(RequestModelError):
            parse_anchor(rendered + "extra\n")
        duplicate_json = rendered.splitlines()[1].replace('"schemaVersion":2', '"schemaVersion":2,"schemaVersion":2', 1)
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
            Request(RequestClass.ADD, request.repository_url, request.description, request.branch, request.skills_root, request.skill_prefixes, reason="reason"),
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

    def test_single_line_body_still_parses_branch_and_prefixes(self):
        request = parse_request_body(RequestClass.ADD, add_body())
        self.assertEqual(request.branch, "refs/heads/main")
        self.assertEqual(request.skill_prefixes, ("swifql",))
        self.assertIsNone(request.publication_lines)
        self.assertIsNone(request.dropped_publication_lines)

    def test_publication_lines_semicolon_grammar_parses_pairs(self):
        body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/release/4=vapor4; refs/heads/main=vapor5\n"
        )
        request = parse_request_body(RequestClass.ADD, body)
        self.assertEqual(len(request.publication_lines), 2)
        self.assertEqual(request.publication_lines[0].ref, "refs/heads/release/4")
        self.assertEqual(request.publication_lines[0].skill_prefixes, ("vapor4",))
        self.assertEqual(request.publication_lines[1].ref, "refs/heads/main")
        self.assertEqual(request.publication_lines[1].skill_prefixes, ("vapor5",))
        multi = parse_request_body(
            RequestClass.ADD,
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/main=vapor5,vapor5extra\n",
        )
        self.assertEqual(multi.publication_lines[0].skill_prefixes, ("vapor5", "vapor5extra"))

    def test_publication_lines_rejects_tags_duplicate_refs_and_shared_roots(self):
        base = "Repository URL:\nhttps://github.com/vapor/vapor\nPublication lines:\n"
        for value in (
            "refs/tags/4.0.0=vapor4",
            "refs/heads/main=vapor5; refs/heads/main=vapor5",
            "refs/heads/main=vapor5; refs/heads/other=vapor5",
            "refs/heads/main=vapor-5; refs/heads/other=vapor-4",
            "",
            "refs/heads/main",
            "refs/heads/main=",
            "refs/heads/main=vapor5;",
        ):
            with self.subTest(value=value), self.assertRaises(RequestModelError):
                parse_request_body(RequestClass.ADD, base + value + "\n")

    def test_publication_lines_with_branch_requires_exact_line_match(self):
        ok = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Branch:\nrefs/heads/main\n"
            "Skill prefixes:\nvapor5\n"
            "Publication lines:\nrefs/heads/release/4=vapor4; refs/heads/main=vapor5\n"
        )
        request = parse_request_body(RequestClass.ADD, ok)
        self.assertEqual(request.branch, "refs/heads/main")
        bad = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Branch:\nrefs/heads/missing\n"
            "Publication lines:\nrefs/heads/release/4=vapor4; refs/heads/main=vapor5\n"
        )
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, bad)

    def test_dropped_publication_lines_requires_update_and_exact_set(self):
        drop_body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/main=vapor5\n"
            "Dropped publication lines:\nrefs/heads/release/4\n"
        )
        with self.assertRaises(RequestModelError):
            parse_request_body(RequestClass.ADD, drop_body)
        request = parse_request_body(RequestClass.UPDATE, drop_body)
        self.assertEqual(request.dropped_publication_lines, ("refs/heads/release/4",))
        proposed = proposed_line_refs(
            request,
            default_branch="main",
            default_prefixes=("vapor5",),
            existing_refs=("refs/heads/release/4", "refs/heads/main"),
        )
        validate_drop_set(
            RequestClass.UPDATE,
            request,
            accepted_line_refs=("refs/heads/release/4", "refs/heads/main"),
            proposed_refs=proposed,
        )
        with self.assertRaises(RequestModelError):
            validate_drop_set(
                RequestClass.UPDATE,
                request,
                accepted_line_refs=("refs/heads/release/4", "refs/heads/main", "refs/heads/other"),
                proposed_refs=proposed,
            )

    def test_drop_last_line_is_invalid(self):
        request = parse_request_body(
            RequestClass.UPDATE,
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Dropped publication lines:\nrefs/heads/main\n",
        )
        with self.assertRaises(RequestModelError):
            validate_drop_set(
                RequestClass.UPDATE,
                request,
                accepted_line_refs=("refs/heads/main",),
                proposed_refs=(),
            )

    def test_patch_can_fold_publication_and_dropped_lines(self):
        body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/release/4=vapor4; refs/heads/main=vapor5\n"
        )
        request = parse_request_body(RequestClass.UPDATE, body)
        anchor = RequestAnchor(1, RequestClass.UPDATE, "id", "login", body_sha256(body), request)
        result = fold_patch_events(
            anchor,
            [
                CommentEvent(
                    2,
                    True,
                    f"{PATCH_SENTINEL}\n\nPublication lines:\nrefs/heads/main=vapor5\n"
                    f"\nDropped publication lines:\nrefs/heads/release/4\n",
                )
            ],
        )
        self.assertEqual(result.request.publication_lines[0].ref, "refs/heads/main")
        self.assertEqual(result.request.dropped_publication_lines, ("refs/heads/release/4",))
        invalid = fold_patch_events(
            anchor,
            [CommentEvent(3, True, f"{PATCH_SENTINEL}\n\nPublication lines:\nrefs/tags/x=vapor5\n")],
        )
        self.assertEqual(invalid.request, request)
        self.assertEqual(invalid.evidence[0].kind, "invalid")

    def test_anchor_v2_round_trips_publication_and_dropped_fields(self):
        body = (
            "Repository URL:\nhttps://github.com/vapor/vapor\n"
            "Publication lines:\nrefs/heads/main=vapor5\n"
            "Dropped publication lines:\nrefs/heads/release/4\n"
        )
        request = parse_request_body(RequestClass.UPDATE, body)
        anchor = RequestAnchor(9, RequestClass.UPDATE, "42", "alice", body_sha256(body), request)
        rendered = anchor.render()
        value = json.loads(rendered.splitlines()[1])
        self.assertEqual(value["schemaVersion"], 2)
        self.assertEqual(value["initialRequest"]["Publication lines"][0]["ref"], "refs/heads/main")
        self.assertEqual(value["initialRequest"]["Dropped publication lines"], ["refs/heads/release/4"])
        self.assertEqual(parse_anchor(rendered), anchor)

    def test_anchor_v1_after_cutover_fails_closed(self):
        body = add_body()
        request = parse_request_body(RequestClass.ADD, body)
        anchor = RequestAnchor(1, RequestClass.ADD, "id", "login", body_sha256(body), request)
        value = json.loads(anchor.render().splitlines()[1])
        value["schemaVersion"] = 1
        with self.assertRaises(RequestModelError) as caught:
            parse_anchor(ANCHOR_MARKER + "\n" + json.dumps(value) + "\n")
        self.assertIn("schemaVersion", str(caught.exception))

    def test_issue_pr_request_renderer_roundtrips_only_manual_request_classes(self):
        requests = (
            parse_request_body(RequestClass.ADD, add_body()),
            parse_request_body(
                RequestClass.UPDATE,
                "Repository URL:\nhttps://github.com/Owner/Repo\nDescription:\nUpdated\n"
                "Branch:\nmain\nSkills root:\nskills\nSkill prefixes:\nswifql,docs\n"
                "Publication lines:\nrefs/heads/main=swifql,docs;refs/heads/stable=apis\n"
                "Dropped publication lines:\nrefs/heads/old,refs/heads/older\n",
            ),
            parse_request_body(RequestClass.REMOVE, "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\nretire\n"),
        )
        for request in requests:
            with self.subTest(request_class=request.request_class):
                rendered = render_request_body(request)
                self.assertTrue(rendered.endswith("\n"))
                self.assertFalse(rendered.endswith("\n\n"))
                self.assertEqual(parse_request_body(request.request_class, rendered), request)
                self.assertEqual(render_request_body(parse_request_body(request.request_class, rendered)), rendered)
        update = render_request_body(requests[1])
        self.assertIn("Skill prefixes:\nswifql,docs\n", update)
        self.assertIn("Publication lines:\nrefs/heads/main=swifql,docs;refs/heads/stable=apis\n", update)
        self.assertIn("Dropped publication lines:\nrefs/heads/old,refs/heads/older\n", update)
        add = render_request_body(requests[0])
        self.assertNotIn("Publication lines:", add)
        self.assertNotIn("Dropped publication lines:", add)
        remove = render_request_body(requests[2])
        self.assertEqual(remove, "Repository URL:\nhttps://github.com/Owner/Repo\n\nReason:\nretire\n")

    def test_issue_pr_request_renderer_rejects_non_manual_classes(self):
        reconcile = parse_request_body(RequestClass.RECONCILE, "Repository URL:\nhttps://github.com/Owner/Repo\n")
        for request in (
            reconcile,
            Request(RequestClass.MACHINE_PUBLICATION, "https://github.com/Owner/Repo"),
            Request(RequestClass.UNRELATED, "https://github.com/Owner/Repo"),
        ):
            with self.subTest(request_class=request.request_class), self.assertRaises(RequestModelError):
                render_request_body(request)


class IssueRequestAnchorModelTests(unittest.TestCase):
    @staticmethod
    def request(request_class):
        if request_class is RequestClass.REMOVE:
            body = "Repository URL:\nhttps://github.com/Owner/Repo\nReason:\nretire\n"
        else:
            body = add_body()
            if request_class is RequestClass.UPDATE:
                body = body.replace("Repository URL:", "Repository URL:", 1)
        return parse_request_body(request_class, body)

    @classmethod
    def anchor(cls, request_class=RequestClass.ADD, **changes):
        value = dict(
            schema_version=1,
            issue_number=7,
            issue_database_id=700,
            issue_node_id="I_kwDOIssueNode",
            request_class=request_class,
            original_author_id="U_kwDORequester",
            original_author_login="alice",
            initial_body_sha256="a" * 64,
            initial_request=cls.request(request_class),
            source_id="owner-repo",
            source_repository_id=41,
            source_canonical_full_name="Owner/Repo",
            source_identity_kind="proposed" if request_class is RequestClass.ADD else "accepted",
            anchor_observed_last_edited_at=None,
            anchor_observed_includes_created_edit=False,
        )
        value.update(changes)
        return IssueRequestAnchor(**value)

    def test_add_update_remove_exact_render_parse_roundtrip(self):
        for request_class in (RequestClass.ADD, RequestClass.UPDATE, RequestClass.REMOVE):
            anchor = self.anchor(request_class)
            rendered = anchor.render()
            self.assertEqual(rendered.splitlines()[0], ISSUE_REQUEST_ANCHOR_MARKER)
            self.assertTrue(rendered.endswith("\n"))
            self.assertEqual(parse_issue_request_anchor(rendered), anchor)

    def test_canonical_json_exact_key_order_and_digest(self):
        anchor = self.anchor()
        rendered = anchor.render()
        json_line = rendered.splitlines()[1]
        value = json.loads(json_line)
        self.assertEqual(set(value), {
            "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId", "requestClass",
            "originalAuthorId", "originalAuthorLogin", "initialBodySha256", "initialRequest",
            "sourceId", "sourceRepositoryId", "sourceCanonicalFullName", "sourceIdentityKind",
            "anchorObservedLastEditedAt", "anchorObservedIncludesCreatedEdit",
        })
        self.assertEqual(list(value), sorted(value))
        self.assertEqual(anchor.canonical_sha256(), hashlib.sha256(rendered.encode("utf-8")).hexdigest())
        self.assertEqual(anchor.canonical_sha256(), self.anchor().canonical_sha256())
        self.assertNotEqual(anchor.canonical_sha256(), self.anchor(issue_number=8).canonical_sha256())

    def test_noncanonical_json_order_whitespace_and_extra_keys_are_rejected(self):
        anchor = self.anchor()
        value = anchor.as_value()
        with self.assertRaises(RequestModelError):
            parse_issue_request_anchor(ISSUE_REQUEST_ANCHOR_MARKER + "\n" + json.dumps(value) + "\n")


        reversed_value = dict(reversed(list(value.items())))
        with self.assertRaises(RequestModelError):
            parse_issue_request_anchor(ISSUE_REQUEST_ANCHOR_MARKER + "\n" + json.dumps(reversed_value, separators=(",", ":")) + "\n")
        for candidate in (dict(value, extra=True), {key: val for key, val in value.items() if key != "sourceId"}):
            with self.subTest(candidate=candidate), self.assertRaises(RequestModelError):
                parse_issue_request_anchor(ISSUE_REQUEST_ANCHOR_MARKER + "\n" + json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\n")

    def test_schema_class_and_source_identity_kinds_are_closed(self):
        anchor = self.anchor()
        value = anchor.as_value()
        for schema in (True, "1", 2):
            candidate = dict(value, schemaVersion=schema)
            with self.subTest(schema=schema), self.assertRaises(RequestModelError):
                parse_issue_request_anchor(ISSUE_REQUEST_ANCHOR_MARKER + "\n" + json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\n")
        for request_class in ("reconcile-source", "machine-publication", "unknown"):
            candidate = dict(value, requestClass=request_class)
            with self.subTest(request_class=request_class), self.assertRaises(RequestModelError):
                parse_issue_request_anchor(ISSUE_REQUEST_ANCHOR_MARKER + "\n" + json.dumps(candidate, sort_keys=True, separators=(",", ":")) + "\n")
        with self.assertRaises(RequestModelError):
            self.anchor(source_identity_kind="accepted")
        with self.assertRaises(RequestModelError):
            self.anchor(RequestClass.UPDATE, source_identity_kind="proposed")
        with self.assertRaises(RequestModelError):
            self.anchor(RequestClass.REMOVE, source_identity_kind="proposed")

    def test_integer_boolean_and_bounds_are_strict(self):
        for field in ("issue_number", "issue_database_id"):
            for bad in (True, 0, -1, 9_223_372_036_854_775_808):
                with self.subTest(field=field, bad=bad), self.assertRaises(RequestModelError):
                    self.anchor(**{field: bad})
        self.assertEqual(self.anchor(issue_number=9_223_372_036_854_775_807).issue_number, 9_223_372_036_854_775_807)

    def test_node_requester_source_and_full_name_bounds(self):
        for field, bad in (
            ("issue_node_id", ""), ("issue_node_id", "x" * 257), ("issue_node_id", "bad\nnode"),
            ("original_author_id", ""), ("original_author_id", "x" * 257), ("original_author_id", "bad\x00id"),
            ("original_author_login", ""), ("original_author_login", "x" * 101), ("original_author_login", "bad\tlogin"),
            ("source_id", "Bad_ID"), ("source_id", ""), ("source_repository_id", True),
            ("source_repository_id", 0), ("source_canonical_full_name", "owner"),
            ("source_canonical_full_name", "/repo"), ("source_canonical_full_name", "owner/"),
            ("source_canonical_full_name", "a/b/c"), ("source_canonical_full_name", "x" * 257),
            ("source_canonical_full_name", "owner/ba\nd"),
        ):
            with self.subTest(field=field, bad=bad), self.assertRaises(RequestModelError):
                self.anchor(**{field: bad})

    def test_hash_request_class_and_timestamp_invariants(self):
        with self.assertRaises(RequestModelError):
            self.anchor(initial_body_sha256="A" * 64)
        update_request = self.request(RequestClass.UPDATE)
        with self.assertRaises(RequestModelError):
            self.anchor(initial_request=update_request)
        self.assertIsNone(self.anchor(anchor_observed_last_edited_at=None).anchor_observed_last_edited_at)
        timestamp = "2026-10-04T12:30:00+03:00"
        self.assertEqual(self.anchor(anchor_observed_last_edited_at=timestamp).anchor_observed_last_edited_at, timestamp)
        for bad in ("2026-10-04T12:30:00", "not-a-date", "", 3, "x" * 129, "2026-10-04T12:30:00Z\n"):
            with self.subTest(timestamp=bad), self.assertRaises(RequestModelError):
                self.anchor(anchor_observed_last_edited_at=bad)
        with self.assertRaises(RequestModelError):
            self.anchor(anchor_observed_includes_created_edit=1)

    def test_extra_lines_wrong_marker_body_bound_and_controls_rejected(self):
        rendered = self.anchor().render()
        for invalid in (
            rendered + "extra\n",
            "wrong marker\n" + rendered.split("\n", 1)[1],
            rendered.replace("\n", "\n\n", 1),
            rendered + "x" * 16_400,
            rendered.replace("Owner/Repo", "Owner/Bad\x00Repo"),
        ):
            with self.subTest(sample=invalid[:100]), self.assertRaises(RequestModelError):
                parse_issue_request_anchor(invalid)

    def test_valid_timestamp_z_and_authority_field_changes_change_digest(self):
        base = self.anchor(anchor_observed_last_edited_at="2026-10-04T12:30:00Z", anchor_observed_includes_created_edit=True)
        alternatives = (
            self.anchor(issue_database_id=701), self.anchor(issue_node_id="I_kwDOOther"),
            self.anchor(original_author_id="U_kwDOOther"), self.anchor(original_author_login="bob"),
            self.anchor(initial_body_sha256="b" * 64), self.anchor(source_id="other-source"),
            self.anchor(source_repository_id=42), self.anchor(source_canonical_full_name="Other/Repo"),
            self.anchor(anchor_observed_last_edited_at="2026-10-05T12:30:00Z"),
            self.anchor(anchor_observed_includes_created_edit=True),
        )
        self.assertIsNotNone(base.anchor_observed_last_edited_at)
        self.assertTrue(all(item.canonical_sha256() != self.anchor().canonical_sha256() for item in alternatives))

    def test_issue_patch_event_requires_strict_identity_and_flags(self):
        for args in ((True, True, False, "x"), (1, 1, False, "x"), (1, True, 0, "x"), (1, True, False, 5), (1, True, False, "x" * 16_385)):
            with self.subTest(args=args), self.assertRaises(RequestModelError):
                IssuePatchEvent(*args)

    def test_issue_patch_fold_orders_authorizes_classifies_and_composes(self):
        anchor = self.anchor()
        events = [
            IssuePatchEvent(30, True, False, f"{PATCH_SENTINEL}\n\nBranch:\nrelease\n"),
            IssuePatchEvent(10, True, False, f"{PATCH_SENTINEL}\n\nDescription:\nfirst\n"),
            IssuePatchEvent(20, True, False, f"{PATCH_SENTINEL}\n\nDescription:\nsecond\n"),
        ]
        folded = fold_issue_patch_events(anchor, events)
        self.assertEqual(folded.request.description, "second")
        self.assertEqual(folded.request.branch, "refs/heads/release")
        self.assertEqual([(item.comment_id, item.kind) for item in folded.evidence], [(10, "applied"), (20, "applied"), (30, "applied")])
        self.assertEqual(folded, fold_issue_patch_events(anchor, reversed(events)))
        with self.assertRaises(RequestModelError):
            fold_issue_patch_events(anchor, [events[0], events[0]])

    def test_issue_patch_fold_invalid_unauthorized_edited_discussion_remove_and_semantics(self):
        anchor = self.anchor()
        discussion = IssuePatchEvent(1, True, False, "ordinary comment")
        invalid = IssuePatchEvent(2, True, False, f"{PATCH_SENTINEL}\n\nUnknown:\nx\n")
        unauthorized = IssuePatchEvent(3, False, False, f"{PATCH_SENTINEL}\n\nDescription:\nno\n")
        edited = IssuePatchEvent(4, True, True, f"{PATCH_SENTINEL}\n\nDescription:\nedited\n")
        semantic = IssuePatchEvent(5, True, False, f"{PATCH_SENTINEL}\n\nBranch:\nblocked\n")
        folded = fold_issue_patch_events(anchor, [discussion, invalid, unauthorized, edited, semantic], lambda request: request.branch != "refs/heads/blocked")
        self.assertEqual(folded.request, anchor.initial_request)
        self.assertEqual([(item.comment_id, item.kind) for item in folded.evidence], [
            (2, "invalid"), (3, "unauthorized"), (4, "invalid"), (5, "semantic-invalid")
        ])
        remove = self.anchor(RequestClass.REMOVE)
        result = fold_issue_patch_events(remove, [IssuePatchEvent(9, True, False, f"{PATCH_SENTINEL}\n\nDescription:\nx\n")])
        self.assertEqual(result.evidence[0].kind, "invalid")
        self.assertEqual(result.request, remove.initial_request)

    def test_repository_url_is_not_patchable_and_existing_pr_fold_is_unchanged(self):
        anchor = self.anchor()
        event = IssuePatchEvent(12, True, False, f"{PATCH_SENTINEL}\n\nRepository URL:\nhttps://github.com/Evil/Repo\n")
        result = fold_issue_patch_events(anchor, [event])
        self.assertEqual(result.request.repository_url, anchor.initial_request.repository_url)
        self.assertEqual(result.evidence[0].kind, "invalid")
        old_request = RequestModelTests()
        pr_anchor = RequestAnchor(1, RequestClass.ADD, "id", "login", "0" * 64, self.request(RequestClass.ADD))
        old = fold_patch_events(pr_anchor, [CommentEvent(2, True, f"{PATCH_SENTINEL}\n\nDescription:\nold-path\n")])
        self.assertEqual(old.request.description, "old-path")


class IssuePRBindingModelTests(unittest.TestCase):
    @staticmethod
    def values():
        return {
            "issue_number": 7,
            "issue_database_id": 700,
            "issue_node_id": "I_kwDOIssue",
            "issue_request_anchor_comment_database_id": 701,
            "issue_request_anchor_sha256": "a" * 64,
            "issue_branch_lease_comment_database_id": 702,
            "issue_branch_lease_sha256": "b" * 64,
            "source_id": "owner-repo",
            "source_repository_id": 41,
            "branch_ref": issue_branch_ref(7),
            "pull_request_number": 8,
            "pull_request_database_id": 800,
            "pull_request_node_id": "PR_kwDOPullRequest",
            "initial_head_sha": "c" * 40,
            "base_ref": "main",
            "central_repository_node_id": "R_kwDOCentral",
        }

    def test_reserved_issue_branch_classifier_is_exact_and_fail_closed(self):
        self.assertEqual(reserved_issue_branch_number("bot/federation/request/issue-1"), 1)
        self.assertEqual(reserved_issue_branch_number("bot/federation/request/issue-9223372036854775807"), 9_223_372_036_854_775_807)
        for ordinary in ("main", "bot/federation/demo", "refs/heads/ordinary", "bot/federation/requester/issue-1"):
            with self.subTest(ordinary=ordinary):
                self.assertIsNone(reserved_issue_branch_number(ordinary))
        for malformed in (
            "bot/federation/request/issue-0",
            "bot/federation/request/issue-01",
            "bot/federation/request/issue-+1",
            "bot/federation/request/issue-9223372036854775808",
            "bot/federation/request/issue-1-junk",
            "bot/federation/request/issue-",
            "bot/federation/request/issue-1\n",
            "refs/heads/bot/federation/request/issue-1",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(RequestModelError):
                reserved_issue_branch_number(malformed)

    def test_two_sided_binding_has_one_canonical_payload_and_exact_artifact_hashes(self):
        binding = IssuePRBinding.create(**self.values())
        issue_text = binding.render_issue_binding()
        pr_text = binding.render_pr_origin_binding()
        issue_value = json.loads(issue_text.splitlines()[1])
        pr_value = json.loads(pr_text.splitlines()[1])
        self.assertEqual(issue_text.splitlines()[0], ISSUE_INTERNAL_PR_BINDING_MARKER)
        self.assertEqual(pr_text.splitlines()[0], PR_ISSUE_ORIGIN_BINDING_MARKER)
        self.assertEqual(issue_value, pr_value)
        self.assertEqual(set(issue_value), {
            "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
            "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
            "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "sourceId",
            "sourceRepositoryId", "branchRef", "pullRequestNumber", "pullRequestDatabaseId",
            "pullRequestNodeId", "initialHeadSha", "baseRef", "centralRepositoryNodeId", "bindingId",
        })
        payload = dict(issue_value)
        binding_id = payload.pop("bindingId")
        canonical_payload = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        self.assertEqual(binding_id, hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest())
        self.assertEqual(parse_issue_internal_pr_binding(issue_text), binding)
        self.assertEqual(parse_pr_issue_origin_binding(pr_text), binding)
        self.assertEqual(binding.issue_comment_sha256(), hashlib.sha256(issue_text.encode("utf-8")).hexdigest())
        self.assertEqual(binding.pr_comment_sha256(), hashlib.sha256(pr_text.encode("utf-8")).hexdigest())
        self.assertNotEqual(binding.issue_comment_sha256(), binding.pr_comment_sha256())

    def test_binding_rejects_wrong_relations_ids_nodes_hashes_and_base(self):
        cases = (
            {"branch_ref": issue_branch_ref(8)},
            {"issue_database_id": True},
            {"pull_request_number": 0},
            {"pull_request_database_id": "800"},
            {"issue_node_id": "I:bad"},
            {"pull_request_node_id": "PR:bad"},
            {"central_repository_node_id": "R:bad"},
            {"issue_request_anchor_sha256": "A" * 64},
            {"issue_branch_lease_sha256": "x" * 64},
            {"initial_head_sha": "C" * 40},
            {"base_ref": "trunk"},
            {"source_id": "Owner/Repo"},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(RequestModelError):
                IssuePRBinding.create(**dict(self.values(), **changes))

    def test_binding_parsers_reject_noncanonical_json_wrong_marker_and_key_sets(self):
        binding = IssuePRBinding.create(**self.values())
        issue_text = binding.render_issue_binding()
        value = json.loads(issue_text.splitlines()[1])
        with self.assertRaises(RequestModelError):
            parse_pr_issue_origin_binding(issue_text)
        with self.assertRaises(RequestModelError):
            parse_issue_internal_pr_binding(issue_text.replace("\n", "\r\n"))
        noncanonical = ISSUE_INTERNAL_PR_BINDING_MARKER + "\n" + json.dumps(value) + "\n"
        with self.assertRaises(RequestModelError):
            parse_issue_internal_pr_binding(noncanonical)
        for changed in (dict(value, extra=True), {key: item for key, item in value.items() if key != "sourceId"}):
            with self.subTest(changed=changed), self.assertRaises(RequestModelError):
                parse_issue_internal_pr_binding(
                    ISSUE_INTERNAL_PR_BINDING_MARKER + "\n"
                    + json.dumps(changed, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
                )


class ClaimedHeadAndIssueLeaseModelTests(unittest.TestCase):
    @staticmethod
    def marker(**changes):
        fields = dict(
            claim_kind="ISSUE_BRANCH_LEASE",
            role="ISSUE_ACTIVE",
            owner_kind="ISSUE",
            owner_key="R_central:700:I_kwDOIssue:7",
            claim_generation_id="1" * 64,
            carrier_nonce="2" * 64,
            transition_kind="INITIAL",
        )
        fields.update(changes)
        return ClaimedHeadMarker(**fields)

    @staticmethod
    def lease(**changes):
        fields = dict(
            schema_version=1,
            issue_number=7,
            issue_database_id=700,
            issue_node_id="I_kwDOIssue",
            issue_request_anchor_comment_database_id=101,
            issue_request_anchor_sha256="a" * 64,
            source_id="owner-repo",
            source_repository_id=41,
            central_repository_node_id="R_central",
            branch_ref="refs/heads/bot/federation/request/issue-7",
            accepted_base_sha="1" * 40,
            carrier_role="ISSUE_ACTIVE",
            claim_kind="ISSUE_BRANCH_LEASE",
            claim_generation_id="b" * 64,
            carrier_nonce="c" * 64,
            authority_preimage_digest="d" * 64,
            initial_head_sha="e" * 40,
            initial_head_tree_sha="f" * 40,
            initial_head_parent_sha="1" * 40,
            initial_head_marker_digest="9" * 64,
            request_class=RequestClass.ADD,
        )
        fields.update(changes)
        return IssueBranchLease.create(**fields)

    @staticmethod
    def authority_fields(**changes):
        fields = dict(
            accepted_base_sha="1" * 40,
            accepted_base_tree_sha="a" * 40,
            branch_ref="refs/heads/bot/federation/request/issue-7",
            central_repository_node_id="R_central",
            owner_key="R_central:700:I_kwDOIssue:7",
            issue_request_anchor_sha256="b" * 64,
            request_class=RequestClass.ADD,
            source_canonical_full_name="Owner/Repo",
            source_id="owner-repo",
            source_identity_kind="proposed",
            source_repository_id=41,
        )
        fields.update(changes)
        return fields

    def authority_digest(self, **changes):
        return issue_branch_lease_authority_digest(**self.authority_fields(**changes))

    def generation(self, **changes):
        fields = dict(
            authority_preimage_digest="3" * 64,
            carrier_nonce="4" * 64,
            central_repository_node_id="R_central",
            owner_key="R_central:700:I_kwDOIssue:7",
            from_head_sha="1" * 40,
            from_tree_sha="a" * 40,
        )
        fields.update(changes)
        return claim_generation_id(**fields)

    def test_marker_exact_render_roundtrip_and_excludes_derived_identifiers(self):
        marker = self.marker()
        expected = (
            f"{CLAIMED_HEAD_MARKER_HEADER}\n"
            "claim-kind=ISSUE_BRANCH_LEASE\nrole=ISSUE_ACTIVE\nowner-kind=ISSUE\n"
            "owner-key=R_central:700:I_kwDOIssue:7\n"
            f"generation={'1' * 64}\nnonce={'2' * 64}\ntransition=INITIAL\n"
        )
        self.assertEqual(marker.render(), expected)
        self.assertEqual(parse_claimed_head_marker(expected), marker)
        for forbidden in ("leaseId", "initialHeadSha", "targetHeadSha", "claimId", "epochId", "fenceId"):
            self.assertNotIn(forbidden, marker.render())

    def test_marker_strictly_rejects_field_order_unknown_fields_and_bad_values(self):
        rendered = self.marker().render()
        invalid = [
            rendered.replace("claim-kind=ISSUE_BRANCH_LEASE\nrole=ISSUE_ACTIVE", "role=ISSUE_ACTIVE\nclaim-kind=ISSUE_BRANCH_LEASE"),
            rendered.replace("transition=INITIAL\n", "transition=INITIAL\nextra=x\n"),
            rendered.replace("owner-kind=ISSUE\n", ""),
            rendered.replace("claim-kind=ISSUE_BRANCH_LEASE", "claim-kind=FUTURE"),
            rendered.replace("role=ISSUE_ACTIVE", "role=FUTURE"),
            rendered.replace("owner-kind=ISSUE", "owner-kind=FUTURE"),
            rendered.replace("generation=" + "1" * 64, "generation=" + "A" * 64),
            rendered.replace("nonce=" + "2" * 64, "nonce=" + "2" * 63),
            rendered.replace("transition=INITIAL", "transition=bad"),
            rendered.rstrip("\n"),
        ]
        for value in invalid:
            with self.subTest(value=value[:40]), self.assertRaises(RequestModelError):
                parse_claimed_head_marker(value)

    def test_owner_key_exact_format_and_all_components_bind(self):
        expected = "R_central:700:I_kwDOIssue:7"
        self.assertEqual(issue_owner_key("R_central", 700, "I_kwDOIssue", 7), expected)
        variants = (
            issue_owner_key("R_other", 700, "I_kwDOIssue", 7),
            issue_owner_key("R_central", 701, "I_kwDOIssue", 7),
            issue_owner_key("R_central", 700, "I_kwDOIssue2", 7),
            issue_owner_key("R_central", 700, "I_kwDOIssue", 8),
        )
        self.assertEqual(len(set(variants + (expected,))), 5)
        for args in (("R:bad", 700, "I_kwDOIssue", 7), ("R_central", True, "I_kwDOIssue", 7),
                     ("R_central", 700, "I:bad", 7)):
            with self.subTest(args=args), self.assertRaises(RequestModelError):
                issue_owner_key(*args)
        self.assertEqual(issue_branch_ref(7), "refs/heads/bot/federation/request/issue-7")

    def test_authority_digest_matches_canonical_golden_and_each_authority_field(self):
        fields = self.authority_fields()
        expected_preimage = (
            "swiftstream-federation-issue-branch-lease-authority:v1\n"
            + json.dumps({
                "acceptedBaseSha": fields["accepted_base_sha"],
                "acceptedBaseTreeSha": fields["accepted_base_tree_sha"],
                "branchRef": fields["branch_ref"],
                "centralRepositoryNodeId": fields["central_repository_node_id"],
                "issueOwnerKey": fields["owner_key"],
                "issueRequestAnchorSha256": fields["issue_request_anchor_sha256"],
                "requestClass": fields["request_class"].value,
                "sourceCanonicalFullName": fields["source_canonical_full_name"],
                "sourceId": fields["source_id"],
                "sourceIdentityKind": fields["source_identity_kind"],
                "sourceRepositoryId": fields["source_repository_id"],
            }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        ).encode("utf-8")
        expected_digest = hashlib.sha256(expected_preimage).hexdigest()
        self.assertEqual(expected_digest, "1e96e22dfaa8d298c3f0a246d5eac93a92f70c95e9a45eac04e0f09482c21b52")
        self.assertEqual(self.authority_digest(), expected_digest)
        self.assertEqual(self.authority_digest(), self.authority_digest())
        changes = (
            {"accepted_base_sha": "2" * 40}, {"accepted_base_tree_sha": "b" * 40},
            {"branch_ref": issue_branch_ref(8), "owner_key": "R_central:700:I_kwDOIssue:8"},
            {"central_repository_node_id": "R_other", "owner_key": "R_other:700:I_kwDOIssue:7"},
            {"owner_key": "R_central:701:I_kwDOIssue:7"},
            {"issue_request_anchor_sha256": "c" * 64},
            {"request_class": RequestClass.UPDATE, "source_identity_kind": "accepted"},
            {"source_canonical_full_name": "Other/Repo"},
            {"source_id": "other-repo"}, {"source_identity_kind": "accepted"},
            {"source_repository_id": 42},
        )
        for change in changes:
            with self.subTest(change=change):
                self.assertNotEqual(self.authority_digest(**change), self.authority_digest())
        invalid = (
            {"branch_ref": "not-a-ref"},
            {"branch_ref": issue_branch_ref(8)},
            {"owner_key": "R_central:700:I_kwDOIssue"},
            {"owner_key": "R_other:700:I_kwDOIssue:7"},
            {"owner_key": "R_central:0700:I_kwDOIssue:7"},
            {"source_canonical_full_name": "/Repo"},
            {"source_canonical_full_name": "Owner/"},
        )
        for change in invalid:
            with self.subTest(invalid_change=change), self.assertRaises(RequestModelError):
                self.authority_digest(**change)
        # Nonce and target-head data are deliberately not accepted by this preimage function.
        with self.assertRaises(TypeError):
            self.authority_digest(carrier_nonce="f" * 64)
        with self.assertRaises(TypeError):
            self.authority_digest(initial_head_sha="e" * 40)

    def test_generation_matches_golden_and_binds_every_generation_semantic(self):
        fields = dict(
            authorityPreimageDigest="3" * 64,
            carrierNonce="4" * 64,
            centralRepositoryNodeId="R_central",
            claimKind="ISSUE_BRANCH_LEASE",
            fromHeadSha="1" * 40,
            fromTreeSha="a" * 40,
            ownerKey="R_central:700:I_kwDOIssue:7",
            ownerKind="ISSUE",
            role="ISSUE_ACTIVE",
            transitionKind="INITIAL",
        )
        expected = hashlib.sha256((CLAIM_GENERATION_PREFIX + json.dumps(
            fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        )).encode("utf-8")).hexdigest()
        self.assertEqual(self.generation(), expected)
        variants = (
            {"authority_preimage_digest": "5" * 64}, {"carrier_nonce": "6" * 64},
            {"central_repository_node_id": "R_other"}, {"claim_kind": "ISSUE_HEAD_CLAIM"},
            {"from_head_sha": "2" * 40}, {"from_tree_sha": "b" * 40},
            {"owner_key": "R_other:700:I_kwDOIssue:7"}, {"owner_kind": "MACHINE_SOURCE"},
            {"role": "ISSUE_FINALIZING"}, {"transition_kind": "RETRY"},
        )
        for change in variants:
            with self.subTest(change=change):
                self.assertNotEqual(self.generation(**change), self.generation())
        self.assertNotEqual(self.generation(), self.generation(carrier_nonce="5" * 64))
        with self.assertRaises(TypeError):
            self.generation(initial_head_sha="e" * 40)

    def test_issue_branch_lease_canonical_roundtrip_keys_digest_and_id(self):
        lease = self.lease()
        rendered = lease.render()
        self.assertTrue(rendered.startswith(ISSUE_BRANCH_LEASE_MARKER + "\n"))
        self.assertEqual(parse_issue_branch_lease(rendered), lease)
        value = json.loads(rendered.splitlines()[1])
        self.assertEqual(set(value), {
            "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
            "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256", "sourceId",
            "sourceRepositoryId", "centralRepositoryNodeId", "branchRef", "acceptedBaseSha",
            "carrierRole", "claimKind", "claimGenerationId", "carrierNonce",
            "authorityPreimageDigest", "initialHeadSha", "initialHeadTreeSha",
            "initialHeadParentSha", "initialHeadMarkerDigest", "requestClass", "leaseId",
        })
        self.assertEqual(list(value), sorted(value))
        body = dict(value)
        lease_id = body.pop("leaseId")
        self.assertEqual(lease_id, hashlib.sha256(json.dumps(body, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode()).hexdigest())
        self.assertEqual(lease.canonical_sha256(), hashlib.sha256(rendered.encode()).hexdigest())
        self.assertEqual(lease.canonical_sha256(), self.lease().canonical_sha256())

    def test_issue_branch_lease_rejects_extra_missing_noncanonical_and_mismatched_fields(self):
        lease = self.lease()
        base = json.loads(lease.render().splitlines()[1])
        invalid = []
        for key, value in (("extra", "x"), ("carrierNonce", "A" * 64), ("carrierRole", "ISSUE_CANCEL"),
                           ("claimKind", "ISSUE_HEAD_CLAIM"), ("branchRef", "refs/heads/other"),
                           ("initialHeadParentSha", "2" * 40), ("issueRequestAnchorSha256", "bad"),
                           ("initialHeadMarkerDigest", "bad"), ("leaseId", "0" * 64),
                           ("schemaVersion", True)):
            value = dict(base)
            value[key] = value.get(key, "x")
            if key == "extra":
                value[key] = "x"
            elif key == "carrierNonce":
                value[key] = "A" * 64
            elif key == "carrierRole":
                value[key] = "ISSUE_CANCEL"
            elif key == "claimKind":
                value[key] = "ISSUE_HEAD_CLAIM"
            elif key == "branchRef":
                value[key] = "refs/heads/other"
            elif key == "initialHeadParentSha":
                value[key] = "2" * 40
            elif key == "issueRequestAnchorSha256":
                value[key] = "bad"
            elif key == "initialHeadMarkerDigest":
                value[key] = "bad"
            elif key == "leaseId":
                value[key] = "0" * 64
            else:
                value[key] = True
            invalid.append(ISSUE_BRANCH_LEASE_MARKER + "\n" + json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        missing = dict(base)
        missing.pop("carrierNonce")
        invalid.append(ISSUE_BRANCH_LEASE_MARKER + "\n" + json.dumps(missing, sort_keys=True, separators=(",", ":")) + "\n")
        for text in invalid:
            with self.subTest(text=text[:80]), self.assertRaises(RequestModelError):
                parse_issue_branch_lease(text)

    def test_changing_lease_authority_fields_changes_lease_id(self):
        original = self.lease()
        variants = (
            {"issue_number": 8, "branch_ref": "refs/heads/bot/federation/request/issue-8"},
            {"issue_database_id": 701}, {"issue_node_id": "I_other"},
            {"issue_request_anchor_comment_database_id": 102},
            {"issue_request_anchor_sha256": "2" * 64}, {"source_id": "other-repo"},
            {"source_repository_id": 42}, {"central_repository_node_id": "R_other"},
            {"accepted_base_sha": "2" * 40, "initial_head_parent_sha": "2" * 40},
            {"claim_generation_id": "2" * 64}, {"carrier_nonce": "2" * 64},
            {"authority_preimage_digest": "2" * 64}, {"initial_head_sha": "2" * 40},
            {"initial_head_tree_sha": "2" * 40}, {"initial_head_marker_digest": "2" * 64},
            {"request_class": RequestClass.UPDATE},
        )
        for change in variants:
            with self.subTest(change=change):
                self.assertNotEqual(self.lease(**change).lease_id, original.lease_id)


class IssueHeadClaimModelTests(unittest.TestCase):
    @staticmethod
    def claim_fields(**changes):
        fields = dict(
            issue_number=7,
            issue_database_id=700,
            issue_node_id="I_kwDOIssue",
            issue_request_anchor_comment_database_id=101,
            issue_request_anchor_sha256="a" * 64,
            issue_branch_lease_comment_database_id=102,
            issue_branch_lease_sha256="b" * 64,
            binding_id="c" * 64,
            source_id="owner-repo",
            source_repository_id=41,
            pull_request_number=8,
            pull_request_database_id=800,
            pull_request_node_id="PR_kwDOPull",
            central_repository_node_id="R_central",
            branch_ref="refs/heads/bot/federation/request/issue-7",
            request_class=RequestClass.ADD,
            accepted_base_sha="1" * 40,
            accepted_base_tree_sha="2" * 40,
            from_head_sha="3" * 40,
            from_tree_sha="4" * 40,
            to_head_sha="5" * 40,
            to_tree_sha="6" * 40,
            transition_kind="PROPOSAL",
            carrier_nonce="7" * 64,
            effective_request_digest="8" * 64,
            patch_projection_evidence_digest="9" * 64,
            target_evidence_digest="0" * 64,
        )
        fields.update(changes)
        return fields

    def claim(self, **changes):
        return IssueHeadClaim.create(**self.claim_fields(**changes))

    def test_exact_revised_schema_canonical_roundtrip_and_independent_ids(self):
        claim = self.claim()
        rendered = claim.render()
        self.assertTrue(rendered.startswith(ISSUE_HEAD_CLAIM_MARKER + "\n"))
        self.assertEqual(parse_issue_head_claim(rendered), claim)
        value = json.loads(rendered.splitlines()[1])
        self.assertEqual(set(value), {
            "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
            "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
            "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "bindingId",
            "sourceId", "sourceRepositoryId", "pullRequestNumber", "pullRequestDatabaseId",
            "pullRequestNodeId", "centralRepositoryNodeId", "branchRef", "requestClass",
            "acceptedBaseSha", "acceptedBaseTreeSha", "fromHeadSha", "fromTreeSha",
            "toHeadSha", "toTreeSha", "carrierRole", "claimKind", "claimGenerationId",
            "transitionKind", "carrierNonce", "effectiveRequestDigest",
            "patchProjectionEvidenceDigest", "targetEvidenceDigest", "authorityPreimageDigest",
            "markerDigest", "claimId",
        })
        self.assertEqual(list(value), sorted(value))
        final_without_id = dict(value)
        claim_id = final_without_id.pop("claimId")
        self.assertEqual(
            claim_id,
            hashlib.sha256(json.dumps(
                final_without_id, ensure_ascii=False, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")).hexdigest(),
        )
        expected_preimage_keys = {
            "schemaVersion", "issueNumber", "issueDatabaseId", "issueNodeId",
            "issueRequestAnchorCommentDatabaseId", "issueRequestAnchorSha256",
            "issueBranchLeaseCommentDatabaseId", "issueBranchLeaseSha256", "bindingId",
            "sourceId", "sourceRepositoryId", "pullRequestNumber", "pullRequestDatabaseId",
            "pullRequestNodeId", "centralRepositoryNodeId", "branchRef", "requestClass",
            "transitionKind", "acceptedBaseSha", "acceptedBaseTreeSha", "fromHeadSha",
            "fromTreeSha", "effectiveRequestDigest", "patchProjectionEvidenceDigest",
            "targetEvidenceDigest",
        }
        preimage = claim.authority_preimage_value()
        self.assertEqual(set(preimage), expected_preimage_keys)
        expected_authority = hashlib.sha256(
            (
                "swiftstream-federation-issue-head-claim-authority:v1\n"
                + json.dumps(preimage, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False)
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(issue_head_claim_authority_digest(claim), expected_authority)
        self.assertEqual(claim.authority_preimage_digest, expected_authority)
        retargeted = self.claim(to_head_sha="f" * 40, to_tree_sha="e" * 40)
        fresh_nonce = self.claim(carrier_nonce="6" * 64)
        self.assertEqual(issue_head_claim_authority_digest(retargeted), expected_authority)
        self.assertEqual(issue_head_claim_authority_digest(fresh_nonce), expected_authority)
        changed_nested = self.claim(effective_request_digest="5" * 64)
        self.assertNotEqual(issue_head_claim_authority_digest(changed_nested), expected_authority)

    def test_historical_claim_replays_from_stored_values_and_rejects_tampering(self):
        historical = self.claim(transition_kind="PROPOSAL")
        saved = historical.render()
        later_patch_digest = "d" * 64
        later_main_sha = "e" * 40
        later_main_tree = "f" * 40
        self.assertEqual(parse_issue_head_claim(saved), historical)
        self.assertEqual(issue_head_claim_authority_digest(historical), historical.authority_preimage_digest)
        self.assertNotEqual(later_patch_digest, historical.patch_projection_evidence_digest)
        self.assertNotEqual(later_main_sha, historical.accepted_base_sha)
        self.assertNotEqual(later_main_tree, historical.accepted_base_tree_sha)
        for key, replacement in (
            ("acceptedBaseTreeSha", "e" * 40),
            ("effectiveRequestDigest", "d" * 64),
            ("patchProjectionEvidenceDigest", "d" * 64),
            ("targetEvidenceDigest", "d" * 64),
        ):
            value = json.loads(saved.splitlines()[1])
            value[key] = replacement
            tampered = ISSUE_HEAD_CLAIM_MARKER + "\n" + json.dumps(
                value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
            ) + "\n"
            with self.subTest(key=key), self.assertRaises(RequestModelError):
                parse_issue_head_claim(tampered)

    def test_fresh_progression_patch_precedes_main_and_normalize_proposal(self):
        proposal = self.claim(transition_kind="PROPOSAL")
        both_changed = classify_issue_head_claim_progression(
            proposal,
            fresh_effective_request_digest="d" * 64,
            fresh_patch_projection_evidence_digest="9" * 64,
            fresh_accepted_base_sha="e" * 40,
            fresh_accepted_base_tree_sha="f" * 40,
            proposal_exists=True,
        )
        self.assertEqual(both_changed, "PATCH_REGENERATION")
        main_changed = classify_issue_head_claim_progression(
            proposal,
            fresh_effective_request_digest=proposal.effective_request_digest,
            fresh_patch_projection_evidence_digest=proposal.patch_projection_evidence_digest,
            fresh_accepted_base_sha="e" * 40,
            fresh_accepted_base_tree_sha="f" * 40,
            proposal_exists=True,
        )
        self.assertEqual(main_changed, "MAIN_ADVANCE")
        normalized = self.claim(transition_kind="NORMALIZE")
        self.assertEqual(
            classify_issue_head_claim_progression(
                normalized,
                fresh_effective_request_digest=normalized.effective_request_digest,
                fresh_patch_projection_evidence_digest=normalized.patch_projection_evidence_digest,
                fresh_accepted_base_sha=normalized.accepted_base_sha,
                fresh_accepted_base_tree_sha=normalized.accepted_base_tree_sha,
                proposal_exists=False,
            ),
            "PROPOSAL",
        )
        self.assertIsNone(classify_issue_head_claim_progression(
            normalized,
            fresh_effective_request_digest=normalized.effective_request_digest,
            fresh_patch_projection_evidence_digest=normalized.patch_projection_evidence_digest,
            fresh_accepted_base_sha=normalized.accepted_base_sha,
            fresh_accepted_base_tree_sha=normalized.accepted_base_tree_sha,
            proposal_exists=True,
        ))

if __name__ == "__main__":
    unittest.main()
