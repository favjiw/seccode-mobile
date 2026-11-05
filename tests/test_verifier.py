"""Unit tests for Deterministic Verifier Agent."""

import unittest
from seccode.agents.verifier import VerifierAgent
from seccode.models import PatchProposal


class TestVerifier(unittest.TestCase):
    def test_verifier_guards_rejection_for_suppression(self):
        verifier = VerifierAgent()
        patch = PatchProposal(
            finding_id="M1-1",
            file_path="lib/test.dart",
            diff="",
            explanation="test",
            original_snippet="var token = '1';",
            repaired_snippet="// ignore: hardcoded_token\nvar token = '1';",
        )
        passed, notes = verifier.check_guards(patch)
        self.assertFalse(passed)
        self.assertTrue(any("suppression token" in n for n in notes))

    def test_verifier_guards_rejection_for_test_file(self):
        verifier = VerifierAgent()
        patch = PatchProposal(
            finding_id="M1-1",
            file_path="test/widget_test.dart",
            diff="",
            explanation="test",
            original_snippet="var token = '1';",
            repaired_snippet="var token = getSafeToken();",
        )
        passed, notes = verifier.check_guards(patch)
        self.assertFalse(passed)
        self.assertTrue(any("forbidden file" in n for n in notes))

    def test_verifier_syntax_check(self):
        verifier = VerifierAgent()
        valid_code = "void main() { print('Hello'); }"
        invalid_code = "void main() { print('Hello'); "

        ok1, _ = verifier.check_syntax(valid_code)
        ok2, _ = verifier.check_syntax(invalid_code)
        self.assertTrue(ok1)
        self.assertFalse(ok2)


if __name__ == "__main__":
    unittest.main()
