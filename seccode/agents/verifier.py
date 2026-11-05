"""Deterministic Verifier Agent: Independent Quality Gate for patch validation."""

import re
from typing import List, Dict, Any, Optional
from seccode.models import VulnerabilityFinding, PatchProposal, VerificationResult
from seccode.config import EngineConfig, default_config
from seccode.rules import FLUTTER_RULES


class VerifierAgent:
    def __init__(self, config: EngineConfig = default_config):
        self.config = config

    def check_guards(self, patch: PatchProposal) -> tuple[bool, List[str]]:
        """Validates that patch complies with security guards."""
        notes = []
        passed = True

        # Guard 1: Forbidden modified files (e.g. test files, analyzer config)
        for pattern in self.config.forbidden_modified_patterns:
            if re.search(pattern, patch.file_path, re.IGNORECASE):
                passed = False
                notes.append(f"Guard violation: Modifying forbidden file '{patch.file_path}' (matches {pattern})")

        # Guard 2: Forbidden suppression comments
        for token in self.config.forbidden_suppression_tokens:
            if token in patch.repaired_snippet:
                passed = False
                notes.append(f"Guard violation: Patch contains cheat/suppression token '{token}'")

        if passed:
            notes.append("Guards check passed: No restricted files modified and no suppression tokens detected.")
        return passed, notes

    def check_syntax(self, code_snippet: str) -> tuple[bool, List[str]]:
        """Performs structural syntax sanity check (balanced braces, parentheses, quotes)."""
        notes = []
        stack = []
        pairs = {')': '(', '}': '{', ']': '['}

        for char in code_snippet:
            if char in "({[":
                stack.append(char)
            elif char in ")}]":
                if not stack or stack[-1] != pairs[char]:
                    notes.append(f"Syntax warning: Mismatched closing bracket '{char}'")
                    return False, notes
                stack.pop()

        if stack:
            notes.append(f"Syntax warning: Unclosed opening bracket '{stack[-1]}'")
            return False, notes

        # Check for unclosed multiline strings or quotes (excluding common inline comments)
        clean_lines = [l.split("//")[0] for l in code_snippet.splitlines()]
        clean_text = "\n".join(clean_lines)
        double_quotes = clean_text.count('"')
        if double_quotes % 2 != 0:
            notes.append("Syntax warning: Unbalanced double quotes in patch snippet")
            return False, notes

        notes.append("Syntax check passed: Structural brackets and quotes balanced.")
        return True, notes

    def check_rescan(self, finding: VulnerabilityFinding, patch: PatchProposal) -> tuple[bool, List[str]]:
        """Re-scans the repaired snippet against the triggering rule to verify the vulnerability is removed."""
        notes = []
        rule_id = finding.evidence.rule_id

        target_rule = next((r for r in FLUTTER_RULES if r.rule_id == rule_id), None)
        if not target_rule:
            notes.append(f"Rescan: Rule '{rule_id}' not found; assuming passed.")
            return True, notes

        # Run rule regex against the repaired code
        if target_rule.regex.search(patch.repaired_snippet):
            notes.append(f"Rescan failed: Triggering regex pattern for rule '{rule_id}' still matched repaired code!")
            return False, notes

        notes.append(f"Rescan passed: Vulnerability pattern '{rule_id}' successfully eliminated.")
        return True, notes

    def verify(self, finding: VulnerabilityFinding, patch: PatchProposal) -> VerificationResult:
        """Executes full deterministic quality gate verification."""
        all_notes = []

        # 1. Guards check
        guards_ok, g_notes = self.check_guards(patch)
        all_notes.extend(g_notes)

        # 2. Syntax check
        syntax_ok, s_notes = self.check_syntax(patch.repaired_snippet)
        all_notes.extend(s_notes)

        # 3. Rescan verification
        rescan_ok, r_notes = self.check_rescan(finding, patch)
        all_notes.extend(r_notes)

        # Deterministic plausibility verdict
        plausible = guards_ok and syntax_ok and rescan_ok

        return VerificationResult(
            finding_id=finding.id,
            syntax_valid=syntax_ok,
            guards_passed=guards_ok,
            rescan_passed=rescan_ok,
            plausible=plausible,
            notes=all_notes,
        )
