"""Unit tests for SecCode Mobile Orchestrator."""

import os
import unittest
from seccode.orchestrator import SecCodeOrchestrator


class TestOrchestrator(unittest.TestCase):
    def test_orchestrator_on_snailly(self):
        snailly_path = "/home/ubuntu/snailly-mobile"
        if not os.path.exists(snailly_path):
            self.skipTest("Snailly repo not found at /home/ubuntu/snailly-mobile")

        orchestrator = SecCodeOrchestrator()
        report = orchestrator.run_audit(snailly_path, categories=["M1", "M5", "M9"], use_llm=False)

        self.assertTrue(report.id.startswith("audit-"))
        self.assertGreater(report.metrics.total_confirmed, 0)
        self.assertGreater(report.metrics.plausible_patches, 0)
        self.assertEqual(len(report.findings), len(report.patches))
        self.assertEqual(len(report.verifications), len(report.findings))

        # Format Markdown
        md = SecCodeOrchestrator.format_markdown(report)
        self.assertIn("# SecCode Mobile", md)
        self.assertIn("M1: Improper Credential Usage", md)


if __name__ == "__main__":
    unittest.main()
