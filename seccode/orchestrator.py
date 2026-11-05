"""Multi-Agent Orchestrator: Coordinates Planner, Detector, Repairer, and Verifier."""

import time
import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any
from seccode.models import AuditReport, AuditMetrics, VulnerabilityFinding
from seccode.agents import PlannerAgent, DetectorAgent, RepairerAgent, VerifierAgent
from seccode.config import EngineConfig, default_config


class SecCodeOrchestrator:
    def __init__(self, config: EngineConfig = default_config):
        self.config = config

    def run_audit(
        self,
        repo_path: str,
        categories: Optional[List[str]] = None,
        use_llm: bool = False,
    ) -> AuditReport:
        """Executes the full multi-agent pipeline on target repository in strictly read-only mode."""
        start_time = time.time()
        report_id = f"audit-{uuid.uuid4().hex[:8]}"

        # 1. Planner Stage
        planner = PlannerAgent(repo_path)
        candidates = planner.plan_audit(target_categories=categories)

        # 2. Detector Stage
        detector = DetectorAgent(self.config)
        findings = detector.analyze_candidates(candidates, use_llm=use_llm)

        # 3. Repairer Stage
        repairer = RepairerAgent(self.config)
        patches = [repairer.generate_patch(f, use_llm=use_llm) for f in findings]

        # 4. Verifier Stage (Deterministic Quality Gate)
        verifier = VerifierAgent(self.config)
        verifications = []
        for finding, patch in zip(findings, patches):
            res = verifier.verify(finding, patch)
            verifications.append(res)

        # Compute Metrics
        duration = round(time.time() - start_time, 2)
        plausible_count = sum(1 for v in verifications if v.plausible)
        cat_counts: Dict[str, int] = {}
        for f in findings:
            prefix = f.category.value.split(":")[0]
            cat_counts[prefix] = cat_counts.get(prefix, 0) + 1

        plausibility_rate = (
            round((plausible_count / len(findings)) * 100, 2) if findings else 0.0
        )

        metrics = AuditMetrics(
            total_candidates=len(candidates),
            total_confirmed=len(findings),
            total_patches=len(patches),
            plausible_patches=plausible_count,
            plausibility_rate=plausibility_rate,
            findings_by_category=cat_counts,
            duration_seconds=duration,
        )

        return AuditReport(
            id=report_id,
            repo_path=repo_path,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            findings=findings,
            patches=patches,
            verifications=verifications,
            metrics=metrics,
        )

    @staticmethod
    def format_markdown(report: AuditReport) -> str:
        """Formats audit report into publication-ready Markdown format."""
        md = []
        md.append(f"# SecCode Mobile: OWASP Security Audit Report")
        md.append(f"**Report ID:** `{report.id}` | **Target Repo:** `{report.repo_path}` | **Date:** {report.timestamp}\n")
        
        md.append("## Executive Summary")
        m = report.metrics
        md.append(f"- **Total Vulnerabilities Confirmed:** {m.total_confirmed}")
        md.append(f"- **Generated Patches:** {m.total_patches}")
        md.append(f"- **Plausible Patches (Passed Deterministic Quality Gate):** {m.plausible_patches} ({m.plausibility_rate}%)")
        md.append(f"- **Execution Duration:** {m.duration_seconds}s\n")

        md.append("### Findings Breakdown by OWASP Category")
        for cat, cnt in m.findings_by_category.items():
            md.append(f"- **{cat}:** {cnt} findings")
        md.append("\n---\n")

        md.append("## Detailed Findings & Verified Remediation Patches\n")
        for finding, patch, ver in zip(report.findings, report.patches, report.verifications):
            status_icon = "✅ Plausible" if ver.plausible else "⚠️ Manual Review Required"
            md.append(f"### [{finding.id}] {finding.title}")
            md.append(f"- **Category:** {finding.category.value}")
            md.append(f"- **CWE:** {finding.cwe_id} | **Severity:** {finding.severity.value}")
            md.append(f"- **Location:** `{finding.evidence.file_path}:{finding.evidence.line_start}-{finding.evidence.line_end}`")
            md.append(f"- **Quality Gate Verdict:** {status_icon}\n")

            md.append("#### Vulnerable Code Snippet")
            md.append(f"```dart\n{finding.evidence.snippet}\n```\n")

            md.append("#### Explainable AI (XAI) Justification")
            md.append(f"{finding.xai_justification}\n")

            md.append("#### Suggested Remediation Patch (Unified Diff)")
            md.append(f"```diff\n{patch.diff}\n```\n")

            md.append("#### Quality Gate Verification Notes")
            for note in ver.notes:
                md.append(f"- {note}")
            md.append("\n" + "-" * 40 + "\n")

        return "\n".join(md)
