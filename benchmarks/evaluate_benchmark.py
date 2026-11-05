#!/usr/bin/env python3
"""
Formal Benchmark Evaluation Runner for SecCode Mobile (Ghera-style 15-Pair Dataset).
Evaluates Empirical Detection Performance (RQ2) and Automated Remediation Plausibility (RQ3)
across OWASP Mobile Top 10 categories M1, M5, and M9.
"""

import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from seccode.orchestrator import SecCodeOrchestrator
from seccode.config import default_config


BENCHMARK_DIR = Path(__file__).resolve().parent
PAIRS_DIR = BENCHMARK_DIR / "pairs"
OUTPUT_JSON = BENCHMARK_DIR / "benchmark_results.json"
OUTPUT_MD = BENCHMARK_DIR / "benchmark_results.md"


def evaluate_all_pairs(use_llm: bool = False) -> Dict[str, Any]:
    """Runs SecCodeOrchestrator on all 15 vulnerable and 15 safe benchmark app pairs."""
    orchestrator = SecCodeOrchestrator(default_config)

    case_dirs = sorted([d for d in PAIRS_DIR.iterdir() if d.is_dir()])
    if not case_dirs:
        raise RuntimeError(f"No benchmark pairs found in {PAIRS_DIR}")

    tp = 0
    fn = 0
    tn = 0
    fp = 0

    total_patches = 0
    plausible_patches = 0
    syntax_valid_count = 0
    guards_passed_count = 0
    rescan_passed_count = 0

    category_stats: Dict[str, Dict[str, Any]] = {}
    case_results: List[Dict[str, Any]] = []

    start_total = time.perf_counter()

    for case_dir in case_dirs:
        meta_path = case_dir / "metadata.json"
        vuln_dir = case_dir / "vulnerable"
        safe_dir = case_dir / "safe"

        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

        case_id = meta["id"]
        category_full = meta["category"]
        cat_key = category_full.split(":")[0].strip()
        expected_rule = meta.get("expected_rule_id")

        if cat_key not in category_stats:
            category_stats[cat_key] = {
                "category": category_full,
                "cases": 0,
                "TP": 0,
                "FN": 0,
                "TN": 0,
                "FP": 0,
                "patches_generated": 0,
                "patches_plausible": 0,
            }
        category_stats[cat_key]["cases"] += 1

        # 1. Audit Vulnerable Version
        t0 = time.perf_counter()
        vuln_report = orchestrator.run_audit(
            str(vuln_dir), categories=[cat_key], use_llm=use_llm
        )
        vuln_ms = round((time.perf_counter() - t0) * 1000, 2)

        vuln_findings = vuln_report.findings
        detected_rules = [f.evidence.rule_id for f in vuln_findings]

        if expected_rule:
            is_tp = expected_rule in detected_rules and len(vuln_findings) > 0
        else:
            is_tp = len(vuln_findings) > 0

        if is_tp:
            tp += 1
            category_stats[cat_key]["TP"] += 1
        else:
            fn += 1
            category_stats[cat_key]["FN"] += 1

        # Evaluate Patch Plausibility on Vulnerable Version (RQ3)
        case_patches = len(vuln_report.patches)
        case_plausible = sum(1 for v in vuln_report.verifications if v.plausible)
        case_syntax_ok = sum(1 for v in vuln_report.verifications if v.syntax_valid)
        case_guards_ok = sum(1 for v in vuln_report.verifications if v.guards_passed)
        case_rescan_ok = sum(1 for v in vuln_report.verifications if v.rescan_passed)

        total_patches += case_patches
        plausible_patches += case_plausible
        syntax_valid_count += case_syntax_ok
        guards_passed_count += case_guards_ok
        rescan_passed_count += case_rescan_ok

        category_stats[cat_key]["patches_generated"] += case_patches
        category_stats[cat_key]["patches_plausible"] += case_plausible

        # 2. Audit Safe Version
        t1 = time.perf_counter()
        safe_report = orchestrator.run_audit(
            str(safe_dir), categories=[cat_key], use_llm=use_llm
        )
        safe_ms = round((time.perf_counter() - t1) * 1000, 2)

        safe_findings = safe_report.findings
        is_tn = len(safe_findings) == 0

        if is_tn:
            tn += 1
            category_stats[cat_key]["TN"] += 1
        else:
            fp += 1
            category_stats[cat_key]["FP"] += 1

        patch_diff_preview = (
            vuln_report.patches[0].diff if vuln_report.patches else ""
        )

        case_results.append({
            "id": case_id,
            "category": cat_key,
            "category_full": category_full,
            "cwe": meta["cwe"],
            "title": meta["title"],
            "expected_rule_id": expected_rule,
            "vulnerable_run": {
                "findings_count": len(vuln_findings),
                "detected_rules": detected_rules,
                "verdict": "TP" if is_tp else "FN",
                "duration_ms": vuln_ms,
                "patch_generated": case_patches > 0,
                "syntax_valid": bool(case_syntax_ok == case_patches and case_patches > 0),
                "guards_passed": bool(case_guards_ok == case_patches and case_patches > 0),
                "rescan_passed": bool(case_rescan_ok == case_patches and case_patches > 0),
                "patch_plausible": bool(case_plausible == case_patches and case_patches > 0),
                "patch_diff": patch_diff_preview,
            },
            "safe_run": {
                "findings_count": len(safe_findings),
                "detected_rules": [f.evidence.rule_id for f in safe_findings],
                "verdict": "TN" if is_tn else "FP",
                "duration_ms": safe_ms,
            },
        })

    total_duration_s = round(time.perf_counter() - start_total, 4)

    # Compute formal classification metrics
    precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
    recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
    f1_score = (
        round(2 * precision * recall / (precision + recall), 4)
        if (precision + recall) > 0
        else 0.0
    )
    accuracy = round((tp + tn) / (tp + tn + fp + fn), 4) if (tp + tn + fp + fn) > 0 else 0.0
    fpr = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
    plausibility_rate = (
        round((plausible_patches / total_patches) * 100, 2) if total_patches > 0 else 0.0
    )

    # Finalize per-category metrics
    for cat_key, st in category_stats.items():
        c_tp, c_fp, c_fn, c_tn = st["TP"], st["FP"], st["FN"], st["TN"]
        c_prec = round(c_tp / (c_tp + c_fp), 4) if (c_tp + c_fp) > 0 else 0.0
        c_rec = round(c_tp / (c_tp + c_fn), 4) if (c_tp + c_fn) > 0 else 0.0
        c_f1 = (
            round(2 * c_prec * c_rec / (c_prec + c_rec), 4)
            if (c_prec + c_rec) > 0
            else 0.0
        )
        c_plaus = (
            round((st["patches_plausible"] / st["patches_generated"]) * 100, 2)
            if st["patches_generated"] > 0
            else 0.0
        )
        st["precision"] = c_prec
        st["recall"] = c_rec
        st["f1_score"] = c_f1
        st["plausibility_rate"] = c_plaus

    return {
        "benchmark_name": "SecCode Mobile Ghera-Style OWASP Benchmark (M1, M5, M9)",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_pairs": len(case_dirs),
        "total_test_executions": len(case_dirs) * 2,
        "duration_seconds": total_duration_s,
        "overall_metrics": {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
            "false_positive_rate": fpr,
            "total_patches_generated": total_patches,
            "syntax_valid_patches": syntax_valid_count,
            "guards_passed_patches": guards_passed_count,
            "rescan_passed_patches": rescan_passed_count,
            "plausible_patches": plausible_patches,
            "plausibility_rate": plausibility_rate,
        },
        "category_breakdown": category_stats,
        "cases": case_results,
    }


def format_markdown_report(results: Dict[str, Any]) -> str:
    """Formats benchmark results into a SINTA publication-ready Markdown report."""
    m = results["overall_metrics"]
    lines = [
        "# SecCode Mobile — Empirical Benchmark Evaluation Report (RQ2 & RQ3)",
        "",
        f"**Benchmark Suite:** {results['benchmark_name']}  ",
        f"**Evaluation Timestamp:** `{results['timestamp']}`  ",
        f"**Dataset Size:** {results['total_pairs']} Vulnerability Pairs ({results['total_test_executions']} Total App Variants: 15 Vulnerable vs. 15 Safe)  ",
        f"**Total Execution Time:** `{results['duration_seconds']}s`",
        "",
        "---",
        "",
        "## 1. Aggregate Detection & Remediation Metrics (RQ2 & RQ3)",
        "",
        "| Metric | Value | Percentage / Formula |",
        "| :--- | :---: | :---: |",
        f"| **True Positives (TP)** | `{m['TP']}` | Vulnerable cases accurately detected ({m['TP']}/15) |",
        f"| **False Positives (FP)** | `{m['FP']}` | Safe cases falsely flagged ({m['FP']}/15) |",
        f"| **True Negatives (TN)** | `{m['TN']}` | Safe cases verified clean ({m['TN']}/15) |",
        f"| **False Negatives (FN)** | `{m['FN']}` | Vulnerable cases missed ({m['FN']}/15) |",
        f"| **Precision** | `{m['precision']:.4f}` | `{m['precision'] * 100:.2f}%` (`TP / (TP + FP)`) |",
        f"| **Recall (Sensitivity)** | `{m['recall']:.4f}` | `{m['recall'] * 100:.2f}%` (`TP / (TP + FN)`) |",
        f"| **F1-Score** | `{m['f1_score']:.4f}` | `{m['f1_score'] * 100:.2f}%` (`2 * P * R / (P + R)`) |",
        f"| **Accuracy** | `{m['accuracy']:.4f}` | `{m['accuracy'] * 100:.2f}%` (`(TP + TN) / N`) |",
        f"| **Patch Syntax Validity** | `{m['syntax_valid_patches']}/{m['total_patches_generated']}` | `{(m['syntax_valid_patches']/max(1, m['total_patches_generated']))*100:.2f}%` |",
        f"| **Guardrail Compliance** | `{m['guards_passed_patches']}/{m['total_patches_generated']}` | `{(m['guards_passed_patches']/max(1, m['total_patches_generated']))*100:.2f}%` |",
        f"| **Deterministic Rescan Pass** | `{m['rescan_passed_patches']}/{m['total_patches_generated']}` | `{(m['rescan_passed_patches']/max(1, m['total_patches_generated']))*100:.2f}%` |",
        f"| **Overall Patch Plausibility Rate (RQ3)** | `{m['plausible_patches']}/{m['total_patches_generated']}` | **`{m['plausibility_rate']:.2f}%`** |",
        "",
        "---",
        "",
        "## 2. Per-Category Performance Breakdown (OWASP Mobile Top 10)",
        "",
        "| OWASP Category | Pairs | TP | FP | TN | FN | Precision | Recall | F1-Score | Plausibility Rate |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]

    for cat_key, st in sorted(results["category_breakdown"].items()):
        lines.append(
            f"| **{st['category']}** | {st['cases']} | {st['TP']} | {st['FP']} | {st['TN']} | {st['FN']} | "
            f"`{st['precision']:.2f}` | `{st['recall']:.2f}` | `{st['f1_score']:.2f}` | **{st['plausibility_rate']:.1f}%** ({st['patches_plausible']}/{st['patches_generated']}) |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Case-by-Case Benchmark Matrix (15 Ghera-Style Pairs)",
        "",
        "| Case ID | OWASP | CWE | Vulnerability Case Title | Vuln (`vulnerable/`) | Safe (`safe/`) | Syntax | Guards | Rescan | Plausible (RQ3) |",
        "| :---: | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |",
    ])

    for c in results["cases"]:
        vr = c["vulnerable_run"]
        sr = c["safe_run"]
        v_badge = "✅ TP" if vr["verdict"] == "TP" else "❌ FN"
        s_badge = "✅ TN" if sr["verdict"] == "TN" else "❌ FP"
        syn_badge = "✅" if vr["syntax_valid"] else "❌"
        grd_badge = "✅" if vr["guards_passed"] else "❌"
        rsc_badge = "✅" if vr["rescan_passed"] else "❌"
        pls_badge = "✅ Yes" if vr["patch_plausible"] else "❌ No"

        lines.append(
            f"| `{c['id']}` | {c['category']} | `{c['cwe']}` | {c['title']} | {v_badge} | {s_badge} | "
            f"{syn_badge} | {grd_badge} | {rsc_badge} | **{pls_badge}** |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 4. Verified Virtual Patches Summary (Sample Unified Diffs)",
        "",
    ])

    for c in results["cases"]:
        vr = c["vulnerable_run"]
        lines.append(f"### [{c['id']}] {c['title']} ({c['cwe']})")
        lines.append(f"- **Detected Rule:** `{', '.join(vr['detected_rules'])}`")
        lines.append(f"- **Audit Latency:** Vulnerable `{vr['duration_ms']} ms` | Safe `{c['safe_run']['duration_ms']} ms`")
        if vr["patch_diff"]:
            lines.append("```diff")
            lines.append(vr["patch_diff"])
            lines.append("```")
        lines.append("")

    return "\n".join(lines)


def main() -> None:
    print("[*] Running SecCode Mobile Formal Benchmark Evaluation (15 Pairs)...")
    results = evaluate_all_pairs(use_llm=False)

    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    md_report = format_markdown_report(results)
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write(md_report)

    m = results["overall_metrics"]
    print(f"[+] Benchmark Evaluation Complete in {results['duration_seconds']}s!")
    print(f"    TP={m['TP']} | FP={m['FP']} | TN={m['TN']} | FN={m['FN']}")
    print(f"    Precision={m['precision']:.4f} | Recall={m['recall']:.4f} | F1-Score={m['f1_score']:.4f}")
    print(f"    Plausibility Rate={m['plausibility_rate']}% ({m['plausible_patches']}/{m['total_patches_generated']})")
    print(f"[+] Saved JSON results to: {OUTPUT_JSON}")
    print(f"[+] Saved Markdown report to: {OUTPUT_MD}")


if __name__ == "__main__":
    main()
