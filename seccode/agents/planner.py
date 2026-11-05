"""Planner Agent: Scans repository layout and prepares decomposed audit targets."""

import os
from typing import Dict, List, Any
from seccode.rules import FLUTTER_RULES, check_vibe_coding_anomalies


class PlannerAgent:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)

    def scan_project_files(self) -> Dict[str, str]:
        """Reads target repository files in a strictly read-only mode."""
        files_dict = {}
        for root, dirs, files in os.walk(self.repo_path):
            # Skip hidden and cache dirs
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("build", ".dart_tool", "node_modules")]
            for file in files:
                rel_path = os.path.relpath(os.path.join(root, file), self.repo_path)
                # Keep relevant mobile files
                if (
                    rel_path.endswith(".dart")
                    or rel_path.endswith("AndroidManifest.xml")
                    or rel_path.endswith("pubspec.yaml")
                    or rel_path.endswith("build.gradle")
                ):
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            files_dict[rel_path] = f.read()
                    except Exception as e:
                        print(f"Warning: could not read {rel_path}: {e}")
        return files_dict

    def plan_audit(self, target_categories: List[str] = None) -> List[Dict[str, Any]]:
        """Decomposes audit into candidates based on static rules and vibe coding heuristics."""
        files = self.scan_project_files()
        candidates = []

        # Run registered rules
        for rel_path, content in files.items():
            for rule in FLUTTER_RULES:
                # Filter by category if specified
                if target_categories:
                    cat_prefix = rule.category.value.split(":")[0]
                    if cat_prefix not in target_categories:
                        continue
                matches = rule.scan_file(rel_path, content)
                candidates.extend(matches)

        # Check architectural anomalies
        anomalies = check_vibe_coding_anomalies(self.repo_path, files)
        candidates.extend(anomalies)

        return candidates
