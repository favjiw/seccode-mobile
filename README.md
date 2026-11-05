# SecCode Mobile 🛡️

**Autonomous Multi-Agent Audit and Remediation Engine for OWASP Mobile Top 10 (Flutter / Mobile Architecture)**

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework: Flutter / Dart](https://img.shields.io/badge/Target-Flutter%20%7C%20Dart-cyan.svg)](https://flutter.dev)
[![Status: Experimental / Research](https://img.shields.io/badge/Status-Research%20%26%20SINTA%20Submission-indigo.svg)]()

SecCode Mobile is an evidence-first, multi-agent cybersecurity pipeline specifically designed to identify, explain, and synthesize verified remediations for mobile vulnerabilities in Flutter codebases—with special focus on architectural security debt resulting from **vibe coding** (unsupervised AI code generation).

Inspired by the robust multi-agent architecture of **MERITA (Explainable AI for Merit-Based Decisions - BPOM / APICTA 2026)**, SecCode Mobile enforces the foundational principle:
> **"LLM Reasons and Explains; Deterministic Code Verifies and Scores."**

---

## 🏛️ Multi-Agent Architecture

```
                       [ Target Flutter Repository ]
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Planner Agent                                                       │
│    - Scans structural layout (lib/**/*.dart, AndroidManifest, pubspec)  │
│    - Static AST and high-recall rule candidate retrieval               │
│    - Decomposes audit workload into category batches (M1, M5, M9)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 2. Detector & Explainer Agent (LLM + Hybrid Context)                   │
│    - Evidence-First Grounding (file path, line start/end, snippet)     │
│    - XAI Justification (threat scenario, exploitation impact, UU PDP) │
│    - Confidence scoring & false-positive filtering                    │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 3. Fixer / Repairer Agent                                              │
│    - Synthesizes virtual Unified Diff patches                          │
│    - Strict Guardrails: DONT modify test files, analysis configs,      │
│      or inject cheat suppression comments (// ignore:)                 │
│    - Read-Only: NEVER touches original repository files                │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│ 4. Deterministic Verifier Agent (Independent Quality Gate)             │
│    - Syntax structural validation (balanced braces/quotes)             │
│    - Guard compliance check (no restricted files touched)              │
│    - Rescan verification (verifies vulnerability pattern eliminated)   │
│    - Deterministic Plausibility score computation                      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
       [ Structured JSON Artifact + Publication-Ready Markdown Report ]
       [ Interactive Real-time Web Dashboard (FastAPI + Tailwind)     ]
```

---

## 🎯 Target Scope (OWASP Mobile Top 10)

1. **M1: Improper Credential Usage**
   - Hardcoded HMAC secret keys in client-side JWT signing (`SecretKey('...')`).
   - Sensitive environment files (`.env`) bundled as public Flutter assets in `pubspec.yaml`.
   - Hardcoded static authorization tokens (`_token = '1'`) and static identity UUIDs.
   - Hardcoded default credentials in login form controllers.
2. **M5: Insecure Communication**
   - Global `android:usesCleartextTraffic="true"` without network security configs.
   - Surveillance or user screenshot uploads over plain HTTP (`http://<public-ip>:port`).
   - Unauthenticated public MQTT brokers (`broker.emqx.io`) without TLS on predictable control topics.
3. **M9: Insecure Data Storage & Vibe Coding Anomalies**
   - Sensitive session bearer tokens stored plaintext in `SharedPreferences` or `GetStorage`.
   - **Vibe Coding Anomaly (Hallmark):** Declaring security packages (e.g. `flutter_secure_storage`) in `pubspec.yaml` dependencies, but zero imports or invocations across `lib/`.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Git

### Installation
```bash
git clone https://github.com/favjiw/seccode-mobile.git
cd seccode-mobile
pip install -r requirements.txt
```

### Running the CLI Engine
Audit any local Flutter repository:
```bash
python -m seccode.cli --repo /path/to/flutter-app --scope M1,M5,M9 --output-json report.json --output-md report.md
```

Options:
- `--repo`, `-r`: Absolute or relative path to the mobile project root.
- `--scope`, `-s`: Comma-separated categories (default: `M1,M5,M9`).
- `--output-json`, `-j`: Destination path for structured JSON findings.
- `--output-md`, `-m`: Destination path for publication-ready Markdown report.
- `--use-llm`: Enable LLM-backed XAI reasoning (via 9router or OpenAI-compatible endpoint).

### Launching the Web Dashboard
```bash
uvicorn seccode.web.app:app --host 0.0.0.0 --port 8000 --reload
```
Navigate to `http://localhost:8000` to access the interactive web interface:
- Enter repository path.
- Select OWASP scopes.
- Trigger audit and inspect real-time metrics, XAI justifications, and unified diff patches.

---

## 🧪 Running Tests
```bash
python -m unittest discover -s tests -p "test_*.py"
```

---

## 📄 License
MIT License. Developed by Muhammad Favian Jiwani for academic research and competitive innovation.
