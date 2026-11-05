# SecCode Mobile — Ghera-Style OWASP Mobile Top 10 Benchmark Suite

Formal empirical benchmark dataset consisting of **15 paired Flutter vulnerability cases (`vulnerable/` vs. `safe/`)** modeled after the **Ghera Android Vulnerability Benchmark Framework** for evaluating RQ2 (Detection Precision, Recall, and F1-Score) and RQ3 (Automated Remediation Patch Plausibility).

---

## 📂 Dataset Taxonomy (15 Pairs = 30 App Variants)

| Case ID | OWASP Category | CWE | Vulnerability Case | Target Rule ID |
| :---: | :---: | :---: | :--- | :--- |
| `M1-01` | M1: Improper Credential Usage | `CWE-798` | Client-Side HMAC Secret JWT Signing | `M1_JWT_SECRET_HARDCODED` |
| `M1-02` | M1: Improper Credential Usage | `CWE-540` | Bundling `.env` Configuration File in `pubspec.yaml` Assets | `M1_ENV_ASSET_BUNDLING` |
| `M1-03` | M1: Improper Credential Usage | `CWE-798` | Hardcoded Static Authorization Token and Identity UUIDs | `M1_STATIC_AUTH_TOKEN` |
| `M1-04` | M1: Improper Credential Usage | `CWE-259` | Hardcoded Credentials in Login Form Controller | `M1_DEFAULT_FORM_CREDENTIALS` |
| `M1-05` | M1: Improper Credential Usage | `CWE-798` | Hardcoded Third-Party API Secret Key in Dart Service | `M1_HARDCODED_API_SECRET` |
| `M5-01` | M5: Insecure Communication | `CWE-319` | Global Cleartext Traffic Allowed in `AndroidManifest.xml` | `M5_CLEARTEXT_TRAFFIC` |
| `M5-02` | M5: Insecure Communication | `CWE-319` | Screenshot and Photo Upload via Plain HTTP to Raw IP | `M5_PLAINTEXT_HTTP_URL` |
| `M5-03` | M5: Insecure Communication | `CWE-306` | Public MQTT Broker (`broker.emqx.io`) Without TLS or Auth | `M5_UNAUTHENTICATED_MQTT` |
| `M5-04` | M5: Insecure Communication | `CWE-295` | Trusting All SSL Certificates via `badCertificateCallback` | `M5_BAD_CERT_CALLBACK` |
| `M5-05` | M5: Insecure Communication | `CWE-319` | WebSocket Connection Over Plaintext `ws://` Instead of `wss://` | `M5_INSECURE_WEBSOCKET` |
| `M9-01` | M9: Insecure Data Storage | `CWE-312` | Plaintext Authentication Token Stored in `SharedPreferences` | `M9_PLAINTEXT_SHARED_PREFS_TOKEN` |
| `M9-02` | M9: Insecure Data Storage | `CWE-312` | Plaintext User PII Stored in Unencrypted `GetStorage` | `M9_PLAINTEXT_GET_STORAGE_PII` |
| `M9-03` | M9: Insecure Data Storage | `CWE-1078` | Vibe Coding Anomaly: `flutter_secure_storage` in `pubspec.yaml` With 0 Imports in `lib/` | `M9_UNUSED_SECURE_STORAGE_ANOMALY` |
| `M9-04` | M9: Insecure Data Storage | `CWE-312` | Unencrypted SQLite Database Storing Biometric/PIN Hashes | `M9_UNENCRYPTED_SQLITE_SENSITIVE` |
| `M9-05` | M9: Insecure Data Storage | `CWE-732` | Storing Authentication Token in Unencrypted Local File | `M9_INSECURE_LOCAL_FILE_TOKEN` |

---

## 🏗️ Directory Structure per Case

Each benchmark pair under `benchmarks/pairs/<case_id>/` contains:
- `vulnerable/` — Minimal, realistic Flutter/Android codebase exhibiting the target vulnerability.
- `safe/` — Corresponding remediated codebase following OWASP Mobile Top 10 best practices (0 false alarms).
- `metadata.json` — Formal Ghera-style descriptor (`id`, `category`, `cwe`, `title`, `description`, `attack_vector`, `fix_rationale`, `expected_rule_id`).

---

## ▶️ Running the Formal Benchmark Evaluation

```bash
python3 benchmarks/evaluate_benchmark.py
```

Outputs:
- `benchmarks/benchmark_results.json` — Machine-readable evaluation artifact (TP, FP, TN, FN, Precision, Recall, F1-Score, Plausibility Rate, per-case diffs and latency).
- `benchmarks/benchmark_results.md` — Publication-ready Markdown tables for SINTA manuscript inclusion.
