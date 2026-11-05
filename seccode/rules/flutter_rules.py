"""Deterministic static rules for Flutter and Android mobile security patterns (OWASP Mobile Top 10)."""

import re
from typing import List, Dict, Any, Optional
from seccode.models import OWASPCategory, Severity


class SecurityRule:
    def __init__(
        self,
        rule_id: str,
        category: OWASPCategory,
        cwe_id: str,
        title: str,
        description: str,
        severity: Severity,
        file_pattern: str,
        regex_pattern: str,
        xai_rationale: str,
    ):
        self.rule_id = rule_id
        self.category = category
        self.cwe_id = cwe_id
        self.title = title
        self.description = description
        self.severity = severity
        self.file_pattern = re.compile(file_pattern, re.IGNORECASE)
        self.regex = re.compile(regex_pattern, re.MULTILINE)
        self.xai_rationale = xai_rationale

    def scan_file(self, file_path: str, content: str) -> List[Dict[str, Any]]:
        matches = []
        if not self.file_pattern.search(file_path):
            return matches

        lines = content.splitlines()
        for match in self.regex.finditer(content):
            start_pos = match.start()
            # Calculate line numbers
            line_start = content[:start_pos].count("\n") + 1
            matched_text = match.group(0).strip()
            line_end = line_start + matched_text.count("\n")
            
            # Context snippet
            snippet_lines = lines[max(0, line_start - 2): min(len(lines), line_end + 2)]
            snippet = "\n".join(snippet_lines)

            matches.append({
                "rule_id": self.rule_id,
                "category": self.category,
                "cwe_id": self.cwe_id,
                "title": self.title,
                "description": self.description,
                "severity": self.severity,
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "snippet": snippet,
                "matched_text": matched_text,
                "xai_rationale": self.xai_rationale,
            })
        return matches


# Registry of rules
FLUTTER_RULES: List[SecurityRule] = [
    # M1: Improper Credential Usage
    SecurityRule(
        rule_id="M1_JWT_SECRET_HARDCODED",
        category=OWASPCategory.M1,
        cwe_id="CWE-798",
        title="Hardcoded JWT Secret Key in Client Code",
        description="JWT tokens are signed on the mobile client using a hardcoded, single-word secret key.",
        severity=Severity.CRITICAL,
        file_pattern=r"\.dart$",
        regex_pattern=r"SecretKey\s*\(\s*['\"][a-zA-Z0-9_\-]+['\"]\s*\)",
        xai_rationale=(
            "Signing JWTs on the mobile client requires the secret key to be embedded in the application binary. "
            "Reverse-engineering the APK/IPA instantly yields the secret, enabling adversaries to forge arbitrary tokens "
            "and hijack parental control or authorization claims."
        ),
    ),
    SecurityRule(
        rule_id="M1_ENV_ASSET_BUNDLING",
        category=OWASPCategory.M1,
        cwe_id="CWE-540",
        title="Environment File Bundled as Public Flutter Asset",
        description="The .env configuration file is declared as an asset in pubspec.yaml, making it extractable from the compiled APK.",
        severity=Severity.HIGH,
        file_pattern=r"pubspec\.yaml$",
        regex_pattern=r"^\s*-\s*\.env\b",
        xai_rationale=(
            "Assets declared in pubspec.yaml are packaged unencrypted in the Flutter asset bundle. "
            "Any API keys, backend URLs, or secrets stored in .env become accessible to anyone decompiling the APK."
        ),
    ),
    SecurityRule(
        rule_id="M1_STATIC_AUTH_TOKEN",
        category=OWASPCategory.M1,
        cwe_id="CWE-798",
        title="Static Authorization Token or Hardcoded Identity UUID",
        description="Static authorization tokens (e.g. token '1') or hardcoded UUIDs are used for sensitive API requests.",
        severity=Severity.HIGH,
        file_pattern=r"\.dart$",
        regex_pattern=r"static\s+const\s+_token\s*=\s*['\"][0-9a-zA-Z]+['\"]",
        xai_rationale=(
            "Using static authorization tokens allows attackers to bypass backend validation trivially. "
            "Combined with hardcoded UUIDs, all instances of the application share a single identity."
        ),
    ),
    SecurityRule(
        rule_id="M1_DEFAULT_FORM_CREDENTIALS",
        category=OWASPCategory.M1,
        cwe_id="CWE-259",
        title="Hardcoded Credentials in Form Controllers",
        description="Login form controllers are initialized with default passwords or email accounts.",
        severity=Severity.MEDIUM,
        file_pattern=r"\.dart$",
        regex_pattern=r"TextEditingController\s*\(\s*text\s*:\s*['\"][^'\"]*(?:password|pass|123456)[^'\"]*['\"]\s*\)",
        xai_rationale=(
            "Hardcoded default passwords in form controllers risk exposing test or administrative credentials in production "
            "and promote insecure user behavior."
        ),
    ),
    SecurityRule(
        rule_id="M1_HARDCODED_API_SECRET",
        category=OWASPCategory.M1,
        cwe_id="CWE-798",
        title="Hardcoded Third-Party API Secret Key in Dart Service",
        description="Sensitive third-party API secret keys (e.g., payment gateway or AI service secret key) are hardcoded directly in client Dart code.",
        severity=Severity.CRITICAL,
        file_pattern=r"\.dart$",
        regex_pattern=r"(?:apiSecret|secretKey|apiKey|stripeSecret|openaiKey)\s*=\s*['\"](?:sk_api_secret_[0-9a-zA-Z_]+|sk_live_[0-9a-zA-Z_]+|sk-[0-9a-zA-Z_]{16,}|AIza[0-9A-Za-z_\-]{20,})['\"]",
        xai_rationale=(
            "Embedding third-party secret keys inside a Flutter client binary allows attackers "
            "to extract the key via strings/jadx analysis and abuse billing quotas or access backend customer records directly."
        ),
    ),

    # M5: Insecure Communication
    SecurityRule(
        rule_id="M5_CLEARTEXT_TRAFFIC",
        category=OWASPCategory.M5,
        cwe_id="CWE-319",
        title="Android Cleartext Traffic Permitted Globally",
        description="AndroidManifest.xml permits unencrypted HTTP cleartext traffic without network security config restrictions.",
        severity=Severity.CRITICAL,
        file_pattern=r"AndroidManifest\.xml$",
        regex_pattern=r'android:usesCleartextTraffic\s*=\s*"true"',
        xai_rationale=(
            "Allowing cleartext traffic globally permits the application to communicate over unencrypted HTTP, leaving all "
            "transmitted data, tokens, and payloads vulnerable to interception and modification by local network adversaries (MITM)."
        ),
    ),
    SecurityRule(
        rule_id="M5_PLAINTEXT_HTTP_URL",
        category=OWASPCategory.M5,
        cwe_id="CWE-319",
        title="Unencrypted HTTP Communication to Remote Endpoint",
        description="The application communicates with a remote host or IP over plain HTTP instead of HTTPS/TLS.",
        severity=Severity.CRITICAL,
        file_pattern=r"\.dart$",
        regex_pattern=r"['\"]http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?::[0-9]+)?/[^'\"]*['\"]",
        xai_rationale=(
            "Sending data (such as minor user screenshots or surveillance frames) over plain HTTP to a public IP address "
            "violates child privacy standards and data protection laws (UU PDP), as data is sent unencrypted over the open internet."
        ),
    ),
    SecurityRule(
        rule_id="M5_UNAUTHENTICATED_MQTT",
        category=OWASPCategory.M5,
        cwe_id="CWE-306",
        title="Public MQTT Broker Without TLS or Authentication",
        description="MQTT client connects to a public broker (broker.emqx.io) without TLS encryption or credentials.",
        severity=Severity.CRITICAL,
        file_pattern=r"\.dart$",
        regex_pattern=r"MqttServerClient\s*\(\s*['\"]broker\.emqx\.io['\"]",
        xai_rationale=(
            "Connecting to a public MQTT broker without credentials or TLS on a predictable topic allows anyone on the internet "
            "to listen in, inject control messages, or remotely disable security functions without authorization."
        ),
    ),
    SecurityRule(
        rule_id="M5_BAD_CERT_CALLBACK",
        category=OWASPCategory.M5,
        cwe_id="CWE-295",
        title="Improper Certificate Validation (Trusting All SSL Certificates)",
        description="HttpClient configures badCertificateCallback to unconditionally return true, disabling TLS certificate verification.",
        severity=Severity.CRITICAL,
        file_pattern=r"\.dart$",
        regex_pattern=r"badCertificateCallback\s*=\s*\([^)]*\)\s*=>\s*true",
        xai_rationale=(
            "Unconditionally returning true in badCertificateCallback disables X.509 certificate chain and hostname verification. "
            "Any active Man-in-the-Middle (MitM) attacker on public Wi-Fi can present a self-signed certificate and intercept encrypted traffic."
        ),
    ),
    SecurityRule(
        rule_id="M5_INSECURE_WEBSOCKET",
        category=OWASPCategory.M5,
        cwe_id="CWE-319",
        title="Unencrypted WebSocket Channel (ws:// instead of wss://)",
        description="WebSocket communication is established over plaintext ws:// protocol rather than TLS-encrypted wss://.",
        severity=Severity.HIGH,
        file_pattern=r"\.dart$",
        regex_pattern=r"WebSocketChannel\.connect\s*\(\s*Uri\.parse\s*\(\s*['\"]ws://[^'\"]+['\"]\s*\)\s*\)",
        xai_rationale=(
            "Establishing real-time WebSocket streams over ws:// transmits session events, alerts, and tokens in cleartext "
            "across the network, allowing packet sniffers and MitM proxies to eavesdrop or inject forged frames."
        ),
    ),

    # M9: Insecure Data Storage
    SecurityRule(
        rule_id="M9_PLAINTEXT_SHARED_PREFS_TOKEN",
        category=OWASPCategory.M9,
        cwe_id="CWE-312",
        title="Sensitive Authentication Token Stored in Plaintext SharedPreferences",
        description="Authentication bearer tokens or sensitive credentials are saved unencrypted in SharedPreferences.",
        severity=Severity.HIGH,
        file_pattern=r"\.dart$",
        regex_pattern=r"(?:pref|prefs)\.setString\s*\(\s*['\"]token(?:_[a-zA-Z0-9]+)?['\"]\s*,\s*[^)]+\)",
        xai_rationale=(
            "SharedPreferences stores data in an unencrypted XML file on the device. On rooted devices, via ADB backup, "
            "or via device exploits, any application or physical possessor can retrieve valid authentication tokens."
        ),
    ),
    SecurityRule(
        rule_id="M9_PLAINTEXT_GET_STORAGE_PII",
        category=OWASPCategory.M9,
        cwe_id="CWE-312",
        title="Plaintext User PII Stored in Unencrypted GetStorage Container",
        description="Personally Identifiable Information (PII) or sensitive profile data is persisted in unencrypted GetStorage.",
        severity=Severity.HIGH,
        file_pattern=r"\.dart$",
        regex_pattern=r"box\.write\s*\(\s*['\"](?:user_pii|nik|child_profile|ssn|credit_card)['\"]\s*,\s*[^)]+\)",
        xai_rationale=(
            "GetStorage persists key-value pairs as unencrypted JSON on the local filesystem. Storing sensitive PII such as "
            "national IDs (NIK) or child profiles exposes user data to local extraction and violates UU PDP protection standards."
        ),
    ),
    SecurityRule(
        rule_id="M9_UNENCRYPTED_SQLITE_SENSITIVE",
        category=OWASPCategory.M9,
        cwe_id="CWE-312",
        title="Unencrypted SQLite Database Storing Biometric or PIN Hashes",
        description="Local SQLite database stores sensitive authentication secrets (PIN hashes or biometric templates) without SQLCipher encryption.",
        severity=Severity.HIGH,
        file_pattern=r"\.dart$",
        regex_pattern=r"openDatabase\s*\(\s*['\"][a-zA-Z0-9_]+\.db['\"]\s*,\s*version:\s*\d+\s*,\s*onCreate:\s*\([^)]*\)\s*=>\s*db\.execute\s*\(\s*['\"]CREATE\s+TABLE\s+[^'\"]*(?:pin_hash|biometric_template)[^'\"]*['\"]\s*\)\s*\)",
        xai_rationale=(
            "Standard sqflite openDatabase creates an unencrypted SQLite file on disk. Storing PIN hashes or biometric metadata "
            "without SQLCipher encryption enables offline brute-force attacks or hash replacement if the device storage is accessed."
        ),
    ),
    SecurityRule(
        rule_id="M9_INSECURE_LOCAL_FILE_TOKEN",
        category=OWASPCategory.M9,
        cwe_id="CWE-732",
        title="Storing Authentication Token in Unencrypted Local File",
        description="Authentication tokens or session secrets are written directly to a plaintext file on local/external storage.",
        severity=Severity.HIGH,
        file_pattern=r"\.dart$",
        regex_pattern=r"File\s*\([^)]*(?:auth_token|session_secret|credentials)\.(?:txt|json)['\"]\s*\)\.writeAsString\s*\([^)]+\)",
        xai_rationale=(
            "Writing authentication tokens to raw local or external files bypasses hardware-backed keystore isolation "
            "and risks exposing credentials to backup utilities, file managers, or co-resident apps when permissions are lax."
        ),
    ),

    # M6: Sensitive Logging
    SecurityRule(
        rule_id="M6_SENSITIVE_LOGGING",
        category=OWASPCategory.M6,
        cwe_id="CWE-532",
        title="Sensitive Token or Payload Printed to Device Logs",
        description="Tokens or authorization payloads are logged to console/logcat using print or log().",
        severity=Severity.LOW,
        file_pattern=r"\.dart$",
        regex_pattern=r"(?:print|log)\s*\(\s*['\"][^'\"]*(?:token|jwt)[^'\"]*:\s*\$[^)]+\)",
        xai_rationale=(
            "Logging authentication tokens or sensitive user data allows other installed apps with log read permissions "
            "or anyone with USB debugging enabled to view credentials in the Android logcat."
        ),
    ),
]


def check_vibe_coding_anomalies(repo_path: str, files_dict: Dict[str, str]) -> List[Dict[str, Any]]:
    """Detect architectural vibe-coding anomalies (e.g. declared security dependencies that are never used)."""
    findings = []
    pubspec = files_dict.get("pubspec.yaml")
    if not pubspec:
        return findings

    # Check for flutter_secure_storage declared but never used in lib/
    if "flutter_secure_storage:" in pubspec:
        dart_files = {p: content for p, content in files_dict.items() if p.endswith(".dart") and p.startswith("lib/")}
        has_import = any("flutter_secure_storage" in content for content in dart_files.values())
        if not has_import:
            findings.append({
                "rule_id": "M9_UNUSED_SECURE_STORAGE_ANOMALY",
                "category": OWASPCategory.M9,
                "cwe_id": "CWE-1078",
                "title": "Unused Security Dependency (Vibe Coding Hallmark)",
                "description": (
                    "Package 'flutter_secure_storage' is declared in pubspec.yaml dependencies but is never imported or used "
                    "in any Dart file across lib/. The application falls back to insecure SharedPreferences."
                ),
                "severity": Severity.MEDIUM,
                "file_path": "pubspec.yaml",
                "line_start": 26,
                "line_end": 26,
                "snippet": "  flutter_secure_storage: ^8.0.0\n  # Declared in pubspec but 0 imports in lib/",
                "matched_text": "flutter_secure_storage",
                "xai_rationale": (
                    "This anomaly is a classic artifact of AI-assisted 'vibe coding': the developer was prompted to install "
                    "a security package, but the generated business logic continued to implement standard SharedPreferences, "
                    "leaving the codebase insecure despite having the remediation library already configured."
                ),
            })
    return findings
