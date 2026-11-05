#!/usr/bin/env python3
"""Generator for the 15-pair Ghera-style OWASP Mobile Top 10 Flutter Benchmark Dataset."""

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent / "pairs"

BENCHMARK_CASES = [
    # ==================== M1: IMPROPER CREDENTIAL USAGE ====================
    {
        "id": "M1-01",
        "category": "M1: Improper Credential Usage",
        "cwe": "CWE-798",
        "expected_rule_id": "M1_JWT_SECRET_HARDCODED",
        "title": "Client-Side HMAC Secret JWT Signing",
        "description": (
            "The Flutter client signs JSON Web Tokens (JWT) locally inside a controller using a hardcoded "
            "HMAC symmetric secret key ('SecretKey'). Because the secret resides in the compiled Dart snapshot, "
            "any attacker can extract it and forge arbitrary session claims."
        ),
        "attack_vector": (
            "An adversary decompiles the APK using jadx or blutter to inspect libapp.so string pools, extracts "
            "the SecretKey literal, and mints forged admin/parent JWTs with elevated privileges."
        ),
        "fix_rationale": (
            "Never embed JWT signing keys in mobile client binaries. Delegate token issuance and cryptographic "
            "signing exclusively to an authenticated backend endpoint over TLS."
        ),
        "files": {
            "lib/controllers/jwt_session_controller.dart": {
                "vulnerable": """import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

class JwtSessionController {
  Future<String> generateClientToken(Map<String, dynamic> data) async {
    final jwt = JWT(data, issuer: 'snailly_mobile_client');
    // Sign JWT on client using hardcoded symmetric secret
    var dataToken = jwt.sign(SecretKey('snailly'));
    // Return signed token string
    return dataToken;
  }
}
""",
                "safe": """class AuthApiService {
  Future<String> requestSessionToken(Map<String, dynamic> payload) async {
    return 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.backend_issued';
  }
}

class JwtSessionController {
  final AuthApiService authApiService;
  JwtSessionController(this.authApiService);

  Future<String> generateClientToken(Map<String, dynamic> data) async {
    // Delegate JWT signing to backend authority
    final dataToken = await authApiService.requestSessionToken(data);
    return dataToken;
  }
}
""",
            }
        },
    },
    {
        "id": "M1-02",
        "category": "M1: Improper Credential Usage",
        "cwe": "CWE-540",
        "expected_rule_id": "M1_ENV_ASSET_BUNDLING",
        "title": "Bundling .env Configuration File in pubspec.yaml Assets",
        "description": (
            "The application declares the local '.env' secret file under the 'flutter: assets:' section of "
            "pubspec.yaml, causing all environment secrets to be packaged unencrypted inside the APK's flutter_assets/ directory."
        ),
        "attack_vector": (
            "An attacker unzips the distributed APK (`unzip app-release.apk assets/flutter_assets/.env`) and "
            "reads production API keys, database URLs, and service secrets in plaintext."
        ),
        "fix_rationale": (
            "Remove '.env' from pubspec.yaml assets and inject non-sensitive runtime configuration via "
            "compile-time `--dart-define-from-file` or retrieve short-lived credentials from a backend vault."
        ),
        "files": {
            "pubspec.yaml": {
                "vulnerable": """name: benchmark_m1_02
description: Flutter benchmark app for M1-02 asset bundling.
version: 1.0.0+1

environment:
  sdk: ">=3.0.0 <4.0.0"

dependencies:
  flutter:
    sdk: flutter

flutter:
  uses-material-design: true
  assets:
    - assets/images/logo.png
    - .env
""",
                "safe": """name: benchmark_m1_02
description: Flutter benchmark app for M1-02 asset bundling (remediated).
version: 1.0.0+1

environment:
  sdk: ">=3.0.0 <4.0.0"

dependencies:
  flutter:
    sdk: flutter

flutter:
  uses-material-design: true
  assets:
    - assets/images/logo.png
""",
            }
        },
    },
    {
        "id": "M1-03",
        "category": "M1: Improper Credential Usage",
        "cwe": "CWE-798",
        "expected_rule_id": "M1_STATIC_AUTH_TOKEN",
        "title": "Hardcoded Static Authorization Token and Identity UUIDs",
        "description": (
            "API service classes define a hardcoded static bearer token (`static const _token = '1'`) and static "
            "identity UUIDs for authenticating backend requests across all installed client instances."
        ),
        "attack_vector": (
            "Attackers inspect client code or intercept a single request to learn the static authorization token "
            "and UUID, enabling unauthorized access to any family or child monitoring record on the API."
        ),
        "fix_rationale": (
            "Eliminate static tokens and hardcoded UUIDs. Provision per-session, cryptographically random "
            "OAuth2/JWT bearer tokens stored in hardware-backed secure storage."
        ),
        "files": {
            "lib/services/parental_control_api.dart": {
                "vulnerable": """class ParentalControlApi {
  static const _baseUrl = 'https://api.snailly.id/v1';
  // Vulnerable hardcoded static authorization token and UUID
  static const _token = '1';
  static const _parentUuid = '550e8400-e29b-41d4-a716-446655440000';

  Map<String, String> buildHeaders() {
    return {'Authorization': 'Bearer $_token', 'X-Parent-Id': _parentUuid};
  }
}
""",
                "safe": """import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ParentalControlApi {
  static const _baseUrl = 'https://api.snailly.id/v1';
  final FlutterSecureStorage secureStorage;

  ParentalControlApi(this.secureStorage);

  Future<Map<String, String>> buildHeaders() async {
    final token = await secureStorage.read(key: 'auth_token');
    final parentUuid = await secureStorage.read(key: 'parent_uuid');
    return {
      'Authorization': 'Bearer ${token ?? ""}',
      'X-Parent-Id': parentUuid ?? '',
    };
  }
}
""",
            }
        },
    },
    {
        "id": "M1-04",
        "category": "M1: Improper Credential Usage",
        "cwe": "CWE-259",
        "expected_rule_id": "M1_DEFAULT_FORM_CREDENTIALS",
        "title": "Hardcoded Credentials in Login Form Controller",
        "description": (
            "A Vibe-Coded login screen controller initializes `TextEditingController` instances with hardcoded "
            "default passwords (`password123456`), shipping developer test credentials into production builds."
        ),
        "attack_vector": (
            "Users or attackers launching the application or inspecting the compiled binary discover pre-populated "
            "administrative or test account credentials that remain active on the production backend."
        ),
        "fix_rationale": (
            "Initialize all authentication `TextEditingController` fields empty (`TextEditingController()`) and "
            "enforce strict separation between development seed data and production builds."
        ),
        "files": {
            "lib/controllers/login_form_controller.dart": {
                "vulnerable": """import 'package:flutter/material.dart';

class LoginFormController {
  final emailController = TextEditingController(text: 'parent.demo@snailly.id');
  // Pre-filled default password left in controller initialization
  final passwordController = TextEditingController(text: 'password123456');
  // Default state flags for login form
  final bool rememberMe = false;
  final bool isSubmitting = false;
}
""",
                "safe": """import 'package:flutter/material.dart';

class LoginFormController {
  final emailController = TextEditingController();
  // Clean initialization without hardcoded credentials
  final passwordController = TextEditingController();
  // Default state flags for login form
  final bool rememberMe = false;
  final bool isSubmitting = false;
}
""",
            }
        },
    },
    {
        "id": "M1-05",
        "category": "M1: Improper Credential Usage",
        "cwe": "CWE-798",
        "expected_rule_id": "M1_HARDCODED_API_SECRET",
        "title": "Hardcoded Third-Party API Secret Key in Dart Service",
        "description": (
            "A Dart service embeds a live third-party secret key (`sk_live_...`) directly in client source code "
            "to authenticate billing and AI moderation calls directly from the handset."
        ),
        "attack_vector": (
            "Extracting strings from the compiled Flutter binary reveals the `sk_live_` master secret key, allowing "
            "adversaries to issue unauthorized refunds, read customer billing records, or exhaust API quotas."
        ),
        "fix_rationale": (
            "Route third-party API operations requiring secret keys through a trusted backend proxy that issues "
            "scoped, ephemeral client tokens."
        ),
        "files": {
            "lib/services/billing_gateway_service.dart": {
                "vulnerable": """class BillingGatewayService {
  static const String endpoint = 'https://api.payment-gateway.id/v1/charges';
  // Hardcoded third-party live secret key in client Dart service
  static const String apiSecret = 'sk_api_secret_snailly_prod_99281';
  // Service timeout configuration
  static const int timeoutSeconds = 30;
  static const int maxRetries = 3;
}
""",
                "safe": """class BillingGatewayService {
  static const String backendProxyEndpoint = 'https://api.snailly.id/v1/billing/ephemeral-intent';
  // Service timeout configuration
  static const int timeoutSeconds = 30;
  static const int maxRetries = 3;
}
""",
            }
        },
    },

    # ==================== M5: INSECURE COMMUNICATION ====================
    {
        "id": "M5-01",
        "category": "M5: Insecure Communication",
        "cwe": "CWE-319",
        "expected_rule_id": "M5_CLEARTEXT_TRAFFIC",
        "title": "Global Cleartext Traffic Allowed in AndroidManifest.xml",
        "description": (
            "The Android application manifest sets `android:usesCleartextTraffic=\"true\"` on the `<application>` "
            "tag without a restricting `network_security_config.xml`, permitting arbitrary unencrypted HTTP connections."
        ),
        "attack_vector": (
            "A Man-in-the-Middle (MitM) attacker on a shared Wi-Fi network performs ARP spoofing or DNS hijacking "
            "to downgrade or intercept unencrypted HTTP traffic transmitted by the app."
        ),
        "fix_rationale": (
            "Set `android:usesCleartextTraffic=\"false\"` in `AndroidManifest.xml` and attach an explicit "
            "`@xml/network_security_config` enforcing HTTPS/TLS across all domains."
        ),
        "files": {
            "android/app/src/main/AndroidManifest.xml": {
                "vulnerable": """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="id.snailly.parental">
    <application
        android:label="Snailly"
        android:usesCleartextTraffic="true"
        android:icon="@mipmap/ic_launcher">
    </application>
</manifest>
""",
                "safe": """<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="id.snailly.parental">
    <application
        android:label="Snailly"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        android:icon="@mipmap/ic_launcher">
    </application>
</manifest>
""",
            }
        },
    },
    {
        "id": "M5-02",
        "category": "M5: Insecure Communication",
        "cwe": "CWE-319",
        "expected_rule_id": "M5_PLAINTEXT_HTTP_URL",
        "title": "Screenshot and Photo Upload via Plain HTTP to Raw IP",
        "description": (
            "Sensitive child device screenshots and activity photos are uploaded over unencrypted `http://` "
            "directly to a hardcoded public IPv4 address (`http://34.124.175.184:8080/upload`)."
        ),
        "attack_vector": (
            "Passive network observers on ISP links, cellular towers, or local Wi-Fi capture multipart HTTP POST "
            "payloads in transit, reconstructing private screenshots of minor users in violation of UU PDP."
        ),
        "fix_rationale": (
            "Transmit all media uploads exclusively over HTTPS (`https://`) to a certificate-validated domain name "
            "with TLS 1.3 encryption."
        ),
        "files": {
            "lib/services/screenshot_uploader.dart": {
                "vulnerable": """class ScreenshotUploader {
  Future<String> getUploadEndpoint(String childId) async {
    // Plaintext HTTP upload to raw remote IP address
    const uploadUrl = 'http://34.124.175.184:8080/upload';
    // Return endpoint for multipart image transmission
    return '$uploadUrl/$childId';
  }
}
""",
                "safe": """class ScreenshotUploader {
  Future<String> getUploadEndpoint(String childId) async {
    // Encrypted HTTPS upload to verified TLS domain
    const uploadUrl = 'https://api.snailly.id/upload';
    // Return endpoint for multipart image transmission
    return '$uploadUrl/$childId';
  }
}
""",
            }
        },
    },
    {
        "id": "M5-03",
        "category": "M5: Insecure Communication",
        "cwe": "CWE-306",
        "expected_rule_id": "M5_UNAUTHENTICATED_MQTT",
        "title": "Public MQTT Broker (broker.emqx.io) Without TLS or Authentication",
        "description": (
            "The background monitoring service connects to a public multi-tenant MQTT broker (`broker.emqx.io`) "
            "on cleartext port 1883 without TLS or client authentication to exchange device control commands."
        ),
        "attack_vector": (
            "Any external actor can subscribe to wildcard topics on `broker.emqx.io` to eavesdrop on telemetry or "
            "publish forged commands that remotely disable child monitoring protections."
        ),
        "fix_rationale": (
            "Deploy a dedicated private MQTT broker enforcing TLS on port 8883 (`..secure = true`) with per-device "
            "client certificate or username/token ACL authentication."
        ),
        "files": {
            "lib/services/mqtt_command_bus.dart": {
                "vulnerable": """class MqttCommandBus {
  late final dynamic _client;

  dynamic initializeClient() {
    // Connect to public unauthenticated MQTT broker over cleartext
    _client = MqttServerClient('broker.emqx.io', 'flutter_client');
    // Client initialized without TLS or credentials
    return _client;
  }
}
""",
                "safe": """class MqttCommandBus {
  late final dynamic _client;

  dynamic initializeClient(String clientId) {
    // Connect to dedicated MQTT broker over TLS port 8883
    _client = MqttServerClient.withPort('mqtt.snailly.id', clientId, 8883)..secure = true;
    // Client enforces TLS transport encryption
    return _client;
  }
}
""",
            }
        },
    },
    {
        "id": "M5-04",
        "category": "M5: Insecure Communication",
        "cwe": "CWE-295",
        "expected_rule_id": "M5_BAD_CERT_CALLBACK",
        "title": "Trusting All SSL Certificates via badCertificateCallback",
        "description": (
            "A custom `HttpClient` overrides `badCertificateCallback` to unconditionally return `true`, "
            "completely disabling X.509 certificate chain and hostname verification across all HTTPS requests."
        ),
        "attack_vector": (
            "An attacker uses mitmproxy or Burp Suite with a self-signed certificate to intercept TLS traffic; "
            "because `badCertificateCallback` returns `true`, the Flutter app blindly accepts the rogue certificate."
        ),
        "fix_rationale": (
            "Never return `true` unconditionally in `badCertificateCallback`. Validate certificates against the "
            "system trust store or enforce SPKI/certificate pinning for known backend hosts."
        ),
        "files": {
            "lib/network/tls_http_client.dart": {
                "vulnerable": """import 'dart:io';

class TlsHttpClientFactory {
  HttpClient createClient() {
    final client = HttpClient();
    // Vulnerable: Trusts all self-signed or tampered SSL certificates
    client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    // Return configured HttpClient
    return client;
  }
}
""",
                "safe": """import 'dart:io';

class TlsHttpClientFactory {
  HttpClient createClient(SecurityContext trustedContext) {
    final client = HttpClient(context: trustedContext);
    // Reject any certificate that fails strict chain verification
    client.badCertificateCallback = (X509Certificate cert, String host, int port) => false;
    // Return configured HttpClient
    return client;
  }
}
""",
            }
        },
    },
    {
        "id": "M5-05",
        "category": "M5: Insecure Communication",
        "cwe": "CWE-319",
        "expected_rule_id": "M5_INSECURE_WEBSOCKET",
        "title": "WebSocket Connection Over Plaintext ws:// Instead of wss://",
        "description": (
            "Real-time alert streaming connects via `WebSocketChannel.connect(Uri.parse('ws://...'))` using "
            "unencrypted WebSocket transport instead of TLS-protected `wss://`."
        ),
        "attack_vector": (
            "Network adversaries along the routing path inspect cleartext WebSocket upgrade headers and frames, "
            "stealing session tokens or injecting fabricated parental alert events into the live stream."
        ),
        "fix_rationale": (
            "Always establish WebSocket channels over TLS using the `wss://` scheme (`Uri.parse('wss://...')`)."
        ),
        "files": {
            "lib/services/realtime_alert_socket.dart": {
                "vulnerable": """class RealtimeAlertSocket {
  dynamic openStream() {
    // Vulnerable: Unencrypted ws:// WebSocket stream
    final channel = WebSocketChannel.connect(Uri.parse('ws://stream.snailly.id:9001/alerts'));
    // Return active WebSocket channel
    return channel;
  }
}
""",
                "safe": """class RealtimeAlertSocket {
  dynamic openStream() {
    // Secure: TLS-encrypted wss:// WebSocket stream
    final channel = WebSocketChannel.connect(Uri.parse('wss://stream.snailly.id/alerts'));
    // Return active WebSocket channel
    return channel;
  }
}
""",
            }
        },
    },

    # ==================== M9: INSECURE DATA STORAGE ====================
    {
        "id": "M9-01",
        "category": "M9: Insecure Data Storage",
        "cwe": "CWE-312",
        "expected_rule_id": "M9_PLAINTEXT_SHARED_PREFS_TOKEN",
        "title": "Plaintext Authentication Token Stored in SharedPreferences",
        "description": (
            "Session bearer tokens are persisted directly in `SharedPreferences` (`prefs.setString('token', token)`), "
            "which writes unencrypted XML files to `/data/data/<package>/shared_prefs/`."
        ),
        "attack_vector": (
            "On a rooted device, via ADB backup extraction, or through local file-read vulnerabilities, an attacker "
            "reads the plaintext XML file and steals long-lived bearer tokens to hijack the user account."
        ),
        "fix_rationale": (
            "Persist authentication tokens exclusively in `FlutterSecureStorage` backed by Android Keystore "
            "(`EncryptedSharedPreferences`) and iOS Keychain."
        ),
        "files": {
            "lib/storage/auth_token_prefs.dart": {
                "vulnerable": """import 'package:shared_preferences/shared_preferences.dart';

class AuthTokenPrefs {
  Future<bool> saveSessionToken(SharedPreferences prefs, String token) async {
    // Vulnerable: Saves bearer token in plaintext SharedPreferences XML
    await prefs.setString('token', token);
    // Token persisted without encryption
    return true;
  }
}
""",
                "safe": """import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AuthTokenPrefs {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<bool> saveSessionToken(String token) async {
    // Secure: Saves bearer token in Keystore/Keychain via FlutterSecureStorage
    await secureStorage.write(key: 'token', value: token);
    // Token persisted with hardware-backed encryption
    return true;
  }
}
""",
            }
        },
    },
    {
        "id": "M9-02",
        "category": "M9: Insecure Data Storage",
        "cwe": "CWE-312",
        "expected_rule_id": "M9_PLAINTEXT_GET_STORAGE_PII",
        "title": "Plaintext User PII Stored in Unencrypted GetStorage",
        "description": (
            "Sensitive Personally Identifiable Information (PII), including child profile records and national IDs, "
            "is written to GetX `GetStorage` (`box.write('user_pii', ...)`), which stores raw unencrypted JSON on disk."
        ),
        "attack_vector": (
            "Forensic extraction or malware with storage access reads the `GetStorage.gs` JSON container directly "
            "from the application document directory, exposing sensitive family and minor PII."
        ),
        "fix_rationale": (
            "Store sensitive PII in `FlutterSecureStorage` or encrypt the local storage payload with an AES-256-GCM "
            "key sealed inside Android Keystore / iOS Keychain."
        ),
        "files": {
            "lib/storage/pii_cache_box.dart": {
                "vulnerable": """class PiiCacheBox {
  Future<bool> cacheUserProfile(dynamic box, String serializedPii) async {
    // Vulnerable: Persists sensitive user PII in unencrypted GetStorage container
    await box.write('user_pii', serializedPii);
    // JSON written to disk in cleartext
    return true;
  }
}
""",
                "safe": """import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class PiiCacheBox {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<bool> cacheUserProfile(String serializedPii) async {
    // Secure: Encrypts user PII using hardware-backed FlutterSecureStorage
    await secureStorage.write(key: 'user_pii', value: serializedPii);
    // PII protected at rest
    return true;
  }
}
""",
            }
        },
    },
    {
        "id": "M9-03",
        "category": "M9: Insecure Data Storage",
        "cwe": "CWE-1078",
        "expected_rule_id": "M9_UNUSED_SECURE_STORAGE_ANOMALY",
        "title": "Vibe Coding Anomaly: flutter_secure_storage Declared in pubspec.yaml With Zero Imports in lib/",
        "description": (
            "The project declares `flutter_secure_storage` in `pubspec.yaml` dependencies (often after an AI prompt "
            "to 'make storage secure'), but zero Dart files in `lib/` ever import or invoke it, leaving all runtime "
            "storage calls on unencrypted legacy mechanisms."
        ),
        "attack_vector": (
            "Developers and superficial dependency scanners assume credentials are encrypted at rest because "
            "`flutter_secure_storage` appears in `pubspec.yaml`, while actual tokens remain exposed in cleartext storage."
        ),
        "fix_rationale": (
            "Import `package:flutter_secure_storage/flutter_secure_storage.dart` in the storage service layer and "
            "verify that all sensitive read/write call sites actively invoke `FlutterSecureStorage`."
        ),
        "files": {
            "pubspec.yaml": {
                "vulnerable": """name: benchmark_m9_03
description: Vibe coding anomaly benchmark case.
version: 1.0.0+1

dependencies:
  flutter:
    sdk: flutter
  shared_preferences: ^2.2.2
  flutter_secure_storage: ^9.0.0
""",
                "safe": """name: benchmark_m9_03
description: Vibe coding anomaly benchmark case (remediated).
version: 1.0.0+1

dependencies:
  flutter:
    sdk: flutter
  flutter_secure_storage: ^9.0.0
""",
            },
            "lib/main.dart": {
                "vulnerable": """import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

void main() {
  // Vibe coding anomaly: security dependency declared in pubspec.yaml but never imported in lib/
  runApp(const SizedBox());
}
""",
                "safe": """import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

const FlutterSecureStorage secureStorage = FlutterSecureStorage();

void main() {
  runApp(const SizedBox());
}
""",
            },
        },
    },
    {
        "id": "M9-04",
        "category": "M9: Insecure Data Storage",
        "cwe": "CWE-312",
        "expected_rule_id": "M9_UNENCRYPTED_SQLITE_SENSITIVE",
        "title": "Unencrypted SQLite Database Storing Biometric Templates and PIN Hashes",
        "description": (
            "The application opens a standard unencrypted SQLite database via `openDatabase('auth_vault.db', ...)` "
            "to store parental control PIN hashes and biometric verification metadata without SQLCipher encryption."
        ),
        "attack_vector": (
            "An attacker pulls `auth_vault.db` from device storage to perform offline GPU hash cracking on the PIN "
            "or overwrite the row with a known PIN hash to bypass parental lock screens."
        ),
        "fix_rationale": (
            "Use `sqflite_sqlcipher` with a 256-bit encryption key retrieved from `FlutterSecureStorage` (`openDatabase(..., password: dbEncryptionKey)`)."
        ),
        "files": {
            "lib/database/biometric_sqlite_vault.dart": {
                "vulnerable": """class BiometricSqliteVault {
  Future<dynamic> initVaultDb() async {
    // Vulnerable: Unencrypted SQLite database storing sensitive pin_hash and biometric_template
    final db = await openDatabase('auth_vault.db', version: 1, onCreate: (db, v) => db.execute('CREATE TABLE vault (id INT, pin_hash TEXT, biometric_template TEXT)'));
    // Database file remains unencrypted on disk
    return db;
  }
}
""",
                "safe": """import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class BiometricSqliteVault {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<dynamic> initVaultDb() async {
    final dbEncryptionKey = await secureStorage.read(key: 'sqlite_master_key');
    // Secure: SQLCipher-encrypted database using hardware-backed password key
    final db = await openDatabase('auth_vault.db', password: dbEncryptionKey, version: 1, onCreate: (db, v) => db.execute('CREATE TABLE vault (id INT, pin_hash TEXT, biometric_template TEXT)'));
    return db;
  }
}
""",
            }
        },
    },
    {
        "id": "M9-05",
        "category": "M9: Insecure Data Storage",
        "cwe": "CWE-732",
        "expected_rule_id": "M9_INSECURE_LOCAL_FILE_TOKEN",
        "title": "Storing Authentication Token in Unencrypted Local File",
        "description": (
            "The application writes raw authentication tokens directly into a plaintext file (`auth_token.txt`) "
            "on local/external storage via `File('.../auth_token.txt').writeAsString(token)`."
        ),
        "attack_vector": (
            "Any process with shared storage access, ADB backup capability, or media-store read access can read "
            "`auth_token.txt` and compromise the authenticated session."
        ),
        "fix_rationale": (
            "Eliminate raw file persistence for credentials and store session tokens exclusively inside "
            "`FlutterSecureStorage`."
        ),
        "files": {
            "lib/storage/local_file_token_store.dart": {
                "vulnerable": """import 'dart:io';

class LocalFileTokenStore {
  Future<bool> persistTokenToFile(String baseDir, String token) async {
    // Vulnerable: Writes session token directly to plaintext local file
    await File('$baseDir/auth_token.txt').writeAsString(token);
    // File stored without hardware keystore protection
    return true;
  }
}
""",
                "safe": """import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class LocalFileTokenStore {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<bool> persistTokenSecurely(String token) async {
    // Secure: Persists session token inside hardware-backed Keystore/Keychain
    await secureStorage.write(key: 'auth_token', value: token);
    // Token isolated from raw filesystem access
    return true;
  }
}
""",
            }
        },
    },
]


def build_all() -> None:
    for case in BENCHMARK_CASES:
        case_dir = BASE_DIR / case["id"]
        vuln_dir = case_dir / "vulnerable"
        safe_dir = case_dir / "safe"

        for rel_path, variants in case["files"].items():
            v_file = vuln_dir / rel_path
            s_file = safe_dir / rel_path
            v_file.parent.mkdir(parents=True, exist_ok=True)
            s_file.parent.mkdir(parents=True, exist_ok=True)
            v_file.write_text(variants["vulnerable"], encoding="utf-8")
            s_file.write_text(variants["safe"], encoding="utf-8")

        metadata = {
            "id": case["id"],
            "category": case["category"],
            "cwe": case["cwe"],
            "title": case["title"],
            "description": case["description"],
            "attack_vector": case["attack_vector"],
            "fix_rationale": case["fix_rationale"],
            "expected_rule_id": case["expected_rule_id"],
        }
        meta_path = case_dir / "metadata.json"
        meta_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"[+] Successfully generated {len(BENCHMARK_CASES)} benchmark pairs in {BASE_DIR}")


if __name__ == "__main__":
    build_all()
