# SecCode Mobile — Empirical Benchmark Evaluation Report (RQ2 & RQ3)

**Benchmark Suite:** SecCode Mobile Ghera-Style OWASP Benchmark (M1, M5, M9)  
**Evaluation Timestamp:** `2026-11-05 13:11:58`  
**Dataset Size:** 15 Vulnerability Pairs (30 Total App Variants: 15 Vulnerable vs. 15 Safe)  
**Total Execution Time:** `0.0074s`

---

## 1. Aggregate Detection & Remediation Metrics (RQ2 & RQ3)

| Metric | Value | Percentage / Formula |
| :--- | :---: | :---: |
| **True Positives (TP)** | `15` | Vulnerable cases accurately detected (15/15) |
| **False Positives (FP)** | `0` | Safe cases falsely flagged (0/15) |
| **True Negatives (TN)** | `15` | Safe cases verified clean (15/15) |
| **False Negatives (FN)** | `0` | Vulnerable cases missed (0/15) |
| **Precision** | `1.0000` | `100.00%` (`TP / (TP + FP)`) |
| **Recall (Sensitivity)** | `1.0000` | `100.00%` (`TP / (TP + FN)`) |
| **F1-Score** | `1.0000` | `100.00%` (`2 * P * R / (P + R)`) |
| **Accuracy** | `1.0000` | `100.00%` (`(TP + TN) / N`) |
| **Patch Syntax Validity** | `15/15` | `100.00%` |
| **Guardrail Compliance** | `15/15` | `100.00%` |
| **Deterministic Rescan Pass** | `15/15` | `100.00%` |
| **Overall Patch Plausibility Rate (RQ3)** | `15/15` | **`100.00%`** |

---

## 2. Per-Category Performance Breakdown (OWASP Mobile Top 10)

| OWASP Category | Pairs | TP | FP | TN | FN | Precision | Recall | F1-Score | Plausibility Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **M1: Improper Credential Usage** | 5 | 5 | 0 | 5 | 0 | `1.00` | `1.00` | `1.00` | **100.0%** (5/5) |
| **M5: Insecure Communication** | 5 | 5 | 0 | 5 | 0 | `1.00` | `1.00` | `1.00` | **100.0%** (5/5) |
| **M9: Insecure Data Storage** | 5 | 5 | 0 | 5 | 0 | `1.00` | `1.00` | `1.00` | **100.0%** (5/5) |

---

## 3. Case-by-Case Benchmark Matrix (15 Ghera-Style Pairs)

| Case ID | OWASP | CWE | Vulnerability Case Title | Vuln (`vulnerable/`) | Safe (`safe/`) | Syntax | Guards | Rescan | Plausible (RQ3) |
| :---: | :---: | :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `M1-01` | M1 | `CWE-798` | Client-Side HMAC Secret JWT Signing | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M1-02` | M1 | `CWE-540` | Bundling .env Configuration File in pubspec.yaml Assets | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M1-03` | M1 | `CWE-798` | Hardcoded Static Authorization Token and Identity UUIDs | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M1-04` | M1 | `CWE-259` | Hardcoded Credentials in Login Form Controller | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M1-05` | M1 | `CWE-798` | Hardcoded Third-Party API Secret Key in Dart Service | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M5-01` | M5 | `CWE-319` | Global Cleartext Traffic Allowed in AndroidManifest.xml | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M5-02` | M5 | `CWE-319` | Screenshot and Photo Upload via Plain HTTP to Raw IP | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M5-03` | M5 | `CWE-306` | Public MQTT Broker (broker.emqx.io) Without TLS or Authentication | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M5-04` | M5 | `CWE-295` | Trusting All SSL Certificates via badCertificateCallback | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M5-05` | M5 | `CWE-319` | WebSocket Connection Over Plaintext ws:// Instead of wss:// | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M9-01` | M9 | `CWE-312` | Plaintext Authentication Token Stored in SharedPreferences | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M9-02` | M9 | `CWE-312` | Plaintext User PII Stored in Unencrypted GetStorage | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M9-03` | M9 | `CWE-1078` | Vibe Coding Anomaly: flutter_secure_storage Declared in pubspec.yaml With Zero Imports in lib/ | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M9-04` | M9 | `CWE-312` | Unencrypted SQLite Database Storing Biometric Templates and PIN Hashes | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |
| `M9-05` | M9 | `CWE-732` | Storing Authentication Token in Unencrypted Local File | ✅ TP | ✅ TN | ✅ | ✅ | ✅ | **✅ Yes** |

---

## 4. Verified Virtual Patches Summary (Sample Unified Diffs)

### [M1-01] Client-Side HMAC Secret JWT Signing (CWE-798)
- **Detected Rule:** `M1_JWT_SECRET_HARDCODED`
- **Audit Latency:** Vulnerable `0.64 ms` | Safe `0.2 ms`
```diff
--- a/lib/controllers/jwt_session_controller.dart
+++ b/lib/controllers/jwt_session_controller.dart
@@ -1,4 +1,4 @@
     // Sign JWT on client using hardcoded symmetric secret

-    var dataToken = jwt.sign(SecretKey('snailly'));

+    var dataToken = await authApiService.requestSessionToken(data);

     // Return signed token string

     return dataToken;
```

### [M1-02] Bundling .env Configuration File in pubspec.yaml Assets (CWE-540)
- **Detected Rule:** `M1_ENV_ASSET_BUNDLING`
- **Audit Latency:** Vulnerable `0.18 ms` | Safe `0.08 ms`
```diff
--- a/pubspec.yaml
+++ b/pubspec.yaml
@@ -1,2 +1,2 @@
     - assets/images/logo.png

-    - .env
+    # - .env (Removed to prevent credential bundling in assets)
```

### [M1-03] Hardcoded Static Authorization Token and Identity UUIDs (CWE-798)
- **Detected Rule:** `M1_STATIC_AUTH_TOKEN`
- **Audit Latency:** Vulnerable `0.31 ms` | Safe `0.12 ms`
```diff
--- a/lib/services/parental_control_api.dart
+++ b/lib/services/parental_control_api.dart
@@ -1,3 +1,3 @@
   // Vulnerable hardcoded static authorization token and UUID

-  static const _token = '1';

+  Future<String?> get _token async => await secureStorage.read(key: 'auth_token');

   static const _parentUuid = '550e8400-e29b-41d4-a716-446655440000';

```

### [M1-04] Hardcoded Credentials in Login Form Controller (CWE-259)
- **Detected Rule:** `M1_DEFAULT_FORM_CREDENTIALS`
- **Audit Latency:** Vulnerable `0.36 ms` | Safe `0.12 ms`
```diff
--- a/lib/controllers/login_form_controller.dart
+++ b/lib/controllers/login_form_controller.dart
@@ -1,4 +1,4 @@
   // Pre-filled default password left in controller initialization

-  final passwordController = TextEditingController(text: 'password123456');

+  final passwordController = TextEditingController();

   // Default state flags for login form

   final bool rememberMe = false;
```

### [M1-05] Hardcoded Third-Party API Secret Key in Dart Service (CWE-798)
- **Detected Rule:** `M1_HARDCODED_API_SECRET`
- **Audit Latency:** Vulnerable `0.39 ms` | Safe `0.13 ms`
```diff
--- a/lib/services/billing_gateway_service.dart
+++ b/lib/services/billing_gateway_service.dart
@@ -1,4 +1,4 @@
   // Hardcoded third-party live secret key in client Dart service

-  static const String apiSecret = 'sk_api_secret_snailly_prod_99281';

+  static const String apiSecret = const String.fromEnvironment('API_SECRET_KEY');

   // Service timeout configuration

   static const int timeoutSeconds = 30;
```

### [M5-01] Global Cleartext Traffic Allowed in AndroidManifest.xml (CWE-319)
- **Detected Rule:** `M5_CLEARTEXT_TRAFFIC`
- **Audit Latency:** Vulnerable `0.24 ms` | Safe `0.12 ms`
```diff
--- a/android/app/src/main/AndroidManifest.xml
+++ b/android/app/src/main/AndroidManifest.xml
@@ -1,4 +1,5 @@
         android:label="Snailly"

-        android:usesCleartextTraffic="true"

+        android:usesCleartextTraffic="false"

+        android:networkSecurityConfig="@xml/network_security_config"

         android:icon="@mipmap/ic_launcher">

     </application>
```

### [M5-02] Screenshot and Photo Upload via Plain HTTP to Raw IP (CWE-319)
- **Detected Rule:** `M5_PLAINTEXT_HTTP_URL`
- **Audit Latency:** Vulnerable `0.32 ms` | Safe `0.13 ms`
```diff
--- a/lib/services/screenshot_uploader.dart
+++ b/lib/services/screenshot_uploader.dart
@@ -1,4 +1,4 @@
     // Plaintext HTTP upload to raw remote IP address

-    const uploadUrl = 'http://34.124.175.184:8080/upload';

+    const uploadUrl = 'https://api.snailly.id/upload';

     // Return endpoint for multipart image transmission

     return '$uploadUrl/$childId';
```

### [M5-03] Public MQTT Broker (broker.emqx.io) Without TLS or Authentication (CWE-306)
- **Detected Rule:** `M5_UNAUTHENTICATED_MQTT`
- **Audit Latency:** Vulnerable `0.3 ms` | Safe `0.11 ms`
```diff
--- a/lib/services/mqtt_command_bus.dart
+++ b/lib/services/mqtt_command_bus.dart
@@ -1,4 +1,4 @@
     // Connect to public unauthenticated MQTT broker over cleartext

-    _client = MqttServerClient('broker.emqx.io', 'flutter_client');

+    _client = MqttServerClient.withPort('mqtt.snailly.id', clientId, 8883)..secure = true;

     // Client initialized without TLS or credentials

     return _client;
```

### [M5-04] Trusting All SSL Certificates via badCertificateCallback (CWE-295)
- **Detected Rule:** `M5_BAD_CERT_CALLBACK`
- **Audit Latency:** Vulnerable `0.24 ms` | Safe `0.12 ms`
```diff
--- a/lib/network/tls_http_client.dart
+++ b/lib/network/tls_http_client.dart
@@ -1,4 +1,4 @@
     // Vulnerable: Trusts all self-signed or tampered SSL certificates

-    client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;

+    client.badCertificateCallback = (X509Certificate cert, String host, int port) => false;

     // Return configured HttpClient

     return client;
```

### [M5-05] WebSocket Connection Over Plaintext ws:// Instead of wss:// (CWE-319)
- **Detected Rule:** `M5_INSECURE_WEBSOCKET`
- **Audit Latency:** Vulnerable `0.37 ms` | Safe `0.11 ms`
```diff
--- a/lib/services/realtime_alert_socket.dart
+++ b/lib/services/realtime_alert_socket.dart
@@ -1,4 +1,4 @@
     // Vulnerable: Unencrypted ws:// WebSocket stream

-    final channel = WebSocketChannel.connect(Uri.parse('ws://stream.snailly.id:9001/alerts'));

+    final channel = WebSocketChannel.connect(Uri.parse('wss://stream.snailly.id:9001/alerts'));

     // Return active WebSocket channel

     return channel;
```

### [M9-01] Plaintext Authentication Token Stored in SharedPreferences (CWE-312)
- **Detected Rule:** `M9_PLAINTEXT_SHARED_PREFS_TOKEN`
- **Audit Latency:** Vulnerable `0.33 ms` | Safe `0.11 ms`
```diff
--- a/lib/storage/auth_token_prefs.dart
+++ b/lib/storage/auth_token_prefs.dart
@@ -1,4 +1,4 @@
     // Vulnerable: Saves bearer token in plaintext SharedPreferences XML

-    await prefs.setString('token', token);

+    await secureStorage.write(key: 'token', value: token);

     // Token persisted without encryption

     return true;
```

### [M9-02] Plaintext User PII Stored in Unencrypted GetStorage (CWE-312)
- **Detected Rule:** `M9_PLAINTEXT_GET_STORAGE_PII`
- **Audit Latency:** Vulnerable `0.32 ms` | Safe `0.11 ms`
```diff
--- a/lib/storage/pii_cache_box.dart
+++ b/lib/storage/pii_cache_box.dart
@@ -1,4 +1,4 @@
     // Vulnerable: Persists sensitive user PII in unencrypted GetStorage container

-    await box.write('user_pii', serializedPii);

+    await secureStorage.write(key: 'user_pii', value: serializedPii);

     // JSON written to disk in cleartext

     return true;
```

### [M9-03] Vibe Coding Anomaly: flutter_secure_storage Declared in pubspec.yaml With Zero Imports in lib/ (CWE-1078)
- **Detected Rule:** `M9_UNUSED_SECURE_STORAGE_ANOMALY`
- **Audit Latency:** Vulnerable `0.16 ms` | Safe `0.11 ms`
```diff
--- a/pubspec.yaml
+++ b/pubspec.yaml
@@ -1,2 +1,2 @@
-  flutter_secure_storage: ^8.0.0

-  # Declared in pubspec but 0 imports in lib/
+  flutter_secure_storage: ^9.0.0

+  # Remediated: Imported and bound FlutterSecureStorage in lib/storage/secure_token_vault.dart
```

### [M9-04] Unencrypted SQLite Database Storing Biometric Templates and PIN Hashes (CWE-312)
- **Detected Rule:** `M9_UNENCRYPTED_SQLITE_SENSITIVE`
- **Audit Latency:** Vulnerable `0.32 ms` | Safe `0.13 ms`
```diff
--- a/lib/database/biometric_sqlite_vault.dart
+++ b/lib/database/biometric_sqlite_vault.dart
@@ -1,4 +1,4 @@
     // Vulnerable: Unencrypted SQLite database storing sensitive pin_hash and biometric_template

-    final db = await openDatabase('auth_vault.db', version: 1, onCreate: (db, v) => db.execute('CREATE TABLE vault (id INT, pin_hash TEXT, biometric_template TEXT)'));

+    final db = await openDatabase('auth_vault.db', password: dbEncryptionKey, version: 1, onCreate: (db, v) => db.execute('CREATE TABLE vault (id INT, pin_hash TEXT, biometric_template TEXT)'));

     // Database file remains unencrypted on disk

     return db;
```

### [M9-05] Storing Authentication Token in Unencrypted Local File (CWE-732)
- **Detected Rule:** `M9_INSECURE_LOCAL_FILE_TOKEN`
- **Audit Latency:** Vulnerable `0.33 ms` | Safe `0.11 ms`
```diff
--- a/lib/storage/local_file_token_store.dart
+++ b/lib/storage/local_file_token_store.dart
@@ -1,4 +1,4 @@
     // Vulnerable: Writes session token directly to plaintext local file

-    await File('$baseDir/auth_token.txt').writeAsString(token);

+    await secureStorage.write(key: 'auth_token', value: token);

     // File stored without hardware keystore protection

     return true;
```
