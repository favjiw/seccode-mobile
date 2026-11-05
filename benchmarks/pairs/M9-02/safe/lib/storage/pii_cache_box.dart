import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class PiiCacheBox {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<bool> cacheUserProfile(String serializedPii) async {
    // Secure: Encrypts user PII using hardware-backed FlutterSecureStorage
    await secureStorage.write(key: 'user_pii', value: serializedPii);
    // PII protected at rest
    return true;
  }
}
