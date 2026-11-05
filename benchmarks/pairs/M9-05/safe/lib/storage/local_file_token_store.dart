import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class LocalFileTokenStore {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<bool> persistTokenSecurely(String token) async {
    // Secure: Persists session token inside hardware-backed Keystore/Keychain
    await secureStorage.write(key: 'auth_token', value: token);
    // Token isolated from raw filesystem access
    return true;
  }
}
