import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class AuthTokenPrefs {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<bool> saveSessionToken(String token) async {
    // Secure: Saves bearer token in Keystore/Keychain via FlutterSecureStorage
    await secureStorage.write(key: 'token', value: token);
    // Token persisted with hardware-backed encryption
    return true;
  }
}
