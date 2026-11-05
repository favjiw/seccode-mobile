import 'package:shared_preferences/shared_preferences.dart';

class AuthTokenPrefs {
  Future<bool> saveSessionToken(SharedPreferences prefs, String token) async {
    // Vulnerable: Saves bearer token in plaintext SharedPreferences XML
    await prefs.setString('token', token);
    // Token persisted without encryption
    return true;
  }
}
