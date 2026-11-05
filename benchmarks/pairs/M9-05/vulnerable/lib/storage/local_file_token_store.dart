import 'dart:io';

class LocalFileTokenStore {
  Future<bool> persistTokenToFile(String baseDir, String token) async {
    // Vulnerable: Writes session token directly to plaintext local file
    await File('$baseDir/auth_token.txt').writeAsString(token);
    // File stored without hardware keystore protection
    return true;
  }
}
