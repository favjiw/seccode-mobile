import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class BiometricSqliteVault {
  final FlutterSecureStorage secureStorage = const FlutterSecureStorage();

  Future<dynamic> initVaultDb() async {
    final dbEncryptionKey = await secureStorage.read(key: 'sqlite_master_key');
    // Secure: SQLCipher-encrypted database using hardware-backed password key
    final db = await openDatabase('auth_vault.db', password: dbEncryptionKey, version: 1, onCreate: (db, v) => db.execute('CREATE TABLE vault (id INT, pin_hash TEXT, biometric_template TEXT)'));
    return db;
  }
}
