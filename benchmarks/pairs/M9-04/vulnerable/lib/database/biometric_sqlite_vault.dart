class BiometricSqliteVault {
  Future<dynamic> initVaultDb() async {
    // Vulnerable: Unencrypted SQLite database storing sensitive pin_hash and biometric_template
    final db = await openDatabase('auth_vault.db', version: 1, onCreate: (db, v) => db.execute('CREATE TABLE vault (id INT, pin_hash TEXT, biometric_template TEXT)'));
    // Database file remains unencrypted on disk
    return db;
  }
}
