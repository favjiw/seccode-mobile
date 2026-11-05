class PiiCacheBox {
  Future<bool> cacheUserProfile(dynamic box, String serializedPii) async {
    // Vulnerable: Persists sensitive user PII in unencrypted GetStorage container
    await box.write('user_pii', serializedPii);
    // JSON written to disk in cleartext
    return true;
  }
}
