import 'dart:io';

class TlsHttpClientFactory {
  HttpClient createClient() {
    final client = HttpClient();
    // Vulnerable: Trusts all self-signed or tampered SSL certificates
    client.badCertificateCallback = (X509Certificate cert, String host, int port) => true;
    // Return configured HttpClient
    return client;
  }
}
