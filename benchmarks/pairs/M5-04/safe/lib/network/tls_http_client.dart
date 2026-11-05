import 'dart:io';

class TlsHttpClientFactory {
  HttpClient createClient(SecurityContext trustedContext) {
    final client = HttpClient(context: trustedContext);
    // Reject any certificate that fails strict chain verification
    client.badCertificateCallback = (X509Certificate cert, String host, int port) => false;
    // Return configured HttpClient
    return client;
  }
}
