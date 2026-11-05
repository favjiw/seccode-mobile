class BillingGatewayService {
  static const String endpoint = 'https://api.payment-gateway.id/v1/charges';
  // Hardcoded third-party live secret key in client Dart service
  static const String apiSecret = 'sk_api_secret_snailly_prod_99281';
  // Service timeout configuration
  static const int timeoutSeconds = 30;
  static const int maxRetries = 3;
}
