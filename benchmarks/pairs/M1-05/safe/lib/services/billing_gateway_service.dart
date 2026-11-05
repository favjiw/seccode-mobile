class BillingGatewayService {
  static const String backendProxyEndpoint = 'https://api.snailly.id/v1/billing/ephemeral-intent';
  // Service timeout configuration
  static const int timeoutSeconds = 30;
  static const int maxRetries = 3;
}
