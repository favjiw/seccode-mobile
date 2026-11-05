class MqttCommandBus {
  late final dynamic _client;

  dynamic initializeClient() {
    // Connect to public unauthenticated MQTT broker over cleartext
    _client = MqttServerClient('broker.emqx.io', 'flutter_client');
    // Client initialized without TLS or credentials
    return _client;
  }
}
