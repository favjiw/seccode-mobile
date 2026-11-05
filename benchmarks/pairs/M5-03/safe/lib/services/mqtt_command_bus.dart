class MqttCommandBus {
  late final dynamic _client;

  dynamic initializeClient(String clientId) {
    // Connect to dedicated MQTT broker over TLS port 8883
    _client = MqttServerClient.withPort('mqtt.snailly.id', clientId, 8883)..secure = true;
    // Client enforces TLS transport encryption
    return _client;
  }
}
