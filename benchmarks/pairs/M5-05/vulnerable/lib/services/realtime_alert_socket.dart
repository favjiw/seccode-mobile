class RealtimeAlertSocket {
  dynamic openStream() {
    // Vulnerable: Unencrypted ws:// WebSocket stream
    final channel = WebSocketChannel.connect(Uri.parse('ws://stream.snailly.id:9001/alerts'));
    // Return active WebSocket channel
    return channel;
  }
}
