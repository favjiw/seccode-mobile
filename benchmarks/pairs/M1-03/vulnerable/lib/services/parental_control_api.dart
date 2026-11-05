class ParentalControlApi {
  static const _baseUrl = 'https://api.snailly.id/v1';
  // Vulnerable hardcoded static authorization token and UUID
  static const _token = '1';
  static const _parentUuid = '550e8400-e29b-41d4-a716-446655440000';

  Map<String, String> buildHeaders() {
    return {'Authorization': 'Bearer $_token', 'X-Parent-Id': _parentUuid};
  }
}
