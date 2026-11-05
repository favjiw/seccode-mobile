import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class ParentalControlApi {
  static const _baseUrl = 'https://api.snailly.id/v1';
  final FlutterSecureStorage secureStorage;

  ParentalControlApi(this.secureStorage);

  Future<Map<String, String>> buildHeaders() async {
    final token = await secureStorage.read(key: 'auth_token');
    final parentUuid = await secureStorage.read(key: 'parent_uuid');
    return {
      'Authorization': 'Bearer ${token ?? ""}',
      'X-Parent-Id': parentUuid ?? '',
    };
  }
}
