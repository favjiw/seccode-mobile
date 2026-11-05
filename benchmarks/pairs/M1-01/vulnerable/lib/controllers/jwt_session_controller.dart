import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

class JwtSessionController {
  Future<String> generateClientToken(Map<String, dynamic> data) async {
    final jwt = JWT(data, issuer: 'snailly_mobile_client');
    // Sign JWT on client using hardcoded symmetric secret
    var dataToken = jwt.sign(SecretKey('snailly'));
    // Return signed token string
    return dataToken;
  }
}
