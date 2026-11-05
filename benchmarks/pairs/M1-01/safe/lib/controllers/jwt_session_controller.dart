class AuthApiService {
  Future<String> requestSessionToken(Map<String, dynamic> payload) async {
    return 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.backend_issued';
  }
}

class JwtSessionController {
  final AuthApiService authApiService;
  JwtSessionController(this.authApiService);

  Future<String> generateClientToken(Map<String, dynamic> data) async {
    // Delegate JWT signing to backend authority
    final dataToken = await authApiService.requestSessionToken(data);
    return dataToken;
  }
}
