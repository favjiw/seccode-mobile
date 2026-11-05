class ScreenshotUploader {
  Future<String> getUploadEndpoint(String childId) async {
    // Encrypted HTTPS upload to verified TLS domain
    const uploadUrl = 'https://api.snailly.id/upload';
    // Return endpoint for multipart image transmission
    return '$uploadUrl/$childId';
  }
}
