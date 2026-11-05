class ScreenshotUploader {
  Future<String> getUploadEndpoint(String childId) async {
    // Plaintext HTTP upload to raw remote IP address
    const uploadUrl = 'http://34.124.175.184:8080/upload';
    // Return endpoint for multipart image transmission
    return '$uploadUrl/$childId';
  }
}
