import 'package:flutter/material.dart';

class LoginFormController {
  final emailController = TextEditingController();
  // Clean initialization without hardcoded credentials
  final passwordController = TextEditingController();
  // Default state flags for login form
  final bool rememberMe = false;
  final bool isSubmitting = false;
}
