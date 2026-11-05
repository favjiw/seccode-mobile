import 'package:flutter/material.dart';

class LoginFormController {
  final emailController = TextEditingController(text: 'parent.demo@snailly.id');
  // Pre-filled default password left in controller initialization
  final passwordController = TextEditingController(text: 'password123456');
  // Default state flags for login form
  final bool rememberMe = false;
  final bool isSubmitting = false;
}
