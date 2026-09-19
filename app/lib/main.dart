import 'package:flutter/material.dart';

import 'screens/login_screen.dart';

void main() {
  runApp(const MolatoApp());
}

class MolatoApp extends StatelessWidget {
  const MolatoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Molato',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1B4332)),
        useMaterial3: true,
      ),
      home: const LoginScreen(),
    );
  }
}
