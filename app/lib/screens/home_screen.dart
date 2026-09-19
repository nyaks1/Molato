import 'package:flutter/material.dart';

import '../models/demo_user.dart';
import '../services/insecure_logger.dart';
import 'login_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key, required this.user});

  final DemoUser user;

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  late double _balance;
  final _amountCtrl = TextEditingController();

  @override
  void initState() {
    super.initState();
    _balance = widget.user.balance;
  }

  void _sendMoney() {
    final amount = double.tryParse(_amountCtrl.text.trim());
    if (amount == null || amount <= 0) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(content: Text('Enter a positive amount')),
      );
      return;
    }
    InsecureLogger.transaction(
      fullName: widget.user.fullName,
      accountNumber: widget.user.accountNumber,
      amount: amount,
      currency: 'ZAR',
    );
    setState(() {
      _balance -= amount;
      _amountCtrl.clear();
    });
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Sent ZAR ${amount.toStringAsFixed(2)}')),
    );
  }

  void _logout() {
    InsecureLogger.logout(widget.user.accountNumber, widget.user.fullName);
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const LoginScreen()),
      (route) => false,
    );
  }

  @override
  void dispose() {
    _amountCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final user = widget.user;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Molato'),
        actions: [
          IconButton(
            onPressed: _logout,
            tooltip: 'Log out',
            icon: const Icon(Icons.logout),
          ),
        ],
      ),
      body: ListView(
        padding: const EdgeInsets.all(24),
        children: [
          Text(user.fullName, style: Theme.of(context).textTheme.headlineSmall),
          const SizedBox(height: 4),
          Text(
            'Acc ${user.accountNumber}',
            style: Theme.of(context).textTheme.bodyMedium,
          ),
          const SizedBox(height: 24),
          Card(
            child: ListTile(
              title: const Text('Available balance'),
              subtitle: Text('ZAR ${_balance.toStringAsFixed(2)}'),
            ),
          ),
          const SizedBox(height: 24),
          TextField(
            controller: _amountCtrl,
            keyboardType: TextInputType.number,
            decoration: const InputDecoration(
              labelText: 'Amount (ZAR)',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          FilledButton(onPressed: _sendMoney, child: const Text('Send money')),
          const SizedBox(height: 12),
          OutlinedButton(onPressed: _logout, child: const Text('Log out')),
        ],
      ),
    );
  }
}
