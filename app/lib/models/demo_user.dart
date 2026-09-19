/// Synthetic demo identity — POPIA standing gate: dummy data only.
class DemoUser {
  const DemoUser({
    required this.fullName,
    required this.email,
    required this.accountNumber,
    required this.balance,
  });

  final String fullName;
  final String email;
  final String accountNumber;
  final double balance;

  static const demo = DemoUser(
    fullName: 'Neo Serame',
    email: 'neo.serame@demo.molato.local',
    accountNumber: '10098765432',
    balance: 12450.00,
  );
}
