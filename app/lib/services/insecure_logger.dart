/// THE OFFENSE — OWASP M6: Inadequate Privacy Controls.
/// Intentionally dumps raw PII into device logs. Do not "fix" this file;
/// Day 2's detector proves it can find these exact lines.
class InsecureLogger {
  static void login(String email, String accountNumber, String fullName) {
    print('[AUTH] login success user=$fullName email=$email account=$accountNumber');
  }

  static void transaction({
    required String fullName,
    required String accountNumber,
    required double amount,
    required String currency,
  }) {
    print(
      '[TX] processed for $fullName | account=$accountNumber | amount=$currency$amount',
    );
  }

  static void logout(String accountNumber, String fullName) {
    print('[SESSION] logout account=$accountNumber user=$fullName');
  }
}
