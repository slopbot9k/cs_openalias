import 'package:cs_openalias/cs_openalias.dart';

Future<void> printRecipient(
  String alias,
  bool Function(String address) isValidAddress,
) async {
  final recipient = await resolveOpenAlias(
    alias,
    isValidAddress: isValidAddress,
  ).result;
  print(recipient.address);
}
