import 'package:cs_openalias/cs_openalias.dart';

Future<void> printRecipient(
  String alias,
  bool Function(String) validateAddress,
) async {
  final resolver = CsOpenAliasResolver(validateAddress: validateAddress);
  final recipient = await resolver.resolve(alias);
  print(recipient.address);
}
