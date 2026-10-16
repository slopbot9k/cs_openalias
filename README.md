# cs_openalias

OpenAlias lookups for Monero wallets: DNS over HTTPS from `doh_transport`,
on-device DNSSEC validation from `dnssec_resolver`, and record parsing from
`openalias`, behind one call.

## Usage

```dart
import 'package:cs_openalias/cs_openalias.dart';

final lookup = resolveOpenAlias(
  'donate@getmonero.org',
  isValidAddress: isValidMoneroAddress,
  proxy: torEnabled
      ? const CsOpenAliasProxy(address: '127.0.0.1', port: 9050)
      : null,
);
// Call lookup.cancel() if the user leaves or the network settings change.
try {
  final recipient = await lookup.result;
  print(recipient.address);
} on CsOpenAliasException catch (error) {
  showError(error.userMessage);
}
```

`normalizeOpenAlias` lowercases an alias and turns `user@domain` into
`user.domain`; it throws `CsOpenAliasInvalidAliasException` for anything
else, so it also tells whether input is an alias at all.

## Network and trust

- Queries go to `https://dns.google/dns-query` at `8.8.8.8`, so no local DNS
  lookup happens; TLS still verifies `dns.google`. Queries are padded.
- Without `proxy` the lookup connects directly. With it, the lookup connects
  only through that SOCKS5 proxy, using fresh isolation credentials, and never
  falls back to a direct connection. The proxy address must be a numeric IP;
  otherwise `resolveOpenAlias` throws `ArgumentError`.
- Each lookup owns one transport, reuses its connections and closes it once
  when the lookup succeeds, fails or is cancelled. `cancel` stops the DNSSEC
  lookup and every request in flight.
- Deadlines: connect 5 s, request 12 s, whole lookup 20 s; through a proxy
  10 s, 20 s and 40 s. At most 64 queries per lookup, validated from the IANA
  root keys.
- Only a DNSSEC-secure TXT answer for the alias is used. Of its `oa1:xmr`
  records exactly one recipient address must remain, and it must pass
  `isValidAddress`. `tx_payment_id` is rejected. `recipient_name` and
  `tx_description` are untrusted display text; `checksum` and
  `address_signature` are not verified.
- The resolver sees every query and, without a proxy, your IP address.

## Errors

`result` fails with a leaf of the sealed `CsOpenAliasException`; `cause`
keeps the underlying error and is never printed by `toString`. Each error
carries the `alias` the lookup was for and a ready-to-show English
`userMessage`; `openAliasLookupFailedTitle` is a matching dialog title.

| Leaf | Meaning |
| --- | --- |
| `CsOpenAliasInvalidAliasException` | not an alias |
| `CsOpenAliasNoRecordException` | no `oa1:xmr` record, or DNSSEC proved there is no TXT record |
| `CsOpenAliasAmbiguousException` | several addresses or conflicting records |
| `CsOpenAliasInvalidRecordException` | malformed record, duplicate or unsupported field, limit exceeded, or address rejected |
| `CsOpenAliasDnssecException` | not secure; `status` is `insecure`, `bogus` or `indeterminate` |
| `CsOpenAliasDnsException` | error rcode, CNAME loop or chain, mismatched question, malformed or oversized response |
| `CsOpenAliasNetworkException` | connection, proxy, TLS or HTTP failure, validator unavailable; `timeout` is set when a deadline passed |
| `CsOpenAliasCancelledException` | the lookup was cancelled |

Errors thrown by `isValidAddress` propagate unchanged.

## Development

Use Dart 3.10 or later and rustup with Rust 1.90.0; the DNSSEC build hook
also needs the Rust target of the platform you build for.

The constituent packages are not published yet. Clone `openalias`,
`dnssec_resolver` and `doh_transport` beside this repository and add an
untracked `pubspec_overrides.yaml` here:

```yaml
dependency_overrides:
  openalias:
    path: ../openalias
  dnssec_resolver:
    path: ../dnssec_resolver
  doh_transport:
    path: ../doh_transport
```

and the same in `example/` with `../../` paths.

- `dart tool/check.dart` resolves dependencies, checks formatting and
  analysis, runs the unit tests and the example's integration suite, and
  performs a publish dry run.
- `example/tool/generate_fixtures.sh` regenerates the integration fixtures
  from a `dnssec_resolver` checkout (`DNSSEC_RESOLVER_DIR`, default
  `../../dnssec_resolver` from `example/`).
- `OPENALIAS_LIVE_TESTS=1 dart test test/live_test.dart` queries dns.google.
- `dart run bin/main.dart donate@getmonero.org [<proxy ip> <proxy port>]` in
  `example/` performs one lookup.

`example/integration_test/support/LICENSE` covers the test support files
copied from `doh_transport`.

## License

MIT; see `LICENSE`.
