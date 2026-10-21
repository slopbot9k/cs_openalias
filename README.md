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
// lookup.cancel() stops further queries and closes the connection early;
// the alias may already have been sent in the first query.
try {
  final recipient = await lookup.result;
  print(recipient.address);
} on CsOpenAliasException catch (error) {
  showError(describeForUser(error));
}
```

`isOpenAlias` tells whether input is an alias at all. The lookup lowercases
it and turns `user@domain` into `user.domain`; `recipient.domain` is that
name.

## Network and trust

- Queries go to `https://dns.google/dns-query` at `8.8.8.8`, so no local DNS
  lookup happens; TLS still verifies `dns.google`. Queries are padded.
- `proxy` is required; with `null` the lookup connects directly. With a
  proxy, the lookup connects only through that SOCKS5 proxy, using fresh
  isolation credentials, and never falls back to a direct connection. The
  proxy address must be a numeric IP; otherwise `resolveOpenAlias` throws
  `ArgumentError`.
- Each lookup owns one transport, reuses its connections and closes it once
  when the lookup succeeds, fails or is cancelled. `cancel` stops the DNSSEC
  lookup and every request in flight.
- Deadlines: connect 5 s, request 12 s, whole lookup 20 s; through a proxy
  10 s, 20 s and 40 s. At most 64 queries per lookup, validated from the IANA
  root keys.
- Only a DNSSEC-secure TXT answer for the alias is used. Other records are
  ignored without being decoded. Of its `oa1:xmr` records exactly one
  recipient address must remain, and it must pass `isValidAddress`. A
  non-empty `tx_payment_id` is rejected. `recipient_name` and
  `tx_description` are untrusted display text; `checksum` and
  `address_signature` are not verified.
- A package re-validates what crosses a public port whose implementation the
  caller supplies; it does not re-check what a private seam or a known sibling
  package already guarantees. cs_openalias repeats none of its constituents'
  checks.
- The resolver sees every query and, without a proxy, your IP address.

## Errors

`result` fails with a leaf of the sealed `CsOpenAliasException`; `cause`
keeps the underlying error and is never printed by `toString`. Each error
carries the `alias` the lookup was for and a developer `message`; wording for
users is the app's choice.

| Leaf | Meaning |
| --- | --- |
| `CsOpenAliasInvalidAliasException` | not an alias |
| `CsOpenAliasNoRecordException` | no `oa1:xmr` record, or DNSSEC proved there is no TXT record |
| `CsOpenAliasInvalidRecordException` | malformed or non-UTF-8 record, duplicate or unsupported field, oversized record, several addresses or conflicting records, or address rejected |
| `CsOpenAliasDnssecException` | not secure; `status` is `insecure`, `bogus` or `indeterminate` |
| `CsOpenAliasNetworkException` | connection, proxy, TLS or HTTP failure, error rcode, CNAME loop, chain or conflict, mismatched question, malformed or oversized response, validator unavailable, or an oversized answer; `timeout` is set when a deadline passed |
| `CsOpenAliasCancelledException` | the lookup was cancelled |

Errors thrown by `isValidAddress` propagate.

## Development

In the repository, with Dart 3.10 and rustup (Rust 1.90.0 and the target you
build for), `dart tool/check.dart` runs format, analyze, the unit and
integration tests and a publish dry run, `OPENALIAS_LIVE_TESTS=1` enables the
live test against dns.google, `example/tool/generate_fixtures.sh` regenerates
the integration fixtures from `DNSSEC_RESOLVER_DIR` (default
`../../dnssec_resolver` from `example/`) and `example/bin/main.dart` performs
one lookup.

```sh
dart tool/check.dart
OPENALIAS_LIVE_TESTS=1 dart test test/live_test.dart
example/tool/generate_fixtures.sh
cd example && dart run bin/main.dart donate@getmonero.org
```

To develop against local checkouts of `openalias`, `dnssec_resolver` and
`doh_transport`, clone them beside this repository and add an untracked
`pubspec_overrides.yaml` here and in `example/`:

```yaml
dependency_overrides:
  openalias:
    path: ../openalias
  dnssec_resolver:
    path: ../dnssec_resolver
  doh_transport:
    path: ../doh_transport
```

In `example/`, the paths start with `../../`.

## License

MIT; see `LICENSE`.
