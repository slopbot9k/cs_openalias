# cs_openalias

Secure OpenAlias resolution composed from `openalias`, local validation from
`dnssec_resolver`, and DNS-over-HTTPS networking from `doh_transport`.

## Usage

```dart
import 'package:cs_openalias/cs_openalias.dart';

final resolver = CsOpenAliasResolver(
  validateAddress: isValidMoneroAddress,
  isAllowed: () => privacySettings.allowExternalCalls,
);
final recipient = await resolver.resolve('donate@getmonero.org');
print(recipient.address);
```

`startResolve` returns a `CsOpenAliasOperation` whose `cancel` callback owns
the complete DNSSEC lookup and all outstanding key requests.

## Network and privacy model

Each lookup owns one transport session and closes it on success, failure, or
cancellation. Closure starts before the result is delivered; socket teardown
may finish asynchronously. The default endpoint is
`https://dns.google/dns-query`, reached at the fixed numeric destination
`8.8.8.8`; TLS continues to verify the endpoint hostname. Configure a numeric
`CsOpenAliasProxy` to use SOCKS. Every proxied lookup gets fresh isolation
credentials, while connections are reused only inside that lookup.

`isAllowed` is checked before session creation, before every DNS exchange,
after every response, and before returning a recipient. Revocation cancels the
lookup. There is no direct-network fallback when proxy creation or use fails.

Passing `networkFactory` replaces the default transport. The facade calls
`create` once per lookup and calls the returned session's `close` exactly once.
Each `startWire` operation must enforce its response bound, provide idempotent
cancellation that releases pending work, and keep independent lookups and
lanes isolated. A custom factory—or `httpClientFactory` in network options—owns
its TLS verification, numeric-destination, proxy, redirect, deadline,
connection-reuse, and no-fallback guarantees; the facade cannot restore
guarantees bypassed by injected networking. DNSSEC still independently checks
HTTP status, body bounds, wire framing/question identity, and response Age.
The facade calls `DnssecResult.secureTxt()` before constructing the trusted
OpenAlias TXT answer. Insecure, bogus, indeterminate, malformed, and
unavailable validation therefore fail as typed facade errors before OpenAlias
parsing; no validator token is treated as independent proof.

The public API exposes only facade-owned operations, results, configuration,
network-test seams, and a sealed exception family. Lower-package result and
exception types do not cross the boundary.

## Development

Use Dart 3.10 or later and rustup with Rust 1.90.0. The DNSSEC build hook
also needs the Rust target for the platform you are building for.

The core packages are not published yet. Clone `openalias`, `dnssec_resolver`,
and `doh_transport` beside this repository, then add an untracked
`pubspec_overrides.yaml`:

```yaml
dependency_overrides:
  openalias:
    path: ../openalias
  dnssec_resolver:
    path: ../dnssec_resolver
  doh_transport:
    path: ../doh_transport
```

Run `dart tool/check.dart` from the repository root. It resolves dependencies,
checks formatting and analysis, runs the tests, and performs a publish dry run;
it does not publish. Opt-in live tests run with
`OPENALIAS_LIVE_TESTS=1 dart test test/live_test.dart`.

Integration fixtures retain their adjacent license notice.

## License

MIT; see `LICENSE`.
