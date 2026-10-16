## 0.0.1

- `resolveOpenAlias` looks up an OpenAlias name over DNS over HTTPS, directly
  or only through a SOCKS5 proxy, validates the answer with DNSSEC on the
  device and returns its one `oa1:xmr` recipient as a cancellable
  operation. Failures are leaves of the sealed `CsOpenAliasException`, each
  carrying its `alias` and a ready-to-show `userMessage`.
