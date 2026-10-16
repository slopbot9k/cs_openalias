#!/bin/sh
# Regenerates integration_test/support/zones.json from dnssec_resolver's
# signed fixture zones. DNSSEC_RESOLVER_DIR defaults to a sibling checkout.
set -eu
cd "$(dirname "$0")/.."
dir=${DNSSEC_RESOLVER_DIR:-../../dnssec_resolver}
out=integration_test/support/zones.json
cargo +1.90.0 run --quiet --locked --manifest-path "$dir/native/Cargo.toml" \
  --example fixtures > "$out.tmp"
mv "$out.tmp" "$out"
