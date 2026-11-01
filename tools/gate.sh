#!/bin/sh
# De poort (handboek §9): host-tests, clippy met de harde set, rustfmt, en de
# no_std-bouw voor het target. Rood is rood.
set -e
cd "$(dirname "$0")/.."
echo "== host: cargo test"
cargo test --quiet
echo "== host: cargo clippy"
cargo clippy --all-targets --quiet -- -D warnings
echo "== host: leannet met de feature ipv6"
# De IPv6-baan staat standaard uit; zijn toetsen en clippy draaien hier.
cargo test --quiet -p leannet --features ipv6
cargo clippy --all-targets --quiet -p leannet --features ipv6 -- -D warnings
echo "== host: leanhttp met de feature std"
# De TCP van een host (leanhttp::host) staat standaard uit; zijn toetsen
# praten echte TCP op localhost.
cargo test --quiet -p leanhttp --features std
cargo clippy --all-targets --quiet -p leanhttp --features std -- -D warnings
echo "== host: leantls en leanhttps met de feature tls12"
# De TLS 1.2-terugval staat standaard uit (leantls is dan één versie); zijn
# toetsen en clippy draaien hier.
cargo test --quiet -p leantls -p leanhttps --features leantls/tls12,leanhttps/tls12
cargo clippy --all-targets --quiet -p leantls -p leanhttps --features leantls/tls12,leanhttps/tls12 -- -D warnings
echo "== rustfmt"
cargo fmt --check
echo "== target: no_std (aarch64)"
cargo build --quiet --target aarch64-unknown-none-softfloat
cargo build --quiet --target aarch64-unknown-none-softfloat -p leantls --features tls12
echo "poort groen"
