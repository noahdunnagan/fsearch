#!/bin/sh
# Release build optimized with a profile of fsearch's own searches (PGO):
# name searches run 10-35% faster. Trains on a copy of your index with
# queries sampled from it (examples/rig.rs), then builds target/release.
# Needs: rustup component add llvm-tools
set -e
profdata=$(ls "$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-profdata 2>/dev/null | head -1)
[ -x "$profdata" ] || { echo "pgo.sh: needs llvm-profdata: rustup component add llvm-tools" >&2; exit 1; }
data="$HOME/Library/Application Support/FSearch"
[ -f "$data/index.bin" ] || { echo "pgo.sh: no index yet; run fsearch once first" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/snap"
cp -c "$data/index.bin" "$tmp/snap/" 2>/dev/null || cp "$data/index.bin" "$tmp/snap/"
cp -cR "$data/content" "$tmp/snap/" 2>/dev/null || cp -R "$data/content" "$tmp/snap/"
RUSTFLAGS="-Cprofile-generate=$tmp/prof" cargo build --release --example rig --target-dir "$tmp/target"
"$tmp/target/release/examples/rig" gen "$tmp/snap" "$tmp/corpus.json"
"$tmp/target/release/examples/rig" run "$tmp/snap" "$tmp/corpus.json" "$tmp/out.json" >/dev/null
"$profdata" merge -o "$tmp/fsearch.profdata" "$tmp/prof"
RUSTFLAGS="-Cprofile-use=$tmp/fsearch.profdata" cargo build --release
