#!/bin/bash
set -e

cargo +nightly build --target wasm32-unknown-unknown --release
wasm-gc target/wasm32-unknown-unknown/release/ot.wasm -o target/wasm32-unknown-unknown/release/ot.gc.wasm
wasm-opt -Os target/wasm32-unknown-unknown/release/ot.wasm -o target/wasm32-unknown-unknown/release/ot.gc.opt.wasm

cp target/wasm32-unknown-unknown/release/ot.gc.opt.wasm dist/ot.wasm