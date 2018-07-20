# Oblivious Transfer

This library implements the semi-honest SimpleOT [CITE] and OT Extension [IKNP].

To compile:
* `export RUSTFLAGS="-C target_cpu=native"` for maximum performance (or set 25519dalek features to "u32_backend" and "std")
