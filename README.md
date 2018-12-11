# Oblivious Transfer

This is still *WIP*

This library implements the semi-honest SimpleOT [1] and OT Extension [2].

Current limitations: 
* I have not found/implemented a websocket library for romio and tokio is not fully compatible
with the new futures. For this reason browser clients can't talk with native servers. This will be fixed in the future.
* The beaver triple example is not there yet. It will be ported to the new version
* No tests in this new version

To compile:
* if you want to use the browser version, install `cargo-web` and run `cargo web run` or `cargo web build`
* `export RUSTFLAGS="-C target_cpu=native"` for maximum performance (or set 25519dalek features to "u32_backend" and "std") in native environments 

## Sources
 [1] T. Chou und C. Orlandi, „The Simplest Protocol for Oblivious Transfer“, in International Conference on Cryptology and Information Security in Latin America, Berlin, Heidelberg, 2015.

 [2] Y. Ishai, J. Kilian, K. Nissim, und E. Petrank, „Extending Oblivious Transfers Efficiently“, in Advances in Cryptology - CRYPTO 2003, Berlin, Heidelberg, 2003, Bd. 2729, S. 145–161.

Todo:
[] replace failure with own Error implementation
[] seamless JS integration
[] more Oblivious Transfer variants?