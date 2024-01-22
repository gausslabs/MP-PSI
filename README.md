# MP-PSI

The library contains the following components:

- `src`: Rust library for multi-party PSI using BFV
- `pkg`: JS-TS-WASM package 

### Build 

The rust library is used to build the JS-TS-WASM package using `wasm-pack` targeting `web` [guide](https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_Wasm)

```bash
wasm-pack build --target web
```

### Test

To test the rust library, run:

```bash
cargo test
```