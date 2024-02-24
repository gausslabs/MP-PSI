# MP-PSI

The library contains the following components:

- `src`: Rust library for multi-party PSI using BFV
- `pkg`: JS-TS-WASM package

### Build

The rust library is used to build the JS-TS-WASM package using `wasm-pack` targeting `web` [guide](https://developer.mozilla.org/en-US/docs/WebAssembly/Rust_to_Wasm). When compiling to `web` the output can natively be included on a web page, and doesn't require any further postprocessing. The output is included as an ES module. For more information check [`wasm-bindgen` guide](https://rustwasm.github.io/docs/wasm-bindgen/reference/deployment.html)

```bash
wasm-pack build --target web
```

### Test

To test the rust library, run:

```bash
cargo test --release
```
