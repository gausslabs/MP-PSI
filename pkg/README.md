# MP-PSI

The package contains the APIs to build a multi party private set intersection web-app. Note that the APIs are compiled specifically for web browser environments and are not compatible with a node environment.

PSI stands for Private Set Intersection. It allows two parties to compute the intersection of their sets without revealing anything else about their sets. 

[BFV](https://inferati.azureedge.net/docs/inferati-fhe-bfv.pdf) is a fully homomorphic encryption scheme. It allows to perform addition and multiplication on encrypted data. The PSI protocol made available in this library uses the BFV scheme to perform the encryption of the sets, compute the intersection and decrypt the result. In particular, the multiparty protocol is based on the paper [Mouchet, Christian, et al. "Multiparty homomorphic encryption from ring-learning-with-errors."](https://eprint.iacr.org/2020/304.pdf). 

### Security Notice

This is a research project and is not meant to be used in production. The code has not been audited.

### Usage in web-app

```js
    import init, { state0_bindgen, state1_bindgen, state2_bindgen, state3_bindgen, state4_bindgen } from "./mp_psi.js";

    init().then(() => {
        const state0 = state0_bindgen();        
        const bit_vector_a = [1, 0, 1, 0, 1, 0, 1, 0, 1, 1];
        const state1 = state1_bindgen(state0.message_a_to_b, bit_vector_a);
        const bit_vector_b = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0];
        const state2 = state2_bindgen(state0.private_output_a, state0.public_output_a, state1.message_b_to_a, bit_vector_b);
        const state3 = state3_bindgen(state1.private_output_b, state1.public_output_b, state2.message_a_to_b);
        const psi_output_a = state4_bindgen(state2.public_output_a, state3.message_b_to_a);
        const psi_output_b = state3.psi_output;
    });
```

The `mp_psi.js` can natively be included on a web page as an ES module. An example of the usage is include in the `index.html` file. 

You can test it by:
- Cloning the repo 
- Serving the `pkg` directory with a local web server, (e.g. `python3 -m http.server`) 
- Visit `http://localhost:8000` in your browser
- Open the console. It will show you the result of the PSI protocol.