# MP-PSI

The package contains the APIs to build a multi party private set intersection application.

PSI stands for Private Set Intersection. It allows two parties to compute the intersection of their sets without revealing anything else about their sets. 

[BFV](https://inferati.azureedge.net/docs/inferati-fhe-bfv.pdf) is a fully homomorphic encryption scheme. It allows to perform addition and multiplication on encrypted data. The PSI protocol made available in this library uses the BFV scheme to perform the encryption of the sets, compute the intersection and decrypt the result. In particular, the multiparty protocol is based on the paper [Mouchet, Christian, et al. "Multiparty homomorphic encryption from ring-learning-with-errors."](https://eprint.iacr.org/2020/304.pdf). 

### Install 

Install the `mp-psi` package with npm:

```bash
npm i mp-psi
```

or yarn:

```bash
yarn add mp-psi
```

### Usage

```js
import { state0_bindgen, state1_bindgen, state2_bindgen, state3_bindgen, state4_bindgen } from "mp-psi";

const state0 = state0_bindgen();  
const bit_vector_a = [1, 0, 1, 0, 1, 0, 1, 0, 1, 1];
const state1 = state1_bindgen(state0.message_a_to_b, bit_vector_a);
const bit_vector_b = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0];
const state2 = state2_bindgen(state0.private_output_a, state0.public_output_a, state1.message_b_to_a, bit_vector_b);
const state3 = state3_bindgen(state1.private_output_b, state1.public_output_b, state2.message_a_to_b);
const psi_output_a = state4_bindgen(state2.public_output_a, state3.message_b_to_a);
const psi_output_b = state3.psi_output;
```

