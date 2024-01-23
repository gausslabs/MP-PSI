use bfv::{
    BfvParameters, Ciphertext, CiphertextProto, CollectiveDecryption, CollectiveDecryptionShare,
    CollectiveDecryptionShareProto, CollectivePublicKeyGenerator, CollectivePublicKeyShareProto,
    CollectiveRlkAggTrimmedShare1Proto, CollectiveRlkGenerator, CollectiveRlkShare1Proto,
    CollectiveRlkShare2Proto, Encoding, EvaluationKey, Evaluator, Plaintext, SecretKey,
    SecretKeyProto,
};
use itertools::{izip, Itertools};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use traits::{
    TryDecodingWithParameters, TryEncodingWithParameters, TryFromWithLevelledParameters,
    TryFromWithParameters,
};
use wasm_bindgen::{prelude::wasm_bindgen, JsValue};

mod bandwidth_benches;

static CRS_PK: [u8; 32] = [11u8; 32];
static CRS_RLK: [u8; 32] = [0u8; 32];

static RING_SIZE: usize = 1 << 11;

fn params() -> BfvParameters {
    let mut params = BfvParameters::new_with_primes(
        vec![1032193, 1073692673],
        vec![995329, 1073668097],
        40961,
        RING_SIZE,
    );
    params.enable_hybrid_key_switching_with_prime(vec![61441]);
    params.enable_pke();
    params
}

fn convert<T, U>(value: &T, parameters: &BfvParameters) -> U
where
    U: TryFromWithParameters<Value = T, Parameters = BfvParameters>,
{
    U::try_from_with_parameters(value, parameters)
}

#[derive(Serialize, Deserialize)]
struct PrivateOutputAPostState0 {
    s_pk_a: SecretKeyProto,
    s_rlk_a: SecretKeyProto,
}

#[derive(Serialize, Deserialize)]
struct PublicOutputAPostState0 {
    share_pk_a: CollectivePublicKeyShareProto,
    share_rlk_a_round1: CollectiveRlkShare1Proto,
}

#[derive(Serialize, Deserialize)]
struct MessageAToBPostState0 {
    share_pk_a: CollectivePublicKeyShareProto,
    share_rlk_a_round1: CollectiveRlkShare1Proto,
}

#[derive(Serialize, Deserialize)]
struct OutputState0 {
    private_output_a: PrivateOutputAPostState0,
    public_output_a: PublicOutputAPostState0,
    message_a_to_b: MessageAToBPostState0,
}

#[derive(Serialize, Deserialize)]
struct PrivateOutputBPostState1 {
    s_pk_b: SecretKeyProto,
}

#[derive(Serialize, Deserialize)]
struct PublicOutputBPostState1 {
    ciphertexts_b: Vec<CiphertextProto>,
    share_rlk_b_round2: CollectiveRlkShare2Proto,
    rlk_agg_round1_h1s: CollectiveRlkAggTrimmedShare1Proto,
}

#[derive(Serialize, Deserialize)]
struct MessageBToAPostState1 {
    share_pk_b: CollectivePublicKeyShareProto,
    share_rlk_b_round1: CollectiveRlkShare1Proto,
    share_rlk_b_round2: CollectiveRlkShare2Proto,
    ciphertexts_b: Vec<CiphertextProto>,
}

#[derive(Serialize, Deserialize)]
struct OutputState1 {
    private_output_b: PrivateOutputBPostState1,
    public_output_b: PublicOutputBPostState1,
    message_b_to_a: MessageBToAPostState1,
}

#[derive(Serialize, Deserialize)]
struct PublicOutputAPostState2 {
    decryption_shares_a: Vec<CollectiveDecryptionShareProto>,
    ciphertexts_res: Vec<CiphertextProto>,
}

#[derive(Serialize, Deserialize)]
struct MessageAToBPostState2 {
    decryption_shares_a: Vec<CollectiveDecryptionShareProto>,
    ciphertexts_a: Vec<CiphertextProto>,
    share_rlk_a_round2: CollectiveRlkShare2Proto,
}

#[derive(Serialize, Deserialize)]
struct OutputState2 {
    public_output_a: PublicOutputAPostState2,
    message_a_to_b: MessageAToBPostState2,
}

#[derive(Serialize, Deserialize)]
struct MessageBToAPostState3 {
    decryption_shares_b: Vec<CollectiveDecryptionShareProto>,
}

#[derive(Serialize, Deserialize)]
struct OutputState3 {
    message_b_to_a: MessageBToAPostState3,
    psi_output: Vec<u32>,
}

#[wasm_bindgen]
pub fn state0_bindgen() -> JsValue {
    let (private_output_a, public_output_a, message_a_to_b) = state0();

    let output = OutputState0 {
        private_output_a,
        public_output_a,
        message_a_to_b,
    };

    serde_wasm_bindgen::to_value(&output).unwrap()
}

fn state0() -> (
    PrivateOutputAPostState0,
    PublicOutputAPostState0,
    MessageAToBPostState0,
) {
    let params = params();
    let mut rng = thread_rng();
    let s_pk_a = SecretKey::random_with_params(&params, &mut rng);

    let s_rlk_a = CollectiveRlkGenerator::init_state(&params, &mut rng);

    let share_pk_a =
        CollectivePublicKeyGenerator::generate_share(&params, &s_pk_a, CRS_PK, &mut rng);

    let share_rlk_a_round1 =
        CollectiveRlkGenerator::generate_share_1(&params, &s_pk_a, &s_rlk_a, CRS_RLK, 0, &mut rng);

    let share_rlk_a_round1_proto: CollectiveRlkShare1Proto = convert(&share_rlk_a_round1, &params);
    let share_pk_a_proto: CollectivePublicKeyShareProto = convert(&share_pk_a, &params);

    let message_a_to_b = MessageAToBPostState0 {
        share_pk_a: share_pk_a_proto.clone(),
        share_rlk_a_round1: share_rlk_a_round1_proto.clone(),
    };

    let private_output_a = PrivateOutputAPostState0 {
        s_pk_a: convert(&s_pk_a, &params),
        s_rlk_a: convert(&s_rlk_a, &params),
    };
    let public_output_a = PublicOutputAPostState0 {
        share_pk_a: share_pk_a_proto,
        share_rlk_a_round1: share_rlk_a_round1_proto,
    };

    (private_output_a, public_output_a, message_a_to_b)
}

#[wasm_bindgen]
pub fn state1_bindgen(message_a_to_b: JsValue, bit_vector: &[u32]) -> JsValue {
    let message_a_to_b: MessageAToBPostState0 = serde_wasm_bindgen::from_value(message_a_to_b)
        .expect("failed to deserialize message_a_to_b");

    let (private_output_b, public_output_b, message_b_to_a) = state1(message_a_to_b, bit_vector);

    let output = OutputState1 {
        private_output_b,
        public_output_b,
        message_b_to_a,
    };

    serde_wasm_bindgen::to_value(&output).unwrap()
}

fn state1(
    message_a_to_b: MessageAToBPostState0,
    bit_vector: &[u32],
) -> (
    PrivateOutputBPostState1,
    PublicOutputBPostState1,
    MessageBToAPostState1,
) {
    let params = params();
    let mut rng = thread_rng();
    let s_pk_b = SecretKey::random_with_params(&params, &mut rng);
    let s_rlk_b = CollectiveRlkGenerator::init_state(&params, &mut rng);

    let share_pk_b =
        CollectivePublicKeyGenerator::generate_share(&params, &s_pk_b, CRS_PK, &mut rng);

    let share_rlk_b_round1 =
        CollectiveRlkGenerator::generate_share_1(&params, &s_pk_b, &s_rlk_b, CRS_RLK, 0, &mut rng);

    let share_rlk_a_round1 = convert(&message_a_to_b.share_rlk_a_round1, &params);

    let share_pk_a = convert(&message_a_to_b.share_pk_a, &params);

    // rlk key part 1
    let rlk_shares_round1 = vec![share_rlk_a_round1, share_rlk_b_round1.clone()];
    let rlk_agg_1 = CollectiveRlkGenerator::aggregate_shares_1(&params, &rlk_shares_round1, 0);

    // B already has access to aggregate shares for rlk round 1 and can proceed with the second round of the protocol
    let share_rlk_b_round2 = CollectiveRlkGenerator::generate_share_2(
        &params, &s_pk_b, &rlk_agg_1, &s_rlk_b, 0, &mut rng,
    );

    // generate collective public key and encryt b's input
    let collective_pk_shares = vec![share_pk_b.clone(), share_pk_a];
    let collecitve_pk = CollectivePublicKeyGenerator::aggregate_shares_and_finalise(
        &params,
        &collective_pk_shares,
        CRS_PK,
    );
    let ciphertexts_b = bit_vector
        .chunks(RING_SIZE)
        .map(|v| {
            let pt = Plaintext::try_encoding_with_parameters(v, &params, Encoding::default());
            collecitve_pk.encrypt(&params, &pt, &mut rng)
        })
        .collect_vec();
    let ciphertexts_b_proto: Vec<CiphertextProto> = ciphertexts_b
        .iter()
        .map(|v| convert(v, &params))
        .collect_vec();

    let share_rlk_b_round2_proto: CollectiveRlkShare2Proto = convert(&share_rlk_b_round2, &params);

    let message_b_to_a = MessageBToAPostState1 {
        share_pk_b: convert(&share_pk_b, &params),
        share_rlk_b_round1: convert(&share_rlk_b_round1, &params),
        share_rlk_b_round2: share_rlk_b_round2_proto.clone(),
        ciphertexts_b: ciphertexts_b_proto.clone(),
    };

    let private_output_b = PrivateOutputBPostState1 {
        s_pk_b: convert(&s_pk_b, &params),
    };

    let rlk_aggregated_shares1_trimmed = rlk_agg_1.trim();
    let public_output_b = PublicOutputBPostState1 {
        ciphertexts_b: ciphertexts_b_proto,
        share_rlk_b_round2: share_rlk_b_round2_proto,
        rlk_agg_round1_h1s: convert(&rlk_aggregated_shares1_trimmed, &params),
    };

    (private_output_b, public_output_b, message_b_to_a)
}

#[wasm_bindgen]
pub fn state2_bindgen(
    private_output_a_state0: JsValue,
    public_output_a_state0: JsValue,
    message_b_to_a: JsValue,
    bit_vector: &[u32],
) -> JsValue {
    let private_output_a_state0: PrivateOutputAPostState0 =
        serde_wasm_bindgen::from_value(private_output_a_state0)
            .expect("failed to deserialize private_output_a_state0");

    let public_output_a_state0: PublicOutputAPostState0 =
        serde_wasm_bindgen::from_value(public_output_a_state0)
            .expect("failed to deserialize public_output_a_state0");

    let message_b_to_a: MessageBToAPostState1 = serde_wasm_bindgen::from_value(message_b_to_a)
        .expect("failed to deserialize message_b_to_a");

    let (public_output_a, message_a_to_b) = state2(
        private_output_a_state0,
        public_output_a_state0,
        message_b_to_a,
        bit_vector,
    );

    let output = OutputState2 {
        public_output_a,
        message_a_to_b,
    };

    serde_wasm_bindgen::to_value(&output).unwrap()
}

fn state2(
    private_output_a_state0: PrivateOutputAPostState0,
    public_output_a_state0: PublicOutputAPostState0,
    message_b_to_a: MessageBToAPostState1,
    bit_vector: &[u32],
) -> (PublicOutputAPostState2, MessageAToBPostState2) {
    let params = params();
    let mut rng = thread_rng();

    // aggrgegate shares of rlk round 1
    let rlk_shares_round1 = vec![
        convert(&public_output_a_state0.share_rlk_a_round1, &params),
        convert(&message_b_to_a.share_rlk_b_round1, &params),
    ];
    let rlk_agg_1 = CollectiveRlkGenerator::aggregate_shares_1(&params, &rlk_shares_round1, 0);

    let s_pk_a = convert(&private_output_a_state0.s_pk_a, &params);
    let s_rlk_a = convert(&private_output_a_state0.s_rlk_a, &params);

    // generate share 2 for rlk round 2
    let share_rlk_a_round2 = CollectiveRlkGenerator::generate_share_2(
        &params, &s_pk_a, &rlk_agg_1, &s_rlk_a, 0, &mut rng,
    );

    let rlk_agg_1_trimmed = rlk_agg_1.trim();
    // aggregate rlk round 2 shares and generate rlk
    let rlk_shares_round2 = vec![
        share_rlk_a_round2.clone(),
        convert(&message_b_to_a.share_rlk_b_round2, &params),
    ];
    let rlk = CollectiveRlkGenerator::aggregate_shares_2(
        &params,
        &rlk_shares_round2,
        rlk_agg_1_trimmed,
        0,
    );
    // create public key and encrypt A's bit vector'
    let collective_pk_shares = vec![
        convert(&public_output_a_state0.share_pk_a, &params),
        convert(&message_b_to_a.share_pk_b, &params),
    ];
    let collective_pk = CollectivePublicKeyGenerator::aggregate_shares_and_finalise(
        &params,
        &collective_pk_shares,
        CRS_PK,
    );
    let ciphertexts_a = bit_vector
        .chunks(RING_SIZE)
        .map(|v| {
            let pt = Plaintext::try_encoding_with_parameters(v, &params, Encoding::default());
            collective_pk.encrypt(&params, &pt, &mut rng)
        })
        .collect_vec();

    // perform PSI
    let evaluator = Evaluator::new(params.clone());
    let evaluation_key = EvaluationKey::new_raw(&[0], vec![rlk], &[], &[], vec![]);
    let ciphertexts_b: Vec<Ciphertext> = message_b_to_a
        .ciphertexts_b
        .iter()
        .map(|v| convert(v, &params))
        .collect_vec();
    let ciphertexts_res = izip!(ciphertexts_a.iter(), ciphertexts_b.iter())
        .map(|(a, b)| {
            let ct = evaluator.mul(a, b);
            evaluator.relinearize(&ct, &evaluation_key)
        })
        .collect_vec();

    // generate decryption share of ciphertext_res
    let decryption_shares_a = ciphertexts_res
        .iter()
        .map(|ct| {
            CollectiveDecryption::generate_share(
                evaluator.params(),
                ct,
                &convert(&private_output_a_state0.s_pk_a, &params),
                &mut rng,
            )
        })
        .collect_vec();

    let decryption_shares_a_proto: Vec<CollectiveDecryptionShareProto> = decryption_shares_a
        .iter()
        .map(|v| CollectiveDecryptionShareProto::try_from_with_levelled_parameters(v, &params, 0))
        .collect_vec();

    let public_output_a = PublicOutputAPostState2 {
        decryption_shares_a: decryption_shares_a_proto.clone(),
        ciphertexts_res: ciphertexts_res
            .iter()
            .map(|v| convert(v, &params))
            .collect_vec(),
    };

    let message_a_to_b = MessageAToBPostState2 {
        decryption_shares_a: decryption_shares_a_proto,
        ciphertexts_a: ciphertexts_a
            .iter()
            .map(|v| convert(v, &params))
            .collect_vec(),
        share_rlk_a_round2: convert(&share_rlk_a_round2, &params),
    };

    (public_output_a, message_a_to_b)
}

#[wasm_bindgen]
pub fn state3_bindgen(
    private_output_b_state1: JsValue,
    public_output_b_state1: JsValue,
    message_a_to_b: JsValue,
) -> JsValue {
    let private_output_b_state1: PrivateOutputBPostState1 =
        serde_wasm_bindgen::from_value(private_output_b_state1)
            .expect("failed to deserialize private_output_b_state1");

    let public_output_b_state1: PublicOutputBPostState1 =
        serde_wasm_bindgen::from_value(public_output_b_state1)
            .expect("failed to deserialize public_output_b_state1");

    let message_a_to_b: MessageAToBPostState2 = serde_wasm_bindgen::from_value(message_a_to_b)
        .expect("failed to deserialize message_a_to_b");

    let (message_b_to_a, psi_output) = state3(
        private_output_b_state1,
        public_output_b_state1,
        message_a_to_b,
    );

    let output = OutputState3 {
        message_b_to_a,
        psi_output,
    };

    serde_wasm_bindgen::to_value(&output).unwrap()
}

fn state3(
    private_output_b_state1: PrivateOutputBPostState1,
    public_output_b_state1: PublicOutputBPostState1,
    message_a_to_b: MessageAToBPostState2,
) -> (MessageBToAPostState3, Vec<u32>) {
    let params = params();
    let mut rng = thread_rng();

    // create rlk
    let rlk_shares_round2 = vec![
        convert(&message_a_to_b.share_rlk_a_round2, &params),
        convert(&public_output_b_state1.share_rlk_b_round2, &params),
    ];

    let rlk_agg_round1_h1s = convert(&public_output_b_state1.rlk_agg_round1_h1s, &params);

    let rlk = CollectiveRlkGenerator::aggregate_shares_2(
        &params,
        &rlk_shares_round2,
        rlk_agg_round1_h1s,
        0,
    );

    // perform PSI
    let evaluator = Evaluator::new(params.clone());
    let evaluation_key = EvaluationKey::new_raw(&[0], vec![rlk], &[], &[], vec![]);

    let ciphertexts_a: Vec<Ciphertext> = message_a_to_b
        .ciphertexts_a
        .iter()
        .map(|v| convert(v, &params))
        .collect_vec();
    let ciphertexts_b: Vec<Ciphertext> = public_output_b_state1
        .ciphertexts_b
        .iter()
        .map(|v| convert(v, &params))
        .collect_vec();

    let ciphertexts_res = izip!(ciphertexts_a.iter(), ciphertexts_b.iter())
        .map(|(a, b)| {
            let ct = evaluator.mul(a, b);
            evaluator.relinearize(&ct, &evaluation_key)
        })
        .collect_vec();

    let s_pk_b = convert(&private_output_b_state1.s_pk_b, &params);

    // generate B's decryption share
    let decryption_shares_b = ciphertexts_res
        .iter()
        .map(|ct| CollectiveDecryption::generate_share(evaluator.params(), ct, &s_pk_b, &mut rng))
        .collect_vec();

    let psi_output = izip!(
        message_a_to_b.decryption_shares_a.iter(),
        decryption_shares_b.iter(),
        ciphertexts_res.iter()
    )
    .flat_map(|(a_proto, b, ct)| {
        let shares_vec = vec![
            b.clone(),
            CollectiveDecryptionShare::try_from_with_levelled_parameters(a_proto, &params, 0),
        ];
        let pt =
            CollectiveDecryption::aggregate_share_and_decrypt(evaluator.params(), ct, &shares_vec);
        Vec::<u32>::try_decoding_with_parameters(&pt, evaluator.params(), Encoding::default())
    })
    .collect_vec();

    let message_b_to_a = MessageBToAPostState3 {
        decryption_shares_b: decryption_shares_b
            .iter()
            .map(|v| {
                CollectiveDecryptionShareProto::try_from_with_levelled_parameters(v, &params, 0)
            })
            .collect_vec(),
    };

    (message_b_to_a, psi_output)
}

#[wasm_bindgen]
pub fn state4_bindgen(public_output_a_state2: JsValue, message_b_to_a: JsValue) -> Vec<u32> {
    let public_output_a_state2: PublicOutputAPostState2 =
        serde_wasm_bindgen::from_value(public_output_a_state2)
            .expect("failed to deserialize public_output_a_state2");

    let message_b_to_a: MessageBToAPostState3 = serde_wasm_bindgen::from_value(message_b_to_a)
        .expect("failed to deserialize message_b_to_a");

    let psi_output = state4(public_output_a_state2, message_b_to_a);

    psi_output
}

fn state4(
    public_output_a_state2: PublicOutputAPostState2,
    message_b_to_a: MessageBToAPostState3,
) -> Vec<u32> {
    let params = params();

    let psi_output = izip!(
        public_output_a_state2.decryption_shares_a.iter(),
        message_b_to_a.decryption_shares_b.iter(),
        public_output_a_state2.ciphertexts_res.iter()
    )
    .flat_map(|(a_proto, b_proto, ct_proto)| {
        let shares_vec = vec![
            CollectiveDecryptionShare::try_from_with_levelled_parameters(&b_proto, &params, 0),
            CollectiveDecryptionShare::try_from_with_levelled_parameters(&a_proto, &params, 0),
        ];
        let ct: Ciphertext = convert(ct_proto, &params);
        let pt = CollectiveDecryption::aggregate_share_and_decrypt(&params, &ct, &shares_vec);
        Vec::<u32>::try_decoding_with_parameters(&pt, &params, Encoding::default())
    })
    .collect_vec();

    psi_output
}

#[cfg(test)]
mod tests {
    use crate::bandwidth_benches::BandwidthBench;

    use super::*;
    use itertools::{izip, Itertools};
    use rand::{distributions::Uniform, Rng};

    fn random_bit_vector(hamming_weight: usize, size: usize) -> Vec<u32> {
        let mut rng = thread_rng();

        let mut bit_vector = vec![0; size];
        (0..hamming_weight).into_iter().for_each(|_| {
            let sample_index = rng.sample(Uniform::new(0, size));
            bit_vector[sample_index] = 1;
        });

        bit_vector
    }

    fn plain_psi(bit_vector0: &[u32], bit_vector_1: &[u32]) -> Vec<u32> {
        izip!(bit_vector0.iter(), bit_vector_1.iter())
            .map(|(b0, b1)| b0 * b1)
            .collect_vec()
    }

    #[test]
    fn psi_works() {
        let hamming_weight = 1000;
        let vector_size = RING_SIZE * 3;

        // A: state 0
        let (private_output_a_state0, public_output_a_state0, message_a_to_b_state0) = state0();

        // Benchmark bandwidth size of output state 0
        let mut byte_count_state0_private_output_a = 0;
        byte_count_state0_private_output_a += private_output_a_state0.s_pk_a.get_byte_size();
        byte_count_state0_private_output_a += private_output_a_state0.s_rlk_a.get_byte_size();

        println!(
            "byte_count_state0_private_output_a: {}",
            byte_count_state0_private_output_a
        );

        let mut byte_count_state0_public_output_a = 0;
        byte_count_state0_public_output_a += public_output_a_state0.share_pk_a.get_byte_size();
        byte_count_state0_public_output_a +=
            public_output_a_state0.share_rlk_a_round1.get_byte_size();

        println!(
            "byte_count_state0_public_output_a: {}",
            byte_count_state0_public_output_a
        );

        let mut byte_count_state0_message_a_to_b = 0;
        byte_count_state0_message_a_to_b += message_a_to_b_state0.share_pk_a.get_byte_size();
        byte_count_state0_message_a_to_b +=
            message_a_to_b_state0.share_rlk_a_round1.get_byte_size();

        println!(
            "byte_count_state0_message_a_to_b: {}",
            byte_count_state0_message_a_to_b
        );

        // B: state 1
        let bit_vector_b = random_bit_vector(hamming_weight, vector_size);
        let (private_output_b_state1, public_output_b_state1, message_b_to_a_state1) =
            state1(message_a_to_b_state0, &bit_vector_b);

        let mut byte_count_state1_private_output_b = 0;
        byte_count_state1_private_output_b += private_output_b_state1.s_pk_b.get_byte_size();
        println!(
            "byte_count_state1_private_output_b: {}",
            byte_count_state1_private_output_b
        );

        let mut byte_count_state1_public_output_b = 0;
        byte_count_state1_public_output_b += public_output_b_state1
            .ciphertexts_b
            .iter()
            .fold(0, |acc, ct| acc + ct.get_byte_size());
        byte_count_state1_public_output_b +=
            public_output_b_state1.rlk_agg_round1_h1s.get_byte_size();
        byte_count_state1_public_output_b +=
            public_output_b_state1.share_rlk_b_round2.get_byte_size();
        println!(
            "byte_count_state1_public_output_b: {}",
            byte_count_state1_public_output_b
        );

        let mut byte_count_state1_message_b_to_a = 0;
        byte_count_state1_message_b_to_a += message_b_to_a_state1
            .ciphertexts_b
            .iter()
            .fold(0, |acc, ct| acc + ct.get_byte_size());
        byte_count_state1_message_b_to_a += message_b_to_a_state1.share_pk_b.get_byte_size();
        byte_count_state1_message_b_to_a +=
            message_b_to_a_state1.share_rlk_b_round1.get_byte_size();
        byte_count_state1_message_b_to_a +=
            message_b_to_a_state1.share_rlk_b_round2.get_byte_size();

        println!(
            "byte_count_state1_message_b_to_a: {}",
            byte_count_state1_message_b_to_a
        );

        // A: state 2
        let bit_vector_a = random_bit_vector(hamming_weight, vector_size);
        let (public_output_a_state2, message_a_to_b_state2) = state2(
            private_output_a_state0,
            public_output_a_state0,
            message_b_to_a_state1,
            &bit_vector_a,
        );

        let mut byte_count_state2_public_output_a = 0;
        byte_count_state2_public_output_a += public_output_a_state2
            .decryption_shares_a
            .iter()
            .fold(0, |acc, share| acc + share.get_byte_size());
        byte_count_state2_public_output_a += public_output_a_state2
            .ciphertexts_res
            .iter()
            .fold(0, |acc, ct| acc + ct.get_byte_size());
        println!(
            "byte_count_state2_public_output_a: {}",
            byte_count_state2_public_output_a
        );

        let mut byte_count_state2_message_a_to_b = 0;
        byte_count_state2_message_a_to_b += message_a_to_b_state2
            .decryption_shares_a
            .iter()
            .fold(0, |acc, share| acc + share.get_byte_size());
        byte_count_state2_message_a_to_b += message_a_to_b_state2
            .ciphertexts_a
            .iter()
            .fold(0, |acc, ct| acc + ct.get_byte_size());
        byte_count_state2_message_a_to_b +=
            message_a_to_b_state2.share_rlk_a_round2.get_byte_size();

        println!(
            "byte_count_state2_message_a_to_b: {}",
            byte_count_state2_message_a_to_b
        );

        // B: state 3
        let (message_b_to_a_state3, psi_output_b) = state3(
            private_output_b_state1,
            public_output_b_state1,
            message_a_to_b_state2,
        );

        let byte_count_state3_message_b_to_a = message_b_to_a_state3
            .decryption_shares_b
            .iter()
            .fold(0, |acc, share| acc + share.get_byte_size());
        let byte_count_state3_psi_output_b = psi_output_b.len() / 8; // Divide by 8 to account for the fact that it is a bit vector

        println!(
            "byte_count_state3_message_b_to_a: {}",
            byte_count_state3_message_b_to_a
        );

        println!(
            "byte_count_state3_psi_output_b: {}",
            byte_count_state3_psi_output_b
        );

        // A: state 4
        let psi_output_a = state4(public_output_a_state2, message_b_to_a_state3);

        let byte_count_state4_psi_output_a = psi_output_a.len() / 8; // Divide by 8 to account for the fact that it is a bit vector

        println!(
            "byte_count_state4_psi_output_a {}",
            byte_count_state4_psi_output_a
        );

        let expected_psi_output = plain_psi(&bit_vector_a, &bit_vector_b);

        assert_eq!(expected_psi_output, psi_output_a[..vector_size]);
        assert_eq!(psi_output_a, psi_output_b);
    }
}
