use bfv::{
    BfvParameters, Ciphertext, CollectiveDecryption, CollectivePublicKeyGenerator,
    CollectiveRlkGenerator, CollectiveRlkGeneratorState, Encoding, EvaluationKey, Evaluator,
    Plaintext, Poly, SecretKey, SecretKeyProto,
};
use rand::thread_rng;
use traits::{TryDecodingWithParameters, TryEncodingWithParameters, TryFromWithParameters};
use wasm_bindgen::prelude::wasm_bindgen;

static CRS_PK: [u8; 32] = [0u8; 32];
static CRS_RLK: [u8; 32] = [0u8; 32];

fn params() -> BfvParameters {
    let mut params = BfvParameters::new(&[30, 30], 65537, 1 << 11);
    params.enable_hybrid_key_switching(&[30]);
    params.enable_pke();
    params
}

struct PrivateOutputAPostState0 {
    s_pk_a: SecretKey,
    s_rlk_a: SecretKey,
}

struct PublicOutputAPostState0 {
    share_pk_a: Poly,
    share_rlk_a_round1: (Vec<Poly>, Vec<Poly>),
}

struct MessageAToBPostState0 {
    share_pk_a: Poly,
    share_rlk_a_round1: (Vec<Poly>, Vec<Poly>),
}

struct PrivateOutputBPostState1 {
    s_pk_b: SecretKey,
}

struct PublicOutputBPostState1 {
    ciphertext_b: Ciphertext,
    share_rlk_b_round2: (Vec<Poly>, Vec<Poly>),
    rlk_agg_round1_h1s: Vec<Poly>,
}

struct MessageBToAPostState1 {
    share_pk_b: Poly,
    share_rlk_b_round1: (Vec<Poly>, Vec<Poly>),
    share_rlk_b_round2: (Vec<Poly>, Vec<Poly>),
    ciphertext_b: Ciphertext,
}

struct PublicOutputAPostState2 {
    decryption_share_a: Poly,
    ciphertext_res: Ciphertext,
}

struct MessageAToBPostState2 {
    decryption_share_a: Poly,
    ciphertext_a: Ciphertext,
    share_rlk_a_round2: (Vec<Poly>, Vec<Poly>),
}

struct MessageBToAPostState3 {
    decryption_share_b: Poly,
}

#[wasm_bindgen]
pub fn statetest() -> Vec<u8> {
    let params = params();
    let mut rng = thread_rng();
    let s_pk_a = SecretKey::random_with_params(&params, &mut rng);

    // Serialize the SecretKey using your existing protobuf methods
    let serialized_sk = SecretKeyProto::try_from_with_parameters(&s_pk_a, &params);

    // Convert the serialized SecretKey to a Vec<u8>
    let bytes = serialized_sk.coefficients;

    bytes
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

    let message_a_to_b = MessageAToBPostState0 {
        share_pk_a: share_pk_a.clone(),
        share_rlk_a_round1: share_rlk_a_round1.clone(),
    };

    let private_state_a = PrivateOutputAPostState0 {
        s_pk_a,
        s_rlk_a: s_rlk_a.0.clone(),
    };
    let public_output_a = PublicOutputAPostState0 {
        share_pk_a,
        share_rlk_a_round1,
    };

    (private_state_a, public_output_a, message_a_to_b)
}

fn state1(
    message_from_a: MessageAToBPostState0,
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

    // rlk key part 1
    let h0s = vec![
        message_from_a.share_rlk_a_round1.0,
        share_rlk_b_round1.0.clone(),
    ];
    let h1s = vec![
        message_from_a.share_rlk_a_round1.1,
        share_rlk_b_round1.1.clone(),
    ];
    let rlk_agg_1 = CollectiveRlkGenerator::aggregate_shares_1(&params, &h0s, &h1s, 0);

    // B already has access to aggregate shares for rlk round 1 and can proceed with the second round of the protocol
    let share_rlk_b_round2 = CollectiveRlkGenerator::generate_share_2(
        &params,
        &s_pk_b,
        &rlk_agg_1.0,
        &rlk_agg_1.1,
        &s_rlk_b,
        0,
        &mut rng,
    );

    // generate collective public key and encryt b's input
    let collective_pk_shares = vec![share_pk_b.clone(), message_from_a.share_pk_a];
    let collecitve_pk = CollectivePublicKeyGenerator::aggregate_shares_and_finalise(
        &params,
        &collective_pk_shares,
        CRS_PK,
    );
    let pt = Plaintext::try_encoding_with_parameters(bit_vector, &params, Encoding::default());
    let ciphertext_b = collecitve_pk.encrypt(&params, &pt, &mut rng);

    let message_to_a = MessageBToAPostState1 {
        share_pk_b,
        share_rlk_b_round1,
        share_rlk_b_round2: share_rlk_b_round2.clone(),
        ciphertext_b: ciphertext_b.clone(),
    };

    let private_output_b = PrivateOutputBPostState1 { s_pk_b };
    let public_output_b = PublicOutputBPostState1 {
        ciphertext_b,
        share_rlk_b_round2,
        rlk_agg_round1_h1s: rlk_agg_1.1,
    };

    (private_output_b, public_output_b, message_to_a)
}

fn state2(
    private_output_a_state0: PrivateOutputAPostState0,
    public_output_a_state0: PublicOutputAPostState0,
    message_from_b: MessageBToAPostState1,
    bit_vector: &[u32],
) -> (PublicOutputAPostState2, MessageAToBPostState2) {
    let params = params();
    let mut rng = thread_rng();

    // aggrgegate shares of rlk round 1
    let h0s = vec![
        public_output_a_state0.share_rlk_a_round1.0,
        message_from_b.share_rlk_b_round1.0,
    ];
    let h1s = vec![
        public_output_a_state0.share_rlk_a_round1.1,
        message_from_b.share_rlk_b_round1.1,
    ];
    let rlk_agg_1 = CollectiveRlkGenerator::aggregate_shares_1(&params, &h0s, &h1s, 0);

    // generate share 2 for rlk round 2
    let share_rlk_a_round2 = CollectiveRlkGenerator::generate_share_2(
        &params,
        &private_output_a_state0.s_pk_a,
        &rlk_agg_1.0,
        &rlk_agg_1.1,
        &CollectiveRlkGeneratorState(private_output_a_state0.s_rlk_a),
        0,
        &mut rng,
    );

    // aggregate rlk round 2 shares and generate rlk
    let h0_dash_shares = vec![
        share_rlk_a_round2.0.clone(),
        message_from_b.share_rlk_b_round2.0,
    ];
    let h1_dash_shares = vec![
        share_rlk_a_round2.1.clone(),
        message_from_b.share_rlk_b_round2.1,
    ];
    let rlk = CollectiveRlkGenerator::aggregate_shares_2(
        &params,
        &h0_dash_shares,
        &h1_dash_shares,
        rlk_agg_1.1,
        0,
    );

    // create public key and encrypt A's bit vector'
    let collective_pk_shares = vec![public_output_a_state0.share_pk_a, message_from_b.share_pk_b];
    let collective_pk = CollectivePublicKeyGenerator::aggregate_shares_and_finalise(
        &params,
        &collective_pk_shares,
        CRS_PK,
    );
    let pt = Plaintext::try_encoding_with_parameters(bit_vector, &params, Encoding::default());
    let ciphertext_a = collective_pk.encrypt(&params, &pt, &mut rng);

    // perform PSI
    let evaluator = Evaluator::new(params);
    let evaluation_key = EvaluationKey::new_raw(&[0], vec![rlk], &[], &[], vec![]);
    let ciphertext_res = evaluator.mul(&ciphertext_a, &message_from_b.ciphertext_b);
    let ciphertext_res = evaluator.relinearize(&ciphertext_res, &evaluation_key);

    // generate decryption share of ciphertext_res
    let decryption_share_a = CollectiveDecryption::generate_share(
        evaluator.params(),
        &ciphertext_res,
        &private_output_a_state0.s_pk_a,
        &mut rng,
    );

    let public_output_a = PublicOutputAPostState2 {
        decryption_share_a: decryption_share_a.clone(),
        ciphertext_res,
    };

    let message_a_to_b = MessageAToBPostState2 {
        decryption_share_a,
        ciphertext_a,
        share_rlk_a_round2,
    };

    (public_output_a, message_a_to_b)
}

fn state3(
    private_output_b_state1: PrivateOutputBPostState1,
    public_output_b_state1: PublicOutputBPostState1,
    message_from_a: MessageAToBPostState2,
) -> (MessageBToAPostState3, Vec<u32>) {
    let params = params();
    let mut rng = thread_rng();

    // create rlk
    let h0_dash_shares = vec![
        message_from_a.share_rlk_a_round2.0,
        public_output_b_state1.share_rlk_b_round2.0,
    ];
    let h1_dash_shares = vec![
        message_from_a.share_rlk_a_round2.1,
        public_output_b_state1.share_rlk_b_round2.1,
    ];
    let rlk = CollectiveRlkGenerator::aggregate_shares_2(
        &params,
        &h0_dash_shares,
        &h1_dash_shares,
        public_output_b_state1.rlk_agg_round1_h1s,
        0,
    );

    // perform PSI
    let evaluator = Evaluator::new(params);
    let evaluation_key = EvaluationKey::new_raw(&[0], vec![rlk], &[], &[], vec![]);
    let ciphertext_res = evaluator.mul(
        &message_from_a.ciphertext_a,
        &public_output_b_state1.ciphertext_b,
    );
    let ciphertext_res = evaluator.relinearize(&ciphertext_res, &evaluation_key);

    // generate B's decryption share
    let decryption_share_b = CollectiveDecryption::generate_share(
        evaluator.params(),
        &ciphertext_res,
        &private_output_b_state1.s_pk_b,
        &mut rng,
    );

    // decrypt ciphertext res
    let decryption_shares_vec = vec![
        decryption_share_b.clone(),
        message_from_a.decryption_share_a,
    ];
    let psi_output = CollectiveDecryption::aggregate_share_and_decrypt(
        evaluator.params(),
        &ciphertext_res,
        &decryption_shares_vec,
    );
    let psi_output = Vec::<u32>::try_decoding_with_parameters(
        &psi_output,
        evaluator.params(),
        Encoding::default(),
    );

    let message_b_to_a = MessageBToAPostState3 { decryption_share_b };

    (message_b_to_a, psi_output)
}

fn state4(
    public_output_a_state2: PublicOutputAPostState2,
    message_from_b: MessageBToAPostState3,
) -> Vec<u32> {
    let params = params();

    // decrypt ciphertext res
    let decryption_shares_vec = vec![
        public_output_a_state2.decryption_share_a,
        message_from_b.decryption_share_b,
    ];
    let psi_output = CollectiveDecryption::aggregate_share_and_decrypt(
        &params,
        &public_output_a_state2.ciphertext_res,
        &decryption_shares_vec,
    );
    let psi_output =
        Vec::<u32>::try_decoding_with_parameters(&psi_output, &params, Encoding::default());

    psi_output
}

#[cfg(test)]
mod tests {
    use super::*;
    use bfv::SecretKeyProto;
    use itertools::{izip, Itertools};
    use rand::{distributions::Uniform, Rng};
    use traits::TryFromWithParameters;

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
        let hamming_weight = 10;
        let vector_size = 10;

        // A: state 0
        let (private_output_a_state0, public_output_a_state0, message_a_to_b_state0) = state0();

        // B: state  1
        let bit_vector_b = random_bit_vector(hamming_weight, vector_size);
        let (private_output_b_state1, public_output_b_state1, message_b_to_a_state1) =
            state1(message_a_to_b_state0, &bit_vector_b);

        // A: state 2
        let bit_vector_a = random_bit_vector(hamming_weight, vector_size);
        let (public_output_a_state2, message_a_to_b_state2) = state2(
            private_output_a_state0,
            public_output_a_state0,
            message_b_to_a_state1,
            &bit_vector_a,
        );

        // B: state 3
        let (message_b_to_a_state3, psi_output_b) = state3(
            private_output_b_state1,
            public_output_b_state1,
            message_a_to_b_state2,
        );

        // A: state 4
        let psi_output_a = state4(public_output_a_state2, message_b_to_a_state3);

        let expected_psi_output = plain_psi(&bit_vector_a, &bit_vector_b);

        assert_eq!(expected_psi_output, psi_output_a[..vector_size]);
        assert_eq!(psi_output_a, psi_output_b);
    }
}
