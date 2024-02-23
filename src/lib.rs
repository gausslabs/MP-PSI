use bfv::{
    BfvParameters, Ciphertext, CollectiveDecryption, CollectiveDecryptionShare,
    CollectivePublicKeyGenerator, CollectivePublicKeyShare, CollectiveRlkAggTrimmedShare1,
    CollectiveRlkGenerator, CollectiveRlkShare1, CollectiveRlkShare2, Encoding, EvaluationKey,
    Evaluator, Plaintext, SecretKey,
};
use itertools::{izip, Itertools};
use rand::thread_rng;

use traits::{TryDecodingWithParameters, TryEncodingWithParameters, TryFromWithParameters};

mod bandwidth_benches;

static CRS_PK: [u8; 32] = [13u8; 32];
static CRS_RLK: [u8; 32] = [121u8; 32];

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

struct PsiKeys {
    s: SecretKey,
    s_rlk: SecretKey,
}

#[derive(Clone)]
struct MessageRound1 {
    share_pk: CollectivePublicKeyShare,
    share_rlk1: CollectiveRlkShare1,
}

fn gen_keys() -> (PsiKeys, MessageRound1) {
    let params = params();
    let mut rng = thread_rng();
    let s = SecretKey::random_with_params(&params, &mut rng);
    let s_rlk = CollectiveRlkGenerator::init_state(&params, &mut rng);

    let share_pk = CollectivePublicKeyGenerator::generate_share(&params, &s, CRS_PK, &mut rng);
    let share_rlk1 =
        CollectiveRlkGenerator::generate_share_1(&params, &s, &s_rlk, CRS_RLK, 0, &mut rng);

    (
        PsiKeys { s, s_rlk },
        MessageRound1 {
            share_pk,
            share_rlk1,
        },
    )
}

struct StateRound2 {
    rlk_agg1_trimmed: CollectiveRlkAggTrimmedShare1,
}

#[derive(Clone)]
struct MessageRound2 {
    share_rlk2: CollectiveRlkShare2,
    cts: Vec<Ciphertext>,
}

fn round1(
    psi_keys: &PsiKeys,
    message: MessageRound1,
    other_message: MessageRound1,
    bit_vector: &[u32],
) -> (StateRound2, MessageRound2) {
    let params = params();
    let mut rng = thread_rng();

    // generate pk
    let collective_pk = CollectivePublicKeyGenerator::aggregate_shares_and_finalise(
        &params,
        &[message.share_pk, other_message.share_pk],
        CRS_PK,
    );

    // generate rlk share 2
    let rlk_agg1 = CollectiveRlkGenerator::aggregate_shares_1(
        &params,
        &[message.share_rlk1, other_message.share_rlk1],
        0,
    );
    let share_rlk2 = CollectiveRlkGenerator::generate_share_2(
        &params,
        &psi_keys.s,
        &rlk_agg1,
        &psi_keys.s_rlk,
        0,
        &mut rng,
    );

    // encrypt bit vector
    let ciphertexts = bit_vector
        .chunks(RING_SIZE)
        .map(|v| {
            let pt = Plaintext::try_encoding_with_parameters(v, &params, Encoding::default());
            collective_pk.encrypt(&params, &pt, &mut rng)
        })
        .collect_vec();

    (
        StateRound2 {
            rlk_agg1_trimmed: rlk_agg1.trim(),
        },
        MessageRound2 {
            share_rlk2,
            cts: ciphertexts,
        },
    )
}

#[derive(Clone)]
struct MessageRound3 {
    decryption_shares: Vec<CollectiveDecryptionShare>,
}

struct StateRound3 {
    cts_res: Vec<Ciphertext>,
}

fn round2(
    psi_keys: &PsiKeys,
    state_round2: StateRound2,
    message: MessageRound2,
    other_message: MessageRound2,
    is_a: bool,
) -> (StateRound3, MessageRound3) {
    let params = params();
    let mut rng = thread_rng();

    // Create RLK
    let rlk = CollectiveRlkGenerator::aggregate_shares_2(
        &params,
        &[message.share_rlk2, other_message.share_rlk2],
        state_round2.rlk_agg1_trimmed,
        0,
    );

    // perform PSI
    let evaluator = Evaluator::new(params.clone());
    let evaluation_key = EvaluationKey::new_raw(&[0], vec![rlk], &[], &[], vec![]);
    let cts_res = izip!(message.cts.iter(), other_message.cts.iter())
        .map(|(ca, cb)| {
            let ct_out = {
                if is_a {
                    evaluator.mul(ca, cb)
                } else {
                    evaluator.mul(cb, ca)
                }
            };
            evaluator.relinearize(&ct_out, &evaluation_key)
        })
        .collect_vec();
    let decryption_shares = cts_res
        .iter()
        .map(|c| CollectiveDecryption::generate_share(evaluator.params(), c, &psi_keys.s, &mut rng))
        .collect_vec();

    (StateRound3 { cts_res }, MessageRound3 { decryption_shares })
}

fn round3(
    state_round3: StateRound3,
    message: MessageRound3,
    other_message: MessageRound3,
) -> Vec<u32> {
    let params = params();
    izip!(
        state_round3.cts_res.iter(),
        message.decryption_shares.into_iter(),
        other_message.decryption_shares.into_iter()
    )
    .flat_map(|(c, share_a, share_b)| {
        let pt = CollectiveDecryption::aggregate_share_and_decrypt(&params, c, &[share_a, share_b]);
        Vec::<u32>::try_decoding_with_parameters(&pt, &params, Encoding::default())
    })
    .collect_vec()
}

fn convert<T, U>(value: &T, parameters: &BfvParameters) -> U
where
    U: TryFromWithParameters<Value = T, Parameters = BfvParameters>,
{
    U::try_from_with_parameters(value, parameters)
}

#[cfg(test)]
mod tests {
    use super::*;

    use itertools::{izip, Itertools};
    use rand::{distributions::Uniform, Rng};

    fn random_bit_vector(hamming_weight: usize, size: usize) -> Vec<u32> {
        let mut rng = thread_rng();

        let mut bit_vector = vec![0; size];
        (0..hamming_weight).for_each(|_| {
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

        // gen keys
        let (a_psi_keys, a_message_round1) = gen_keys();
        let (b_psi_keys, b_message_round1) = gen_keys();

        // round1
        let a_bit_vector = random_bit_vector(hamming_weight, vector_size);
        let b_bit_vector = random_bit_vector(hamming_weight, vector_size);
        let (a_state_round2, a_message_round2) = round1(
            &a_psi_keys,
            a_message_round1.clone(),
            b_message_round1.clone(),
            &a_bit_vector,
        );
        let (b_state_round2, b_message_round2) = round1(
            &b_psi_keys,
            b_message_round1,
            a_message_round1,
            &b_bit_vector,
        );

        // round2
        let (a_state_round3, a_message_round3) = round2(
            &a_psi_keys,
            a_state_round2,
            a_message_round2.clone(),
            b_message_round2.clone(),
            true,
        );
        let (b_state_round3, b_message_round3) = round2(
            &b_psi_keys,
            b_state_round2,
            b_message_round2,
            a_message_round2,
            false,
        );

        // round3
        let a_psi_output = round3(
            a_state_round3,
            a_message_round3.clone(),
            b_message_round3.clone(),
        );
        let b_psi_output = round3(b_state_round3, b_message_round3, a_message_round3);

        let expected_psi_output = plain_psi(&a_bit_vector, &b_bit_vector);

        assert_eq!(expected_psi_output, a_psi_output[..vector_size]);
        assert_eq!(a_psi_output, b_psi_output);
    }
}
