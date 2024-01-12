use bfv::{
    BfvParameters, CollectiveDecryption, CollectivePublicKeyGenerator, CollectiveRlkGenerator,
    Encoding, EvaluationKey, Evaluator, MHEDebugger, Plaintext, Poly, PublicKey, SecretKey,
};
use itertools::{izip, Itertools};
use rand::{distributions::Uniform, thread_rng, Rng};

struct Party {
    secret: SecretKey,
    bit_vector: Vec<u64>,
}

impl Party {
    fn random(params: &BfvParameters, hamming_weight: usize) -> Party {
        let mut rng = thread_rng();
        let secret = SecretKey::random_with_params(params, &mut rng);

        let mut bit_vector = vec![0; params.degree];
        (0..hamming_weight).into_iter().for_each(|_| {
            let sample_index = rng.sample(Uniform::new(0, params.degree));
            bit_vector[sample_index] = 1;
        });

        Party { secret, bit_vector }
    }
}

fn plain_psi(parties: &[Party]) -> Vec<u64> {
    let mut common = parties[0].bit_vector.clone();
    parties.iter().skip(1).for_each(|party_i| {
        izip!(common.iter_mut(), party_i.bit_vector.iter()).for_each(|(b_out, b_in)| {
            *b_out *= b_in;
        });
    });
    common
}

fn main() {
    let mut params = BfvParameters::new(&[30, 30], 65537, 1 << 15);
    params.enable_hybrid_key_switching(&[30]);
    params.enable_pke();

    let hw = 21000;

    let parties = vec![Party::random(&params, hw), Party::random(&params, hw)];

    // Collective public key generation //
    let crs = [0u8; 32];
    let mut rng = thread_rng();
    // Each party generates their share
    let shares = parties
        .iter()
        .map(|party_i| {
            CollectivePublicKeyGenerator::generate_share(&params, &party_i.secret, crs, &mut rng)
        })
        .collect::<Vec<Poly>>();
    // After each party has broadcasted their share, any one can generate public key
    let public_key =
        CollectivePublicKeyGenerator::aggregate_shares_and_finalise(&params, &shares, crs);

    // Collective relinearization key generation //
    // This is a 2 round protocol
    let crs = [0u8; 32];
    let level = 0;
    // Each party generates a ephemeral state
    let parties_state = parties
        .iter()
        .map(|_| CollectiveRlkGenerator::init_state(&params, &mut rng))
        .collect_vec();
    // Each party generates share1
    let mut share1s_part0 = vec![];
    let mut share1s_part1 = vec![];
    izip!(parties.iter(), parties_state.iter()).for_each(|(party_i, internal_state_i)| {
        // Party i brodcasts `part0` and `part1`
        let (part0, part1) = CollectiveRlkGenerator::generate_share_1(
            &params,
            &party_i.secret,
            internal_state_i,
            crs,
            level,
            &mut rng,
        );
        share1s_part0.push(part0);
        share1s_part1.push(part1);
    });
    // After each party has broadcasted their share1, each party proceeds to aggregate share1s and generate their share2.
    let (share1s_part0_agg, share1s_part1_agg) =
        CollectiveRlkGenerator::aggregate_shares_1(&params, &share1s_part0, &share1s_part1, level);

    // Round 2
    // Each party generates share2
    let mut share2s_part0 = vec![];
    let mut share2s_part1 = vec![];
    izip!(parties.iter(), parties_state.iter()).for_each(|(party_i, internal_state_i)| {
        // Party i brodcasts `part0` and `part1`
        let (part0, part1) = CollectiveRlkGenerator::generate_share_2(
            &params,
            &party_i.secret,
            &share1s_part0_agg,
            &share1s_part1_agg,
            internal_state_i,
            level,
            &mut rng,
        );
        share2s_part0.push(part0);
        share2s_part1.push(part1);
    });
    // Each party broadcasts their share2, after which they aggregate the received shares and finalise the protocol
    let rlk = CollectiveRlkGenerator::aggregate_shares_2(
        &params,
        &share2s_part0,
        &share2s_part1,
        share1s_part1_agg,
        level,
    );

    // PSI //
    // Two users use the public key to encryt their `bit_vector`s. Note that unless the two users come together to collecticely decrypt, their inputs stay private.
    // Party 1
    let pt1 = Plaintext::encode(&parties[0].bit_vector, &params, Encoding::default());
    let ct1 = public_key.encrypt(&params, &pt1, &mut rng);

    // Party 2
    let pt2 = Plaintext::encode(&parties[1].bit_vector, &params, Encoding::default());
    let ct2 = public_key.encrypt(&params, &pt2, &mut rng);

    // Each party sends their ciphertext to the other party and both of them evaluate the FHE circuit (FHE circuit is simple ciphertext multiplication)
    let evaluation_key = EvaluationKey::new_raw(&[level], vec![rlk], &[], &[], vec![]);
    let evaluator = Evaluator::new(params);
    let ct1ct2 = evaluator.mul(&ct1, &ct2);
    let psi_ct = evaluator.relinearize(&ct1ct2, &evaluation_key);

    unsafe {
        let secrets = parties.iter().map(|s| s.secret.clone()).collect_vec();
        dbg!(MHEDebugger::measure_noise(
            &secrets,
            evaluator.params(),
            &psi_ct
        ));
    }

    // Collective decryption //
    // Each party can independently generate their share to decrypt `psi_ct`. Unless the other party has evaluated the FHE circuit maliciously, they should be able to decrypt `psi_ct` after receiving other party's share.
    // As it is often the case in MPC, the last party to send their share has leverage to not send the share and prevent the other party from learning PSI output.
    let party1_share = CollectiveDecryption::generate_share(
        evaluator.params(),
        &psi_ct,
        &parties[0].secret,
        &mut rng,
    );
    let party2_share = CollectiveDecryption::generate_share(
        &evaluator.params(),
        &psi_ct,
        &parties[1].secret,
        &mut rng,
    );

    // With shares from party1 and party2, one can decrypt the ciphertext
    let psi_output_pt = CollectiveDecryption::aggregate_share_and_decrypt(
        evaluator.params(),
        &psi_ct,
        &[party1_share, party2_share],
    );
    let psi_output: Vec<u64> = psi_output_pt.decode(Encoding::default(), evaluator.params());
    let expected_outpout = plain_psi(&parties);

    assert_eq!(psi_output, expected_outpout);
}
