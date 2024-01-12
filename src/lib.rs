use bfv::{
    BfvParameters, Ciphertext, CollectivePublicKeyGenerator, CollectiveRlkGenerator,
    CollectiveRlkGeneratorState, Poly, SecretKey,
};
use rand::thread_rng;

static CRS_PK: [u8; 32] = [0u8; 32];
static CRS_RLK: [u8; 32] = [0u8; 32];

fn params() -> BfvParameters {
    let mut params = BfvParameters::new(&[30, 30], 65537, 1 << 15);
    params.enable_hybrid_key_switching(&[30]);
    params.enable_pke();
    params
}

struct PrivateOutputAPostState0 {
    s_pk_a: SecretKey,
    s_rlk_a: SecretKey,
}
struct MessageAToBPostState0 {
    share_pk_a: Poly,
    share_rlk_a: (Vec<Poly>, Vec<Poly>),
}

struct PrivateOutputBPostState0 {
    s_pk_b: SecretKey,
}
struct MessageBToAPostState1 {}

struct MessageAToBPostState2 {}

struct MessageBToAPostState3 {}

fn state0() -> (PrivateOutputAPostState0, MessageAToBPostState0) {
    let params = params();
    let mut rng = thread_rng();
    let s_pk_a = SecretKey::random_with_params(&params, &mut rng);
    let s_rlk_a = CollectiveRlkGenerator::init_state(&params, &mut rng);

    let share_pk_a =
        CollectivePublicKeyGenerator::generate_share(&params, &s_pk_a, CRS_PK, &mut rng);

    let share_rlk_a =
        CollectiveRlkGenerator::generate_share_1(&params, &s_pk_a, &s_rlk_a, CRS_RLK, 0, &mut rng);

    let message_a_to_b = MessageAToBPostState0 {
        share_pk_a,
        share_rlk_a,
    };

    let private_state_a = PrivateOutputAPostState0 {
        s_pk_a,
        s_rlk_a: s_rlk_a.0.clone(),
    };

    (private_state_a, message_a_to_b)
}

fn state1(input: MessageAToBPostState0) -> () {
    let params = params();
    let mut rng = thread_rng();
    let s_pk_b = SecretKey::random_with_params(&params, &mut rng);
    let s_rlk_b = CollectiveRlkGenerator::init_state(&params, &mut rng);

    let share_pk_b =
        CollectivePublicKeyGenerator::generate_share(&params, &s_pk_b, CRS_PK, &mut rng);

    let share_rlk_b =
        CollectiveRlkGenerator::generate_share_1(&params, &s_pk_b, &s_rlk_b, CRS_RLK, 0, &mut rng);

    // collective public key
    let collective_pk_shares = vec![share_pk_b.clone(), input.share_pk_a];
    let collecitve_pk = CollectivePublicKeyGenerator::aggregate_shares_and_finalise(
        &params,
        &collective_pk_shares,
        CRS_PK,
    );
}

fn state2() {}

fn state3() {}
