use crate::utils::*;
use libcrux::drbg::Drbg;
// a simulated party

#[derive(Clone, Debug)]
struct View {
    secret: i128,
    randomness: i128,
    party_id: i128,
    messages: Vec<Message>,
}

/*
Messages to be send to parties
- Value P(partyID) = secret + randomness * partyID, partyID of receiver
- Sender, partyID of sender
 */
#[derive(Clone, Debug)]
struct Party {
    secret: i128,
    computed_secret: i128,
    randomness: i128,
    general_prime: i128,
    party_id: i128,

    view: View
}
#[derive(Clone, Debug)]
struct Message {
    value: i128,
    sender: i128
}

const FIELD: finite_field::Field = finite_field::Field {
    p: 257
};

// main method for running simulation
pub fn main() {

    let secret = 30;
    // assert_eq!(secret % 5, 0);

    // creating five parties who each have a part of the secret
    let parties = request_mpc_parties(secret, FIELD.p);
    // println!("{:?}", parties);
    // performing mpc with set parties, should return a view for each party
    let res_parties = perform_mpc(parties);

    let party1 = res_parties[0].clone();
    let party2 = res_parties[1].clone();

    let check = check_consistent_view(party1.view, party2.view, 6, party1.general_prime);
    println!("Check: {:?}", check);

    let second_check = parties_get_right_secret(res_parties, secret);
    println!("Second check: {:?}", second_check);

}

// 5 parties with respective start states
#[hax_lib::requires(secret < prime && secret > 0 && prime < i128::max_value())]
#[hax_lib::ensures(|result| result.len() > 0)]
fn request_mpc_parties(secret: i128, prime: i128) -> Vec<Party> {
    hax_lib::assert!(math::modulo(secret,6) == 0);
    let secrets = split_secret(secret);
    // has to be larger than secret
    let general_prime_p = prime;
    // creating each parti
    let parties = create_parties(secrets, prime);
    parties
}

#[hax_lib::exclude]
fn create_parties(secrets: [i128; 6], prime: i128) -> Vec<Party> {
    let mut number_iter = 0..7;
    let parties = secrets.into_iter()
        .map(|x| create_party(x, prime, helper_for_number_sequence(number_iter.next())))
        .collect::<Vec<_>>();
    parties
}
// splitting secret
#[hax_lib::requires(secret % 6 == 0)]
fn split_secret(secret: i128) -> [i128; 6] {

    [secret/6, secret/6,secret/6,secret/6,secret/6, secret/6]
}
// creation of party
#[hax_lib::requires(secret_share < general_prime_p && general_prime_p < i128::max_value())]
#[hax_lib::ensures(|result| result.randomness < general_prime_p)]
fn create_party(secret_share: i128, general_prime_p: i128, party_id: i128) -> Party {
    let mut rand_gen = match Drbg::new(libcrux::digest::Algorithm::Sha256) {
        Ok(drbg) => drbg,
        Err(e) => panic!("{}", e)
    };
    let mut rand_bytes = [0u8; 1];
    match rand_gen.generate(&mut rand_bytes) {
        Ok(_) => (),
        Err(e) => panic!("{}", e)
    };

    let random_num = u8::from_le_bytes(rand_bytes);

    let party: Party = Party {secret: secret_share,
        computed_secret: 0,
        randomness: random_num as i128,
        general_prime: general_prime_p,
        party_id,
        view: View {secret: secret_share, randomness: random_num as i128, messages: vec![], party_id }
    };
    party
}

#[hax_lib::requires(parties.len() > 0)]
#[hax_lib::ensures(|result| result.len() == parties.len())]
fn perform_mpc(parties: Vec<Party>) -> Vec<Party>{
    // sending messages to other parties
    // let resulting_parties = parties.iter().fold(parties.clone(), |acc, party| {println!("{:?}", acc); update_secret(party, acc)});
    // resulting_parties
    let number_iter = 0..6;

    let first_messages = number_iter
        .map(|i| parties.iter()
            .map(|party| generate_first_message(party, i+1))
            .collect::<Vec<_>>())
        .collect::<Vec<_>>();

    let number_iter_copy = 0..6;



    // new parties have calculated R_partyID
    let parties_containg_first_messages = number_iter_copy
        .map(|i| sum_of_polynomials(parties[i].clone(), first_messages[i].clone()))
        .collect::<Vec<_>>();

    // need messages (partyID, R_partyID)
    let second_messages = parties_containg_first_messages.iter()
        .map(|party| generate_second_message(party.clone()))
        .collect::<Vec<_>>();

    // new parties with MPC been finished

    let final_parties = parties_containg_first_messages.iter()
        .map(|party|  lagrange_interpolation(second_messages.clone(), party.clone()))
        .collect::<Vec<_>>();

    final_parties
}


#[hax_lib::requires(message_receiver > 0)]
#[hax_lib::ensures(|result| result.value == math::modulo((x.secret + x.randomness * message_receiver + x.randomness * message_receiver * message_receiver), x.general_prime))]
fn generate_first_message(x: &Party, message_receiver: i128) -> Message {
    let message = Message {
        value: math::modulo(x.secret + x.randomness * message_receiver + x.randomness * message_receiver * message_receiver, x.general_prime),
        sender: x.party_id,
    };

    message
}

fn generate_second_message(x: Party) -> Message {
    let message = Message {
        value: x.computed_secret,
        sender: x.party_id,
    };


    message
}

fn helper_for_number_sequence(number: Option<i32>) -> i128 {
    let number_to_return = match number {
        Some(id) => id as i128 + 1,
        None =>  -1
    };
    number_to_return
}

fn sum_of_polynomials(party: Party, messages: Vec<Message>) -> Party {
    let sum_of_messages = messages.iter()
        .fold(0, |acc, message| {math::modulo(acc + message.value, party.general_prime)});
    Party { computed_secret: sum_of_messages,
        view: View {messages: messages, ..party.view},
        ..party
    }
}

fn lagrange_interpolation(messages: Vec<Message>, party: Party) -> Party {
    let message11 = messages[0].clone();
    let message21 = messages[1].clone();
    let message31 = messages[2].clone();

    let message12 = messages[0].clone();
    let message22 = messages[1].clone();
    let message32 = messages[2].clone();

    let message13 = messages[0].clone();
    let message23 = messages[1].clone();
    let message33 = messages[2].clone();

    let lambda1 = lambda_i_of(message11, message21, message31, party.general_prime);
    let lambda2 = lambda_i_of(message22, message12, message32, party.general_prime);
    let lambda3 = lambda_i_of(message33, message13, message23, party.general_prime);

    let message1 = messages[0].clone();
    let message2 = messages[1].clone();
    let message3 = messages[2].clone();

    let secret = math::modulo(lambda1 * (message1.value) + lambda2 * (message2.value) + lambda3 * (message3.value), party.general_prime);

    let mut new_messags = party.view.messages.clone();
    new_messags.extend(messages);

    Party {
        computed_secret: secret,
        view: View {messages: new_messags, ..party.view},
        ..party
    }
}

fn lambda_i_of(message1: Message, message2: Message, message3: Message, prime: i128) -> i128 {
    let x1 = message1.sender;
    let x2 = message2.sender;
    let x3 = message3.sender;

    let numer = &x3 * &x2;

    let denom = math::modulo((&x1 - &x3) * (&x1 - &x2), prime);
    let denom_inv = FIELD.multiplicative_inverse(denom);
    // let gcd = &denom.extended_gcd(prime);
    // let denom_inv = gcd.x.rem_euclid(prime);

    math::modulo(numer * denom_inv, prime)
}


fn check_consistent_view(view1: View, view2: View, n: usize, general_prime: i128) -> bool {
    let number_iter = n..n + n;
    let result = number_iter.fold(true, |acc, number| {
        view1.messages[number].sender == view2.messages[number].sender &&
            view1.messages[number].value == view2.messages[number].value && acc
    });

    let party1_value = math::modulo(view1.secret + view1.randomness * view2.party_id + view1.randomness * view2.party_id * view2.party_id, general_prime);
    let party2_value = math::modulo(view2.secret + view2.randomness * view1.party_id + view2.randomness * view1.party_id * view1.party_id,general_prime);

    let has_seen_message_from_party_1 = view2.messages.iter().fold(false, |acc, message| {
        acc || (message.sender == view1.party_id && message.value == party1_value)
    });

    let has_seen_message_from_party_2 = view1.messages.iter().fold(false, |acc, message| {
        acc || (message.sender == view2.party_id && message.value == party2_value)
    });

    result && has_seen_message_from_party_1 && has_seen_message_from_party_2
}

fn parties_get_right_secret(parties: Vec<Party>, secret: i128) -> bool{
    let result = parties.iter().fold(true, |acc, party| {party.computed_secret == secret && acc});

    result
}

/*
fn update_secret(x: &Party, parties: Vec<Party>) -> Vec<Party> {
    let new_secret = parties.into_iter().map(|y| Party{secret: y.secret,
        computed_secret: y.computed_secret + x.secret,
        randomness: y.randomness,
        general_prime: y.general_prime,
        party_id: y.party_id,
        received: y.received + 1
    }).collect::<Vec<_>>();
    new_secret
}
 */