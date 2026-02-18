
// a simulated party

#[derive(Clone, Debug)]
struct View {
    secret: i64,
    randomness: i64,
    party_id: i64,
    messages: Vec<Message>,
}

/*
Messages to be send to parties
- Value P(partyID) = secret + randomness * partyID, partyID of receiver
- Sender, partyID of sender
 */
#[derive(Clone, Debug)]
struct Party {
    secret: i64,
    computed_secret: i64,
    randomness: i64,
    general_prime: i64,
    party_id: i64,
    received: i64,
    view: View
}
#[derive(Clone, Debug)]
struct Message {
    value: i64,
    sender: i64
}

// main method for running simulation
#[hax_lib::requires(true)]
fn main() {
    let secret = 30;
    // assert_eq!(secret % 5, 0);
    let general_prime_p = 257;
    // creating five parties who each have a part of the secret
    let parties = request_mpc_parties(secret, general_prime_p);
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
#[hax_lib::requires(secret < prime)]
fn request_mpc_parties(secret: i64, prime: i64) -> Vec<Party> {
    let secrets = split_secret(secret);
    // has to be larger than secret
    let general_prime_p = prime;
    let mut numberIter = 0..7;
    // creating each parti
    let parties = secrets.into_iter().map(|x| create_party(x, general_prime_p,
                                                           helper_for_number_sequence(numberIter.next()))).collect::<Vec<_>>();
    parties
}
// splitting secret
// #[hax_lib::requires(secret % 5 == 0)]
fn split_secret(secret: i64) -> [i64; 6] {

    [secret/6, secret/6,secret/6,secret/6,secret/6, secret/6]
}
// creation of party
fn create_party(secret_share: i64, general_prime_p: i64, partyID: i64) -> Party {
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
        randomness: random_num as i64,
        general_prime: general_prime_p,
        party_id: partyID,
        received: 0,
        view: View {secret: secret_share, randomness: random_num as i64, messages: vec![], party_id: partyID}
    };
    party
}

fn perform_mpc(parties: Vec<Party>) -> Vec<Party>{
    // sending messages to other parties
    // let resulting_parties = parties.iter().fold(parties.clone(), |acc, party| {println!("{:?}", acc); update_secret(party, acc)});
    // resulting_parties
    let number_iter = 0..6;

    let first_messages = number_iter
            .map(|i| parties.iter()
                .map(|party| generate_first_message(party, (i+1)))
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



fn generate_first_message(x: &Party, message_receiver: i64) -> Message {
    let message = Message {
        value: i64::rem_euclid((x.secret + x.randomness * message_receiver + x.randomness * message_receiver * message_receiver), x.general_prime),
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

fn helper_for_number_sequence(number: Option<i32>) -> i64 {
    let number_to_return = match number {
        Some(id) => id as i64 + 1,
        None =>  -1
    };
    number_to_return
}

fn sum_of_polynomials(party: Party, messages: Vec<Message>) -> Party {
    let sum_of_messages = messages.iter()
        .fold(0, |acc, message| {i64::rem_euclid(acc + message.value, party.general_prime)});
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

    let lambda1 = lambda_i_of(message11, message21, message31, party.general_prime as f64);
    let lambda2 = lambda_i_of(message22, message12, message32, party.general_prime as f64);
    let lambda3 = lambda_i_of(message33, message13, message23, party.general_prime as f64);

    let message1 = messages[0].clone();
    let message2 = messages[1].clone();
    let message3 = messages[2].clone();

    let secret = f64::rem_euclid(lambda1 * (message1.value as f64) + lambda2 * (message2.value as f64) + lambda3 * (message3.value as f64), party.general_prime as f64);

    let mut new_messags = party.view.messages.clone();
    new_messags.extend(messages);

    Party {
        computed_secret: secret as i64,
        view: View {messages: new_messags, ..party.view},
        ..party
    }
}

fn lambda_i_of(message1: Message, message2: Message, message3: Message, prime: f64) -> f64 {
    let product1 = (message3.sender as f64) / (message1.sender as f64 - message3.sender as f64);
    let product2 = (message2.sender as f64) / (message1.sender as f64 - message2.sender as f64);

    f64::rem_euclid(product1 * product2, prime)
}


fn check_consistent_view(view1: View, view2: View, n: usize, general_prime: i64) -> bool {
    let number_iter = n..n + n;
    let result = number_iter.fold(true, |acc, number| {
        view1.messages[number].sender == view2.messages[number].sender &&
            view1.messages[number].value == view2.messages[number].value && acc
    });

    let party1_value = i64::rem_euclid(view1.secret + view1.randomness * view2.party_id + view1.randomness * view2.party_id * view2.party_id, general_prime);
    let party2_value = i64::rem_euclid(view2.secret + view2.randomness * view1.party_id + view2.randomness * view1.party_id * view1.party_id,general_prime);

    let has_seen_message_from_party_1 = view2.messages.iter().fold(false, |acc, message| {
        acc || (message.sender == view1.party_id && message.value == party1_value)
    });

    let has_seen_message_from_party_2 = view1.messages.iter().fold(false, |acc, message| {
        acc || (message.sender == view2.party_id && message.value == party2_value)
    });

    result && has_seen_message_from_party_1 && has_seen_message_from_party_2
}

fn parties_get_right_secret(parties: Vec<Party>, secret: i64) -> bool{
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