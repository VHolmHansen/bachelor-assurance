
// a simulated party

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
}
#[derive(Clone, Debug)]
struct Message {
    value: i64,
    sender: i64,
    ID: String
}

// main method for running simulation
#[hax_lib::requires(true)]
fn main() {
    let secret = 30;
    assert_eq!(secret % 5, 0);
    let general_prime_p = 17;
    // creating five parties who each have a part of the secret
    let parties = request_mpc_parties(secret, general_prime_p);
    println!("{:?}", parties);
    // performing mpc with set parties, should return a view for each party
    perform_mpc(parties);
}

// 5 parties with respective start states
fn request_mpc_parties(secret: i64, prime: i64) -> Vec<Party>{
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
#[hax_lib::requires(secret % 5 == 0)]
fn split_secret(secret: i64) -> [i64; 6] {
    [secret/6, secret/6,secret/6,secret/6,secret/6, secret/6]
}
// creation of party
fn create_party(secret_share: i64, general_prime_p: i64, partyID: i64) -> Party {
    let random_value = general_prime_p;
    let party: Party = Party {secret: secret_share,
        computed_secret: 0,
        randomness: random_value,
        general_prime: general_prime_p,
        party_id: partyID,
        received: 0,
    };
    party
}

fn perform_mpc(parties: Vec<Party>) -> Vec<Party>{
    // sending messages to other parties
    // let resulting_parties = parties.iter().fold(parties.clone(), |acc, party| {println!("{:?}", acc); update_secret(party, acc)});
    // resulting_parties
    let mut numberIter = 0..6;

    let messages = parties.iter().map(|party| generate_first_message(party, 1)).collect::<Vec<_>>();
    println!("{:#?}", messages);

    parties
}

fn on_party_receive_message(x: Party, message: Message) -> Party {
    let updated_party = Party{
        secret: x.secret,
        computed_secret: (x.computed_secret + message.value) % x.general_prime,
        randomness: x.randomness,
        general_prime: x.general_prime,
        party_id: x.party_id,
        received: x.received + 1,
    };
    updated_party
}

fn generate_first_message(x: &Party, message_receiver: i64) -> Message {
    let message = Message {
        value: (x.secret + x.randomness * message_receiver + x.randomness * message_receiver * message_receiver) % x.general_prime,
        sender: x.party_id,
        ID: "P of ".to_string() + &*(x.party_id).to_string() + " for " + &*message_receiver.to_string()
    };
    message
}

fn generate_second_message(x: Party) -> Message {
    let message = Message {
        value: x.computed_secret,
        sender: x.party_id,
        ID: "(PartyID, R_PartyID)".to_string()
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