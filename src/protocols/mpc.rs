use std::any::TypeId;
use std::array;
use crate::utils::*;
use libcrux::drbg::Drbg;
use hax_lib::{assume, loop_invariant, Int, ToInt};
// a simulated party


#[derive(Clone, Debug)]
struct View {
    secret: Int,
    randomness: Int,
    party_id: Int,
    messages: Vec<Message>,
}

/*
Messages to be send to parties
- Value P(partyID) = secret + randomness * partyID, partyID of receiver
- Sender, partyID of sender
 */
#[derive(Clone, Debug)]
struct Party {
    secret: Int,
    computed_secret: Int,
    randomness: Int,
    general_prime: Int,
    party_id: Int,

    view: View
}
#[derive(Clone, Debug)]
struct Message {
    value: Int,
    sender: Int
}



#[hax_lib::attributes]
#[hax_lib::ensures(|result| result.p > 0.to_int())]
fn field() -> finite_field::Field {
    finite_field::new(257.to_int())
}

// const FIELD: finite_field::Field  = field();

// main method for running simulation
#[hax_lib::exclude]
pub fn main() {


    let secret = 30.to_int();
    // assert_eq!(secret % 5, 0);

    // creating five parties who each have a part of the secret
    hax_lib::assert!(field().p > 0.to_int());
    let parties = request_mpc_parties(secret);
    // println!("{:?}", parties);
    // performing mpc with set parties, should return a view for each party
    let res_parties = perform_mpc(parties);

    let party1 = res_parties[0].clone();
    let party2 = res_parties[1].clone();

    let check = check_consistent_view(party1.view, party2.view, 6);
    println!("Check: {:?}", check);

    let second_check = parties_get_right_secret(res_parties, secret);
    println!("Second check: {:?}", second_check);

}

// 5 parties with respective start states
#[hax_lib::exclude]
#[hax_lib::requires(secret < field().p
                    && secret > 0.to_int()
                    //&& field().p > 0.to_int()
                    && secret.rem_euclid(6.to_int()) == 0.to_int())]
#[hax_lib::ensures(|result| result.len() > 0

                    )]
fn request_mpc_parties(secret: Int) -> Vec<Party> {
    //assert_eq!(secret.rem_euclid(6.to_int()), 0.to_int());
    let secrets = split_secret(secret);
    // has to be larger than secret

    let parties: Vec<Party> = array::from_fn::<Party, 6, _>(|n: usize| {
        assume!(n < secrets.len());
        create_party(secrets[n], (n + 1).to_int())
    }).to_vec();

    parties


}
// splitting secret
#[hax_lib::exclude]
#[hax_lib::requires(secret.rem_euclid(6.to_int()) == 0.to_int())]
#[hax_lib::ensures(|result| result.len() == 6
                    && (0..result.len()).fold(true, |acc, i| {
                        hax_lib::assume!(i < result.len());
                        acc && result[i] < field().p })
                    )]
fn split_secret(secret: Int) -> [Int; 6] {

    [secret/6.to_int(), secret/6.to_int(),secret/6.to_int(),secret/6.to_int(),secret/6.to_int(), secret/6.to_int()]
}

#[hax_lib::exclude]
#[hax_lib::opaque]
#[hax_lib::ensures(|result| result < field().p)]
fn generate_random_number() -> Int {
    let mut rand_gen = match Drbg::new(libcrux::digest::Algorithm::Sha256) {
        Ok(drbg) => drbg,
        Err(e) => panic!("{}", e)
    };
    let mut rand_bytes = [0u8; 1];
    match rand_gen.generate(&mut rand_bytes) {
        Ok(_) => (),
        Err(e) => panic!("{}", e)
    };

    (u8::from_le_bytes(rand_bytes)).to_int()

}
// creation of party
#[hax_lib::exclude]
#[hax_lib::requires(secret_share < field().p
                    && party_id > 0.to_int()
                    )]
#[hax_lib::ensures(|result| result.randomness < field().p
                    && result.party_id > 0.to_int()
                    )]
fn create_party(secret_share: Int, party_id: Int) -> Party {

    let random_num = generate_random_number();
    hax_lib::assume!(random_num < field().p);
    let party: Party = Party {secret: secret_share,
        computed_secret: 0.to_int(),
        randomness: random_num,
        general_prime: field().p,
        party_id,
        view: View {secret: secret_share, randomness: random_num, messages: vec![], party_id }
    };
    party
}
#[hax_lib::exclude]
#[hax_lib::requires(parties.len() > 0
                    && parties.len() < usize::MAX
                    )]
#[hax_lib::ensures(|result| result.len() == parties.len())]
fn perform_mpc(parties: Vec<Party>) -> Vec<Party>{
    // sending messages to other parties
    // let resulting_parties = parties.iter().fold(parties.clone(), |acc, party| {println!("{:?}", acc); update_secret(party, acc)});
    // resulting_parties


    /*
    vec2.len() < usize::MAX - vec3.len()
                    && vec2.len() > 0
                    && vec3.len() > 0
                    )]
     */

    let mut first_messages: Vec<Vec<Message>> = vec![];

    for i in 0..parties.len() {
        loop_invariant!(|i: usize| {
            i <= parties.len()
            && first_messages.len() == i
            && first_messages.len() < usize::MAX - parties.len()
        });


        let mut inner_messages: Vec<Message> = vec![];

        for j in 0..parties.len() {
            loop_invariant!(|j: usize| {
                j <= parties.len()
                && inner_messages.len() == j
                && inner_messages.len() < usize::MAX - parties.len()
            });
            assert!(j < parties.len());

            /*
            (message_receiver > 0.to_int()
                    && x.party_id > 0.to_int()
                    && message_receiver < field().p
                    && x.party_id < field().p
                    //&& field().p > 0.to_int()
                    )]
             */
            let receiver = (i+1).to_int();
            assume!(parties[j].party_id > 0.to_int());
            assume!(parties[j].party_id < field().p);
            assert!(receiver > 0.to_int());
            assume!(receiver < field().p);
            let vec_to_add = vec![generate_first_message(&parties[j].clone(), receiver)];
            assert_eq!(vec_to_add.len(), 1);
            assert!(inner_messages.len() < usize::MAX - vec_to_add.len());
            let old_len = inner_messages.len();
            inner_messages = push_on_vec(inner_messages, vec_to_add.clone());
            assert!(old_len == j);
            assert!(vec_to_add.len() == 1);
            //assert!(inner_messages.len() == old_len + 1);
            assert!(inner_messages.len() == j + 1);
        }


        let vec_to_add = vec![inner_messages];
        assert_eq!(vec_to_add.len(), 1);
        assert!(first_messages.len() < usize::MAX - vec_to_add.len());
        let old_len = first_messages.len();
        first_messages = push_on_vec(first_messages, vec_to_add.clone());
        assert!(old_len == i);
        assert!(vec_to_add.len() == 1);
        //assert!(first_messages.len() == old_len + 1);
        assert!(first_messages.len() == i + 1);
    }


    for i in 0..parties.len() {
        let mut inner: Vec<Message> = vec![];
        for j in 0..parties.len() {
            /*hax_lib::loop_invariant!(|j: usize| {

            });
             */

            inner.push(generate_first_message(&parties[j].clone(), (i+1).to_int()));
        }
        first_messages.push(inner);

    }





    //hax_lib::assert!(first_messages.len() == parties.len());
    /*
    // new parties have calculated R_partyID
    let mut parties_containing_first_messages = vec![];
    for i in 0..parties.len() {
        parties_containing_first_messages.push(sum_of_polynomials(parties[i].clone(), first_messages[i].clone()));
    }


    // need messages (partyID, R_partyID)
    let mut second_messages: Vec<Message> = vec![];

    for i in 0..parties.len() {
        second_messages.push(generate_second_message(parties_containing_first_messages[i].clone()))
    };

    // new parties with MPC been finished
    //let final_parties = push_on_vec(vec![], lagrange_interpolation(second_messages.clone(), parties_containing_first_messages));

    let mut final_parties: Vec<Party> = vec![];
    for i in 0..6 {
        final_parties = push_on_vec(final_parties, vec![lagrange_interpolation(second_messages.clone(), parties_containing_first_messages[i].clone())]);
    }



    final_parties

     */
    parties
}
#[hax_lib::requires(parties.len() > 0)]
#[hax_lib::ensures(|result| result.len() > 0)]
fn generate_first_messages(parties: &Vec<Party>) -> Vec<Vec<Message>> {
    let f = field();
    let parties_len = parties.len();
    let mut messages: Vec<Message> = vec![];
    for i in 0..parties_len {
        hax_lib::loop_invariant!(|i: usize| {
            messages.len() == i
            && i <= parties_len
        });

        let receiver = (i + 1).to_int();

        assert!(receiver > 0.to_int());

        assert!(receiver < f.p);
        assert!(parties[i].party_id > 0.to_int());
                assert!(parties[i].party_id < f.p);

        let vec_to_add = vec![generate_first_message(&parties[i], receiver)];

        assert!(messages.len() <= usize::MAX - vec_to_add.len()
                && vec_to_add.len() > 0
                && vec_to_add.len() <= usize::MAX);

        messages = push_on_vec(messages, vec_to_add);
    }
    vec![vec![]]
}

#[hax_lib::opaque]
#[hax_lib::requires(message_receiver > 0.to_int()
                    && x.party_id > 0.to_int()
                    && message_receiver < field().p
                    && x.party_id < field().p
                    )]
#[hax_lib::ensures(|result| result.value < field().p
                    && result.sender == x.party_id
                    // result.value == ((x.secret + x.randomness * message_receiver + x.randomness * message_receiver * message_receiver)).rem_euclid(field().p)
                    )]
fn generate_first_message(x: &Party, message_receiver: Int) -> Message {
    let temp = x.secret + x.randomness * message_receiver + x.randomness * message_receiver * message_receiver;
    let message = Message {
        value: (temp).rem_euclid(field().p),
        sender: x.party_id,
    };

    message
}

#[hax_lib::requires(x.party_id > 0.to_int()
                    && x.computed_secret < field().p
                    )]
#[hax_lib::ensures(|result| result.value < field().p
                    && result.sender == x.party_id
                    )]
fn generate_second_message(x: Party) -> Message {
    let message = Message {
        value: x.computed_secret,
        sender: x.party_id,
    };
    //assert_eq!(x.party_id, message.sender);

    message
}

#[hax_lib::requires(messages.len() > 0
                    && party.party_id > 0.to_int()
                    && (0..messages.len()).fold(true, |acc, i| {
                        hax_lib::assume!(i < messages.len());
                        acc && messages[i].value < field().p})
                    )]
#[hax_lib::ensures(|result| result.computed_secret < field().p
                    && result.view.messages.len() > 0
                    )]
fn sum_of_polynomials(party: Party, messages: Vec<Message>) -> Party {
    let f = field();

    let mut sum_of_messages = 0.to_int();
    for i in 0..messages.len() {
        loop_invariant!(|i: usize| {
                i <= messages.len()
                && sum_of_messages < f.p

            });
        assume!(messages[i].value < f.p); //TODO
        sum_of_messages = f.addition(sum_of_messages, messages[i].value)
    }

    Party { computed_secret: sum_of_messages,
        view: View {messages, ..party.view},
        ..party
    }
}

#[hax_lib::requires(messages.len() > 2
                    && party.view.messages.len() > 0
                    && messages.len() < usize::MAX - party.view.messages.len()
                    && messages[0].sender != messages[1].sender
                    && messages[0].sender != messages[2].sender
                    && messages[1].sender != messages[2].sender
                    && messages[0].sender < field().p
                    && messages[1].sender < field().p
                    && messages[2].sender < field().p
                    && messages[0].sender > 0.to_int()
                    && messages[1].sender > 0.to_int()
                    && messages[2].sender > 0.to_int()
                    && field().p > 0.to_int()
                    )]
#[hax_lib::ensures(|result| result.computed_secret < field().p
                    && result.view.messages.len() > 0
                    )]
fn lagrange_interpolation(messages: Vec<Message>, party: Party) -> Party {
    let f = field();
    let message11 = messages[0].clone();
    let message21 = messages[1].clone();
    let message31 = messages[2].clone();

    let message12 = messages[0].clone();
    let message22 = messages[1].clone();
    let message32 = messages[2].clone();

    let message13 = messages[0].clone();
    let message23 = messages[1].clone();
    let message33 = messages[2].clone();


    let lambda1 = lambda_i_of(message11, message21, message31);
    let lambda2 = lambda_i_of(message22, message12, message32);
    let lambda3 = lambda_i_of(message33, message13, message23);

    let message1 = messages[0].clone();
    let message2 = messages[1].clone();
    let message3 = messages[2].clone();

    let secret = (lambda1 * (message1.value) + lambda2 * (message2.value) + lambda3 * (message3.value)).rem_euclid(field().p);

    let new_messages = push_on_vec(party.view.messages, messages);

    hax_lib::assert!(new_messages.len() > 0);
    hax_lib::assert!(secret < f.p);
    Party {
        computed_secret: secret,
        view: View {messages: new_messages, ..party.view},
        ..party
    }
}
#[hax_lib::requires(vec3.len() <= usize::MAX
                    && vec3.len() > 0
                    && vec2.len() <= usize::MAX - vec3.len()
                    && vec2.len() >= 0
                    )]
#[hax_lib::ensures(|result| result.len() > 0
                    && result.len() > vec2.len()
                    && result.len() == vec2.len() + vec3.len()
                    )]
fn push_on_vec<T: Clone>(vec2: Vec<T>, vec3: Vec<T>) -> Vec<T> {
    let mut vec1 = vec2.clone();
    /*
    assume!(vec1.len() <= usize::MAX - 1);
    assume!(vec2.len() > 0);

    if vec2.len() > 0 {
    for i in 0..vec2.len() {
        loop_invariant!(|i: usize| {
            i <= vec2.len()
            && vec1.len() == i
        });
        let old_len = vec1.len();
        assume!(i < vec2.len() && vec1.len() < usize::MAX - 1);
        vec1.push(vec2[i].clone());
        assert!(old_len <= usize::MAX - 1);
        assert!(vec1.len() == old_len + 1);
        assert!(old_len == i);
        assert!(vec1.len() == (i + 1));
        assert!(vec1.len() <= usize::MAX);
    }}

     */


    for i in 0..vec3.len() {
        loop_invariant!(|i: usize| {
            i <= vec3.len()
            && vec1.len() == vec2.clone().len() + i
        });
        let old_len = vec1.len();

        vec1.insert(vec2.len() + i, vec3[i].clone());
        //vec1.push(vec3[i].clone());
        assert!(vec2.len() <= usize::MAX - (i + 1));
        assert!(old_len <= usize::MAX - 1);
        //assert!(vec1.len() <= usize::MAX - (vec2.len() + i + 1));
        assert!(vec1.len() == old_len + 1);
        assert!(old_len == vec2.clone().len() + i);
        assert!(vec1.len() == vec2.len() + (i + 1));
    }

    assume!(vec1.len() <= usize::MAX && vec1.len() > 0 && vec1.len() == vec2.len() + vec3.len());
    vec1
}

#[hax_lib::requires(message1.sender > 0.to_int()
                    && message2.sender > 0.to_int()
                    && message3.sender > 0.to_int()
                    && message1.sender < field().p
                    && message2.sender < field().p
                    && message3.sender < field().p
                    && message1.sender != message2.sender
                    && message1.sender != message3.sender
                    )]
#[hax_lib::ensures(|result| result < field().p)]
fn lambda_i_of(message1: Message, message2: Message, message3: Message) -> Int {
    let x1 = message1.sender;
    let x2 = message2.sender;
    let x3 = message3.sender;
    let f = field();

    let numer = f.multiplication(x3, x2);
    //let numer = x3 * x2;

    let denom= f.multiplication(f.addition(x1, f.additive_inverse(x3)), f.addition(x1, f.additive_inverse(x2)));
    //let denom = ((x1 - x3) * (x1 - x2)).rem_euclid(field().p);
    hax_lib::assert!(denom < f.p);
    hax_lib::assume!(denom > 0.to_int()); //TODO: Check if can be replaced with assert
    let denom_inv = f.multiplicative_inverse(denom);
    hax_lib::assert!(denom_inv < f.p);

    //(numer * denom_inv).rem_euclid(field().p)
    f.multiplication(numer, denom_inv)
}

#[hax_lib::exclude]
#[hax_lib::requires(view1.messages.len() > 0
                    && view2.messages.len() > 0
                    && n < view1.messages.len() //TODO: probably not correct
                    )]
fn check_consistent_view(view1: View, view2: View, n: usize) -> bool {
    let number_iter = n..n + n;
    let result = number_iter.fold(true, |acc, number| {
        view1.messages[number].sender == view2.messages[number].sender &&
            view1.messages[number].value == view2.messages[number].value && acc
    });

    let party1_value = (view1.secret + view1.randomness * view2.party_id + view1.randomness * view2.party_id * view2.party_id).rem_euclid(field().p);
    let party2_value = (view2.secret + view2.randomness * view1.party_id + view2.randomness * view1.party_id * view1.party_id).rem_euclid(field().p);

    let has_seen_message_from_party_1 = view2.messages.iter().fold(false, |acc, message| {
        acc || (message.sender == view1.party_id && message.value == party1_value)
    });

    let has_seen_message_from_party_2 = view1.messages.iter().fold(false, |acc, message| {
        acc || (message.sender == view2.party_id && message.value == party2_value)
    });

    result && has_seen_message_from_party_1 && has_seen_message_from_party_2
}

#[hax_lib::exclude]
#[hax_lib::requires(parties.len() > 0
                    && secret < field().p
                    )]
fn parties_get_right_secret(parties: Vec<Party>, secret: Int) -> bool{
    let result = parties.iter().fold(true, |acc, party| {party.computed_secret == secret && acc});

    result
}
