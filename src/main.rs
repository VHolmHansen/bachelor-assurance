#[derive(Clone, Debug)]
struct Party {
    secret: i64,
    computed_secret: i64,
}

#[hax_lib::requires(true)]
fn main() {
    let secret = 25;
    hax_lib::assert!(secret % 5 == 0);
    request_mpc(secret);
}


// 5 parties with respective states
// each party has

fn request_mpc(secret: i64) {
    let secrets = split_secret(secret);
    let parties = secrets.into_iter().map(|x| create_party(x)).collect::<Vec<_>>();
    perform_mpc(parties);
}

#[hax_lib::requires(secret % 5 == 0)]
fn split_secret(secret: i64) -> [i64; 5] {
    [secret/5, secret/5,secret/5,secret/5,secret/5]
}

fn create_party(secret_share: i64) -> Party {
    let party: Party = Party {secret: secret_share, computed_secret: 0};
    println!("secret: {}", secret_share);
    party
}

fn perform_mpc(parties: Vec<Party>) -> Vec<Party>{
    let resulting_parties = parties.iter().fold(parties.clone(),
                                               |acc, party|
                                                   {println!("{:?}", acc); update_secret(party, acc)});
    resulting_parties
}

fn update_secret(x: &Party, parties: Vec<Party>) -> Vec<Party> {
    let new_secret = parties.into_iter().map(|y| Party{secret: y.secret, computed_secret: y.computed_secret + x.secret}).collect::<Vec<_>>();
    new_secret
}