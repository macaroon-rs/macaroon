use macaroon::Macaroon;

pub type VerifierCallback = fn(&str) -> bool;

pub struct Verifier {
    predicates: Vec<String>,
    callbacks: Vec<VerifierCallback>,
}

impl Verifier {
    pub fn new() -> Verifier {
        Verifier {
            predicates: Vec::new(),
            callbacks: Vec::new(),
        }
    }

    pub fn satisfy_exact(&mut self, predicate: &str) {
        self.predicates.push(String::from(predicate));
    }

    pub fn satisfy_general(&mut self, callback: VerifierCallback) {
        self.callbacks.push(callback);
    }

    pub fn verify_predicate(&self, predicate: &str) -> bool {
        let mut count = self.predicates.iter().filter(|&p| p == predicate).count();
        if count > 0 {
            return true;
        }

        count = self.callbacks.iter().filter(|&callback| callback(predicate)).count();
        if count > 0 {
            return true;
        }

        false
    }

    pub fn verify_discharge_macaroon(&self,
                                     macaroon: &Macaroon,
                                     discharge_macaroons: &Vec<Macaroon>,
                                     id_chain: &mut Vec<String>)
                                     -> bool {
        match discharge_macaroons.iter().find(|&dm| macaroon == dm) {
            Some(dm) => {
                if id_chain.iter().any(|id| id == macaroon.get_identifier()) {
                    return false;
                }
                id_chain.push(macaroon.get_identifier().clone());
                dm.verify_caveats(self, discharge_macaroons, id_chain)
            }
            None => false,
        }
    }

    pub fn verify(&self,
                  macaroon: &Macaroon,
                  key: &[u8],
                  discharge_macaroons: &Vec<Macaroon>)
                  -> bool {
        if !macaroon.verify_signature(key) {
            return false;
        }
        if discharge_macaroons.iter().any(|ref dm| !dm.verify_signature(key)) {
            return false;
        }
        macaroon.verify_caveats(self, discharge_macaroons, &mut Vec::new())
    }

    pub fn verify_caveat(&self,
                         id: &str,
                         discharge_macaroons: &Vec<Macaroon>,
                         id_chain: &mut Vec<String>)
                         -> bool {
        let dm_opt = discharge_macaroons.iter().find(|dm| dm.get_identifier() == id);
        match dm_opt {
            Some(dm) => self.verify_discharge_macaroon(dm, discharge_macaroons, id_chain),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate time;

    use macaroon::Macaroon;
    use super::Verifier;

    #[test]
    fn test_simple_macaroon() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let verifier = Verifier::new();
        assert!(verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }

    #[test]
    fn test_simple_macaroon_bad_verifier_key() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let verifier = Verifier::new();
        assert!(!verifier.verify(&macaroon, "this is not the key".as_bytes(), &Vec::new()));
    }

    #[test]
    fn test_simple_macaroon_exact_caveat() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        assert!(verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }

    #[test]
    fn test_simple_macaroon_exact_caveat_wrong_verifier() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 0000000000");
        assert!(!verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }

    #[test]
    fn test_simple_macaroon_exact_caveat_wrong_context() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let verifier = Verifier::new();
        assert!(!verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }

    #[test]
    fn test_simple_macaroon_two_exact_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        assert!(verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }

    #[test]
    fn test_simple_macaroon_two_exact_caveats_incomplete_verifier() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        assert!(!verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("user = alice");
        assert!(!verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }

    fn after_time_verifier(caveat: &str) -> bool {
        println!("after_time_verifier, caveat = {:?}", caveat);
        if !caveat.starts_with("time > ") {
            println!("returning false");
            return false;
        }

        match time::strptime(&caveat[7..], "%Y-%m-%dT%H:%M") {
            Ok(compare) => {
                println!("{:?}", compare);
                return time::now() > compare;
            },
            Err(error) => {
                println!("{:?}", error);
                return false;
            },
        }
    }

    #[test]
    fn test_simple_macaroon_two_exact_caveats_and_one_general() {
        let mut macaroon = Macaroon::create("http://example.org/", "this is the key".as_bytes(), "keyid").unwrap();
        macaroon.add_first_party_caveat("account = 3735928559");
        macaroon.add_first_party_caveat("user = alice");
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00");
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.satisfy_general(after_time_verifier);
        assert!(verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()));
    }
}