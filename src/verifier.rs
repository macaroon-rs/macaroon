use caveat;
use crypto;
use error::MacaroonError;
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
                                     signature: &mut [u8; 32],
                                     discharge_macaroons: &Vec<Macaroon>,
                                     id_chain: &mut Vec<String>)
                                     -> Result<bool, MacaroonError> {
        match discharge_macaroons.iter().find(|&dm| macaroon == dm) {
            Some(dm) => {
                if id_chain.iter().any(|id| id == macaroon.get_identifier()) {
                    return Ok(false);
                }
                id_chain.push(macaroon.get_identifier().clone());
                dm.verify_caveats(self, signature, discharge_macaroons, id_chain)
            }
            None => Ok(false),
        }
    }

    pub fn verify(&self,
                  macaroon: &Macaroon,
                  key: &[u8],
                  discharge_macaroons: &Vec<Macaroon>)
                  -> Result<bool, MacaroonError> {
        if !macaroon.verify_signature(key) {
            return Ok(false);
        }
        let mut signature = crypto::generate_signature(key, macaroon.get_identifier());
        macaroon.verify_caveats(self, &mut signature, discharge_macaroons, &mut Vec::new())
    }

    fn verify_as_discharge(&self,
                           discharge_macaroon: &Macaroon,
                           root_macaroon: &Macaroon,
                           key: &[u8],
                           discharge_macaroons: &Vec<Macaroon>)
                           -> Result<bool, MacaroonError> {
        let mut signature = discharge_macaroon.generate_signature(key);
        if !discharge_macaroon.verify_discharge_signature(root_macaroon, &signature) {
            return Ok(false);
        }
        discharge_macaroon.verify_caveats(self, &mut signature, discharge_macaroons, &mut Vec::new())
    }

    pub fn verify_caveat(&self,
                         caveat: &caveat::ThirdPartyCaveat,
                         macaroon: &Macaroon,
                         signature: &[u8; 32],
                         discharge_macaroons: &Vec<Macaroon>,
                         id_chain: &mut Vec<String>)
                         -> Result<bool, MacaroonError> {
        let dm_opt = discharge_macaroons.iter().find(|dm| *dm.get_identifier() == caveat.get_id());
        match dm_opt {
            Some(dm) => {
                if id_chain.iter().any(|id| id == dm.get_identifier()) {
                    // TODO: Log id chain
                    return Ok(false);
                }
                id_chain.push(dm.get_identifier().clone());
                let key = crypto::decrypt(*signature, &caveat.get_verifier_id().as_slice())?;
                self.verify_as_discharge(dm, macaroon, key.as_slice(), discharge_macaroons)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate time;

    use crypto;
    use macaroon::Macaroon;
    use super::Verifier;

    #[test]
    fn test_simple_macaroon() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let verifier = Verifier::new();
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_simple_macaroon_bad_verifier_key() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let verifier = Verifier::new();
        let key = crypto::generate_derived_key("this is not the key".as_bytes());
        assert!(!verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_exact_caveat() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_verifier() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 0000000000");
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(!verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_context() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let verifier = Verifier::new();
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(!verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_caveats_incomplete_verifier() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(!verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("user = alice");
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(!verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    fn after_time_verifier(caveat: &str) -> bool {
        if !caveat.starts_with("time > ") {
            return false;
        }

        match time::strptime(&caveat[7..], "%Y-%m-%dT%H:%M") {
            Ok(compare) => {
                return time::now() > compare;
            }
            Err(_) => {
                return false;
            }
        }
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_caveat() {
        let mut macaroon =
            Macaroon::create("http://example.org/", "this is the key".as_bytes(), "keyid").unwrap();
        macaroon.add_first_party_caveat("account = 3735928559");
        macaroon.add_first_party_caveat("user = alice");
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00");
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.satisfy_general(after_time_verifier);
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_fails_general() {
        let mut macaroon =
            Macaroon::create("http://example.org/", "this is the key".as_bytes(), "keyid").unwrap();
        macaroon.add_first_party_caveat("account = 3735928559");
        macaroon.add_first_party_caveat("user = alice");
        macaroon.add_first_party_caveat("time > 3010-01-01T00:00");
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        verifier.satisfy_general(after_time_verifier);
        let key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(!verifier.verify(&macaroon, &key, &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_incomplete_verifier() {
        let mut macaroon =
            Macaroon::create("http://example.org/", "this is the key".as_bytes(), "keyid").unwrap();
        macaroon.add_first_party_caveat("account = 3735928559");
        macaroon.add_first_party_caveat("user = alice");
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00");
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559");
        verifier.satisfy_exact("user = alice");
        assert!(!verifier.verify(&macaroon, "this is the key".as_bytes(), &Vec::new()).unwrap());
    }

    #[test]
    fn test_macaroon_third_party_caveat() {
        let mut macaroon =
            Macaroon::create("http://example.org/", "this is the key".as_bytes(), "keyid").unwrap();
        macaroon.add_third_party_caveat("http://auth.mybank/",
                                        "this is another key".as_bytes(),
                                        "other keyid");
        let mut discharge = Macaroon::create("http://auth.mybank/",
                                             "this is another key".as_bytes(),
                                             "other keyid")
            .unwrap();
        discharge.add_first_party_caveat("time > 2010-01-01T00:00");
        macaroon.prepare_for_request(&mut discharge);
        let mut verifier = Verifier::new();
        verifier.satisfy_general(after_time_verifier);
        let root_key = crypto::generate_derived_key("this is the key".as_bytes());
        assert!(verifier.verify(&macaroon, &root_key, &vec![discharge]).unwrap());
    }
}