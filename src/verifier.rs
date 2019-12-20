use caveat;
use crypto;
use ByteString;
use Macaroon;
use Result;

/// Type of callback for `Verifier::satisfy_general()`
pub type VerifierCallback = fn(&ByteString) -> bool;

/// Verifier struct
///
/// Contains all information and maintains all state for the macaroon
/// verification process
#[derive(Default)]
pub struct Verifier {
    predicates: Vec<ByteString>,
    callbacks: Vec<VerifierCallback>,
    discharge_macaroons: Vec<Macaroon>,
    signature: [u8; 32],
    id_chain: Vec<ByteString>,
}

impl Verifier {
    /// Create a new Verifier
    pub fn new() -> Verifier {
        Default::default()
    }

    pub fn reset(&mut self) {
        self.signature = [0; 32];
        self.id_chain.clear();
    }

    /// Predicate to satisfy a caveat by exact string match
    pub fn satisfy_exact(&mut self, predicate: ByteString) {
        self.predicates.push(predicate);
    }

    /// Provides a callback function used to verify a caveat
    pub fn satisfy_general(&mut self, callback: VerifierCallback) {
        self.callbacks.push(callback);
    }

    /// Adds discharge macaroons to the verifier
    pub fn add_discharge_macaroons(&mut self, discharge_macaroons: &[Macaroon]) {
        self.discharge_macaroons
            .extend(discharge_macaroons.to_vec());
    }

    pub fn set_signature(&mut self, signature: [u8; 32]) {
        self.signature = signature;
    }

    pub fn update_signature<F>(&mut self, generator: F)
    where
        F: Fn(&[u8; 32]) -> [u8; 32],
    {
        self.signature = generator(&self.signature);
    }

    pub fn verify(&mut self, caveat: &caveat::Caveat, macaroon: &Macaroon) -> Result<bool> {
        match caveat {
            caveat::Caveat::FirstParty(fp) => Ok(self.verify_predicate(&fp.predicate())),
            caveat::Caveat::ThirdParty(tp) => self.verify_caveat(tp, macaroon),
        }
    }

    fn verify_predicate(&self, predicate: &ByteString) -> bool {
        let mut count = self.predicates.iter().filter(|&p| p == predicate).count();
        if count > 0 {
            return true;
        }

        count = self
            .callbacks
            .iter()
            .filter(|&callback| callback(predicate))
            .count();
        if count > 0 {
            return true;
        }

        false
    }

    fn verify_caveat(&mut self, caveat: &caveat::ThirdParty, macaroon: &Macaroon) -> Result<bool> {
        let dm = self.discharge_macaroons.clone();
        let dm_opt = dm.iter().find(|dm| dm.identifier() == caveat.id());
        match dm_opt {
            Some(dm) => {
                if self.id_chain.iter().any(|id| id == &dm.identifier()) {
                    info!(
                        "Verifier::verify_caveat: caveat verification loop - id {:?} found in \
                         id chain {:?}",
                        dm.identifier(),
                        self.id_chain
                    );
                    return Ok(false);
                }
                self.id_chain.push(dm.identifier().clone());
                let key = crypto::decrypt(self.signature, &caveat.verifier_id().0)?;
                dm.verify_as_discharge(self, macaroon, key.as_slice())
            }
            None => {
                info!(
                    "Verifier::verify_caveat: No discharge macaroon found matching caveat id \
                     {:?}",
                    caveat.id()
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate time;

    use super::Verifier;
    use crypto;
    use ByteString;
    use Macaroon;

    #[test]
    fn test_simple_macaroon() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_simple_macaroon_bad_verifier_key() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        let key = crypto::generate_derived_key(b"this is not the key");
        assert!(!macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_exact_caveat() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559".into());
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_verifier() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 0000000000".into());
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(!macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_context() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(!macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_caveats_incomplete_verifier() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let macaroon = Macaroon::deserialize(&serialized.as_bytes().to_vec()).unwrap();
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559".into());
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(!macaroon.verify(&key, &mut verifier).unwrap());
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("user = alice".into());
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(!macaroon.verify(&key, &mut verifier).unwrap());
    }

    fn after_time_verifier(caveat: &ByteString) -> bool {
        if !caveat.0.starts_with(b"time > ") {
            return false;
        }
        let strcaveat = match std::str::from_utf8(&caveat.0) {
            Ok(s) => s,
            Err(_) => return false,
        };

        match time::strptime(&strcaveat[7..], "%Y-%m-%dT%H:%M") {
            Ok(compare) => time::now() > compare,
            Err(_) => false,
        }
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_caveat() {
        let mut macaroon =
            Macaroon::create("http://example.org/", b"this is the key", "keyid".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00".into());
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        verifier.satisfy_general(after_time_verifier);
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_fails_general() {
        let mut macaroon =
            Macaroon::create("http://example.org/", b"this is the key", "keyid".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_first_party_caveat("time > 3010-01-01T00:00".into());
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        verifier.satisfy_general(after_time_verifier);
        let key = crypto::generate_derived_key(b"this is the key");
        assert!(!macaroon.verify(&key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_incomplete_verifier() {
        let key = b"this is the key";
        let mut macaroon = Macaroon::create("http://example.org/", key, "keyid".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00".into());
        let mut verifier = Verifier::new();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        assert!(!macaroon.verify(key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_third_party_caveat() {
        let mut macaroon =
            Macaroon::create("http://example.org/", b"this is the key", "keyid".into()).unwrap();
        macaroon.add_third_party_caveat(
            "http://auth.mybank/",
            b"this is another key",
            "other keyid".into(),
        );
        let mut discharge = Macaroon::create(
            "http://auth.mybank/",
            b"this is another key",
            "other keyid".into(),
        )
        .unwrap();
        discharge.add_first_party_caveat("time > 2010-01-01T00:00".into());
        macaroon.bind(&mut discharge);
        let mut verifier = Verifier::new();
        verifier.satisfy_general(after_time_verifier);
        verifier.add_discharge_macaroons(&[discharge]);
        let root_key = crypto::generate_derived_key(b"this is the key");
        assert!(macaroon.verify(&root_key, &mut verifier).unwrap());
    }

    #[test]
    fn test_macaroon_third_party_caveat_with_cycle() {
        let mut macaroon =
            Macaroon::create("http://example.org/", b"this is the key", "keyid".into()).unwrap();
        macaroon.add_third_party_caveat(
            "http://auth.mybank/",
            b"this is another key",
            "other keyid".into(),
        );
        let mut discharge = Macaroon::create(
            "http://auth.mybank/",
            b"this is another key",
            "other keyid".into(),
        )
        .unwrap();
        discharge.add_third_party_caveat(
            "http://auth.mybank/",
            b"this is another key",
            "other keyid".into(),
        );
        macaroon.bind(&mut discharge);
        let mut verifier = Verifier::new();
        verifier.satisfy_general(after_time_verifier);
        verifier.add_discharge_macaroons(&[discharge]);
        let root_key = crypto::generate_derived_key(b"this is the key");
        assert!(!macaroon.verify(&root_key, &mut verifier).unwrap());
    }
}
