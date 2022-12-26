use crate::crypto;
use crate::{ByteString, Caveat, Macaroon, MacaroonError, MacaroonKey, Result};
use std::collections::BTreeSet;
use std::collections::HashMap;

pub type VerifyFunc = fn(&ByteString) -> bool;

#[derive(Default)]
pub struct Verifier {
    exact: BTreeSet<ByteString>,
    general: Vec<VerifyFunc>,
}

impl Verifier {
    pub fn verify(&self, m: &Macaroon, key: &MacaroonKey, discharges: Vec<Macaroon>) -> Result<()> {
        let mut discharge_set = discharges
            .iter()
            .map(|d| (d.identifier.clone(), d.clone()))
            .collect::<HashMap<ByteString, Macaroon>>();
        self.verify_with_sig(&m.signature, m, key, &mut discharge_set)?;
        // Now check that all discharges were used
        if !discharge_set.is_empty() {
            return Err(MacaroonError::DischargeNotUsed);
        }
        Ok(())
    }

    fn verify_with_sig(
        &self,
        root_sig: &MacaroonKey,
        m: &Macaroon,
        key: &MacaroonKey,
        discharge_set: &mut HashMap<ByteString, Macaroon>,
    ) -> Result<()> {
        let mut sig = crypto::key::hmac(key, &m.identifier());
        for c in m.caveats() {
            sig = match &c {
                Caveat::ThirdParty(tp) => {
                    let caveat_key = crypto::key::decrypt_key(&sig, &tp.verifier_id().0)?;
                    let dm = discharge_set.remove(&tp.id()).ok_or_else(|| MacaroonError::CaveatNotSatisfied("no discharge macaroon found (or discharge has already been used) for third-party caveat".to_string()))?;
                    self.verify_with_sig(root_sig, &dm, &caveat_key, discharge_set)?;
                    c.sign(&sig)
                }
                Caveat::FirstParty(fp) => {
                    // This checks exact caveats first and then general second
                    // if it fails due to logic short circuiting
                    if !(self.exact.contains(&fp.predicate())
                        || self.verify_general(&fp.predicate()))
                    {
                        // If both failed, it means we weren't successful at either
                        return Err(MacaroonError::CaveatNotSatisfied(format!(
                            "first party caveat not satisfied: {}",
                            String::from_utf8_lossy(fp.predicate().as_ref())
                        )));
                    }
                    c.sign(&sig)
                }
            };
        }
        // If the root sig equals the newly generated sig, that means we reached
        // the end of the line and we are ok to return
        if root_sig == &sig {
            return Ok(());
        }
        // Check the bound signature equals the signature of the discharge
        // macaroon
        let zero_key: MacaroonKey = [0; 32].into();
        let bound_sig = crypto::key::hmac2(&zero_key, &ByteString(root_sig.to_vec()), &sig.into());
        if bound_sig != m.signature {
            return Err(MacaroonError::InvalidSignature);
        }
        Ok(())
    }

    pub fn satisfy_exact(&mut self, b: ByteString) {
        self.exact.insert(b);
    }

    pub fn satisfy_general(&mut self, f: VerifyFunc) {
        self.general.push(f)
    }

    fn verify_general(&self, value: &ByteString) -> bool {
        for f in self.general.iter() {
            if f(value) {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Verifier;
    use crate::{ByteString, Macaroon, MacaroonError, MacaroonKey};

    #[test]
    fn test_simple_macaroon() {
        let key = MacaroonKey::generate(b"this is the key");
        let macaroon = Macaroon::create(None, &key, "testing".into()).unwrap();
        let verifier = Verifier::default();
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap();
    }

    #[test]
    fn test_simple_macaroon_bad_verifier_key() {
        let macaroon =
            Macaroon::create(None, &MacaroonKey::generate(b"key"), "testing".into()).unwrap();
        let key = MacaroonKey::generate(b"this is not the key");
        let verifier = Verifier::default();
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_exact_caveat() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap()
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_verifier() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 0000000000".into());
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_exact_caveat_wrong_context() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        let verifier = Verifier::default();
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_two_exact_caveats() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap()
    }

    #[test]
    fn test_macaroon_two_exact_caveats_incomplete_verifier() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon = Macaroon::create(None, &key, "testing".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("user = alice".into());
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
    }

    fn after_time_verifier(caveat: &ByteString) -> bool {
        if !caveat.0.starts_with(b"time > ") {
            return false;
        }
        let strcaveat = match std::str::from_utf8(&caveat.0) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let format = time::format_description::parse(
            "[year]-[month]-[day]T[hour]:[minute][offset_hour sign:mandatory][offset_minute]",
        )
        .unwrap();
        match time::OffsetDateTime::parse(&strcaveat[7..], &format) {
            Ok(compare) => time::OffsetDateTime::now_utc() > compare,
            Err(_) => false,
        }
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_caveat() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/".into()), &key, "keyid".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00+0000".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        verifier.satisfy_general(after_time_verifier);
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap()
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_fails_general() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/".into()), &key, "keyid".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_first_party_caveat("time > 3010-01-01T00:00+0000".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        verifier.satisfy_general(after_time_verifier);
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_two_exact_and_one_general_incomplete_verifier() {
        let key = MacaroonKey::generate(b"this is the key");
        let mut macaroon =
            Macaroon::create(Some("http://example.org/".into()), &key, "keyid".into()).unwrap();
        macaroon.add_first_party_caveat("account = 3735928559".into());
        macaroon.add_first_party_caveat("user = alice".into());
        macaroon.add_first_party_caveat("time > 2010-01-01T00:00+0000".into());
        let mut verifier = Verifier::default();
        verifier.satisfy_exact("account = 3735928559".into());
        verifier.satisfy_exact("user = alice".into());
        verifier
            .verify(&macaroon, &key, Default::default())
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_third_party_caveat() {
        let root_key = MacaroonKey::generate(b"this is the key");
        let another_key = MacaroonKey::generate(b"this is another key");
        let mut macaroon = Macaroon::create(
            Some("http://example.org/".into()),
            &root_key,
            "keyid".into(),
        )
        .unwrap();
        macaroon.add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid".into());
        let mut discharge = Macaroon::create(
            Some("http://auth.mybank/".into()),
            &another_key,
            "other keyid".into(),
        )
        .unwrap();
        discharge.add_first_party_caveat("time > 2010-01-01T00:00+0000".into());
        macaroon.bind(&mut discharge);
        let mut verifier = Verifier::default();
        verifier.satisfy_general(after_time_verifier);
        verifier
            .verify(&macaroon, &root_key, vec![discharge])
            .unwrap()
    }

    #[test]
    fn test_macaroon_third_party_caveat_with_cycle() {
        let root_key = MacaroonKey::generate(b"this is the key");
        let another_key = MacaroonKey::generate(b"this is another key");
        let mut macaroon = Macaroon::create(
            Some("http://example.org/".into()),
            &root_key,
            "keyid".into(),
        )
        .unwrap();
        macaroon.add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid".into());
        let mut discharge = Macaroon::create(
            Some("http://auth.mybank/".into()),
            &another_key,
            "other keyid".into(),
        )
        .unwrap();
        discharge.add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid".into());
        macaroon.bind(&mut discharge);
        let mut verifier = Verifier::default();
        verifier.satisfy_general(after_time_verifier);
        verifier
            .verify(&macaroon, &root_key, vec![discharge])
            .unwrap_err();
    }

    #[test]
    fn test_macaroon_third_party_unsatisfied() {
        let root_key = MacaroonKey::generate(b"this is the key");
        let another_key = MacaroonKey::generate(b"this is another key");
        let mut macaroon = Macaroon::create(
            Some("http://example.org/".into()),
            &root_key,
            "keyid".into(),
        )
        .unwrap();

        // with no caveats, should verify fine
        let verifier = Verifier::default();
        verifier.verify(&macaroon, &root_key, vec![]).unwrap();

        // add a third party caveat but no satisfier, should fail
        macaroon.add_third_party_caveat("http://auth.mybank/", &another_key, "other keyid".into());
        assert!(matches!(
            verifier.verify(&macaroon, &root_key, vec![]),
            Err(MacaroonError::CaveatNotSatisfied(_))
        ));
    }
}
