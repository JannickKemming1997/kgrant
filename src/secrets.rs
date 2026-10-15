//! Where secrets come from, and how they are read from KeePassXC.
//!
//! A secret is a field of an entry: the entry is found by its URL
//! `kgrant://<entry>`, the field is a custom field named `KPH: <field>`. All
//! fields wanted from one entry come with one request, so KeePassXC asks for
//! one confirmation per entry and not per field.

use crate::Result;
use crate::secret::Secret;

mod connection;
mod lookup;
mod pairing;
#[cfg(test)]
mod testing;

pub use pairing::pair;

/// Where secrets come from. The commands that need one take a `&dyn Secrets`
/// and do not know where it comes from: KeePassXC in the real `kgrant`
/// ([`KeePassXc`]), fixed values in tests ([`StaticSecrets`]). `main` is the
/// only place that picks.
///
/// Any function or closure from secrets to values is a `Secrets` as well, which
/// is the shortest way to make one for a test. (A closure given as `&dyn
/// Secrets` needs the type of its argument written: `|secrets: &[Secret]| ...`.)
pub trait Secrets {
    /// The values of these secrets, in the same order. Fails on the first that
    /// cannot be read. Secrets of the same entry should be asked for together:
    /// that is one request, and one confirmation in KeePassXC.
    fn read_many(&self, secrets: &[Secret]) -> Result<Vec<String>>;

    /// One secret.
    fn read(&self, secret: &Secret) -> Result<String> {
        self.read_many(std::slice::from_ref(secret))?
            .into_iter()
            .next()
            .ok_or_else(|| format!("no value for the secret `{secret}`").into())
    }
}

impl<F> Secrets for F
where
    F: Fn(&[Secret]) -> Result<Vec<String>>,
{
    fn read_many(&self, secrets: &[Secret]) -> Result<Vec<String>> {
        self(secrets)
    }
}

/// The real source: the open KeePassXC database, over its browser-integration
/// socket.
pub struct KeePassXc;

impl Secrets for KeePassXc {
    fn read_many(&self, secrets: &[Secret]) -> Result<Vec<String>> {
        lookup::read_from_keepassxc(secrets)
    }
}

/// Fixed secrets, for tests (also those in `tests/`, which is why it is not
/// `cfg(test)`).
#[derive(Default)]
pub struct StaticSecrets {
    secrets: Vec<(Secret, String)>,
}

impl StaticSecrets {
    /// `(entry, field, value)`; the entry in any form, see
    /// [`crate::entry_slug`].
    #[must_use]
    pub fn new<E: AsRef<str>, F: AsRef<str>, V: Into<String>>(
        secrets: impl IntoIterator<Item = (E, F, V)>,
    ) -> StaticSecrets {
        StaticSecrets {
            secrets: secrets
                .into_iter()
                .map(|(entry, field, value)| {
                    (Secret::new(entry.as_ref(), field.as_ref()), value.into())
                })
                .collect(),
        }
    }
}

impl Secrets for StaticSecrets {
    fn read_many(&self, secrets: &[Secret]) -> Result<Vec<String>> {
        secrets
            .iter()
            .map(|secret| {
                self.secrets
                    .iter()
                    .find(|(known, _)| known == secret)
                    .map(|(_, value)| value.clone())
                    .ok_or_else(|| format!("no secret `{secret}`").into())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::testing::secret;
    use super::*;

    #[test]
    fn static_secrets_answer_in_the_order_asked() {
        let secrets = StaticSecrets::new([("a", "x", "1"), ("b", "y", "2")]);
        assert_eq!(
            secrets
                .read_many(&[secret("b", "y"), secret("a", "x")])
                .unwrap(),
            ["2", "1"]
        );
        assert_eq!(secrets.read(&secret("a", "x")).unwrap(), "1");
        assert!(secrets.read_many(&[]).unwrap().is_empty());
        // The entry may be written in any form.
        assert_eq!(secrets.read(&secret("A", "x")).unwrap(), "1");
    }

    #[test]
    fn static_secrets_name_the_one_that_is_missing() {
        let secrets = StaticSecrets::new([("a", "x", "1")]);
        let error = secrets
            .read_many(&[secret("a", "x"), secret("a", "nope")])
            .unwrap_err()
            .to_string();
        assert_eq!(error, "no secret `a / nope`");
    }

    #[test]
    fn a_closure_is_a_source_of_secrets() {
        let secrets = |secrets: &[Secret]| -> Result<Vec<String>> {
            Ok(secrets.iter().map(|s| s.field.to_uppercase()).collect())
        };
        let secrets: &dyn Secrets = &secrets;
        assert_eq!(secrets.read(&secret("e", "abc")).unwrap(), "ABC");
        assert_eq!(
            secrets
                .read_many(&[secret("e", "a"), secret("e", "b")])
                .unwrap(),
            ["A", "B"]
        );
    }
}
