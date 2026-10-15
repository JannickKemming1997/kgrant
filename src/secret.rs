use std::fmt;

/// A secret in KeePassXC: one field of one entry. It holds no value
/// only where to find it. Several secrets can be
/// fields of the same entry, which `kgrant` then reads with one request.
///
/// `entry` is the form of the entry's name that goes in its URL
/// (`kgrant://<entry>`), see [`entry_slug`]; `field` is the name of the field in
/// KeePassXC without its `KPH: ` prefix, as it is.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Secret {
    /// The entry, as in its URL.
    pub entry: String,
    /// The field, without the `KPH: ` prefix.
    pub field: String,
}

/// Why a secret reference is not valid.
#[derive(Debug, PartialEq, Eq)]
pub enum SecretError {
    /// The name of the entry has no letters or digits, so nothing is left of it.
    EmptyEntry(String),
    /// The name of the field is empty.
    EmptyField,
}

impl fmt::Display for SecretError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretError::EmptyEntry(name) => write!(
                f,
                "the entry name {name:?} has no letters or digits to make a URL from"
            ),
            SecretError::EmptyField => write!(f, "the field name is empty"),
        }
    }
}

impl std::error::Error for SecretError {}

impl Secret {
    /// For names written in the code: panics if they are not valid, which the
    /// tests find. Use [`Secret::parse`] for what a user typed.
    #[must_use]
    pub fn new(entry: &str, field: &str) -> Secret {
        Secret::parse(entry, field).unwrap_or_else(|e| panic!("{e}"))
    }

    /// The entry name in any form (`AWS Keys`, `aws-keys`) and the field name.
    pub fn parse(entry: &str, field: &str) -> Result<Secret, SecretError> {
        let slug = entry_slug(entry);
        if slug.is_empty() {
            return Err(SecretError::EmptyEntry(entry.to_owned()));
        }
        if field.is_empty() {
            return Err(SecretError::EmptyField);
        }
        Ok(Secret {
            entry: slug,
            field: field.to_owned(),
        })
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {}", self.entry, self.field)
    }
}

/// The name of an entry as it is in its URL: lower case, and every run of
/// characters that are not letters or digits (spaces, `/`, `&`, `-`, `_`, ...)
/// becomes one `-`, with none at the start or the end. `Test / Mine & your
/// entry` gives `test-mine-your-entry`, `Multi-Field` gives `multi-field`.
/// Letters of any script stay (`Müller` gives `müller`).
#[must_use]
pub fn entry_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut pending_separator = false;
    for c in name.chars() {
        if c.is_alphanumeric() {
            if pending_separator && !slug.is_empty() {
                slug.push('-');
            }
            pending_separator = false;
            slug.extend(c.to_lowercase());
        } else {
            pending_separator = true;
        }
    }
    slug
}
