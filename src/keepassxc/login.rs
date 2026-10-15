use std::fmt;

use serde::Deserialize;

/// What a custom field of an entry has to start with to be returned by
/// `get-logins` (as `stringFields`), if the setting "Return also advanced
/// string fields which start with \"KPH: \"" is on in KeePassXC's
/// browser-integration settings.
pub const FIELD_PREFIX: &str = "KPH: ";

/// One entry returned by `get-logins`.
#[derive(Clone, Deserialize)]
pub struct Login {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub uuid: String,
    /// The fields that start with [`FIELD_PREFIX`], as `(name, value)` with the
    /// whole name, prefix included. The wire format is a list of objects with
    /// one field each.
    #[serde(default, rename = "stringFields", deserialize_with = "string_fields")]
    pub string_fields: Vec<(String, String)>,
}

impl Login {
    /// The value of the field `KPH: <name>`. The name is matched exactly.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.string_fields
            .iter()
            .find(|(key, _)| key.strip_prefix(FIELD_PREFIX) == Some(name))
            .map(|(_, value)| value.as_str())
    }

    /// The names of the fields that start with the prefix, without it.
    pub fn field_names(&self) -> Vec<&str> {
        self.string_fields
            .iter()
            .filter_map(|(key, _)| key.strip_prefix(FIELD_PREFIX))
            .collect()
    }
}

/// `[{"KPH: a": "1"}, {"KPH: b": "2"}]` as `[("KPH: a", "1"), ("KPH: b", "2")]`.
fn string_fields<'de, D>(deserializer: D) -> std::result::Result<Vec<(String, String)>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let objects = Vec::<std::collections::BTreeMap<String, String>>::deserialize(deserializer)?;
    Ok(objects.into_iter().flatten().collect())
}

impl fmt::Debug for Login {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Login")
            .field("name", &self.name)
            .field("uuid", &self.uuid)
            .field("string_fields", &self.field_names())
            .finish_non_exhaustive()
    }
}
