//! Helpers shared by the tests of the submodules.

use serde_json::json;

use crate::keepassxc::Association;
use crate::keepassxc::fake::{Fake, error_response};
use crate::{Result, secret::Secret};

pub(super) fn association(id: &str, key: &str) -> Association {
    Association {
        id: id.into(),
        key: key.into(),
    }
}

/// An entry as `get-logins` returns it: the fields given as `(name,
/// value)`, with the `KPH: ` prefix added. The password is a decoy that must
/// never be used.
pub(super) fn entry(title: &str, fields: &[(&str, &str)]) -> serde_json::Value {
    let string_fields: Vec<_> = fields
        .iter()
        .map(|(name, value)| json!({ format!("KPH: {name}"): value }))
        .collect();
    json!({
        "name": title, "login": "", "password": "decoy-password", "uuid": title,
        "stringFields": string_fields,
    })
}

/// Answers one `test-associate`, accepting it or not.
pub(super) fn answer_test_associate(fake: &mut Fake, accept: bool) {
    let (nonce, request) = fake.read_encrypted();
    assert_eq!(request["action"], "test-associate");
    if accept {
        fake.reply("test-associate", &nonce, json!({ "success": "true" }));
    } else {
        fake.send(error_response("test-associate", "8", "association failed"));
    }
}

/// Answers the `get-logins` request for `url` with `entries`.
pub(super) fn answer_get_logins(fake: &mut Fake, url: &str, entries: &[serde_json::Value]) {
    let (nonce, request) = fake.read_encrypted();
    assert_eq!(request["action"], "get-logins");
    assert_eq!(request["url"], url);
    fake.reply(
        "get-logins",
        &nonce,
        json!({ "count": entries.len(), "entries": entries, "success": "true" }),
    );
}

pub(super) fn secret(entry: &str, field: &str) -> Secret {
    Secret::new(entry, field)
}

pub(super) fn error_of<T>(result: Result<T>) -> String {
    result.err().expect("an error").to_string()
}
