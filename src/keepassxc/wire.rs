//! The messages on the socket: reading responses, decoding keys and nonces,
//! and turning error responses into [`Error`].

use std::io::{BufReader, Write};
use std::os::unix::net::UnixStream;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use crypto_box::{Nonce, PublicKey};
use serde_json::Value;

use super::error::{Error, Result};

/// Writes `request` and reads until the response to `action` arrives.
///
/// KeePassXC also pushes unsolicited signals (`database-locked`,
/// `database-unlocked`); those are skipped. An unencrypted `error` response
/// becomes `Error::Remote`.
///
/// The socket carries bare JSON objects with no length prefix, so responses
/// are read with serde_json's streaming deserializer (checked against
/// KeePassXC 2.7.12).
pub(super) fn exchange(
    stream: &mut BufReader<UnixStream>,
    action: &str,
    request: &Value,
) -> Result<Value> {
    stream.get_mut().write_all(&serde_json::to_vec(request)?)?;
    loop {
        let next = serde_json::Deserializer::from_reader(&mut *stream)
            .into_iter::<Value>()
            .next();
        let response = match next {
            Some(value) => value?,
            None => return Err(Error::Protocol("KeePassXC closed the connection".into())),
        };
        if response.get("error").is_some() {
            return Err(remote_error(&response));
        }
        if response.get("action").and_then(Value::as_str) == Some(action) {
            return Ok(response);
        }
    }
}

pub(super) fn check_inner_error(inner: &Value) -> Result<()> {
    if inner.get("error").is_some() || inner.get("success").and_then(Value::as_str) == Some("false")
    {
        return Err(remote_error(inner));
    }
    Ok(())
}

pub(super) fn remote_error(value: &Value) -> Error {
    let text = |key: &str| match value.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    };
    Error::Remote {
        code: text("errorCode"),
        message: text("error"),
    }
}

pub(super) fn str_field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol(format!("missing string field `{key}`")))
}

pub(super) fn decode_public_key(encoded: &str) -> Result<PublicKey> {
    let bytes: [u8; 32] = B64
        .decode(encoded)?
        .try_into()
        .map_err(|_| Error::Protocol("public key is not 32 bytes".into()))?;
    Ok(PublicKey::from(bytes))
}

pub(super) fn decode_nonce(encoded: &str) -> Result<Nonce> {
    let bytes = B64.decode(encoded)?;
    if bytes.len() != 24 {
        return Err(Error::Protocol("nonce is not 24 bytes".into()));
    }
    Ok(*Nonce::from_slice(&bytes))
}

/// libsodium's `sodium_increment`: little-endian +1 with carry. KeePassXC
/// answers with the request nonce incremented this way.
pub(super) fn incremented(nonce: &Nonce) -> Nonce {
    let mut bytes = *nonce;
    for byte in bytes.iter_mut() {
        let (value, carry) = byte.overflowing_add(1);
        *byte = value;
        if !carry {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn increment_wraps_around_at_the_end() {
        let result = incremented(Nonce::from_slice(&[0xff; 24]));
        assert_eq!(result.as_slice(), [0u8; 24]);
    }

    #[test]
    fn decoding_rejects_wrong_lengths() {
        let short = B64.encode([0u8; 31]);
        assert!(matches!(decode_public_key(&short), Err(Error::Protocol(_))));
        assert!(matches!(decode_nonce(&short), Err(Error::Protocol(_))));
        assert!(matches!(
            decode_public_key("not base64!"),
            Err(Error::Base64(_))
        ));
    }

    #[test]
    fn remote_errors_keep_numeric_codes_and_missing_fields() {
        let Error::Remote { code, message } =
            remote_error(&json!({ "errorCode": 15, "error": "No logins found" }))
        else {
            panic!("not a remote error");
        };
        assert_eq!((code.as_str(), message.as_str()), ("15", "No logins found"));

        let Error::Remote { code, message } = remote_error(&json!({})) else {
            panic!("not a remote error");
        };
        assert_eq!((code.as_str(), message.as_str()), ("", ""));
    }

    #[test]
    fn inner_error_is_detected_by_error_field_or_failed_success() {
        assert!(check_inner_error(&json!({ "success": "true" })).is_ok());
        assert!(check_inner_error(&json!({ "error": "x", "errorCode": "1" })).is_err());
        assert!(check_inner_error(&json!({ "success": "false" })).is_err());
    }

    #[test]
    fn increment_carries_little_endian() {
        let mut bytes = [0u8; 24];
        bytes[0] = 0xff;
        let result = incremented(Nonce::from_slice(&bytes));
        assert_eq!(result[0], 0);
        assert_eq!(result[1], 1);
        assert_eq!(result[2], 0);
    }
}
