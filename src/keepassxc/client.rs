use std::fmt;
use std::io::{self, BufReader};
use std::os::unix::net::UnixStream;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::error::{Error, Result};
use super::login::Login;
use super::wire::{
    check_inner_error, decode_nonce, decode_public_key, exchange, incremented, str_field,
};

/// What a client must persist after pairing with a database: the `id`
/// KeePassXC assigned and the identification public key. The key acts as a
/// bearer token, so its `Debug` output is redacted.
#[derive(Clone, Serialize, Deserialize)]
pub struct Association {
    pub id: String,
    pub key: String,
}

impl fmt::Debug for Association {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Association")
            .field("id", &self.id)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// An encrypted session with KeePassXC.
///
/// A fresh session keypair is generated per connection; `salsa` holds the
/// shared key derived from it and KeePassXC's session public key.
pub struct Client {
    stream: BufReader<UnixStream>,
    client_id: String,
    session_public: PublicKey,
    salsa: SalsaBox,
}

impl Client {
    /// Connects and exchanges session keys (`change-public-keys`).
    pub fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => Error::SocketNotFound(path.to_owned()),
            _ => Error::Connect(e),
        })?;

        let secret = SecretKey::generate(&mut OsRng);
        let session_public = secret.public_key();
        let client_id = B64.encode(SalsaBox::generate_nonce(&mut OsRng));

        let mut stream = BufReader::new(stream);
        let request = json!({
            "action": "change-public-keys",
            "publicKey": B64.encode(session_public.as_bytes()),
            "nonce": B64.encode(SalsaBox::generate_nonce(&mut OsRng)),
            "clientID": client_id,
        });
        let response = exchange(&mut stream, "change-public-keys", &request)?;
        let host_public = decode_public_key(str_field(&response, "publicKey")?)?;

        Ok(Self {
            stream,
            client_id,
            session_public,
            salsa: SalsaBox::new(&host_public, &secret),
        })
    }

    /// Sends an encrypted request and returns the decrypted inner response.
    ///
    /// `inner` is the unencrypted message from the protocol document. Only the
    /// typed methods below use it; new protocol actions get their own method.
    fn request(&mut self, action: &str, inner: &Value) -> Result<Value> {
        let nonce = SalsaBox::generate_nonce(&mut OsRng);
        let plaintext = serde_json::to_vec(inner)?;
        let ciphertext = self
            .salsa
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| Error::Crypto)?;

        let request = json!({
            "action": action,
            "message": B64.encode(ciphertext),
            "nonce": B64.encode(nonce),
            "clientID": self.client_id,
        });
        let response = exchange(&mut self.stream, action, &request)?;

        let response_nonce = decode_nonce(str_field(&response, "nonce")?)?;
        if response_nonce != incremented(&nonce) {
            return Err(Error::Protocol(
                "response nonce is not request nonce + 1".into(),
            ));
        }
        let ciphertext = B64.decode(str_field(&response, "message")?)?;
        let plaintext = self
            .salsa
            .decrypt(&response_nonce, ciphertext.as_slice())
            .map_err(|_| Error::Crypto)?;
        let inner: Value = serde_json::from_slice(&plaintext)?;
        check_inner_error(&inner)?;
        Ok(inner)
    }

    /// Pairs with the open database. KeePassXC asks the user to approve and
    /// name the connection, so this can block for a long time.
    pub fn associate(&mut self) -> Result<Association> {
        // The identification key is only ever sent as a public key, so the
        // secret half is dropped right away.
        let identification = SecretKey::generate(&mut OsRng).public_key();
        let key = B64.encode(identification.as_bytes());
        let inner = json!({
            "action": "associate",
            "key": B64.encode(self.session_public.as_bytes()),
            "idKey": key,
        });
        let response = self.request("associate", &inner)?;
        Ok(Association {
            id: str_field(&response, "id")?.to_owned(),
            key,
        })
    }

    /// Checks that `association` is still valid for the open database.
    pub fn test_associate(&mut self, association: &Association) -> Result<()> {
        let inner = json!({
            "action": "test-associate",
            "id": association.id,
            "key": association.key,
        });
        self.request("test-associate", &inner).map(|_| ())
    }

    /// Entries whose URL matches `url`. Triggers KeePassXC's access checks
    /// and confirmation dialogs.
    ///
    /// `associations` are all the pairings the caller has. KeePassXC searches
    /// the databases that one of them belongs to: only the active database, or
    /// every open one if "search in all opened databases" is enabled in its
    /// browser-integration settings. A connection must already have passed
    /// [`test_associate`](Self::test_associate) against the active database.
    pub fn get_logins(&mut self, url: &str, associations: &[Association]) -> Result<Vec<Login>> {
        let keys: Vec<_> = associations
            .iter()
            .map(|a| json!({ "id": a.id, "key": a.key }))
            .collect();
        let inner = json!({
            "action": "get-logins",
            "url": url,
            "keys": keys,
        });
        let response = self.request("get-logins", &inner)?;
        match response.get("entries") {
            Some(entries) => Ok(serde_json::from_value(entries.clone())?),
            None => Ok(Vec::new()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keepassxc::Login;
    use crate::keepassxc::fake::{error_response, serve};

    #[test]
    fn debug_output_redacts_the_key_and_the_field_values() {
        let association = Association {
            id: "id".into(),
            key: "very-secret-key".into(),
        };
        let login = Login {
            name: "Entry".into(),
            uuid: "abc".into(),
            string_fields: vec![("KPH: Token".into(), "very-secret-field".into())],
        };
        let debug = format!("{association:?} {login:?}");
        assert!(!debug.contains("very-secret"), "{debug}");
        assert!(debug.contains("id") && debug.contains("Entry"), "{debug}");
    }

    fn association() -> Association {
        Association {
            id: "test".into(),
            key: "identification-key".into(),
        }
    }

    #[test]
    fn get_logins_returns_entries_and_skips_signals() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, request) = fake.read_encrypted();
            assert_eq!(request["action"], "get-logins");
            assert_eq!(request["url"], "shared://default");
            assert_eq!(request["keys"][0]["id"], "test");
            assert_eq!(request["keys"][0]["key"], "identification-key");

            // KeePassXC pushes signals that are not a reply to the request.
            fake.send(json!({ "action": "database-unlocked" }));
            fake.reply(
                "get-logins",
                &nonce,
                json!({
                    "count": 1,
                    "entries": [{
                        "group": "Shared", "login": "", "name": "Default",
                        "password": "secret", "stringFields": [], "uuid": "abc",
                    }],
                    "success": "true",
                }),
            );
        });

        let mut client = Client::connect(&path).unwrap();
        let logins = client
            .get_logins("shared://default", &[association()])
            .unwrap();
        assert_eq!(logins.len(), 1);
        assert_eq!(logins[0].name, "Default");
        assert_eq!(logins[0].uuid, "abc");
        server.join().unwrap();
    }

    #[test]
    fn string_fields_are_returned_by_name_without_the_prefix() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            fake.reply(
                "get-logins",
                &nonce,
                json!({
                    "count": 1,
                    "entries": [{
                        "login": "", "name": "Multi-Field", "password": "unused", "uuid": "abc",
                        "stringFields": [
                            { "KPH: Access Key ID": "id" },
                            { "KPH: Secret": "line one\nline two" },
                        ],
                    }],
                    "success": "true",
                }),
            );
        });

        let mut client = Client::connect(&path).unwrap();
        let logins = client
            .get_logins("kgrant://multi-field", &[association()])
            .unwrap();
        let login = &logins[0];
        assert_eq!(login.field("Access Key ID"), Some("id"));
        assert_eq!(login.field("Secret"), Some("line one\nline two"));
        assert_eq!(login.field_names(), ["Access Key ID", "Secret"]);
        // Names are exact, and the prefix is not part of the name.
        assert_eq!(login.field("access key id"), None);
        assert_eq!(login.field("KPH: Secret"), None);
        // The values do not show in the debug output.
        assert!(!format!("{login:?}").contains("line one"));
        server.join().unwrap();
    }

    #[test]
    fn fields_without_the_prefix_are_not_fields() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            fake.reply(
                "get-logins",
                &nonce,
                json!({
                    "count": 1,
                    "entries": [{ "name": "E", "uuid": "abc", "stringFields": [{ "Other": "x" }] }],
                    "success": "true",
                }),
            );
        });
        let mut client = Client::connect(&path).unwrap();
        let logins = client.get_logins("kgrant://e", &[association()]).unwrap();
        assert_eq!(logins[0].field("Other"), None);
        assert!(logins[0].field_names().is_empty());
        server.join().unwrap();
    }

    #[test]
    fn get_logins_sends_every_association() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, request) = fake.read_encrypted();
            // The same name in two databases is fine: the keys differ.
            assert_eq!(request["keys"].as_array().unwrap().len(), 2);
            assert_eq!(request["keys"][0]["id"], "test");
            assert_eq!(request["keys"][0]["key"], "identification-key");
            assert_eq!(request["keys"][1]["id"], "test");
            assert_eq!(request["keys"][1]["key"], "other-key");
            fake.reply(
                "get-logins",
                &nonce,
                json!({ "count": 0, "entries": [], "success": "true" }),
            );
        });

        let mut other = association();
        other.key = "other-key".into();
        let mut client = Client::connect(&path).unwrap();
        let logins = client
            .get_logins("shared://default", &[association(), other])
            .unwrap();
        assert!(logins.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn get_logins_with_empty_list_is_not_an_error() {
        // What KeePassXC sends when the user denies the request.
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            fake.reply(
                "get-logins",
                &nonce,
                json!({ "count": 0, "entries": [], "success": "true" }),
            );
        });

        let mut client = Client::connect(&path).unwrap();
        assert!(
            client
                .get_logins("shared://default", &[association()])
                .unwrap()
                .is_empty()
        );
        server.join().unwrap();
    }

    #[test]
    fn no_logins_error_is_recognized() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            fake.read_encrypted();
            fake.send(error_response("get-logins", "15", "No logins found"));
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client
            .get_logins("shared://nope", &[association()])
            .err()
            .unwrap();
        assert!(error.is_no_logins(), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn locked_database_error_is_recognized() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            fake.read_encrypted();
            fake.send(error_response("test-associate", "1", "Database not opened"));
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client.test_associate(&association()).err().unwrap();
        assert!(error.is_database_locked(), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn association_failure_is_recognized() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            fake.read_encrypted();
            fake.send(error_response(
                "test-associate",
                "8",
                "KeePassXC association failed, try again",
            ));
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client.test_associate(&association()).err().unwrap();
        assert!(error.is_association_failed(), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn associate_sends_both_keys_and_returns_the_assigned_id() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, request) = fake.read_encrypted();
            assert_eq!(request["action"], "associate");
            let session_key = B64.encode(fake.client_public.as_ref().unwrap().as_bytes());
            assert_eq!(request["key"], session_key);
            // A separate, fresh key identifies the client in later sessions.
            assert_ne!(request["idKey"], request["key"]);
            assert_eq!(
                B64.decode(request["idKey"].as_str().unwrap())
                    .unwrap()
                    .len(),
                32
            );

            fake.reply(
                "associate",
                &nonce,
                json!({ "id": "my-pairing", "hash": "h", "success": "true" }),
            );
            // Remember what the client must send later.
            let (nonce, request) = fake.read_encrypted();
            assert_eq!(request["action"], "test-associate");
            assert_eq!(request["id"], "my-pairing");
            fake.reply(
                "test-associate",
                &nonce,
                json!({ "id": "my-pairing", "success": "true" }),
            );
        });

        let mut client = Client::connect(&path).unwrap();
        let association = client.associate().unwrap();
        assert_eq!(association.id, "my-pairing");
        assert_eq!(association.key.len(), 44); // 32 bytes in base64
        client.test_associate(&association).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn response_with_wrong_nonce_is_rejected() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            // The request nonce unchanged, instead of incremented.
            fake.reply_with_nonce("test-associate", nonce, json!({ "success": "true" }));
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client.test_associate(&association()).err().unwrap();
        assert!(matches!(error, Error::Protocol(_)), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn missing_socket_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        match Client::connect(&dir.path().join("nope")) {
            Err(Error::SocketNotFound(_)) => {}
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("connected to a socket that does not exist"),
        }
    }

    #[test]
    fn numeric_error_code_is_recognized() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            fake.read_encrypted();
            fake.send(
                json!({ "action": "get-logins", "error": "No logins found", "errorCode": 15 }),
            );
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client
            .get_logins("shared://nope", &[association()])
            .err()
            .unwrap();
        assert!(error.is_no_logins(), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn failure_inside_the_encrypted_response_is_an_error() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            fake.reply(
                "test-associate",
                &nonce,
                json!({ "success": "false", "error": "denied", "errorCode": "6" }),
            );
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client.test_associate(&association()).err().unwrap();
        assert!(
            matches!(&error, Error::Remote { code, .. } if code == "6"),
            "{error}"
        );
        server.join().unwrap();
    }

    #[test]
    fn closed_connection_is_reported() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            fake.read_encrypted();
            // Return without answering; the socket closes.
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client.test_associate(&association()).err().unwrap();
        assert!(matches!(error, Error::Protocol(_)), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn associate_without_an_id_is_a_protocol_error() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            fake.reply("associate", &nonce, json!({ "success": "true" }));
        });

        let mut client = Client::connect(&path).unwrap();
        let error = client.associate().err().unwrap();
        assert!(matches!(error, Error::Protocol(_)), "{error}");
        server.join().unwrap();
    }

    #[test]
    fn response_without_entries_is_an_empty_list() {
        let (_dir, path, server) = serve(|fake| {
            fake.handshake();
            let (nonce, _) = fake.read_encrypted();
            fake.reply("get-logins", &nonce, json!({ "success": "true" }));
        });

        let mut client = Client::connect(&path).unwrap();
        let logins = client
            .get_logins("shared://default", &[association()])
            .unwrap();
        assert!(logins.is_empty());
        server.join().unwrap();
    }

    #[test]
    fn handshake_with_an_invalid_public_key_is_rejected() {
        let (_dir, path, server) = serve(|fake| {
            fake.read();
            fake.send(json!({
                "action": "change-public-keys",
                "publicKey": B64.encode([0u8; 5]),
                "success": "true",
            }));
        });

        let error = Client::connect(&path).err().unwrap();
        assert!(matches!(error, Error::Protocol(_)), "{error}");
        server.join().unwrap();
    }
}
