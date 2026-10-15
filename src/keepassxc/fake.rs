//! A fake KeePassXC listening on a temporary Unix socket, for tests.
//!
//! The fake does the real NaCl handshake and encryption, so tests cover the
//! wire protocol without a running KeePassXC. Behavior of the real thing
//! (error codes, dialogs, matching) is checked manually, see
//! `docs/testing.md`.

use std::io::{BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread::{self, JoinHandle};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use crypto_box::aead::{Aead, OsRng};
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use serde_json::{Value, json};

/// The server side of one connection.
pub struct Fake {
    stream: BufReader<UnixStream>,
    salsa: Option<SalsaBox>,
    /// The client's session public key, known after `handshake`.
    pub client_public: Option<PublicKey>,
}

impl Fake {
    pub fn read(&mut self) -> Value {
        serde_json::Deserializer::from_reader(&mut self.stream)
            .into_iter::<Value>()
            .next()
            .expect("client closed the connection")
            .expect("client sent invalid JSON")
    }

    pub fn send(&mut self, value: Value) {
        let bytes = serde_json::to_vec(&value).unwrap();
        self.stream.get_mut().write_all(&bytes).unwrap();
    }

    /// Answers `change-public-keys` like KeePassXC does.
    pub fn handshake(&mut self) {
        let request = self.read();
        assert_eq!(request["action"], "change-public-keys");
        let client_public = public_key(request["publicKey"].as_str().unwrap());
        let secret = SecretKey::generate(&mut OsRng);
        self.send(json!({
            "action": "change-public-keys",
            "version": "2.7.12",
            "publicKey": B64.encode(secret.public_key().as_bytes()),
            "success": "true",
        }));
        self.salsa = Some(SalsaBox::new(&client_public, &secret));
        self.client_public = Some(client_public);
    }

    /// Reads one encrypted request, returning its nonce and decrypted body.
    pub fn read_encrypted(&mut self) -> (Nonce, Value) {
        let request = self.read();
        let nonce = nonce(request["nonce"].as_str().unwrap());
        let ciphertext = B64.decode(request["message"].as_str().unwrap()).unwrap();
        let plaintext = self
            .salsa
            .as_ref()
            .unwrap()
            .decrypt(&nonce, ciphertext.as_slice())
            .unwrap();
        (nonce, serde_json::from_slice(&plaintext).unwrap())
    }

    /// Answers with `request_nonce + 1`, as KeePassXC does.
    pub fn reply(&mut self, action: &str, request_nonce: &Nonce, body: Value) {
        self.reply_with_nonce(action, incremented(request_nonce), body);
    }

    pub fn reply_with_nonce(&mut self, action: &str, nonce: Nonce, body: Value) {
        let plaintext = serde_json::to_vec(&body).unwrap();
        let ciphertext = self
            .salsa
            .as_ref()
            .unwrap()
            .encrypt(&nonce, plaintext.as_slice())
            .unwrap();
        self.send(json!({
            "action": action,
            "message": B64.encode(ciphertext),
            "nonce": B64.encode(nonce),
        }));
    }
}

/// Starts a fake KeePassXC that runs `script` for the first connection.
/// Join the handle at the end of the test so assertions in the script fail it.
pub fn serve(
    script: impl FnOnce(&mut Fake) + Send + 'static,
) -> (tempfile::TempDir, PathBuf, JoinHandle<()>) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("socket");
    let listener = UnixListener::bind(&path).unwrap();
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut fake = Fake {
            stream: BufReader::new(stream),
            salsa: None,
            client_public: None,
        };
        script(&mut fake);
    });
    (dir, path, handle)
}

fn public_key(encoded: &str) -> PublicKey {
    let bytes: [u8; 32] = B64.decode(encoded).unwrap().try_into().unwrap();
    PublicKey::from(bytes)
}

fn nonce(encoded: &str) -> Nonce {
    *Nonce::from_slice(&B64.decode(encoded).unwrap())
}

/// Deliberately written out again here instead of shared with the client, so
/// the two implementations check each other.
fn incremented(nonce: &Nonce) -> Nonce {
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

/// An unencrypted error response, as KeePassXC sends for failed requests.
pub fn error_response(action: &str, code: &str, message: &str) -> Value {
    json!({ "action": action, "error": message, "errorCode": code })
}
