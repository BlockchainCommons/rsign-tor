use crate::constants::*;
use crate::crypto::ed25519;
use crate::errors::*;
use crate::helpers::*;
use crate::keynum::*;
use crate::public_key::*;
use crate::secret_key::*;
use base32::{encode, Alphabet};
use getrandom::getrandom;
use sha3::{Digest, Sha3_256};
use std::io::{self, Write};
use std::u64;
extern crate data_encoding;
use data_encoding::base64url;
use serde_json::json;

/// A key pair (`PublicKey` and `SecretKey`, also in esk format - expanded secret key).
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub pk: PublicKey,
    pub sk: SecretKey,
    pub esk: Vec<u8>,
}

impl KeyPair {
    /// Create an unencrypted key pair.
    ///
    /// The secret key will not be protected by a password.
    ///
    /// This is not recommended and incompatible with other implementations,
    /// but can be necessary if using a password is really not an option
    /// for your application.
    ///
    /// You generally want to use `generated_encrypted_keypair()` instead.
    pub fn generate_unencrypted_keypair(seed: Option<Vec<u8>>) -> Result<Self> {
        let mut seed_tmp = vec![0u8; 32];
        match seed {
            Some(x) => {
                if x.len() != 32 {
                    return Err(PError::new(ErrorKind::Io, "Seed must be 32 bytes long"));
                }
                seed_tmp = x
            }
            None => getrandom(&mut seed_tmp)?,
        }

        let (sk, pk, esk) = ed25519::keypair(&seed_tmp);
        let mut keynum = [0u8; KEYNUM_BYTES];
        getrandom(&mut keynum)?;
        let mut kdf_salt = [0u8; KDF_SALTBYTES];
        getrandom(&mut kdf_salt)?;

        let opslimit = OPSLIMIT;
        let memlimit = MEMLIMIT;
        let pk = PublicKey {
            sig_alg: SIGALG,
            keynum_pk: KeynumPK { keynum, pk },
        };
        let sk = SecretKey {
            sig_alg: SIGALG,
            kdf_alg: KDF_ALG,
            chk_alg: CHK_ALG,
            kdf_salt,
            kdf_opslimit_le: store_u64_le(opslimit),
            kdf_memlimit_le: store_u64_le(memlimit as u64),
            keynum_sk: KeynumSK {
                keynum,
                sk,
                chk: [0; CHK_BYTES],
            },
        };

        Ok(KeyPair {
            pk,
            sk,
            esk: esk.to_vec(),
        })
    }

    /// Create and encrypt a new key pair.
    ///
    /// If `password` is `None`, a password will be interactively asked for.
    ///
    /// A key can be converted to a box in order to be serialized and saved.
    /// Ex: `pk.to_box()?.to_bytes()`
    pub fn generate_encrypted_keypair(
        seed: Option<Vec<u8>>,
        password: Option<String>,
    ) -> Result<Self> {
        let KeyPair { pk, mut sk, esk } = Self::generate_unencrypted_keypair(seed)?;

        let interactive = password.is_none();
        sk.write_checksum()
            .map_err(|_| PError::new(ErrorKind::Generate, "failed to hash and write checksum!"))?;
        let password = match password {
            Some(password) => password,
            None => {
                writeln!(
                    io::stdout(),
                    "Please enter a password to protect the secret key."
                )?;
                let password = get_password("Password: ")?;
                let password2 = get_password("Password (one more time): ")?;
                if password != password2 {
                    return Err(PError::new(ErrorKind::Generate, "passwords don't match!"));
                }
                write!(
                    io::stdout(),
                    "Deriving a key from the password in order to encrypt the secret key... "
                )
                .map_err(|e| PError::new(ErrorKind::Io, e))?;
                io::stdout().flush()?;
                password
            }
        };
        let sk = sk.encrypt(password)?;
        if interactive {
            writeln!(io::stdout(), "done").map_err(|e| PError::new(ErrorKind::Io, e))?;
        }
        Ok(KeyPair { pk, sk, esk })
    }

    /// Create, encrypt and save a new key pair.
    ///
    /// # Arguments
    ///
    /// * `pk_writer` - Where to store the public key box.
    /// * `sk_writer` - Where to store the secret key box.
    /// * `comment` - An optional untrusted comment to replace the default one.
    /// * `password` - If `None`, a password will be interactively asked for.
    pub fn generate_and_write_encrypted_keypair<W, X>(
        mut pk_writer: W,
        mut sk_writer: X,
        comment: Option<&str>,
        password: Option<String>,
        seed: Option<Vec<u8>>,
    ) -> Result<Self>
    where
        W: Write,
        X: Write,
    {
        let KeyPair { pk, sk, esk } = Self::generate_encrypted_keypair(seed, password)?;

        pk_writer.write_all(&pk.to_box()?.to_bytes())?;
        pk_writer.flush()?;

        sk_writer.write_all(&sk.to_box(comment)?.to_bytes())?;
        sk_writer.flush()?;

        Ok(KeyPair { pk, sk, esk })
    }

    /// Create and save an unencrypted key pair.
    ///
    /// The secret key will not be protected by a password,
    /// and keys will be stored as raw bytes, not as a box.
    ///
    /// This is not recommended and incompatible with other implementations,
    /// but can be necessary if using a password is not an option
    /// for your application.
    ///
    /// You generally want to use `generated_encrypted_keypair()` instead.
    ///
    /// # Arguments
    ///
    /// * `pk_writer` - Where to store the public key box.
    /// * `sk_writer` - Where to store the secret key box.
    pub fn generate_and_write_unencrypted_keypair<W, X>(
        mut pk_writer: W,
        mut sk_writer: X,
        seed: Option<Vec<u8>>,
    ) -> Result<Self>
    where
        W: Write,
        X: Write,
    {
        let KeyPair { pk, sk, esk } = Self::generate_unencrypted_keypair(seed)?;

        pk_writer.write_all(&pk.to_bytes())?;
        pk_writer.flush()?;

        sk_writer.write_all(&sk.to_bytes())?;
        sk_writer.flush()?;

        Ok(KeyPair { pk, sk, esk })
    }
}

pub fn convert_secret_to_onion_keys<W, X, Z>(
    mut tor_sk_writer: W,
    mut tor_pk_writer: X,
    mut tor_hostname_writer: Z,
    secret: SecretKey,
) -> Result<bool>
where
    W: Write,
    X: Write,
    Z: Write,
{
    let seed = secret.keynum_sk.sk[0..32].to_vec();
    let KeyPair { pk, sk: _, esk } = KeyPair::generate_unencrypted_keypair(Some(seed))?;

    tor_pk_writer.write_all(b"== ed25519v1-public: type0 ==\0\0\0")?;
    tor_pk_writer.write_all(&pk.keynum_pk.pk)?;
    tor_pk_writer.flush()?;

    let onion_address = pk.to_onion_address();

    tor_hostname_writer.write_all(&onion_address.as_bytes())?;
    tor_hostname_writer.flush()?;

    tor_sk_writer.write_all(b"== ed25519v1-secret: type0 ==\0\0\0")?;
    tor_sk_writer.write_all(&esk)?;
    tor_sk_writer.flush()?;

    Ok(true)
}

pub fn convert_secret_to_tor_auth_keys<W, X>(
    mut tor_sk_writer: W,
    mut tor_pk_writer: X,
    tor_hostname: &str,
    secret: SecretKey,
) -> Result<bool>
where
    W: Write,
    X: Write,
{
    let seed = secret.keynum_sk.sk[0..32].to_vec();
    let mut seed_arr = [0u8; 32];
    for (place, element) in seed_arr.iter_mut().zip(seed.iter()) {
        *place = *element;
    }
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::from(seed_arr);
    let public_key = PublicKey::from(&secret);

    let b32_secret = base32::encode(
        base32::Alphabet::RFC4648 { padding: false },
        &secret.to_bytes(),
    );

    let b32_public = base32::encode(
        base32::Alphabet::RFC4648 { padding: false },
        public_key.as_bytes(),
    );

    tor_sk_writer.write_all(tor_hostname[0..56].as_bytes())?;
    tor_sk_writer.write_all(b":descriptor:x25519:")?;
    tor_sk_writer.write_all(b32_secret.as_bytes())?;
    tor_sk_writer.flush()?;

    tor_pk_writer.write_all(b"descriptor:x25519:")?;
    tor_pk_writer.write_all(b32_public.as_bytes())?;
    tor_pk_writer.flush()?;

    Ok(true)
}

pub fn generate_did_document(
    /*
        mut tor_sk_writer: W,
        mut tor_pk_writer: X,
        tor_hostname: &str,
    */
    secret: SecretKey,
) -> Result<bool>
/*
where
    W: Write,
    X: Write,
*/
{
    let seed = secret.keynum_sk.sk[0..32].to_vec();
    let KeyPair { pk, sk, esk: _ } = KeyPair::generate_unencrypted_keypair(Some(seed))?;

    let seed = secret.keynum_sk.sk[0..32].to_vec();
    let pubkey_ed25519 = pk.to_bytes();
    let mut seed_arr = [0u8; 32];
    for (place, element) in seed_arr.iter_mut().zip(seed.iter()) {
        *place = *element;
    }
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret_xd25519 = StaticSecret::from(seed_arr);
    let pubkey_x25519 = PublicKey::from(&secret_xd25519);

    // Convert pubkeys to JSON JWK format:
    let pubkey_ed25519_jwk = base64url::encode(&pubkey_ed25519);
    println!("pubkey_ed25519_jwk: {:?}", pubkey_ed25519_jwk);

    let pubkey_x25519_jwk = base64url::encode(&pubkey_x25519.to_bytes());
    println!("pubkey_ed25519_jwk: {:?}", pubkey_x25519_jwk);

    let onion = pk.to_onion_address();
    let did_onion = format!("did:onion:{}", &onion[0..56]);

    let did = json!({
         "@context": ["https://www.w3.org/ns/did/v1", {"@base": did_onion} ],
         "id" : format!("did:onion:{}", &onion[0..56]),
         "VerificationMethod" : [
         {
             "id" : "TODO",
             "type" : "JsonWebKey2020",
             "controller" : did_onion,
             "publicKeyJwk": {
                "crv": "Ed25519",
                "x": pubkey_ed25519_jwk,
                "kty": "OKP"
             }
         },
        {
            "id": "TODO",
            "type": "JsonWebKey2020",
            "controller": did_onion,
            "publicKeyJwk": {
              "kty": "OKP",
              "crv": "X25519",
              "x": pubkey_x25519_jwk
         }
       }
    ]
    });

    let did_doc_json = serde_json::to_string_pretty(&did).unwrap();
    println!("{}", did_doc_json);

    /*
        tor_sk_writer.write_all(tor_hostname[0..56].as_bytes())?;
        tor_sk_writer.write_all(b":descriptor:x25519:")?;
        tor_sk_writer.write_all(b32_secret.as_bytes())?;
        tor_sk_writer.flush()?;

        tor_pk_writer.write_all(b"descriptor:x25519:")?;
        tor_pk_writer.write_all(b32_public.as_bytes())?;
        tor_pk_writer.flush()?;
    */
    Ok(true)
}
