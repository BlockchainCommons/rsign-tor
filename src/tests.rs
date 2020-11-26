#[test]

fn byte_array_store() {
    use crate::store_u64_le;

    assert_eq!([0xFF, 0, 0, 0, 0, 0, 0, 0], store_u64_le(0xFF));
}

#[test]
fn byte_array_load() {
    use crate::load_u64_le;

    assert_eq!(255, load_u64_le(&[0xFF, 0, 0, 0, 0, 0, 0, 0]));
}

#[test]
fn pk_key_struct_conversion() {
    use crate::{KeyPair, PublicKey};

    let KeyPair { pk, .. } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    assert_eq!(pk, PublicKey::from_bytes(&pk.to_bytes()).unwrap());
}

#[test]
fn sk_key_struct_conversion() {
    use crate::{KeyPair, SecretKey};

    let KeyPair { sk, .. } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
}

#[test]
fn sk_determinstic_key_struct_conversion() {
    use crate::{KeyPair, SecretKey};

    let seed = vec![
        0x03, 0x63, 0x04, 0xe1, 0x6b, 0x01, 0x87, 0xfa, 0x9d, 0x7a, 0x35, 0x37, 0xd8, 0x07, 0x29,
        0x00, 0x03, 0x63, 0x04, 0xe1, 0x6b, 0x01, 0x87, 0xfa, 0x9d, 0x7a, 0x35, 0x37, 0xd8, 0x07,
        0x29, 0x00,
    ];
    let KeyPair { sk, .. } = KeyPair::generate_unencrypted_keypair(Some(seed)).unwrap();

    assert_eq!(sk, SecretKey::from_bytes(&sk.to_bytes()).unwrap());
}

#[test]
fn xor_keynum() {
    use crate::KeyPair;
    use getrandom::getrandom;

    let KeyPair { mut sk, .. } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    let mut key = vec![0u8; sk.keynum_sk.len()];
    getrandom(&mut key).unwrap();
    let original_keynum = sk.keynum_sk.clone();
    sk.xor_keynum(&key);
    assert_ne!(original_keynum, sk.keynum_sk);
    sk.xor_keynum(&key);
    assert_eq!(original_keynum, sk.keynum_sk);
}

#[test]
fn sk_checksum() {
    use crate::KeyPair;

    let KeyPair { mut sk, .. } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    assert!(sk.write_checksum().is_ok());
    assert_eq!(sk.keynum_sk.chk.to_vec(), sk.read_checksum().unwrap());
}

#[test]
fn load_public_key_string() {
    use crate::PublicKey;

    assert!(
        PublicKey::from_base64("RWRzq51bKcS8oJvZ4xEm+nRvGYPdsNRD3ciFPu1YJEL8Bl/3daWaj72r").is_ok()
    );
    assert!(
        PublicKey::from_base64("RWQt7oYqpar/yePp+nonossdnononovlOSkkckMMfvHuGc+0+oShmJyN5Y")
            .is_err()
    );
}

#[test]
fn signature() {
    use crate::{sign, verify, KeyPair};
    use std::io::Cursor;

    let KeyPair { pk, sk, esk: _ } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    let data = b"test";
    let signature_box = sign(None, &sk, Cursor::new(data), false, None, None).unwrap();
    verify(&pk, &signature_box, Cursor::new(data), true, false).unwrap();
    let data = b"test2";
    assert!(verify(&pk, &signature_box, Cursor::new(data), true, false).is_err());
}

#[test]
fn signature_prehashed() {
    use crate::{sign, verify, KeyPair};
    use std::io::Cursor;

    let KeyPair { pk, sk, esk: _ } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    let data = b"test";
    let signature_box = sign(None, &sk, Cursor::new(data), true, None, None).unwrap();
    verify(&pk, &signature_box, Cursor::new(data), true, false).unwrap();
    let data = b"test2";
    assert!(verify(&pk, &signature_box, Cursor::new(data), true, false).is_err());
}

#[test]
fn signature_bones() {
    use crate::{sign, verify, KeyPair, SignatureBones};
    use std::io::Cursor;

    let KeyPair { pk, sk, esk: _ } = KeyPair::generate_unencrypted_keypair(None).unwrap();
    let data = b"test";
    let signature_box = sign(None, &sk, Cursor::new(data), false, None, None).unwrap();
    let signature_bones: SignatureBones = signature_box.into();
    verify(
        &pk,
        &signature_bones.clone().into(),
        Cursor::new(data),
        true,
        false,
    )
    .unwrap();
    let data = b"test2";
    assert!(verify(&pk, &signature_bones.into(), Cursor::new(data), true, false).is_err());
}

#[test]
fn verify_det() {
    use crate::{verify, PublicKey, SignatureBox};
    use std::io::Cursor;

    let pk =
        PublicKey::from_base64("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3").unwrap();
    let signature_box = SignatureBox::from_string(
        "untrusted comment: signature from minisign secret key
RWQf6LRCGA9i59SLOFxz6NxvASXDJeRtuZykwQepbDEGt87ig1BNpWaVWuNrm73YiIiJbq71Wi+dP9eKL8OC351vwIasSSbXxwA=
trusted comment: timestamp:1555779966\tfile:test
QtKMXWyYcwdpZAlPF7tE2ENJkRd1ujvKjlj1m9RtHTBnZPa5WKU5uWRs5GoP5M/VqE81QFuMKI5k/SfNQUaOAA==",
    )
    .unwrap();
    assert!(!signature_box.is_prehashed());
    assert_eq!(
        signature_box.untrusted_comment().unwrap(),
        "signature from minisign secret key"
    );
    assert_eq!(
        signature_box.trusted_comment().unwrap(),
        "timestamp:1555779966\tfile:test"
    );
    let bin = b"test";
    verify(&pk, &signature_box, Cursor::new(bin), false, false).expect("Signature didn't verify");
}

#[test]
fn verify_prehashed_det() {
    use crate::{verify, PublicKey, SignatureBox};
    use std::io::Cursor;

    let pk =
        PublicKey::from_base64("RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3").unwrap();
    let signature_box = SignatureBox::from_string(
        "untrusted comment: signature from minisign secret key
RUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=
trusted comment: timestamp:1556193335\tfile:test
y/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==",
    )
    .unwrap();
    assert!(signature_box.is_prehashed());
    assert_eq!(
        signature_box.untrusted_comment().unwrap(),
        "signature from minisign secret key"
    );
    assert_eq!(
        signature_box.trusted_comment().unwrap(),
        "timestamp:1556193335\tfile:test"
    );
    let bin = b"test";
    verify(&pk, &signature_box, Cursor::new(bin), false, false)
        .expect("Signature with prehashing didn't verify");
}

#[test]
fn test_pubkey_from_onion_address() {
    use crate::public_key::PublicKey;
    use crate::signature_box::SignatureBox;
    let onion_address = "fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid.onion";
    let signature = "untrusted comment: signature from rsign secret key
RWTFh+S84tByDUw+zC2dDGuaX3r3yAePDGhAaoNliwTfDek1ADKuc7Y/L5AKd089Y8k/HuXRRmNPO4cjsmE2dQLu0v7C3DC7SAk=
trusted comment: fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid.onion
NbTt3wnK1ruWxPFstDT/bineOaX8mVlChY/R8xS9s0ERGfkA7rNDnbSqqJ7jbr8Af0/8ONWi/hRINxwCy6hSDQ==";
    let signature_box = SignatureBox::from_string(&signature).unwrap();

    let pubkey = PublicKey::from_onion_address(
        onion_address,
        signature_box.get_sig_alg(),
        signature_box.get_keynum(),
    )
    .unwrap();

    assert_eq!(
        pubkey.to_base64(),
        "RWTFh+S84tByDSyFKfSXYtkde0HGZ2zxWTmMleaMqLTR1NieXUFHU1Gu"
    );

    // TEST: bad onion checksum:
    let onion_address = "fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkkxf7mid.onion";
    assert!(PublicKey::from_onion_address(
        onion_address,
        signature_box.get_sig_alg(),
        signature_box.get_keynum(),
    )
    .is_err());
}

#[test]
fn test_deterministic_seed() {
    use crate::keypair::KeyPair;

    // keys generated from the same deterministic key are always equal
    let seed1 = vec![0; 32];
    let keypair1 = KeyPair::generate_unencrypted_keypair(Some(seed1.clone())).unwrap();
    let keypair2 = KeyPair::generate_unencrypted_keypair(Some(seed1)).unwrap();
    assert_eq!(keypair1.sk, keypair2.sk);
    assert_eq!(keypair1.pk, keypair2.pk);

    // keys generated from different deterministic seeds are different
    let seed2 = vec![1; 32];
    let keypair3 = KeyPair::generate_unencrypted_keypair(Some(seed2)).unwrap();
    assert!(keypair1.sk != keypair3.sk);

    // deterministic seed is different than TRNG seed
    let keypair4 = KeyPair::generate_unencrypted_keypair(None).unwrap();
    assert!(keypair3.sk != keypair4.sk);

    // only 32 byte seed allowed
    let seed = vec![0; 16];
    assert!(KeyPair::generate_unencrypted_keypair(Some(seed)).is_err());

    // Temporary Proof of concept for JSON pwk notation of secret/public keys
    // TODO
    let seed_tmp = vec![
        0xe7, 0x45, 0xc7, 0x4c, 0x57, 0xdb, 0xb9, 0x79, 0x51, 0x31, 0x64, 0xfe, 0x8b, 0x99, 0xc0,
        0xfc, 0x3d, 0x57, 0x73, 0x5e, 0x20, 0xcf, 0xb2, 0x13, 0x04, 0xb1, 0x1c, 0x8c, 0x28, 0x7f,
        0x0a, 0xcc,
    ];
    extern crate data_encoding;
    use data_encoding::base64url;
    let mykeys = KeyPair::generate_unencrypted_keypair(Some(seed_tmp)).unwrap();

    let pubkey = mykeys.pk.keynum_pk.pk;
    let x = base64url::encode(&pubkey);
    println!("pubkey bas64ur: {:?}", x);

    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&x);
    let result = hasher.finalize();

    let y = base64url::encode(&result);

    println!("id base64url: {:?}", y);
}
