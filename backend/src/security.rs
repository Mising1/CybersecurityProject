use std::sync::LazyLock;

use argon2::{password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use rand::{rngs::OsRng, seq::SliceRandom, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Argon2id z domyślnymi parametrami crate'a (m = 19 MiB, t = 2, p = 1) i solą losowaną osobno dla każdego hasła.
/// Wynik w formacie PHC przechowuje algorytm, parametry i sól razem ze skrótem.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(password.as_bytes(), &salt)?.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .is_ok_and(|h| Argon2::default().verify_password(password.as_bytes(), &h).is_ok())
}

/// Skrót sprawdzany, gdy loginu nie ma w bazie - odpowiedź trwa tyle samo, więc czas jej nie zdradza, czy konto istnieje.
pub static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("dummy-password").expect("hashowanie hasła zastępczego"));

/// 256 losowych bitów z CSPRNG systemu.
pub fn new_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Token ma pełną entropię, więc do jego skrótu wystarcza SHA-256 (w odróżnieniu od haseł).
/// Wyciek tabeli sesji nie pozwala przejąć sesji.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Dłuższych haseł nie przyjmujemy - Argon2 liczyłby je niepotrzebnie długo.
const MAX_PASSWORD_LENGTH: usize = 256;
const PASSPHRASE_MIN_WORDS: usize = 3;

/// Polityka haseł z settings:main. Nie dotyczy haseł jednorazowych - te generuje system.
#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub passphrase_rule_enabled: bool,
}

impl PasswordPolicy {
    pub fn check(&self, password: &str) -> Result<(), &'static str> {
        let length = password.chars().count();
        if length < self.min_length {
            return Err("Hasło jest za krótkie.");
        }
        if length > MAX_PASSWORD_LENGTH {
            return Err("Hasło jest za długie.");
        }
        // słowo to fragment zawierający choć jedną literę, więc "1-2-3" frazą nie jest
        let words = password.split([' ', '-']).filter(|w| w.chars().any(char::is_alphabetic)).count();
        if self.passphrase_rule_enabled && words < PASSPHRASE_MIN_WORDS {
            return Err("Hasło musi być frazą: co najmniej 3 słowa oddzielone spacją lub myślnikiem.");
        }
        Ok(())
    }
}

pub const ONE_TIME_PASSWORD_LENGTH: usize = 12;

const LETTERS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
const DIGITS:  &[u8] = b"23456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_=+?";

pub fn one_time_password() -> String {
    let mut rng = OsRng;
    // po jednym znaku z każdej klasy, reszta losowa z sumy
    let all: Vec<u8> = [LETTERS, DIGITS, SPECIAL].concat();
    let mut chars: Vec<u8> = vec![
        *LETTERS.choose(&mut rng).unwrap(),
        *DIGITS.choose(&mut rng).unwrap(),
        *SPECIAL.choose(&mut rng).unwrap(),
    ];
    while chars.len() < ONE_TIME_PASSWORD_LENGTH {
        chars.push(all[rng.gen_range(0..all.len())]);
    }
    chars.shuffle(&mut rng);
    String::from_utf8(chars).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_time_password_format() {
        let p = one_time_password();
        assert_eq!(p.chars().count(), ONE_TIME_PASSWORD_LENGTH);
        assert!(p.bytes().any(|b| LETTERS.contains(&b)));
        assert!(p.bytes().any(|b| DIGITS.contains(&b)));
        assert!(p.bytes().any(|b| SPECIAL.contains(&b)));
    }

    #[test]
    fn policy() {
        let mut policy = PasswordPolicy { min_length: 15, passphrase_rule_enabled: false };
        assert!(policy.check("krótkie").is_err());
        assert!(policy.check("bardzodlugiehaslo").is_ok());

        policy.passphrase_rule_enabled = true;
        assert!(policy.check("bardzodlugiehaslo").is_err());
        assert!(policy.check("dwa-slowa-------").is_err());
        assert!(policy.check("1111-2222-3333-4444").is_err());
        assert!(policy.check("zielona herbata-rano").is_ok());
        assert!(policy.check("żółta-łódź-płynie").is_ok());
    }
}
