//! Member identity with secret hygiene.
//!
//! Each member holds an `Identity { sk, salt }` that never leaves the device
//! in raw form. The public representation is the `IdentityCommitment =
//! H(sk ‖ salt)`, which is what gets enrolled in the multisig's Merkle tree.
//!
//! ## Secret hygiene (PLAN.md step 5 + THREAT_MODEL.md T6.1 / T6.2)
//!
//! - `Member` implements `Drop` with explicit zeroization of the identity
//!   fields so `sk` and `salt` do not linger after the struct is dropped.
//! - `Member` implements a redacting `Debug` impl — it will never log sk or
//!   salt bytes.
//! - The on-disk keystore encrypts `(sk, salt)` with an Argon2id-derived KEK
//!   + ChaCha20-Poly1305. The derived key is zeroized immediately after use.
//! - BIP39 mnemonic export is deferred to a follow-on task; the current
//!   export path is an encrypted keystore blob (see [`Keystore`]).
//!
//! ## Creating a new member
//!
//! ```ignore
//! use private_multisig_sdk::Member;
//!
//! let member = Member::new()?;
//! println!("Commitment: {:?}", member.commitment());
//! // sk is NOT printed — Debug redacts it
//! ```

use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::KeyInit;
use rand::rngs::SysRng;
use rand::TryRng;
use secrecy::SecretBox;
use zeroize::Zeroize;

use crypto::hash::Sha256Hasher;
use crypto::identity::Identity;

use crate::error::SdkError;

/// On-device member identity.
///
/// Construct via [`Member::new`] or [`Member::from_keystore`].
///
/// This type is `Send + Sync` but deliberately NOT `Clone` — each device holds
/// exactly one identity. If a member needs to be represented on another device,
/// export the keystore and import it there.
pub struct Member {
    identity: Identity,
}

impl Member {
    /// Generate a fresh identity with cryptographically random `sk` and `salt`.
    ///
    /// Uses `SysRng` so the source is the OS-level CSPRNG, not a deterministic
    /// seeded generator. No network entropy is required.
    pub fn new() -> Result<Self, SdkError> {
        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        // In rand 0.10 `OsRng` was replaced by `SysRng` (re-exported from
        // `getrandom`) and only implements the fallible `TryRng` trait.
        // `try_fill_bytes` returns the OS-level error if the syscall
        // fails; we `expect()` here because a `getrandom`/`/dev/urandom`
        // failure is fatal for the SDK — no fallback is meaningful at
        // this layer.
        SysRng
            .try_fill_bytes(&mut sk)
            .expect("SysRng::try_fill_bytes failed — kernel CSPRNG unavailable");
        SysRng
            .try_fill_bytes(&mut salt)
            .expect("SysRng::try_fill_bytes failed — kernel CSPRNG unavailable");
        Ok(Self {
            identity: Identity::new(sk, salt),
        })
    }

    /// The public identity commitment enrolled in the multisig's Merkle tree.
    ///
    /// This is the only value that ever appears on-chain or in transaction
    /// metadata. It is safe to share freely.
    pub fn commitment(&self) -> IdentityCommitment {
        IdentityCommitment(self.identity.commitment::<Sha256Hasher>().0)
    }

    /// Derive this member's nullifier for `proposal_id`.
    ///
    /// `nullifier = H(sk ‖ proposal_id)`.
    pub fn nullifier(&self, proposal_id: &[u8; 32]) -> [u8; 32] {
        self.identity.nullifier::<Sha256Hasher>(proposal_id)
    }

    /// Access the raw secret key as a `SecretBox<[u8; 32]>`.
    ///
    /// `SecretBox<T>` redacts the value from `Debug` output and zeroizes on
    /// drop (renamed from `Secret<T>` in `secrecy` 0.10). Callers should use
    /// `expose_secret()` only in contexts where the bytes are passed
    /// directly to the Risc0 prover or to the keystore encryptor.
    pub fn secret_key(&self) -> SecretBox<[u8; 32]> {
        SecretBox::new(Box::new(self.identity.sk))
    }

    /// Access the salt as a `SecretBox<[u8; 32]>`.
    ///
    /// Salt is not as sensitive as sk but keeping it in `SecretBox` ensures
    /// it is not accidentally logged.
    pub fn salt(&self) -> SecretBox<[u8; 32]> {
        SecretBox::new(Box::new(self.identity.salt))
    }

    /// Extract the `(sk, salt)` raw bytes for Risc0 guest input.
    ///
    /// These bytes are already zeroized on `Member::drop`. The prover
    /// zeroizes them again on its own `Drop`.
    pub(crate) fn witness(&self) -> ([u8; 32], [u8; 32]) {
        (self.identity.sk, self.identity.salt)
    }

    /// Encrypt this member's identity to an at-rest keystore blob.
    ///
    /// The blob contains the Argon2id parameters, salt, and ChaCha20-Poly1305
    /// ciphertext. Safe to back up to disk or a password manager.
    ///
    /// ```ignore
    /// let blob = member.encrypt("hunter2")?;
    /// std::fs::write("member.keystore", &blob)?;
    /// ```
    pub fn encrypt(&self, password: &str) -> Result<KeystoreBytes, SdkError> {
        let (sk, salt) = self.witness();

        // 128-bit random salt for Argon2id.
        let mut argon_salt = [0u8; 16];
        SysRng
            .try_fill_bytes(&mut argon_salt)
            .expect("SysRng::try_fill_bytes failed — kernel CSPRNG unavailable");

        // 96-bit random nonce for ChaCha20-Poly1305.
        let mut nonce_bytes = [0u8; 12];
        SysRng
            .try_fill_bytes(&mut nonce_bytes)
            .expect("SysRng::try_fill_bytes failed — kernel CSPRNG unavailable");

        // Argon2id parameters: 64 MiB memory, 3 iterations, 4 parallelism.
        // RFC 9106 "interactive" parameters — fast for CLI, costly to brute-force.
        let argon_params = argon2::Params::new(65536, 3, 4, None)
            .map_err(|_| SdkError::KeystoreSerializationFailed)?;

        let argon2id = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );
        let mut kek = [0u8; 32];
        argon2id
            .hash_password_into(password.as_bytes(), &argon_salt, &mut kek)
            .map_err(|_| SdkError::KeystoreSerializationFailed)?;

        // ChaCha20-Poly1305 AEAD: encrypt sk || salt.
        // ChaCha20Poly1305 produces a 16-byte tag appended to the ciphertext.
        // Output = plaintext (64) + tag (16) = 80 bytes.
        let key = chacha20poly1305::Key::from_slice(&kek);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
        let aad = b"private-multisig-keystore-v1";

        // Build plaintext: sk || salt
        let mut in_out = Vec::with_capacity(80);
        in_out.extend_from_slice(&sk);
        in_out.extend_from_slice(&salt);

        let result = cipher.encrypt_in_place(nonce, aad, &mut in_out);
        if result.is_err() {
            // Zeroize plaintext before returning (RT-1 fix)
            in_out.zeroize();
            kek.zeroize();
            return Err(SdkError::KeystoreSerializationFailed);
        }
        // in_out now holds ciphertext || tag (80 bytes) — plaintext is gone.
        // The Vec is moved into Keystore.ciphertext, taking the encrypted bytes
        // with it. No further zeroization needed here.

        // Zeroize derived key material.
        kek.zeroize();

        let ks = Keystore {
            argon_salt,
            nonce: nonce_bytes,
            ciphertext: in_out,
        };
        let mut bytes = Vec::with_capacity(512);
        ks.serialize(&mut bytes)
            .map_err(|_| SdkError::KeystoreSerializationFailed)?;
        Ok(bytes)
    }

    /// Decrypt a keystore blob to recover the member identity.
    ///
    /// Returns `Err(SdkError::KeystoreDecryptionFailed)` if the password is
    /// wrong or the blob is corrupted. Both cases produce the same error
    /// to prevent oracle attacks.
    pub fn from_keystore(blob: &[u8], password: &str) -> Result<Self, SdkError> {
        let mut cursor = blob;
        let ks =
            Keystore::deserialize(&mut cursor).map_err(|_| SdkError::KeystoreDecryptionFailed)?;

        let argon_params = argon2::Params::new(65536, 3, 4, None)
            .map_err(|_| SdkError::KeystoreDecryptionFailed)?;

        let argon2id = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon_params,
        );
        let mut kek = [0u8; 32];
        argon2id
            .hash_password_into(password.as_bytes(), &ks.argon_salt, &mut kek)
            .map_err(|_| SdkError::KeystoreDecryptionFailed)?;

        let key = chacha20poly1305::Key::from_slice(&kek);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);
        let nonce = chacha20poly1305::Nonce::from_slice(&ks.nonce);
        let aad = b"private-multisig-keystore-v1";

        // Ciphertext = sk (32) + salt (32) + tag (16) = 80 bytes.
        let mut in_out = ks.ciphertext.clone();
        let result = cipher.decrypt_in_place(nonce, aad, &mut in_out);
        if result.is_err() {
            kek.zeroize();
            return Err(SdkError::KeystoreDecryptionFailed);
        }
        // in_out[..64] now holds sk || salt

        // Zeroize derived key material.
        kek.zeroize();

        let mut sk = [0u8; 32];
        let mut salt = [0u8; 32];
        sk.copy_from_slice(&in_out[..32]);
        salt.copy_from_slice(&in_out[32..64]);
        in_out.zeroize();

        Ok(Self {
            identity: Identity::new(sk, salt),
        })
    }
}

/// On-chain identity commitment. Unlike `Member`, this type is cheap to clone
/// and safe to log or serialize.
///
/// ```ignore
/// let commitment = member.commitment();
/// println!("Enrolling: {:?}", commitment);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize)]
pub struct IdentityCommitment(pub crypto::hash::Hash);

impl IdentityCommitment {
    /// The 32-byte raw commitment bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for IdentityCommitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IdentityCommitment(0x")?;
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        write!(f, ")")
    }
}

/// Serialization format for an encrypted member keystore.
///
/// Borsh layout:
/// ```text
/// argon_salt:  [u8; 16]
/// nonce:       [u8; 12]
/// ciphertext:  Vec<u8>  (sk (32) + salt (32) + 16-byte tag)
/// ```
#[derive(BorshSerialize, BorshDeserialize)]
struct Keystore {
    argon_salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

/// Re-export type alias for the keystore byte output.
type KeystoreBytes = Vec<u8>;

impl core::fmt::Debug for Member {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Member")
            .field("sk", &"[REDACTED]")
            .field("salt", &"[REDACTED]")
            .finish()
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        // Explicitly zeroize the identity fields so they don't linger
        // in memory after the Member is dropped.
        self.identity.sk.zeroize();
        self.identity.salt.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn new_member_produces_valid_commitment() {
        let member = Member::new().unwrap();
        let commitment = member.commitment();
        assert_ne!(*commitment.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn two_fresh_members_have_different_commitments() {
        let alice = Member::new().unwrap();
        let bob = Member::new().unwrap();
        assert_ne!(alice.commitment(), bob.commitment());
    }

    #[test]
    fn commitment_is_deterministic() {
        let member = Member::new().unwrap();
        assert_eq!(member.commitment(), member.commitment());
    }

    #[test]
    fn keystore_round_trip_recovers_member() {
        let original = Member::new().unwrap();
        let commitment_before = original.commitment();
        let sk_before = *original.secret_key().expose_secret();

        let blob = original.encrypt("correct-horse-battery-staple").unwrap();
        let restored = Member::from_keystore(&blob, "correct-horse-battery-staple").unwrap();

        assert_eq!(restored.commitment(), commitment_before);
        assert_eq!(*restored.secret_key().expose_secret(), sk_before);
    }

    #[test]
    fn keystore_wrong_password_rejected() {
        let member = Member::new().unwrap();
        let blob = member.encrypt("hunter2").unwrap();
        assert!(Member::from_keystore(&blob, "hunter3").is_err());
    }

    #[test]
    fn debug_redacts_identity() {
        let member = Member::new().unwrap();
        let rendered = format!("{:?}", member);
        assert!(
            rendered.contains("[REDACTED]"),
            "Debug should redact sk/salt"
        );
        assert!(
            !rendered.contains("0x"),
            "Debug should not expose raw bytes"
        );
    }
}
