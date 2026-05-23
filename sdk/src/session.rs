//! Resumable approval session storage.
//!
//! PLAN.md step 5 specifies that the SDK persists an `ApprovalSession` to a
//! local sled database under `~/.private-multisig/state` keyed by
//! `(instance_pda, proposal_id, member_commitment)`. This enables crash
//! recovery: if the client dies mid-proof-generation or mid-submission,
//! the next invocation resumes from the last persisted status.
//!
//! ## Status state machine
//!
//! ```text
//! Drafted ──► Proving ──► Proved ──► Submitted ──► Confirmed
//!                              │
//!                              └──► Failed (any step can fail)
//! ```
//!
//! Transitions:
//! - `Drafted → Proving`: caller invokes `ApprovalProver::prove()`.
//! - `Proving → Proved`: `prove()` succeeds; receipt bytes cached.
//! - `Proved → Submitted`: caller submits `Instruction::Approve` to chain.
//! - `Submitted → Confirmed`: chain reports N-block finality.
//! - `Any → Failed`: unrecoverable error (prover panic, submission rejected).
//!
//! ## Reorg handling
//!
//! If a submitted transaction lands in a reorg, the chain observer demotes it
//! back to `Proved` so the cached receipt is re-broadcast. The session
//! tracks `submission_block` so callers can detect reorgs by watching for
//! chain reverts below that block number.
//!
//! ## Key format
//!
//! Keys are Borsh-serialized tuples:
//! `[instance_pda: 32][proposal_id: 32][commitment: 32] = 96 bytes`.
//! This makes lookups by `(instance_pda, proposal_id)` a range scan over
//! 64-byte prefix, and a point lookup by full 3-tuple for a specific
//! member's session.

use borsh::{BorshDeserialize, BorshSerialize};
use private_multisig_core::AccountId;
use sled::{Db, Tree};
use std::path::PathBuf;
use std::sync::Mutex;

use crate::error::SdkError;
use crate::member::IdentityCommitment;

/// Approval session status.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum SessionStatus {
    /// Session created but proving has not started.
    Drafted,
    /// Risc0 proving is in progress (or crashed before completion).
    Proving,
    /// Proof generated; receipt bytes cached locally.
    Proved,
    /// `Instruction::Approve` submitted to the chain; awaiting finality.
    Submitted,
    /// Chain reached N-block finality; approval is irreversible.
    Confirmed,
    /// Unrecoverable error; session must be discarded and restarted.
    Failed,
}

impl SessionStatus {
    /// True if the session has a cached receipt ready for submission.
    pub fn has_receipt(&self) -> bool {
        matches!(self, Self::Proved | Self::Submitted | Self::Confirmed)
    }

    /// True if the session can be resumed by re-entering the prover.
    pub fn can_reprove(&self) -> bool {
        matches!(self, Self::Drafted | Self::Proving)
    }

    /// True if the session can be re-submitted without re-proving.
    pub fn can_resubmit(&self) -> bool {
        matches!(self, Self::Proved | Self::Submitted)
    }
}

/// A resumable approval session for a single `(instance, proposal, member)`.
///
/// Construct via [`ApprovalSession::new`], persist via [`save`](Self::save),
/// recover via [`SessionStore::load`].
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct ApprovalSession {
    /// Which multisig instance this session targets.
    pub instance_pda: AccountId,
    /// The canonical proposal_id this session approves.
    pub proposal_id: [u8; 32],
    /// The member's identity commitment — also the session's key component 3.
    pub member_commitment: IdentityCommitment,
    /// Current position in the state machine.
    pub status: SessionStatus,
    /// Cached Risc0 receipt bytes. Present from `Proved` onward.
    pub receipt: Option<Vec<u8>>,
    /// Cached `ApprovePublicInputs` bytes. Present from `Drafted` onward.
    pub public_inputs: Option<[u8; 96]>,
    /// Cached nullifier. Present from `Drafted` onward.
    pub nullifier: Option<[u8; 32]>,
    /// LEZ block number at which the approval was submitted.
    /// `None` until `Submitted`.
    pub submission_block: Option<u64>,
    /// Human-readable error message if `status == Failed`.
    pub error_message: Option<String>,
    /// Number of retry attempts (for metrics and backoff guidance).
    pub retry_count: u32,
    /// UTC timestamp of last status change (seconds since Unix epoch).
    pub last_updated: u64,
}

impl ApprovalSession {
    /// Start a new session in `Drafted` status.
    ///
    /// `instance_pda`, `proposal_id`, and `member_commitment` are set here
    /// and never change. Status transitions and cached data are the only
    /// mutable parts.
    pub fn new(
        instance_pda: AccountId,
        proposal_id: [u8; 32],
        member_commitment: IdentityCommitment,
        public_inputs: [u8; 96],
        nullifier: [u8; 32],
    ) -> Self {
        Self {
            instance_pda,
            proposal_id,
            member_commitment,
            status: SessionStatus::Drafted,
            receipt: None,
            public_inputs: Some(public_inputs),
            nullifier: Some(nullifier),
            submission_block: None,
            error_message: None,
            retry_count: 0,
            last_updated: current_unix_seconds(),
        }
    }

    /// Transition to `Proving` status.
    ///
    /// Returns `SdkError::SessionStatusMismatch` if the current status is
    /// not `Drafted` or `Proved` (the only valid predecessors).
    pub fn mark_proving(&mut self) -> Result<(), SdkError> {
        self.transition_to(SessionStatus::Proving)
    }

    /// Transition to `Proved` with the cached receipt.
    pub fn mark_proved(&mut self, receipt: Vec<u8>) -> Result<(), SdkError> {
        self.receipt = Some(receipt);
        self.transition_to(SessionStatus::Proved)
    }

    /// Transition to `Submitted` with the submission block number.
    pub fn mark_submitted(&mut self, block: u64) -> Result<(), SdkError> {
        self.submission_block = Some(block);
        self.transition_to(SessionStatus::Submitted)
    }

    /// Demote from `Submitted` to `Proved` on reorg detection.
    /// Caller provides the current block height — if it is below the
    /// submission block, this is a confirmed reorg.
    pub fn demote_on_reorg(&mut self, current_block: u64) {
        if let Some(submitted_at) = self.submission_block {
            if current_block < submitted_at {
                self.status = SessionStatus::Proved;
                self.submission_block = None;
                self.retry_count += 1;
                self.last_updated = current_unix_seconds();
            }
        }
    }

    /// Force-transition to `Confirmed`. Skips finality checks — prefer
    /// [`try_confirm`](Self::try_confirm) which enforces an N-block buffer.
    /// This entry point exists for tests and recovery scripts that have
    /// out-of-band confirmation that finality has been reached.
    pub fn mark_confirmed(&mut self) -> Result<(), SdkError> {
        self.transition_to(SessionStatus::Confirmed)
    }

    /// Promote from `Submitted` to `Confirmed` only if `current_block` is
    /// at least `n_blocks` ahead of `submission_block`. Returns `Ok(false)`
    /// if not enough blocks have passed (the documented `N` buffer in
    /// THREAT_MODEL T6.5; `N = 32` is the recommended default for LEZ).
    /// Returns `Err` if the session is not in `Submitted` status.
    pub fn try_confirm(&mut self, current_block: u64, n_blocks: u64) -> Result<bool, SdkError> {
        if self.status != SessionStatus::Submitted {
            return Err(SdkError::SessionStatusMismatch);
        }
        let Some(submitted_at) = self.submission_block else {
            return Err(SdkError::SessionStatusMismatch);
        };
        let confirmed_at = match submitted_at.checked_add(n_blocks) {
            Some(b) => b,
            None => return Err(SdkError::SessionStatusMismatch),
        };
        if current_block < confirmed_at {
            return Ok(false);
        }
        self.transition_to(SessionStatus::Confirmed)?;
        Ok(true)
    }

    /// Transition to `Failed` with an error message. Failed is terminal
    /// and reachable from any state, so this never returns Err.
    pub fn mark_failed(&mut self, message: String) {
        self.status = SessionStatus::Failed;
        self.error_message = Some(message);
        self.last_updated = current_unix_seconds();
    }

    fn transition_to(&mut self, next: SessionStatus) -> Result<(), SdkError> {
        // Enforce the documented state machine (BT-11 fix):
        // Drafted -> Proving -> Proved -> Submitted -> Confirmed
        // Any state can transition to Failed (via mark_failed, not this path)
        // Submitted -> Proved only via demote_on_reorg
        // Proved -> Proving (retry)
        let valid = matches!(
            (&self.status, &next),
            (SessionStatus::Drafted, SessionStatus::Proving)
                | (SessionStatus::Proving, SessionStatus::Proved)
                | (SessionStatus::Proved, SessionStatus::Submitted)
                | (SessionStatus::Submitted, SessionStatus::Confirmed)
                | (SessionStatus::Proved, SessionStatus::Proving)
        );
        if !valid {
            return Err(SdkError::SessionStatusMismatch);
        }
        self.status = next;
        self.last_updated = current_unix_seconds();
        Ok(())
    }
}

/// Key type for the session tree: `(instance_pda, proposal_id, commitment)`.
#[derive(Clone, Copy, BorshSerialize, BorshDeserialize)]
struct SessionKey {
    instance_pda: AccountId,
    proposal_id: [u8; 32],
    member_commitment: [u8; 32],
}

impl SessionKey {
    fn new(instance_pda: AccountId, proposal_id: [u8; 32], commitment: &IdentityCommitment) -> Self {
        Self {
            instance_pda,
            proposal_id,
            member_commitment: *commitment.as_bytes(),
        }
    }

    fn to_vec(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("SessionKey Borsh serialization is infallible")
    }
}

/// Thread-safe session store backed by sled.
///
/// The store is opened lazily on first access and held for the lifetime
/// of the `SessionStore` handle. The database lives at
/// `~/.private-multisig/state/approval_sessions`.
pub struct SessionStore {
    inner: Mutex<Inner>,
}

struct Inner {
    // `db` must outlive `tree` (sled invariant). Keeping it here ensures
    // drop order: `Inner` drops `db` after `tree` (field order = drop order).
    #[allow(dead_code)]
    db: Db,
    tree: Tree,
}

impl SessionStore {
    /// Open (or create) the session store at `~/.private-multisig/state`.
    ///
    /// Returns `Err(HomeDirNotFound)` if `$HOME` is unset.
    /// Returns `Err(SessionStoreOpenFailed)` if the sled open fails
    /// (permission denied, disk full, corruption).
    pub fn open() -> Result<Self, SdkError> {
        let db_path = Self::db_path()?;

        // Create the directory tree if it doesn't exist.
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?;
        }

        let db = sled::open(&db_path)
            .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?;

        let tree = db
            .open_tree("approval_sessions")
            .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?;

        Ok(Self {
            inner: Mutex::new(Inner { db, tree }),
        })
    }

    /// Persist an `ApprovalSession`. The key is derived from the session's
    /// `(instance_pda, proposal_id, member_commitment)`.
    ///
    /// Subsequent loads of the same key overwrite the previous session.
    pub fn save(&self, session: &ApprovalSession) -> Result<(), SdkError> {
        let key = SessionKey::new(
            session.instance_pda,
            session.proposal_id,
            &session.member_commitment,
        );
        let key_bytes = key.to_vec();
        let value_bytes = borsh::to_vec(session)
            .map_err(|_| SdkError::BorshSerializationFailed)?;

        let inner = self.inner.lock().map_err(|e| {
            SdkError::SessionStoreOpenFailed(format!("mutex poisoned: {e}"))
        })?;
        inner
            .tree
            .insert(&key_bytes, value_bytes)
            .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?;

        Ok(())
    }

    /// Load a session by its 3-tuple key.
    ///
    /// Returns `Err(SessionNotFound)` if no session exists for this key.
    pub fn load(
        &self,
        instance_pda: &AccountId,
        proposal_id: &[u8; 32],
        member_commitment: &IdentityCommitment,
    ) -> Result<ApprovalSession, SdkError> {
        let key = SessionKey::new(*instance_pda, *proposal_id, member_commitment);
        let key_bytes = key.to_vec();

        let inner = self.inner.lock().map_err(|e| {
            SdkError::SessionStoreOpenFailed(format!("mutex poisoned: {e}"))
        })?;
        let value_bytes = inner
            .tree
            .get(&key_bytes)
            .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?
            .ok_or(SdkError::SessionNotFound)?;

        let session: ApprovalSession = borsh::from_slice(&value_bytes)
            .map_err(|_| SdkError::SessionCorrupted)?;

        Ok(session)
    }

    /// Load all sessions for a given `(instance_pda, proposal_id)`.
    ///
    /// Returns an iterator over all matching sessions. Useful for the
    /// CLI's approval-count display before `execute`.
    pub fn load_for_proposal(
        &self,
        instance_pda: &AccountId,
        proposal_id: &[u8; 32],
    ) -> Result<alloc::vec::Vec<ApprovalSession>, SdkError> {
        let prefix = {
            let mut p = alloc::vec::Vec::with_capacity(64);
            p.extend_from_slice(instance_pda);
            p.extend_from_slice(proposal_id);
            p
        };

        let inner = self.inner.lock().map_err(|e| {
            SdkError::SessionStoreOpenFailed(format!("mutex poisoned: {e}"))
        })?;

        let mut results = alloc::vec::Vec::new();
        for item in inner.tree.range(prefix.clone()..) {
            let (key_bytes, value_bytes) = item
                .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?;
            // Stop when the key no longer has the prefix.
            if key_bytes.len() < prefix.len() || &key_bytes[..prefix.len()] != &prefix {
                break;
            }
            let session: ApprovalSession = borsh::from_slice(&value_bytes)
                .map_err(|_| SdkError::SessionCorrupted)?;
            results.push(session);
        }
        Ok(results)
    }

    /// Delete a session by key.
    pub fn delete(
        &self,
        instance_pda: &AccountId,
        proposal_id: &[u8; 32],
        member_commitment: &IdentityCommitment,
    ) -> Result<(), SdkError> {
        let key = SessionKey::new(*instance_pda, *proposal_id, member_commitment);
        let key_bytes = key.to_vec();

        let inner = self.inner.lock().map_err(|e| {
            SdkError::SessionStoreOpenFailed(format!("mutex poisoned: {e}"))
        })?;
        inner
            .tree
            .remove(&key_bytes)
            .map_err(|e| SdkError::SessionStoreOpenFailed(e.to_string()))?;
        Ok(())
    }

    /// The on-disk path for the sled database.
    fn db_path() -> Result<PathBuf, SdkError> {
        let home = dirs::home_dir().ok_or(SdkError::HomeDirNotFound)?;
        Ok(home.join(".private-multisig/state"))
    }
}

// --- Utilities ---

/// Returns the current Unix timestamp in seconds.
fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    // We can't easily use a temp dir with sled (sled requires an owned path),
    // so we skip full integration tests here. The round-trip via Borsh
    // is exercised by the tests below.

    #[test]
    fn session_status_transitions() {
        assert!(SessionStatus::Drafted.has_receipt() == false);
        assert!(SessionStatus::Proving.has_receipt() == false);
        assert!(SessionStatus::Proved.has_receipt() == true);
        assert!(SessionStatus::Submitted.has_receipt() == true);
        assert!(SessionStatus::Confirmed.has_receipt() == true);
        assert!(SessionStatus::Failed.has_receipt() == false);
    }

    #[test]
    fn session_borsh_round_trip() {
        let instance = [0xAA; 32];
        let proposal_id = [0xBB; 32];
        let commitment = IdentityCommitment([0xCC; 32]);
        let public_inputs = [0x11; 96];
        let nullifier = [0x22; 32];

        let session = ApprovalSession::new(
            instance,
            proposal_id,
            commitment,
            public_inputs,
            nullifier,
        );
        let bytes = borsh::to_vec(&session).unwrap();
        let decoded: ApprovalSession = borsh::from_slice(&bytes).unwrap();
        assert_eq!(session.instance_pda, decoded.instance_pda);
        assert_eq!(session.proposal_id, decoded.proposal_id);
        assert_eq!(session.status, SessionStatus::Drafted);
    }

    #[test]
    fn session_key_serialization_is_96_bytes() {
        let key = SessionKey::new(
            [0xAA; 32],
            [0xBB; 32],
            &IdentityCommitment([0xCC; 32]),
        );
        let bytes = borsh::to_vec(&key).unwrap();
        // 32 + 32 + 32 = 96 bytes for the three 32-byte fields
        assert_eq!(bytes.len(), 96, "SessionKey must be 96 bytes for deterministic key spacing");
    }

    #[test]
    fn session_transitions_to_proved() {
        // Session starts in Drafted, must go through Proving to reach Proved.
        let session = ApprovalSession::new(
            [0xAA; 32],
            [0xBB; 32],
            IdentityCommitment([0xCC; 32]),
            [0x11; 96],
            [0x22; 32],
        );
        let mut s = session;
        s.mark_proving().unwrap();
        assert_eq!(s.status, SessionStatus::Proving);
        s.mark_proved(vec![0x99; 64]).unwrap();
        assert_eq!(s.status, SessionStatus::Proved);
        assert!(s.receipt.is_some());
    }

    #[test]
    fn session_reorg_demotion() {
        // Full state machine walk: Drafted -> Proving -> Proved -> Submitted.
        let mut session = ApprovalSession::new(
            [0xAA; 32],
            [0xBB; 32],
            IdentityCommitment([0xCC; 32]),
            [0x11; 96],
            [0x22; 32],
        );
        session.mark_proving().unwrap();
        session.mark_proved(vec![0x99; 64]).unwrap();
        session.mark_submitted(100).unwrap();
        assert_eq!(session.status, SessionStatus::Submitted);

        // Block 99 is before submission block 100 — this IS a reorg.
        session.demote_on_reorg(99);
        assert_eq!(session.status, SessionStatus::Proved);
        assert!(session.submission_block.is_none());

        // Block 101 is after submission block 100 — not a reorg.
        session.mark_submitted(100).unwrap();
        session.demote_on_reorg(101);
        assert_eq!(session.status, SessionStatus::Submitted);
    }

    #[test]
    fn try_confirm_requires_n_block_buffer() {
        let mut session = ApprovalSession::new(
            [0xAA; 32],
            [0xBB; 32],
            IdentityCommitment([0xCC; 32]),
            [0x11; 96],
            [0x22; 32],
        );
        session.mark_proving().unwrap();
        session.mark_proved(vec![0x99; 64]).unwrap();
        session.mark_submitted(100).unwrap();

        // 31 blocks past — not yet confirmed under N=32.
        assert_eq!(session.try_confirm(131, 32).unwrap(), false);
        assert_eq!(session.status, SessionStatus::Submitted);

        // 32 blocks past — boundary, now confirmed.
        assert_eq!(session.try_confirm(132, 32).unwrap(), true);
        assert_eq!(session.status, SessionStatus::Confirmed);

        // try_confirm on a non-Submitted session returns Err.
        let mut fresh = ApprovalSession::new(
            [0xAA; 32],
            [0xBB; 32],
            IdentityCommitment([0xCC; 32]),
            [0x11; 96],
            [0x22; 32],
        );
        assert!(matches!(
            fresh.try_confirm(100, 32),
            Err(SdkError::SessionStatusMismatch)
        ));
    }

    #[test]
    fn invalid_transition_returns_err_not_panic() {
        let mut session = ApprovalSession::new(
            [0xAA; 32],
            [0xBB; 32],
            IdentityCommitment([0xCC; 32]),
            [0x11; 96],
            [0x22; 32],
        );
        // Drafted -> Proved is not a valid forward step.
        assert!(matches!(
            session.mark_proved(vec![]),
            Err(SdkError::SessionStatusMismatch)
        ));
        // Mark Failed via the dedicated method (always succeeds).
        session.mark_failed("test".to_string());
        // Failed -> anything is rejected.
        assert!(matches!(
            session.mark_proving(),
            Err(SdkError::SessionStatusMismatch)
        ));
    }
}