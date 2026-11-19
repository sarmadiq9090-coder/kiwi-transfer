//! What the store knows about a file beyond "it was committed": where it
//! stands in a final move, and the look-ups the transfer layer needs to talk
//! to a phone about its own files.
//!
//! Everything here is **per device**. A phone is only ever told about the
//! records of its own link, which lie inside its own folder.

use std::path::PathBuf;

use super::verify::Probe;
use super::{DeviceId, Store};
use crate::error::StoreError;
use crate::fsops::EntryKind;
use crate::hash::ContentHash;
use crate::ledger::{FileRecord, FileState, FmState};
use crate::sanitize::SafeRelPath;

/// A ledger record of one stored file, as the ledger believes it to be.
/// Nothing in here has been checked against the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    /// Ledger row.
    pub file_id: i64,
    /// The device the file belongs to.
    pub device: String,
    /// The item key the phone gave it.
    pub key: Vec<u8>,
    /// Content hash recorded at commit.
    pub hash: ContentHash,
    /// Size in bytes.
    pub size: u64,
    /// The device's commit number for it (what the receipt carried).
    pub commit_seq: u64,
    /// The device's session in which it was committed.
    pub session_seq: u64,
    /// Wall-clock time of the commit (Unix milliseconds).
    pub committed_unix_ms: i64,
    /// Path relative to the destination root.
    pub rel_path: String,
    /// Absolute path.
    pub abs_path: PathBuf,
    /// The name the phone sent, before sanitising.
    pub source_name: String,
    /// What the last check believed about the file on disk.
    pub state: FileState,
    /// Where it stands in a final move.
    pub fm: FmState,
    /// When the phone's trash lets go of its copy, if the phone said.
    pub fm_expires_unix_ms: Option<i64>,
}

/// Answer of [`Store::audit`]: a look at the record and at the directory
/// entry, without reading the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditStatus {
    /// The record exists and a plain file of the recorded size is at its path.
    Present(StoredRecord),
    /// This device has no record of this item.
    NoRecord,
    /// The record exists, but its file is gone or is not a plain file of the
    /// recorded size. The ledger has been told, and final move is blocked,
    /// exactly as when a scan finds it.
    Damaged(StoredRecord),
    /// The PC user acknowledged that this file was removed.
    Removed(StoredRecord),
}

impl Store {
    pub(crate) fn stored_record(&self, rec: FileRecord) -> StoredRecord {
        let abs_path = match SafeRelPath::from_stored(&rec.rel_path) {
            Some(rel) => rel.under(self.inner.root()),
            None => PathBuf::new(),
        };
        StoredRecord {
            file_id: rec.id,
            device: rec.device,
            key: rec.key,
            hash: rec.hash,
            size: rec.size,
            commit_seq: rec.commit_no,
            session_seq: rec.committed_session,
            committed_unix_ms: rec.committed_unix_ms,
            rel_path: rec.rel_path,
            abs_path,
            source_name: rec.source_name,
            state: rec.state,
            fm: rec.fm,
            fm_expires_unix_ms: rec.fm_expires_unix_ms,
        }
    }

    /// The records this device has for this content hash, oldest first.
    /// Ledger only: nothing is read from the disk. This is the look-up for
    /// re-anchoring (a phone whose receipts are void asks for its item by
    /// hash and size) and never returns another device's records.
    pub fn records(
        &self,
        device: &DeviceId,
        hash: &ContentHash,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        Ok(self
            .inner
            .ledger
            .device_files_by_hash(device.as_str(), hash)?
            .into_iter()
            .map(|rec| self.stored_record(rec))
            .collect())
    }

    /// The files of one device in a given final-move state: with
    /// [`FmState::SoleCopy`], the files this PC holds the only copy of; with
    /// [`FmState::Reverified`], the ones that may be the only copy.
    pub fn records_in_state(
        &self,
        device: &DeviceId,
        state: FmState,
    ) -> Result<Vec<StoredRecord>, StoreError> {
        Ok(self
            .inner
            .ledger
            .device_files_in_fm_state(device.as_str(), state)?
            .into_iter()
            .map(|rec| self.stored_record(rec))
            .collect())
    }

    /// Notes that the phone reported its copy of an item trashed or gone:
    /// the stored file is the only copy from now on. `expires_unix_ms` is
    /// when the phone's trash lets go of it, if the phone said. Returns how
    /// many records of this device matched (item key and hash).
    pub fn mark_sole_copy(
        &self,
        device: &DeviceId,
        key: &[u8],
        hash: &ContentHash,
        expires_unix_ms: Option<i64>,
    ) -> Result<u64, StoreError> {
        self.set_fm(device, key, hash, FmState::SoleCopy, expires_unix_ms)
    }

    /// Notes that the phone named an item as still in place (it offered it
    /// again, audited it, or restored it from its trash): the stored file is
    /// an ordinary copy again. A file the PC user acknowledged as removed
    /// stays that. Returns how many records matched.
    pub fn mark_in_place(
        &self,
        device: &DeviceId,
        key: &[u8],
        hash: &ContentHash,
    ) -> Result<u64, StoreError> {
        self.set_fm(device, key, hash, FmState::None, None)
    }

    fn set_fm(
        &self,
        device: &DeviceId,
        key: &[u8],
        hash: &ContentHash,
        state: FmState,
        expires_unix_ms: Option<i64>,
    ) -> Result<u64, StoreError> {
        let inner = &self.inner;
        let mut changed = 0;
        for rec in inner.ledger.device_files_by_hash(device.as_str(), hash)? {
            if rec.key != key || rec.fm == FmState::UserRemoved {
                continue;
            }
            if rec.fm == state && rec.fm_expires_unix_ms == expires_unix_ms {
                changed += 1;
                continue;
            }
            let detail = match expires_unix_ms {
                Some(at) => format!("reported by the phone; its trash expires at {at}"),
                None => "reported by the phone".to_owned(),
            };
            if inner
                .ledger
                .set_fm_state(rec.id, state, expires_unix_ms, &detail, inner.now())?
            {
                changed += 1;
            }
        }
        Ok(changed)
    }

    /// The PC user acknowledges that a missing or changed file was removed,
    /// changed on purpose, or is lost. Nothing is confirmed for it from then
    /// on ([`DeletionDenied::RemovedByUser`](super::DeletionDenied)), and it
    /// no longer counts as a file without a copy. The file, if there is one,
    /// is not touched. Refused (false) for a file that is believed intact:
    /// only a known problem can be acknowledged.
    pub fn acknowledge_removed(&self, file_id: i64, note: &str) -> Result<bool, StoreError> {
        let inner = &self.inner;
        match inner.ledger.file_by_id(file_id)? {
            Some(rec) if rec.state != FileState::Committed => Ok(inner.ledger.set_fm_state(
                file_id,
                FmState::UserRemoved,
                None,
                note,
                inner.now(),
            )?),
            _ => Ok(false),
        }
    }

    /// A metadata-only check of one item of one device: is there a record,
    /// and is a plain file of the recorded size at its path? The file is not
    /// read. This is what lets a phone find out that a plain copy (which
    /// nothing else ever re-checks for it) is no longer on the PC.
    pub fn audit(
        &self,
        device: &DeviceId,
        key: &[u8],
        hash: &ContentHash,
        size: u64,
    ) -> Result<AuditStatus, StoreError> {
        let inner = &self.inner;
        let mut damaged = None;
        for rec in inner.ledger.device_files_by_hash(device.as_str(), hash)? {
            if rec.key != key || rec.size != size {
                continue;
            }
            if rec.fm == FmState::UserRemoved {
                return Ok(AuditStatus::Removed(self.stored_record(rec)));
            }
            let finding = match SafeRelPath::from_stored(&rec.rel_path) {
                None => Probe::InvalidRecord,
                Some(rel) => match inner.fs.stat(&rel.under(inner.root())) {
                    Ok(Some(s)) if s.reparse => Probe::Reparse(rel.under(inner.root())),
                    Ok(Some(s)) if s.kind == EntryKind::File && s.size == rec.size => {
                        return Ok(AuditStatus::Present(self.stored_record(rec)));
                    }
                    Ok(Some(_)) => {
                        Probe::Changed("it is no longer a plain file of that size".to_owned())
                    }
                    Ok(None) => Probe::Missing,
                    // Unknown is not "missing": say nothing about this record.
                    Err(_) => continue,
                },
            };
            inner.apply_probe(&rec, &finding)?;
            damaged = Some(rec);
        }
        Ok(match damaged {
            Some(rec) => AuditStatus::Damaged(self.stored_record(rec)),
            None => AuditStatus::NoRecord,
        })
    }
}
