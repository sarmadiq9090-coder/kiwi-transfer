//! The recovery pass run when a store is opened.
//!
//! A crash can leave two kinds of debris: temp files whose transfer never
//! finished, and a ledger that disagrees with the disk. The pass
//!
//! 1. walks the destination, never following a reparse point, and deals with
//!    every temp file it finds (see below);
//! 2. compares every record believed intact with the disk (existence and
//!    size only; content is the integrity scan's job) and marks what is gone
//!    or obviously different; and
//! 3. if files were found missing, walks once more to count the unknown
//!    files that look like renamed copies of them.
//!
//! # What is deleted, and why that can never be a stored file
//!
//! The engine deletes nothing but its own temp files, and a temp file is
//! deleted only if **all** of this holds:
//!
//! * its name is exactly `.kiwi-tmp-<tag>-<n>-<random>.part`, a name no
//!   stored file can have (the sanitiser never produces a name starting with
//!   `.kiwi-`, and a ledger row carrying one is refused when it is read);
//! * `<tag>` is a tag recorded in this ledger: every run of the store draws a
//!   random tag and writes it to the ledger, flushed, before it creates its
//!   first temp file. A look-alike made by anything else has no such tag;
//! * it is a plain file, reached through plain directories, inside the root;
//! * it does not belong to a transfer in progress;
//! * **it is not a committed file whose rename was lost.** If a record of the
//!   same size is without its file, the temp file is read and hashed first.
//!   If it has the hash of such a record in its own directory it *is* that
//!   file (a drive acknowledged a flush it had not done, and the rename did
//!   not survive the power failure): it is given its final name again. If it
//!   has the hash of a missing file elsewhere, it is kept. Only a temp file
//!   that holds no missing committed content is deleted.
//!
//! A file that merely looks like a temp file (unknown tag) is reported in
//! [`RecoveryReport::unowned_temps`] and left alone.
//!
//! One crash window needs no repair here: a file that got its final name but
//! not its ledger record. It is complete and verified (it was renamed only
//! after verification); it is merely unknown. When the phone sends it again,
//! the commit finds the identical file and records it instead of storing a
//! second copy.

use std::ops::ControlFlow;
use std::path::{Path, PathBuf};

use super::pipeline::{temp_tag_of, PRIMARY};
use super::scan::{CancelToken, ChangeEvidence, MissingIndex};
use super::verify::Probe;
use super::{lock, Inner, Store, STORE_DIR};
use crate::error::StoreError;
use crate::fsops::{DirEntryInfo, EntryKind};
use crate::hash::ContentHash;
use crate::ledger::{path_key, FileRecord, FileState, MirrorFileRow, MirrorFileState};
use crate::sanitize::{collision_key, SafeRelPath, MAX_DEPTH};

/// Most paths listed individually in a [`RecoveryReport`].
const MAX_LISTED: usize = 200;

/// What the recovery pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecoveryReport {
    /// The pass ran to the end (it was not cancelled).
    pub completed: bool,
    /// Orphaned temp files deleted.
    pub orphan_temps_removed: u64,
    /// Their total size.
    pub orphan_temp_bytes: u64,
    /// Orphaned temp files that could not be deleted or judged (they will be
    /// looked at again next time).
    pub orphan_temps_left: Vec<String>,
    /// Files that are named like temp files but do not carry a tag of this
    /// ledger: not the engine's. They are never deleted; listed so the user
    /// can decide. (At most 200 are listed; `unowned_temp_count` is complete.)
    pub unowned_temps: Vec<String>,
    /// How many such files there are.
    pub unowned_temp_count: u64,
    /// Committed files that were found under their temp name (the rename had
    /// been lost) and were given their final name again.
    pub renames_recreated: Vec<String>,
    /// Reparse points found in the destination. They were not followed.
    pub reparse_points_skipped: Vec<String>,
    /// Directories that could not be listed.
    pub unreadable_dirs: Vec<String>,
    /// Ledger records compared with the disk.
    pub records_checked: u64,
    /// Records whose file is gone.
    pub newly_missing: u64,
    /// Records whose file is no longer a regular file of the recorded size.
    pub newly_changed: u64,
    /// Unknown files that look like renamed copies of missing ones.
    pub rename_suspects: u64,
    /// The findings were judged a mass change (ransomware-like).
    pub mass_change: bool,
}

/// One thing met while walking a tree.
pub(crate) enum Visit<'a> {
    /// A regular file.
    File {
        dir_rel: &'a [String],
        dir_abs: &'a Path,
        entry: &'a DirEntryInfo,
    },
    /// A reparse point (file or directory). It is reported, never entered.
    Reparse { rel: String },
    /// A directory that could not be listed, or is nested absurdly deep.
    Unreadable { rel: String, error: String },
}

fn join_rel(dir_rel: &[String], name: &str) -> String {
    if dir_rel.is_empty() {
        name.to_owned()
    } else {
        format!("{}/{}", dir_rel.join("/"), name)
    }
}

/// What became of one temp-named file.
pub(crate) enum TempFate {
    /// Not the engine's (unknown tag, or a name that is not exactly the
    /// on-disk name). Left alone.
    Unowned,
    /// Belongs to a transfer in progress. Left alone.
    InUse,
    /// Deleted; the size it had.
    Deleted(u64),
    /// It was a committed file whose rename had been lost; it has its final
    /// name again (the path relative to the root).
    Recreated(String),
    /// Could not be deleted or judged. Left for next time.
    Left,
}

/// What a sweep over one tree did with the temp files it found.
#[derive(Debug, Default)]
pub(crate) struct TempSweep {
    /// The walk ran to the end.
    pub completed: bool,
    pub removed: u64,
    pub removed_bytes: u64,
    pub left: Vec<String>,
    pub unowned: Vec<String>,
    pub unowned_count: u64,
    pub recreated: Vec<String>,
    pub reparse_points: Vec<String>,
    pub unreadable_dirs: Vec<String>,
}

/// A record that is without its file and could be what a temp file really is.
enum Lost {
    Primary(FileRecord),
    Mirror(MirrorFileRow, ContentHash),
}

impl Lost {
    fn rel_path(&self) -> &str {
        match self {
            Lost::Primary(rec) => &rec.rel_path,
            Lost::Mirror(row, _) => &row.rel_path,
        }
    }

    fn hash(&self) -> &ContentHash {
        match self {
            Lost::Primary(rec) => &rec.hash,
            Lost::Mirror(_, hash) => hash,
        }
    }
}

impl Inner {
    /// Walks every directory below `root` (the destination or a mirror),
    /// skipping the engine's own bookkeeping directory and never entering a
    /// reparse point. Returns false if it was cancelled.
    pub(crate) fn walk(
        &self,
        root: &Path,
        cancel: &CancelToken,
        visit: &mut dyn FnMut(Visit<'_>),
    ) -> bool {
        let store_dir_key = collision_key(STORE_DIR);
        let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(root.to_path_buf(), Vec::new())];
        while let Some((dir_abs, dir_rel)) = stack.pop() {
            if cancel.is_cancelled() {
                return false;
            }
            let entries = match self.fs.list_dir(&dir_abs) {
                Ok(entries) => entries,
                Err(e) => {
                    visit(Visit::Unreadable {
                        rel: dir_rel.join("/"),
                        error: e.to_string(),
                    });
                    continue;
                }
            };
            for entry in &entries {
                if dir_rel.is_empty() && collision_key(&entry.name) == store_dir_key {
                    continue;
                }
                if entry.stat.reparse {
                    visit(Visit::Reparse {
                        rel: join_rel(&dir_rel, &entry.name),
                    });
                    continue;
                }
                match entry.stat.kind {
                    EntryKind::Dir => {
                        if dir_rel.len() >= MAX_DEPTH + 8 {
                            let rel = join_rel(&dir_rel, &entry.name);
                            visit(Visit::Unreadable {
                                rel,
                                error: "nested too deeply; not entered".to_owned(),
                            });
                            continue;
                        }
                        let mut child_rel = dir_rel.clone();
                        child_rel.push(entry.name.clone());
                        stack.push((dir_abs.join(&entry.name), child_rel));
                    }
                    EntryKind::File => visit(Visit::File {
                        dir_rel: &dir_rel,
                        dir_abs: &dir_abs,
                        entry,
                    }),
                    EntryKind::Other => {}
                }
            }
        }
        true
    }

    /// The records at `location` whose file has this size and is not where
    /// it should be; with each, whether it should be in this directory.
    fn lost_with_size(
        &self,
        location: i64,
        root: &Path,
        dir_key: &str,
        size: u64,
    ) -> Result<Vec<(Lost, bool)>, StoreError> {
        let mut candidates = Vec::new();
        if location == PRIMARY {
            for rec in self.ledger.files_with_size(size)? {
                candidates.push(Lost::Primary(rec));
            }
        } else {
            for row in self.ledger.mirror_rows_with_size(location, size)? {
                if let Some(rec) = self.ledger.file_by_id(row.file_id)? {
                    candidates.push(Lost::Mirror(row, rec.hash));
                }
            }
        }
        let mut lost = Vec::new();
        for candidate in candidates {
            let Some(rel) = SafeRelPath::from_stored(candidate.rel_path()) else {
                continue;
            };
            // "Without its file": anything but a positive "it is there".
            if !matches!(self.fs.stat(&rel.under(root)), Ok(Some(_))) {
                let here = rel.parent().collision_key() == dir_key;
                lost.push((candidate, here));
            }
        }
        Ok(lost)
    }

    /// Applies the deletion rule (see the module documentation) to one
    /// temp-named regular file that a walk came across.
    pub(crate) fn dispose_of_temp(
        &self,
        location: i64,
        root: &Path,
        dir_rel: &[String],
        dir_abs: &Path,
        entry: &DirEntryInfo,
    ) -> Result<TempFate, StoreError> {
        let own = entry.exact
            && temp_tag_of(&entry.name).is_some_and(|tag| lock(&self.known_tags).contains(tag));
        if !own {
            return Ok(TempFate::Unowned);
        }
        let path = dir_abs.join(&entry.name);
        if lock(&self.in_flight).temps.contains(&path) {
            return Ok(TempFate::InUse);
        }
        if entry.stat.kind != EntryKind::File || entry.stat.reparse {
            return Ok(TempFate::Left);
        }
        let size = entry.stat.size;

        // Never delete while a record of this size is without its file:
        // read and hash the temp file first.
        let dir_key = path_key(&dir_rel.join("/"));
        let lost = self.lost_with_size(location, root, &dir_key, size)?;
        if !lost.is_empty() {
            let mut hasher = blake3::Hasher::new();
            let read = self.fs.read_verify(&path, &mut |chunk| {
                hasher.update(chunk);
                ControlFlow::Continue(())
            });
            let hash = match read {
                Ok(r) if r.completed && r.bytes == size => ContentHash::from(hasher.finalize()),
                // It cannot be judged now; it is certainly not deleted.
                _ => return Ok(TempFate::Left),
            };
            let matching = || lost.iter().filter(|(l, _)| *l.hash() == hash);
            if let Some((found, _)) = matching().find(|(_, here)| *here) {
                // It is that committed file. Give it its final name again:
                // create-new, flushed, and confirmed under that name.
                let Some(rel) = SafeRelPath::from_stored(found.rel_path()) else {
                    return Ok(TempFate::Left);
                };
                let target = rel.under(root);
                if self.fs.rename_noreplace(&path, &target).is_err() {
                    return Ok(TempFate::Left);
                }
                let _ = self.fs.sync_file(&target);
                let _ = self.fs.sync_dir(dir_abs);
                if self.confirm_in_place(&target, size, &hash).is_err() {
                    // Under its final name now, but not confirmed: the record
                    // is left as it is for the scan to judge.
                    return Ok(TempFate::Left);
                }
                let detail = format!(
                    "{} was found as {} (its rename had been lost) and was given its name again",
                    found.rel_path(),
                    entry.name
                );
                match found {
                    Lost::Primary(rec) => {
                        self.ledger
                            .record_rename_recreated(rec, &detail, self.now())?;
                    }
                    Lost::Mirror(row, _) => {
                        self.ledger.set_mirror_file_state(
                            row.mirror_id,
                            row.file_id,
                            MirrorFileState::Verified,
                            &detail,
                            self.now(),
                        )?;
                        self.ledger.log_event(
                            "mirror_rename_recreated",
                            None,
                            Some(row.file_id),
                            Some(&detail),
                            self.now(),
                        )?;
                    }
                }
                return Ok(TempFate::Recreated(found.rel_path().to_owned()));
            }
            // The bytes of a committed file that is missing somewhere else:
            // not a lost rename (a temp file lies next to its final name),
            // but not something to throw away either. It stays.
            if matching().next().is_some() {
                return Ok(TempFate::Left);
            }
        }

        if self.delete_own_temp(&path) {
            Ok(TempFate::Deleted(size))
        } else {
            Ok(TempFate::Left)
        }
    }

    /// Walks one tree and applies the deletion rule to every temp-named file.
    pub(crate) fn sweep_temps(
        &self,
        location: i64,
        root: &Path,
        cancel: &CancelToken,
    ) -> Result<TempSweep, StoreError> {
        let mut sweep = TempSweep::default();
        let mut failure: Option<StoreError> = None;
        sweep.completed = self.walk(root, cancel, &mut |visit| match visit {
            Visit::File {
                dir_rel,
                dir_abs,
                entry,
            } => {
                if failure.is_some() || temp_tag_of(&entry.name).is_none() {
                    return;
                }
                let rel = join_rel(dir_rel, &entry.name);
                match self.dispose_of_temp(location, root, dir_rel, dir_abs, entry) {
                    Ok(TempFate::Unowned) => {
                        sweep.unowned_count += 1;
                        if sweep.unowned.len() < MAX_LISTED {
                            sweep.unowned.push(rel);
                        }
                    }
                    Ok(TempFate::InUse) => {}
                    Ok(TempFate::Deleted(size)) => {
                        sweep.removed += 1;
                        sweep.removed_bytes += size;
                    }
                    Ok(TempFate::Recreated(final_rel)) => {
                        if sweep.recreated.len() < MAX_LISTED {
                            sweep.recreated.push(final_rel);
                        }
                    }
                    Ok(TempFate::Left) => {
                        if sweep.left.len() < MAX_LISTED {
                            sweep.left.push(rel);
                        }
                    }
                    Err(e) => failure = Some(e),
                }
            }
            Visit::Reparse { rel } => {
                if sweep.reparse_points.len() < MAX_LISTED {
                    sweep.reparse_points.push(rel);
                }
            }
            Visit::Unreadable { rel, error } => {
                if sweep.unreadable_dirs.len() < MAX_LISTED {
                    sweep.unreadable_dirs.push(format!("{rel}: {error}"));
                }
            }
        });
        match failure {
            Some(e) => Err(e),
            None => Ok(sweep),
        }
    }
}

impl Store {
    /// Runs the recovery pass. [`Store::open`] does this unless
    /// [`StoreConfig::defer_recovery`](super::StoreConfig::defer_recovery) is
    /// set. It is safe to run while files are being received.
    pub fn run_recovery(&self, cancel: &CancelToken) -> Result<RecoveryReport, StoreError> {
        let inner = &self.inner;
        let ledger = &inner.ledger;
        let mut report = RecoveryReport::default();
        let mut evidence = ChangeEvidence::default();
        let started_seq = ledger.log_event("recovery_started", None, None, None, inner.now())?;

        // 1. Temp files first: a committed file whose rename was lost must
        //    get its name back before step 2 would call it missing.
        let sweep = inner.sweep_temps(PRIMARY, inner.root(), cancel)?;
        report.orphan_temps_removed = sweep.removed;
        report.orphan_temp_bytes = sweep.removed_bytes;
        report.orphan_temps_left = sweep.left;
        report.unowned_temps = sweep.unowned;
        report.unowned_temp_count = sweep.unowned_count;
        report.renames_recreated = sweep.recreated;
        report.reparse_points_skipped = sweep.reparse_points;
        report.unreadable_dirs = sweep.unreadable_dirs;
        let mut cancelled = !sweep.completed;

        // 2. The ledger against the disk.
        let upper = ledger.max_file_id()?;
        let mut cursor = 0i64;
        'records: loop {
            if cancelled {
                break;
            }
            let batch = ledger.files_after(cursor, upper, 256)?;
            if batch.is_empty() {
                break;
            }
            for rec in &batch {
                if cancel.is_cancelled() {
                    cancelled = true;
                    break 'records;
                }
                cursor = rec.id;
                if rec.state != FileState::Committed {
                    continue;
                }
                report.records_checked += 1;
                let Some(rel) = SafeRelPath::from_stored(&rec.rel_path) else {
                    inner.apply_probe(rec, &Probe::InvalidRecord)?;
                    continue;
                };
                let finding = match inner.fs.stat(&rel.under(inner.root())) {
                    // Unknown is not "missing": leave the record alone.
                    Err(_) => continue,
                    Ok(None) => Probe::Missing,
                    // A link where the file was is the scan's business (it checks the whole chain).
                    Ok(Some(s)) if s.reparse => continue,
                    Ok(Some(s)) if s.kind != EntryKind::File => {
                        Probe::Changed("the path is no longer a regular file".to_owned())
                    }
                    Ok(Some(s)) if s.size != rec.size => {
                        evidence.note_changed_mtime(s.mtime);
                        Probe::Changed(format!(
                            "its size is {} bytes instead of {}",
                            s.size, rec.size
                        ))
                    }
                    Ok(Some(_)) => continue,
                };
                match finding {
                    Probe::Missing => report.newly_missing += 1,
                    _ => report.newly_changed += 1,
                }
                inner.apply_probe(rec, &finding)?;
            }
        }

        // 3. Files that look like renamed copies of the ones just found
        //    missing. Nothing is adopted: an unknown file is only counted.
        let missing = MissingIndex::new(&ledger.missing_since(started_seq)?);
        if !cancelled && !missing.is_empty() {
            let mut ledger_error = None;
            let walked = inner.walk(inner.root(), cancel, &mut |visit| {
                if let Visit::File { dir_rel, entry, .. } = visit {
                    if ledger_error.is_some() || temp_tag_of(&entry.name).is_some() {
                        return;
                    }
                    let dir_key = path_key(&dir_rel.join("/"));
                    if missing.is_rename_suspect(&dir_key, &entry.name) {
                        match ledger.path_key_exists(&path_key(&join_rel(dir_rel, &entry.name))) {
                            Ok(true) => {}
                            Ok(false) => report.rename_suspects += 1,
                            Err(e) => ledger_error = Some(e),
                        }
                    }
                }
            });
            if let Some(e) = ledger_error {
                return Err(e.into());
            }
            cancelled = !walked;
        }
        report.completed = !cancelled;

        evidence.checked = report.records_checked;
        evidence.missing = report.newly_missing;
        evidence.changed = report.newly_changed;
        evidence.rename_suspects = report.rename_suspects;
        report.mass_change = inner.judge_mass_change(&evidence)?;

        let summary = format!(
            "temps removed {} ({} bytes), lost renames made again {}, temp-like files of others left alone {}, records checked {}, missing {}, changed {}, rename-suspects {}, reparse points {}",
            report.orphan_temps_removed,
            report.orphan_temp_bytes,
            report.renames_recreated.len(),
            report.unowned_temp_count,
            report.records_checked,
            report.newly_missing,
            report.newly_changed,
            report.rename_suspects,
            report.reparse_points_skipped.len()
        );
        ledger.log_event("recovery_finished", None, None, Some(&summary), inner.now())?;
        // Cached directory listings predate the clean-up.
        inner.forget_all_names();
        *lock(&inner.recovery) = Some(report.clone());
        Ok(report)
    }
}
