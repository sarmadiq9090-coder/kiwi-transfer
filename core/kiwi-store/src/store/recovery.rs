//! The recovery pass run when a store is opened.
//!
//! A crash can leave two kinds of debris: temp files whose transfer never
//! finished, and a ledger that disagrees with the disk. The pass
//!
//! 1. compares every record believed intact with the disk (existence and
//!    size only; content is the integrity scan's job) and marks what is gone
//!    or obviously different, and
//! 2. deletes orphaned temp files, and
//! 3. walks the destination, never following a reparse point, to report what
//!    it finds there.
//!
//! # What is deleted, and why that can never be a stored file
//!
//! A file is deleted only if **all** of this holds:
//!
//! * the ledger has an intent row for it: the engine noted creating exactly
//!   this file as a temp file (the row is written after the file is created,
//!   and removed in the same transaction that records the commit, so a file
//!   that was committed has none, even if a power failure undid its rename
//!   and left it under its temp name);
//! * its name has the exact shape of a temp-file name, which no stored file
//!   can have (the sanitiser never produces a name starting with `.kiwi-`,
//!   and a ledger row carrying one is refused when it is read);
//! * no ledger record names its path;
//! * it does not belong to a transfer in progress;
//! * it is a plain file, reached through plain directories only.
//!
//! A file that merely *looks* like a temp file (somebody else made it, or its
//! intent row was lost) is reported in [`RecoveryReport::unowned_temps`] and
//! left alone.
//!
//! One crash window needs no repair here: a file that got its final name but
//! not its ledger record. It is complete and verified (it was renamed only
//! after verification); it is merely unknown. When the phone sends it again,
//! the commit finds the identical file and records it instead of storing a
//! second copy.

use std::path::{Path, PathBuf};

use super::pipeline::{is_temp_name, PRIMARY};
use super::scan::{CancelToken, ChangeEvidence, MissingIndex};
use super::verify::Probe;
use super::{lock, Inner, Store, STORE_DIR};
use crate::error::StoreError;
use crate::fsops::{DirEntryInfo, EntryKind};
use crate::ledger::{path_key, FileState};
use crate::sanitize::{collision_key, SafeName, SafeRelPath, MAX_DEPTH};

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
    /// Orphaned temp files that could not be deleted (they will be retried).
    pub orphan_temps_left: Vec<String>,
    /// Files that are named like temp files but that the engine has no
    /// record of creating. They are never deleted; listed so the user can
    /// decide. (At most 200 are listed; `unowned_temp_count` is complete.)
    pub unowned_temps: Vec<String>,
    /// How many such files there are.
    pub unowned_temp_count: u64,
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

/// One thing met while walking the destination.
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

/// What became of the temp files the ledger has intent rows for.
#[derive(Debug, Default)]
pub(crate) struct TempCleanup {
    pub removed: u64,
    pub removed_bytes: u64,
    /// Could not be deleted, or could not be reached safely; retried next time.
    pub left: Vec<String>,
}

impl Inner {
    /// Deletes the orphaned temp files at one location (the destination or a
    /// mirror): those the ledger has an intent row for. See the module
    /// documentation for why this cannot touch a stored file.
    pub(crate) fn clean_partials(
        &self,
        location: i64,
        root: &Path,
    ) -> Result<TempCleanup, StoreError> {
        let mut out = TempCleanup::default();
        for rel in self.ledger.partials(location)? {
            // The row is read from the ledger, which is not trusted: every
            // directory on the way must be a name the sanitiser would have
            // produced, and the file name must be a temp-file name.
            let mut parts: Vec<&str> = rel.split('/').collect();
            let name = parts.pop().unwrap_or("");
            let dirs: Option<Vec<SafeName>> =
                parts.iter().map(|p| SafeName::from_stored(p)).collect();
            let (Some(dirs), true) = (dirs, is_temp_name(name)) else {
                self.ledger.remove_partial(location, &rel)?;
                continue;
            };
            let dir_rel = SafeRelPath::from_components(dirs);
            let path = dir_rel.under(root).join(name);
            // A transfer in progress owns its temp file.
            if lock(&self.in_flight).temps.contains(&path) {
                continue;
            }
            // A path the ledger records as a stored file is never deleted,
            // whatever else is true. (It cannot happen; it is checked anyway.)
            if location == PRIMARY && self.ledger.path_key_exists(&path_key(&rel))? {
                self.ledger.remove_partial(location, &rel)?;
                continue;
            }
            // Only through plain directories: a link on the way could lead
            // the delete somewhere else.
            let mut dir = root.to_path_buf();
            let mut reachable = Some(true);
            for part in dir_rel.components() {
                dir.push(part.as_str());
                match self.fs.stat(&dir) {
                    Ok(Some(s)) if s.kind == EntryKind::Dir && !s.reparse => {}
                    Ok(None) => {
                        reachable = Some(false);
                        break;
                    }
                    _ => {
                        reachable = None;
                        break;
                    }
                }
            }
            let stat = match reachable {
                Some(true) => self.fs.stat(&path),
                // The directory is gone, and the temp file with it.
                Some(false) => Ok(None),
                None => {
                    if out.left.len() < MAX_LISTED {
                        out.left.push(rel);
                    }
                    continue;
                }
            };
            match stat {
                Ok(None) => self.ledger.remove_partial(location, &rel)?,
                Ok(Some(s)) if s.kind == EntryKind::File && !s.reparse => {
                    if self.delete_own_temp(&path) {
                        out.removed += 1;
                        out.removed_bytes += s.size;
                        self.ledger.remove_partial(location, &rel)?;
                    } else if out.left.len() < MAX_LISTED {
                        out.left.push(rel);
                    }
                }
                // Not a plain file (any more), or it cannot be examined.
                _ => {
                    if out.left.len() < MAX_LISTED {
                        out.left.push(rel);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Walks every directory below the root, skipping the engine's own
    /// bookkeeping directory and never entering a reparse point. Returns
    /// false if it was cancelled.
    pub(crate) fn walk(&self, cancel: &CancelToken, visit: &mut dyn FnMut(Visit<'_>)) -> bool {
        let store_dir_key = collision_key(STORE_DIR);
        let mut stack: Vec<(PathBuf, Vec<String>)> = vec![(self.root().to_path_buf(), Vec::new())];
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

        // 1. The ledger against the disk.
        let upper = ledger.max_file_id()?;
        let mut cursor = 0i64;
        let mut cancelled = false;
        'records: loop {
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

        // 2. Orphaned temp files: exactly those the ledger has an intent row for.
        if !cancelled && !cancel.is_cancelled() {
            let cleanup = inner.clean_partials(PRIMARY, inner.root())?;
            report.orphan_temps_removed = cleanup.removed;
            report.orphan_temp_bytes = cleanup.removed_bytes;
            report.orphan_temps_left = cleanup.left;
        }

        // 3. The disk: files that look like temp files but are not the
        //    engine's, and files that look like renamed copies of the ones
        //    just found missing. Nothing is deleted or adopted here.
        let missing = MissingIndex::new(&ledger.missing_since(started_seq)?);
        let mut ledger_error = None;
        let walked = cancelled
            || inner.walk(cancel, &mut |visit| match visit {
                Visit::File {
                    dir_rel,
                    dir_abs,
                    entry,
                } => {
                    if is_temp_name(&entry.name) {
                        let path = dir_abs.join(&entry.name);
                        let rel = join_rel(dir_rel, &entry.name);
                        // A transfer in progress owns its temp file; one that
                        // still has its intent row was listed above.
                        if lock(&inner.in_flight).temps.contains(&path)
                            || report.orphan_temps_left.contains(&rel)
                        {
                            return;
                        }
                        match ledger.has_partial(PRIMARY, &rel) {
                            Ok(true) => {}
                            Ok(false) => {
                                report.unowned_temp_count += 1;
                                if report.unowned_temps.len() < MAX_LISTED {
                                    report.unowned_temps.push(rel);
                                }
                            }
                            Err(e) => ledger_error = Some(e),
                        }
                    } else if !missing.is_empty() && ledger_error.is_none() {
                        let dir_key = path_key(&dir_rel.join("/"));
                        if missing.is_rename_suspect(&dir_key, &entry.name) {
                            match ledger.path_key_exists(&path_key(&join_rel(dir_rel, &entry.name)))
                            {
                                Ok(true) => {}
                                Ok(false) => report.rename_suspects += 1,
                                Err(e) => ledger_error = Some(e),
                            }
                        }
                    }
                }
                Visit::Reparse { rel } => {
                    if report.reparse_points_skipped.len() < MAX_LISTED {
                        report.reparse_points_skipped.push(rel);
                    }
                }
                Visit::Unreadable { rel, error } => {
                    if report.unreadable_dirs.len() < MAX_LISTED {
                        report.unreadable_dirs.push(format!("{rel}: {error}"));
                    }
                }
            });
        if let Some(e) = ledger_error {
            return Err(e.into());
        }
        report.completed = walked && !cancelled;

        evidence.checked = report.records_checked;
        evidence.missing = report.newly_missing;
        evidence.changed = report.newly_changed;
        evidence.rename_suspects = report.rename_suspects;
        report.mass_change = inner.judge_mass_change(&evidence)?;

        let summary = format!(
            "temps removed {} ({} bytes), unowned temp-like files left alone {}, records checked {}, missing {}, changed {}, rename-suspects {}, reparse points {}",
            report.orphan_temps_removed,
            report.orphan_temp_bytes,
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
