//! The recovery pass run when a store is opened.
//!
//! A crash can leave two kinds of debris: temp files whose transfer never
//! finished, and a ledger that disagrees with the disk. The pass
//!
//! 1. compares every record believed intact with the disk (existence and
//!    size only; content is the integrity scan's job) and marks what is gone
//!    or obviously different, and
//! 2. walks the destination, never following a reparse point, and deletes
//!    orphaned temp files.
//!
//! The pass deletes nothing but files carrying the engine's temp-file name,
//! and never one that belongs to a transfer in progress.
//!
//! One crash window needs no repair here: a file that got its final name but
//! not its ledger record. It is complete and verified (it was renamed only
//! after verification); it is merely unknown. When the phone sends it again,
//! the commit finds the identical file and records it instead of storing a
//! second copy.

use std::path::{Path, PathBuf};

use super::incoming::is_temp_name;
use super::scan::{CancelToken, ChangeEvidence, MissingIndex};
use super::verify::Probe;
use super::{lock, Inner, Store, STORE_DIR};
use crate::error::StoreError;
use crate::fsops::{DirEntryInfo, EntryKind};
use crate::ledger::{path_key, FileState};
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
    /// Orphaned temp files that could not be deleted (they will be retried).
    pub orphan_temps_left: Vec<String>,
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

impl Inner {
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

        // 2. The disk: orphaned temp files, and files that look like renamed
        //    copies of the ones just found missing.
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
                        if !entry.exact {
                            return;
                        }
                        let path = dir_abs.join(&entry.name);
                        // A transfer in progress owns its temp file.
                        if lock(&inner.in_flight).temps.contains(&path) {
                            return;
                        }
                        match inner.fs.remove_file(&path) {
                            Ok(()) => {
                                report.orphan_temps_removed += 1;
                                report.orphan_temp_bytes += entry.stat.size;
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                            Err(_) => {
                                if report.orphan_temps_left.len() < MAX_LISTED {
                                    report
                                        .orphan_temps_left
                                        .push(join_rel(dir_rel, &entry.name));
                                }
                            }
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
            "temps removed {} ({} bytes), records checked {}, missing {}, changed {}, rename-suspects {}, reparse points {}",
            report.orphan_temps_removed,
            report.orphan_temp_bytes,
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
