//! The integrity scan: re-read every recorded file and compare.
//!
//! The scan walks the ledger in row order, re-hashes each file from disk
//! (unbuffered where the platform allows), and then walks the destination
//! looking for files the ledger does not know. It can be rate-limited,
//! cancelled at any point and resumed later, also after a restart: progress
//! is kept in the ledger.
//!
//! Anything wrong sets the persistent final-move block. Many problems at once
//! are labelled as a mass change (what ransomware, a failing disk or a bad
//! sync tool look like from here), so the application can word its warning
//! accordingly.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use super::incoming::is_temp_name;
use super::recovery::Visit;
use super::verify::Probe;
use super::{Inner, Store};
use crate::error::StoreError;
use crate::ledger::{path_key, BlockInfo, BlockKind, FileState, ScanState};
use crate::sanitize::collision_key;

/// Most findings listed individually in one [`ScanReport`]. Counts are
/// always complete.
pub const MAX_LISTED_FINDINGS: usize = 1_000;

/// A flag that asks a long-running operation to stop. Clones share the flag.
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    /// A token that has not been cancelled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks the operation to stop as soon as it can.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether [`CancelToken::cancel`] has been called.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What the integrity checks treat as alarming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanPolicy {
    /// A recorded file that has disappeared blocks final move. A file whose
    /// *content* changed always blocks; this switch is only about deletions.
    pub block_on_missing: bool,
    /// This many files changed or suspiciously renamed in one check is a mass change.
    pub mass_change_min_files: u64,
    /// This many files missing in one check is a mass change, if it is also
    /// at least `mass_missing_min_percent` of the files checked.
    pub mass_missing_min_percent: u8,
    /// This many changed files whose on-disk modification times fall within
    /// `burst_window_secs` of each other is a mass change.
    pub burst_min_files: u64,
    /// See `burst_min_files`.
    pub burst_window_secs: u64,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        ScanPolicy {
            block_on_missing: true,
            mass_change_min_files: 10,
            mass_missing_min_percent: 5,
            burst_min_files: 5,
            burst_window_secs: 600,
        }
    }
}

/// How to run a scan.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    /// Read at most this many bytes per second (averaged over the call).
    pub max_bytes_per_sec: Option<u64>,
    /// Stop after checking this many files in this call; the scan stays resumable.
    pub max_files: Option<u64>,
    /// Discard saved progress and start from the first record.
    pub restart: bool,
    /// Do not look for files the ledger does not know.
    pub skip_unexpected: bool,
}

/// What kind of thing a scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// A recorded file is gone.
    Missing,
    /// A recorded file has different content.
    Changed,
    /// A recorded file could not be read.
    Unreadable,
    /// A reparse point (junction, link) inside the destination.
    ReparsePoint,
    /// A recorded file's data is not on the local disk.
    NotLocal,
    /// A ledger row that does not describe a valid path.
    InvalidRecord,
    /// A file in the destination that the ledger does not know.
    Unexpected,
    /// An unknown file that looks like a renamed copy of a missing one.
    RenameSuspect,
    /// A file previously marked missing or changed is intact again.
    Restored,
}

/// One thing a scan found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanFinding {
    /// What it is.
    pub kind: FindingKind,
    /// Path relative to the destination root.
    pub rel_path: String,
    /// Detail, if any.
    pub detail: String,
    /// False if an earlier check had already recorded this problem.
    pub new: bool,
}

/// A scan's overall conclusion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanVerdict {
    /// The scan has not finished; call again to continue.
    Incomplete,
    /// Every recorded file was read back and matched.
    Clean,
    /// Nothing wrong was found, but some files could not be read (in use,
    /// access denied), so the scan cannot vouch for them. Does not block.
    Inconclusive,
    /// Something is wrong; final move is blocked.
    Problems,
    /// Many files changed, vanished or were renamed together; final move is blocked.
    MassChange,
}

/// Result of [`Store::integrity_scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// The whole ledger (as of the scan's start) has been checked.
    pub completed: bool,
    /// This call continued an earlier, interrupted scan.
    pub resumed: bool,
    /// The conclusion.
    pub verdict: ScanVerdict,
    /// Records checked so far in this scan (all calls).
    pub files_checked: u64,
    /// Records checked in this call.
    pub files_checked_this_call: u64,
    /// Bytes read back and matched so far in this scan.
    pub bytes_verified: u64,
    /// Files that matched.
    pub ok: u64,
    /// Files newly found missing.
    pub missing: u64,
    /// Files newly found changed.
    pub changed: u64,
    /// Files that could not be read.
    pub unreadable: u64,
    /// Records behind a reparse point, not local, or invalid.
    pub suspicious: u64,
    /// Files previously marked bad that are intact again.
    pub restored: u64,
    /// Files still missing or changed that an earlier check already recorded.
    pub known_bad: u64,
    /// Files in the destination the ledger does not know (complete scans only).
    pub unexpected: u64,
    /// Unknown files that look like renamed copies of missing ones.
    pub rename_suspects: u64,
    /// Reparse points seen while walking the destination.
    pub reparse_points: u64,
    /// Individual findings of this call, up to [`MAX_LISTED_FINDINGS`].
    pub findings: Vec<ScanFinding>,
    /// More findings existed than are listed.
    pub findings_truncated: bool,
    /// The final-move block in force after this call, if any.
    pub block: Option<BlockInfo>,
}

/// Averages reads down to a byte rate and notices cancellation.
struct Throttle<'a> {
    rate: Option<u64>,
    started: Instant,
    bytes: u64,
    cancel: &'a CancelToken,
}

impl Throttle<'_> {
    fn tick(&mut self, n: usize) -> ControlFlow<()> {
        if self.cancel.is_cancelled() {
            return ControlFlow::Break(());
        }
        self.bytes += n as u64;
        if let Some(rate) = self.rate.filter(|r| *r > 0) {
            let due = Duration::from_secs_f64(self.bytes as f64 / rate as f64);
            loop {
                let elapsed = self.started.elapsed();
                if elapsed >= due {
                    break;
                }
                if self.cancel.is_cancelled() {
                    return ControlFlow::Break(());
                }
                std::thread::sleep((due - elapsed).min(Duration::from_millis(25)));
            }
        }
        ControlFlow::Continue(())
    }
}

/// The files newly found missing, grouped by directory, for spotting renames.
pub(crate) struct MissingIndex {
    by_dir: HashMap<String, Vec<(String, String)>>,
}

fn stem_of(name_key: &str) -> &str {
    match name_key.rfind('.') {
        Some(i) if i > 0 => &name_key[..i],
        _ => name_key,
    }
}

impl MissingIndex {
    pub(crate) fn new(rel_paths: &[String]) -> Self {
        let mut by_dir: HashMap<String, Vec<(String, String)>> = HashMap::new();
        for rel in rel_paths {
            let key = path_key(rel);
            let (dir, name) = match key.rfind('/') {
                Some(i) => (key[..i].to_owned(), key[i + 1..].to_owned()),
                None => (String::new(), key.clone()),
            };
            let stem = stem_of(&name).to_owned();
            by_dir.entry(dir).or_default().push((name, stem));
        }
        Self { by_dir }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.by_dir.is_empty()
    }

    /// Does an unknown file `name` in the directory `dir_key` look like a
    /// renamed copy of a missing file there? Two patterns are recognised:
    /// an extension appended (`a.jpg` -> `a.jpg.locked`) and an extension
    /// replaced (`a.jpg` -> `a.locked`).
    pub(crate) fn is_rename_suspect(&self, dir_key: &str, name: &str) -> bool {
        let Some(missing) = self.by_dir.get(dir_key) else {
            return false;
        };
        let name_key = collision_key(name);
        let stem = stem_of(&name_key);
        missing.iter().any(|(missing_name, missing_stem)| {
            name_key != *missing_name
                && (name_key
                    .strip_prefix(missing_name.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
                    || (stem == missing_stem && stem != name_key))
        })
    }
}

/// The numbers a mass-change decision is made from.
#[derive(Debug, Clone, Default)]
pub(crate) struct ChangeEvidence {
    pub checked: u64,
    pub missing: u64,
    pub changed: u64,
    pub rename_suspects: u64,
    /// On-disk modification times (Unix seconds) of the changed files.
    pub changed_mtimes: Vec<i64>,
}

impl ChangeEvidence {
    pub(crate) fn note_changed_mtime(&mut self, mtime: Option<SystemTime>) {
        if let Some(secs) = mtime.and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()) {
            self.changed_mtimes.push(secs.as_secs() as i64);
        }
    }

    /// Returns a description if the evidence looks like a mass change.
    pub(crate) fn mass_change(&self, policy: &ScanPolicy) -> Option<String> {
        let altered = self.changed + self.rename_suspects;
        if policy.mass_change_min_files > 0 && altered >= policy.mass_change_min_files {
            return Some(format!(
                "{} stored files were changed and {} look renamed in one check; this is what ransomware or a failing disk looks like",
                self.changed, self.rename_suspects
            ));
        }
        if policy.mass_change_min_files > 0
            && self.missing >= policy.mass_change_min_files
            && self.missing.saturating_mul(100)
                >= u64::from(policy.mass_missing_min_percent).saturating_mul(self.checked)
        {
            return Some(format!(
                "{} of {} stored files disappeared in one check",
                self.missing, self.checked
            ));
        }
        if policy.burst_min_files > 0 && self.changed_mtimes.len() as u64 >= policy.burst_min_files
        {
            let mut times = self.changed_mtimes.clone();
            times.sort_unstable();
            let k = policy.burst_min_files as usize;
            let window = i64::try_from(policy.burst_window_secs).unwrap_or(i64::MAX);
            if times.windows(k).any(|w| w[k - 1] - w[0] <= window) {
                return Some(format!(
                    "{k} or more stored files were changed within {} seconds of each other",
                    policy.burst_window_secs
                ));
            }
        }
        None
    }
}

struct Findings {
    list: Vec<ScanFinding>,
    truncated: bool,
}

impl Findings {
    fn push(&mut self, kind: FindingKind, rel_path: &str, detail: impl Into<String>, new: bool) {
        if self.list.len() < MAX_LISTED_FINDINGS {
            self.list.push(ScanFinding {
                kind,
                rel_path: rel_path.to_owned(),
                detail: detail.into(),
                new,
            });
        } else {
            self.truncated = true;
        }
    }
}

impl Store {
    /// Runs (or continues) an integrity scan.
    ///
    /// Each call checks records until the ledger is exhausted, `cancel` is
    /// set, or [`ScanOptions::max_files`] is reached. An unfinished scan
    /// returns `completed: false` and the next call continues where it
    /// stopped, also after a restart of the program.
    ///
    /// Findings take effect immediately, not at the end: a changed or missing
    /// file is marked in the ledger and blocks final move as soon as it is
    /// seen.
    pub fn integrity_scan(
        &self,
        opts: &ScanOptions,
        cancel: &CancelToken,
    ) -> Result<ScanReport, StoreError> {
        let inner = &self.inner;
        let ledger = &inner.ledger;

        let saved = if opts.restart {
            None
        } else {
            ledger.scan_state()?
        };
        let resumed = saved.is_some();
        let mut state = match saved {
            Some(s) => s,
            None => {
                let started_seq =
                    ledger.log_event("scan_started", None, None, None, inner.now())?;
                let fresh = ScanState {
                    started_seq,
                    upper_id: ledger.max_file_id()?,
                    ..ScanState::default()
                };
                ledger.save_scan_state(&fresh)?;
                fresh
            }
        };

        let mut findings = Findings {
            list: Vec::new(),
            truncated: false,
        };
        let mut evidence = ChangeEvidence::default();
        let mut throttle = Throttle {
            rate: opts.max_bytes_per_sec,
            started: Instant::now(),
            bytes: 0,
            cancel,
        };
        let mut this_call = 0u64;
        let mut stopped = false;

        'records: loop {
            let batch = ledger.files_after(state.cursor_id, state.upper_id, 64)?;
            if batch.is_empty() {
                break;
            }
            for rec in &batch {
                if cancel.is_cancelled() || opts.max_files.is_some_and(|max| this_call >= max) {
                    stopped = true;
                    break 'records;
                }
                let probe = inner.probe(rec, &mut |n| throttle.tick(n));
                if probe == Probe::Interrupted {
                    // Not counted and the cursor does not move: the file is checked again on resume.
                    stopped = true;
                    break 'records;
                }
                inner.apply_probe(rec, &probe)?;
                state.cursor_id = rec.id;
                state.files_checked += 1;
                this_call += 1;
                let path = rec.rel_path.as_str();
                match &probe {
                    Probe::Match { .. } => {
                        state.ok += 1;
                        state.bytes_checked += rec.size;
                        if rec.state != FileState::Committed {
                            state.restored += 1;
                            findings.push(FindingKind::Restored, path, "", true);
                        }
                    }
                    Probe::Missing => {
                        let new = rec.state != FileState::Missing;
                        if new {
                            state.missing += 1;
                        } else {
                            state.known_bad += 1;
                        }
                        findings.push(FindingKind::Missing, path, "", new);
                    }
                    Probe::Changed(how) => {
                        let new = rec.state != FileState::Changed;
                        if new {
                            state.changed += 1;
                            if let Some(rel) = crate::sanitize::SafeRelPath::from_stored(path) {
                                let stat = inner.fs.stat(&rel.under(inner.root())).ok().flatten();
                                evidence.note_changed_mtime(stat.and_then(|s| s.mtime));
                            }
                        } else {
                            state.known_bad += 1;
                        }
                        findings.push(FindingKind::Changed, path, how.as_str(), new);
                    }
                    Probe::Unreadable(why) => {
                        state.unreadable += 1;
                        findings.push(FindingKind::Unreadable, path, why.as_str(), true);
                    }
                    Probe::Reparse(at) => {
                        state.suspicious += 1;
                        findings.push(
                            FindingKind::ReparsePoint,
                            path,
                            at.display().to_string(),
                            true,
                        );
                    }
                    Probe::NotLocal => {
                        state.suspicious += 1;
                        findings.push(FindingKind::NotLocal, path, "", true);
                    }
                    Probe::InvalidRecord => {
                        state.suspicious += 1;
                        findings.push(FindingKind::InvalidRecord, path, "", true);
                    }
                    Probe::Interrupted => unreachable!("handled above"),
                }
            }
            ledger.save_scan_state(&state)?;
        }
        ledger.save_scan_state(&state)?;

        let mut unexpected = 0u64;
        let mut rename_suspects = 0u64;
        let mut reparse_points = 0u64;
        if !stopped && !opts.skip_unexpected {
            let missing = MissingIndex::new(&ledger.missing_since(state.started_seq)?);
            let mut ledger_error = None;
            let walked = inner.walk(cancel, &mut |visit| match visit {
                Visit::File { dir_rel, entry, .. } => {
                    if is_temp_name(&entry.name) || ledger_error.is_some() {
                        return;
                    }
                    let rel = if dir_rel.is_empty() {
                        entry.name.clone()
                    } else {
                        format!("{}/{}", dir_rel.join("/"), entry.name)
                    };
                    match ledger.path_key_exists(&path_key(&rel)) {
                        Ok(true) => {}
                        Ok(false) => {
                            unexpected += 1;
                            let dir_key = path_key(&dir_rel.join("/"));
                            if missing.is_rename_suspect(&dir_key, &entry.name) {
                                rename_suspects += 1;
                                findings.push(FindingKind::RenameSuspect, &rel, "", true);
                            } else {
                                findings.push(FindingKind::Unexpected, &rel, "", true);
                            }
                        }
                        Err(e) => ledger_error = Some(e),
                    }
                }
                Visit::Reparse { rel, .. } => {
                    reparse_points += 1;
                    findings.push(FindingKind::ReparsePoint, &rel, "not followed", true);
                }
                Visit::Unreadable { rel, error } => {
                    findings.push(FindingKind::Unreadable, &rel, error, true);
                }
            });
            if let Some(e) = ledger_error {
                return Err(e.into());
            }
            stopped = !walked;
        }

        let report = |verdict, completed, block| ScanReport {
            completed,
            resumed,
            verdict,
            files_checked: state.files_checked,
            files_checked_this_call: this_call,
            bytes_verified: state.bytes_checked,
            ok: state.ok,
            missing: state.missing,
            changed: state.changed,
            unreadable: state.unreadable,
            suspicious: state.suspicious,
            restored: state.restored,
            known_bad: state.known_bad,
            unexpected,
            rename_suspects,
            reparse_points,
            findings: findings.list.clone(),
            findings_truncated: findings.truncated,
            block,
        };

        if stopped {
            return Ok(report(ScanVerdict::Incomplete, false, ledger.block_info()?));
        }

        evidence.checked = state.files_checked;
        evidence.missing = state.missing;
        evidence.changed = state.changed;
        evidence.rename_suspects = rename_suspects;
        let now = inner.now();
        let verdict = if let Some(why) = evidence.mass_change(&inner.cfg.scan_policy) {
            ledger.block(BlockKind::MassChange, &why, now)?;
            ScanVerdict::MassChange
        } else if state.missing + state.changed + state.suspicious > 0 {
            // Changed files and (by default) missing files have already set
            // the block when they were found. Make sure of it here, so that
            // "Problems" always means "blocked".
            let why = format!(
                "the integrity scan found {} missing, {} changed and {} suspicious records",
                state.missing, state.changed, state.suspicious
            );
            ledger.block(BlockKind::IntegrityProblems, &why, now)?;
            ScanVerdict::Problems
        } else if state.unreadable > 0 {
            ScanVerdict::Inconclusive
        } else {
            ScanVerdict::Clean
        };
        let summary = format!(
            "checked {} ok {} missing {} changed {} unreadable {} suspicious {} restored {} unexpected {} rename-suspects {}",
            state.files_checked, state.ok, state.missing, state.changed, state.unreadable, state.suspicious, state.restored,
            unexpected, rename_suspects
        );
        ledger.log_event("scan_finished", None, None, Some(&summary), now)?;
        ledger.clear_scan_state()?;
        // The walk saw the tree as it is now; cached listings may be stale.
        inner.forget_all_names();
        Ok(report(verdict, true, ledger.block_info()?))
    }
}

impl Inner {
    /// Applies the mass-change heuristics to what a recovery pass found.
    pub(crate) fn judge_mass_change(&self, evidence: &ChangeEvidence) -> Result<bool, StoreError> {
        match evidence.mass_change(&self.cfg.scan_policy) {
            Some(why) => {
                self.ledger.block(BlockKind::MassChange, &why, self.now())?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(
        checked: u64,
        missing: u64,
        changed: u64,
        suspects: u64,
        mtimes: &[i64],
    ) -> ChangeEvidence {
        ChangeEvidence {
            checked,
            missing,
            changed,
            rename_suspects: suspects,
            changed_mtimes: mtimes.to_vec(),
        }
    }

    #[test]
    fn mass_change_thresholds() {
        let p = ScanPolicy::default();
        // A few problems are problems, not a mass change.
        assert!(evidence(1_000, 3, 2, 1, &[]).mass_change(&p).is_none());
        assert!(evidence(1_000, 0, 9, 0, &[]).mass_change(&p).is_none());
        // Ten changed, or changed plus renamed.
        assert!(evidence(1_000, 0, 10, 0, &[]).mass_change(&p).is_some());
        assert!(evidence(1_000, 0, 4, 6, &[]).mass_change(&p).is_some());
        assert!(evidence(1_000, 0, 0, 10, &[]).mass_change(&p).is_some());
        // Deletions: many AND a meaningful share of the library.
        assert!(evidence(1_000, 49, 0, 0, &[]).mass_change(&p).is_none());
        assert!(evidence(1_000, 50, 0, 0, &[]).mass_change(&p).is_some());
        assert!(evidence(100, 9, 0, 0, &[]).mass_change(&p).is_none());
        assert!(evidence(100, 10, 0, 0, &[]).mass_change(&p).is_some());
        assert!(evidence(10, 10, 0, 0, &[]).mass_change(&p).is_some());
        // Nothing wrong at all.
        assert!(evidence(0, 0, 0, 0, &[]).mass_change(&p).is_none());
    }

    #[test]
    fn bursts_of_changes_in_a_short_span() {
        let p = ScanPolicy::default();
        // Five files changed within ten minutes.
        assert!(
            evidence(1_000, 0, 5, 0, &[1_000, 1_100, 1_200, 1_300, 1_600])
                .mass_change(&p)
                .is_some()
        );
        // Five files changed over five days.
        assert!(
            evidence(1_000, 0, 5, 0, &[0, 86_400, 172_800, 259_200, 345_600])
                .mass_change(&p)
                .is_none()
        );
        // Four in a burst is below the threshold.
        assert!(evidence(1_000, 0, 4, 0, &[1_000, 1_001, 1_002, 1_003])
            .mass_change(&p)
            .is_none());
        // Order does not matter, and a burst hidden among older changes is found.
        assert!(
            evidence(1_000, 0, 7, 0, &[9_000_000, 50, 10, 40, 5_000_000, 20, 30])
                .mass_change(&p)
                .is_some()
        );
    }

    #[test]
    fn policy_can_switch_heuristics_off() {
        let p = ScanPolicy {
            mass_change_min_files: 0,
            burst_min_files: 0,
            ..ScanPolicy::default()
        };
        assert!(evidence(10, 10, 10, 10, &[1, 2, 3, 4, 5, 6])
            .mass_change(&p)
            .is_none());
    }

    #[test]
    fn rename_suspects() {
        let index = MissingIndex::new(&[
            "Pixel/DCIM/IMG_1.jpg".to_owned(),
            "Pixel/DCIM/IMG_2.JPG".to_owned(),
            "top.png".to_owned(),
            "Pixel/noext".to_owned(),
        ]);
        assert!(!index.is_empty());
        let dir = path_key("Pixel/DCIM");
        // Extension appended or replaced, in any case.
        assert!(index.is_rename_suspect(&dir, "IMG_1.jpg.locked"));
        assert!(index.is_rename_suspect(&dir, "img_1.JPG.LOCKED"));
        assert!(index.is_rename_suspect(&dir, "IMG_1.locked"));
        assert!(index.is_rename_suspect(&dir, "IMG_2.jpg.enc"));
        assert!(index.is_rename_suspect("", "top.png.crypt"));
        assert!(index.is_rename_suspect(&path_key("Pixel"), "noext.locked"));
        // Not suspects: the same name, unrelated names, other directories.
        assert!(!index.is_rename_suspect(&dir, "IMG_1.jpg"));
        assert!(!index.is_rename_suspect(&dir, "IMG_10.jpg"));
        assert!(!index.is_rename_suspect(&dir, "IMG_3.jpg.locked"));
        assert!(!index.is_rename_suspect(&dir, "holiday.mp4"));
        assert!(!index.is_rename_suspect(&path_key("Pixel/Other"), "IMG_1.jpg.locked"));
        assert!(!index.is_rename_suspect(&path_key("Pixel"), "noext"));
        assert!(MissingIndex::new(&[]).is_empty());
    }

    #[test]
    fn throttle_limits_the_rate_and_obeys_cancel() {
        let cancel = CancelToken::new();
        let mut t = Throttle {
            rate: Some(1_000_000),
            started: Instant::now(),
            bytes: 0,
            cancel: &cancel,
        };
        let begin = Instant::now();
        for _ in 0..4 {
            assert!(t.tick(50_000).is_continue());
        }
        // 200 kB at 1 MB/s takes at least 0.2 s.
        assert!(
            begin.elapsed() >= Duration::from_millis(190),
            "{:?}",
            begin.elapsed()
        );

        // Unlimited: no waiting.
        let mut t = Throttle {
            rate: None,
            started: Instant::now(),
            bytes: 0,
            cancel: &cancel,
        };
        let begin = Instant::now();
        assert!(t.tick(usize::MAX / 2).is_continue());
        assert!(begin.elapsed() < Duration::from_millis(100));

        // A cancelled token stops a wait that would take an hour.
        let mut t = Throttle {
            rate: Some(1),
            started: Instant::now(),
            bytes: 0,
            cancel: &cancel,
        };
        let canceller = cancel.clone();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            canceller.cancel();
        });
        let begin = Instant::now();
        assert!(t.tick(3_600).is_break());
        assert!(begin.elapsed() < Duration::from_secs(5));
        handle.join().unwrap();
        assert!(t.tick(1).is_break());
    }
}
