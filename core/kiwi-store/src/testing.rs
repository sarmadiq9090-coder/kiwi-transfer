//! Fault injection for tests (feature `test-util`).
//!
//! [`FaultFs`] wraps a real [`Fs`] and can make any single operation fail,
//! make writes short, or run a hook just before an operation (to flip a byte
//! on disk between the flush and the read-back, to create the target between
//! the collision check and the rename, and so on). It also records every
//! operation, so a test can first run a scenario cleanly, learn how many
//! operations it takes, and then fail each one in turn.
//!
//! [`ManualClock`] is a clock tests can set.

use std::collections::HashMap;
use std::io;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::fsops::{Checkpoint, Clock, DirEntryInfo, FileStat, Fs, RealFs, TempFile, VerifyRead};

/// An operation that can be intercepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    /// [`Fs::free_space`].
    FreeSpace,
    /// [`Fs::stat`].
    Stat,
    /// [`Fs::list_dir`].
    ListDir,
    /// [`Fs::resolve`].
    Resolve,
    /// [`Fs::create_dir`].
    CreateDir,
    /// [`Fs::create_temp`].
    CreateTemp,
    /// [`TempFile::write`].
    Write,
    /// [`TempFile::set_mtime`].
    SetMtime,
    /// [`TempFile::sync`].
    Sync,
    /// [`Fs::read_verify`].
    ReadVerify,
    /// [`Fs::rename_noreplace`].
    Rename,
    /// [`Fs::sync_dir`].
    SyncDir,
    /// [`Fs::remove_file`].
    RemoveFile,
    /// [`Fs::checkpoint`].
    Checkpoint(Checkpoint),
}

/// When a rule fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// On the n-th (0-based) call of this operation since the last reset.
    Nth(Op, usize),
    /// On every call of this operation.
    Every(Op),
    /// On the n-th (0-based) operation of any kind since the last reset.
    Global(usize),
}

/// A hook run with the operation's path just before the real operation.
pub type Hook = Arc<dyn Fn(&Path) + Send + Sync>;

/// What a rule does.
#[derive(Clone)]
pub enum Action {
    /// Fail with an error of this kind instead of performing the operation.
    Fail(io::ErrorKind),
    /// For [`Op::Write`]: accept at most this many bytes (0 = accept nothing).
    ShortWrite(usize),
    /// For [`Op::FreeSpace`]: report this many bytes free.
    FreeSpace(u64),
    /// Run the hook, then perform the real operation.
    Before(Hook),
    /// For [`Op::ReadVerify`]: perform the read but report it as cached.
    ReportBuffered,
}

impl Action {
    /// An [`Action::Before`] from a closure.
    pub fn before(hook: impl Fn(&Path) + Send + Sync + 'static) -> Action {
        Action::Before(Arc::new(hook))
    }
}

#[derive(Default)]
struct State {
    rules: Vec<(When, Action)>,
    counts: HashMap<Op, usize>,
    global: usize,
    log: Vec<(Op, PathBuf)>,
}

/// A file system that misbehaves on request. Clones share their rules, so a
/// test keeps one clone to steer the instance it gave to the store.
#[derive(Clone)]
pub struct FaultFs {
    inner: Arc<dyn Fs>,
    state: Arc<Mutex<State>>,
}

impl Default for FaultFs {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultFs {
    /// Wraps the real file system.
    pub fn new() -> FaultFs {
        FaultFs::wrap(Arc::new(RealFs))
    }

    /// Wraps another [`Fs`].
    pub fn wrap(inner: Arc<dyn Fs>) -> FaultFs {
        FaultFs { inner, state: Arc::new(Mutex::new(State::default())) }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Adds a rule. Earlier rules win when several match.
    pub fn inject(&self, when: When, action: Action) {
        self.state().rules.push((when, action));
    }

    /// Removes all rules.
    pub fn clear_rules(&self) {
        self.state().rules.clear();
    }

    /// Resets the operation counters and the log (rules stay).
    pub fn reset_counters(&self) {
        let mut s = self.state();
        s.counts.clear();
        s.global = 0;
        s.log.clear();
    }

    /// Every operation seen since the last reset, in order.
    pub fn log(&self) -> Vec<(Op, PathBuf)> {
        self.state().log.clone()
    }

    /// How often an operation was seen since the last reset.
    pub fn count(&self, op: Op) -> usize {
        self.state().counts.get(&op).copied().unwrap_or(0)
    }

    /// Records the operation and returns the action of the first matching rule.
    fn intercept(state: &Mutex<State>, op: Op, path: &Path) -> Option<Action> {
        let mut s = state.lock().unwrap_or_else(|p| p.into_inner());
        let nth = *s.counts.get(&op).unwrap_or(&0);
        let global = s.global;
        s.counts.insert(op, nth + 1);
        s.global += 1;
        s.log.push((op, path.to_path_buf()));
        s.rules
            .iter()
            .find(|(when, _)| match *when {
                When::Nth(o, n) => o == op && n == nth,
                When::Every(o) => o == op,
                When::Global(n) => n == global,
            })
            .map(|(_, action)| action.clone())
    }

    /// Applies the generic part of an action. `Ok(action)` hands back what the
    /// operation itself has to interpret.
    fn before(state: &Mutex<State>, op: Op, path: &Path) -> io::Result<Option<Action>> {
        match Self::intercept(state, op, path) {
            Some(Action::Fail(kind)) => Err(io::Error::new(kind, format!("injected fault at {op:?}"))),
            Some(Action::Before(hook)) => {
                hook(path);
                Ok(None)
            }
            other => Ok(other),
        }
    }
}

struct FaultTemp {
    inner: Box<dyn TempFile>,
    path: PathBuf,
    state: Arc<Mutex<State>>,
}

impl TempFile for FaultTemp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match FaultFs::before(&self.state, Op::Write, &self.path)? {
            Some(Action::ShortWrite(0)) => Ok(0),
            Some(Action::ShortWrite(max)) => self.inner.write(&buf[..buf.len().min(max)]),
            _ => self.inner.write(buf),
        }
    }

    fn set_mtime(&mut self, mtime: SystemTime) -> io::Result<()> {
        FaultFs::before(&self.state, Op::SetMtime, &self.path)?;
        self.inner.set_mtime(mtime)
    }

    fn sync(&mut self) -> io::Result<()> {
        FaultFs::before(&self.state, Op::Sync, &self.path)?;
        self.inner.sync()
    }
}

impl Fs for FaultFs {
    fn free_space(&self, dir: &Path) -> io::Result<u64> {
        match Self::before(&self.state, Op::FreeSpace, dir)? {
            Some(Action::FreeSpace(bytes)) => Ok(bytes),
            _ => self.inner.free_space(dir),
        }
    }

    fn stat(&self, path: &Path) -> io::Result<Option<FileStat>> {
        Self::before(&self.state, Op::Stat, path)?;
        self.inner.stat(path)
    }

    fn list_dir(&self, dir: &Path) -> io::Result<Vec<DirEntryInfo>> {
        Self::before(&self.state, Op::ListDir, dir)?;
        self.inner.list_dir(dir)
    }

    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        Self::before(&self.state, Op::Resolve, path)?;
        self.inner.resolve(path)
    }

    fn create_dir(&self, path: &Path) -> io::Result<()> {
        Self::before(&self.state, Op::CreateDir, path)?;
        self.inner.create_dir(path)
    }

    fn create_temp(&self, path: &Path) -> io::Result<Box<dyn TempFile>> {
        Self::before(&self.state, Op::CreateTemp, path)?;
        let inner = self.inner.create_temp(path)?;
        Ok(Box::new(FaultTemp { inner, path: path.to_path_buf(), state: Arc::clone(&self.state) }))
    }

    fn read_verify(&self, path: &Path, sink: &mut dyn FnMut(&[u8]) -> ControlFlow<()>) -> io::Result<VerifyRead> {
        let action = Self::before(&self.state, Op::ReadVerify, path)?;
        let mut read = self.inner.read_verify(path, sink)?;
        if matches!(action, Some(Action::ReportBuffered)) {
            read.unbuffered = false;
        }
        Ok(read)
    }

    fn rename_noreplace(&self, from: &Path, to: &Path) -> io::Result<()> {
        Self::before(&self.state, Op::Rename, to)?;
        self.inner.rename_noreplace(from, to)
    }

    fn sync_dir(&self, dir: &Path) -> io::Result<()> {
        Self::before(&self.state, Op::SyncDir, dir)?;
        self.inner.sync_dir(dir)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        Self::before(&self.state, Op::RemoveFile, path)?;
        self.inner.remove_file(path)
    }

    fn checkpoint(&self, point: Checkpoint) -> io::Result<()> {
        Self::before(&self.state, Op::Checkpoint(point), Path::new(""))?;
        self.inner.checkpoint(point)
    }
}

/// A clock that only moves when told to.
#[derive(Debug, Default)]
pub struct ManualClock(AtomicI64);

impl ManualClock {
    /// A clock reading `unix_ms`.
    pub fn new(unix_ms: i64) -> Arc<ManualClock> {
        Arc::new(ManualClock(AtomicI64::new(unix_ms)))
    }

    /// Sets the time.
    pub fn set(&self, unix_ms: i64) {
        self.0.store(unix_ms, Ordering::SeqCst);
    }

    /// Moves the time by `ms` (negative values move it backwards).
    pub fn advance_ms(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    /// Moves the time forward by whole hours.
    pub fn advance_hours(&self, hours: i64) {
        self.advance_ms(hours * 3_600_000);
    }
}

impl Clock for ManualClock {
    fn now_unix_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}
