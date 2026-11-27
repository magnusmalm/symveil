//! Stderr progress for `symveil learn`.
//!
//! A terminal is redrawn in place, at most five times a second. A pipe gets a
//! plain line every few seconds, plus a line at the start and at the end.
//! The text is counts, sizes, times, and a truncated path. File contents are
//! never written here.

use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;

#[derive(Clone)]
pub struct SlowFile {
    pub path: String,
    pub bytes: u64,
    pub elapsed: Duration,
}

pub struct Progress {
    enabled: bool,
    tty: bool,
    total_files: usize,
    total_bytes: u64,
    started: Instant,
    files: AtomicUsize,
    bytes: AtomicU64,
    last_draw_ms: AtomicU64,
    current: Mutex<String>,
    slow: Mutex<Vec<SlowFile>>,
    threshold: Duration,
    err: Mutex<Box<dyn Write + Send>>,
}

impl Progress {
    pub fn start(
        enabled: bool,
        tty: bool,
        total_files: usize,
        total_bytes: u64,
        threshold: Duration,
        err: Box<dyn Write + Send>,
    ) -> Self {
        let progress = Self {
            enabled,
            tty: enabled && tty,
            total_files,
            total_bytes,
            started: Instant::now(),
            files: AtomicUsize::new(0),
            bytes: AtomicU64::new(0),
            last_draw_ms: AtomicU64::new(0),
            current: Mutex::new(String::new()),
            slow: Mutex::new(Vec::new()),
            threshold,
            err: Mutex::new(err),
        };
        progress.draw(true);
        progress
    }

    pub fn note_current(&self, path: &str) {
        if !self.enabled {
            return;
        }
        if let Ok(mut current) = self.current.lock() {
            current.clear();
            current.push_str(path);
        }
        self.draw(false);
    }

    pub fn finish_file(&self, path: &str, bytes: u64, elapsed: Duration) {
        self.files.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        if let Ok(mut current) = self.current.lock() {
            current.clear();
            current.push_str(path);
        }
        if elapsed >= self.threshold {
            if let Ok(mut slow) = self.slow.lock() {
                slow.push(SlowFile {
                    path: path.to_string(),
                    bytes,
                    elapsed,
                });
            }
            self.warn_slow(path, bytes, elapsed);
        }
        self.draw(false);
    }

    pub fn finish(&self) {
        self.draw(true);
        if !self.enabled {
            return;
        }
        if let Ok(mut err) = self.err.lock() {
            let _ = writeln!(err);
            let _ = err.flush();
        }
    }

    pub fn slow_files(&self) -> Vec<SlowFile> {
        let mut rows = self
            .slow
            .lock()
            .map(|slow| slow.clone())
            .unwrap_or_default();
        rows.sort_by(|left, right| {
            right
                .elapsed
                .cmp(&left.elapsed)
                .then_with(|| left.path.cmp(&right.path))
        });
        rows
    }

    fn warn_slow(&self, path: &str, bytes: u64, elapsed: Duration) {
        if let Ok(mut err) = self.err.lock() {
            if self.tty {
                let _ = writeln!(err);
            }
            let _ = writeln!(
                err,
                "symveil learn: slow file {} ({} bytes, {})",
                truncate_path(path),
                bytes,
                fmt_secs(elapsed.as_secs_f64())
            );
            let _ = err.flush();
        }
    }

    fn draw(&self, force: bool) {
        if !self.enabled {
            return;
        }
        let elapsed_ms = self.started.elapsed().as_millis() as u64;
        let min_gap = if self.tty { 200 } else { 2_000 };
        let previous = self.last_draw_ms.load(Ordering::Relaxed);
        if !force && elapsed_ms.saturating_sub(previous) < min_gap {
            return;
        }
        if !force
            && self
                .last_draw_ms
                .compare_exchange(previous, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        if force {
            self.last_draw_ms.store(elapsed_ms, Ordering::Relaxed);
        }
        let files = self.files.load(Ordering::Relaxed);
        let bytes = self.bytes.load(Ordering::Relaxed);
        let current = self
            .current
            .lock()
            .map(|path| truncate_path(&path))
            .unwrap_or_default();
        let line = format!(
            "symveil learn: {files}/{} files  {}  {}{}  {current}",
            self.total_files,
            fmt_bytes(bytes),
            fmt_secs(self.started.elapsed().as_secs_f64()),
            fmt_eta(self.started.elapsed(), bytes, self.total_bytes)
        );
        if let Ok(mut err) = self.err.lock() {
            if self.tty {
                let _ = write!(err, "\r\x1b[2K{line}");
            } else {
                let _ = writeln!(err, "{line}");
            }
            let _ = err.flush();
        }
    }
}

pub fn write_slow_summary(slow: &[SlowFile], stdout: &mut dyn Write) -> Result<()> {
    if slow.is_empty() {
        return Ok(());
    }
    writeln!(stdout, "slow files:")?;
    let shown = slow.len().min(20);
    for row in slow.iter().take(shown) {
        writeln!(
            stdout,
            "  {}  {} bytes  {}",
            fmt_secs(row.elapsed.as_secs_f64()),
            row.bytes,
            row.path
        )?;
    }
    if slow.len() > shown {
        writeln!(stdout, "  and {} more", slow.len() - shown)?;
    }
    Ok(())
}

fn fmt_eta(elapsed: Duration, done: u64, total: u64) -> String {
    if done == 0 || total == 0 || done >= total {
        return String::new();
    }
    let remain = elapsed.as_secs_f64() * (total - done) as f64 / done as f64;
    format!("  eta {}", fmt_secs(remain))
}

fn fmt_bytes(bytes: u64) -> String {
    if bytes < 1024 * 1024 {
        format!("{bytes} bytes")
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn fmt_secs(secs: f64) -> String {
    if secs >= 10.0 {
        format!("{}s", secs.round() as u64)
    } else {
        format!("{secs:.1}s")
    }
}

fn truncate_path(path: &str) -> String {
    const MAX: usize = 60;
    let count = path.chars().count();
    if count <= MAX {
        return path.to_string();
    }
    let skip = count - (MAX - 3);
    let tail: String = path.chars().skip(skip).collect();
    format!("...{tail}")
}

pub fn stderr_is_tty() -> bool {
    io::IsTerminal::is_terminal(&io::stderr())
}

pub fn stderr_sink() -> Box<dyn Write + Send> {
    Box::new(StderrSink)
}

struct StderrSink;

impl Write for StderrSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        io::stderr().lock().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}

#[cfg(test)]
pub struct SharedBuf {
    buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

#[cfg(test)]
impl SharedBuf {
    pub fn new(buf: std::sync::Arc<std::sync::Mutex<Vec<u8>>>) -> Self {
        Self { buf }
    }
}

#[cfg(test)]
impl Write for SharedBuf {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf
            .lock()
            .expect("progress buffer")
            .extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
