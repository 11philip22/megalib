//! Progress reporting for file transfers.
//!
//! This module defines the structures and types used to report upload and download progress.
//! You can use the built-in `make_progress_bar` for a simple CLI progress bar, or provide
//! your own closure to handle progress events custom logic (e.g. GUI updates).
//!
//! # Example: Custom Progress Handler
//!
//! ```
//! use megalib::progress::{TransferProgress, ProgressCallback};
//!
//! let mut callback: ProgressCallback = Box::new(|p: &TransferProgress| {
//!     println!("{} is {:.1}% done...", p.filename, p.percent());
//!     true // Return true to continue the transfer, false to cancel
//! });
//! ```

use std::io::Write;
use std::time::Instant;

/// Progress information for uploads and downloads.
///
/// This struct is passed to the progress callback periodically during a transfer.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Bytes transferred so far.
    pub done: u64,
    /// Total bytes to transfer.
    pub total: u64,
    /// Name of the file being transferred.
    pub filename: String,
}

impl TransferProgress {
    /// Create a new progress report.
    ///
    /// # Arguments
    /// * `done` - Bytes transferred
    /// * `total` - Total bytes
    /// * `filename` - Name of the file
    pub fn new(done: u64, total: u64, filename: impl Into<String>) -> Self {
        Self {
            done,
            total,
            filename: filename.into(),
        }
    }

    /// Get progress as a percentage (0.0 to 100.0).
    ///
    /// # Example
    /// ```
    /// use megalib::progress::TransferProgress;
    ///
    /// let p = TransferProgress::new(50, 100, "test.txt");
    /// assert_eq!(p.percent(), 50.0);
    /// ```
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.done as f64 / self.total as f64) * 100.0
    }

    /// Check if transfer is complete.
    ///
    /// Returns `true` if `done` is equal to or greater than `total`.
    pub fn is_complete(&self) -> bool {
        self.done >= self.total
    }
}

/// Type alias for progress callback function.
///
/// The callback receives `&TransferProgress` and must return a `bool`.
/// - Return `true` to continue the transfer.
/// - Return `false` to abort the transfer.
pub type ProgressCallback = Box<dyn FnMut(&TransferProgress) -> bool + Send>;

fn format_bytes_per_second(bytes_per_second: f64) -> String {
    if !bytes_per_second.is_finite() || bytes_per_second <= 0.0 {
        return "0 B/s".to_string();
    }

    const UNITS: [&str; 5] = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s"];
    let mut value = bytes_per_second;
    let mut unit_idx = 0usize;

    while value >= 1024.0 && unit_idx < UNITS.len() - 1 {
        value /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{:.0} {}", value, UNITS[unit_idx])
    } else {
        format!("{:.2} {}", value, UNITS[unit_idx])
    }
}

/// Create a simple CLI progress bar callback.
///
/// This function returns a closure that prints a text-based progress bar to stdout.
/// It uses `\r` (carriage return) to animate the bar on a single line.
///
/// Output format: `[====      ] 40.0% filename.txt - 400/1000 bytes @ 2.10 MB/s`
///
/// # Example
/// ```no_run
/// # use megalib::Session;
/// use megalib::progress::make_progress_bar;
///
/// # async fn run(session: &mut Session) -> megalib::Result<()> {
/// session.watch_status(make_progress_bar());
/// # Ok(())
/// # }
/// ```
pub fn make_progress_bar() -> ProgressCallback {
    let mut previous_sample: Option<(Instant, u64)> = None;
    let mut speed_bps = 0.0f64;

    Box::new(move |progress: &TransferProgress| {
        let percent = progress.percent();
        let bar_width = 40;
        let filled = (percent / 100.0 * bar_width as f64) as usize;
        let empty = bar_width - filled;
        let now = Instant::now();

        if let Some((previous_time, previous_done)) = previous_sample {
            let elapsed = now.duration_since(previous_time).as_secs_f64();
            if elapsed >= 0.1 {
                let delta_bytes = progress.done.saturating_sub(previous_done);
                speed_bps = delta_bytes as f64 / elapsed;
                previous_sample = Some((now, progress.done));
            }
        } else {
            previous_sample = Some((now, progress.done));
        }

        print!(
            "\r[{}{}] {:.1}% {} - {}/{} bytes @ {}",
            "=".repeat(filled),
            " ".repeat(empty),
            percent,
            progress.filename,
            progress.done,
            progress.total,
            format_bytes_per_second(speed_bps)
        );

        if progress.is_complete() {
            println!();
        }

        let _ = std::io::stdout().flush();

        true // Continue transfer
    })
}
