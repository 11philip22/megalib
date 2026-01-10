//! Progress reporting for file transfers.

/// Progress information for uploads and downloads.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Bytes transferred so far
    pub done: u64,
    /// Total bytes to transfer
    pub total: u64,
    /// Name of the file being transferred
    pub filename: String,
}

impl TransferProgress {
    /// Create a new progress report.
    pub fn new(done: u64, total: u64, filename: impl Into<String>) -> Self {
        Self {
            done,
            total,
            filename: filename.into(),
        }
    }

    /// Get progress as a percentage (0.0 to 100.0).
    pub fn percent(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        (self.done as f64 / self.total as f64) * 100.0
    }

    /// Check if transfer is complete.
    pub fn is_complete(&self) -> bool {
        self.done >= self.total
    }
}

/// Type alias for progress callback function.
///
/// The callback receives progress information and can return `false` to cancel the transfer.
pub type ProgressCallback = Box<dyn FnMut(&TransferProgress) -> bool + Send>;

/// Create a simple progress callback that prints to stdout.
///
/// # Example
/// ```no_run
/// use megalib::progress::make_progress_bar;
///
/// let callback = make_progress_bar();
/// ```
pub fn make_progress_bar() -> ProgressCallback {
    Box::new(|progress: &TransferProgress| {
        let percent = progress.percent();
        let bar_width = 40;
        let filled = (percent / 100.0 * bar_width as f64) as usize;
        let empty = bar_width - filled;

        print!(
            "\r[{}{}] {:.1}% {} - {}/{} bytes",
            "=".repeat(filled),
            " ".repeat(empty),
            percent,
            progress.filename,
            progress.done,
            progress.total
        );

        if progress.is_complete() {
            println!();
        }

        use std::io::Write;
        let _ = std::io::stdout().flush();

        true // Continue transfer
    })
}
