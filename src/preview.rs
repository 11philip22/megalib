//! Preview/thumbnail generation for file uploads.
//!
//! This module provides functionality to generate 128x128 thumbnails for files before they are uploaded.
//! Available on native targets (not WASM) as it requires filesystem access and the `image` crate.
//!
//! # Supported Formats
//!
//! - **Images** (Native Rust): JPEG, PNG, GIF, BMP, TIFF, WebP, ICO.
//! - **Videos** (External Tool): MP4, MKV, AVI, MOV, WMV, FLV, WEBM, MPG, MPEG, M4V.
//!   - Requires `ffmpegthumbnailer` to be installed and available in the system PATH.
//!
//! # Example
//!
//! ```no_run
//! use std::path::Path;
//! use megalib::preview::generate_thumbnail;
//!
//! fn main() {
//!     let path = Path::new("my_photo.jpg");
//!     
//!     if let Some(result) = generate_thumbnail(path) {
//!         match result {
//!             Ok(thumbnail_data) => {
//!                 println!("Generated thumbnail: {} bytes", thumbnail_data.len());
//!                 // Upload thumbnail_data...
//!             }
//!             Err(e) => eprintln!("Failed to generate thumbnail: {}", e),
//!         }
//!     } else {
//!         println!("No thumbnail support for this file type.");
//!     }
//! }
//! ```

use std::io::Cursor;
use std::path::Path;
use std::process::Command;

use image::{ImageFormat, ImageReader};

use crate::error::{MegaError, Result};

/// Thumbnail size (MEGA uses 128x128)
pub const THUMBNAIL_SIZE: u32 = 128;

/// Supported image extensions for pure Rust thumbnail generation
const IMAGE_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "gif", "bmp", "tiff", "tif", "webp", "ico",
];

/// Supported video extensions for ffmpegthumbnailer
const VIDEO_EXTENSIONS: &[&str] = &[
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "mpg", "mpeg", "m4v",
];

/// Check if a file extension is a supported image format.
///
/// Case-insensitive comparison against supported extensions.
///
/// # Example
/// ```
/// use megalib::preview::is_image;
///
/// assert!(is_image("jpg"));
/// assert!(is_image("PNG"));
/// assert!(!is_image("txt"));
/// ```
pub fn is_image(extension: &str) -> bool {
    IMAGE_EXTENSIONS.contains(&extension.to_lowercase().as_str())
}

/// Check if a file extension is a supported video format.
///
/// Case-insensitive comparison against supported extensions.
///
/// # Example
/// ```
/// use megalib::preview::is_video;
///
/// assert!(is_video("mp4"));
/// assert!(is_video("MKV"));
/// assert!(!is_video("jpg"));
/// ```
pub fn is_video(extension: &str) -> bool {
    VIDEO_EXTENSIONS.contains(&extension.to_lowercase().as_str())
}

/// Generate a thumbnail from image data (pure Rust).
///
/// This function decodes the image data, crops and resizes it to 128x128 pixels using
/// the Lanczos3 filter, and re-encodes it as a JPEG.
///
/// # Arguments
/// * `data` - Raw image file data
///
/// # Returns
/// JPEG thumbnail data (128x128) or error if not a supported format.
pub fn generate_image_thumbnail(data: &[u8]) -> Result<Vec<u8>> {
    let reader = ImageReader::new(Cursor::new(data))
        .with_guessed_format()
        .map_err(|e| MegaError::Custom(format!("Failed to detect image format: {}", e)))?;

    let img = reader
        .decode()
        .map_err(|e| MegaError::Custom(format!("Failed to decode image: {}", e)))?;

    // Resize to 128x128 (cover style - crop to fit)
    let thumbnail = img.resize_to_fill(
        THUMBNAIL_SIZE,
        THUMBNAIL_SIZE,
        image::imageops::FilterType::Lanczos3,
    );

    // Encode as JPEG
    let mut output = Vec::new();
    let mut cursor = Cursor::new(&mut output);
    thumbnail
        .write_to(&mut cursor, ImageFormat::Jpeg)
        .map_err(|e| MegaError::Custom(format!("Failed to encode thumbnail: {}", e)))?;

    Ok(output)
}

/// Generate a thumbnail from an image file (pure Rust).
///
/// Wrapper around `generate_image_thumbnail` that readsFromFile first.
///
/// # Arguments
/// * `path` - Path to the image file
pub fn generate_image_thumbnail_from_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let data = std::fs::read(path.as_ref())
        .map_err(|e| MegaError::Custom(format!("Failed to read file: {}", e)))?;
    generate_image_thumbnail(&data)
}

/// Generate a thumbnail from a video file using ffmpegthumbnailer.
///
/// Requires `ffmpegthumbnailer` to be installed and in PATH.
/// It attempts to take a snapshot at 5% of the video duration.
///
/// # Arguments
/// * `path` - Path to the video file
///
/// # Returns
/// JPEG thumbnail data or error if ffmpegthumbnailer is not available or fails.
pub fn generate_video_thumbnail<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    // Create temp file for thumbnail
    let temp_dir = std::env::temp_dir();
    let thumb_path = temp_dir.join(format!("megalib_thumb_{}.jpg", std::process::id()));

    // Run ffmpegthumbnailer
    let output = Command::new("ffmpegthumbnailer")
        .args([
            "-i",
            path.as_ref()
                .to_str()
                .ok_or_else(|| MegaError::Custom("Invalid path".to_string()))?,
            "-o",
            thumb_path
                .to_str()
                .ok_or_else(|| MegaError::Custom("Invalid temp path".to_string()))?,
            "-s",
            "128",
            "-t",
            "5%", // 5% into the video
            "-f", // Overwrite
        ])
        .output();

    match output {
        Ok(result) => {
            if !result.status.success() {
                let _ = std::fs::remove_file(&thumb_path);
                return Err(MegaError::Custom(format!(
                    "ffmpegthumbnailer failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                )));
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(MegaError::Custom(
                    "ffmpegthumbnailer not found. Install it to generate video thumbnails."
                        .to_string(),
                ));
            }
            return Err(MegaError::Custom(format!(
                "Failed to run ffmpegthumbnailer: {}",
                e
            )));
        }
    }

    // Read thumbnail data
    let data = std::fs::read(&thumb_path)
        .map_err(|e| MegaError::Custom(format!("Failed to read thumbnail: {}", e)))?;

    // Cleanup
    let _ = std::fs::remove_file(&thumb_path);

    Ok(data)
}

/// Check if ffmpegthumbnailer is available.
///
/// Returns `true` if the `ffmpegthumbnailer` command can be executed successfully.
pub fn has_ffmpegthumbnailer() -> bool {
    Command::new("ffmpegthumbnailer")
        .arg("--help")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Generate a thumbnail for a file (auto-detects format).
///
/// This is the main entry point for thumbnail generation. It inspects the file extension
/// and delegates to the appropriate generator.
///
/// # Arguments
/// * `path` - Path to the file
///
/// # Returns
/// * `Some(Ok(Vec<u8>))` - Thumbnail generated successfully
/// * `Some(Err(MegaError))` - Supported type but generation failed
/// * `None` - Unsupported file type
///
/// # Example
/// ```no_run
/// use megalib::preview::generate_thumbnail;
///
/// if let Some(Ok(data)) = generate_thumbnail("video.mp4") {
///     // use data
/// }
/// ```
pub fn generate_thumbnail<P: AsRef<Path>>(path: P) -> Option<Result<Vec<u8>>> {
    let path = path.as_ref();
    let extension = path.extension()?.to_str()?.to_lowercase();

    if is_image(&extension) {
        Some(generate_image_thumbnail_from_file(path))
    } else if is_video(&extension) {
        Some(generate_video_thumbnail(path))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_image() {
        assert!(is_image("jpg"));
        assert!(is_image("PNG"));
        assert!(is_image("jpeg"));
        assert!(!is_image("mp4"));
        assert!(!is_image("txt"));
    }

    #[test]
    fn test_is_video() {
        assert!(is_video("mp4"));
        assert!(is_video("MKV"));
        assert!(is_video("avi"));
        assert!(!is_video("jpg"));
        assert!(!is_video("txt"));
    }
    #[test]
    fn test_generate_image_thumbnail_invalid_data() {
        let garbage = [0u8; 100];
        assert!(generate_image_thumbnail(&garbage).is_err());
    }

    #[test]
    fn test_generate_thumbnail_unsupported() {
        let path = Path::new("test.txt");
        assert!(generate_thumbnail(path).is_none());
    }
}
