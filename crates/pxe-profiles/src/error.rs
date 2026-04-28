use std::{io, path::PathBuf};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProfileError {
    /// The boot media source could not be opened or parsed.
    #[error("boot source unreadable at {0}: {1}")]
    SourceUnreadable(PathBuf, #[source] io::Error),
    /// No supported platform was detected in the source.
    #[error("no supported platform detected in boot source")]
    UnknownDistro,
    /// A file that must exist inside the source for the detected distro is absent.
    #[error("expected file missing from boot source: {path}")]
    MissingFile { path: String },
}
