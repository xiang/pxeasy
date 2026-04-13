use std::{fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum ProfileError {
    /// The boot media source could not be opened or parsed.
    SourceUnreadable(PathBuf, io::Error),
    /// No supported distro was detected in the source.
    UnknownDistro,
    /// A file that must exist inside the source for the detected distro is absent.
    MissingFile { path: String },
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::SourceUnreadable(path, err) => {
                write!(f, "boot source unreadable at {}: {}", path.display(), err)
            }
            ProfileError::UnknownDistro => {
                write!(f, "no supported distro detected in boot source")
            }
            ProfileError::MissingFile { path } => {
                write!(f, "expected file missing from boot source: {}", path)
            }
        }
    }
}

impl std::error::Error for ProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProfileError::SourceUnreadable(_, err) => Some(err),
            _ => None,
        }
    }
}
