use std::{fmt, io, path::PathBuf};

#[derive(Debug)]
pub enum ProfileError {
    /// The ISO file could not be opened or parsed.
    IsoUnreadable(PathBuf, io::Error),
    /// No supported distro was detected in the ISO.
    UnknownDistro,
    /// A file that must exist inside the ISO for the detected distro is absent.
    MissingFile { path: String },
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::IsoUnreadable(path, err) => {
                write!(f, "ISO unreadable at {}: {}", path.display(), err)
            }
            ProfileError::UnknownDistro => {
                write!(f, "no supported distro detected in ISO")
            }
            ProfileError::MissingFile { path } => {
                write!(f, "expected file missing from ISO: {}", path)
            }
        }
    }
}

impl std::error::Error for ProfileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProfileError::IsoUnreadable(_, err) => Some(err),
            _ => None,
        }
    }
}
