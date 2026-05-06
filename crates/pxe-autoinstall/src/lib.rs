use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoInstallConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub username: Option<String>,
    pub password: Option<String>,
    pub hostname: Option<String>,
    pub language: Option<String>,
    pub keyboard: Option<String>,
    pub timezone: Option<String>,
    pub product_key: Option<String>,
    pub edition: Option<String>,
    #[serde(default = "default_true")]
    pub wipe_disk: bool,

    // OS-specific overrides
    pub windows: Option<OsSpecificConfig>,
    pub ubuntu: Option<OsSpecificConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OsSpecificConfig {
    pub username: Option<String>,
    pub password: Option<String>,
    pub hostname: Option<String>,
    pub language: Option<String>,
    pub keyboard: Option<String>,
    pub timezone: Option<String>,
    pub product_key: Option<String>,
    pub edition: Option<String>,
    pub wipe_disk: Option<bool>,
}

impl AutoInstallConfig {
    /// Merge OS-specific overrides into a flat configuration.
    pub fn for_os(&self, os_override: Option<&OsSpecificConfig>) -> Self {
        let mut base = self.clone();
        if let Some(over) = os_override {
            if over.username.is_some() {
                base.username = over.username.clone();
            }
            if over.password.is_some() {
                base.password = over.password.clone();
            }
            if over.hostname.is_some() {
                base.hostname = over.hostname.clone();
            }
            if over.language.is_some() {
                base.language = over.language.clone();
            }
            if over.keyboard.is_some() {
                base.keyboard = over.keyboard.clone();
            }
            if over.timezone.is_some() {
                base.timezone = over.timezone.clone();
            }
            if over.product_key.is_some() {
                base.product_key = over.product_key.clone();
            }
            if over.edition.is_some() {
                base.edition = over.edition.clone();
            }
            if let Some(wipe) = over.wipe_disk {
                base.wipe_disk = wipe;
            }
        }
        base
    }
}

fn default_true() -> bool {
    true
}

impl Default for AutoInstallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            username: None,
            password: None,
            hostname: Some("pxeasy-vm".to_string()),
            language: Some("en-US".to_string()),
            keyboard: Some("us".to_string()),
            timezone: Some("UTC".to_string()),
            product_key: None,
            edition: None,
            wipe_disk: true,
            windows: None,
            ubuntu: None,
        }
    }
}

pub mod windows;
pub use windows::generate_unattend;

#[cfg(test)]
mod tests;
