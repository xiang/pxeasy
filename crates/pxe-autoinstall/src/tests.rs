#[cfg(test)]
mod tests {
    use crate::{AutoInstallConfig, generate_unattend};

    #[test]
    fn test_generate_unattend_with_defaults() {
        let config = AutoInstallConfig::default();
        let unattend = generate_unattend(&config, "amd64", None);

        assert!(unattend.contains("<UILanguage>en-US</UILanguage>"));
        assert!(unattend.contains("<ComputerName>pxeasy-vm</ComputerName>"));
        assert!(unattend.contains("<DisplayName>pxeasy</DisplayName>"));
        assert!(unattend.contains("<Value>password</Value>"));
        assert!(unattend.contains("processorArchitecture=\"amd64\""));
        assert!(unattend.contains("<Value>Windows 11 Home</Value>"));
    }

    #[test]
    fn test_generate_unattend_with_custom_values() {
        let config = AutoInstallConfig {
            enabled: true,
            username: Some("admin".to_string()),
            password: Some("secret123".to_string()),
            hostname: Some("lab-host".to_string()),
            language: Some("en-GB".to_string()),
            keyboard: Some("uk".to_string()),
            timezone: Some("GMT Standard Time".to_string()),
            product_key: Some("AAAAA-BBBBB-CCCCC-DDDDD-EEEEE".to_string()),
            edition: Some("Windows 11 Pro".to_string()),
            wipe_disk: true,
            windows: None,
            ubuntu: None,
        };
        let unattend = generate_unattend(&config, "arm64", None);

        assert!(unattend.contains("<UILanguage>en-GB</UILanguage>"));
        assert!(unattend.contains("<ComputerName>lab-host</ComputerName>"));
        assert!(unattend.contains("<DisplayName>admin</DisplayName>"));
        assert!(unattend.contains("<Value>secret123</Value>"));
        assert!(unattend.contains("<TimeZone>GMT Standard Time</TimeZone>"));
        assert!(unattend.contains("<ProductKey><Key>AAAAA-BBBBB-CCCCC-DDDDD-EEEEE</Key>"));
        assert!(unattend.contains("processorArchitecture=\"arm64\""));
        assert!(unattend.contains("<Value>Windows 11 Pro</Value>"));
    }
}
