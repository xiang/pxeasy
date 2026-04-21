use std::path::Path;

use crate::{
    architecture_from_path, detect_architecture, Architecture, BootSourceKind, LinuxProfile,
    Platform, ProfileError, SourceFs,
};

pub(crate) fn detect_profile(source_path: &Path) -> Option<LinuxProfile> {
    let filename = source_path.file_name()?.to_str()?.to_ascii_lowercase();
    if !filename.contains("freebsd") {
        return None;
    }

    let is_install_image = filename.contains("bootonly")
        || filename.contains("memstick")
        || filename.contains("disc1")
        || filename.contains("mini")
        || filename.contains("sanboot")
        || filename.contains("mfs");
    if !is_install_image
        || !matches!(source_path.extension().and_then(|ext| ext.to_str()), Some(ext) if ext.eq_ignore_ascii_case("iso") || ext.eq_ignore_ascii_case("img") || ext.eq_ignore_ascii_case("raw"))
    {
        return None;
    }

    let architecture = architecture_from_path(&filename).unwrap_or(Architecture::Unknown);
    let efi_path = Some("/boot/loader.efi".to_string());

    Some(LinuxProfile {
        platform: Platform::FreeBSD,
        source_kind: BootSourceKind::FreeBSDBootOnly,
        architecture,
        efi_path,
        label: "FreeBSD".to_string(),
        kernel_path: "/boot/loader.efi".to_string(),
        initrd_path: String::new(),
        boot_params: String::new(),
    })
}

pub(crate) fn detect_from_source(
    source: &dyn SourceFs,
    filename: Option<&str>,
) -> Result<Option<LinuxProfile>, ProfileError> {
    if source.path_exists("/boot/kernel/kernel")? && source.path_exists("/boot/loader.efi")? {
        let label = "FreeBSD".to_string();
        let efi_path = Some("/boot/loader.efi".to_string());
        let mut hints = vec!["FreeBSD"];
        if let Some(f) = filename {
            hints.push(f);
        }

        return Ok(Some(LinuxProfile {
            platform: Platform::FreeBSD,
            source_kind: BootSourceKind::FreeBSDBootOnly,
            architecture: detect_architecture(source, &hints, &efi_path, &["/boot/kernel"])?,
            efi_path,
            label,
            kernel_path: "/boot/loader.efi".to_string(),
            initrd_path: String::new(),
            boot_params: String::new(),
        }));
    }

    Ok(None)
}
