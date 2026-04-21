use crate::{Architecture, BootSourceKind, ProfileError, SourceFs, WindowsProfile};

pub(crate) fn detect_from_source(
    source: &dyn SourceFs,
    volume_label: Option<&str>,
) -> Result<Option<WindowsProfile>, ProfileError> {
    let install_wim_path = if source.path_exists("/sources/install.wim")? {
        Some("/sources/install.wim".to_string())
    } else if source.path_exists("/sources/install.esd")? {
        Some("/sources/install.esd".to_string())
    } else {
        None
    };

    let Some(install_wim_path) = install_wim_path else {
        return Ok(None);
    };

    let bootmgr_path = first_existing_path(source, &["/bootmgr", "/bootmgr.efi", "/bootmgfw.efi"])?
        .ok_or_else(|| ProfileError::MissingFile {
            path: "/bootmgr".to_string(),
        })?;
    let bcd_path = first_existing_path(source, &["/boot/bcd", "/efi/microsoft/boot/bcd"])?
        .ok_or_else(|| ProfileError::MissingFile {
            path: "/boot/bcd".to_string(),
        })?;

    for required in ["/boot/boot.sdi", "/sources/boot.wim"] {
        if !source.path_exists(required)? {
            return Err(ProfileError::MissingFile {
                path: required.to_string(),
            });
        }
    }

    let efi_path = if source.path_exists("/efi/boot/bootx64.efi")? {
        Some("/efi/boot/bootx64.efi".to_string())
    } else if source.path_exists("/efi/boot/bootaa64.efi")? {
        Some("/efi/boot/bootaa64.efi".to_string())
    } else {
        None
    };

    let architecture = if source.path_exists("/efi/boot/bootx64.efi")? {
        Architecture::Amd64
    } else if source.path_exists("/efi/boot/bootaa64.efi")? {
        Architecture::Arm64
    } else {
        Architecture::Amd64
    };

    let label = volume_label
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Windows (detected)".to_string());

    Ok(Some(WindowsProfile {
        source_kind: BootSourceKind::WindowsIso,
        architecture,
        efi_path,
        label,
        bootmgr_path,
        bcd_path,
        boot_sdi_path: "/boot/boot.sdi".to_string(),
        boot_wim_path: "/sources/boot.wim".to_string(),
        install_wim_path,
    }))
}

fn first_existing_path(
    source: &dyn SourceFs,
    candidates: &[&str],
) -> Result<Option<String>, ProfileError> {
    for candidate in candidates {
        if source.path_exists(candidate)? {
            return Ok(Some((*candidate).to_string()));
        }
    }

    Ok(None)
}
