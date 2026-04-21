/// Integration test against a real Ubuntu 24.04 LTS ISO.
///
/// Skipped by default. To run:
///   UBUNTU_ISO=/path/to/ubuntu-24.04-live-server-amd64.iso cargo test -p pxe-profiles -- --ignored
#[test]
#[ignore = "requires UBUNTU_ISO env var pointing to a real Ubuntu 24.04 LTS ISO"]
fn real_ubuntu_iso_detected() {
    let path = std::env::var("UBUNTU_ISO").expect("UBUNTU_ISO env var must be set");
    let profile =
        pxe_profiles::detect_profile(std::path::Path::new(&path)).expect("detect_profile failed");

    match &profile {
        pxe_profiles::BootProfile::Linux(profile) => {
            assert_eq!(profile.platform, pxe_profiles::Platform::Ubuntu);
            let kernel_path = &profile.kernel_path;
            let initrd_path = &profile.initrd_path;
            assert_eq!(kernel_path, "/casper/vmlinuz");
            assert_eq!(initrd_path, "/casper/initrd");
            assert!(profile.efi_path.is_some(), "EFI path should be detected");
            assert!(!profile.label.is_empty(), "label should not be empty");
            println!("Detected label: {}", profile.label);
            println!("Detected EFI: {:?}", profile.efi_path);
        }
        _ => panic!("expected BootProfile::Linux for Ubuntu"),
    }
}
