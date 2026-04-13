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

    assert_eq!(profile.distro, pxe_profiles::Distro::Ubuntu);
    assert_eq!(profile.kernel_path, "/casper/vmlinuz");
    assert_eq!(profile.initrd_path, "/casper/initrd");
    assert!(!profile.label.is_empty(), "label should not be empty");
    println!("Detected label: {}", profile.label);

    let script = pxe_profiles::generate_ipxe_script(&profile, "192.168.1.1", 8080);
    assert!(script.starts_with("#!ipxe\n"));
    assert!(script.contains("/boot/ubuntu/vmlinuz"));
    assert!(script.ends_with("boot\n"));
}
