use crate::AutoInstallConfig;

const DEFAULT_WINDOWS_UNATTEND: &str = include_str!("../templates/autounattend.xml");

pub fn generate_unattend(
    config: &AutoInstallConfig,
    arch: &str,
    template: Option<&str>,
) -> String {
    let template = template.unwrap_or(DEFAULT_WINDOWS_UNATTEND);

    // Hardcoded internal defaults if config fields are None
    let username = config.username.as_deref().unwrap_or("pxeasy");
    let password = config.password.as_deref().unwrap_or("password");
    let hostname = config.hostname.as_deref().unwrap_or("pxeasy-vm");
    let language = config.language.as_deref().unwrap_or("en-US");
    let keyboard = config.keyboard.as_deref().unwrap_or("us");
    let timezone = config.timezone.as_deref().unwrap_or("UTC");
    let edition = config.edition.as_deref().unwrap_or("Windows 11 Home");

    let product_key_xml = if let Some(key) = &config.product_key {
        format!(
            "<ProductKey><Key>{}</Key><WillShowUI>OnError</WillShowUI></ProductKey>",
            key
        )
    } else {
        "<ProductKey><Key></Key><WillShowUI>OnError</WillShowUI></ProductKey>".to_string()
    };

    let image_selection_xml = format!(
        r#"<InstallFrom>
            <MetaData wcm:action="add">
                <Key>/IMAGE/NAME</Key>
                <Value>{}</Value>
            </MetaData>
        </InstallFrom>"#,
        edition
    );

    template
        .replace("{{ARCH}}", arch)
        .replace("{{USERNAME}}", username)
        .replace("{{PASSWORD}}", password)
        .replace("{{HOSTNAME}}", hostname)
        .replace("{{LANGUAGE}}", language)
        .replace("{{KEYBOARD}}", keyboard)
        .replace("{{TIMEZONE}}", timezone)
        .replace("{{WIPE_DISK}}", if config.wipe_disk { "true" } else { "false" })
        .replace("{{PRODUCT_KEY_XML}}", &product_key_xml)
        .replace("{{IMAGE_SELECTION_XML}}", &image_selection_xml)
}
