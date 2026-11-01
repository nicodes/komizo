use crate::host::authority::quote;
use anyhow::{Result, ensure};
fn chars(value: &str, dot: bool, slash: bool, colon: bool) -> bool {
    value.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || b == b'_'
            || b == b'-'
            || (dot && b == b'.')
            || (slash && b == b'/')
            || (colon && b == b':')
    })
}
pub fn app(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && chars(value, false, false, false),
        "--app must be letters, digits, underscore or hyphen; got {}",
        quote(value)
    );
    ensure!(
        !value.starts_with('_'),
        "app names starting with \"_\" are reserved for komizo; got {}",
        quote(value)
    );
    Ok(())
}
pub fn user(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && chars(value, false, false, false),
        "--user must be letters, digits, underscore or hyphen; got {}",
        quote(value)
    );
    Ok(())
}
pub fn login_user(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.starts_with('-') && chars(value, true, false, false),
        "login user contains characters that are not allowed: {}",
        quote(value)
    );
    Ok(())
}
pub fn host(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty() && !value.starts_with('-') && chars(value, true, false, false),
        "hostname contains unexpected characters: {}",
        quote(value)
    );
    Ok(())
}
pub fn app_dir(value: &str) -> Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    ensure!(
        value.starts_with('/'),
        "--app-dir must be an absolute path, got {}",
        quote(value)
    );
    ensure!(
        chars(value, true, true, false),
        "--app-dir contains characters that are not allowed: {}",
        quote(value)
    );
    ensure!(
        !value.split('/').any(|part| part == ".."),
        "--app-dir must not contain a \"..\" path component, got {}",
        quote(value)
    );
    Ok(())
}
pub fn network(value: &str) -> Result<()> {
    ensure!(
        chars(value, true, false, false),
        "--network must be letters, digits, dot, underscore or hyphen; got {}",
        quote(value)
    );
    Ok(())
}
pub fn config_image(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty(),
        "--config is required, e.g. --config ghcr.io/you/myapp-config\n\n    It is where the host looks for each deploy's compose.yml. Pinning it\n    on the server is what stops a leaked deploy key redirecting the host\n    at an image an attacker controls."
    );
    ensure!(
        !value.contains('@'),
        "--config must not include a digest, got {}",
        quote(value)
    );
    ensure!(
        chars(value, true, true, true),
        "--config contains characters that are not valid in an image reference: {}",
        quote(value)
    );
    ensure!(
        !value.rsplit('/').next().unwrap_or_default().contains(':'),
        "--config must not include a tag (got {}); the deploy supplies it",
        quote(value)
    );
    ensure!(
        !value.ends_with('/'),
        "--config must not end in \"/\", got {}",
        quote(value)
    );
    Ok(())
}
pub fn scrub(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c != '\n' && c != '\t' && (c < ' ' || ('\u{7f}'..='\u{9f}').contains(&c)) {
                ' '
            } else {
                c
            }
        })
        .collect()
}
