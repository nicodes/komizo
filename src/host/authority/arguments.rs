use super::{Command, alphabet, quote};
use crate::wire::Slice;
use anyhow::{Result, ensure};
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AddSpec {
    #[serde(rename = "App")]
    pub app: String,
    #[serde(rename = "Config")]
    pub config: String,
    #[serde(rename = "PubKey")]
    pub pubkey: String,
    #[serde(rename = "User")]
    pub user: String,
    #[serde(rename = "AppDir")]
    pub app_dir: String,
    #[serde(rename = "KnownAs")]
    pub known_as: Slice<String>,
    #[serde(rename = "HardenSSH")]
    pub harden_ssh: bool,
}
pub fn valid_pubkey(key: &str) -> Result<()> {
    ensure!(!key.is_empty(), "needs the public half of a deploy key");
    ensure!(!key.contains(['\n', '\r']), "a deploy key is one line");
    ensure!(
        key.starts_with("ssh-ed25519 "),
        "a deploy key is ssh-ed25519"
    );
    Ok(())
}
pub fn valid_hostname(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && !value.starts_with('-')
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
        "{} is not a hostname",
        quote(value)
    );
    Ok(())
}
pub fn valid_account(value: &str) -> bool {
    !value.is_empty() && value.len() <= 32 && !value.starts_with('-') && alphabet(value)
}
pub fn has_dot_dot(value: &str) -> bool {
    value.split('/').any(|part| part == "..")
}
pub fn only_path_chars(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/'))
}
pub fn only_image_chars(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'/' | b':'))
}
pub fn last_segment(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}
impl Command {
    pub fn arg(&self, name: &str) -> &str {
        self.args.get(name).map(String::as_str).unwrap_or_default()
    }
    pub fn app_of(&self) -> Result<&str> {
        let name = self.arg("app");
        ensure!(!name.is_empty(), "{} needs an app", self.op);
        ensure!(
            !name.contains(['/', '.']) && !name.starts_with('-') && alphabet(name),
            "{} is not an app name",
            quote(name)
        );
        Ok(name)
    }
    pub fn rotate_of(&self) -> Result<(&str, &str)> {
        let app = self.app_of()?;
        ensure!(!app.starts_with('_'), "{} is reserved", quote(app));
        let key = self.arg("pubkey");
        valid_pubkey(key)?;
        for name in self.args.keys() {
            ensure!(
                matches!(name.as_str(), "app" | "pubkey"),
                "app.rotate does not take {} -- it changes the deploy key and nothing else",
                quote(name)
            );
        }
        Ok((app, key))
    }
    pub fn add_of(&self) -> Result<AddSpec> {
        let mut spec = AddSpec {
            app: self.app_of()?.into(),
            config: self.arg("config").into(),
            pubkey: self.arg("pubkey").into(),
            user: self.arg("user").into(),
            app_dir: self.arg("app_dir").into(),
            harden_ssh: self.arg("harden_ssh") == "1",
            ..Default::default()
        };
        valid_pubkey(&spec.pubkey).map_err(|e| anyhow::anyhow!("app.add {e}"))?;
        ensure!(
            !spec.app.starts_with('_'),
            "{} is reserved",
            quote(&spec.app)
        );
        ensure!(
            !spec.config.is_empty(),
            "app.add needs the image its compose file comes from"
        );
        ensure!(
            only_image_chars(&spec.config),
            "{} is not a registry path",
            quote(&spec.config)
        );
        ensure!(
            !last_segment(&spec.config).contains(':'),
            "a config image carries no tag"
        );
        ensure!(
            !spec.config.ends_with('/'),
            "a config image does not end in {}",
            quote("/")
        );
        if !spec.app_dir.is_empty() {
            ensure!(spec.app_dir.starts_with('/'), "app_dir must be absolute");
            ensure!(
                only_path_chars(&spec.app_dir),
                "{} is not a path",
                quote(&spec.app_dir)
            );
            ensure!(
                !has_dot_dot(&spec.app_dir),
                "app_dir must not contain a {} component",
                quote("..")
            );
        }
        let mut known = vec![];
        for name in self
            .arg("known_as")
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            valid_hostname(name).map_err(|e| anyhow::anyhow!("known_as: {e}"))?;
            known.push(name.to_owned());
        }
        if !known.is_empty() {
            spec.known_as = known.into();
        }
        if spec.user.is_empty() {
            spec.user = format!("komizo-{}", spec.app);
        }
        ensure!(
            valid_account(&spec.user),
            "{} is not an account name",
            quote(&spec.user)
        );
        ensure!(spec.user != "root", "the deploy account must not be root");
        Ok(spec)
    }
}
