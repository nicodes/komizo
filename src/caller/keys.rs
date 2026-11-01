//! Deploy keys stay in memory until an explicit key-file destination is selected.
use crate::{host::authority::keys::public_from_seed, wire::Bytes};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::path::Path;
const BAD: &str = "existing key is not an intact komizo key for this application and host";
const MAGIC: &[u8] = b"openssh-key-v1\0";
pub struct Keypair {
    pub private: Bytes,
    pub public: String,
}
impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("private", &"[redacted]")
            .field("public", &self.public)
            .finish()
    }
}
fn field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}
pub fn public_blob(public: &[u8]) -> Vec<u8> {
    let mut blob = vec![];
    field(&mut blob, b"ssh-ed25519");
    field(&mut blob, public);
    blob
}
pub fn comment(user: &str, host: &str) -> String {
    format!("komizo:{user}@{}", host.trim())
}
pub fn encode(seed: &[u8; 32], comment: &str, check: [u8; 4]) -> Result<Keypair> {
    ensure!(comment.len() <= 4096, "key comment exceeds its bound");
    let public = public_from_seed(seed)?;
    let mut private = seed.to_vec();
    private.extend_from_slice(&public);
    let mut section = vec![];
    section.extend_from_slice(&check);
    section.extend_from_slice(&check);
    field(&mut section, b"ssh-ed25519");
    field(&mut section, &public);
    field(&mut section, &private);
    field(&mut section, comment.as_bytes());
    let mut padding = 1;
    while section.len() % 8 != 0 {
        section.push(padding);
        padding += 1;
    }
    let blob = public_blob(&public);
    let mut body = MAGIC.to_vec();
    field(&mut body, b"none");
    field(&mut body, b"none");
    field(&mut body, b"");
    body.extend_from_slice(&1u32.to_be_bytes());
    field(&mut body, &blob);
    field(&mut body, &section);
    let encoded = STANDARD.encode(body);
    let mut pem = b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec();
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END OPENSSH PRIVATE KEY-----\n");
    Ok(Keypair {
        private: pem.into(),
        public: format!("ssh-ed25519 {} {comment}", STANDARD.encode(blob)),
    })
}
pub fn generate(comment: &str) -> Result<Keypair> {
    let mut seed = [0; 32];
    let mut check = [0; 4];
    getrandom::fill(&mut seed)?;
    getrandom::fill(&mut check)?;
    encode(&seed, comment, check)
}
struct Reader<'a> {
    body: &'a [u8],
}
impl<'a> Reader<'a> {
    fn number(&mut self) -> Result<u32> {
        ensure!(self.body.len() >= 4, "{BAD}");
        let n = u32::from_be_bytes(self.body[..4].try_into().unwrap());
        self.body = &self.body[4..];
        Ok(n)
    }
    fn field(&mut self) -> Result<&'a [u8]> {
        let n = self.number()? as usize;
        ensure!(n <= self.body.len(), "{BAD}");
        let value = &self.body[..n];
        self.body = &self.body[n..];
        Ok(value)
    }
}
pub fn decode(body: &[u8], comment: &str) -> Result<Keypair> {
    ensure!(body.len() <= 64 << 10, "{BAD}");
    let start = b"-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = b"-----END OPENSSH PRIVATE KEY-----";
    let first = body
        .windows(start.len())
        .enumerate()
        .find_map(|(index, v)| {
            (v == start && (index == 0 || body[index - 1] == b'\n')).then_some(index)
        })
        .ok_or_else(|| anyhow::anyhow!(BAD))?
        + start.len();
    let tail = &body[first..];
    let last = tail
        .windows(end.len())
        .position(|v| v == end)
        .ok_or_else(|| anyhow::anyhow!(BAD))?;
    ensure!(
        crate::wire::trim_space(&tail[last + end.len()..]).is_empty(),
        "{BAD}"
    );
    let text = std::str::from_utf8(&tail[..last]).map_err(|_| anyhow::anyhow!(BAD))?;
    let encoded: String = text
        .lines()
        .filter(|line| !line.contains(':'))
        .map(str::trim)
        .collect();
    let decoded = crate::wire::decode_base64(&encoded).map_err(|_| anyhow::anyhow!(BAD))?;
    ensure!(decoded.starts_with(MAGIC), "{BAD}");
    let mut r = Reader {
        body: &decoded[MAGIC.len()..],
    };
    ensure!(
        r.field()? == b"none" && r.field()? == b"none" && r.field()?.is_empty() && r.number()? == 1,
        "{BAD}"
    );
    let blob = r.field()?;
    let section = r.field()?;
    ensure!(r.body.is_empty(), "{BAD}");
    let mut p = Reader { body: section };
    let check = p.number()?;
    ensure!(
        p.number()? == check && p.field()? == b"ssh-ed25519",
        "{BAD}"
    );
    let public = p.field()?;
    let private = p.field()?;
    let recorded = p.field()?;
    ensure!(
        public.len() == 32 && private.len() == 64 && recorded == comment.as_bytes(),
        "{BAD}"
    );
    let derived = public_from_seed(&private[..32])?;
    ensure!(
        private[32..] == derived
            && public == derived
            && blob == public_blob(public)
            && section.len() % 8 == 0
            && p.body.len() <= 8
            && p.body.iter().enumerate().all(|(i, b)| *b == (i + 1) as u8),
        "{BAD}"
    );
    Ok(Keypair {
        private: body.to_vec().into(),
        public: format!("ssh-ed25519 {} {comment}", STANDARD.encode(blob)),
    })
}
pub fn read_existing(path: &Path, comment: &str) -> Result<Keypair> {
    decode(&super::state::read_file(path, 64 << 10, true)?, comment)
}
