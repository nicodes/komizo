//! Routes are compiled from protected identities and bounded hostname annotations.
use super::{
    identifier,
    policy::{StaticServingOptions, commit_id},
};
use crate::{host::authority::quote, wire::Slice};
use anyhow::{Result, bail, ensure};
use std::collections::{BTreeMap, BTreeSet};
pub fn deployment_route(
    app: &str,
    revision: &str,
    hostnames: &[u8],
    allow_wildcard: bool,
) -> Result<(Vec<u8>, Vec<u8>, Slice<String>)> {
    ensure!(
        identifier(app) && commit_id(revision) && hostnames.len() <= 16 << 10,
        "invalid route inputs"
    );
    let mut plain = vec![];
    let mut wild = vec![];
    let mut names = Slice::default();
    let mut metadata = vec![];
    let mut seen = BTreeSet::new();
    for line in String::from_utf8_lossy(hostnames).split('\n') {
        let line = line.split('#').next().unwrap().trim();
        if line.is_empty() {
            continue;
        }
        let mut fields: Vec<_> = line.split_whitespace().map(str::to_owned).collect();
        ensure!(fields.len() <= 4, "invalid hostname annotation");
        let mut index = 1;
        if fields.len() > 1 && fields[1] == "->" {
            ensure!(
                fields.len() >= 3 && identifier(&fields[2]),
                "invalid container annotation"
            );
            index = 3;
        }
        if fields.len() > index {
            ensure!(
                fields.len() == index + 1 && fields[index] == "on-demand",
                "unsupported certificate mode"
            );
            index += 1;
        }
        ensure!(index == fields.len(), "invalid hostname annotation");
        let name = fields[0].to_lowercase();
        let raw = name.strip_prefix("*.").unwrap_or(&name);
        ensure!(
            name.len() <= 253 && raw.contains('.') && !seen.contains(&name) && names.len() < 128,
            "invalid or repeated hostname"
        );
        for label in raw.split('.') {
            ensure!(
                !label.is_empty()
                    && label.len() <= 63
                    && label.as_bytes()[0].is_ascii_alphanumeric()
                    && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "invalid hostname label"
            );
        }
        if name.starts_with("*.") {
            ensure!(
                allow_wildcard,
                "wildcard route needs the operator certificate approval gate"
            );
            wild.push(name.clone());
        } else {
            plain.push(name.clone());
        }
        seen.insert(name.clone());
        names.push(name.clone());
        fields[0] = name;
        metadata.push(fields.join(" "));
    }
    let mut body = String::new();
    if !names.is_empty() {
        body.push_str(&format!(
            "# Written by komizo from {revision}.\n# Edits here are lost on the next deploy.\n"
        ));
    }
    for (group, wildcard) in [(plain, false), (wild, true)] {
        if group.is_empty() {
            continue;
        }
        body.push_str(&format!("{} {{\n", group.join(", ")));
        if wildcard {
            body.push_str("\ttls {\n\t\ton_demand\n\t}\n");
        }
        body.push_str(&format!("\theader Strict-Transport-Security \"max-age=31536000\"\n\theader >X-Komizo-Revision \"{revision}\"\n"));
        body.push_str("\tlog {\n\t\toutput file /var/log/caddy/access.log {\n\t\t\troll_size 10mb\n\t\t\troll_keep 3\n\t\t}\n\t\tformat json\n\t}\n");
        body.push_str(&format!("\treverse_proxy {app}-gate:80 {{\n\t\theader_up X-Forwarded-For {{remote_host}}\n\t}}\n}}\n"));
    }
    let recorded = if metadata.is_empty() {
        vec![]
    } else {
        (metadata.join("\n") + "\n").into_bytes()
    };
    Ok((body.into_bytes(), recorded, names))
}
fn words(values: &[String]) -> String {
    values
        .iter()
        .map(|v| quote(v))
        .collect::<Vec<_>>()
        .join(" ")
}
fn header_block(output: &mut String, selector: &str, headers: &BTreeMap<String, String>) {
    for (name, value) in headers {
        output.push_str(&format!("\t\theader {selector}{name} {}\n", quote(value)));
    }
}
pub fn static_serving_route(app: &str, revision: &str, s: &StaticServingOptions) -> String {
    let mut output = format!("\troute {{\n\t\troot * /srv/public/{app}/{revision}\n");
    header_block(&mut output, "", &s.headers);
    for (index, rule) in s.header_rules.iter().enumerate() {
        let name = format!("{app}_header_{index}");
        output.push_str(&format!("\t\t@{name} {{\n"));
        if !rule.paths.is_empty() {
            output.push_str(&format!("\t\t\tpath {}\n", words(&rule.paths)));
        }
        if !rule.except_paths.is_empty() {
            output.push_str(&format!("\t\t\tnot path {}\n", words(&rule.except_paths)));
        }
        if !rule.path_regexp.is_empty() {
            output.push_str(&format!(
                "\t\t\tpath_regexp {name} {}\n",
                quote(&rule.path_regexp)
            ));
        }
        if !rule.methods.is_empty() {
            output.push_str(&format!("\t\t\tmethod {}\n", rule.methods.join(" ")));
        }
        if rule.existing_file {
            output.push_str("\t\t\tfile {path}\n");
        }
        output.push_str("\t\t}\n");
        header_block(&mut output, &format!("@{name} "), &rule.headers);
    }
    if !s.deny_paths.is_empty() {
        output.push_str(&format!(
            "\t\t@{app}_denied path {}\n\t\trespond @{app}_denied 404\n",
            words(&s.deny_paths),
        ));
    }
    if !s.encode.is_empty() {
        output.push_str(&format!("\t\tencode {}", s.encode.join(" ")));
        if s.encode_content_types.is_empty() {
            output.push('\n');
        } else {
            output.push_str(" {\n\t\t\tmatch {\n");
            for value in s.encode_content_types.iter() {
                output.push_str(&format!("\t\t\t\theader Content-Type {}\n", quote(value)));
            }
            output.push_str("\t\t\t}\n\t\t}\n");
        }
    }
    if !s.fallbacks.is_empty() {
        output.push_str(&format!("\t\ttry_files {}\n", words(&s.fallbacks)));
    }
    if s.precompressed.is_empty() {
        output.push_str("\t\tfile_server\n");
    } else {
        output.push_str(&format!(
            "\t\tfile_server {{\n\t\t\tprecompressed {}\n\t\t}}\n",
            s.precompressed.join(" ")
        ));
    }
    output.push_str("\t}\n");
    output
}
pub fn static_route(
    route: &[u8],
    app: &str,
    revision: &str,
    hostnames: &[String],
    serving: &StaticServingOptions,
) -> Result<Vec<u8>> {
    serving.check()?;
    ensure!(
        identifier(app) && commit_id(revision) && route.len() <= super::yaml::MAX_BYTES,
        "invalid static route identity"
    );
    let wanted: BTreeSet<_> = hostnames.iter().map(String::as_str).collect();
    let mut seen = BTreeSet::new();
    let route = String::from_utf8_lossy(route);
    for line in route.split('\n') {
        if line.is_empty() || line.starts_with(['\t', '#']) || !line.ends_with(" {") {
            continue;
        }
        for host in line.strip_suffix(" {").unwrap().split_whitespace() {
            ensure!(
                wanted.contains(host) && seen.insert(host),
                "static route hostname differs from its reviewed serving profile"
            );
        }
    }
    ensure!(
        !seen.is_empty() && seen.len() == wanted.len(),
        "static route lacks its reviewed exact hostnames"
    );
    let needle = format!(
        "\treverse_proxy {app}-gate:80 {{\n\t\theader_up X-Forwarded-For {{remote_host}}\n\t}}\n"
    );
    if !(1..=64).contains(&route.matches(&needle).count()) {
        bail!("static profile requires exact host-generated gate routes");
    }
    Ok(route
        .replace(&needle, &static_serving_route(app, revision, serving))
        .replace(
            "\theader >X-Komizo-Revision ",
            "\theader X-Komizo-Revision ",
        )
        .into_bytes())
}
