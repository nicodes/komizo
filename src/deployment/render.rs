use super::{model::*, validation::*};
use anyhow::{Result, anyhow, ensure};
use std::{collections::BTreeMap, fmt::Write, net::SocketAddr};

fn token(value: &str) -> String {
    serde_json::to_string(value).expect("string serialization")
}

fn headers(out: &mut String, values: &BTreeMap<String, String>, matcher: &str) {
    if !values.is_empty() {
        writeln!(out, "header {matcher} {{").unwrap();
        for (key, value) in values {
            writeln!(out, "{} {}", token(key), token(value)).unwrap();
        }
        out.push_str("}\n");
    }
}

fn baseline(out: &mut String) {
    headers(out,&BTreeMap::from([
        ("Strict-Transport-Security".into(),"max-age=31536000".into()),
        ("Content-Security-Policy".into(),"default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'".into()),
        ("Permissions-Policy".into(),"camera=(), microphone=(), geolocation=()".into()),
        ("X-Content-Type-Options".into(),"nosniff".into()),
        ("X-Frame-Options".into(),"DENY".into()),
        ("Referrer-Policy".into(),"strict-origin-when-cross-origin".into()),
    ]),"");
}

fn encode(out: &mut String, encodings: &[String], content_types: &[String]) {
    if encodings.is_empty() {
        return;
    }
    writeln!(out, "encode {} {{", encodings.join(" ")).unwrap();
    if !content_types.is_empty() {
        out.push_str("match {\n");
        for content_type in content_types {
            writeln!(out, "header Content-Type {}", token(content_type)).unwrap();
        }
        out.push_str("}\n");
    }
    out.push_str("}\n");
}

fn replacement(value: &str, matcher: &str) -> String {
    let re = regex::Regex::new(r"\$([0-9]+)").unwrap();
    re.replace_all(value, |c: &regex::Captures<'_>| {
        format!("{{http.regexp.{matcher}.{}}}", &c[1])
    })
    .into_owned()
}

fn serving(out: &mut String, value: &Serving, root: &str, prefix: &str) {
    writeln!(out, "root * {}", token(root)).unwrap();
    if !value.deny_paths.is_empty() {
        writeln!(
            out,
            "@{prefix}deny path {}",
            value
                .deny_paths
                .iter()
                .map(|v| token(v))
                .collect::<Vec<_>>()
                .join(" ")
        )
        .unwrap();
        writeln!(out, "respond @{prefix}deny 404").unwrap();
    }
    headers(out, &value.headers, "");
    for (i, rule) in value.header_rules.iter().enumerate() {
        let matcher = format!("{prefix}h{i}");
        writeln!(out, "@{matcher} {{").unwrap();
        if !rule.paths.is_empty() {
            writeln!(
                out,
                "path {}",
                rule.paths
                    .iter()
                    .map(|v| token(v))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
            .unwrap();
        }
        if !rule.except_paths.is_empty() {
            writeln!(
                out,
                "not path {}",
                rule.except_paths
                    .iter()
                    .map(|v| token(v))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
            .unwrap();
        }
        if let Some(pattern) = &rule.path_regexp {
            writeln!(out, "path_regexp {}", token(pattern)).unwrap();
        }
        if !rule.methods.is_empty() {
            writeln!(out, "method {}", rule.methods.join(" ")).unwrap();
        }
        if rule.existing_file {
            out.push_str("file {path}\n");
        }
        out.push_str("}\n");
        headers(out, &rule.headers, &format!("@{matcher}"));
    }
    for (i, rule) in value.route_rules.iter().enumerate() {
        let matcher = format!("{prefix}r{i}");
        writeln!(
            out,
            "@{matcher} path_regexp {matcher} {}",
            token(&rule.pattern)
        )
        .unwrap();
        let destination = token(&replacement(&rule.replacement, &matcher));
        if let Some(status) = rule.redirect_status {
            writeln!(out, "redir @{matcher} {destination} {status}").unwrap();
        } else {
            writeln!(out, "rewrite @{matcher} {destination}").unwrap();
        }
    }
    encode(out, &value.encode, &value.encode_content_types);
    if !value.fallbacks.is_empty() {
        let paths = value
            .fallbacks
            .iter()
            .map(|p| {
                if p.starts_with('/') || p.starts_with("{path}") {
                    p.clone()
                } else {
                    format!("/{p}")
                }
            })
            .map(|p| token(&p))
            .collect::<Vec<_>>()
            .join(" ");
        writeln!(out, "try_files {paths}").unwrap();
    }
    out.push_str("file_server {\n");
    if !value.precompressed.is_empty() {
        writeln!(out, "precompressed {}", value.precompressed.join(" ")).unwrap();
    }
    if value.not_found.is_some() {
        out.push_str("pass_thru\n");
    }
    out.push_str("}\n");
    if let Some(path) = &value.not_found {
        writeln!(
            out,
            "rewrite * {}\nfile_server {{\nstatus 404\n}}",
            token(&format!("/{path}"))
        )
        .unwrap();
    }
}

/// Render a complete proxy configuration from the same model used by admission.
/// Test HTTP listeners are an explicit offline option, never a host policy flag.
pub fn caddy(
    document: &ReleaseDocument,
    assets_root: &str,
    upstreams: &BTreeMap<String, String>,
    http: bool,
) -> Result<String> {
    document.release.validate()?;
    ensure!(
        absolute(assets_root),
        "asset root requires a literal absolute path"
    );
    for (key, value) in upstreams {
        ensure!(
            key.split(':').next().is_some_and(|n| document
                .release
                .workload
                .services
                .contains_key(n))
                && value.parse::<SocketAddr>().is_ok(),
            "upstream must name an owned service and literal socket address"
        );
    }
    let mut out = String::new();
    if http {
        out.push_str("{\nadmin off\nauto_https off\n}\n");
    }
    let mut hosts: BTreeMap<&str, Vec<(usize, &Route)>> = BTreeMap::new();
    for (i, route) in document.release.workload.routes.iter().enumerate() {
        hosts.entry(&route.host).or_default().push((i, route));
    }
    for (host, mut routes) in hosts {
        writeln!(out, "{}{host} {{", if http { "http://" } else { "" }).unwrap();
        baseline(&mut out);
        routes.sort_by(|a, b| {
            b.1.path
                .len()
                .cmp(&a.1.path.len())
                .then(a.1.path.cmp(&b.1.path))
        });
        out.push_str("route {\n");
        for (i, route) in &routes {
            if route.path == "/" {
                out.push_str("handle {\n");
            } else {
                writeln!(out, "handle {} {{", token(&route.path)).unwrap();
            }
            out.push_str("route {\n");
            headers(&mut out, &route.headers, "");
            writeln!(
                out,
                "header X-Komizo-Release {}\nheader X-Komizo-Revision {}",
                token(&document.digest),
                token(&document.release.source.revision)
            )
            .unwrap();
            if route.strip_prefix && route.path != "/" {
                writeln!(
                    out,
                    "uri strip_prefix {}",
                    token(route.path.trim_end_matches('*').trim_end_matches('/'))
                )
                .unwrap();
            }
            if let Some(redirect) = &route.redirect {
                let destination = format!(
                    "{}{}",
                    redirect.to,
                    if redirect.preserve_uri { "{uri}" } else { "" }
                );
                writeln!(out, "redir {} {}", token(&destination), redirect.status).unwrap();
            } else {
                match route
                    .target
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing route target"))?
                {
                    RouteTarget::Asset { name } => serving(
                        &mut out,
                        &document.release.workload.assets[name].serving,
                        &format!("{assets_root}/{name}"),
                        &format!("k{i}"),
                    ),
                    RouteTarget::Service { name, port } => {
                        let upstream = upstreams
                            .get(&format!("{name}:{port}"))
                            .or_else(|| upstreams.get(name))
                            .ok_or_else(|| anyhow!("missing owned upstream for {name}:{port}"))?;
                        if let Some(proxy) = &route.proxy {
                            encode(&mut out, &proxy.encode, &proxy.encode_content_types);
                        }
                        writeln!(out, "reverse_proxy {} {{", token(upstream)).unwrap();
                        if let Some(proxy) = &route.proxy {
                            if proxy.dial_timeout_seconds.is_some()
                                || proxy.response_header_timeout_seconds.is_some()
                            {
                                out.push_str("transport http {\n");
                                if let Some(seconds) = proxy.dial_timeout_seconds {
                                    writeln!(out, "dial_timeout {seconds}s").unwrap();
                                }
                                if let Some(seconds) = proxy.response_header_timeout_seconds {
                                    writeln!(out, "response_header_timeout {seconds}s").unwrap();
                                }
                                out.push_str("}\n");
                            }
                        }
                        out.push_str("}\n");
                    }
                }
            }
            out.push_str("}\n}\n");
        }
        out.push_str("respond 404\n}\n");
        if routes.iter().any(|(_, r)| {
            r.proxy
                .as_ref()
                .is_some_and(|p| p.error_body.is_some() || p.error_status.is_some())
        }) {
            out.push_str("handle_errors {\nroute {\n");
            for (_, route) in &routes {
                let Some(proxy) = &route.proxy else { continue };
                if proxy.error_body.is_none() && proxy.error_status.is_none() {
                    continue;
                }
                if route.path == "/" {
                    out.push_str("handle {\n");
                } else {
                    writeln!(out, "handle {} {{", token(&route.path)).unwrap();
                }
                headers(&mut out, &route.headers, "");
                writeln!(
                    out,
                    "respond {} {}",
                    token(
                        proxy
                            .error_body
                            .as_deref()
                            .unwrap_or("upstream unavailable")
                    ),
                    proxy
                        .error_status
                        .map_or_else(|| "{err.status_code}".to_string(), |n| n.to_string())
                )
                .unwrap();
                out.push_str("}\n");
            }
            out.push_str("}\n}\n");
        }
        out.push_str("}\n");
    }
    out.push_str("http:// {\n");
    baseline(&mut out);
    out.push_str("respond 404\n}\n");
    Ok(out)
}
