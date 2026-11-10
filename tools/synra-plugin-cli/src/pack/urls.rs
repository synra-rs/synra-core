//! Address rules for registry uploads and static package indexes.

/// The scheme and authority of a registry URL, or why it is not a shape the installing side could read.
///
/// The client reads the scheme and host and takes the protocol's paths from there (16 §4.2), so a URL with a path, a
/// non-http scheme or plain `http` for a public host is a mistake worth naming here rather than a surprise after publish.
pub(super) fn registry_base(url: &str) -> Result<String, String> {
    let (scheme, authority, rest) = http_parts(url.trim())?;
    if rest.trim_end_matches('/') != authority {
        return Err("it must name only a scheme and a host, with no path".to_owned());
    }
    check_http_host(scheme, authority, "registry")?;
    Ok(format!("{scheme}://{authority}"))
}

/// The base a static index's tarball URLs are built from.
///
/// Unlike a registry, a static host's path is where the bucket's files live, so it is kept. The rules that remain are the
/// ones the installing side enforces: a scheme, a host, and `http` only for a local bucket.
pub(super) fn index_base(url: &str) -> Result<String, String> {
    let (scheme, authority, rest) = http_parts(url.trim().trim_end_matches('/'))?;
    check_http_host(scheme, authority, "bucket")?;
    Ok(format!("{scheme}://{rest}"))
}

fn http_parts(url: &str) -> Result<(&str, &str, &str), String> {
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err("it must start with https:// or http://".to_owned());
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err("it names no host".to_owned());
    }
    Ok((scheme, authority, rest))
}

fn check_http_host(scheme: &str, authority: &str, kind: &str) -> Result<(), String> {
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|character| character.is_ascii_digit()) => host,
        _ => authority,
    };
    let loopback = matches!(host.trim_matches(['[', ']']), "127.0.0.1" | "localhost" | "::1");
    if scheme == "http" && !loopback {
        return Err(format!(
            "plain http is only for a local {kind}; a published package must travel over https"
        ));
    }
    Ok(())
}
