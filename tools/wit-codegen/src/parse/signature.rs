/// Splits `name: func(…) -> …;` into the name and the signature.
///
/// `None` when the line is not a function declaration, which is how every other construct is skipped.
pub(super) fn split_function(line: &str) -> Option<(String, &str)> {
    let (name, rest) = line.split_once(':')?;
    let name = name.trim();
    // A name is an identifier: a keyword or a dotted path would be something else, and `use types.{…}` is already
    // handled above.
    if name.is_empty() || !name.chars().all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') {
        return None;
    }
    let rest = rest.trim();
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    // `func` is the keyword that makes it a function. Without it this is a type declaration inside `types` —
    // `log-level: enum { … }` is not WIT, and `record device-target { … }` has no colon, but a future construct might.
    if !rest.starts_with("func") {
        return None;
    }
    Some((name.to_owned(), rest))
}

/// Reads a function's parameters and return type from its signature.
///
/// # Why the text is kept rather than parsed into a type tree
///
/// The WIT this contract uses has ten distinct types, and the generator that consumes them needs to spell each one in
/// Rust. A tree here would be a second representation of the same thing, and the mapping from it would be as long as the
/// mapping from the text — with the difference that a reader cannot see what the generator understood by looking at the
/// file.
///
/// `None` for the return when the signature has none, which is `deactivate` and nothing else today.
pub(super) fn read_signature(signature: &str) -> (Vec<(String, String)>, Option<String>) {
    let Some(open) = signature.find('(') else {
        return (Vec::new(), None);
    };
    // The closing parenthesis is the *matching* one, and a parameter may itself be a generic: `list<device-target>` has
    // an angle bracket and no parenthesis, so the first `)` after the open parenthesis is the right one today — and a
    // type that contained a parenthesis would need this to count depth. Stated rather than assumed.
    let Some(close) = signature[open..].find(')').map(|at| open + at) else {
        return (Vec::new(), None);
    };

    let mut params = Vec::new();
    for raw in signature[open + 1..close].split(',') {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        if let Some((name, ty)) = raw.split_once(':') {
            params.push((name.trim().to_owned(), ty.trim().to_owned()));
        }
    }

    let returns = signature[close + 1..]
        .trim()
        .strip_prefix("->")
        .map(|rest| rest.trim().trim_end_matches(';').trim().to_owned())
        .filter(|rest| !rest.is_empty());

    (params, returns)
}
