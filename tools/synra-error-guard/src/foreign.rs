//! Foreign error types at public declaration boundaries, excluding implementations and private helpers.

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{Fields, ImplItem, Item, TraitItem, Visibility};

use super::{FOREIGN_ERRORS, Source, Violation};

pub(super) fn check(source: &Source) -> Vec<Violation> {
    let file = match syn::parse_file(&source.text) {
        Ok(file) => file,
        Err(error) => {
            return vec![Violation::Unreadable {
                path: source.path.clone(),
                reason: format!("Rust syntax could not be parsed: {error}"),
            }];
        }
    };
    let mut visitor = PublicTypes {
        source,
        violations: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.violations
}

struct PublicTypes<'a> {
    source: &'a Source,
    violations: Vec<Violation>,
}

const fn public(visibility: &Visibility) -> bool {
    matches!(visibility, Visibility::Public(_))
}

impl PublicTypes<'_> {
    fn fields(&mut self, fields: &Fields, all: bool) {
        for field in fields {
            if all || public(&field.vis) {
                self.visit_type(&field.ty);
            }
        }
    }
}

impl<'ast> Visit<'ast> for PublicTypes<'_> {
    fn visit_item(&mut self, item: &'ast Item) {
        match item {
            Item::Fn(item) if public(&item.vis) => self.visit_signature(&item.sig),
            Item::Struct(item) if public(&item.vis) => self.fields(&item.fields, false),
            Item::Enum(item) if public(&item.vis) => {
                for variant in &item.variants {
                    self.fields(&variant.fields, true);
                }
            }
            Item::Type(item) if public(&item.vis) => self.visit_type(&item.ty),
            Item::Const(item) if public(&item.vis) => self.visit_type(&item.ty),
            Item::Static(item) if public(&item.vis) => self.visit_type(&item.ty),
            Item::Mod(item) if public(&item.vis) => {
                if let Some((_, items)) = &item.content {
                    for item in items {
                        self.visit_item(item);
                    }
                }
            }
            Item::Impl(item) if item.trait_.is_none() => {
                for item in &item.items {
                    match item {
                        ImplItem::Fn(item) if public(&item.vis) => self.visit_signature(&item.sig),
                        ImplItem::Const(item) if public(&item.vis) => self.visit_type(&item.ty),
                        ImplItem::Type(item) if public(&item.vis) => self.visit_type(&item.ty),
                        _ => {}
                    }
                }
            }
            Item::Trait(item) if public(&item.vis) => {
                for item in &item.items {
                    match item {
                        TraitItem::Fn(item) => self.visit_signature(&item.sig),
                        TraitItem::Const(item) => self.visit_type(&item.ty),
                        TraitItem::Type(item) => {
                            for bound in &item.bounds {
                                self.visit_type_param_bound(bound);
                            }
                            if let Some((_, ty)) = &item.default {
                                self.visit_type(ty);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        // Do not default-visit items: that would inspect bodies, private items and foreign trait implementations.
    }

    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        let segments: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        let name = segments.join("::");
        for foreign in FOREIGN_ERRORS {
            if name == *foreign || name.ends_with(&format!("::{foreign}")) {
                let line = path.span().start().line;
                let item = self
                    .source
                    .text
                    .lines()
                    .nth(line.saturating_sub(1))
                    .unwrap_or_default()
                    .trim()
                    .trim_end_matches(',')
                    .to_owned();
                self.violations.push(Violation::ForeignError {
                    file: self.source.path.clone(),
                    line,
                    item,
                    foreign: (*foreign).to_owned(),
                });
            }
        }
        syn::visit::visit_type_path(self, path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(text: &str) -> Vec<Violation> {
        check(&Source {
            path: "fixture.rs".to_owned(),
            text: text.to_owned(),
        })
    }

    #[test]
    fn private_helpers_function_bodies_and_foreign_trait_methods_are_ignored() {
        let source = r#"
            fn helper(error: &std::io::Error) {}
            pub(crate) fn restricted(error: std::io::Error) {}
            pub(super) fn parent(error: std::io::Error) {}
            enum Private { Io(std::io::Error) }
            pub struct Opaque(std::io::Error);
            pub fn implementation() { let _ = std::io::Error::other("private detail"); }
            impl std::io::Read for Opaque {
                fn read(&mut self, bytes: &mut [u8]) -> Result<usize, std::io::Error> { todo!() }
            }
            #[cfg(test)] mod tests { pub fn helper() -> std::io::Error { todo!() } }
        "#;
        assert!(findings(source).is_empty());
    }

    #[test]
    fn multiline_public_signatures_and_nested_error_fields_are_checked() {
        let source = r#"
            pub enum Failure { Named { source: Option<std::io::Error> } }
            pub struct Report { pub source: serde_json::Error }
            pub fn action(
                error: &std::io::Error,
            ) -> Result<(), std::str::Utf8Error> { todo!() }
            impl Report { pub fn detail(&self) -> std::fmt::Error { todo!() } }
            pub trait Service { fn run(&self) -> Result<(), std::io::Error>; }
            pub type ResultAlias = Result<(), std::string::FromUtf8Error>;
            pub mod nested { pub struct Tuple(pub std::io::Error); }
        "#;
        let found = findings(source);
        assert_eq!(found.len(), 8, "{found:?}");
        assert!(
            found
                .iter()
                .all(|finding| matches!(finding, Violation::ForeignError { .. }))
        );
    }

    #[test]
    fn malformed_source_is_reported_instead_of_silently_skipped() {
        assert!(matches!(
            findings("pub fn broken( -> std::io::Error").as_slice(),
            [Violation::Unreadable { .. }]
        ));
    }
}
