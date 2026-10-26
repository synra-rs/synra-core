//! The manifest's property tests: what must hold for **every** input rather than for a named one.

use proptest::prelude::*;

use synra_protocol::PluginId;


    use super::*;
    

    proptest! {
        /// Version comparison is a total order: irreflexive-equal, antisymmetric and transitive. A comparator
        /// that broke any of those would make an SDK requirement depend on which side it was written on.
        #[test]
        fn version_comparison_is_a_total_order(
            a in (0u64..5, 0u64..5, 0u64..5),
            b in (0u64..5, 0u64..5, 0u64..5),
            c in (0u64..5, 0u64..5, 0u64..5),
        ) {
            let render = |(major, minor, patch): (u64, u64, u64)| format!("{major}.{minor}.{patch}");
            let (a, b, c) = (render(a), render(b), render(c));

            // Reflexive.
            prop_assert_eq!(compare_versions(&a, &a).expect("valid"), core::cmp::Ordering::Equal);

            // Antisymmetric.
            let forward = compare_versions(&a, &b).expect("valid");
            let backward = compare_versions(&b, &a).expect("valid");
            prop_assert_eq!(forward, backward.reverse());

            // Transitive.
            if compare_versions(&a, &b).expect("valid") == core::cmp::Ordering::Less
                && compare_versions(&b, &c).expect("valid") == core::cmp::Ordering::Less
            {
                prop_assert_eq!(
                    compare_versions(&a, &c).expect("valid"),
                    core::cmp::Ordering::Less,
                );
            }
        }

        /// Parsing a manifest is total: arbitrary text either yields a manifest or an error, and never panics.
        /// Manifests arrive from disk and from a package the user downloaded, so they are only semi-trusted.
        #[test]
        fn parsing_is_total(text in ".{0,400}") {
            let _ = Manifest::from_json(&text);
        }

        /// Validating a parsed manifest is total, at both levels and with every combination of context. The
        /// loader runs this on input it did not write.
        #[test]
        fn validation_is_total(
            text in ".{0,400}",
            has_artifacts in any::<bool>(),
            has_implementation in any::<bool>(),
        ) {
            let Ok(manifest) = Manifest::from_json(&text) else {
                return Ok(());
            };
            let context = ManifestContext {
                host_sdk: Some("1.0.0".to_owned()),
                host_wit: None,
                present_artifacts: has_artifacts.then(Vec::new),
                implementation: has_implementation.then(Implementation::default),
            };
            let _ = manifest.validate(ValidationLevel::Schema, &context);
            let _ = manifest.validate(ValidationLevel::Verify, &context);
            // And the derived accessors do not panic on whatever survived.
            let _ = manifest.capability_set();
            let _ = manifest.project_slug();
            let _ = manifest.event_namespace();
            let _ = manifest.localised_title("zh-CN");
        }

        /// Full package identities produce valid event owners without requiring a short directory slug.
        #[test]
        fn a_package_identity_is_a_legal_event_owner(
            scope in "[a-z][a-z0-9-]{0,10}",
            name in "[a-z][a-z0-9-]{0,10}",
        ) {
            let id = format!("@{scope}/{name}");
            let Ok(id) = PluginId::parse(&id) else {
                return Ok(());
            };
            let event = format!("{}thing", id.event_namespace());
            prop_assert!(
                synra_protocol::event::EventName::parse(&event).is_ok(),
                "the package identity produced an unnameable event: {event}",
            );
        }

        /// A payload schema either validates or is refused for a reason. The walk is bounded, so a hostile
        /// schema cannot make the loader's work unbounded.
        #[test]
        fn payload_schemas_are_total(depth in 0usize..40) {
            let mut payload = String::from(r#"{"type":"object","properties":{"a":"#);
            for _ in 0..depth {
                payload.push_str(r#"{"type":"object","properties":{"a":"#);
            }
            payload.push_str("{}");
            for _ in 0..=depth {
                payload.push_str("}}");
            }
            payload.push('}');

            let text = format!(
                "{{\"id\":\"@synra-plugin/chat\",\"version\":\"1.0.0\",\"title\":\"T\",\
                 \"publisher\":{{\"id\":\"p\"}},\"sdk\":{{\"min\":\"1.0.0\"}},\
                 \"wit\":\"synra:plugin@1.0.0\",\
                 \"runtime\":{{\"headless\":{{\"artifact\":\"a\",\"stateful\":false}}}},\
                 \"capabilities\":[],\
                 \"events\":[{{\"name\":\"_plugin.@synra-plugin/chat.x\",\"payload\":{payload}}}]}}"
            );
            if let Ok(manifest) = Manifest::from_json(&text) {
                let _ = manifest.validate(ValidationLevel::Schema, &ManifestContext::default());
            }
        }
    }
