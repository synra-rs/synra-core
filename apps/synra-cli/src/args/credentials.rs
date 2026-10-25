use clap::{Args, Subcommand};

/// Local identity maintenance through the running daemon.
#[derive(Debug, Args)]
pub struct CredentialArgs {
    /// Explicit maintenance operation.
    #[command(subcommand)]
    pub action: CredentialAction,
}

/// What local identity maintenance may change.
#[derive(Debug, Subcommand)]
pub enum CredentialAction {
    /// Display the public enrollment fingerprint and pending cleanup count.
    Status,
    /// Revoke every pairing and replace the exact confirmed certificate; restart and pair again.
    Repair {
        /// Fingerprint displayed by identity status; stale values are refused.
        #[arg(long, value_name = "SHA256")]
        expected_fingerprint: String,
    },
    /// Retry deletion of retired keys without replacing the current key.
    Cleanup,
}

impl From<&CredentialAction> for synra_control::CredentialAction {
    fn from(action: &CredentialAction) -> Self {
        match action {
            CredentialAction::Status => Self::Status,
            CredentialAction::Repair {
                expected_fingerprint,
            } => Self::Repair {
                expected_fingerprint: expected_fingerprint.clone(),
            },
            CredentialAction::Cleanup => Self::Cleanup,
        }
    }
}
#[cfg(test)]
mod tests {
    use crate::args::{Cli, Command};
    use clap::Parser;

    #[test]
    fn identity_actions_require_explicit_confirmation_and_reach_control_requests() {
        assert!(Cli::try_parse_from(["synra", "identity", "repair"]).is_err());
        for (arguments, expected) in [
            (
                vec!["synra", "identity", "status"],
                synra_control::CredentialAction::Status,
            ),
            (
                vec!["synra", "identity", "cleanup"],
                synra_control::CredentialAction::Cleanup,
            ),
            (
                vec![
                    "synra",
                    "identity",
                    "repair",
                    "--expected-fingerprint",
                    "displayed",
                ],
                synra_control::CredentialAction::Repair {
                    expected_fingerprint: "displayed".to_owned(),
                },
            ),
        ] {
            let parsed = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(&parsed.command, Command::Identity(_)));
            let question = crate::channel::question_for(&parsed.command, None, || None).unwrap();
            assert_eq!(
                question.request,
                synra_control::Request::Credentials { action: expected }
            );
        }
    }
}
