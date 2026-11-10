use super::arguments::NotifyArguments;
use super::{CallError, CallResult, HostCalls, PlatformAction};

impl HostCalls<'_> {
/// Runs a platform action through the one host function they all share.
    pub(super) fn platform(&self, action: PlatformAction, argument: &str) -> CallResult {
        // Only the write-clipboard action carries text; the rest carry a URL, a path or a chord, and notify carries a
        // title and a body as JSON.
        let text = match action {
            PlatformAction::Notify => {
                let parsed: NotifyArguments = serde_json::from_str(argument)
                    .map_err(|error| CallError::new(CallError::BAD_ARGUMENT, error.to_string()))?;
                format!("{}\u{1}{}", parsed.title, parsed.body)
            }
            _ => argument.to_owned(),
        };
        let answer = self.host.platform(&self.plugin, action, &text)?;
        if action == PlatformAction::ReadClipboard {
            serde_json::to_string(&answer)
                .map_err(|error| CallError::new(CallError::HOST_FAILED, error.to_string()))
        } else {
            Ok(answer.unwrap_or_default())
        }
    }
}
