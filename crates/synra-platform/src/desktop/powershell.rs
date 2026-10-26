//! Fixed scripts receive UTF-8 data only through stdin, never after PowerShell's -Command.

use super::CommandPlatform;
use crate::PlatformError;

const PREFIX: &str = concat!(
    "$ErrorActionPreference='Stop'; [Console]::InputEncoding=[Text.UTF8Encoding]::new($false,$true); [Console]::OutputEncoding=[Text.UTF8Encoding]::new($false,$true); ",
    "function Write-SynraJson { param($value); if($null -eq $value){[Console]::Write('null')}else{[Console]::Write((ConvertTo-Json -InputObject $value -Compress))} }; ",
);

pub(super) const READ: &str = "$value=Get-Clipboard -Raw -Format Text; Write-SynraJson $value";
pub(super) const WRITE: &str = "$value=[Console]::In.ReadToEnd(); Set-Clipboard -Value $value";
pub(super) const KEYS: &str = "Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.SendKeys]::SendWait([Console]::In.ReadToEnd())";
pub(super) const NOTIFY: &str = "$value=ConvertFrom-Json -InputObject ([Console]::In.ReadToEnd()); New-BurntToastNotification -Text $value.title,$value.body | Out-Null";

impl CommandPlatform {
    pub(super) fn powershell(
        &self,
        body: &'static str,
        input: Option<&str>,
    ) -> Result<String, PlatformError> {
        let script = format!("{PREFIX}{body}");
        self.run_with_input(
            "powershell",
            &[
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-STA",
                "-Command",
                &script,
            ],
            input,
        )
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::super::{CommandPlatform, Desktop, SystemRunner};

    #[test]
    fn actual_powershell_preserves_utf8_and_treats_script_syntax_as_data() {
        let platform = CommandPlatform::with(Desktop::Windows, Box::new(SystemRunner::default()));
        for input in ["", "\"quoted\"; $(1+2); `literal`\r\n中文🖱️\\"] {
            let answer = platform
                .powershell("[Console]::Write([Console]::In.ReadToEnd())", Some(input))
                .expect("UTF-8 echo");
            assert_eq!(answer, input);
        }
    }

    #[test]
    fn actual_powershell_failure_is_not_silent_or_echoed_into_the_error() {
        let platform = CommandPlatform::with(Desktop::Windows, Box::new(SystemRunner::default()));
        let error = platform
            .powershell("Write-Error 'sensitive-clipboard-content'", None)
            .expect_err("terminating failure");
        assert!(!error.to_string().contains("sensitive-clipboard-content"));
    }

    #[test]
    fn actual_powershell_clipboard_contract_supports_nullable_utf8_json() {
        let platform = CommandPlatform::with(Desktop::Windows, Box::new(SystemRunner::default()));
        let metadata = platform.powershell("$read=(Get-Command Get-Clipboard).Parameters; $write=(Get-Command Set-Clipboard).Parameters; [Console]::Write(($read.ContainsKey('Raw') -and $read.ContainsKey('Format') -and $write.ContainsKey('Value')))", None).expect("cmdlet metadata");
        assert_eq!(metadata, "True");
        assert_eq!(
            platform
                .powershell("Write-SynraJson $null", None)
                .expect("null JSON"),
            "null"
        );
        for text in ["", "null", "\"quoted\"\r\n中文🖱️\\"] {
            let answer = platform
                .powershell("Write-SynraJson ([Console]::In.ReadToEnd())", Some(text))
                .expect("JSON string");
            assert_eq!(
                serde_json::from_str::<Option<String>>(&answer)
                    .expect("nullable text")
                    .as_deref(),
                Some(text)
            );
        }
    }
}
