//! Platform trait implementation for desktop actions.

use std::path::Path;

use crate::actions::{MAX_CLIPBOARD_BYTES, PlatformAction, Policies};
use crate::error::PlatformError;
use crate::guard::{PathUse, check_clipboard_text, check_key_chord, check_notification, check_path, check_url};
use crate::host::Platform;

use super::{CommandPlatform, Desktop};
use super::super::powershell;

impl Platform for CommandPlatform {
    fn name(&self) -> &'static str {
        // The name a log line and a health screen show, and it names the desktop because that is what decides which
        // programs run.
        match self.desktop {
            Desktop::Linux => "desktop-linux",
            Desktop::MacOs => "desktop-macos",
            Desktop::Windows => "desktop-windows",
        }
    }

    fn policies(&self) -> &Policies {
        &self.policies
    }

    fn open_url(&self, url: &str) -> Result<(), PlatformError> {
        // ★ The check first, and the runner second. A check that ran after the launch would be a check that reported a
        // window it had already opened.
        check_url(url, &self.policies)?;
        self.limiter
            .admit(PlatformAction::OpenUrl, Self::now_ms())?;
        let _ = self.run(self.desktop.opener(), &[url])?;
        Ok(())
    }

    fn open_path(&self, path: &Path) -> Result<(), PlatformError> {
        check_path(path, PathUse::Open, &self.policies, None)?;
        self.limiter
            .admit(PlatformAction::OpenPath, Self::now_ms())?;
        let text = path.to_string_lossy().to_string();
        let _ = self.run(self.desktop.opener(), &[text.as_str()])?;
        Ok(())
    }

    fn reveal_path(&self, path: &Path, sandbox_root: Option<&Path>) -> Result<(), PlatformError> {
        // The sandbox root is what stops a plugin revealing `~/.ssh` in a file manager the user is looking at.
        check_path(path, PathUse::Reveal, &self.policies, sandbox_root)?;
        self.limiter
            .admit(PlatformAction::RevealPath, Self::now_ms())?;
        let text = path.to_string_lossy().to_string();
        let (program, flag) = self.desktop.revealer();
        let arguments: Vec<&str> = if flag.is_empty() {
            vec![text.as_str()]
        } else {
            vec![flag, text.as_str()]
        };
        let _ = self.run(program, &arguments)?;
        Ok(())
    }

    fn simulate_keys(&self, chord: &str) -> Result<(), PlatformError> {
        check_key_chord(chord)?;
        if !self.policies.allows_simulate_keys() {
            return Err(PlatformError::SimulateKeysNotGranted);
        }
        // ★ The rate limit is the whole of the protection here: a plugin that can type into whatever window is focused
        // can do anything the user can, and the interval is what makes it a slow, visible thing rather than a
        // keystroke storm.
        self.limiter
            .admit(PlatformAction::SimulateKeys, Self::now_ms())?;
        match self.desktop {
            Desktop::Linux => {
                let _ = self.run("xdotool", &["key", "--", chord])?;
            }
            Desktop::MacOs => {
                // A fixed program that reads the chord from `argv`, for the same reason the notification does.
                let _ = self.run(
                    "osascript",
                    &[
                        "-e",
                        "on run argv",
                        "-e",
                        "tell application \"System Events\" to keystroke (item 1 of argv)",
                        "-e",
                        "end run",
                        "--",
                        chord,
                    ],
                )?;
            }
            Desktop::Windows => {
                let _ = self.powershell(powershell::KEYS, Some(chord))?;
            }
        }
        Ok(())
    }

    fn read_clipboard(&self) -> Result<Option<String>, PlatformError> {
        self.limiter
            .admit(PlatformAction::ReadClipboard, Self::now_ms())?;
        let text: Option<String> = match self.desktop {
            Desktop::Linux => Some(self.run("xclip", &["-selection", "clipboard", "-o"])?),
            Desktop::MacOs => Some(self.run("pbpaste", &[])?),
            Desktop::Windows => {
                let answer = self.powershell(powershell::READ, None)?;
                serde_json::from_str(&answer).map_err(|_| PlatformError::RunnerFailed {
                    program: "powershell".to_owned(),
                    reason: "clipboard response is not nullable text JSON".to_owned(),
                })?
            }
        };
        if text
            .as_ref()
            .is_some_and(|text| text.len() > MAX_CLIPBOARD_BYTES)
        {
            return Err(PlatformError::RunnerOutputTooLong {
                program: "clipboard backend".to_owned(),
                stream: "decoded clipboard text",
                max: MAX_CLIPBOARD_BYTES,
            });
        }
        Ok(text)
    }

    fn write_clipboard(&self, text: &str) -> Result<(), PlatformError> {
        check_clipboard_text(text)?;
        self.limiter
            .admit(PlatformAction::WriteClipboard, Self::now_ms())?;
        match self.desktop {
            Desktop::Linux => {
                let _ =
                    self.run_with_input("xclip", &["-selection", "clipboard", "-in"], Some(text))?;
            }
            Desktop::MacOs => {
                let _ = self.run_with_input("pbcopy", &[], Some(text))?;
            }
            Desktop::Windows => {
                let _ = self.powershell(powershell::WRITE, Some(text))?;
            }
        }
        Ok(())
    }

    fn notify(&self, title: &str, body: &str) -> Result<(), PlatformError> {
        check_notification(title, body)?;
        // The limiter is what a notification has instead of a permission: it is user-visible, so the risk is being
        // annoying rather than being dangerous.
        self.limiter.admit(PlatformAction::Notify, Self::now_ms())?;
        self.notify_with(title, body)
    }

    fn supported_actions(&self) -> Vec<PlatformAction> {
        if !self.runner.is_available() {
            return Vec::new();
        }
        // ★ The list an interface draws its menu from, and it is the *askable* list rather than the implemented one:
        // `SimulateKeys` is offered when the policy allows it, because a menu item that is never available is worse
        // than one that explains why it is not.
        let mut actions = vec![
            PlatformAction::OpenUrl,
            PlatformAction::OpenPath,
            PlatformAction::RevealPath,
            PlatformAction::Notify,
            PlatformAction::ReadClipboard,
            PlatformAction::WriteClipboard,
        ];
        if self.policies.allows_simulate_keys() {
            actions.push(PlatformAction::SimulateKeys);
        }
        actions
    }
}




