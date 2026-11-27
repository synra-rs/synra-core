//! Desktop keyboard backends and balanced delivery of a single chord.

use crate::{Key, KeyChord, Modifier, PlatformError};

use super::{CommandPlatform, Desktop};

#[cfg(any(windows, target_os = "macos"))]
mod native;
#[cfg(test)]
mod tests;

const X11_TOOL: &str = "xdotool";
const NO_KEYBOARD: PlatformError = PlatformError::Unsupported("simulate keys on this desktop");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Down,
    Up,
}

impl CommandPlatform {
    pub(super) fn keyboard_available(&self) -> bool {
        match self.desktop {
            Desktop::Linux => self.x11_keyboard().is_ok(),
            Desktop::Windows | Desktop::MacOs => {
                #[cfg(any(windows, target_os = "macos"))]
                if self.desktop == Desktop::current() {
                    return native::connect().is_ok();
                }
                false
            }
        }
    }

    pub(super) fn emit_chord(&self, chord: KeyChord) -> Result<(), PlatformError> {
        let _exclusive = self
            .key_input
            .try_lock()
            .ok_or(PlatformError::KeyInputBusy)?;
        match self.desktop {
            Desktop::Linux => {
                self.x11_keyboard()?;
                let modifiers = chord
                    .modifiers()
                    .map(|modifier| x11_modifier(modifier).to_owned());
                play(modifiers, x11_key(chord.key()), |key, direction| {
                    let command = match direction {
                        Direction::Down => "keydown",
                        Direction::Up => "keyup",
                    };
                    self.run(X11_TOOL, &[command, "--", key]).map(|_| ())
                })
            }
            Desktop::Windows | Desktop::MacOs => {
                #[cfg(any(windows, target_os = "macos"))]
                if self.desktop == Desktop::current() {
                    return native::emit(chord);
                }
                Err(NO_KEYBOARD)
            }
        }
    }

    fn x11_keyboard(&self) -> Result<(), PlatformError> {
        self.run(X11_TOOL, &["getdisplaygeometry"])
            .map(|_| ())
            .map_err(|error| match error {
                PlatformError::Unsupported(_) | PlatformError::RunnerFailed { .. } => {
                    PlatformError::Unsupported(
                        "simulate keys through an available X11 display and xdotool",
                    )
                }
                other => other,
            })
    }
}

fn play<K>(
    modifiers: impl Iterator<Item = K>,
    main: K,
    mut emit: impl FnMut(&K, Direction) -> Result<(), PlatformError>,
) -> Result<(), PlatformError> {
    let mut pressed = Vec::with_capacity(5);
    let input = modifiers.chain(std::iter::once(main)).try_for_each(|key| {
        let result = emit(&key, Direction::Down);
        if result.is_ok()
            || matches!(
                result,
                Err(PlatformError::RunnerTimedOut { .. }
                    | PlatformError::RunnerCleanupFailed { .. }
                    | PlatformError::RunnerOutputTooLong { .. })
            )
        {
            // A command with unfinished output or cleanup may already have delivered the key.
            pressed.push(key);
        }
        result
    });

    let failures: Vec<_> = pressed
        .into_iter()
        .rev()
        .filter_map(|key| {
            emit(&key, Direction::Up)
                .err()
                .map(|error| error.to_string())
        })
        .collect();
    if failures.is_empty() {
        return input;
    }
    Err(PlatformError::KeyReleaseFailed {
        input: input.err().map(|error| error.to_string()),
        failures,
    })
}

const fn x11_modifier(modifier: Modifier) -> &'static str {
    match modifier {
        Modifier::Ctrl => "Control_L",
        Modifier::Alt => "Alt_L",
        Modifier::Shift => "Shift_L",
        Modifier::Meta => "Super_L",
    }
}

fn x11_key(key: Key) -> String {
    match key {
        Key::Letter(letter) => return letter.to_ascii_lowercase().to_string(),
        Key::Digit(number) => return number.to_string(),
        Key::Function(number) => return format!("F{number}"),
        Key::Enter => "Return",
        Key::Escape => "Escape",
        Key::Tab => "Tab",
        Key::Space => "space",
        Key::Backspace => "BackSpace",
        Key::Delete => "Delete",
        Key::Home => "Home",
        Key::End => "End",
        Key::PageUp => "Prior",
        Key::PageDown => "Next",
        Key::ArrowUp => "Up",
        Key::ArrowDown => "Down",
        Key::ArrowLeft => "Left",
        Key::ArrowRight => "Right",
        Key::NumpadAdd => "KP_Add",
    }
    .to_owned()
}
