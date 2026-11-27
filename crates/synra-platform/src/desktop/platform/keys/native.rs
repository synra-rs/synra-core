#[cfg(windows)]
use enigo::Mouse;
use enigo::{Direction as Event, Enigo, InputError, Key as NativeKey, Keyboard, Settings};

use crate::{Key, KeyChord, Modifier, PlatformError};

use super::{Direction, NO_KEYBOARD, play};

pub(super) fn connect() -> Result<Enigo, PlatformError> {
    let keyboard = Enigo::new(&Settings {
        open_prompt_to_get_permissions: false,
        ..Settings::default()
    })
    .map_err(|_| NO_KEYBOARD)?;
    #[cfg(windows)]
    keyboard.location().map_err(|_| NO_KEYBOARD)?;
    Ok(keyboard)
}

pub(super) fn emit(chord: KeyChord) -> Result<(), PlatformError> {
    let main = key(chord.key()).ok_or(PlatformError::Unsupported("map this key on the desktop"))?;
    let mut keyboard = connect()?;
    play(chord.modifiers().map(modifier), main, |key, edge| {
        let event = match edge {
            Direction::Down => Event::Press,
            Direction::Up => Event::Release,
        };
        keyboard.key(*key, event).map_err(|error| match error {
            InputError::Mapping(_) => PlatformError::Unsupported("map this key on the desktop"),
            other => PlatformError::RunnerFailed {
                program: "native keyboard".to_owned(),
                reason: format!("{event:?} {key:?}: {other}"),
            },
        })
    })
}

const fn modifier(modifier: Modifier) -> NativeKey {
    match modifier {
        Modifier::Ctrl => NativeKey::Control,
        Modifier::Alt => NativeKey::Alt,
        Modifier::Shift => NativeKey::Shift,
        Modifier::Meta => NativeKey::Meta,
    }
}

fn key(key: Key) -> Option<NativeKey> {
    const FUNCTIONS: [NativeKey; 12] = [
        NativeKey::F1,
        NativeKey::F2,
        NativeKey::F3,
        NativeKey::F4,
        NativeKey::F5,
        NativeKey::F6,
        NativeKey::F7,
        NativeKey::F8,
        NativeKey::F9,
        NativeKey::F10,
        NativeKey::F11,
        NativeKey::F12,
    ];
    Some(match key {
        Key::Letter(letter) => NativeKey::Other(letter_code(letter)?),
        Key::Digit(number) => NativeKey::Other(digit_code(number)?),
        Key::Function(number) => *FUNCTIONS.get(usize::from(number.checked_sub(1)?))?,
        Key::Enter => NativeKey::Return,
        Key::Escape => NativeKey::Escape,
        Key::Tab => NativeKey::Tab,
        Key::Space => NativeKey::Space,
        Key::Backspace => NativeKey::Backspace,
        Key::Delete => NativeKey::Delete,
        Key::Home => NativeKey::Home,
        Key::End => NativeKey::End,
        Key::PageUp => NativeKey::PageUp,
        Key::PageDown => NativeKey::PageDown,
        Key::ArrowUp => NativeKey::UpArrow,
        Key::ArrowDown => NativeKey::DownArrow,
        Key::ArrowLeft => NativeKey::LeftArrow,
        Key::ArrowRight => NativeKey::RightArrow,
        Key::NumpadAdd => NativeKey::Add,
    })
}

#[cfg(windows)]
fn letter_code(letter: char) -> Option<u32> {
    letter.is_ascii_uppercase().then_some(u32::from(letter))
}

#[cfg(windows)]
fn digit_code(number: u8) -> Option<u32> {
    (number < 10).then(|| u32::from(b'0' + number))
}

// The Apple ANSI key positions are fixed keyboard keys. Enigo's Unicode layout
// lookup can substitute keycode zero when it cannot map a character.
#[cfg(target_os = "macos")]
fn letter_code(letter: char) -> Option<u32> {
    const ANSI_LETTERS: [u32; 26] = [
        0x00, 0x0b, 0x08, 0x02, 0x0e, 0x03, 0x05, 0x04, 0x22, 0x26, 0x28, 0x25, 0x2e, 0x2d, 0x1f,
        0x23, 0x0c, 0x0f, 0x01, 0x11, 0x20, 0x09, 0x0d, 0x07, 0x10, 0x06,
    ];
    let index = usize::try_from(u32::from(letter).checked_sub(u32::from('A'))?).ok()?;
    ANSI_LETTERS.get(index).copied()
}

#[cfg(target_os = "macos")]
fn digit_code(number: u8) -> Option<u32> {
    const ANSI_DIGITS: [u32; 10] = [0x1d, 0x12, 0x13, 0x14, 0x15, 0x17, 0x16, 0x1a, 0x1c, 0x19];
    ANSI_DIGITS.get(usize::from(number)).copied()
}

#[cfg(all(test, windows))]
#[test]
fn maps_shortcuts_to_virtual_keys_on_windows() {
    for (input, modifiers, primary) in [
        ("Ctrl+C", vec![NativeKey::Control], NativeKey::Other(u32::from('C'))),
        ("Ctrl+V", vec![NativeKey::Control], NativeKey::Other(u32::from('V'))),
        ("Ctrl+Shift+S", vec![NativeKey::Control, NativeKey::Shift], NativeKey::Other(u32::from('S'))),
        ("Alt+Tab", vec![NativeKey::Alt], NativeKey::Tab),
        ("Meta+E", vec![NativeKey::Meta], NativeKey::Other(u32::from('E'))),
    ] {
        let chord = input.parse::<KeyChord>().unwrap();
        assert_eq!(chord.modifiers().map(modifier).collect::<Vec<_>>(), modifiers);
        assert_eq!(key(chord.key()), Some(primary));
    }
}
