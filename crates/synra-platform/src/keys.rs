//! The portable input for one keyboard chord.

use std::{fmt, str::FromStr};

use crate::{MAX_CHORD_LEN, PlatformError};

/// A modifier, in canonical press order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    /// Control on every platform.
    Ctrl,
    /// Alt, called Option on macOS.
    Alt,
    /// Shift.
    Shift,
    /// Windows, Command on macOS, and Super on X11.
    Meta,
}

impl Modifier {
    const ORDER: [Self; 4] = [Self::Ctrl, Self::Alt, Self::Shift, Self::Meta];

    const fn name(self) -> &'static str {
        match self {
            Self::Ctrl => "Ctrl",
            Self::Alt => "Alt",
            Self::Shift => "Shift",
            Self::Meta => "Meta",
        }
    }

    fn find(token: &str) -> Option<Self> {
        Self::ORDER
            .into_iter()
            .find(|modifier| token.eq_ignore_ascii_case(modifier.name()))
    }
}

/// The main key of a parsed chord.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// An ASCII letter key represented by its uppercase name.
    Letter(char),
    /// A digit key on the main keyboard, from zero through nine.
    Digit(u8),
    /// A function key, from F1 through F12.
    Function(u8),
    /// Enter.
    Enter,
    /// Escape.
    Escape,
    /// Tab.
    Tab,
    /// Space.
    Space,
    /// Backspace.
    Backspace,
    /// Forward delete.
    Delete,
    /// Home.
    Home,
    /// End.
    End,
    /// Page Up.
    PageUp,
    /// Page Down.
    PageDown,
    /// Up arrow.
    ArrowUp,
    /// Down arrow.
    ArrowDown,
    /// Left arrow.
    ArrowLeft,
    /// Right arrow.
    ArrowRight,
    /// The add key on the numeric keypad.
    NumpadAdd,
}

const NAMED_KEYS: [(Key, &str); 15] = [
    (Key::Enter, "Enter"),
    (Key::Escape, "Escape"),
    (Key::Tab, "Tab"),
    (Key::Space, "Space"),
    (Key::Backspace, "Backspace"),
    (Key::Delete, "Delete"),
    (Key::Home, "Home"),
    (Key::End, "End"),
    (Key::PageUp, "PageUp"),
    (Key::PageDown, "PageDown"),
    (Key::ArrowUp, "ArrowUp"),
    (Key::ArrowDown, "ArrowDown"),
    (Key::ArrowLeft, "ArrowLeft"),
    (Key::ArrowRight, "ArrowRight"),
    (Key::NumpadAdd, "NumpadAdd"),
];

impl Key {
    fn find(token: &str) -> Option<Self> {
        let upper = token.to_ascii_uppercase();
        match upper.as_bytes() {
            [letter @ b'A'..=b'Z'] => return Some(Self::Letter(char::from(*letter))),
            [digit @ b'0'..=b'9'] => return Some(Self::Digit(digit - b'0')),
            _ => {}
        }
        if let Some(number) = upper.strip_prefix('F')
            && !number.starts_with('0')
            && let Ok(number) = number.parse::<u8>()
            && (1..=12).contains(&number)
        {
            return Some(Self::Function(number));
        }
        NAMED_KEYS
            .iter()
            .find_map(|(key, name)| token.eq_ignore_ascii_case(name).then_some(*key))
    }
}

/// Why the input could not be parsed as a single chord.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum KeyChordError {
    /// An empty chord or an empty token between separators.
    #[error("the chord contains an empty part")]
    EmptyPart,
    /// A repeated modifier.
    #[error("a modifier occurs more than once")]
    DuplicateModifier,
    /// A token before the final key was not a modifier.
    #[error("only Ctrl Alt Shift and Meta may precede the main key")]
    ExpectedModifier,
    /// A modifier was used as the final key.
    #[error("the chord needs a main key after the modifiers")]
    MissingKey,
    /// The final key was outside the supported key set.
    #[error("the chord contains an unknown main key")]
    UnknownKey,
}

/// One primary key with zero or more distinct modifiers.
///
/// Parse the guest's string with `str::parse`. Formatting uses the canonical
/// spelling, for example `Ctrl+Shift+S`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyChord {
    modifiers: u8,
    key: Key,
}

impl KeyChord {
    /// The modifiers in press order.
    pub fn modifiers(self) -> impl DoubleEndedIterator<Item = Modifier> {
        Modifier::ORDER
            .into_iter()
            .filter(move |modifier| self.modifiers & (1 << *modifier as u8) != 0)
    }

    /// The primary key.
    #[must_use]
    pub const fn key(self) -> Key {
        self.key
    }

    pub(crate) const fn copy_with(modifier: Modifier) -> Self {
        Self {
            modifiers: 1 << modifier as u8,
            key: Key::Letter('C'),
        }
    }
}

impl FromStr for KeyChord {
    type Err = PlatformError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let len = input.chars().count();
        if len > MAX_CHORD_LEN {
            return Err(PlatformError::TooLong {
                field: "key chord",
                len,
                max: MAX_CHORD_LEN,
            });
        }

        let mut parts = input.rsplit('+').map(|part| part.trim_matches(' '));
        let key = parts
            .next()
            .filter(|part| !part.is_empty())
            .ok_or(KeyChordError::EmptyPart)?;
        if Modifier::find(key).is_some() {
            return Err(KeyChordError::MissingKey.into());
        }
        let key = Key::find(key).ok_or(KeyChordError::UnknownKey)?;
        let mut modifiers = 0;
        for part in parts {
            if part.is_empty() {
                return Err(KeyChordError::EmptyPart.into());
            }
            let modifier = Modifier::find(part).ok_or(KeyChordError::ExpectedModifier)?;
            let bit = 1 << modifier as u8;
            if modifiers & bit != 0 {
                return Err(KeyChordError::DuplicateModifier.into());
            }
            modifiers |= bit;
        }
        Ok(Self { modifiers, key })
    }
}

impl fmt::Display for KeyChord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for modifier in self.modifiers() {
            write!(formatter, "{}+", modifier.name())?;
        }
        match self.key {
            Key::Letter(letter) => write!(formatter, "{letter}"),
            Key::Digit(number) => write!(formatter, "{number}"),
            Key::Function(number) => write!(formatter, "F{number}"),
            key => NAMED_KEYS
                .iter()
                .find_map(|(named, name)| (*named == key).then_some(*name))
                .ok_or(fmt::Error)
                .and_then(|name| formatter.write_str(name)),
        }
    }
}
