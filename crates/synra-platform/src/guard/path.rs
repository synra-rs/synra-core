//! Filesystem policy for opening and revealing paths.

use std::path::{Component, Path};

use crate::actions::{EXECUTABLE_EXTENSIONS, Policies};
use crate::error::{PathRefusal, PlatformError};

/// The Windows device names, without their extensions and in upper case.
///
/// # Why each of these is a device and not a file
///
/// Because Windows has reserved them since DOS and still resolves them **before** the file system: `NUL` is a sink that
/// discards whatever is written, `CON` is the console, `AUX` and `PRN` are the first serial and parallel ports, and
/// `COM1`–`COM9` and `LPT1`–`LPT9` are those ports by number. A sandbox that believed it had written
/// `<root>/NUL` would have written nothing at all, and one that believed it had read `<root>/CON` would be reading the
/// console — so the check is not about tidiness, it is about the kernel and the file system disagreeing on what a name
/// means.
const RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Whether one path component names a Windows device rather than a file.
///
/// # The three things Windows ignores, and why each is handled here
///
/// 1. **Case.** `nul`, `Nul` and `NUL` are the same device.
/// 2. **A trailing dot or space.** Windows strips them from a name before resolving it, so `NUL.` and `NUL ` are `NUL` —
///    and a check that compared the text as written would pass both.
/// 3. **The extension.** `CON.txt` is still the console, because the device is resolved before the extension is looked at.
///    This is the one that surprises people, and the reason the comparison is on the part before the first dot.
///
/// The check is applied on every platform rather than only on Windows, because a path is data: a kernel on Linux that
/// passes `NUL` through is one whose *behaviour* changes when the same plugin runs on Windows, and the capability model
/// is about what a plugin may do rather than about which machine it happens to be doing it on.
#[must_use]
pub fn is_reserved_name(component: &str) -> bool {
    let trimmed = component.trim_end_matches([' ', '.']);
    let stem = trimmed.split('.').next().unwrap_or(trimmed);
    // `eq_ignore_ascii_case` rather than `to_ascii_uppercase` into a `String`: this runs per component on every path a
    // plugin touches, and the comparison allocates nothing.
    RESERVED_NAMES.iter().any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// Whether a path begins in the Windows device namespace.
///
/// # Why these are refused rather than normalised
///
/// The design's table says to normalise them, and for the sandbox check that would be wrong. `\\?\` is not decoration: it
/// turns **off** the path cleaning Windows otherwise does, so `\\?\C:\data\..\..\Windows` is a literal name for a directory
/// called `..` rather than a way back up the tree. Two paths that look like each other therefore do not mean the same
/// thing, and a check that stripped the prefix and compared the rest would be comparing a name with a different one — and
/// the difference is exactly the part that decides where the data goes.
///
/// The same applies to `\\server\share`, which names a machine rather than a place inside this one: nothing under the
/// sandbox root can contain it, and treating it as a path to compare would be pretending otherwise.
#[must_use]
pub fn is_device_namespace(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Prefix(prefix)) if prefix.as_os_str().to_string_lossy().starts_with(r"\\")
    )
}

/// How a path is being used, which decides which checks apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathUse {
    /// Opened with the default application, so an executable would run.
    Open,
    /// Shown in the file manager, which does not run anything.
    Reveal,
}

/// Checks a path against the policies.
///
/// # Errors
///
/// [`PlatformError::BadPath`] describing the first refusal.
///
/// # Absolute paths only
///
/// A relative path is checked against the working directory, which for a plugin's call is whichever thread the
/// host happened to be on. The same call would then open different files at different times, and the consent
/// prompt could not say which.
pub fn check_path(
    path: &Path,
    path_use: PathUse,
    policies: &Policies,
    sandbox_root: Option<&Path>,
) -> Result<(), PlatformError> {
    let text = path.to_string_lossy();
    let refuse = |reason: PathRefusal| PlatformError::BadPath { path: text.to_string(), reason };

    if text.is_empty() {
        return Err(refuse(PathRefusal::Empty));
    }
    if text.chars().any(char::is_control) {
        return Err(refuse(PathRefusal::ControlCharacter));
    }
    if !path.is_absolute() {
        return Err(refuse(PathRefusal::NotAbsolute));
    }

    // ★ The Windows traps, and why they are checked here rather than where the file is opened.
    //
    // Each of these makes the kernel's idea of a name differ from the file system's. A check made at the point of the open
    // would be a check that had already decided which of the two it was talking to.
    if is_device_namespace(path) {
        return Err(refuse(PathRefusal::DeviceNamespace));
    }
    for component in path.components() {
        let text = component.as_os_str().to_string_lossy();
        // ★ An alternate data stream: `notes.txt:secret` is a second, hidden stream of `notes.txt`, and `evil.exe:x` is a
        // stream of a program rather than the program. Windows allows it on NTFS, every other platform treats the colon as
        // an ordinary character in a name, and the two readings differ — so the path is refused rather than interpreted.
        //
        // The drive prefix is excluded because on Windows `C:` is a prefix and not a component of the path.
        if !matches!(component, Component::Prefix(_)) && text.contains(':') {
            return Err(refuse(PathRefusal::AlternativeStream));
        }
        if is_reserved_name(&text) {
            return Err(refuse(PathRefusal::ReservedName));
        }
    }

    if path_use == PathUse::Reveal && policies.restrict_reveal_to_sandbox {
        match sandbox_root {
            Some(root) => {
                // Component-wise, because `/data` is a string prefix of `/database`.
                if !synra_store::is_within(root, path) {
                    return Err(refuse(PathRefusal::OutsideSandbox));
                }
            }
            // No sandbox supplied and the policy restricts to one means the check cannot be made, and a check
            // that cannot be made is not a check that passed.
            None => return Err(refuse(PathRefusal::OutsideSandbox)),
        }
    }

    if path_use == PathUse::Open && !policies.allow_executables {
        // The list is by extension, and a path with no extension is refused too: the check's purpose is to prove
        // a file is not a program, and with no extension there is nothing to prove it with.
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
        {
            Some(extension) => {
                if EXECUTABLE_EXTENSIONS.contains(&extension.as_str()) {
                    return Err(refuse(PathRefusal::Executable));
                }
            }
            None => return Err(refuse(PathRefusal::UnknownKind)),
        }
    }

    Ok(())
}
