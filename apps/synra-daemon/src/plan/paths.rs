use synra_store::sanitise_component;

use super::PlanError;

/// A name turned into one path component, refusing the shapes that would name somewhere else.
///
/// Used when the daemon makes a directory after a plugin or a device, because a name that came from outside is a path
/// traversal waiting to happen and the check has to run before the join rather than after it.
///
/// # Sanitising rather than refusing, for everything but the empty shape
///
/// The store's substitution is what makes `@synra-plugin/chat` a single directory name, and refusing a name that
/// contains a separator would refuse every plugin id there is. So a name with separators is *turned into* a component,
/// by the same function the rest of the kernel uses — two spellings of one plugin's directory would be one plugin with
/// two directories.
///
/// The exception is a name that sanitises to nothing useful, and the reason is arithmetic rather than taste: joining
/// an empty component is the *parent* directory, so a caller that meant to write inside its own directory would write
/// one level up. `..` sanitises to `_`, which is a harmless directory named `_`, so it is not refused — but a name of
/// only dots sanitises to a run of dots, and `...` joined is a path that means something other than a directory.
///
/// # Errors
///
/// [`PlanError::BadName`] when the name is empty or sanitises to nothing usable.
pub fn checked_component(name: &str) -> Result<String, PlanError> {
    if name.trim().is_empty() {
        return Err(PlanError::BadName {
            name: name.to_owned(),
        });
    }
    let component = sanitise_component(name);
    // Empty is the dangerous one: `Path::join("")` is the parent. A run of dots is refused too, because `..` collapsing
    // to `.` and then joining is a path that names a directory the caller did not ask for.
    if component.is_empty() || component.chars().all(|ch| ch == '.') {
        return Err(PlanError::BadName {
            name: name.to_owned(),
        });
    }
    Ok(component)
}
