//! Policy checks for actions that reach the desktop.

mod path;
mod rate;
mod text;
mod url;

pub use path::{PathUse, check_path, is_device_namespace, is_reserved_name};
pub use rate::RateLimiter;
pub use text::{check_clipboard_text, check_notification};
pub use url::{check_url, check_url_length};
