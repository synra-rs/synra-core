//! `synra-daemon` — the kernel's windowless host.
//!
//! Short on purpose: read the flags, run the start-up, print what it decided, release the claim on the way out.
//! Everything decidable lives in the library, which is what keeps this file readable in one go — the crate docs say
//! why that is a design requirement rather than a preference.

use std::process::ExitCode;
use synra_daemon::args::DaemonArgs;
use synra_daemon::startup::{begin, now_ms, release};

fn main() -> ExitCode {
    let args = <DaemonArgs as clap::Parser>::parse();
    // ★ A real reading, not zero. The claim's heartbeat is in the same frame, and a reading of zero made every claim
    // look like it had just beaten — so the crash recovery never fired and a daemon that died abruptly blocked the
    // next start for ever.
    let decision = begin(&args, std::process::id(), now_ms());

    for line in decision.lines() {
        println!("{line}");
    }
    // A refusal goes to the error stream, so a script redirecting one does not lose it and a user piping to a pager
    // does not have it buried among the output.
    if let Some(reason) = decision.failure() {
        eprintln!("synra-daemon: {reason}");
    }

    if decision.may_run() {
        // The kernel's own start-up is the next step, and it needs the socket and the session that the core crate
        // owns. A host that reported success without running a kernel would be worse than one that says what it did
        // not do.
        println!("no kernel is started yet: the session layer is not implemented");
        // ★ A clean shutdown says so in the claim rather than deleting it. A deleted file is indistinguishable from a
        // daemon that was killed before it wrote one — and that difference is exactly what the next start wants to
        // know, because it is what lets a crashed session be reported as a crash.
        if let Err(error) = release(&decision) {
            eprintln!("synra-daemon: {error}");
            return ExitCode::FAILURE;
        }
    }

    ExitCode::from(decision.exit_code())
}
