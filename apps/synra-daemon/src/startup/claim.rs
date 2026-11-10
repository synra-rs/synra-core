use std::path::Path;

use crate::args::{ClaimFile, DaemonArgs, Parsed};
use crate::lock::{Claim, LockError, LockFile};

use super::{Startup, now_ms};

/// Runs start-up as far as the claim, creating nothing.
///
/// # Errors
///
/// Never — a refusal is a [`Startup::Refused`] rather than an error, because "this configuration is wrong" is an
/// answer to the question the daemon was asked, not a failure of asking it.
#[must_use]
pub fn startup(args: &DaemonArgs, now_ms: u64) -> Startup {
    let parsed = match Parsed::resolve(args) {
        Ok(parsed) => parsed,
        Err(error) => return Startup::Refused { reason: error.to_string() },
    };

    if parsed.dry_run {
        return Startup::DryRun { plan: Box::new(parsed.plan) };
    }

    let path = parsed.plan.lock_path();
    let existing = match ClaimFile::read(&path) {
        Ok(existing) => existing,
        // A claim file that exists and cannot be interpreted is refused rather than treated as absent, because it
        // might be a live owner's — and starting over a running daemon is what the lock exists to prevent.
        Err(error) => return Startup::Refused { reason: error.to_string() },
    };

    // A diagnostic run reads the claim and does not take it: a user who wants to see what a running daemon thinks
    // should not have to stop it.
    let claim = if parsed.plan.exclusive {
        match existing.decide(now_ms, &path) {
            Ok(claim) => claim,
            Err(error) => return Startup::Refused { reason: error.to_string() },
        }
    }
    else {
        Claim::Taken
    };

    if !claim.may_run() {
        // The lines are the plan's, so a user sees which installation is already in use — which is the first thing
        // they need to know and the thing a bare "already running" would not tell them.
        let mut lines = parsed.plan.lines();
        // The claim's own refusal names the pid and the age, which is the part a user acts on.
        if let Claim::Held { owner, age_ms } = &claim {
            lines.push(format!(
                "held by pid {} (version {}), last alive {}s ago",
                owner.pid,
                owner.version,
                age_ms / 1_000
            ));
        }
        return Startup::AlreadyRunning {
            lines,
            reason: claim
                .refusal()
                .unwrap_or_else(|| "another synra-daemon is already using this data directory".to_owned()),
        };
    }

    let reclaimed_from = match &claim {
        Claim::Reclaimed { previous, .. } => Some(Box::new(previous.clone())),
        _ => None,
    };

    Startup::Ready {
        plan: Box::new(parsed.plan),
        claim: Box::new(claim),
        written: None,
        reclaimed_from,
    }
}

/// Runs start-up **and writes the claim**, which is what a real start does.
///
/// # Why this exists
///
/// [`startup`] decides and writes nothing, which is what makes it testable — a function with a side effect cannot be
/// called twice in one test to see what the second call decides. But a daemon that only *decided* it owned the
/// directory is a daemon whose exclusive claim is decorative: it reported "claimed the data directory" while leaving
/// no file behind, so a second instance decided the same thing and both believed they were alone.
///
/// So the writing is its own step, taken here, after the decision. A failure to write is a [`Startup::Refused`]: a
/// daemon that cannot write its claim must not run, because it would be running while believing it holds a claim it
/// does not.
#[must_use]
pub fn begin(args: &DaemonArgs, pid: u32, now_ms: u64) -> Startup {
    let decision = startup(args, now_ms);

    let Startup::Ready { plan, .. } = &decision else {
        return decision;
    };

    // A diagnostic run takes no claim, so there is nothing to write — writing one would make a run that promised not
    // to touch the directory the one that held it.
    if !plan.exclusive {
        return decision;
    }

    let path = plan.lock_path();
    match crate::args::write_claim(&path, pid, now_ms) {
        // The written claim goes back to the caller, because a clean shutdown has to mark *this* claim rather than
        // write a new one — and only the value knows the claimed-at reading and the pid.
        Ok(lock) => match decision {
            Startup::Ready { plan, claim, reclaimed_from, .. } => Startup::Ready {
                plan,
                claim,
                written: Some(Box::new(lock)),
                reclaimed_from,
            },
            other => other,
        },
        Err(error) => Startup::Refused { reason: error.to_string() },
    }
}

/// Releases the claim this process holds.
///
/// # Errors
///
/// [`LockError`] when the file exists and cannot be removed.
///
/// # Why a clean shutdown takes its own claim away
///
/// A claim left behind is not *wrong* — the next start reclaims it after the heartbeat goes stale — but it costs the
/// user ninety seconds of waiting and it writes "the previous session ended without shutting down" into the log for a
/// session that ended perfectly well. Removing it on the way out is what makes that message mean something.
pub fn release(decision: &Startup) -> Result<(), LockError> {
    let Startup::Ready { plan, written: Some(lock), .. } = decision else {
        // A diagnostic run wrote no claim, and a decision that never took one has nothing to mark. Returning `Ok`
        // rather than an error is right: the caller wanted the claim released and it is not there.
        return Ok(());
    };
    if !plan.exclusive {
        return Ok(());
    }
    mark_clean_shutdown(&plan.lock_path(), lock).map(|_| ())
}

/// Marks the claim as cleanly shut down.
///
/// # Why this is a write rather than a removal
///
/// Removing the file is indistinguishable from a daemon that was killed before it ever wrote one, and the difference
/// is exactly what the next start wants to know. So the claim is *kept* and marked: the next start reads it, sees
/// `clean`, and reports an ordinary first start rather than a reclaim.
///
/// # Errors
///
/// [`LockError`] when the file cannot be rewritten.
pub fn mark_clean_shutdown(path: &Path, lock: &LockFile) -> Result<LockFile, LockError> {
    let mut clean = lock.clone();
    clean.owner.clean = true;
    clean.owner.heartbeat_ms = now_ms();
    std::fs::write(path, crate::args::encode_claim(&clean, path)?).map_err(|error| LockError::Unreadable {
        path: path.display().to_string(),
        reason: format!("the claim could not be marked clean: {error}"),
    })?;
    Ok(clean)
}
