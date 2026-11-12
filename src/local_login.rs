//! `remote-dm local-login`: keeps a local login from starting a second desktop next to the user's
//! remote session.
//!
//! One user can't run two desktops at once (see `logind::graphical_sessions`). Plasma is worse
//! than niri there: its desktop runs as systemd user services, which the remote session already
//! started, so a local Plasma login finds them "already running", never starts its own KWin and
//! hangs on a black screen. And when that local session ends, it stops those services, taking the
//! remote session with it.
//!
//! The local login manager runs this from its PAM `account` stack (after the password checked
//! out) with `pam_exec.so stdout`:
//!
//! - no remote graphical session of the user: succeed;
//! - otherwise the first login fails, after showing for a few seconds that logging in again logs
//!   the remote session out (local greeters can't ask a question, and plasmalogin replaces any
//!   message with "Login Failed" when the login fails);
//! - logging in again within a minute logs the remote sessions out, waits until they're gone, and
//!   succeeds.

use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use anyhow::Context;

use crate::logind;

/// How long a second login counts as confirming.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(60);
/// How long the message stays up before the login fails (and the greeter replaces it).
const MESSAGE_TIME: Duration = Duration::from_secs(5);

fn message(username: &str) -> String {
    if crate::chinese() {
        format!("{username} 正在远程登录。一分钟内再登录一次会注销远程会话（未保存的会丢失）")
    } else {
        format!(
            "{username} is logged in remotely. Log in again within a minute to log that out \
             (unsaved work is lost)"
        )
    }
}

/// Logs to the journal: pam_exec shows our stdout and stderr to the user.
fn log(message: &str) {
    if let Ok(socket) = UnixDatagram::unbound() {
        let entry = format!("SYSLOG_IDENTIFIER=remote-dm\nPRIORITY=6\nMESSAGE=local-login: {message}\n");
        let _ = socket.send_to(entry.as_bytes(), "/run/systemd/journal/socket");
    }
}

/// The marker of an unconfirmed login, in remote-dm's runtime directory (root only).
fn marker(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/remote-dm/local-login-{uid}"))
}

fn recent(path: &PathBuf) -> bool {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age < CONFIRM_TIMEOUT)
}

/// Returns the exit code for pam_exec: 0 lets the login through.
pub fn main() -> i32 {
    match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)
        .and_then(|runtime| runtime.block_on(run()))
    {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(err) => {
            // Don't lock people out of their computer over a bug here.
            log(&format!("error, letting the login through: {err:#}"));
            0
        }
    }
}

async fn run() -> anyhow::Result<bool> {
    if std::env::var("PAM_TYPE").as_deref() != Ok("account") {
        return Ok(true);
    }
    let username = std::env::var("PAM_USER").context("PAM_USER isn't set")?;
    let uid = nix::unistd::User::from_name(&username)?
        .context("no such user")?
        .uid
        .as_raw();

    let conn = zbus::Connection::system().await?;
    let remote: Vec<String> = logind::graphical_sessions_with_remote(&conn, uid)
        .await?
        .into_iter()
        .filter_map(|(id, remote)| remote.then_some(id))
        .collect();
    let marker = marker(uid);
    if remote.is_empty() {
        let _ = std::fs::remove_file(&marker);
        return Ok(true);
    }

    if recent(&marker) {
        let _ = std::fs::remove_file(&marker);
        log(&format!("{username} logged in again, logging out the remote sessions {remote:?}"));
        logind::terminate_sessions_and_wait(&conn, &remote).await;
        logind::stop_graphical_session(&username).await;
        return Ok(true);
    }

    log(&format!("{username} is logged in remotely ({remote:?}), asking to log in again"));
    if let Some(dir) = marker.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&marker, b"")?;
    // pam_exec passes each line on as a PAM info message right away.
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{}", message(&username))?;
    stdout.flush()?;
    tokio::time::sleep(MESSAGE_TIME).await;
    Ok(false)
}
