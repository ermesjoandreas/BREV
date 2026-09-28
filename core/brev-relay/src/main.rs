//! brev-relay (docs/PHASE3_DESIGN.md §4.5, docs/PHASE4_DESIGN.md §4.6):
//! `serve` runs the relay on `127.0.0.1:<port>` with its limits; `release`
//! is the operator command that frees an address; `invite` is the operator
//! command that prints a root invite. Arguments are parsed by hand;
//! everything else is in the library.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use brev_proto::body::is_valid_address;
use brev_relay::{parse_listen, Config, Gates, Open, Relay, Server};

const USAGE: &str = "usage: brev-relay serve --db <absolute path> --listen 127.0.0.1:<port> [--port-file <path>] [--trace]
                        [--letters-per-day N] [--requests-per-day N] [--invites-per-day N]
                        [--open-invites N] [--pending-requests N] [--invite-days N]
       brev-relay serve --phase3 --db <absolute path> --listen 127.0.0.1:<port> [--port-file <path>] [--trace]
       brev-relay release --db <absolute path> <address>
       brev-relay invite --db <absolute path>
defaults: 50 letters, 10 requests and 3 invites per identity per UTC day, 5 open
invites, 16 pending requests per recipient, invites live 7 days. --phase3 serves
Phase 3's bodies without any Phase 4 check, for Phase 3's app and tests only.";

/// A usage error (exit 2) or a failure (exit 1), with its message.
enum Fail {
    Usage(String),
    Run(String),
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Fail::Usage(message)) => {
            eprintln!("brev-relay: {message}\n{USAGE}");
            ExitCode::from(2)
        }
        Err(Fail::Run(message)) => {
            eprintln!("brev-relay: {message}");
            ExitCode::FAILURE
        }
    }
}

/// A limit flag's value: decimal digits that fit a u32.
fn number(arg: &OsString, value: &OsString) -> Result<u32, Fail> {
    value
        .to_str()
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse().ok())
        .ok_or(Fail::Usage(format!("{arg:?} needs a number")))
}

fn run(args: Vec<OsString>) -> Result<(), Fail> {
    let mut args = args.into_iter();
    let command = args.next().ok_or(Fail::Usage("no command".into()))?;
    let mut db = None;
    let mut listen = None;
    let mut port_file = None;
    let mut trace = false;
    let mut phase3 = false;
    let mut limits = false;
    let mut config = Config::default();
    let mut rest = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or(Fail::Usage(format!("{arg:?} needs a value")))
        };
        let limit = match arg.to_str() {
            Some("--db") => {
                db = Some(PathBuf::from(value()?));
                None
            }
            Some("--listen") => {
                listen = Some(value()?);
                None
            }
            Some("--port-file") => {
                port_file = Some(PathBuf::from(value()?));
                None
            }
            Some("--trace") => {
                trace = true;
                None
            }
            Some("--phase3") => {
                phase3 = true;
                None
            }
            Some("--letters-per-day") => Some(&mut config.letters_per_day),
            Some("--requests-per-day") => Some(&mut config.requests_per_day),
            Some("--invites-per-day") => Some(&mut config.invites_per_day),
            Some("--open-invites") => Some(&mut config.open_invites),
            Some("--pending-requests") => Some(&mut config.pending_requests),
            Some("--invite-days") => Some(&mut config.invite_days),
            _ => {
                rest.push(arg.clone());
                None
            }
        };
        if let Some(limit) = limit {
            *limit = number(&arg, &value()?)?;
            limits = true;
        }
    }
    let db = db.ok_or(Fail::Usage("--db is required".into()))?;
    let only_db = listen.is_none() && port_file.is_none() && !trace && !phase3 && !limits;
    match command.to_str() {
        Some("serve") => {
            if !rest.is_empty() {
                return Err(Fail::Usage(format!("unexpected arguments {rest:?}")));
            }
            if phase3 && limits {
                return Err(Fail::Usage("--phase3 has no limits to set".into()));
            }
            let listen = listen.ok_or(Fail::Usage("--listen is required".into()))?;
            let listen = listen
                .to_str()
                .ok_or(brev_relay::Error::Listen)
                .and_then(parse_listen)
                .map_err(|e| Fail::Usage(e.to_string()))?;
            config.phase3 = phase3;
            serve(&db, config, listen, port_file.as_deref(), trace)
        }
        Some("release") => {
            if !only_db {
                return Err(Fail::Usage("release takes only --db and an address".into()));
            }
            let [address] = <[OsString; 1]>::try_from(rest)
                .map_err(|_| Fail::Usage("release needs one address".into()))?;
            let address = address
                .to_str()
                .filter(|a| is_valid_address(a.as_bytes()))
                .ok_or(Fail::Usage(
                    "an address is 3-32 of a-z, 0-9 and '-', starting with a letter".into(),
                ))?;
            release(&db, address)
        }
        Some("invite") => {
            if !only_db || !rest.is_empty() {
                return Err(Fail::Usage("invite takes only --db".into()));
            }
            invite(&db)
        }
        _ => Err(Fail::Usage(format!("unknown command {command:?}"))),
    }
}

fn serve(
    db: &Path,
    config: Config,
    listen: std::net::SocketAddr,
    port_file: Option<&Path>,
    trace: bool,
) -> Result<(), Fail> {
    let relay = Relay::open_with(db, Box::new(Open), config, Gates::default())
        .map_err(|e| Fail::Run(e.to_string()))?;
    let server =
        Server::start(Arc::new(relay), listen, trace).map_err(|e| Fail::Run(e.to_string()))?;
    let addr = server.addr();
    if let Some(path) = port_file {
        write_port_file(path, addr.port())
            .map_err(|e| Fail::Run(format!("cannot write the port file: {e}")))?;
    }
    eprintln!("brev-relay: listening on {addr}");
    server
        .wait()
        .map_err(|e| Fail::Run(format!("serving failed: {e}")))
}

/// Writes the port and a newline to `<path>.tmp`, then renames it, so a
/// reader never sees a partly written file.
fn write_port_file(path: &Path, port: u16) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    std::fs::write(&tmp, format!("{port}\n"))?;
    std::fs::rename(&tmp, path)
}

/// Opens the relay file for an operator command, with Phase 4's default
/// config (the commands use only its clock and the invite life).
fn open(db: &Path) -> Result<Relay, Fail> {
    Relay::open_with(db, Box::new(Open), Config::default(), Gates::default())
        .map_err(|e| Fail::Run(e.to_string()))
}

fn release(db: &Path, address: &str) -> Result<(), Fail> {
    // `open` would create a missing file; a release never should.
    if !db.is_file() {
        return Err(Fail::Run(format!("no relay database at {}", db.display())));
    }
    match open(db)?.release(address) {
        Ok(true) => {
            eprintln!(
                "brev-relay: released; its waiting letters, links, events, invites and counts are deleted"
            );
            Ok(())
        }
        Ok(false) => Err(Fail::Run("no identity has that address".into())),
        Err(e) => Err(Fail::Run(e.to_string())),
    }
}

/// Prints a new root invite code and a newline on stdout. Creates the
/// relay file if it is missing: a root invite brings in the first identity.
fn invite(db: &Path) -> Result<(), Fail> {
    let code = open(db)?
        .root_invite()
        .map_err(|e| Fail::Run(e.to_string()))?;
    let mut out = std::io::stdout().lock();
    out.write_all(&code)
        .and_then(|()| out.write_all(b"\n"))
        .and_then(|()| out.flush())
        .map_err(|e| Fail::Run(format!("cannot print the code: {e}")))
}
