//! brev-relay (docs/PHASE3_DESIGN.md §4.5): `serve` runs the relay on
//! `127.0.0.1:<port>`; `release` is the operator command that frees an
//! address. Arguments are parsed by hand; everything else is in the library.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use brev_proto::body::is_valid_address;
use brev_relay::{parse_listen, Open, Relay, Server};

const USAGE: &str = "usage: brev-relay serve --db <absolute path> --listen 127.0.0.1:<port> [--port-file <path>] [--trace]
       brev-relay release --db <absolute path> <address>";

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

fn run(args: Vec<OsString>) -> Result<(), Fail> {
    let mut args = args.into_iter();
    let command = args.next().ok_or(Fail::Usage("no command".into()))?;
    let mut db = None;
    let mut listen = None;
    let mut port_file = None;
    let mut trace = false;
    let mut rest = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = || {
            args.next()
                .ok_or(Fail::Usage(format!("{arg:?} needs a value")))
        };
        match arg.to_str() {
            Some("--db") => db = Some(PathBuf::from(value()?)),
            Some("--listen") => listen = Some(value()?),
            Some("--port-file") => port_file = Some(PathBuf::from(value()?)),
            Some("--trace") => trace = true,
            _ => rest.push(arg),
        }
    }
    let db = db.ok_or(Fail::Usage("--db is required".into()))?;
    match command.to_str() {
        Some("serve") => {
            if !rest.is_empty() {
                return Err(Fail::Usage(format!("unexpected arguments {rest:?}")));
            }
            let listen = listen.ok_or(Fail::Usage("--listen is required".into()))?;
            let listen = listen
                .to_str()
                .ok_or(brev_relay::Error::Listen)
                .and_then(parse_listen)
                .map_err(|e| Fail::Usage(e.to_string()))?;
            serve(&db, listen, port_file.as_deref(), trace)
        }
        Some("release") => {
            if listen.is_some() || port_file.is_some() || trace {
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
        _ => Err(Fail::Usage(format!("unknown command {command:?}"))),
    }
}

fn serve(
    db: &Path,
    listen: std::net::SocketAddr,
    port_file: Option<&Path>,
    trace: bool,
) -> Result<(), Fail> {
    let relay = Relay::open(db, Box::new(Open)).map_err(|e| Fail::Run(e.to_string()))?;
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

fn release(db: &Path, address: &str) -> Result<(), Fail> {
    // `open` would create a missing file; a release never should.
    if !db.is_file() {
        return Err(Fail::Run(format!("no relay database at {}", db.display())));
    }
    let relay = Relay::open(db, Box::new(Open)).map_err(|e| Fail::Run(e.to_string()))?;
    match relay.release(address) {
        Ok(true) => {
            eprintln!("brev-relay: released; its waiting letters are deleted");
            Ok(())
        }
        Ok(false) => Err(Fail::Run("no identity has that address".into())),
        Err(e) => Err(Fail::Run(e.to_string())),
    }
}
