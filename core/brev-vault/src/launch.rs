//! The launch guard (feature `launch-guard`, on by default, off in tests):
//! nothing is created, opened or unlocked in a process that loaded code
//! through a `DYLD_*` variable, or in which freed memory is not scribbled
//! (`MallocScribble=1`, which the app sets in its Info.plist and its
//! LaunchGuard re-executes for; CLAUDE.md §2).

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use crate::Error;

/// `Unsafe` if a variable's name starts with `DYLD_`, or if `MallocScribble`
/// is missing or not exactly `1`.
pub fn launch_check(vars: impl IntoIterator<Item = (OsString, OsString)>) -> Result<(), Error> {
    let mut scribble = false;
    for (name, value) in vars {
        if name.as_bytes().starts_with(b"DYLD_") {
            return Err(Error::Unsafe);
        }
        if name == "MallocScribble" {
            scribble = value == "1";
        }
    }
    if scribble {
        Ok(())
    } else {
        Err(Error::Unsafe)
    }
}

/// [`launch_check`] of this process's environment, with the feature on.
pub(crate) fn check_env() -> Result<(), Error> {
    if cfg!(feature = "launch-guard") {
        launch_check(std::env::vars_os())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(list: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        list.iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect()
    }

    #[test]
    fn launch_check_needs_scribble_and_no_dyld() {
        let base = [("PATH", "/usr/bin:/bin"), ("HOME", "/Users/x")];
        let safe = [&base[..], &[("MallocScribble", "1")]].concat();
        assert!(launch_check(vars(&safe)).is_ok());
        for (name, list) in [
            ("no MallocScribble", base.to_vec()),
            (
                "MallocScribble=0",
                [&base[..], &[("MallocScribble", "0")]].concat(),
            ),
            (
                "MallocScribble=",
                [&base[..], &[("MallocScribble", "")]].concat(),
            ),
            (
                "MallocScribble=11",
                [&base[..], &[("MallocScribble", "11")]].concat(),
            ),
            (
                "DYLD_INSERT_LIBRARIES",
                [&safe[..], &[("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib")]].concat(),
            ),
            (
                "DYLD_FALLBACK_LIBRARY_PATH",
                [&[("DYLD_FALLBACK_LIBRARY_PATH", "")], &safe[..]].concat(),
            ),
            ("DYLD_ alone", [&safe[..], &[("DYLD_", "1")]].concat()),
        ] {
            assert!(
                matches!(launch_check(vars(&list)), Err(Error::Unsafe)),
                "{name}"
            );
        }
        // Only the prefix counts: these are fine.
        let near = [
            &safe[..],
            &[("XDYLD_X", "1"), ("dyld_x", "1"), ("DYLD", "1")],
        ]
        .concat();
        assert!(launch_check(vars(&near)).is_ok());
    }
}
