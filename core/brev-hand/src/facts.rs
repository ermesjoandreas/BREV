//! Facts, not flags (docs/AUTHORSHIP.md §2.2, §3.1): the adapter hands over
//! what it saw — process names, the window list, the raw SIP bits — and
//! this module counts. The adapter has no way to set a count.
//!
//! Times are milliseconds on a monotonic clock the caller owns, so the
//! rules here are pure and the tests can move time.

/// The agent list (docs/AUTHORSHIP.md §4.4): process names, compared
/// without case. A process name from `sysctl KERN_PROC_ALL` is at most 16
/// bytes, so no entry is longer. A renamed program is not seen.
pub const AGENTS: [&str; 9] = [
    "aider",
    "chatgpt",
    "claude",
    "codex",
    "cursor",
    "goose",
    "lm studio",
    "ollama",
    "windsurf",
];

/// SIP bits that guard Brev's code and memory: untrusted kexts (0x01),
/// unrestricted filesystem (0x02), task_for_pid (0x04), kernel debugger
/// (0x08) and unrestricted dtrace (0x20). Any of them set is "SIP off".
pub const SIP_GUARDS: u32 = 0x2F;

/// A gap in the measuring longer than this many seconds fails the
/// requirements (`max-gap`).
pub const MAX_GAP_SECONDS: u32 = 5;

/// One on-screen window, as `CGWindowListCopyWindowInfo` lists it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// The owning process.
    pub owner_pid: i32,
    /// The window layer; 0 is an ordinary app window.
    pub layer: i32,
}

/// What the adapter read at one moment. `None` means the read failed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sample {
    /// `IsSecureEventInputEnabled()`.
    pub secure_input: bool,
    /// The compose window's `sharingType` is `.none`.
    pub sharing_none: bool,
    /// The protected content layer has `preventsCapture`.
    pub prevents_capture: bool,
    /// `csr_get_active_config`.
    pub csr_config: Option<u32>,
    /// The name of every process (`sysctl KERN_PROC_ALL`).
    pub processes: Option<Vec<String>>,
    /// Every on-screen window.
    pub windows: Option<Vec<Window>>,
}

/// What the app is built to do; it cannot measure these at run time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Design {
    /// Content views expose no text to Accessibility.
    pub ax_opaque: bool,
    /// No copy, cut, paste or drag of content.
    pub pasteboard_off: bool,
    /// Events from another process are dropped.
    pub input_filter: bool,
}

/// The facts a token carries (`"env"`), in the token's key order.
/// `None` is a fact that could not be read, or was never sampled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Env {
    /// SIP on: no bit of [`SIP_GUARDS`] set, in every sample.
    pub sip: Option<bool>,
    /// Most `sudo`/`su` processes in any sample.
    pub sudo: Option<u32>,
    /// The user is in the admin group.
    pub admin: Option<bool>,
    /// Most distinct [`AGENTS`] names running in any sample.
    pub agents: Option<u32>,
    /// Pastes that reached the content.
    pub pastes: u32,
    /// Longest gap in the measuring, in whole seconds rounded up.
    pub max_gap: u32,
    /// From opening compose to the send request, in whole seconds.
    pub seconds: u32,
    /// Most other apps' ordinary windows on screen in any sample.
    pub windows: Option<u32>,
    /// [`Design::ax_opaque`].
    pub ax_opaque: bool,
    /// Capture excluded in every sample.
    pub capture_off: Option<bool>,
    /// [`Design::input_filter`].
    pub input_filter: bool,
    /// Secure event input on in every sample.
    pub secure_input: Option<bool>,
    /// Synthetic events the filter dropped.
    pub blocked_input: u32,
    /// [`Design::pasteboard_off`].
    pub pasteboard_off: bool,
}

/// Why Brev locks (docs/AUTHORSHIP.md §4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockReason {
    /// A `sudo` or `su` process runs.
    Sudo,
    /// A bit of [`SIP_GUARDS`] is set.
    SipOff,
}

/// The lock rule for one sample: empty when Brev may stay unlocked. A read
/// that failed is no reason to lock (it fails the requirements instead).
pub fn lock_reasons(s: &Sample) -> Vec<LockReason> {
    let mut out = Vec::new();
    if s.processes.as_deref().map(sudo_count).unwrap_or(0) > 0 {
        out.push(LockReason::Sudo);
    }
    if s.csr_config.is_some_and(|c| c & SIP_GUARDS != 0) {
        out.push(LockReason::SipOff);
    }
    out
}

fn sudo_count(names: &[String]) -> u32 {
    count(names.iter().filter(|n| *n == "sudo" || *n == "su"))
}

fn agent_count(names: &[String]) -> u32 {
    count(
        AGENTS
            .iter()
            .filter(|a| names.iter().any(|n| n.eq_ignore_ascii_case(a))),
    )
}

fn window_count(windows: &[Window], own_pid: i32) -> u32 {
    count(
        windows
            .iter()
            .filter(|w| w.layer == 0 && w.owner_pid != own_pid),
    )
}

fn count<T>(it: impl Iterator<Item = T>) -> u32 {
    u32::try_from(it.count()).unwrap_or(u32::MAX)
}

/// A sampled fact: never sampled, read in every sample so far, or failed
/// to read at least once.
#[derive(Clone, Copy, Debug)]
enum Seen<T> {
    Never,
    Value(T),
    Unreadable,
}

impl<T: Copy> Seen<T> {
    fn add(&mut self, read: Option<T>, merge: fn(T, T) -> T) {
        *self = match (*self, read) {
            (Seen::Unreadable, _) | (_, None) => Seen::Unreadable,
            (Seen::Never, Some(v)) => Seen::Value(v),
            (Seen::Value(a), Some(b)) => Seen::Value(merge(a, b)),
        };
    }

    fn get(self) -> Option<T> {
        match self {
            Seen::Value(v) => Some(v),
            Seen::Never | Seen::Unreadable => None,
        }
    }
}

/// The facts of one letter, from compose opening to the send request.
#[derive(Clone, Debug)]
pub struct FactLog {
    own_pid: i32,
    design: Design,
    admin: Option<bool>,
    started: u64,
    last: u64,
    max_gap: u64,
    secure_input: Seen<bool>,
    capture_off: Seen<bool>,
    sip: Seen<bool>,
    sudo: Seen<u32>,
    agents: Seen<u32>,
    windows: Seen<u32>,
    pastes: u32,
    blocked_input: u32,
}

impl FactLog {
    /// Compose opened at `now` (ms). `admin` is read once; `own_pid` is
    /// this process, whose windows do not count.
    pub fn start(now: u64, own_pid: i32, design: Design, admin: Option<bool>) -> FactLog {
        FactLog {
            own_pid,
            design,
            admin,
            started: now,
            last: now,
            max_gap: 0,
            secure_input: Seen::Never,
            capture_off: Seen::Never,
            sip: Seen::Never,
            sudo: Seen::Never,
            agents: Seen::Never,
            windows: Seen::Never,
            pastes: 0,
            blocked_input: 0,
        }
    }

    /// One sample at `now` (ms).
    pub fn sample(&mut self, now: u64, s: &Sample) {
        self.max_gap = self.max_gap.max(now.saturating_sub(self.last));
        self.last = self.last.max(now);
        let and = |a: bool, b: bool| a && b;
        self.secure_input.add(Some(s.secure_input), and);
        self.capture_off
            .add(Some(s.sharing_none && s.prevents_capture), and);
        self.sip.add(s.csr_config.map(|c| c & SIP_GUARDS == 0), and);
        let names = s.processes.as_deref();
        self.sudo.add(names.map(sudo_count), u32::max);
        self.agents.add(names.map(agent_count), u32::max);
        let own = self.own_pid;
        self.windows
            .add(s.windows.as_deref().map(|w| window_count(w, own)), u32::max);
    }

    /// The filter dropped one synthetic event.
    pub fn synthetic_dropped(&mut self) {
        self.blocked_input = self.blocked_input.saturating_add(1);
    }

    /// A paste reached the content. Brev never calls this; an SDK app that
    /// allows paste must.
    pub fn paste_accepted(&mut self) {
        self.pastes = self.pastes.saturating_add(1);
    }

    /// The send request at `now` (ms), with the sample taken then.
    pub fn finish(mut self, now: u64, last: &Sample) -> Env {
        self.sample(now, last);
        let secs = |ms: u64| u32::try_from(ms.div_ceil(1000)).unwrap_or(u32::MAX);
        Env {
            sip: self.sip.get(),
            sudo: self.sudo.get(),
            admin: self.admin,
            agents: self.agents.get(),
            pastes: self.pastes,
            max_gap: secs(self.max_gap),
            seconds: u32::try_from(now.saturating_sub(self.started) / 1000).unwrap_or(u32::MAX),
            windows: self.windows.get(),
            ax_opaque: self.design.ax_opaque,
            capture_off: self.capture_off.get(),
            input_filter: self.design.input_filter,
            secure_input: self.secure_input.get(),
            blocked_input: self.blocked_input,
            pasteboard_off: self.design.pasteboard_off,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PID: i32 = 4242;
    const DESIGN: Design = Design {
        ax_opaque: true,
        pasteboard_off: true,
        input_filter: true,
    };

    fn names(list: &[&str]) -> Option<Vec<String>> {
        Some(list.iter().map(|s| s.to_string()).collect())
    }

    fn clean() -> Sample {
        Sample {
            secure_input: true,
            sharing_none: true,
            prevents_capture: true,
            csr_config: Some(0),
            processes: names(&["launchd", "Brev", "zsh"]),
            windows: Some(vec![Window {
                owner_pid: PID,
                layer: 0,
            }]),
        }
    }

    #[test]
    fn a_clean_letter_counts_what_it_saw() {
        let mut log = FactLog::start(0, PID, DESIGN, Some(true));
        let mut s = clean();
        s.processes = names(&["claude", "Claude", "node", "Cursor", "sudo"]);
        s.windows = Some(vec![
            Window {
                owner_pid: PID,
                layer: 0,
            },
            Window {
                owner_pid: 7,
                layer: 0,
            },
            Window {
                owner_pid: 8,
                layer: 0,
            },
            Window {
                owner_pid: 9,
                layer: 25,
            },
        ]);
        log.sample(2_000, &s);
        log.synthetic_dropped();
        let env = log.finish(4_000, &clean());
        assert_eq!(env.agents, Some(2), "claude and cursor, each once");
        assert_eq!(env.sudo, Some(1));
        assert_eq!(
            env.windows,
            Some(2),
            "own and layer-25 windows do not count"
        );
        assert_eq!(env.sip, Some(true));
        assert_eq!(env.secure_input, Some(true));
        assert_eq!(env.capture_off, Some(true));
        assert_eq!(env.admin, Some(true));
        assert_eq!(env.blocked_input, 1);
        assert_eq!(env.pastes, 0);
        assert_eq!(env.max_gap, 2);
        assert_eq!(env.seconds, 4);
    }

    #[test]
    fn one_failed_read_makes_the_fact_unreadable() {
        let mut log = FactLog::start(0, PID, DESIGN, None);
        let mut s = clean();
        s.processes = None;
        s.windows = None;
        s.csr_config = None;
        log.sample(2_000, &s);
        let env = log.finish(4_000, &clean());
        assert_eq!(
            (env.sudo, env.agents, env.windows, env.sip, env.admin),
            (None, None, None, None, None)
        );
    }

    #[test]
    fn one_bad_sample_is_enough() {
        let mut log = FactLog::start(0, PID, DESIGN, Some(false));
        let mut s = clean();
        s.secure_input = false;
        s.prevents_capture = false;
        s.csr_config = Some(0x04);
        log.sample(2_000, &s);
        let env = log.finish(4_000, &clean());
        assert_eq!(env.secure_input, Some(false));
        assert_eq!(env.capture_off, Some(false));
        assert_eq!(env.sip, Some(false));
    }

    #[test]
    fn gaps_count_from_compose_opening_to_send() {
        // Nothing between opening and send: the whole time is one gap.
        let env = FactLog::start(1_000, PID, DESIGN, Some(true)).finish(9_000, &clean());
        assert_eq!(env.max_gap, 8);
        // Opening to the first sample.
        let mut log = FactLog::start(0, PID, DESIGN, Some(true));
        log.sample(6_000, &clean());
        log.sample(8_000, &clean());
        assert_eq!(log.finish(9_000, &clean()).max_gap, 6);
        // The last sample to send; 5.2 s rounds up to 6.
        let mut log = FactLog::start(0, PID, DESIGN, Some(true));
        log.sample(2_000, &clean());
        assert_eq!(log.finish(7_200, &clean()).max_gap, 6);
        // A clock that goes back gives no negative gap.
        let mut log = FactLog::start(5_000, PID, DESIGN, Some(true));
        log.sample(4_000, &clean());
        assert_eq!(log.finish(6_000, &clean()).max_gap, 1);
    }

    #[test]
    fn lock_rule_is_sudo_or_sip_and_never_a_failed_read() {
        assert_eq!(lock_reasons(&clean()), vec![]);
        let mut s = clean();
        s.processes = names(&["su"]);
        assert_eq!(lock_reasons(&s), vec![LockReason::Sudo]);
        s.processes = names(&["sudo", "Brev"]);
        s.csr_config = Some(0x7F);
        assert_eq!(lock_reasons(&s), vec![LockReason::Sudo, LockReason::SipOff]);
        // Only the guard bits count: NVRAM (0x40) and Apple Internal (0x10)
        // alone do not lock.
        let mut s = clean();
        s.csr_config = Some(0x50);
        assert_eq!(lock_reasons(&s), vec![]);
        for bit in [0x01, 0x02, 0x04, 0x08, 0x20] {
            s.csr_config = Some(bit);
            assert_eq!(lock_reasons(&s), vec![LockReason::SipOff], "{bit:#x}");
        }
        // Names are exact: "sudoers-helper" or "SUDO" are not sudo.
        s.csr_config = Some(0);
        s.processes = names(&["sudoers-helper", "SUDO", "subversion"]);
        assert_eq!(lock_reasons(&s), vec![]);
        // Failed reads do not lock.
        let s = Sample {
            processes: None,
            csr_config: None,
            ..clean()
        };
        assert_eq!(lock_reasons(&s), vec![]);
    }

    #[test]
    fn agent_names_fit_a_process_name() {
        for a in AGENTS {
            assert!(a.len() <= 16 && a == a.to_lowercase(), "{a}");
        }
    }
}
