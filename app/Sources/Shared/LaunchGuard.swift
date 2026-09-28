// LaunchGuard.swift — launch hygiene, the first thing main.swift runs.
//
// Upholds CLAUDE.md §1.1 and §1.10 and §2's MallocScribble residual risk
// (docs/PHASE2_DESIGN.md §8.6). AppKit, Foundation and HIToolbox have
// debugging switches that log events or keep freed objects alive
// (NSTraceEvents, NSZombieEnabled, TSMEventTracing, ...), set by arguments,
// defaults or environment variables. Brev refuses arguments (Release and
// Verify), empties the argument domain, and treats a debugging variable or
// default, or a missing MallocScribble=1, as an unsafe launch: it
// re-executes itself once with a cleaned environment, and if the launch is
// still unsafe, nothing is ever decrypted in the process (AppDelegate shows
// only launch.error.unsafe).
// No AppKit: compiled into the app and the CLI harness, which tests every
// function here except `run`.

import Foundation
import os

enum LaunchGuard {
    /// Environment variables with these prefixes make a launch unsafe.
    static let unsafePrefixes = ["NSZombie", "CFZombie", "NSDebug", "NSTrace", "NSDeallocateZombies",
                                 "NSObjCMessageLogging", "OBJC_", "MallocStackLogging", "CFLOG",
                                 "OS_ACTIVITY_DT_MODE"]
    /// Defaults that make a launch unsafe when true (global domain included).
    /// TSMEventTracing is HIToolbox's key-event trace: it traces every key
    /// event on stderr without get-task-allow, so also in Release (launch
    /// spike, docs/DECISIONS.md D-0064). The TSMTrace keys are its siblings
    /// from the spike's scan of HIToolbox.
    static let unsafeDefaultKeys = ["NSTraceEvents", "NSZombieEnabled", "NSDebugEnabled", "NSDeallocateZombies",
                                    "TSMEventTracing", "TSMTraceAssistiveTouch", "TSMTraceCapsLockPressAndHold",
                                    "TSMTraceCharacterPalette", "TSMTraceCursorUI", "TSMTraceDocumentProperties",
                                    "TSMTraceEventInfo", "TSMTraceFloatingIndicator", "TSMTraceForAsyncClient",
                                    "TSMTraceInputSourceNotifications", "TSMTraceInputSourceSelection",
                                    "TSMTraceIronwood", "TSMTracePressAndHold", "TSMTraceTrackpadIM"]
    /// Set in the cleaned environment, so Brev re-executes itself only once.
    static let reexecMarker = "BREV_LAUNCH_CLEANED"

    /// Set by `run()`. False means nothing may be decrypted in this process.
    private(set) static var isSafe = false

    enum Verdict: Equatable {
        case safe
        /// The environment is the only problem, and Brev has not re-executed yet.
        case reexec
        case unsafe
    }

    /// Only `argv[0]`.
    static func argumentsAllowed(_ argv: [String]) -> Bool {
        argv.count <= 1
    }

    /// Replaces the argument domain with an empty one, so `-Key value`
    /// arguments reach no default. On macOS 26.2 `removeVolatileDomain`
    /// alone leaves the argument domain in place (the harness checks the
    /// effect); setting an empty domain clears it for UserDefaults and
    /// CFPreferences.
    static func clearArgumentDomain() {
        let defaults = UserDefaults.standard
        defaults.removeVolatileDomain(forName: UserDefaults.argumentDomain)
        defaults.setVolatileDomain([:], forName: UserDefaults.argumentDomain)
    }

    /// Names of the unsafe variables in `env` (names only; logs never get values).
    static func unsafeVariables(_ env: [String: String]) -> [String] {
        env.keys.filter { key in unsafePrefixes.contains { key.hasPrefix($0) } }.sorted()
    }

    /// The unsafe defaults that are true in `defaults`.
    static func unsafeDefaults(_ defaults: UserDefaults) -> [String] {
        unsafeDefaultKeys.filter { defaults.bool(forKey: $0) }
    }

    static func verdict(environment env: [String: String], defaults: UserDefaults) -> Verdict {
        // A re-executed process reads the same defaults, so re-executing
        // cannot fix them.
        if !unsafeDefaults(defaults).isEmpty { return .unsafe }
        if unsafeVariables(env).isEmpty && env["MallocScribble"] == "1" { return .safe }
        return env[reexecMarker] == nil ? .reexec : .unsafe
    }

    /// `env` without the unsafe variables, plus MallocScribble=1 and the marker.
    static func cleanedEnvironment(_ env: [String: String]) -> [String: String] {
        var out = env.filter { key, _ in !unsafePrefixes.contains { key.hasPrefix($0) } }
        out["MallocScribble"] = "1"
        out[reexecMarker] = "1"
        return out
    }

    /// Runs the checks for this process. Exits on arguments (not in Debug,
    /// where Xcode passes its own), re-executes on an unsafe environment,
    /// and otherwise sets `isSafe`.
    static func run() {
        let log = Logger(subsystem: "no.brev.app", category: "launch")
        #if !DEBUG
        if !argumentsAllowed(CommandLine.arguments) {
            log.error("launch refused: arguments")
            exit(64)
        }
        #endif
        clearArgumentDomain()
        let env = ProcessInfo.processInfo.environment
        switch verdict(environment: env, defaults: .standard) {
        case .safe:
            isSafe = true
        case .reexec:
            log.notice("launch unsafe: environment; re-executing")
            let code = reexec(cleanedEnvironment(env))
            log.error("launch unsafe: re-exec failed errno=\(code, privacy: .public)")
        case .unsafe:
            log.error("launch unsafe")
        }
    }

    /// Replaces this process with a fresh copy of Brev's executable and the
    /// same arguments. Returns only if execve failed, with its errno.
    private static func reexec(_ env: [String: String]) -> Int32 {
        guard let path = Bundle.main.executablePath else { return ENOENT }
        let argv = [strdup(path)] + CommandLine.arguments.dropFirst().map { strdup($0) } + [nil]
        let envp = env.map { strdup("\($0.key)=\($0.value)") } + [nil]
        execve(path, argv, envp)
        let code = errno
        (argv + envp).forEach { free($0) }
        return code
    }
}
