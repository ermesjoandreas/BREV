// BrevApplication.swift — the NSApplication subclass that drops synthetic input.
//
// Upholds CLAUDE.md §2 and §3.2 (synthetic input is rejected in the app;
// docs/PHASE2_DESIGN.md §7.1, §8.5). Info.plist names this class as
// NSPrincipalClass, and main.swift creates it. Every input event goes
// through InputFilter's PID rule twice: in `sendEvent`, and in `nextEvent`,
// where tracking loops (buttons, scrollers, menus) pull events without
// `sendEvent`. A dropped event is logged by type and source PID only.
// Accepted input stamps the idle clock that LockController reads, tells
// Rust's idle clock at most once a second (`noteActivity`), and marks the
// time spent dispatching it (`inHumanDispatch`), which HumanButton uses to
// refuse actions that do not come from a human event. Dropped events reach
// neither clock.

import AppKit
import os

extension InputFilter {
    /// Every event type that carries input: keys, modifier flags, all mouse
    /// buttons, moves and drags, scrolling, gestures, touches and tablets.
    static let inputTypes: Set<NSEvent.EventType> = [
        .keyDown, .keyUp, .flagsChanged,
        .leftMouseDown, .leftMouseUp, .leftMouseDragged,
        .rightMouseDown, .rightMouseUp, .rightMouseDragged,
        .otherMouseDown, .otherMouseUp, .otherMouseDragged, .mouseMoved,
        .scrollWheel, .magnify, .swipe, .rotate, .smartMagnify, .pressure, .quickLook,
        .beginGesture, .endGesture, .gesture, .directTouch,
        .tabletPoint, .tabletProximity, .changeMode,
    ]

    static func isInput(_ e: NSEvent) -> Bool {
        inputTypes.contains(e.type)
    }

    /// An input event that fails the PID rule. Other events are never synthetic.
    static func isSynthetic(_ e: NSEvent) -> Bool {
        isInput(e) && isSynthetic(e.cgEvent)
    }
}

@objc(BrevApplication)
final class BrevApplication: NSApplication {
    private static let log = Logger(subsystem: "no.brev.app", category: "input")

    /// True while an accepted input event is being dispatched.
    private(set) static var inHumanDispatch = false
    /// CLOCK_MONOTONIC nanoseconds of the last accepted input event.
    private(set) static var lastHumanInput = clock_gettime_nsec_np(CLOCK_MONOTONIC)
    /// Tells Rust a human is there (`Brev.noteActivity`); set by
    /// AppDelegate while it holds a session.
    static var noteActivity: (() -> Void)?
    /// CLOCK_MONOTONIC nanoseconds of the last `noteActivity` call.
    private static var lastNoted: UInt64 = 0

    override func sendEvent(_ event: NSEvent) {
        if InputFilter.isSynthetic(event) {
            Self.drop(event)
            return
        }
        let human = InputFilter.isInput(event)
        if human { Self.accepted() }
        let was = Self.inHumanDispatch
        Self.inHumanDispatch = human
        defer { Self.inHumanDispatch = was }
        super.sendEvent(event)
    }

    override func nextEvent(matching mask: NSEvent.EventTypeMask, until expiration: Date?,
                            inMode mode: RunLoop.Mode, dequeue deqFlag: Bool) -> NSEvent? {
        while true {
            guard let event = super.nextEvent(matching: mask, until: expiration, inMode: mode, dequeue: deqFlag)
            else { return nil }
            if !InputFilter.isSynthetic(event) {
                if InputFilter.isInput(event) { Self.accepted() }
                return event
            }
            Self.drop(event)
            // A peek left the event queued: take it out, or the next peek
            // returns it again.
            if !deqFlag { _ = super.nextEvent(matching: mask, until: .distantPast, inMode: mode, dequeue: true) }
        }
    }

    /// An input event passed the filter: stamp the idle clock, and Rust's
    /// at most once a second.
    private static func accepted() {
        let now = clock_gettime_nsec_np(CLOCK_MONOTONIC)
        lastHumanInput = now
        guard now &- lastNoted >= 1_000_000_000 else { return }
        lastNoted = now
        noteActivity?()
    }

    private static func drop(_ event: NSEvent) {
        let pid = InputFilter.sourcePID(event.cgEvent)
        log.notice("dropped synthetic \(event.type.rawValue, privacy: .public) pid=\(pid, privacy: .public)")
    }
}
