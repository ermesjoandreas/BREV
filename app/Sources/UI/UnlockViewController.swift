// UnlockViewController.swift — the lock screen, and onboarding's first unlock.
//
// Upholds CLAUDE.md §1.8 (Touch ID only) and §3.2 (docs/PHASE2_DESIGN.md
// §5.3 steps 7 and 8, §5.4, §5.5). Brev never prompts on its own: only a
// human click on Lås opp med Touch ID, or Return, calls `onUnlock`
// (HumanButton). While the prompt is up every button is disabled. A failure
// shows its text (UnlockFailure); a cancel shows the screen as before.
// "Slett alt og start på nytt" appears after damaged or changed-fingers
// failures, after any failure of the first unlock, and when the stores do
// not open; it only opens ConfirmSheet (AppDelegate). The unlock button
// stays next to it, so a wrong guess about the fingers never forces a reset.
// After a lock that a sample of the Mac caused (a running sudo, SIP off;
// docs/AUTHORSHIP.md §4.3), the screen says why under its title, until a
// failure replaces the line.

import AppKit

final class UnlockViewController: NSViewController {
    enum Mode {
        /// Brev er låst.
        case lockScreen
        /// Lås opp for første gang: the end of onboarding (§5.3 step 7).
        case firstUnlock
    }

    /// A human pressed Lås opp med Touch ID (or Return).
    var onUnlock: () -> Void = {}
    /// A human pressed Slett alt og start på nytt.
    var onReset: () -> Void = {}

    private let mode: Mode
    /// Why Brev locked, when a sample caused it (LockController.lockNotice).
    private let notice: String?
    private let page = PageView()
    private var unlock: HumanButton?

    init(mode: Mode, notice: String? = nil) {
        self.mode = mode
        self.notice = notice
        super.init(nibName: nil, bundle: nil)
        showReady()
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func loadView() {
        view = page
    }

    /// The screen with its unlock button, no error, and the lock's notice.
    func showReady() {
        layout(message: notice, reset: false)
    }

    /// The Touch ID prompt is up: every button is disabled until it ends,
    /// the reset too, so no reset can run under an unlock still in flight.
    func showWorking() {
        page.disableButtons()
    }

    func show(_ failure: UnlockFailure) {
        let message: String
        switch failure {
        case .cancelled: return showReady()
        case .lockout: message = L10n.unlockErrorLockout
        case .unavailable: message = L10n.unlockErrorUnavailable
        case .damaged: message = L10n.unlockErrorDamaged
        case .fingers: message = L10n.unlockErrorFingers
        case .retry: message = L10n.unlockErrorRetry
        }
        layout(message: message, reset: failure.offersReset || mode == .firstUnlock)
    }

    /// The stores did not open (§5.2 step 1): no unlock, only the reset.
    func showDamagedStores() {
        unlock = nil
        page.show([InterfaceText(L10n.unlockTitle, style: .title, width: PageView.columnWidth),
                   InterfaceText(L10n.unlockErrorDamaged, style: .secondary, width: PageView.columnWidth),
                   resetButton()], symbol: "exclamationmark.triangle")
    }

    private func layout(message: String?, reset: Bool) {
        var views: [NSView]
        switch mode {
        case .lockScreen:
            views = [InterfaceText(L10n.unlockTitle, style: .title, width: PageView.columnWidth)]
        case .firstUnlock:
            views = [InterfaceText(L10n.onboardingFirstTitle, style: .title, width: PageView.columnWidth),
                     InterfaceText(L10n.onboardingFirstBody, style: .secondary, width: PageView.columnWidth)]
        }
        if let message { views.append(InterfaceText(message, style: .secondary, width: PageView.columnWidth)) }
        let unlock = PageView.button(L10n.unlockButton, target: self, action: #selector(unlockPressed(_:)),
                                     symbol: "touchid")
        unlock.keyEquivalent = "\r"
        self.unlock = unlock
        views.append(unlock)
        if reset { views.append(resetButton()) }
        page.show(views, symbol: mode == .lockScreen ? "lock" : "touchid")
    }

    /// Small and quiet under the unlock button, so the reset is never the
    /// loud option.
    private func resetButton() -> HumanButton {
        let reset = PageView.secondary(L10n.resetButton, target: self, action: #selector(resetPressed(_:)))
        reset.hasDestructiveAction = true
        return reset
    }

    // MARK: - Actions (HumanButton: human input only)

    @objc private func unlockPressed(_ sender: Any?) {
        guard unlock?.isEnabled == true else { return }
        onUnlock()
    }

    @objc private func resetPressed(_ sender: Any?) {
        onReset()
    }
}
