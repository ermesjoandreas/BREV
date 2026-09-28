// UnlockViewController.swift — the lock screen, and onboarding's first unlock.
//
// Upholds CLAUDE.md §1.8 (Touch ID only) and §3.2 (docs/PHASE2_DESIGN.md
// §5.3 steps 7 and 8, §5.4, §5.5). Brev never prompts on its own: only a
// human click on Lås opp med Touch ID, or Return, calls `onUnlock`
// (HumanButton). While the prompt is up the button is disabled. A failure
// shows its text (UnlockFailure); a cancel shows the screen as before.
// "Slett alt og start på nytt" appears after damaged or changed-fingers
// failures, after any failure of the first unlock, and when the stores do
// not open; it only opens ConfirmSheet (AppDelegate). The unlock button
// stays next to it, so a wrong guess about the fingers never forces a reset.

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
    private let page = PageView()
    private var unlock: HumanButton?

    init(mode: Mode) {
        self.mode = mode
        super.init(nibName: nil, bundle: nil)
        showReady()
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func loadView() {
        view = page
    }

    /// The screen with its unlock button and no error.
    func showReady() {
        layout(message: nil, reset: false)
    }

    /// The Touch ID prompt is up: the button is disabled until it ends.
    func showWorking() {
        unlock?.isEnabled = false
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
                   InterfaceText(L10n.unlockErrorDamaged, width: PageView.columnWidth),
                   resetButton()])
    }

    private func layout(message: String?, reset: Bool) {
        var views: [NSView]
        switch mode {
        case .lockScreen:
            views = [InterfaceText(L10n.unlockTitle, style: .title, width: PageView.columnWidth)]
        case .firstUnlock:
            views = [InterfaceText(L10n.onboardingFirstTitle, style: .title, width: PageView.columnWidth),
                     InterfaceText(L10n.onboardingFirstBody, width: PageView.columnWidth)]
        }
        if let message { views.append(InterfaceText(message, width: PageView.columnWidth)) }
        let unlock = PageView.button(L10n.unlockButton, target: self, action: #selector(unlockPressed(_:)))
        unlock.keyEquivalent = "\r"
        self.unlock = unlock
        views.append(unlock)
        if reset { views.append(resetButton()) }
        page.show(views)
    }

    private func resetButton() -> HumanButton {
        let reset = PageView.button(L10n.resetButton, target: self, action: #selector(resetPressed(_:)))
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
