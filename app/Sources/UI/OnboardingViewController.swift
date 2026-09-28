// OnboardingViewController.swift — the pages before Brev has keys.
//
// Upholds CLAUDE.md §1.8 and §1.9 (setup explains that there is no password
// and no backup, that a fingerprint change loses the letters, and when to
// accept a Touch ID prompt) and §2 (not to write new letters if the history
// is suddenly gone) (docs/PHASE2_DESIGN.md §5.3; D-0033 item 2). Pages:
// Velkommen → Dette må du vite (four rules, the warning, a checkbox that
// enables Opprett nøkler) → Oppretter nøkler … → on failure, Prøv igjen.
// Without Touch ID the second page says so and stops. The first unlock is
// UnlockViewController's first-unlock mode. Every button is a HumanButton;
// AppDelegate does the work behind `onCreate`.

import AppKit

final class OnboardingViewController: NSViewController {
    /// A human pressed Opprett nøkler or Prøv igjen.
    var onCreate: () -> Void = {}

    private let page = PageView()
    private var understood: HumanButton?
    private var create: HumanButton?

    init() {
        super.init(nibName: nil, bundle: nil)
        showWelcome()
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func loadView() {
        view = page
    }

    /// Page 1.
    func showWelcome() {
        let next = PageView.button(L10n.onboardingWelcomeNext, target: self, action: #selector(welcomeDone(_:)))
        next.keyEquivalent = "\r"
        page.show([
            InterfaceText(L10n.onboardingWelcomeTitle, style: .title, width: PageView.columnWidth),
            InterfaceText(L10n.onboardingWelcomeBody, width: PageView.columnWidth),
            next,
        ])
    }

    /// Page 2, or the Touch ID notice instead of it.
    private func showRules() {
        guard Enclave.touchIDAvailable() else {
            page.show([InterfaceText(L10n.onboardingErrorNoTouchID, width: PageView.columnWidth)])
            return
        }
        let understood = HumanButton(checkboxWithTitle: L10n.onboardingRulesConfirm, target: self,
                                     action: #selector(understoodChanged(_:)))
        let create = PageView.button(L10n.onboardingRulesCreate, target: self, action: #selector(createPressed(_:)))
        create.keyEquivalent = "\r"
        create.isEnabled = false
        self.understood = understood
        self.create = create
        let rules = [L10n.onboardingRulesTouchID, L10n.onboardingRulesNoBackup, L10n.onboardingRulesFingers,
                     L10n.onboardingRulesPrompt, L10n.onboardingRulesGone]
        page.show([InterfaceText(L10n.onboardingRulesTitle, style: .title, width: PageView.columnWidth)]
                  + rules.map { InterfaceText($0, width: PageView.columnWidth, alignment: .natural) }
                  + [understood, create])
    }

    /// Keys are being made; no button.
    func showWorking() {
        page.show([InterfaceText(L10n.onboardingWorking, width: PageView.columnWidth)])
    }

    /// Making the keys failed: Prøv igjen starts over from the cleanup.
    func showFailed() {
        let retry = PageView.button(L10n.onboardingErrorRetry, target: self, action: #selector(retryPressed(_:)))
        retry.keyEquivalent = "\r"
        page.show([InterfaceText(L10n.onboardingErrorFailed, width: PageView.columnWidth), retry])
    }

    // MARK: - Actions (HumanButton: human input only)

    @objc private func welcomeDone(_ sender: Any?) {
        showRules()
    }

    @objc private func understoodChanged(_ sender: Any?) {
        create?.isEnabled = understood?.state == .on
    }

    @objc private func createPressed(_ sender: Any?) {
        guard understood?.state == .on else { return }
        onCreate()
    }

    @objc private func retryPressed(_ sender: Any?) {
        onCreate()
    }
}
