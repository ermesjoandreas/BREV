// L10n.swift — typed access to nb.lproj/Localizable.strings.
//
// Upholds CLAUDE.md §3.2 (UI in bokmål, strings in Localizable.strings) and
// §1.5 (docs/PHASE2_DESIGN.md §5.6): every string here is fixed interface
// text. None is ever built from content, and none takes an address, a
// name or an identity code (docs/PHASE3_DESIGN.md §6.4, §6.6); the only
// argument is a date (metadata).

import Foundation

enum L10n {
    static let onboardingWelcomeTitle = tr("onboarding.welcome.title")
    static let onboardingWelcomeBody = tr("onboarding.welcome.body")
    static let onboardingWelcomeNext = tr("onboarding.welcome.next")
    static let onboardingRulesTitle = tr("onboarding.rules.title")
    static let onboardingRulesTouchID = tr("onboarding.rules.touchid")
    static let onboardingRulesNoBackup = tr("onboarding.rules.nobackup")
    static let onboardingRulesFingers = tr("onboarding.rules.fingers")
    static let onboardingRulesPrompt = tr("onboarding.rules.prompt")
    static let onboardingRulesGone = tr("onboarding.rules.gone")
    static let onboardingRulesConfirm = tr("onboarding.rules.confirm")
    static let onboardingRulesCreate = tr("onboarding.rules.create")
    static let onboardingWorking = tr("onboarding.working")
    static let onboardingFirstTitle = tr("onboarding.first.title")
    static let onboardingFirstBody = tr("onboarding.first.body")
    static let onboardingErrorNoTouchID = tr("onboarding.error.notouchid")
    static let onboardingErrorFailed = tr("onboarding.error.failed")
    static let onboardingErrorRetry = tr("onboarding.error.retry")

    static let launchErrorUnsafe = tr("launch.error.unsafe")

    static let unlockTitle = tr("unlock.title")
    static let unlockButton = tr("unlock.button")
    static let unlockCancel = tr("unlock.cancel")
    static let unlockReason = tr("unlock.reason")
    static let unlockErrorRetry = tr("unlock.error.retry")
    static let unlockErrorLockout = tr("unlock.error.lockout")
    static let unlockErrorUnavailable = tr("unlock.error.unavailable")
    static let unlockErrorFingers = tr("unlock.error.fingers")
    static let unlockErrorDamaged = tr("unlock.error.damaged")

    static let resetButton = tr("reset.button")
    static let resetConfirmTitle = tr("reset.confirm.title")
    static let resetConfirmBody = tr("reset.confirm.body")
    static let resetConfirmOK = tr("reset.confirm.ok")
    static let resetConfirmCancel = tr("reset.confirm.cancel")

    static let addressTitle = tr("address.title")
    static let addressBody = tr("address.body")
    static let addressRegister = tr("address.register")
    static let registerReason = tr("register.reason")
    static let addressErrorTaken = tr("address.error.taken")
    static let addressErrorInvalid = tr("address.error.invalid")
    static let addressErrorFailed = tr("address.error.failed")

    static let mailNew = tr("mail.new")
    static let mailAddContact = tr("mail.addcontact")
    static let mailLock = tr("mail.lock")
    static let mailNoThreads = tr("mail.nothreads")
    /// "Sendt <date>".
    static func mailSent(_ date: String) -> String { String(format: tr("mail.sent"), date) }
    /// "Mottatt <date>".
    static func mailReceived(_ date: String) -> String { String(format: tr("mail.received"), date) }

    static let composeTo = tr("compose.to")
    static let composeSubject = tr("compose.subject")
    static let composeSend = tr("compose.send")
    static let composeCancel = tr("compose.cancel")
    static let composeError = tr("compose.error")
    static let composeSending = tr("compose.sending")
    static let composeKeyChanged = tr("compose.keychanged")
    static let composeRetry = tr("compose.retry")
    static let sendReason = tr("send.reason")
    static let netError = tr("net.error")

    static let contactTitle = tr("contact.title")
    static let contactField = tr("contact.field")
    static let contactAdd = tr("contact.add")
    static let contactCancel = tr("contact.cancel")
    static let contactErrorNotFound = tr("contact.error.notfound")
    static let contactErrorDuplicate = tr("contact.error.duplicate")
    static let contactErrorSelf = tr("contact.error.self")
    static let contactErrorFailed = tr("contact.error.failed")

    static let headerMe = tr("header.me")
    static let headerCode = tr("header.code")
    static let contactChanged = tr("contact.changed")
    static let contactNewCode = tr("contact.newcode")
    static let contactAccept = tr("contact.accept")

    static let acceptConfirmTitle = tr("accept.confirm.title")
    static let acceptConfirmBody = tr("accept.confirm.body")
    static let acceptConfirmOK = tr("accept.confirm.ok")
    static let acceptConfirmCancel = tr("accept.confirm.cancel")
    static let acceptError = tr("accept.error")

    static let menuAppTitle = tr("menu.app.title")
    static let menuAppLock = tr("menu.app.lock")
    static let menuAppQuit = tr("menu.app.quit")
    static let menuFileTitle = tr("menu.file.title")
    static let menuFileNew = tr("menu.file.new")

    static let windowMainTitle = tr("window.main.title")

    private static func tr(_ key: String) -> String {
        Bundle.main.localizedString(forKey: key, value: nil, table: nil)
    }
}
