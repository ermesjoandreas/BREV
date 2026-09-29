// L10n.swift — typed access to nb.lproj/Localizable.strings.
//
// Upholds CLAUDE.md §3.2 (UI in bokmål, strings in Localizable.strings) and
// §1.5 (docs/PHASE2_DESIGN.md §5.6): every string here is fixed interface
// text. None is ever built from content, and none takes an address, a
// name or an identity code (docs/PHASE3_DESIGN.md §6.4, §6.6); the only
// arguments are a date (metadata), Hand's fixed names of checks and facts
// (from Rust, each shown as its text from this file), a class letter and
// the counts of a letter's proof (docs/AUTHORSHIP.md §6).

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

    /// The lock screen after a sample locked Brev (docs/AUTHORSHIP.md §4.3):
    /// one line per cause.
    static func lockedBecause(_ causes: [LockCause]) -> String {
        causes.map { $0 == .sudo ? tr("lock.sudo") : tr("lock.sip") }.joined(separator: "\n")
    }

    /// The lock screen after Rust refused to confirm an unlock whose sample
    /// shows `sudo` or SIP off: one line per fact ("sudo", "sip").
    static func unlockRefused(_ facts: [String]) -> String {
        let lines = facts.compactMap { ["sudo": tr("unlock.refused.sudo"), "sip": tr("unlock.refused.sip")][$0] }
        return lines.isEmpty ? unlockErrorRetry : lines.joined(separator: "\n")
    }

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
    static let addressInviteTitle = tr("address.invite.title")
    static let addressInviteBody = tr("address.invite.body")
    static let addressInviteNext = tr("address.invite.next")

    static let mailboxInbox = tr("mailbox.inbox")
    static let mailboxSent = tr("mailbox.sent")
    static let sidebarAdd = tr("sidebar.add")
    static let toolbarNew = tr("toolbar.new")
    static let toolbarLock = tr("toolbar.lock")
    static let listEmptyInbox = tr("list.empty.inbox")
    static let listEmptySent = tr("list.empty.sent")
    static let listEmptyContact = tr("list.empty.contact")
    static let listReceived = tr("list.received")
    static let listSent = tr("list.sent")
    /// «Klasse <A, B or C>»: a received letter's chip in the list.
    static func chipClass(_ letter: String) -> String { String(format: tr("chip.class"), letter) }
    static let readingNone = tr("reading.none")
    static let readingFrom = tr("reading.from")
    static let readingTo = tr("reading.to")
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
    static let composeNotApproved = tr("compose.notapproved")
    static let composeRateLimited = tr("compose.ratelimited")
    static let composeRetry = tr("compose.retry")
    /// "Kan ikke sende: <the fact> (<its name>)." for each fact Rust names
    /// in BrevError.Environment (docs/AUTHORSHIP.md §3.3), one line each.
    /// No fact named means no compose session was measuring.
    static func composeEnvironment(_ facts: [String]) -> String {
        guard !facts.isEmpty else { return tr("compose.environment.none") }
        return facts.map { String(format: tr("compose.environment"), fact($0), $0) }.joined(separator: "\n")
    }
    static let sendReason = tr("send.reason")
    static let netError = tr("net.error")

    static let contactsTitle = tr("contacts.title")
    static let contactsSectionMe = tr("contacts.section.me")
    static let contactsSectionInvite = tr("contacts.section.invite")
    static let contactsSectionAdd = tr("contacts.section.add")
    static let contactsAddress = tr("contacts.address")
    static let contactsCode = tr("contacts.code")
    static let contactsCopyMe = tr("contacts.copyme")
    static let contactsField = tr("contacts.field")
    static let contactsAdd = tr("contacts.add")
    static let contactsClose = tr("contacts.close")
    static let inviteMake = tr("invite.make")
    static let inviteCopy = tr("invite.copy")
    static let inviteNote = tr("invite.note")
    static let inviteFrom = tr("invite.from")
    static let inviteAccept = tr("invite.accept")
    static let inviteRoot = tr("invite.root")
    static let inviteErrorInvalid = tr("invite.error.invalid")
    static let inviteErrorMismatch = tr("invite.error.mismatch")
    static let inviteErrorLimit = tr("invite.error.limit")
    static let inviteErrorFailed = tr("invite.error.failed")
    static let requestSent = tr("request.sent")
    static let requestErrorLimit = tr("request.error.limit")
    static let contactErrorNotFound = tr("contact.error.notfound")
    static let contactErrorDuplicate = tr("contact.error.duplicate")
    static let contactErrorSelf = tr("contact.error.self")
    static let contactErrorFailed = tr("contact.error.failed")

    static let requestsTitle = tr("requests.title")
    static let requestBody = tr("request.body")
    static let requestAccept = tr("request.accept")
    static let requestDecline = tr("request.decline")

    static let contactWaiting = tr("contact.waiting")
    static let contactVerified = tr("contact.verified")
    static let contactBlocked = tr("contact.blocked")
    static let contactBlock = tr("contact.block")
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
    #if BREV_PASTE_MENU
    static let menuEditTitle = tr("menu.edit.title")
    static let menuEditPaste = tr("menu.edit.paste")
    #endif

    static let windowMainTitle = tr("window.main.title")
    #if BREV_DEV
    /// «UTVIKLER»: a dev build's label in the title bar (DevBuild).
    static let devLabel = tr("dev.label")
    #endif

    // MARK: - A letter's proof (docs/AUTHORSHIP.md §6)

    /// «Skrevet i Brev · klasse A» (B, C) for a verified letter, «Ikke
    /// verifisert» otherwise.
    static func badge(verified: Bool, classCode: UInt8?) -> String {
        guard verified, let code = classCode, (1...3).contains(code) else { return tr("badge.unverified") }
        return String(format: tr("badge.verified"), ["A", "B", "C"][Int(code) - 1])
    }

    /// The text of a failed check (`"token"`, `"signature"`, `"content"`,
    /// `"iat"`, `"app-attest"`), or nil for a name that is not a check.
    static func proofCheck(_ name: String) -> String? {
        ["token", "signature", "content", "iat", "app-attest"].contains(name) ? tr("proof.check.\(name)") : nil
    }

    /// «Klassen stemmer ikke med målingene: <facts>».
    static func proofClass(_ facts: [String]) -> String {
        String(format: tr("proof.check.class"), facts.map(fact).joined(separator: ", "))
    }

    static func proofKey(_ value: String) -> String { String(format: tr("proof.key"), value) }
    static func proofWindows(_ value: String) -> String { String(format: tr("proof.windows"), value) }
    static func proofAgents(_ value: String) -> String { String(format: tr("proof.agents"), value) }
    static func proofAdmin(_ value: String) -> String { String(format: tr("proof.admin"), value) }
    static func proofBlocked(_ value: String) -> String { String(format: tr("proof.blocked"), value) }
    static func proofSeconds(_ value: String) -> String { String(format: tr("proof.seconds"), value) }
    static func proofSIP(_ value: String) -> String { String(format: tr("proof.sip"), value) }
    static func proofSudo(_ value: String) -> String { String(format: tr("proof.sudo"), value) }
    /// "<n> min".
    static func proofMinutes(_ n: UInt32) -> String { String(format: tr("proof.minutes"), "\(n)") }
    static let proofUnderAMinute = tr("proof.minutes.under")
    static let proofYes = tr("proof.yes")
    static let proofNo = tr("proof.no")
    static let proofOn = tr("proof.on")
    static let proofOff = tr("proof.off")
    static let proofUnknown = tr("proof.unknown")
    static let proofAttest = tr("proof.attest")
    static let proofClose = tr("proof.close")

    /// A fact of the token (Rust's fixed name, such as "max-gap") in words;
    /// a name this file does not know is shown as it is.
    private static func fact(_ name: String) -> String {
        let key = "fact.\(name)"
        let text = tr(key)
        return text == key ? name : text
    }

    private static func tr(_ key: String) -> String {
        Bundle.main.localizedString(forKey: key, value: nil, table: nil)
    }
}
