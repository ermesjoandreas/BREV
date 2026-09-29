// MailViewController.swift — the unlocked screen: a sidebar, a message list
// and a reading pane, as in a Mac mail app.
//
// Upholds CLAUDE.md §1.2, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §7.2, §9;
// docs/PHASE3_DESIGN.md §5.3, §6.3, §6.5; docs/PHASE4_DESIGN.md §6.1;
// docs/UI_REDESIGN.md §2). An NSSplitViewController with three panes that
// cannot be collapsed and whose sizes are not saved: the sidebar
// (SidebarView: Innboks and Sendt, the contact requests by the asker's
// address, the contacts by address, and «Legg til kontakt»), the message
// list (a SecureListView of the selected mailbox's or contact's threads,
// newest first, under the ContactBar while a contact or request is
// selected) and the reading pane (the ReadingHeaderView and the letter's
// body, LetterStackView). The window's toolbar (MailToolbar) has Nytt brev
// and Lås; the window's title names the selected mailbox (else «Brev»),
// never a contact. One selection across the sidebar. Brev starts on the
// first contact (with none, on Innboks, which then reads nothing) and never
// opens a letter by itself: a body is read only when a human selects its
// row. Innboks and Sendt are read only when a human selects them, and a
// reload keeps a mailbox only if a human chose it (`mailboxChosen`; a
// contact that arrives by sync is selected instead) (DECISIONS.md,
// UI redesign, Q1): reading one asks Rust for every contact's threads, which
// decrypts every subject once per contact, and the list keeps each subject
// and a copy of each name while it is open. No body is read to draw a list.
// A mailbox row shows the other party's name and the subject; a contact's
// row shows the subject and «Mottatt»/«Sendt»; a received letter's row
// carries its class (`letterProof`, which decrypts nothing). The reading
// header shows the subject, «Fra:»/«Til:» and the name, the date and, for a
// received letter, the badge (docs/AUTHORSHIP.md §6), whose press opens
// ProofSheet (one sheet at a time; a proof that cannot be read shows as
// «Ikke verifisert» with «Beviset kan ikke leses»). With a mailbox selected
// and a letter whose contact has a changed key or is blocked, the ContactBar
// shows above the reading header, so the warning is never hidden. Nytt brev
// writes to the selected contact, or with a mailbox to the selected letter's
// contact; it is off for a contact whose key changed or that is blocked,
// and while a request is selected. «Legg til kontakt» opens ContactSheet; a
// contact it adds is selected when it closes. Godta ny kode opens
// ConfirmSheet, and only its Godta accepts the code the bar shows
// (acceptNewKey). Godta and Avslå answer the selected request with one click
// (`answerRequest` on `Session.net`): Godta selects the new contact, Avslå
// drops the request; Blokker blocks the bar's contact with one click
// (`blockContact` on `Session.net`). No Touch ID and no confirmation for
// either (PHASE4 §6.1, owner answers 6 and 7); a result from before
// `wipeAll()` is dropped. `sync()` handles the relay's events and fetches
// the letters waiting there: once at `start()`, every 5 seconds from a timer
// in the common run-loop modes (docs/DECISIONS.md D-0050), and once after a
// letter is sent. It runs on `Session.net`, never on main; a sync still
// running makes the next tick skip, and its result returns to main, where a
// result from before `wipeAll()` is dropped. When a contact changed or the
// number of requests changed, the requests and the contacts are read again,
// keeping the selection; when only letters arrived, the list is read again
// (its old texts wiped). Every reload keeps the selected letter by thread
// id; if that thread is gone, the reading pane is cleared and no other row
// is selected. Every text read here is a SecretText owned by a list, the
// bar, the reading header or a letter view, and every request's code a
// SecretBytes kept here until the requests are read again; a new selection
// wipes what it replaces, and `wipeAll()` (lock sequence §8.4 step 3) wipes
// everything and stops the timer. The controller holds the Session weakly,
// never an OpenText. Logs carry counts and error names only (§6.3 rule 7);
// a sync failure is logged once per change, not at every tick.

import AppKit
import os

/// What the sidebar has selected: a mailbox, a contact or a request.
enum SidebarSelection: Equatable {
    case inbox
    case sent
    case contact(Data)
    case request(Data)

    var isMailbox: Bool { self == .inbox || self == .sent }
}

/// A view controller that only holds a view (a split view item's).
private final class Pane: NSViewController {
    private let pane: NSView

    init(_ pane: NSView) {
        self.pane = pane
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func loadView() {
        view = pane
    }
}

/// A list's empty state: a large SF Symbol, one line, and at most one
/// button. Chrome.
private final class EmptyStateView: NSStackView {
    func show(symbol: String, text: String, button: HumanButton? = nil) {
        arrangedSubviews.forEach { $0.removeFromSuperview() }
        let image = NSImageView()
        let config = NSImage.SymbolConfiguration(pointSize: 40, weight: .light)
        image.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)?.withSymbolConfiguration(config)
        image.contentTintColor = .tertiaryLabelColor
        addArrangedSubview(image)
        addArrangedSubview(InterfaceText(text, style: .empty, width: 260))
        if let button {
            setCustomSpacing(16, after: arrangedSubviews[1])
            addArrangedSubview(button)
        }
        orientation = .vertical
        alignment = .centerX
        spacing = 8
        isHidden = false
    }
}

final class MailViewController: NSViewController, ContentHolder, MailActions, NSMenuItemValidation,
    NSToolbarItemValidation {
    private static let log = Logger(subsystem: "no.brev.app", category: "mail")
    /// Seconds between two `sync()` calls (PHASE3 §5.3).
    static let syncInterval: TimeInterval = 5
    /// The narrowest the sidebar, the list and the reading pane get, by
    /// divider or window. A letter laid out much narrower puts a few units
    /// on each line, and every line costs a CTLine (TextLayout), again at
    /// every width change: seconds per resize step for a long letter.
    static let minPaneWidths: [CGFloat] = [180, 300, 380]

    /// A human pressed Lås.
    var onLock: () -> Void = {}
    /// A human asked for a new letter to a contact (Nytt brev, ⌘N):
    /// AppDelegate shows the compose sheet. While nil, Nytt brev is
    /// disabled; while a sheet is up, it does nothing.
    var onNewLetter: ((ContactItem) -> Void)? {
        didSet { updateButtons() }
    }

    /// One row of the message list: a thread, as shown.
    private struct Listed {
        let id: Data
        let contact: Data
        let createdAt: Int64
        /// Owned (and wiped) by the message list.
        let subject: SecretText
        let outgoing: Bool
    }

    private weak var session: Session?
    private(set) var selection: SidebarSelection?
    /// True only while Innboks or Sendt is selected because a human chose
    /// it: only then is a mailbox read (DECISIONS.md, UI redesign, Q1). A
    /// mailbox Brev falls back to by itself (a new user, a declined request)
    /// reads nothing, and a reload moves off it to the first contact.
    private(set) var mailboxChosen = false
    private var contacts: [ContactItem] = []
    /// The contact requests, oldest first, as the requests list shows them;
    /// their codes are wiped when the requests are read again or wiped.
    private var requests: [RequestItem] = []
    /// The message list's threads, as it shows them.
    private var listed: [Listed] = []
    /// The proofs of the letters shown, in their order: nil for a sent
    /// letter. Content-free.
    private(set) var proofs: [Proof?] = []
    private var syncTimer: Timer?
    /// True while a `sync()` is on `Session.net`.
    private var syncing = false
    /// Bumped by `stopSync()`: a sync result from before it is dropped.
    private var syncGeneration = 0
    /// The last sync's outcome ("ok" or an error name), logged on change.
    private var syncOutcome = "ok"

    private(set) lazy var sidebar = SidebarView(target: self, add: #selector(showContacts(_:)))
    var requestList: SecureListView { sidebar.requestList }
    var contactList: SecureListView { sidebar.contactList }
    var mailboxes: MailboxListView { sidebar.mailboxes }
    let messageList = SecureListView(style: .messages)
    let letters = LetterStackView()
    let readingHeader = ReadingHeaderView()
    let header = ContactBar()
    private let listScroll = NSScrollView()
    private let letterScroll = NSScrollView()
    private let listStack = NSStackView()
    private let readingStack = NSStackView()
    private let emptyList = EmptyStateView()
    private let noLetter = InterfaceText(L10n.readingNone, style: .placeholder, width: 260)
    let split: NSSplitViewController = {
        let split = NSSplitViewController()
        let view = MailSplitView()
        view.isVertical = true
        view.dividerStyle = .thin
        split.splitView = view
        return split
    }()
    private(set) lazy var mailToolbar = MailToolbar(target: self, new: #selector(newLetter(_:)),
                                                    lock: #selector(lockPressed(_:)), split: split.splitView)
    /// The toolbar the window shows with this screen.
    var toolbar: NSToolbar { mailToolbar.toolbar }
    /// The contact whose new code was not accepted (accept.error shows).
    private var acceptFailed: Data?
    /// The contact whose block the relay was not told of (net.error shows,
    /// Blokker stays).
    private var blockFailed: Data?
    /// The request whose answer did not reach the relay (net.error shows).
    private var answerFailed: Data?
    /// True while an answer or a block is on `Session.net`.
    private var answering = false, blocking = false
    private var dividersPlaced = false

    private let dates: DateFormatter = MailViewController.formatter(date: .medium, time: .short)
    private let times: DateFormatter = MailViewController.formatter(template: "HH:mm")
    private let weekdays: DateFormatter = MailViewController.formatter(template: "EEEE")
    private let days: DateFormatter = MailViewController.formatter(template: "dd.MM.yyyy")

    private static func formatter(date: DateFormatter.Style = .none, time: DateFormatter.Style = .none,
                                  template: String? = nil) -> DateFormatter {
        let f = DateFormatter()
        f.locale = Locale(identifier: "nb_NO")
        if let template { f.setLocalizedDateFormatFromTemplate(template) } else {
            f.dateStyle = date
            f.timeStyle = time
        }
        return f
    }

    init(session: Session) {
        self.session = session
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        nil
    }

    deinit {
        syncTimer?.invalidate()
    }

    // MARK: - Views

    override func loadView() {
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 1080, height: 680))
        header.onAccept = { [weak self] in self?.acceptNewKey() }
        header.onBlock = { [weak self] in self?.blockSelected() }
        header.onAnswer = { [weak self] approve in self?.answerSelected(approve: approve) }
        readingHeader.onBadge = { [weak self] in self?.showProof(0) }

        // A plain item, not `sidebarWithViewController:`: on macOS 26 that
        // is a floating glass material that blurs what lies behind it, which
        // no capture probe has covered, and which cacheDisplay cannot draw.
        let sidebarItem = NSSplitViewItem(viewController: Pane(sidebar))
        let listItem = NSSplitViewItem(contentListWithViewController: Pane(listPane()))
        let readingItem = NSSplitViewItem(viewController: Pane(readingPane()))
        for (i, item) in [sidebarItem, listItem, readingItem].enumerated() {
            item.minimumThickness = Self.minPaneWidths[i]
            item.canCollapse = false
            if #available(macOS 14.0, *) { item.canCollapseFromWindowResize = false }
            // A change in width goes to the reading pane first, then the
            // list, then the sidebar.
            item.holdingPriority = NSLayoutConstraint.Priority(260 - Float(i) * 5)
            split.addSplitViewItem(item)
        }
        sidebarItem.maximumThickness = 280
        addChild(split)
        split.view.frame = root.bounds
        split.view.autoresizingMask = [.width, .height]
        root.addSubview(split.view)

        mailboxes.onSelect = { [weak self] i in self?.mailboxSelected(i) }
        requestList.onSelect = { [weak self] _ in self?.requestSelected() }
        contactList.onSelect = { [weak self] _ in self?.contactSelected() }
        messageList.onSelect = { [weak self] _ in self?.showLetter(scrolledTo: .zero) }
        letters.onBadge = { [weak self] i in self?.showProof(i) }
        contactList.nextKeyView = messageList
        messageList.nextKeyView = mailboxes
        view = root
        updateButtons()
    }

    /// The ContactBar's place over the list, and the list with its empty
    /// state over it.
    private func listPane() -> NSView {
        let pane = NSView(frame: NSRect(x: 0, y: 0, width: 340, height: 600))
        Self.configure(listScroll, messageList)
        listStack.orientation = .vertical
        listStack.alignment = .leading
        listStack.spacing = 0
        listStack.detachesHiddenViews = true
        listStack.addArrangedSubview(listScroll)
        Self.fill(pane, with: listStack)
        listScroll.widthAnchor.constraint(equalTo: listStack.widthAnchor).isActive = true
        listScroll.setContentHuggingPriority(.defaultLow, for: .vertical)
        emptyList.translatesAutoresizingMaskIntoConstraints = false
        pane.addSubview(emptyList)
        NSLayoutConstraint.activate([
            emptyList.centerXAnchor.constraint(equalTo: listScroll.centerXAnchor),
            // Centred on the pane below the toolbar, as «Ingen brev valgt» is.
            emptyList.centerYAnchor.constraint(equalTo: listScroll.centerYAnchor),
        ])
        emptyList.isHidden = true
        return pane
    }

    /// The ContactBar's place in a mailbox, the reading header, and the
    /// letter, with «Ingen brev valgt» over it while none is open.
    private func readingPane() -> NSView {
        let pane = BackgroundView()
        pane.frame = NSRect(x: 0, y: 0, width: 420, height: 600)
        Self.configure(letterScroll, letters)
        readingStack.orientation = .vertical
        readingStack.alignment = .leading
        readingStack.spacing = 0
        readingStack.detachesHiddenViews = true
        readingStack.addArrangedSubview(readingHeader)
        readingStack.addArrangedSubview(letterScroll)
        Self.fill(pane, with: readingStack)
        for v in [readingHeader, letterScroll] { v.widthAnchor.constraint(equalTo: readingStack.widthAnchor).isActive = true }
        letterScroll.setContentHuggingPriority(.defaultLow, for: .vertical)
        noLetter.translatesAutoresizingMaskIntoConstraints = false
        pane.addSubview(noLetter)
        NSLayoutConstraint.activate([
            noLetter.centerXAnchor.constraint(equalTo: pane.centerXAnchor),
            noLetter.centerYAnchor.constraint(equalTo: pane.centerYAnchor),
        ])
        return pane
    }

    private static func fill(_ pane: NSView, with stack: NSStackView) {
        stack.translatesAutoresizingMaskIntoConstraints = false
        pane.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: pane.topAnchor),
            stack.bottomAnchor.constraint(equalTo: pane.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: pane.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: pane.trailingAnchor),
        ])
    }

    private static func configure(_ scroll: NSScrollView, _ document: NSView) {
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.backgroundColor = .textBackgroundColor
        // Nothing scrolls under the toolbar (docs/UI_REDESIGN.md review 1).
        scroll.automaticallyAdjustsContentInsets = false
        scroll.documentView = document
    }

    override func viewDidLayout() {
        super.viewDidLayout()
        // The sidebar about 220 pt, the list about 340 pt, the letter the rest.
        let splitView = split.splitView
        guard !dividersPlaced, splitView.bounds.width > 880 else { return }
        dividersPlaced = true
        splitView.setPosition(220, ofDividerAt: 0)
        splitView.setPosition(220 + splitView.dividerThickness + 340, ofDividerAt: 1)
    }

    // MARK: - Reading and showing

    /// After unlock: the requests and the contacts, the first contact (or
    /// Innboks with no contact, not chosen by a human, which reads nothing)
    /// and its list, no letter open; then the sync timer.
    func start() {
        readRequests()
        readContacts()
        apply(contacts.first.map { .contact($0.id) } ?? .inbox, byHuman: false)
        syncTimer?.invalidate()
        syncTimer = commonModeTimer(every: Self.syncInterval) { [weak self] in self?.syncNow() }
        syncNow()
        view.window?.makeFirstResponder(contacts.isEmpty ? mailboxes : contactList)
    }

    /// Reads the contacts (the old names are wiped). `contacts` owns the
    /// names; the list shows copies.
    private func readContacts() {
        contacts.forEach { $0.name.wipe() }
        let rows: [ContactItem]
        do {
            rows = try session?.contacts() ?? []
        } catch {
            Self.log.error("contacts failed: \(Self.name(error), privacy: .public)")
            rows = []
        }
        contacts = rows
        contactList.setRows(rows.map { SecureListView.Row(text: $0.name.copy(), flag: $0.keyChanged, dim: $0.blocked) },
                            selected: nil)
        sidebar.update()
    }

    /// Reads the requests the last sync fetched (the old addresses and
    /// codes are wiped). `requests` owns them; the list shows copies.
    private func readRequests() {
        requests.forEach { $0.address.wipe(); $0.code.wipe() }
        let rows: [RequestItem]
        do {
            rows = try session?.requests() ?? []
        } catch {
            Self.log.error("requests failed: \(Self.name(error), privacy: .public)")
            rows = []
        }
        requests = rows
        requestList.setRows(rows.map { SecureListView.Row(text: $0.address.copy()) }, selected: nil)
        sidebar.update()
    }

    /// Makes `selection` the sidebar's selection: marks it, shows the
    /// ContactBar for a contact or request, reads the list (no letter
    /// open) and names a mailbox in the window's title. `byHuman` says a
    /// human chose it: a mailbox is read only then.
    private func apply(_ next: SidebarSelection, byHuman: Bool) {
        selection = next
        mailboxChosen = byHuman && next.isMailbox
        markSidebar()
        readList(keeping: nil)
    }

    /// The sidebar's lists show `selection`, without calling `onSelect`.
    private func markSidebar() {
        mailboxes.setSelected(selection == .inbox ? 0 : selection == .sent ? 1 : nil)
        contactList.setSelected(selectedContact.flatMap { c in contacts.firstIndex { $0.id == c.id } })
        requestList.setSelected(selectedRequest.flatMap { r in requests.firstIndex { $0.peer == r.peer } })
        showTitle()
    }

    /// The window's title: a mailbox's fixed name while one is selected,
    /// else «Brev»; never a contact. The subtitle stays empty, so the title
    /// is one line and does not move.
    private func showTitle() {
        view.window?.title = selection == .inbox ? L10n.mailboxInbox
            : selection == .sent ? L10n.mailboxSent : L10n.windowMainTitle
        view.window?.subtitle = ""
    }

    /// Reads the contacts again, keeping the selection (the contact `id`,
    /// if given and still there): after a contact is added, a key is
    /// accepted, a contact blocked, or a compose sheet closed without
    /// sending. The requests are read again too.
    func reloadContacts(selecting id: Data?) {
        refresh(id.map { .contact($0) })
    }

    /// Reads the requests and the contacts again and selects `wanted` if it
    /// is still there, else what was selected, else the first contact, else
    /// Innboks (not chosen, so it reads nothing). A mailbox is kept only if
    /// a human chose it: a contact that arrives by sync while Brev sits on
    /// Innboks by itself is selected, and no mailbox is read. The same
    /// selection keeps its letter by thread id.
    private func refresh(_ wanted: SidebarSelection?) {
        let before = selection
        let thread = selectedThreadID
        readRequests()
        readContacts()
        let next = [wanted, before].compactMap { $0 }.first { exists($0) && (!$0.isMailbox || mailboxChosen) }
            ?? contacts.first.map { .contact($0.id) } ?? .inbox
        mailboxChosen = mailboxChosen && next == before && next.isMailbox
        selection = next
        markSidebar()
        readList(keeping: next == before ? thread : nil)
    }

    private func exists(_ s: SidebarSelection) -> Bool {
        switch s {
        case .inbox, .sent: return true
        case .contact(let id): return contacts.contains { $0.id == id }
        case .request(let peer): return requests.contains { $0.peer == peer }
        }
    }

    /// A human selected Innboks (0) or Sendt (1).
    private func mailboxSelected(_ i: Int) {
        acceptFailed = nil
        apply(i == 0 ? .inbox : .sent, byHuman: true)
    }

    /// A human selected a contact.
    private func contactSelected() {
        guard let i = contactList.selected, contacts.indices.contains(i) else { return }
        acceptFailed = nil
        apply(.contact(contacts[i].id), byHuman: true)
    }

    /// A human selected a request: the asker in the bar, no list.
    private func requestSelected() {
        guard let i = requestList.selected, requests.indices.contains(i) else { return }
        acceptFailed = nil
        apply(.request(requests[i].peer), byHuman: true)
    }

    /// The ContactBar for the selection: over the list for a contact or a
    /// request; over the reading header in a mailbox, while the open
    /// letter's contact has a changed key or is blocked; else hidden. The
    /// old texts are wiped; the bar gets its own copies.
    private func showBar() {
        if let request = selectedRequest {
            let code = SecretBytes(capacity: request.code.count)
            request.code.withBytes { _ = code.append($0) }
            header.showRequest(address: request.address.copy(), code: code, failed: answerFailed == request.peer)
            return place(header, in: listStack)
        }
        if let contact = selectedContact {
            showDetails(of: contact)
            return place(header, in: listStack)
        }
        if let contact = letterContact, contact.keyChanged || contact.blocked {
            showDetails(of: contact)
            return place(header, in: readingStack)
        }
        header.clear()
        place(header, in: nil)
    }

    private func showDetails(of contact: ContactItem) {
        guard let session else { return header.clear() }
        do {
            header.showContact(try session.contactInfo(contact: contact.id), acceptFailed: acceptFailed == contact.id,
                               blockFailed: blockFailed == contact.id)
        } catch {
            Self.log.error("contact info failed: \(Self.name(error), privacy: .public)")
            header.clear()
        }
    }

    /// Moves `bar` to the top of `stack`, or out of the window (nil).
    private func place(_ bar: NSView, in stack: NSStackView?) {
        if let old = bar.superview as? NSStackView, old !== stack {
            old.removeArrangedSubview(bar)
            bar.removeFromSuperview()
        }
        guard let stack, bar.superview !== stack else { return }
        stack.insertArrangedSubview(bar, at: 0)
        bar.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
    }

    /// Reads the selection's threads into the list (the old subjects, names
    /// and letters are wiped first) and selects `threadID` if it is still
    /// there; otherwise nothing is selected and nothing opens. A kept thread
    /// keeps the reading pane where it was; the position is read before
    /// `clear()` shrinks the document, which moves it to the top.
    private func readList(keeping threadID: Data?) {
        let origin = letterScroll.contentView.bounds.origin
        listed = []
        messageList.clear()
        closeLetter()
        var rows: [SecureListView.Row] = []
        if let session, let selection {
            switch selection {
            case .request: break
            case .contact(let id): (listed, rows) = readThreads(of: id, session)
            case .inbox, .sent:
                // Only a mailbox a human chose is read (Q1).
                if mailboxChosen { (listed, rows) = readMailbox(sent: selection == .sent, session) }
            }
        }
        let kept = threadID.flatMap { id in listed.firstIndex { $0.id == id } }
        messageList.setRows(rows, selected: kept)
        showEmptyState()
        showNoLetter()
        if kept != nil { showLetter(scrolledTo: origin) } else { showBar() }
    }

    /// A contact's threads, newest first: the subject, «Mottatt»/«Sendt»,
    /// the date and a received letter's mark.
    private func readThreads(of contact: Data, _ session: Session) -> ([Listed], [SecureListView.Row]) {
        let threads: [ThreadItem]
        do {
            threads = Array(try session.threads(contact: contact).reversed())
        } catch {
            Self.log.error("threads failed: \(Self.name(error), privacy: .public)")
            return ([], [])
        }
        var listed: [Listed] = [], rows: [SecureListView.Row] = []
        for t in threads {
            let (incoming, outgoing) = directions(t.id, session)
            let out = incoming == nil && outgoing
            listed.append(Listed(id: t.id, contact: contact, createdAt: t.createdAt, subject: t.subject, outgoing: out))
            rows.append(SecureListView.Row(text: t.subject, meta: listDate(t.createdAt),
                                           note: out ? L10n.listSent : L10n.listReceived,
                                           mark: incoming.map { Self.mark(Self.proof($0, session)) }))
        }
        return (listed, rows)
    }

    /// Innboks (threads with a received letter) or Sendt (with a sent one)
    /// across every contact, newest first: the other party's name and the
    /// subject, the date, and in Innboks the mark. Rust decrypts every
    /// subject for each contact; the ones not listed are wiped at once.
    private func readMailbox(sent: Bool, _ session: Session) -> ([Listed], [SecureListView.Row]) {
        var found: [(Listed, SecureListView.Row)] = []
        for c in contacts {
            let threads: [ThreadItem]
            do {
                threads = try session.threads(contact: c.id)
            } catch {
                Self.log.error("threads failed: \(Self.name(error), privacy: .public)")
                continue
            }
            for t in threads {
                let (incoming, outgoing) = directions(t.id, session)
                guard sent ? outgoing : incoming != nil else {
                    t.subject.wipe()
                    continue
                }
                let mark = sent ? nil : incoming.map { Self.mark(Self.proof($0, session)) }
                found.append((Listed(id: t.id, contact: c.id, createdAt: t.createdAt, subject: t.subject, outgoing: sent),
                              SecureListView.Row(text: c.name.copy(), text2: t.subject, meta: listDate(t.createdAt),
                                                 mark: mark)))
            }
        }
        found.sort { $0.0.createdAt > $1.0.createdAt }
        return (found.map(\.0), found.map(\.1))
    }

    /// A thread's first received letter (nil if none) and whether it has a
    /// sent one. `messages` decrypts nothing.
    private func directions(_ thread: Data, _ session: Session) -> (incoming: Data?, outgoing: Bool) {
        guard let messages = try? session.messages(thread: thread) else { return (nil, false) }
        return (messages.first { !$0.outgoing }?.id, messages.contains { $0.outgoing })
    }

    private static func mark(_ proof: Proof) -> SecureListView.Mark {
        proof.verified ? .verified : .unverified
    }

    /// The list's empty state for the selection: none for a request.
    private func showEmptyState() {
        guard messageList.count == 0, let selection else { return emptyList.isHidden = true }
        switch selection {
        case .request:
            emptyList.isHidden = true
        case .inbox:
            let add = contacts.isEmpty
                ? HumanButton(title: L10n.sidebarAdd, target: self, action: #selector(showContacts(_:))) : nil
            emptyList.show(symbol: "tray", text: L10n.listEmptyInbox, button: add)
        case .sent:
            emptyList.show(symbol: "paperplane", text: L10n.listEmptySent)
        case .contact:
            emptyList.show(symbol: "envelope", text: L10n.listEmptyContact)
        }
    }

    /// Wipes the open letter (its bodies, the reading header's copies) and
    /// shows «Ingen brev valgt» (see showNoLetter).
    private func closeLetter() {
        letters.clear()
        readingHeader.clear()
        proofs = []
        showNoLetter()
        updateButtons()
    }

    /// «Ingen brev valgt» while the list has rows and none is open; not for
    /// a request, and not over an empty list, whose own empty state says it.
    private func showNoLetter() {
        noLetter.isHidden = selection == nil || selectedRequest != nil || messageList.count == 0 || !letters.isEmpty
    }

    /// Reads the selected thread's letters (the old bodies are wiped first)
    /// and scrolls the reading pane to `origin`: .zero shows the top.
    private func showLetter(scrolledTo origin: NSPoint) {
        closeLetter()
        defer {
            showBar()
            updateButtons()
        }
        guard let i = messageList.selected, listed.indices.contains(i), let session else { return }
        let thread = listed[i]
        var shown: [LetterStackView.Letter] = []
        var read: [Proof?] = []
        do {
            for m in try session.messages(thread: thread.id) {
                let when = date(m.createdAt)
                let proof = m.outgoing ? nil : Self.proof(m.id, session)
                read.append(proof)
                shown.append(LetterStackView.Letter(header: m.outgoing ? L10n.mailSent(when) : L10n.mailReceived(when),
                                                    body: try session.body(message: m.id),
                                                    badge: proof.map { L10n.badge(verified: $0.verified) }))
            }
        } catch {
            Self.log.error("letters failed: \(Self.name(error), privacy: .public)")
            shown.forEach { $0.body.wipe() }
            return
        }
        proofs = read
        letters.show(shown)
        letters.scroll(origin)
        let name = contacts.first { $0.id == thread.contact }?.name.copy() ?? SecretText(maxUnits: 1)
        let first = read.first ?? nil
        readingHeader.show(subject: thread.subject.copy(), name: name, outgoing: first == nil,
                           date: date(thread.createdAt),
                           badge: first.map { (L10n.badge(verified: $0.verified), $0.verified) })
        noLetter.isHidden = true
    }

    /// A received letter's proof; one that cannot be read is not verified,
    /// with the token as the failed check.
    private static func proof(_ message: Data, _ session: Session) -> Proof {
        do {
            if let proof = try session.letterProof(message: message) { return proof }
        } catch {
            log.error("proof failed: \(name(error), privacy: .public)")
        }
        return Proof(verified: false, failed: ["token"], attested: false, hardwareKey: nil, admin: nil, agents: nil,
                     windows: nil, blockedInput: nil, seconds: nil, sip: nil, sudo: nil)
    }

    /// A human pressed the badge of the letter at `index`: its detail, in a
    /// sheet on this window (one sheet at a time).
    func showProof(_ index: Int) {
        guard !composing, let window = view.window, proofs.indices.contains(index), let proof = proofs[index]
        else { return }
        ProofSheet.present(on: window, proof)
    }

    /// A letter to `contact` started `thread`: the list is read again if it
    /// shows that contact or Sendt, keeping the open letter (the new one is
    /// not opened), and a sync runs.
    func showSent(thread: Data, contact: Data) {
        syncNow()
        guard selection == .contact(contact) || selection == .sent else { return }
        readList(keeping: selectedThreadID)
    }

    private var selectedContact: ContactItem? {
        guard case .contact(let id) = selection else { return nil }
        return contacts.first { $0.id == id }
    }

    /// The selected request, while one is selected.
    private var selectedRequest: RequestItem? {
        guard case .request(let peer) = selection else { return nil }
        return requests.first { $0.peer == peer }
    }

    /// In a mailbox, the open letter's contact.
    private var letterContact: ContactItem? {
        guard selection?.isMailbox == true, let i = messageList.selected, listed.indices.contains(i) else { return nil }
        return contacts.first { $0.id == listed[i].contact }
    }

    /// The contact the ContactBar shows (Blokker, Godta ny kode).
    private var barContact: ContactItem? {
        selectedContact ?? letterContact.flatMap { $0.keyChanged || $0.blocked ? $0 : nil }
    }

    /// Who Nytt brev writes to: the selected contact, or in a mailbox the
    /// selected letter's contact.
    private var recipient: ContactItem? {
        selectedContact ?? letterContact
    }

    /// The open letter's thread (the tools' checks).
    var openThread: Data? { letters.isEmpty ? nil : selectedThreadID }

    private var selectedThreadID: Data? {
        messageList.selected.flatMap { listed.indices.contains($0) ? listed[$0].id : nil }
    }

    private func date(_ seconds: Int64) -> String {
        dates.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }

    /// Today the time, this week the weekday, else the date (metadata).
    private func listDate(_ seconds: Int64) -> String {
        let d = Date(timeIntervalSince1970: TimeInterval(seconds))
        let calendar = Calendar.current
        if calendar.isDateInToday(d) { return times.string(from: d) }
        if let week = calendar.date(byAdding: .day, value: -6, to: calendar.startOfDay(for: Date())), d >= week {
            return weekdays.string(from: d)
        }
        return days.string(from: d)
    }

    // MARK: - Sync (PHASE3 §5.3)

    /// Fetches the waiting letters on `Session.net`, unless a sync is still
    /// running or the timer is stopped. Before registration Rust answers
    /// NotFound without a request.
    private func syncNow() {
        guard let session else { return stopSync() }
        guard syncTimer != nil, !syncing else { return }
        syncing = true
        let generation = syncGeneration
        Session.net.async {
            let result = Result { try session.sync() }
            DispatchQueue.main.async { [weak self] in self?.synced(result, generation) }
        }
    }

    /// On main. When a contact changed or the number of requests did, the
    /// requests and the contacts are read again; else when letters arrived,
    /// the list is (a request has none). A locked session stops the timer.
    private func synced(_ result: Result<SyncResult, Error>, _ generation: Int) {
        syncing = false
        guard generation == syncGeneration else { return }
        switch result {
        case .success(let got):
            noteSync("ok")
            let asked = Int(got.requests) != requests.count
            guard got.letters > 0 || got.contactsChanged || asked else { return }
            Self.log.notice(
                "sync arrived=\(got.letters, privacy: .public) contacts=\(got.contactsChanged, privacy: .public) requests=\(got.requests, privacy: .public)")
            if got.contactsChanged || asked { return refresh(nil) }
            if selectedRequest == nil { readList(keeping: selectedThreadID) }
        case .failure(BrevError.Locked):
            stopSync()
        case .failure(let error):
            noteSync(Self.name(error))
        }
    }

    /// Logs a sync's outcome when it differs from the last one.
    private func noteSync(_ outcome: String) {
        guard outcome != syncOutcome else { return }
        syncOutcome = outcome
        if outcome == "ok" {
            Self.log.notice("sync ok")
        } else {
            Self.log.error("sync failed: \(outcome, privacy: .public)")
        }
    }

    private func stopSync() {
        syncTimer?.invalidate()
        syncTimer = nil
        syncGeneration &+= 1
    }

    /// Runs one sync now, as the timer would (the tools' checks).
    func syncOnce() {
        syncNow()
    }

    // MARK: - ContentHolder (lock sequence §8.4 step 3)

    func wipeAll() {
        stopSync()
        header.clear()
        acceptFailed = nil
        blockFailed = nil
        answerFailed = nil
        answering = false
        blocking = false
        requests.forEach { $0.address.wipe(); $0.code.wipe() }
        requests = []
        contacts.forEach { $0.name.wipe() }
        requestList.clear()
        contactList.clear()
        messageList.clear()
        letters.clear()
        readingHeader.clear()
        proofs = []
        contacts = []
        listed = []
        selection = nil
        mailboxChosen = false
        mailboxes.setSelected(nil)
        sidebar.update()
        emptyList.isHidden = true
        showTitle()
        updateButtons()
    }

    // MARK: - Actions (HumanButton: human input only; ⌘N and the toolbar)

    /// One compose sheet at a time (⌘N can reach this while the sheet is key).
    @objc func newLetter(_ sender: Any?) {
        guard !composing, canWriteNewLetter, let contact = recipient, let onNewLetter else { return }
        onNewLetter(contact)
    }

    @objc private func lockPressed(_ sender: Any?) {
        onLock()
    }

    /// «Legg til kontakt»: ContactSheet on this window. When it closes, the
    /// requests and contacts are read again, with the contact it added last
    /// selected (else the selection kept). One sheet at a time.
    @objc func showContacts(_ sender: Any?) {
        guard !composing, let window = view.window, let session else { return }
        ContactSheet.present(on: window, session: session) { [weak self] added in
            self?.refresh(added.map { .contact($0) })
        }
    }

    /// Godta or Avslå on the selected request: one click, no Touch ID
    /// (`answerRequest` on `Session.net`). Godta selects the new contact;
    /// either way the request leaves the list. A failed answer shows
    /// net.error and can be given again.
    func answerSelected(approve: Bool) {
        guard !answering, !composing, let session, let request = selectedRequest else { return }
        let peer = request.peer, generation = syncGeneration
        answering = true
        header.setAnswering(true)
        Session.net.async {
            let result = Result { try session.answerRequest(peer: peer, approve: approve) }
            DispatchQueue.main.async { [weak self] in self?.answered(result, peer, generation) }
        }
    }

    private func answered(_ result: Result<Data, Error>, _ peer: Data, _ generation: Int) {
        guard generation == syncGeneration else { return }
        answering = false
        switch result {
        case .success(let id):
            answerFailed = nil
            Self.log.notice("request answered")
            refresh(id.isEmpty ? nil : .contact(id))
        case .failure(let error):
            Self.log.error("answer failed: \(Self.name(error), privacy: .public)")
            answerFailed = (error as? BrevError) == .Network ? peer : nil
            refresh(.request(peer))
        }
    }

    /// Blokker on the bar's contact: one click, no Touch ID
    /// (`blockContact` on `Session.net`). The local block holds at once; if
    /// the relay was not told, net.error shows and Blokker tells it again.
    /// Rust also keeps that sealed, and every sync tells the relay until it
    /// answers, so a lock (which forgets `blockFailed`) loses nothing.
    func blockSelected() {
        guard !blocking, !composing, let session, let contact = barContact else { return }
        let id = contact.id, generation = syncGeneration
        blocking = true
        header.setBlocking(true)
        Session.net.async {
            let result = Result { try session.blockContact(contact: id) }
            DispatchQueue.main.async { [weak self] in self?.blocked(result, id, generation) }
        }
    }

    private func blocked(_ result: Result<Void, Error>, _ id: Data, _ generation: Int) {
        guard generation == syncGeneration else { return }
        blocking = false
        switch result {
        case .success:
            blockFailed = nil
            Self.log.notice("contact blocked")
        case .failure(let error):
            Self.log.error("block failed: \(Self.name(error), privacy: .public)")
            blockFailed = (error as? BrevError) == .Network ? id : nil
        }
        refresh(nil)
    }

    /// Godta ny kode: ConfirmSheet, and on its Godta the code the bar shows
    /// is accepted for the contact it showed when it was pressed.
    func acceptNewKey() {
        guard !composing, let window = view.window, let contact = barContact, header.newCode != nil else { return }
        let id = contact.id
        ConfirmSheet.present(on: window, .acceptKey) { [weak self] confirmed in
            if confirmed { self?.accept(contact: id) }
        }
    }

    /// Rust refuses unless `code` is still the pending key's (KeyChanged);
    /// either way the contacts are read again, and a refusal shows
    /// accept.error under the code now pending.
    private func accept(contact id: Data) {
        guard let session, barContact?.id == id, let code = header.newCode else { return }
        do {
            try session.acceptNewKey(contact: id, newCode: code)
            acceptFailed = nil
            Self.log.notice("new key accepted")
        } catch {
            acceptFailed = id
            Self.log.error("accept failed: \(Self.name(error), privacy: .public)")
        }
        refresh(nil)
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(newLetter(_:)) { return canWriteNewLetter && !composing }
        return true
    }

    func validateToolbarItem(_ item: NSToolbarItem) -> Bool {
        if item.action == #selector(newLetter(_:)) { return canWriteNewLetter && !composing }
        return true
    }

    private var composing: Bool {
        view.window?.attachedSheet != nil
    }

    /// Whether Nytt brev can write now: a recipient whose key did not
    /// change and who is not blocked.
    var canWriteNewLetter: Bool {
        onNewLetter != nil && recipient.map { !$0.keyChanged && !$0.blocked } == true
    }

    private func updateButtons() {
        mailToolbar.item(MailToolbar.newLetter)?.isEnabled = canWriteNewLetter
    }

    /// A BrevError's variant name; never an error's message.
    private static func name(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }
}

/// The split view: thin dividers in the separator colour, so the three
/// panes read apart in light and dark. Chrome.
private final class MailSplitView: NSSplitView {
    override var dividerColor: NSColor { .separatorColor }
}

/// The reading pane's background (textBackgroundColor). Chrome.
private final class BackgroundView: NSView {
    override var isOpaque: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        NSColor.textBackgroundColor.setFill()
        dirtyRect.fill()
    }
}
