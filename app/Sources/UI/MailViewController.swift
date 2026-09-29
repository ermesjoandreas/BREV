// MailViewController.swift — the unlocked screen: contacts, threads, letters.
//
// Upholds CLAUDE.md §1.2, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §7.2, §9;
// docs/PHASE3_DESIGN.md §5.3, §6.3, §6.5; docs/PHASE4_DESIGN.md §6.1). A
// bar with Nytt brev, Kontakter and Lås (HumanButtons), the contact header
// (ContactHeaderView: the own address and code, the selected contact's with
// its state and Blokker, a changed key's warning with Godta ny kode, or a
// selected request's asker with Godta and Avslå, all contact data in the
// protected layer), and an NSSplitView with three panes: the contacts pane
// (under «Forespørsler», while there are any, the contact requests by the
// asker's address, then the contacts; both SecureListViews, one row
// selected in either; a contact's name is its address), the contact's
// threads, newest first (SecureListView), and the selected thread's
// letters, oldest first (LetterStackView). `start()` reads the own address,
// the requests (none before the first sync) and the contacts and selects
// the first contact, then its newest thread, then that thread's letters.
// Nytt brev is off for a contact whose key changed or that is blocked, and
// while a request is selected. Kontakter opens ContactSheet; a contact it
// adds is selected when it closes. Godta ny kode opens ConfirmSheet, and
// only its Godta accepts the code the header shows (acceptNewKey). Godta and
// Avslå answer the selected request with one click (`answerRequest` on
// `Session.net`): Godta selects the new contact, Avslå drops the request;
// Blokker blocks the selected contact with one click (`blockContact` on
// `Session.net`). No Touch ID and no confirmation for either (design §6.1,
// owner answers 6 and 7); a result from before `wipeAll()` is dropped.
// After a compose sheet is cancelled (it may have found a changed key),
// the contacts are read again. `sync()` handles the relay's events and
// fetches the letters waiting there: once at `start()`, every 5 seconds from a
// timer in the common run-loop modes (docs/DECISIONS.md D-0050), and
// once after a letter is sent. It runs on `Session.net`, never on main; a
// sync still running makes the next tick skip, and its result returns to
// main, where a result from before `wipeAll()` is dropped. When a contact
// changed (added by an invite or an approval, or its state or key) or the
// number of requests changed, the requests and the contacts are read again,
// keeping the selected request or contact and thread by id
// (docs/PHASE4_DESIGN.md §6.1); when only letters arrived, the thread and
// letter panes are read again (their old texts wiped) and keep the selected
// thread by id. Every text read here is a SecretText owned by a list or
// letter view, and every request's code a SecretBytes kept here until the
// requests are read again; a new selection wipes what it replaces,
// and `wipeAll()` (lock sequence §8.4 step 3) wipes everything and stops the
// timer. The controller holds the Session weakly, never an OpenText. Logs
// carry counts and error names only (§6.3 rule 7); a sync failure is logged
// once per change, not at every tick.

import AppKit
import os

final class MailViewController: NSViewController, ContentHolder, MailActions, NSMenuItemValidation {
    private static let log = Logger(subsystem: "no.brev.app", category: "mail")
    /// Seconds between two `sync()` calls (PHASE3 §5.3).
    static let syncInterval: TimeInterval = 5
    /// The narrowest the contacts, threads and letter panes get, by divider
    /// or window. A letter laid out much narrower puts a few units on each
    /// line, and every line costs a CTLine (TextLayout), again at every
    /// width change: seconds per resize step for a long letter.
    static let minPaneWidths: [CGFloat] = [150, 200, 300]

    /// A human pressed Lås.
    var onLock: () -> Void = {}
    /// A human asked for a new letter to the selected contact (Nytt brev,
    /// ⌘N): AppDelegate shows the compose sheet. While nil, Nytt brev is
    /// disabled; while a sheet is up, it does nothing.
    var onNewLetter: ((ContactItem) -> Void)? {
        didSet { updateButtons() }
    }

    private weak var session: Session?
    private var contacts: [ContactItem] = []
    /// The contact requests, oldest first, as the requests list shows them;
    /// their codes are wiped when the requests are read again or wiped.
    private var requests: [RequestItem] = []
    /// The selected contact's threads, newest first, as the list shows them.
    private var threads: [ThreadItem] = []
    private var syncTimer: Timer?
    /// True while a `sync()` is on `Session.net`.
    private var syncing = false
    /// Bumped by `stopSync()`: a sync result from before it is dropped.
    private var syncGeneration = 0
    /// The last sync's outcome ("ok" or an error name), logged on change.
    private var syncOutcome = "ok"

    let requestList = SecureListView(rowHeight: 32)
    /// «Forespørsler», inset like the rows below it.
    private let requestsTitle = NSView()
    private var requestScroll: NSScrollView?
    /// The requests list's height: its rows, at most four.
    private var requestsHeight: NSLayoutConstraint?
    private let contactList = SecureListView(rowHeight: 32)
    private let threadList = SecureListView(rowHeight: 48)
    private let letters = LetterStackView()
    private let letterScroll = NSScrollView()
    private let split = NSSplitView()
    private let noLetters = InterfaceText(L10n.mailNoThreads, width: 260)
    let header = ContactHeaderView()
    private var newButton: HumanButton?
    private(set) var contactsButton: HumanButton?
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

    private let dates: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "nb_NO")
        f.dateStyle = .medium
        f.timeStyle = .short
        return f
    }()

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
        let root = NSView(frame: NSRect(x: 0, y: 0, width: 900, height: 600))

        let new = HumanButton(title: L10n.mailNew, target: self, action: #selector(newLetter(_:)))
        let people = HumanButton(title: L10n.contactsTitle, target: self, action: #selector(showContacts(_:)))
        let lock = HumanButton(title: L10n.mailLock, target: self, action: #selector(lockPressed(_:)))
        newButton = new
        contactsButton = people
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let bar = NSStackView(views: [new, people, spacer, lock])
        bar.orientation = .horizontal
        header.onAccept = { [weak self] in self?.acceptNewKey() }
        header.onBlock = { [weak self] in self?.blockSelected() }
        header.onAnswer = { [weak self] approve in self?.answerSelected(approve: approve) }

        split.isVertical = true
        split.dividerStyle = .thin
        split.addSubview(contactsPane())
        split.addSubview(Self.scrollView(threadList, background: .controlBackgroundColor))
        split.addSubview(letterPane())
        // Each pane keeps its minimum width, by divider or window (auto
        // layout carries their sum up to the window's minimum). A change in
        // width goes to the letter pane first, then the threads, then the
        // contacts (the lowest holding priority gives first).
        for (i, pane) in split.subviews.enumerated() {
            pane.widthAnchor.constraint(greaterThanOrEqualToConstant: Self.minPaneWidths[i]).isActive = true
            split.setHoldingPriority(NSLayoutConstraint.Priority(252 - Float(i)), forSubviewAt: i)
        }

        for v in [bar, header, split] {
            v.translatesAutoresizingMaskIntoConstraints = false
            root.addSubview(v)
        }
        NSLayoutConstraint.activate([
            bar.topAnchor.constraint(equalTo: root.topAnchor, constant: 8),
            bar.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 12),
            bar.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -12),
            header.topAnchor.constraint(equalTo: bar.bottomAnchor, constant: 6),
            header.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            header.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            split.topAnchor.constraint(equalTo: header.bottomAnchor, constant: 4),
            split.leadingAnchor.constraint(equalTo: root.leadingAnchor),
            split.trailingAnchor.constraint(equalTo: root.trailingAnchor),
            split.bottomAnchor.constraint(equalTo: root.bottomAnchor),
        ])

        requestList.onSelect = { [weak self] _ in self?.requestSelected() }
        contactList.onSelect = { [weak self] _ in self?.contactSelected() }
        threadList.onSelect = { [weak self] _ in self?.showLetters(scrolledTo: .zero) }
        requestList.nextKeyView = contactList
        contactList.nextKeyView = threadList
        threadList.nextKeyView = requestList
        view = root
        updateButtons()
    }

    /// «Forespørsler» and the requests list (both hidden while there are
    /// none), then the contacts list, which takes the rest of the height.
    private func contactsPane() -> NSView {
        let pane = NSView(frame: NSRect(x: 0, y: 0, width: 200, height: 500))
        let requestScroll = Self.scrollView(requestList, background: .controlBackgroundColor)
        let contactScroll = Self.scrollView(contactList, background: .controlBackgroundColor)
        self.requestScroll = requestScroll
        let title = InterfaceText(L10n.requestsTitle, style: .heading, width: 180, alignment: .left)
        title.translatesAutoresizingMaskIntoConstraints = false
        requestsTitle.addSubview(title)
        NSLayoutConstraint.activate([
            title.topAnchor.constraint(equalTo: requestsTitle.topAnchor, constant: 8),
            title.bottomAnchor.constraint(equalTo: requestsTitle.bottomAnchor),
            title.leadingAnchor.constraint(equalTo: requestsTitle.leadingAnchor, constant: SecureListView.inset),
            title.trailingAnchor.constraint(lessThanOrEqualTo: requestsTitle.trailingAnchor),
        ])
        let stack = NSStackView(views: [requestsTitle, requestScroll, contactScroll])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 4
        stack.detachesHiddenViews = true
        stack.setHuggingPriority(.defaultLow, for: .vertical)
        stack.translatesAutoresizingMaskIntoConstraints = false
        pane.addSubview(stack)
        let height = requestScroll.heightAnchor.constraint(equalToConstant: 0)
        requestsHeight = height
        contactScroll.setContentHuggingPriority(.defaultLow, for: .vertical)
        NSLayoutConstraint.activate([
            stack.topAnchor.constraint(equalTo: pane.topAnchor),
            stack.bottomAnchor.constraint(equalTo: pane.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: pane.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: pane.trailingAnchor),
            requestScroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            contactScroll.widthAnchor.constraint(equalTo: stack.widthAnchor),
            height,
        ])
        stack.setCustomSpacing(0, after: requestScroll)
        requestsTitle.isHidden = true
        requestScroll.isHidden = true
        return pane
    }

    /// The letters' scroll view, with "Ingen brev ennå" over it while no
    /// thread is selected.
    private func letterPane() -> NSView {
        let pane = NSView(frame: NSRect(x: 0, y: 0, width: 420, height: 500))
        Self.configure(letterScroll, letters, background: .textBackgroundColor)
        letterScroll.frame = pane.bounds
        letterScroll.autoresizingMask = [.width, .height]
        pane.addSubview(letterScroll)
        noLetters.translatesAutoresizingMaskIntoConstraints = false
        pane.addSubview(noLetters)
        NSLayoutConstraint.activate([
            noLetters.centerXAnchor.constraint(equalTo: pane.centerXAnchor),
            noLetters.centerYAnchor.constraint(equalTo: pane.centerYAnchor),
        ])
        return pane
    }

    private static func scrollView(_ document: NSView, background: NSColor) -> NSScrollView {
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 0, width: 200, height: 500))
        configure(scroll, document, background: background)
        return scroll
    }

    private static func configure(_ scroll: NSScrollView, _ document: NSView, background: NSColor) {
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.backgroundColor = background
        scroll.documentView = document
    }

    override func viewDidLayout() {
        super.viewDidLayout()
        // Contacts about 200 pt, threads about 280 pt, letters the rest.
        guard !dividersPlaced, split.bounds.width > 520 else { return }
        dividersPlaced = true
        split.setPosition(200, ofDividerAt: 0)
        split.setPosition(200 + split.dividerThickness + 280, ofDividerAt: 1)
    }

    // MARK: - Reading and showing

    /// After unlock: the own address and code, contacts, the first
    /// contact's header line, newest thread and its letters, then the sync
    /// timer.
    func start() {
        do {
            if let me = try session?.me() { header.showMe(address: me.address, code: me.code) }
        } catch {
            Self.log.error("me failed: \(Self.name(error), privacy: .public)")
        }
        readRequests(selecting: nil)
        readContacts(selecting: nil)
        showContactHeader()
        showThreads(keeping: nil)
        syncTimer?.invalidate()
        syncTimer = commonModeTimer(every: Self.syncInterval) { [weak self] in self?.syncNow() }
        syncNow()
        view.window?.makeFirstResponder(contactList)
    }

    /// Reads the contacts (the old names are wiped) and selects the one
    /// with `id`, or else the first unless a request is selected.
    private func readContacts(selecting id: Data?) {
        let rows: [ContactItem]
        do {
            rows = try session?.contacts() ?? []
        } catch {
            Self.log.error("contacts failed: \(Self.name(error), privacy: .public)")
            rows = []
        }
        contacts = rows
        let first = rows.isEmpty || requestList.selected != nil ? nil : 0
        let chosen = id.flatMap { id in rows.firstIndex { $0.id == id } } ?? first
        contactList.setRows(rows.map { SecureListView.Row(text: $0.name, meta: nil) }, selected: chosen)
        if chosen != nil { requestList.deselect() }
    }

    /// Reads the requests the last sync fetched (the old addresses and
    /// codes are wiped) and selects the asker `peer` if it is still there.
    /// The list shows at most four rows at once, and hides with its title
    /// while there are none.
    private func readRequests(selecting peer: Data?) {
        requests.forEach { $0.code.wipe() }
        let rows: [RequestItem]
        do {
            rows = try session?.requests() ?? []
        } catch {
            Self.log.error("requests failed: \(Self.name(error), privacy: .public)")
            rows = []
        }
        requests = rows
        let chosen = peer.flatMap { p in rows.firstIndex { $0.peer == p } }
        requestList.setRows(rows.map { SecureListView.Row(text: $0.address, meta: nil) }, selected: chosen)
        requestsTitle.isHidden = rows.isEmpty
        requestScroll?.isHidden = rows.isEmpty
        requestsHeight?.constant = CGFloat(min(rows.count, 4)) * requestList.rowHeight
    }

    /// Reads the contacts again with `id` selected (or the first), its
    /// header line and its threads, keeping the selected thread if it is
    /// the same contact's: after a contact is added, a key is accepted, or
    /// a compose sheet closed without sending. The requests are read again
    /// too, none selected.
    func reloadContacts(selecting id: Data?) {
        reload(request: nil, contact: id)
    }

    /// Reads the requests and the contacts again: the request `peer` stays
    /// selected if it is still there, else the contact `id` (or the first).
    private func reload(request peer: Data?, contact id: Data?) {
        let before = selectedContact?.id
        let thread = threadList.selected.flatMap { threads.indices.contains($0) ? threads[$0].id : nil }
        readRequests(selecting: peer)
        readContacts(selecting: requestList.selected == nil ? id : nil)
        showContactHeader()
        showThreads(keeping: selectedContact?.id == before ? thread : nil)
    }

    /// A human selected a contact: its header line and its threads.
    private func contactSelected() {
        requestList.deselect()
        acceptFailed = nil
        showContactHeader()
        showThreads(keeping: nil)
    }

    /// A human selected a request: the asker in the header, no threads.
    private func requestSelected() {
        contactList.deselect()
        acceptFailed = nil
        showContactHeader()
        showThreads(keeping: nil)
    }

    /// The header's line 2 for the selected request or contact (the old
    /// one is wiped). The header gets its own copies of a request's address
    /// and code.
    private func showContactHeader() {
        if let request = selectedRequest {
            let code = SecretBytes(capacity: request.code.count)
            request.code.withBytes { _ = code.append($0) }
            return header.showRequest(address: request.address.copy(), code: code,
                                      failed: answerFailed == request.peer)
        }
        guard let contact = selectedContact, let session else { return header.showContact(nil) }
        do {
            header.showContact(try session.contactInfo(contact: contact.id), acceptFailed: acceptFailed == contact.id,
                               blockFailed: blockFailed == contact.id)
        } catch {
            Self.log.error("contact info failed: \(Self.name(error), privacy: .public)")
            header.showContact(nil)
        }
    }

    /// Reads the selected contact's threads (the old subjects and letters
    /// are wiped first) and selects `threadID` if it is still there,
    /// otherwise the newest thread. A kept thread keeps the letter pane
    /// where it was; the position is read before `clear()` shrinks the
    /// document, which moves it to the top.
    private func showThreads(keeping threadID: Data?) {
        let origin = letterScroll.contentView.bounds.origin
        threads = []
        threadList.clear()
        letters.clear()
        updateButtons()
        guard let contact = selectedContact, let session else { return showLetters(scrolledTo: .zero) }
        do {
            threads = Array(try session.threads(contact: contact.id).reversed())
        } catch {
            Self.log.error("threads failed: \(Self.name(error), privacy: .public)")
        }
        let kept = threadID.flatMap { id in threads.firstIndex { $0.id == id } }
        threadList.setRows(threads.map { SecureListView.Row(text: $0.subject, meta: date($0.createdAt)) },
                           selected: kept ?? (threads.isEmpty ? nil : 0))
        showLetters(scrolledTo: kept != nil ? origin : .zero)
    }

    /// Reads the selected thread's letters (the old bodies are wiped first)
    /// and scrolls the letter pane to `origin`: .zero shows the first letter.
    private func showLetters(scrolledTo origin: NSPoint) {
        letters.clear()
        defer { noLetters.isHidden = !letters.isEmpty }
        guard let i = threadList.selected, threads.indices.contains(i), let session else { return }
        var shown: [LetterStackView.Letter] = []
        do {
            for m in try session.messages(thread: threads[i].id) {
                let when = date(m.createdAt)
                shown.append(LetterStackView.Letter(header: m.outgoing ? L10n.mailSent(when) : L10n.mailReceived(when),
                                                    body: try session.body(message: m.id)))
            }
        } catch {
            Self.log.error("letters failed: \(Self.name(error), privacy: .public)")
            shown.forEach { $0.body.wipe() }
            return
        }
        letters.show(shown)
        letters.scroll(origin)
    }

    /// A letter to `contact` started `thread`: if that contact is still
    /// selected, its threads are read again with the new one selected, and
    /// its letter shows from the top.
    func showSent(thread: Data, contact: Data) {
        syncNow()
        guard selectedContact?.id == contact else { return }
        showThreads(keeping: thread)
        letters.scroll(.zero)
    }

    private var selectedContact: ContactItem? {
        contactList.selected.flatMap { contacts.indices.contains($0) ? contacts[$0] : nil }
    }

    /// The selected request, while one is selected (then no contact is).
    private var selectedRequest: RequestItem? {
        requestList.selected.flatMap { requests.indices.contains($0) ? requests[$0] : nil }
    }

    private func date(_ seconds: Int64) -> String {
        dates.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
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
    /// the thread and letter panes are. A locked session stops the timer.
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
            if got.contactsChanged || asked {
                return reload(request: selectedRequest?.peer, contact: selectedContact?.id)
            }
            let kept = threadList.selected.flatMap { threads.indices.contains($0) ? threads[$0].id : nil }
            showThreads(keeping: kept)
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

    // MARK: - ContentHolder (lock sequence §8.4 step 3)

    func wipeAll() {
        stopSync()
        header.clear()
        acceptFailed = nil
        blockFailed = nil
        answerFailed = nil
        answering = false
        blocking = false
        requests.forEach { $0.code.wipe() }
        requests = []
        requestList.clear()
        requestsTitle.isHidden = true
        requestScroll?.isHidden = true
        contactList.clear()
        threadList.clear()
        letters.clear()
        contacts = []
        threads = []
        noLetters.isHidden = false
        updateButtons()
    }

    // MARK: - Actions (HumanButton: human input only; ⌘N from the menu)

    /// One compose sheet at a time (⌘N can reach this while the sheet is key).
    @objc func newLetter(_ sender: Any?) {
        guard !composing, canWriteNewLetter, let contact = selectedContact, let onNewLetter else { return }
        onNewLetter(contact)
    }

    @objc private func lockPressed(_ sender: Any?) {
        onLock()
    }

    /// Kontakter: the sheet on this window. When it closes, the requests
    /// and contacts are read again, with the contact it added last selected
    /// (else the one selected before). One sheet at a time.
    @objc func showContacts(_ sender: Any?) {
        guard !composing, let window = view.window, let session else { return }
        ContactSheet.present(on: window, session: session) { [weak self] added in
            guard let self else { return }
            self.reload(request: added == nil ? self.selectedRequest?.peer : nil,
                        contact: added ?? self.selectedContact?.id)
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
            reload(request: nil, contact: id.isEmpty ? selectedContact?.id : id)
        case .failure(let error):
            Self.log.error("answer failed: \(Self.name(error), privacy: .public)")
            answerFailed = (error as? BrevError) == .Network ? peer : nil
            reload(request: peer, contact: selectedContact?.id)
        }
    }

    /// Blokker on the selected contact: one click, no Touch ID
    /// (`blockContact` on `Session.net`). The local block holds at once; if
    /// the relay was not told, net.error shows and Blokker tells it again.
    func blockSelected() {
        guard !blocking, !composing, let session, let contact = selectedContact else { return }
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
        reloadContacts(selecting: id)
    }

    /// Godta ny kode: ConfirmSheet, and on its Godta the code the header
    /// shows is accepted for the contact selected when it was pressed.
    func acceptNewKey() {
        guard !composing, let window = view.window, let contact = selectedContact, header.newCode != nil else { return }
        let id = contact.id
        ConfirmSheet.present(on: window, .acceptKey) { [weak self] confirmed in
            if confirmed { self?.accept(contact: id) }
        }
    }

    /// Rust refuses unless `code` is still the pending key's (KeyChanged);
    /// either way the contacts are read again, and a refusal shows
    /// accept.error under the code now pending.
    private func accept(contact id: Data) {
        guard let session, selectedContact?.id == id, let code = header.newCode else { return }
        do {
            try session.acceptNewKey(contact: id, newCode: code)
            acceptFailed = nil
            Self.log.notice("new key accepted")
        } catch {
            acceptFailed = id
            Self.log.error("accept failed: \(Self.name(error), privacy: .public)")
        }
        reloadContacts(selecting: id)
    }

    func validateMenuItem(_ menuItem: NSMenuItem) -> Bool {
        if menuItem.action == #selector(newLetter(_:)) { return canWriteNewLetter && !composing }
        return true
    }

    private var composing: Bool {
        view.window?.attachedSheet != nil
    }

    private var canWriteNewLetter: Bool {
        onNewLetter != nil && selectedContact.map { !$0.keyChanged && !$0.blocked } == true
    }

    private func updateButtons() {
        newButton?.isEnabled = canWriteNewLetter
    }

    /// A BrevError's variant name; never an error's message.
    private static func name(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }
}
