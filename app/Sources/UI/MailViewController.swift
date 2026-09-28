// MailViewController.swift — the unlocked screen: contacts, threads, letters.
//
// Upholds CLAUDE.md §1.2, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §7.2, §9;
// docs/PHASE3_DESIGN.md §5.3, §6.3, §6.5). A bar with Nytt brev, Legg til
// kontakt and Lås (HumanButtons), the contact header (ContactHeaderView: the
// own address and code, the selected contact's, and a changed key's warning
// with Godta ny kode, all contact data in the protected layer), and an
// NSSplitView with three panes: contacts (SecureListView; a contact's name
// is its address), the contact's threads, newest first (SecureListView),
// and the selected thread's letters, oldest first (LetterStackView).
// `start()` reads the own address and the contacts and selects the first,
// then its newest thread, then that thread's letters. Nytt brev is off for
// a contact whose key changed. Legg til kontakt opens AddContactSheet; a
// contact it adds is selected. Godta ny kode opens ConfirmSheet, and only
// its Godta accepts the code the header shows (acceptNewKey). After a
// compose sheet is cancelled (it may have found a changed key),
// the contacts are read again. `sync()` fetches the
// letters waiting at the relay: once at `start()`, every 5 seconds from a
// timer in the common run-loop modes (D-0052 in the shifted numbering), and
// once after a letter is sent. It runs on `Session.net`, never on main; a
// sync still running makes the next tick skip, and its result returns to
// main, where a result from before `wipeAll()` is dropped. When letters
// arrive, the thread and letter panes are read again (their old texts wiped)
// and keep the selected thread by id. Every text read here is a SecretText
// owned by a list or letter view; a new selection wipes what it replaces,
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
    /// The selected contact's threads, newest first, as the list shows them.
    private var threads: [ThreadItem] = []
    private var syncTimer: Timer?
    /// True while a `sync()` is on `Session.net`.
    private var syncing = false
    /// Bumped by `stopSync()`: a sync result from before it is dropped.
    private var syncGeneration = 0
    /// The last sync's outcome ("ok" or an error name), logged on change.
    private var syncOutcome = "ok"

    private let contactList = SecureListView(rowHeight: 32)
    private let threadList = SecureListView(rowHeight: 48)
    private let letters = LetterStackView()
    private let letterScroll = NSScrollView()
    private let split = NSSplitView()
    private let noLetters = InterfaceText(L10n.mailNoThreads, width: 260)
    let header = ContactHeaderView()
    private var newButton: HumanButton?
    private(set) var addButton: HumanButton?
    /// The contact whose new code was not accepted (accept.error shows).
    private var acceptFailed: Data?
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
        let add = HumanButton(title: L10n.mailAddContact, target: self, action: #selector(addContact(_:)))
        let lock = HumanButton(title: L10n.mailLock, target: self, action: #selector(lockPressed(_:)))
        newButton = new
        addButton = add
        let spacer = NSView()
        spacer.setContentHuggingPriority(.defaultLow, for: .horizontal)
        let bar = NSStackView(views: [new, add, spacer, lock])
        bar.orientation = .horizontal
        header.onAccept = { [weak self] in self?.acceptNewKey() }

        split.isVertical = true
        split.dividerStyle = .thin
        split.addSubview(Self.scrollView(contactList, background: .controlBackgroundColor))
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

        contactList.onSelect = { [weak self] _ in self?.contactSelected() }
        threadList.onSelect = { [weak self] _ in self?.showLetters(scrolledTo: .zero) }
        contactList.nextKeyView = threadList
        threadList.nextKeyView = contactList
        view = root
        updateButtons()
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
        readContacts(selecting: nil)
        showContactHeader()
        showThreads(keeping: nil)
        syncTimer?.invalidate()
        syncTimer = commonModeTimer(every: Self.syncInterval) { [weak self] in self?.syncNow() }
        syncNow()
        view.window?.makeFirstResponder(contactList)
    }

    /// Reads the contacts (the old names are wiped) and selects the one
    /// with `id`, or else the first.
    private func readContacts(selecting id: Data?) {
        let rows: [ContactItem]
        do {
            rows = try session?.contacts() ?? []
        } catch {
            Self.log.error("contacts failed: \(Self.name(error), privacy: .public)")
            rows = []
        }
        contacts = rows
        let chosen = id.flatMap { id in rows.firstIndex { $0.id == id } } ?? (rows.isEmpty ? nil : 0)
        contactList.setRows(rows.map { SecureListView.Row(text: $0.name, meta: nil) }, selected: chosen)
    }

    /// Reads the contacts again with `id` selected (or the first), its
    /// header line and its threads, keeping the selected thread if it is
    /// the same contact's: after a contact is added, a key is accepted, or
    /// a compose sheet closed without sending.
    func reloadContacts(selecting id: Data?) {
        let before = selectedContact?.id
        let thread = threadList.selected.flatMap { threads.indices.contains($0) ? threads[$0].id : nil }
        readContacts(selecting: id)
        showContactHeader()
        showThreads(keeping: selectedContact?.id == before ? thread : nil)
    }

    /// A human selected a contact: its header line and its threads.
    private func contactSelected() {
        acceptFailed = nil
        showContactHeader()
        showThreads(keeping: nil)
    }

    /// The header's line 2 for the selected contact (the old one is wiped).
    private func showContactHeader() {
        guard let contact = selectedContact, let session else { return header.showContact(nil) }
        do {
            header.showContact(try session.contactInfo(contact: contact.id), acceptFailed: acceptFailed == contact.id)
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

    /// On main. When letters arrived, the thread and letter panes are read
    /// again. A locked session stops the timer.
    private func synced(_ result: Result<UInt32, Error>, _ generation: Int) {
        syncing = false
        guard generation == syncGeneration else { return }
        switch result {
        case .success(let arrived):
            noteSync("ok")
            guard arrived > 0 else { return }
            Self.log.notice("sync arrived=\(arrived, privacy: .public)")
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

    /// Legg til kontakt: the sheet on this window; a contact it adds is
    /// selected. One sheet at a time.
    @objc func addContact(_ sender: Any?) {
        guard !composing, let window = view.window, let session else { return }
        AddContactSheet.present(on: window, session: session) { [weak self] added in
            guard let added else { return }
            self?.reloadContacts(selecting: added)
        }
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
        onNewLetter != nil && selectedContact.map { !$0.keyChanged } == true
    }

    private func updateButtons() {
        newButton?.isEnabled = canWriteNewLetter
    }

    /// A BrevError's variant name; never an error's message.
    private static func name(_ error: Error) -> String {
        (error as? BrevError).map { "\($0)" } ?? "other"
    }
}
