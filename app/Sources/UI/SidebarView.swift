// SidebarView.swift — the mail window's sidebar: Innboks and Sendt, the
// contact requests, the contacts, and «Legg til kontakt».
//
// Upholds CLAUDE.md §1.2, §1.10 and §2 (docs/UI_REDESIGN.md §2.3). The
// mailbox rows are chrome: two fixed names and SF Symbols, drawn by AppKit.
// The requests and the contacts are SecureListViews (content: an address is
// a name). A section title and its list are hidden while the list is empty
// (the requests); with no contacts the footer's «Legg til kontakt» says
// what to do. The background is a plain colour set apart from the list's.
// Selecting a mailbox row makes the mail screen read every contact's
// subjects, so only a human may do it (review 3): MailboxListView takes a
// selection only from mouseDown and keyDown (↑/↓), which BrevApplication
// delivers only after InputFilter, and the view drops a synthetic event
// again. Accessibility sees each row as static text only: no row, no list,
// no selected state it can set and no action it can press or pick. The
// footer's «Legg til kontakt» is a HumanButton. Nothing here is saved.

import AppKit

/// Innboks and Sendt. Chrome, with no accessibility action.
final class MailboxListView: NSView {
    static let rowHeight: CGFloat = 28

    /// A human selected row `index` (0 Innboks, 1 Sendt).
    var onSelect: (Int) -> Void = { _ in }
    private(set) var selected: Int?
    let names = [L10n.mailboxInbox, L10n.mailboxSent]
    private let symbols = ["tray", "paperplane"]
    private lazy var elements: [StaticRow] = names.indices.map { StaticRow(self, $0) }

    override var isFlipped: Bool { true }
    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: CGFloat(names.count) * Self.rowHeight)
    }

    /// Selects `index` (or none) without calling `onSelect`: the mail screen
    /// moved the selection elsewhere, or a lock.
    func setSelected(_ index: Int?) {
        selected = index
        needsDisplay = true
    }

    // MARK: Human input only

    override var acceptsFirstResponder: Bool { true }

    override func becomeFirstResponder() -> Bool {
        needsDisplay = true
        return true
    }

    override func resignFirstResponder() -> Bool {
        needsDisplay = true
        return true
    }

    override func mouseDown(with event: NSEvent) {
        guard !InputFilter.isSynthetic(event) else { return }
        window?.makeFirstResponder(self)
        let i = Int((convert(event.locationInWindow, from: nil).y / Self.rowHeight).rounded(.down))
        choose(i)
    }

    override func keyDown(with event: NSEvent) {
        guard !InputFilter.isSynthetic(event) else { return }
        switch event.keyCode {
        case 125: choose(min((selected ?? -1) + 1, names.count - 1))   // ↓
        case 126: choose(max((selected ?? names.count) - 1, 0))        // ↑
        default: super.keyDown(with: event)
        }
    }

    private func choose(_ i: Int) {
        guard names.indices.contains(i), i != selected else { return }
        selected = i
        needsDisplay = true
        onSelect(i)
    }

    // MARK: Drawing (fixed text only)

    override func draw(_ dirtyRect: NSRect) {
        let focused = window?.firstResponder === self
        for (i, name) in names.enumerated() {
            let r = NSRect(x: 0, y: CGFloat(i) * Self.rowHeight, width: bounds.width, height: Self.rowHeight)
            let onAccent = i == selected && focused
            if i == selected {
                (focused ? NSColor.selectedContentBackgroundColor : .unemphasizedSelectedContentBackgroundColor).setFill()
                NSBezierPath(roundedRect: r.insetBy(dx: 8, dy: 1), xRadius: 6, yRadius: 6).fill()
            }
            let tint: NSColor = onAccent ? .alternateSelectedControlTextColor : .secondaryLabelColor
            let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .regular)
                .applying(.init(paletteColors: [tint]))
            if let image = NSImage(systemSymbolName: symbols[i], accessibilityDescription: nil)?
                .withSymbolConfiguration(config) {
                let s = image.size
                image.draw(in: NSRect(x: 14 + (18 - s.width) / 2, y: r.minY + (r.height - s.height) / 2,
                                      width: s.width, height: s.height),
                           from: .zero, operation: .sourceOver, fraction: 1, respectFlipped: true, hints: nil)
            }
            let attrs: [NSAttributedString.Key: Any] = [
                .font: NSFont.systemFont(ofSize: 13),
                .foregroundColor: onAccent ? NSColor.alternateSelectedControlTextColor : .labelColor,
            ]
            let h = (name as NSString).size(withAttributes: attrs).height
            (name as NSString).draw(at: NSPoint(x: SecureListView.textX, y: r.minY + (r.height - h) / 2),
                                    withAttributes: attrs)
        }
    }

    // MARK: Accessibility: static text, nothing to select or press

    override func isAccessibilityElement() -> Bool { false }
    override func accessibilityChildren() -> [Any]? { elements }
    override func accessibilityPerformPress() -> Bool { false }
    override func accessibilityPerformPick() -> Bool { false }
    override func setAccessibilitySelectedChildren(_ accessibilitySelectedChildren: [Any]?) {}
    override func accessibilitySelectedChildren() -> [Any]? { nil }

    /// One row as accessibility sees it: its fixed name as static text.
    final class StaticRow: NSAccessibilityElement {
        private weak var list: MailboxListView?
        private let index: Int

        init(_ list: MailboxListView, _ index: Int) {
            self.list = list
            self.index = index
            super.init()
        }

        override func accessibilityRole() -> NSAccessibility.Role? { .staticText }
        override func accessibilityValue() -> Any? { list?.names[index] }
        override func accessibilityLabel() -> String? { list?.names[index] }
        override func accessibilityParent() -> Any? { list }
        override func isAccessibilityElement() -> Bool { true }
        override func isAccessibilitySelected() -> Bool { false }
        override func setAccessibilitySelected(_ accessibilitySelected: Bool) {}
        override func accessibilityPerformPress() -> Bool { false }
        override func accessibilityPerformPick() -> Bool { false }
        override func accessibilityFrame() -> NSRect {
            guard let list, let window = list.window else { return .zero }
            let r = NSRect(x: 0, y: CGFloat(index) * MailboxListView.rowHeight, width: list.bounds.width,
                           height: MailboxListView.rowHeight)
            return window.convertToScreen(list.convert(r, to: nil))
        }
        override func isAccessibilitySelectorAllowed(_ selector: Selector) -> Bool {
            // Reads only: no setter and no action.
            let name = NSStringFromSelector(selector)
            return !name.hasPrefix("setAccessibility") && !name.hasPrefix("accessibilityPerform")
        }
    }
}

/// A flipped document view, so the sidebar's column starts at the top.
private final class FlippedView: NSView {
    override var isFlipped: Bool { true }
}

/// `view` 16 pt in from the leading edge, 6 pt from the top.
private func padded(_ view: NSView) -> NSView {
    let box = NSView()
    view.translatesAutoresizingMaskIntoConstraints = false
    box.addSubview(view)
    NSLayoutConstraint.activate([
        view.topAnchor.constraint(equalTo: box.topAnchor, constant: 6),
        view.bottomAnchor.constraint(equalTo: box.bottomAnchor),
        view.leadingAnchor.constraint(equalTo: box.leadingAnchor, constant: 16),
        view.trailingAnchor.constraint(lessThanOrEqualTo: box.trailingAnchor),
    ])
    return box
}

final class SidebarView: NSView {
    override var isOpaque: Bool { true }

    /// The sidebar's plain background (no material; MailViewController):
    /// light and dark greys set apart from the list's text background.
    static let background = NSColor(name: nil) { appearance in
        appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            ? NSColor(white: 0.17, alpha: 1) : NSColor(white: 0.965, alpha: 1)
    }

    override func draw(_ dirtyRect: NSRect) {
        Self.background.setFill()
        dirtyRect.fill()
    }

    let mailboxes = MailboxListView()
    let requestList = SecureListView(style: .sidebar, symbol: "person.crop.circle.badge.questionmark")
    let contactList = SecureListView(style: .sidebar, symbol: "person.crop.circle")
    private(set) var addButton: HumanButton?
    private let requestsTitle = InterfaceText(L10n.requestsTitle, style: .section, width: 180, alignment: .left)
    private let contactsTitle = InterfaceText(L10n.contactsTitle, style: .section, width: 180, alignment: .left)
    private lazy var requestsHeader = padded(requestsTitle)
    private lazy var contactsHeader = padded(contactsTitle)

    init(target: AnyObject, add: Selector) {
        super.init(frame: NSRect(x: 0, y: 0, width: 220, height: 600))
        let scroll = NSScrollView()
        scroll.drawsBackground = false
        scroll.hasVerticalScroller = true
        scroll.autohidesScrollers = true
        scroll.borderType = .noBorder
        scroll.automaticallyAdjustsContentInsets = false
        let document = FlippedView()
        document.translatesAutoresizingMaskIntoConstraints = false
        scroll.documentView = document
        let column = NSStackView(views: [mailboxes, requestsHeader, requestList, contactsHeader, contactList])
        column.orientation = .vertical
        column.alignment = .leading
        column.spacing = 0
        column.detachesHiddenViews = true
        column.edgeInsets = NSEdgeInsets(top: 8, left: 0, bottom: 16, right: 0)
        for header in [requestsHeader, contactsHeader] { column.setCustomSpacing(4, after: header) }
        column.setCustomSpacing(16, after: mailboxes)
        column.setCustomSpacing(16, after: requestList)
        column.translatesAutoresizingMaskIntoConstraints = false
        document.addSubview(column)

        let add = HumanButton(title: L10n.sidebarAdd, target: target, action: add)
        add.image = NSImage(systemSymbolName: "plus", accessibilityDescription: nil)
        add.imagePosition = .imageLeading
        add.isBordered = false
        add.contentTintColor = .secondaryLabelColor
        add.font = NSFont.systemFont(ofSize: 13)
        addButton = add
        for v in [scroll, add] as [NSView] {
            v.translatesAutoresizingMaskIntoConstraints = false
            addSubview(v)
        }
        let inset = SecureListView.textX - 24
        NSLayoutConstraint.activate([
            scroll.topAnchor.constraint(equalTo: topAnchor),
            scroll.leadingAnchor.constraint(equalTo: leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: trailingAnchor),
            scroll.bottomAnchor.constraint(equalTo: add.topAnchor, constant: -8),
            add.leadingAnchor.constraint(equalTo: leadingAnchor, constant: inset),
            add.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -12),
            document.topAnchor.constraint(equalTo: scroll.contentView.topAnchor),
            document.leadingAnchor.constraint(equalTo: scroll.contentView.leadingAnchor),
            document.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            column.topAnchor.constraint(equalTo: document.topAnchor),
            column.leadingAnchor.constraint(equalTo: document.leadingAnchor),
            column.trailingAnchor.constraint(equalTo: document.trailingAnchor),
            column.bottomAnchor.constraint(equalTo: document.bottomAnchor),
            mailboxes.widthAnchor.constraint(equalTo: column.widthAnchor),
            requestList.widthAnchor.constraint(equalTo: column.widthAnchor),
            contactList.widthAnchor.constraint(equalTo: column.widthAnchor),
        ])
        mailboxes.nextKeyView = requestList
        requestList.nextKeyView = contactList
        update()
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Shows or hides the section titles for the lists' counts; call after
    /// setting their rows.
    func update() {
        requestsHeader.isHidden = requestList.count == 0
        requestList.isHidden = requestList.count == 0
        contactsHeader.isHidden = contactList.count == 0
        contactList.isHidden = contactList.count == 0
    }
}
