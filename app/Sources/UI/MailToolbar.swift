// MailToolbar.swift — the mail screen's toolbar: Nytt brev and Lås.
//
// Upholds CLAUDE.md §1.1, §1.4 and §1.5 (docs/UI_REDESIGN.md §2.2). A
// unified toolbar with two standard items: an SF Symbol and a fixed label
// each, no tooltip. Both are harmless and already in the menu, which
// accessibility can press too (MainMenu.swift): Nytt brev opens an empty
// compose sheet, and Lås locks. Every button that sends, confirms or
// unlocks stays a HumanButton. The user cannot customise the toolbar or
// change its display mode, and nothing about it is saved
// (`autosavesConfiguration = false`). No search field, no share item, no
// sidebar toggle. A tracking separator follows the divider between the
// list and the reading pane, so Nytt brev sits at the start of the reading
// pane and Lås at the end, as in Mail. It exists only while the mail screen
// is shown (RootViewController); its items' target is the mail screen.

import AppKit

final class MailToolbar: NSObject, NSToolbarDelegate {
    static let newLetter = NSToolbarItem.Identifier("no.brev.toolbar.new")
    static let lock = NSToolbarItem.Identifier("no.brev.toolbar.lock")
    static let divider = NSToolbarItem.Identifier("no.brev.toolbar.divider")

    let toolbar = NSToolbar(identifier: "no.brev.mail")
    private weak var target: AnyObject?
    private let newAction: Selector
    private let lockAction: Selector
    /// The mail screen's split view, whose divider 1 (list | reading pane)
    /// the separator tracks.
    private weak var split: NSSplitView?

    init(target: AnyObject, new: Selector, lock: Selector, split: NSSplitView) {
        self.target = target
        newAction = new
        lockAction = lock
        self.split = split
        super.init()
        toolbar.delegate = self
        toolbar.displayMode = .iconOnly
        toolbar.allowsUserCustomization = false
        toolbar.autosavesConfiguration = false
        if #available(macOS 15.0, *) { toolbar.allowsDisplayModeCustomization = false }
    }

    func toolbarDefaultItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        [Self.divider, Self.newLetter, .flexibleSpace, Self.lock]
    }

    func toolbarAllowedItemIdentifiers(_ toolbar: NSToolbar) -> [NSToolbarItem.Identifier] {
        toolbarDefaultItemIdentifiers(toolbar)
    }

    func toolbar(_ toolbar: NSToolbar, itemForItemIdentifier id: NSToolbarItem.Identifier,
                 willBeInsertedIntoToolbar flag: Bool) -> NSToolbarItem? {
        if id == Self.divider {
            guard let split else { return nil }
            return NSTrackingSeparatorToolbarItem(identifier: id, splitView: split, dividerIndex: 1)
        }
        let item = NSToolbarItem(itemIdentifier: id)
        let (label, symbol, action) = id == Self.newLetter
            ? (L10n.toolbarNew, "square.and.pencil", newAction)
            : (L10n.toolbarLock, "lock", lockAction)
        item.label = label
        item.paletteLabel = label
        item.image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)
        item.target = target
        item.action = action
        item.isBordered = false
        return item
    }

    /// The item with `id`, for validation and the tools' checks.
    func item(_ id: NSToolbarItem.Identifier) -> NSToolbarItem? {
        toolbar.items.first { $0.itemIdentifier == id }
    }
}
