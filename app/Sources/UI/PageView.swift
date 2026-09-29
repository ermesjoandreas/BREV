// PageView.swift — the centred column of an onboarding page, the lock
// screen, the address page and a notice.
//
// Upholds CLAUDE.md §3.2 (these screens never show content; docs/PHASE2_DESIGN.md
// §5.3, §5.4; docs/UI_REDESIGN.md §2.9). It holds only InterfaceText blocks,
// SF Symbols and buttons, replaced as a whole when the screen's state
// changes: an optional 48 pt symbol, the title, the text in secondary
// colour, one large primary button, and quieter secondary actions under it.

import AppKit

final class PageView: NSView {
    /// Width of every text block in the column.
    static let columnWidth: CGFloat = 400

    private let stack = NSStackView()

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 1080, height: 680))
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 12
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor, constant: -16),
        ])
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Replaces the column with `symbol` (if any) and `views`, top to
    /// bottom: 16 pt after the symbol and after the title (the first view),
    /// 24 pt before the first button, 8 pt between buttons.
    func show(_ views: [NSView], symbol: String? = nil) {
        for old in stack.arrangedSubviews {
            stack.removeArrangedSubview(old)
            old.removeFromSuperview()
        }
        if let symbol {
            let icon = Self.symbol(symbol)
            stack.addArrangedSubview(icon)
            stack.setCustomSpacing(16, after: icon)
        }
        views.forEach { stack.addArrangedSubview($0) }
        if let title = views.first, views.count > 1 { stack.setCustomSpacing(16, after: title) }
        if let i = views.firstIndex(where: { $0 is NSButton && ($0 as? NSButton)?.bezelStyle != .inline }), i > 0 {
            stack.setCustomSpacing(24, after: views[i - 1])
        }
        for (a, b) in zip(views, views.dropFirst()) where a is NSButton && b is NSButton {
            stack.setCustomSpacing(8, after: a)
        }
    }

    /// Disables every button in the column, until the next `show`.
    func disableButtons() {
        func all(_ v: NSView) -> [NSButton] { (v as? NSButton).map { [$0] } ?? v.subviews.flatMap(all) }
        all(stack).forEach { $0.isEnabled = false }
    }

    /// The column's primary button: large; Return where the page had it.
    static func button(_ title: String, target: AnyObject, action: Selector, symbol: String? = nil) -> HumanButton {
        let button = HumanButton(title: title, target: target, action: action)
        button.controlSize = .large
        if let symbol {
            button.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
            button.imagePosition = .imageLeading
        }
        return button
    }

    /// A secondary action under the primary one (Slett alt og start på
    /// nytt): small and quiet, so it is never the loud option.
    static func secondary(_ title: String, target: AnyObject, action: Selector) -> HumanButton {
        let button = HumanButton(title: title, target: target, action: action)
        button.bezelStyle = .inline
        button.controlSize = .small
        return button
    }

    /// A 48 pt SF Symbol in secondary colour. Never content.
    static func symbol(_ name: String, size: CGFloat = 48) -> NSImageView {
        let icon = NSImageView()
        let config = NSImage.SymbolConfiguration(pointSize: size, weight: .light)
            .applying(.init(hierarchicalColor: .secondaryLabelColor))
        icon.image = NSImage(systemSymbolName: name, accessibilityDescription: nil)?.withSymbolConfiguration(config)
        return icon
    }

    /// A row of the rules page: a symbol and a left-aligned text.
    static func rule(_ symbol: String, _ text: String) -> NSView {
        let icon = Self.symbol(symbol, size: 18)
        icon.translatesAutoresizingMaskIntoConstraints = false
        icon.widthAnchor.constraint(equalToConstant: 28).isActive = true
        let row = NSStackView(views: [icon, InterfaceText(text, style: .secondary, width: columnWidth - 40,
                                                          alignment: .natural)])
        row.orientation = .horizontal
        row.alignment = .top
        row.spacing = 12
        return row
    }
}
