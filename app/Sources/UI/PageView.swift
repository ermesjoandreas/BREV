// PageView.swift — the centred column of an onboarding page or the lock screen.
//
// Upholds CLAUDE.md §3.2 (these screens never show content; docs/PHASE2_DESIGN.md
// §5.3, §5.4). It holds only InterfaceText blocks and buttons, replaced as a
// whole when the screen's state changes.

import AppKit

final class PageView: NSView {
    /// Width of every text block in the column.
    static let columnWidth: CGFloat = 460

    private let stack = NSStackView()

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: 600))
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 14
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Replaces the column with `views`, top to bottom. A little more space
    /// follows the first view (the title).
    func show(_ views: [NSView]) {
        for old in stack.arrangedSubviews {
            stack.removeArrangedSubview(old)
            old.removeFromSuperview()
        }
        views.forEach { stack.addArrangedSubview($0) }
        if let title = views.first, views.count > 1 {
            stack.setCustomSpacing(24, after: title)
        }
    }

    /// Disables every button in the column, until the next `show`.
    func disableButtons() {
        for case let button as NSButton in stack.arrangedSubviews {
            button.isEnabled = false
        }
    }

    /// A button in the column's style.
    static func button(_ title: String, target: AnyObject, action: Selector) -> HumanButton {
        let button = HumanButton(title: title, target: target, action: action)
        button.controlSize = .large
        return button
    }
}
