// InterfaceText.swift — a block of fixed interface text.
//
// Upholds CLAUDE.md §1.2 and §3.2 (docs/PHASE2_DESIGN.md §5.6): the
// onboarding pages, the lock screen and ConfirmSheet show only strings from
// Localizable.strings, never content. They are drawn here instead of with
// an AppKit text field (the forbidden-API check in scripts/test.sh keeps
// those out of app/Sources), and are readable by VoiceOver because they are
// not content. Never pass anything to this view that did not come from L10n.

import AppKit

final class InterfaceText: NSView {
    enum Style {
        /// A screen's title.
        case title
        /// A sheet's title.
        case heading
        case body

        var font: NSFont {
            switch self {
            case .title: return NSFont.systemFont(ofSize: 22, weight: .semibold)
            case .heading: return NSFont.systemFont(ofSize: 15, weight: .semibold)
            case .body: return NSFont.systemFont(ofSize: 13)
            }
        }
    }

    private let text: String
    private let attributes: [NSAttributedString.Key: Any]
    private let size: NSSize

    /// `text` wrapped to `width` points.
    init(_ text: String, style: Style = .body, width: CGFloat, alignment: NSTextAlignment = .center) {
        self.text = text
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = alignment
        attributes = [.font: style.font, .foregroundColor: NSColor.labelColor, .paragraphStyle: paragraph]
        let height = text.boundingRect(with: NSSize(width: width, height: .greatestFiniteMagnitude),
                                       options: .usesLineFragmentOrigin, attributes: attributes).height
        size = NSSize(width: width, height: ceil(height))
        super.init(frame: NSRect(origin: .zero, size: size))
    }

    required init?(coder: NSCoder) {
        nil
    }

    override var isFlipped: Bool { true }
    override var intrinsicContentSize: NSSize { size }

    override func draw(_ dirtyRect: NSRect) {
        text.draw(with: bounds, options: .usesLineFragmentOrigin, attributes: attributes)
    }

    override func isAccessibilityElement() -> Bool { true }
    override func accessibilityRole() -> NSAccessibility.Role? { .staticText }
    override func accessibilityValue() -> Any? { text }
}
