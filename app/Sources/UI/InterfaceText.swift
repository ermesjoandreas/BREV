// InterfaceText.swift — a block of fixed interface text.
//
// Upholds CLAUDE.md §1.2 and §3.2 (docs/PHASE2_DESIGN.md §5.6): the
// onboarding pages, the lock screen and ConfirmSheet show only strings from
// Localizable.strings, never content. They are drawn here instead of with
// an AppKit text field (the forbidden-API check in scripts/test.sh keeps
// those out of app/Sources), and are readable by VoiceOver because they are
// not content. Never pass anything to this view that did not come from L10n
// (or a date or a count). The styles are those of docs/UI_REDESIGN.md §3.1;
// a text can be rewrapped to a new width (`setWidth`), for a column that
// changes width.

import AppKit

final class InterfaceText: NSView {
    enum Style {
        /// A screen's title: 22 semibold.
        case title
        /// A sheet's title: 15 semibold.
        case heading
        /// 13 regular, the label colour.
        case body
        /// 13 regular, secondary: a page's text, a form's label.
        case secondary
        /// 11 regular, secondary: a state or a note.
        case caption
        /// 11 semibold, secondary: a sidebar or form section's title.
        case section
        /// 15 semibold, secondary: an empty list's line.
        case empty
        /// 13 regular, tertiary: the empty reading pane.
        case placeholder

        var font: NSFont {
            switch self {
            case .title: return NSFont.systemFont(ofSize: 22, weight: .semibold)
            case .heading, .empty: return NSFont.systemFont(ofSize: 15, weight: .semibold)
            case .body, .secondary, .placeholder: return NSFont.systemFont(ofSize: 13)
            case .caption: return NSFont.systemFont(ofSize: 11)
            case .section: return NSFont.systemFont(ofSize: 11, weight: .semibold)
            }
        }

        var color: NSColor {
            switch self {
            case .title, .heading, .body: return .labelColor
            case .secondary, .caption, .section, .empty: return .secondaryLabelColor
            case .placeholder: return .tertiaryLabelColor
            }
        }
    }

    private let text: String
    private var attributes: [NSAttributedString.Key: Any]
    private var size: NSSize

    /// `text` wrapped to `width` points, in `style`'s font and colour (or
    /// `color`).
    init(_ text: String, style: Style = .body, width: CGFloat, alignment: NSTextAlignment = .center,
         color: NSColor? = nil) {
        self.text = text
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = alignment
        attributes = [.font: style.font, .foregroundColor: color ?? style.color, .paragraphStyle: paragraph]
        size = .zero
        super.init(frame: .zero)
        setWidth(width)
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Wraps the text to `width` points from now on.
    func setWidth(_ width: CGFloat) {
        let w = max(width, 1)
        guard w != size.width else { return }
        let height = text.boundingRect(with: NSSize(width: w, height: .greatestFiniteMagnitude),
                                       options: .usesLineFragmentOrigin, attributes: attributes).height
        size = NSSize(width: w, height: ceil(height))
        setFrameSize(size)
        invalidateIntrinsicContentSize()
        needsDisplay = true
    }

    /// Draws in `font` from now on (a sheet's bold 13 pt title).
    func setFont(_ font: NSFont) {
        attributes[.font] = font
        let w = size.width
        size.width = -1
        setWidth(w)
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
