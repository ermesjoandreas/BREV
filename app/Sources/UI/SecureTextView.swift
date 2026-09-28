// SecureTextView.swift — one letter's body, drawn line by line.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §6.4,
// §7.2). The body is a SecretText that this view owns: `clear()` wipes it,
// and LetterStackView clears every letter on a new selection, a reload and
// lock. It is laid out by TextLayout (CTLine only, at most 448 units per
// line) when the width changes, and only the lines that meet the rect being
// drawn are made into CTLines. There is no selection, no caret and no mouse
// handling, so nothing can be selected, copied or dragged out. The view is
// a ContentView: not an accessibility element, no menu, no Services.

import AppKit

final class SecureTextView: ContentView {
    /// Left and right margin of the text.
    static let inset: CGFloat = 16

    private let layout = TextLayout(font: ContentView.contentFont)
    private var text: SecretText?
    /// The width the lines were broken for; -1 when there are none.
    private var laidOutWidth: CGFloat = -1

    /// Shows `text` from now on. The view owns it and wipes it in `clear()`.
    func show(_ text: SecretText) {
        clear()
        self.text = text
    }

    /// The height the text needs at `width`. Breaks the lines again only
    /// when the width changed.
    func height(forWidth width: CGFloat) -> CGFloat {
        guard let text else { return 0 }
        if width != laidOutWidth {
            layout.layout(text, width: max(width - 2 * Self.inset, 1))
            laidOutWidth = width
            needsDisplay = true
        }
        return layout.height
    }

    /// Wipes the text and forgets its lines.
    func clear() {
        text?.wipe()
        text = nil
        layout.reset()
        laidOutWidth = -1
        needsDisplay = true
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        if newSize.width != laidOutWidth { _ = height(forWidth: newSize.width) }
    }

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        guard let text, !layout.lines.isEmpty else { return }
        let h = layout.lineHeight
        let first = max(Int((rect.minY / h).rounded(.down)), 0)
        let last = min(Int((rect.maxY / h).rounded(.up)), layout.lines.count)
        guard first < last else { return }
        ctx.saveGState()
        ctx.setFillColor(color(.labelColor))
        layout.draw(text, lines: first..<last, in: ctx, x: Self.inset, top: 0)
        ctx.restoreGState()
    }
}
