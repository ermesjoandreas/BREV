// LetterStackView.swift — the letters of one thread, one under the other.
//
// Upholds CLAUDE.md §1.2, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §6.4, §7.2).
// The flipped document view of the letter pane's NSScrollView; scrolling is
// the stock scroll view's. Each letter is a header ("Sendt …" or
// "Mottatt …" and a date: metadata, drawn by an OpaqueView) above a
// SecureTextView with the body. Frames come from each body's layout height
// at the scroll view's width. `clear()` wipes every body, removes the views
// and runs GlyphFlush, which is the letter view's teardown (§6.4); a new
// thread, a reload and the lock sequence all go through it.

import AppKit

final class LetterStackView: OpaqueView {
    struct Letter {
        /// "Sendt <date>" or "Mottatt <date>": metadata, never content.
        let header: String
        /// The body, owned and wiped by the view from `show` on.
        let body: SecretText
    }

    static let top: CGFloat = 12
    static let headerHeight: CGFloat = 24
    static let gap: CGFloat = 20

    private var letters: [(header: LetterHeaderView, body: SecureTextView)] = []

    var isEmpty: Bool { letters.isEmpty }

    /// Replaces the letters shown (the old bodies are wiped first).
    func show(_ new: [Letter]) {
        clear()
        for l in new {
            let header = LetterHeaderView(l.header)
            let body = SecureTextView()
            body.show(l.body)
            addSubview(header)
            addSubview(body)
            letters.append((header, body))
        }
        relayout()
    }

    /// Wipes every body and removes the letters. Then GlyphFlush replaces
    /// what Core Text kept alive of their lines.
    func clear() {
        guard !letters.isEmpty else { return }
        for l in letters {
            l.body.clear()
            l.header.removeFromSuperview()
            l.body.removeFromSuperview()
        }
        letters = []
        relayout()
        GlyphFlush.flush()
    }

    override func resize(withOldSuperviewSize oldSize: NSSize) {
        relayout()
    }

    /// Stacks the letters at the scroll view's width; the view is at least
    /// as tall as the scroll view.
    private func relayout() {
        let visible = superview?.bounds.size ?? bounds.size
        let width = visible.width
        var y = Self.top
        for l in letters {
            l.header.frame = NSRect(x: 0, y: y, width: width, height: Self.headerHeight)
            y += Self.headerHeight
            let h = ceil(l.body.height(forWidth: width))
            l.body.frame = NSRect(x: 0, y: y, width: width, height: h)
            y += h + Self.gap
        }
        setFrameSize(NSSize(width: width, height: max(y, visible.height)))
    }
}

/// A letter's header: a separator line and "Sendt …"/"Mottatt …".
private final class LetterHeaderView: ContentView {
    private let text: String

    init(_ text: String) {
        self.text = text
        super.init(frame: .zero)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        ctx.saveGState()
        ctx.setFillColor(color(.separatorColor))
        ctx.fill(CGRect(x: SecureTextView.inset, y: 0, width: bounds.width - 2 * SecureTextView.inset, height: 1))
        drawMeta(text, in: ctx, x: SecureTextView.inset, baseline: bounds.height - 6, color: color(.secondaryLabelColor))
        ctx.restoreGState()
    }
}
