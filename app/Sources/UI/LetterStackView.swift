// LetterStackView.swift — the letters of one thread, one under the other.
//
// Upholds CLAUDE.md §1.2, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §6.4, §7.2;
// docs/UI_REDESIGN.md §2.5). The flipped document view of the reading
// pane's NSScrollView; scrolling is the stock scroll view's. A thread holds
// one letter since Phase 3: then the pane shows only its body (a
// SecureTextView), and the ReadingHeaderView above the pane shows the
// subject, the name, the date and the badge. An older thread with more
// letters shows each after a hairline and a header ("Sendt …" or
// "Mottatt …" and a date: metadata, drawn by an OpaqueView) above a
// SecureTextView with the body. A received letter's header has its badge at
// the right (docs/AUTHORSHIP.md §6): «Skrevet i Brev · klasse A» or «Ikke
// verifisert», fixed text from L10n, never content, on a HumanButton whose
// press (a human's only) asks for the detail (`onBadge`). The badges are
// the only thing in the pane that accessibility sees: their text. Frames
// come from each body's layout height at the scroll view's width. `clear()`
// wipes every body, removes the views and runs GlyphFlush, which is the
// letter view's teardown (§6.4); a new thread, a reload and the lock
// sequence all go through it.

import AppKit

final class LetterStackView: OpaqueView {
    struct Letter {
        /// "Sendt <date>" or "Mottatt <date>": metadata, never content.
        let header: String
        /// The body, owned and wiped by the view from `show` on.
        let body: SecretText
        /// A received letter's badge (L10n.badge); nil for a sent letter.
        var badge: String? = nil
    }

    static let top: CGFloat = 20
    static let headerHeight: CGFloat = 28
    static let gap: CGFloat = 24

    /// A human pressed the badge of the letter at this index.
    var onBadge: (Int) -> Void = { _ in }

    private var letters: [(header: LetterHeaderView, body: SecureTextView, badge: HumanButton?)] = []

    var isEmpty: Bool { letters.isEmpty }

    /// The badges shown, in letter order (nil for a sent letter).
    var badges: [HumanButton?] { letters.map(\.badge) }

    /// Replaces the letters shown (the old bodies are wiped first).
    func show(_ new: [Letter]) {
        clear()
        let single = new.count == 1
        for (i, l) in new.enumerated() {
            let header = LetterHeaderView(l.header)
            let body = SecureTextView()
            body.show(l.body)
            header.isHidden = single
            addSubview(header)
            addSubview(body)
            let badge = (single ? nil : l.badge).map { title -> HumanButton in
                let b = HumanButton(title: title, target: self, action: #selector(badgePressed(_:)))
                b.bezelStyle = .inline
                b.controlSize = .small
                b.tag = i
                b.sizeToFit()
                addSubview(b)
                return b
            }
            letters.append((header, body, badge))
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
            l.badge?.removeFromSuperview()
        }
        letters = []
        relayout()
        GlyphFlush.flush()
    }

    /// Accessibility sees the badges' text and nothing else of the pane.
    override func accessibilityChildren() -> [Any]? {
        letters.compactMap(\.badge)
    }

    /// A badge's action (HumanButton: only a human's press gets here).
    @objc private func badgePressed(_ sender: NSButton) {
        onBadge(sender.tag)
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
            l.header.frame = NSRect(x: 0, y: y, width: width, height: l.header.isHidden ? 0 : Self.headerHeight)
            if let badge = l.badge {
                let size = badge.frame.size
                badge.frame = NSRect(x: max(0, width - SecureTextView.inset - size.width),
                                     y: y + (Self.headerHeight - size.height) / 2, width: size.width, height: size.height)
            }
            y += l.header.frame.height
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
