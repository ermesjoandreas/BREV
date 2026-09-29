// SecureListView.swift — the contacts list and the thread list.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §7.2;
// docs/PHASE4_DESIGN.md §6.1: also the contact requests, by address).
// Rows have a fixed height. Each row draws the first line of its SecretText
// (a name or a subject: at most 448 units, up to the first line break,
// clipped at the row's edge) through TextLayout, and optionally one line of
// metadata (a date). The list owns the rows' SecretTexts: setting new rows
// or `clear()` wipes the old ones. Selection is of rows, never of text: a
// click or ↑/↓ selects a row and calls `onSelect` with its index. The list
// is the document view of an NSScrollView and follows its width. As a
// ContentView it is not an accessibility element and has no menu.

import AppKit

final class SecureListView: ContentView {
    struct Row {
        /// A name or a subject, owned and wiped by the list.
        let text: SecretText
        /// A date: metadata, never content.
        let meta: String?
    }

    static let inset: CGFloat = 12

    let rowHeight: CGFloat
    /// A human selected row `index` (click or ↑/↓). Not called by `setRows`.
    var onSelect: (Int) -> Void = { _ in }
    private(set) var selected: Int?

    private let layout = TextLayout(font: ContentView.contentFont)
    private var rows: [Row] = []

    init(rowHeight: CGFloat) {
        self.rowHeight = rowHeight
        super.init(frame: NSRect(x: 0, y: 0, width: 200, height: rowHeight))
    }

    required init?(coder: NSCoder) {
        nil
    }

    var count: Int { rows.count }

    /// Replaces the rows, wiping the old ones' texts and pixels, and selects
    /// `selected` without calling `onSelect`.
    func setRows(_ new: [Row], selected: Int?) {
        rows.forEach { $0.text.wipe() }
        blank()
        rows = new
        self.selected = selected.flatMap { rows.indices.contains($0) ? $0 : nil }
        fitSize()
        needsDisplay = true
        if let s = self.selected { scrollToVisible(rowRect(s)) }
    }

    /// Wipes every row's text and removes the rows.
    func clear() {
        setRows([], selected: nil)
    }

    /// No row selected, the rows kept, without calling `onSelect`: another
    /// list's row was selected (the requests and the contacts share the
    /// header).
    func deselect() {
        guard selected != nil else { return }
        selected = nil
        needsDisplay = true
    }

    // MARK: - Size: the scroll view's width, and at least its height

    override func resize(withOldSuperviewSize oldSize: NSSize) {
        fitSize()
    }

    private func fitSize() {
        let visible = superview?.bounds.size ?? bounds.size
        setFrameSize(NSSize(width: visible.width, height: max(CGFloat(rows.count) * rowHeight, visible.height)))
    }

    private func rowRect(_ i: Int) -> NSRect {
        NSRect(x: 0, y: CGFloat(i) * rowHeight, width: bounds.width, height: rowHeight)
    }

    // MARK: - Selection by click and ↑/↓

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
        window?.makeFirstResponder(self)
        let p = convert(event.locationInWindow, from: nil)
        let i = Int((p.y / rowHeight).rounded(.down))
        if rows.indices.contains(i) { choose(i) }
    }

    override func keyDown(with event: NSEvent) {
        switch event.keyCode {
        case 125: choose(min((selected ?? -1) + 1, rows.count - 1))   // ↓
        case 126: choose(max((selected ?? rows.count) - 1, 0))        // ↑
        default: super.keyDown(with: event)
        }
    }

    private func choose(_ i: Int) {
        guard rows.indices.contains(i), i != selected else { return }
        selected = i
        needsDisplay = true
        scrollToVisible(rowRect(i))
        onSelect(i)
    }

    // MARK: - Drawing

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        guard !rows.isEmpty else { return }
        let first = max(Int((rect.minY / rowHeight).rounded(.down)), 0)
        let last = min(Int((rect.maxY / rowHeight).rounded(.up)), rows.count)
        guard first < last else { return }
        let focused = window?.firstResponder === self
        let ascent = CTFontGetAscent(layout.font)
        let descent = CTFontGetDescent(layout.font)
        ctx.saveGState()
        for i in first..<last {
            let r = rowRect(i)
            let isSelected = i == selected
            if isSelected {
                ctx.setFillColor(color(focused ? .selectedContentBackgroundColor
                                               : .unemphasizedSelectedContentBackgroundColor))
                ctx.fill(r.insetBy(dx: 4, dy: 1))
            }
            let text = color(isSelected && focused ? .alternateSelectedControlTextColor : .labelColor)
            let meta = color(isSelected && focused ? .alternateSelectedControlTextColor : .secondaryLabelColor)
            // One line of text, centred; with metadata, text on top and the
            // date below it.
            let lineHeight = ascent + descent
            let baseline = rows[i].meta == nil
                ? r.minY + (rowHeight - lineHeight) / 2 + ascent
                : r.minY + 7 + ascent
            ctx.saveGState()
            ctx.clip(to: r.insetBy(dx: Self.inset, dy: 0))
            ctx.setFillColor(text)
            layout.drawLine(rows[i].text, TextLayout.firstLine(rows[i].text), in: ctx, x: Self.inset,
                            baseline: baseline)
            if let m = rows[i].meta {
                drawMeta(m, in: ctx, x: Self.inset, baseline: r.maxY - 8, color: meta)
            }
            ctx.restoreGState()
        }
        ctx.restoreGState()
    }
}
