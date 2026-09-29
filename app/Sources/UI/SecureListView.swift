// SecureListView.swift — the sidebar's contacts and requests, and the
// message list.
//
// Upholds CLAUDE.md §1.2, §1.3, §1.10 and §3.2 (docs/PHASE2_DESIGN.md §7.2;
// docs/PHASE4_DESIGN.md §6.1; docs/UI_REDESIGN.md §2.3, §2.4). Rows have a
// fixed height. Each row draws only the first line of its SecretTexts (a
// name or a subject: at most 448 units, up to the first line break, clipped
// at its column's edge) through TextLayout, never a body. Two styles:
// - sidebar (28 pt): an SF Symbol, the name, and for a contact whose key
//   changed an orange dot at the end; a blocked contact's name is dimmed.
//   The list is exactly as tall as its rows, so two lists stack in one
//   scroll view.
// - messages (56 pt): line 1 (a name, or a subject) in semibold with a date
//   at the end, line 2 (a subject, or «Mottatt»/«Sendt») with a received
//   letter's class chip at the end; a hairline between rows. The list is the
//   document view of an NSScrollView and at least as tall as it.
// Symbols, dates, «Mottatt»/«Sendt», the dot and the chips are fixed
// strings and metadata, drawn in this view's protected layer; the texts are
// content. The list owns the rows' SecretTexts: setting new rows or
// `clear()` wipes the old ones. Selection is of rows, never of text: a click
// or ↑/↓ selects a row and calls `onSelect` with its index. As a
// ContentView it is not an accessibility element and has no menu, so
// accessibility can neither read nor select a row.

import AppKit

final class SecureListView: ContentView {
    enum Style {
        case sidebar
        case messages
    }

    /// A received letter's class («Klasse C») or «Ikke verifisert»
    /// (`warning`): fixed text, never content.
    struct Chip {
        let text: String
        let warning: Bool
    }

    struct Row {
        /// A name or a subject, owned and wiped by the list.
        let text: SecretText
        /// Messages: line 2's subject under a name, owned and wiped too.
        var text2: SecretText? = nil
        /// Messages: a date at the end of line 1. Metadata.
        var meta: String? = nil
        /// Messages: line 2 when it has no subject («Mottatt»/«Sendt»).
        var note: String? = nil
        /// Messages: a received letter's chip.
        var chip: Chip? = nil
        /// Sidebar: a contact whose key changed (the orange dot).
        var flag = false
        /// Sidebar: a blocked contact (its name dimmed).
        var dim = false
    }

    /// Where a sidebar row's text starts, after its symbol.
    static let textX: CGFloat = 40
    /// Where a message row's text starts.
    static let messageX: CGFloat = 20

    let style: Style
    let rowHeight: CGFloat
    /// The sidebar's symbol for every row.
    private let symbol: String?
    /// A human selected row `index` (click or ↑/↓). Not called by `setRows`.
    var onSelect: (Int) -> Void = { _ in }
    private(set) var selected: Int?

    private let regular = TextLayout(font: ContentView.fontF1)
    private let bold = TextLayout(font: ContentView.fontF2)
    private var rows: [Row] = []

    init(style: Style, symbol: String? = nil) {
        self.style = style
        self.symbol = symbol
        rowHeight = style == .sidebar ? 28 : 56
        super.init(frame: NSRect(x: 0, y: 0, width: 200, height: rowHeight))
    }

    required init?(coder: NSCoder) {
        nil
    }

    var count: Int { rows.count }

    /// Replaces the rows, wiping the old ones' texts and pixels, and selects
    /// `selected` without calling `onSelect`.
    func setRows(_ new: [Row], selected: Int?) {
        rows.forEach { $0.text.wipe(); $0.text2?.wipe() }
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

    /// Row `index` (or none) selected, the rows kept, without calling
    /// `onSelect`: the sidebar's one selection moved (a row of another list
    /// was selected, or a reload kept a contact).
    func setSelected(_ index: Int?) {
        let i = index.flatMap { rows.indices.contains($0) ? $0 : nil }
        guard i != selected else { return }
        selected = i
        needsDisplay = true
    }

    /// No row selected, the rows kept, without calling `onSelect`.
    func deselect() {
        setSelected(nil)
    }

    // MARK: - Size

    /// The sidebar's lists: as tall as their rows (auto layout).
    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: CGFloat(rows.count) * rowHeight)
    }

    /// The message list: the scroll view's width, and at least its height.
    override func resize(withOldSuperviewSize oldSize: NSSize) {
        if style == .messages { fitSize() } else { super.resize(withOldSuperviewSize: oldSize) }
    }

    private func fitSize() {
        guard style == .messages else { return invalidateIntrinsicContentSize() }
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
        guard !InputFilter.isSynthetic(event) else { return }
        window?.makeFirstResponder(self)
        let p = convert(event.locationInWindow, from: nil)
        let i = Int((p.y / rowHeight).rounded(.down))
        if rows.indices.contains(i) { choose(i) }
    }

    override func keyDown(with event: NSEvent) {
        guard !InputFilter.isSynthetic(event) else { return }
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
        ctx.saveGState()
        for i in first..<last {
            let r = rowRect(i)
            let isSelected = i == selected
            if isSelected {
                let box = style == .sidebar ? r.insetBy(dx: 8, dy: 1) : r.insetBy(dx: 8, dy: 2)
                ctx.setFillColor(color(focused ? .selectedContentBackgroundColor
                                               : .unemphasizedSelectedContentBackgroundColor))
                ctx.addPath(CGPath(roundedRect: box, cornerWidth: 6, cornerHeight: 6, transform: nil))
                ctx.fillPath()
            }
            let onAccent = isSelected && focused
            switch style {
            case .sidebar:
                drawSidebarRow(rows[i], r, onAccent: onAccent, in: ctx)
            case .messages:
                // A hairline under each row, but not beside a selection.
                if !isSelected && selected != i + 1 && i + 1 < rows.count {
                    ctx.setFillColor(color(.separatorColor))
                    ctx.fill(CGRect(x: Self.messageX, y: r.maxY - 0.5, width: r.width - Self.messageX, height: 0.5))
                }
                drawMessageRow(rows[i], r, onAccent: onAccent, in: ctx)
            }
        }
        ctx.restoreGState()
    }

    private func drawSidebarRow(_ row: Row, _ r: CGRect, onAccent: Bool, in ctx: CGContext) {
        let text: NSColor = onAccent ? .alternateSelectedControlTextColor : row.dim ? .tertiaryLabelColor : .labelColor
        if let symbol {
            drawSymbol(symbol, in: ctx, rect: CGRect(x: 14, y: r.minY + 5, width: 18, height: 18),
                       color: onAccent ? .alternateSelectedControlTextColor : .secondaryLabelColor)
        }
        let dot: CGFloat = 6
        let end = r.maxX - 16 - (row.flag ? dot + 6 : 0)
        let ascent = CTFontGetAscent(regular.font), descent = CTFontGetDescent(regular.font)
        ctx.saveGState()
        ctx.clip(to: CGRect(x: Self.textX, y: r.minY, width: max(end - Self.textX, 0), height: r.height))
        ctx.setFillColor(color(text))
        regular.drawLine(row.text, TextLayout.firstLine(row.text), in: ctx, x: Self.textX,
                         baseline: r.minY + (r.height - ascent - descent) / 2 + ascent)
        ctx.restoreGState()
        if row.flag {
            ctx.setFillColor(color(.systemOrange))
            ctx.fillEllipse(in: CGRect(x: r.maxX - 16 - dot, y: r.midY - dot / 2, width: dot, height: dot))
        }
    }

    private func drawMessageRow(_ row: Row, _ r: CGRect, onAccent: Bool, in ctx: CGContext) {
        let x = Self.messageX, right = r.maxX - 16
        let text = color(onAccent ? .alternateSelectedControlTextColor : .labelColor)
        let meta = color(onAccent ? .alternateSelectedControlTextColor : .secondaryLabelColor)
        let line1 = r.minY + 10 + CTFontGetAscent(bold.font)
        let line2 = r.minY + 30 + CTFontGetAscent(regular.font)
        // Line 1: the name or subject, and the date at the end.
        var end1 = right
        if let date = row.meta {
            let w = Self.metaWidth(date)
            drawMeta(date, in: ctx, x: right - w, baseline: line1, color: meta)
            end1 = right - w - 8
        }
        ctx.saveGState()
        ctx.clip(to: CGRect(x: x, y: r.minY, width: max(end1 - x, 0), height: r.height / 2 + 4))
        ctx.setFillColor(text)
        bold.drawLine(row.text, TextLayout.firstLine(row.text), in: ctx, x: x, baseline: line1)
        ctx.restoreGState()
        // Line 2: the subject or the direction, and the chip at the end.
        var end2 = right
        if let chip = row.chip {
            let w = Self.metaWidth(chip.text) + 12
            let box = CGRect(x: right - w, y: line2 - 11, width: w, height: 15)
            let tint: NSColor = onAccent ? .alternateSelectedControlTextColor
                : chip.warning ? .systemOrange : .secondaryLabelColor
            ctx.setStrokeColor(color(onAccent ? tint : chip.warning ? .systemOrange : .separatorColor))
            ctx.setLineWidth(1)
            ctx.addPath(CGPath(roundedRect: box.insetBy(dx: 0.5, dy: 0.5), cornerWidth: 4, cornerHeight: 4,
                               transform: nil))
            ctx.strokePath()
            drawMeta(chip.text, in: ctx, x: box.minX + 6, baseline: line2, color: color(tint))
            end2 = box.minX - 8
        }
        if let text2 = row.text2 {
            ctx.saveGState()
            ctx.clip(to: CGRect(x: x, y: r.midY - 4, width: max(end2 - x, 0), height: r.height / 2 + 4))
            ctx.setFillColor(text)
            regular.drawLine(text2, TextLayout.firstLine(text2), in: ctx, x: x, baseline: line2)
            ctx.restoreGState()
        } else if let note = row.note {
            drawMeta(note, in: ctx, x: x, baseline: line2, color: meta)
        }
    }
}
