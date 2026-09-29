// ReadingHeaderView.swift — the open letter's header in the reading pane.
//
// Upholds CLAUDE.md §1.2, §1.5, §1.10 and §3.2 (docs/UI_REDESIGN.md §2.5;
// docs/AUTHORSHIP.md §6). The subject (17 pt semibold) and the other
// party's name are content: two ContactTextViews, each drawing only the
// first line of a copy the header owns, clipped at its edge, through the
// protected layer. «Fra:» (a received letter) or «Til:» (a sent one) is a
// fixed label; the date is metadata, drawn by a MetaView in its own
// protected layer as the letter's meta lines always were. For a received
// letter the badge follows: «Skrevet i Brev · klasse A» or «Ikke
// verifisert», fixed text from L10n on a HumanButton whose press (a
// human's only) asks for the detail (`onBadge`, ProofSheet). A new letter
// and `clear()` (a new selection, the lock sequence) wipe the copies and
// zero the pixels. No tooltip, no popover.

import AppKit

/// One line of metadata (a date), right-aligned, in the protected layer.
final class MetaView: ContentView {
    private(set) var text: String?

    func show(_ text: String?) {
        self.text = text
        blank()
        needsDisplay = true
    }

    override func drawContent(in ctx: CGContext, rect: CGRect) {
        guard let text else { return }
        let ascent = CTFontGetAscent(Self.metaFont), descent = CTFontGetDescent(Self.metaFont)
        drawMeta(text, in: ctx, x: bounds.width - Self.metaWidth(text),
                 baseline: (bounds.height - ascent - descent) / 2 + ascent, color: color(.secondaryLabelColor))
    }
}

final class ReadingHeaderView: NSView {
    static let margin: CGFloat = 24

    /// A human pressed the badge.
    var onBadge: () -> Void = {}

    let subjectView = ContactTextView(rows: 1, font: ContentView.fontF3)
    let nameView = ContactTextView(rows: 1, font: ContentView.fontF2)
    let dateView = MetaView(frame: .zero)
    private(set) var badge: HumanButton?
    private let from = InterfaceText(L10n.readingFrom, style: .secondary, width: 40, alignment: .left)
    private let to = InterfaceText(L10n.readingTo, style: .secondary, width: 40, alignment: .left)

    init() {
        super.init(frame: NSRect(x: 0, y: 0, width: 500, height: 100))
        let badge = HumanButton(title: "", target: self, action: #selector(badgePressed(_:)))
        badge.bezelStyle = .inline
        badge.controlSize = .small
        badge.imagePosition = .imageLeading
        self.badge = badge
        let line = Hairline()
        for v in [subjectView, nameView, dateView, from, to, badge, line] as [NSView] {
            v.translatesAutoresizingMaskIntoConstraints = false
            addSubview(v)
        }
        let m = Self.margin
        NSLayoutConstraint.activate([
            subjectView.topAnchor.constraint(equalTo: topAnchor, constant: 20),
            subjectView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m),
            subjectView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -m),
            nameView.topAnchor.constraint(equalTo: subjectView.bottomAnchor, constant: 6),
            nameView.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m + 36),
            nameView.trailingAnchor.constraint(equalTo: dateView.leadingAnchor, constant: -8),
            from.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m),
            from.centerYAnchor.constraint(equalTo: nameView.centerYAnchor),
            to.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m),
            to.centerYAnchor.constraint(equalTo: nameView.centerYAnchor),
            dateView.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -m),
            dateView.centerYAnchor.constraint(equalTo: nameView.centerYAnchor),
            dateView.widthAnchor.constraint(equalToConstant: 160),
            dateView.heightAnchor.constraint(equalToConstant: 16),
            badge.topAnchor.constraint(equalTo: nameView.bottomAnchor, constant: 8),
            badge.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m - 2),
            line.topAnchor.constraint(equalTo: nameView.bottomAnchor, constant: 44),
            line.leadingAnchor.constraint(equalTo: leadingAnchor, constant: m),
            line.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -m),
            line.heightAnchor.constraint(equalToConstant: 1),
            line.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])
        clear()
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// Shows a letter's header. The header owns `subject` and `name` (copies
    /// made for it) from now on. `badge` is a received letter's badge text
    /// (L10n.badge) and whether it is verified; nil for a sent letter.
    func show(subject: SecretText, name: SecretText, outgoing: Bool, date: String,
              badge verdict: (title: String, verified: Bool)?) {
        clear()
        subjectView.set(0, subject)
        nameView.set(0, name)
        dateView.show(date)
        from.isHidden = outgoing
        to.isHidden = !outgoing
        if let verdict, let badge {
            badge.title = verdict.title
            badge.image = NSImage(systemSymbolName: verdict.verified ? "checkmark.seal" : "exclamationmark.triangle",
                                  accessibilityDescription: nil)
            badge.contentTintColor = verdict.verified ? nil : .systemOrange
            badge.isHidden = false
        }
        isHidden = false
    }

    /// Wipes the subject and the name, zeroes their pixels, and hides.
    func clear() {
        subjectView.clear()
        nameView.clear()
        dateView.show(nil)
        badge?.isHidden = true
        from.isHidden = true
        to.isHidden = true
        isHidden = true
    }

    /// The badge's action (HumanButton: only a human's press gets here).
    @objc private func badgePressed(_ sender: Any?) {
        onBadge()
    }
}
