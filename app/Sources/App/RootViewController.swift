// RootViewController.swift — swaps Brev's screens inside the main window.
//
// Upholds CLAUDE.md §3.2 (blank-on-lock) and §1.10 (docs/PHASE2_DESIGN.md
// §4.1, §8.1, §8.4). The window's content view controller is set once;
// onboarding, the lock screen and the mail window are children shown one at
// a time inside it, so the window keeps its size across lock and unlock.
// In the lock sequence every sheet still attached wipes what it holds (the
// compose sheet) and ends, then the current screen wipes what it holds, and
// LockController shows the lock screen.

import AppKit

/// A screen or a sheet that holds content wipes all of it (every
/// SecretText) when Brev locks.
protocol ContentHolder: AnyObject {
    func wipeAll()
}

final class RootViewController: NSViewController {
    private(set) var child: NSViewController?

    override func loadView() {
        view = BlankContentView(frame: NSRect(x: 0, y: 0, width: 900, height: 600))
    }

    /// Replaces the current screen with `next`, at the root's size.
    func show(_ next: NSViewController) {
        if let old = child {
            old.view.removeFromSuperview()
            old.removeFromParent()
        }
        addChild(next)
        next.view.frame = view.bounds
        next.view.autoresizingMask = [.width, .height]
        view.addSubview(next.view)
        child = next
    }

    /// Lock sequence steps 2 and 3 (§8.4), in that order: every sheet on the
    /// window wipes its own content and ends, then the current screen wipes
    /// its content.
    func wipeContent() {
        if let window = view.window {
            window.sheets.forEach {
                ($0 as? ContentHolder)?.wipeAll()
                window.endSheet($0)
            }
        }
        (child as? ContentHolder)?.wipeAll()
    }
}

/// One short interface text in the middle of the window, never content:
/// launch.error.unsafe, and unlock.error.damaged when the folder, the
/// instance lock or the keychain is unusable.
final class NoticeViewController: NSViewController {
    private let text: String

    init(_ text: String) {
        self.text = text
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func loadView() {
        view = NoticeView(text: text)
    }
}

private final class NoticeView: NSView {
    private let text: String

    init(text: String) {
        self.text = text
        super.init(frame: NSRect(x: 0, y: 0, width: 900, height: 600))
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func draw(_ dirtyRect: NSRect) {
        let style = NSMutableParagraphStyle()
        style.alignment = .center
        let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.systemFont(ofSize: 15),
                                                    .foregroundColor: NSColor.labelColor,
                                                    .paragraphStyle: style]
        let width = min(bounds.width - 48, 480)
        let size = text.boundingRect(with: NSSize(width: width, height: bounds.height),
                                     options: .usesLineFragmentOrigin, attributes: attrs).size
        let rect = NSRect(x: (bounds.width - width) / 2, y: (bounds.height - ceil(size.height)) / 2,
                          width: width, height: ceil(size.height))
        text.draw(with: rect, options: .usesLineFragmentOrigin, attributes: attrs)
    }
}
