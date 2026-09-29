# UI redesign: a calm, Mail-like Brev

Status: built 2026-09-29 on branch `claude/ui-redesign`, with the review of
2026-09-29 applied (below); DECISIONS.md D-0114 lists what
the build settled that this spec did not. `tools/snapshot` draws every scene
of §5.4 (light and dark) and runs §5.6's checks in scripts/test.sh. Since
D-0115 there are no classes: the badge says «Skrevet i Brev» or «Ikke
verifisert», and the list shows a seal or the chip «Ikke verifisert»; the
drawings below are updated.
Scope: the Swift app only (`app/Sources/App`, `app/Sources/UI`, one file in
`app/Sources/Shared`), plus a new offscreen tool under `tools/`.
No change to the Rust core or the FFI (`scripts/ffi-surface.txt` stays as it is).

CLAUDE.md §1–§3 bind every line of this spec. When this spec and CLAUDE.md
disagree, CLAUDE.md wins and the spec is wrong.

## Review applied (2026-09-29)

Every high and medium finding of the review is fixed in the sections below.
The low ones too. In short:

| # | Finding | Fix (where) |
|---|---|---|
| 1 (high) | `.fullSizeContentView` lets content scroll under the blurring toolbar; no capture probe covers that | **Dropped**: the style mask keeps no `.fullSizeContentView`, so nothing sits under the toolbar. The snapshot tool checks that no ContentView's frame leaves the window's `contentLayoutRect` (§2.1, §5.6). |
| 2 (high) | Innboks as the start view decrypts every subject at each unlock and sync; a sync reload by row index would open another letter | **Start on the first contact, as today.** Innboks and Sendt are read only after a human clicks them. A sync keeps the selected letter by thread id; if it is gone, the reading pane is cleared and no other row is selected. Recorded as a §1.10 decision in DECISIONS.md (Q1 closed; §2.3, §2.4, §8). |
| 3 (med) | `MailboxListView` rows would be AX-selectable: an agent could switch mailboxes and make Rust decrypt | The rows are AX static text only: no select, no press. Selection comes only from `mouseDown`/`keyDown`, which pass `BrevApplication.sendEvent`/InputFilter. The snapshot tool checks that AX attempts change nothing (§2.3, §5.6). |
| 4 (med) | Svar is a new feature and does what Nytt brev does | **Svar dropped** (no `reply`, no ⌘R, no strings). The toolbar has Nytt brev and Lås (§2.2). |
| 5 (med) | Key-change and blocked states hidden in Innboks and Sendt | With a mailbox selected and a letter whose contact has a changed key or is blocked, the whole ContactBar shows above the reading header. Scene `mail-inbox-keychanged` (§2.4, §2.5, §5.4). |
| 6 (med) | The fixture moves out of ViewHost, which orders windows front and activates | `tools/fixture/Fixture.swift` holds only the relay, `User` and `fake()`. test.sh fails if `tools/fixture` or `tools/snapshot` names `orderFront`, `makeKeyAndOrderFront`, `activate(`, `runModal`, `beginSheet` or `.present(`. The tool aborts at once on any window becoming key or visible. Compose text is set through the model, never by focus or keys; after each compose scene secure input must be off (§5.2, §5.3). |
| 7 (low-med) | A sidebar item can be collapsed by dragging, with no way back | `canCollapse = false` (and no collapse on window resize) on all three items; the tool checks it (§2.1). |
| 8 (low) | Grep holes | `autosave` grepped case-insensitively (code lines), only `autosavesConfiguration = false` allowed; `NSCollectionView`, `NSBrowser`, `NSTokenField`, `NSComboBox` added to FORBIDDEN; any `drawContent(` call outside OpaqueView.swift fails (§6.3). |
| 9 (low) | Empty states for a selected request and for a new user | A request: no list empty state, a blank reading pane. No contacts: the Innboks empty state carries «Legg til kontakt» (`sidebar.add`). No new strings (§2.4). |
| 10 (low) | `SecureLineView` repeats `ContactTextView` | `ContactTextView(rows:font:)` draws the subject and the name; no new file. Only `TextLayout.firstLine`, clipped. The window subtitle is cleared whenever the toolbar is removed (§2.5, §4). |

## 0. Goals and rules

- Look like a native Mac mail app. Apple Mail is the model: a sidebar, a
  message list, a reading pane, a unified toolbar, and a clean compose sheet.
- Do less than Mail. Every feature must already exist in Brev today.
- The owner will not test by hand. Everything is checked by builds, tests
  and offscreen snapshots (§5).
- Content stays where it is today: only ContentViews draw names, addresses,
  codes, subjects and bodies, through the protected layer. Chrome (labels,
  buttons, icons, empty states) is plain AppKit with fixed text from
  `Localizable.strings`.

Words used below:

- **Content view**: a subclass of `ContentView` (OpaqueView.swift). It draws
  only in `drawContent(in:rect:)`, into the protected
  `AVSampleBufferDisplayLayer` (`preventsCapture = true`). It is not an
  accessibility element, has no menu and no Services.
- **Chrome**: everything else. Only fixed strings from L10n, dates, counts
  and Hand's fixed words.

## 1. The UI today

### 1.1 How the window is built

| Part | File | How it is built | Secure or chrome |
|---|---|---|---|
| Main window | App/MainWindow.swift | `HardenedWindow`, 900×600, `.titled .closable .resizable`, transparent title bar, title «Brev». Not miniaturizable. | chrome |
| Screen swapper | App/RootViewController.swift | One root VC. Onboarding, lock screen, address page and mail are children, one at a time. `wipeContent()` in the lock sequence. `NoticeViewController` draws one fixed text. | chrome |
| Menu | App/MainMenu.swift | Brev (Lås ⌘L, Avslutt ⌘Q) and Arkiv (Nytt brev ⌘N). No Edit, View, Window, Help, Services. | chrome |
| Hardening | App/Hardening.swift | `sharingType .none`, no Windows menu, not restorable, no tabs; applied to every sheet and child window. | — |
| Lock | App/LockController.swift | Lock triggers and the lock sequence (wipe, `ContentView.blankAll()`, `GlyphFlush.flush()`, Rust lock, lock screen). | — |

### 1.2 Screens

| Screen | File | What it shows | Secure parts |
|---|---|---|---|
| Onboarding | UI/OnboardingViewController.swift, UI/PageView.swift | Centred column: Velkommen → Dette må du vite (5 rules, checkbox, Opprett nøkler) → Oppretter nøkler … → errors. | none (InterfaceText + HumanButton) |
| Lock / first unlock | UI/UnlockViewController.swift | «Brev er låst», optional notice (sudo/SIP), Lås opp med Touch ID, sometimes Slett alt og start på nytt. | none |
| Address page | UI/AddressViewController.swift | Step 1 invite code (ContactField), step 2 own address (SecureComposeView) and Registrer. | the two fields, the inviter's address and code (ContactTextView) |
| Mail window | UI/MailViewController.swift | A button bar (Nytt brev, Kontakter, Lås); the ContactHeaderView (own address and code, the selected contact's address, code, state, Blokker, key-change block, or a request with Godta/Avslå); an NSSplitView with three panes: contacts (requests list above contacts list), threads, letters. | all lists (SecureListView), header texts (ContactTextView), letter bodies (SecureTextView) |
| Letter pane | UI/LetterStackView.swift | For each letter: «Sendt/Mottatt <dato>» (LetterHeaderView, a ContentView that draws only metadata), the body, and for a received letter the badge (HumanButton, fixed text) that opens ProofSheet. | bodies |
| Compose sheet | UI/ComposeSheet.swift, UI/SecureComposeView.swift | 600×460 sheet. «Til:» + RecipientView, «Emne:» + subject field, body field, status text, Avbryt / Prøv igjen / Send. | recipient, subject, body |
| Kontakter sheet | UI/ContactSheet.swift, UI/ContactField.swift | Own address + Kopier adressen min; Lag invitasjon + code + Kopier koden + note; field + Legg til; «Invitert av:» + Godta invitasjonen; one result text; Lukk. | own address, invite code, inviter, field |
| Confirm sheet | UI/ConfirmSheet.swift | Reset or accept new key. Fixed text, Avbryt + action, no default button. | none |
| Proof sheet | UI/ProofSheet.swift | The badge as title, failed checks, reported facts, proof.attest («Appen er ikke bekreftet av Apple …»), Lukk. | none (fixed text + Rust's counts) |

### 1.3 Facts that shape the redesign

- **A thread holds one letter** since Phase 3 (each send starts a thread;
  `sign_request` takes no thread id). Older stores may still have threads
  with more letters. So "thread list" and "message list" are the same thing.
- **The FFI lists threads per contact only**: `threads(contact)`. There is
  no call for all threads. And `threads(contact)` decrypts every subject in
  the store in Rust and keeps only that contact's (store.rs `threads()`).
- **`messages(thread)` decrypts nothing** and gives `id`, `created_at`,
  `outgoing`. `letter_proof(message)` decrypts nothing.
- **There is no read flag in the FFI.** The store has a `read` column, but
  `MessageRow` does not carry it and there is no "mark read" call.
- **One content font.** `GlyphFlush.attrs` holds one font; `flush()` clears
  Core Text's caches for that font only. SelfScan's glyph control (V39/V65)
  uses the same font.
- **Tests name the current views**: app/Tests/Lock uses `mail.header` and
  `mail.proofs`; tools/viewhost uses `mail.requestList`, `mail.header`,
  `newLetter`, `showContacts`, `answerSelected`, `blockSelected`, counts
  SecureListViews and prints "rect" lines for three panes;
  tools/verify/capture-probe finds content panes as AX scroll areas.

## 2. The redesign

### 2.1 Main window layout

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ ● ● ●  Brev                 [✎ Nytt brev]                            [🔒 Lås] │  unified toolbar
├───────────────┬───────────────────────────┬──────────────────────────────────┤
│ ▢ Innboks     │ (ContactBar, only when a  │  Emne i stor skrift              │
│ ➤ Sendt       │  contact/request is       │  Fra: ekko            12. sep.   │
│               │  selected)                │  [✓ Skrevet i Brev]              │
│ FORESPØRSLER  ├───────────────────────────┤  ─────────────────────────────── │
│   asker-adr   │ ekko             12:04    │                                  │
│               │ Emnet her          ✓      │  Brødtekst i New York 15 pt,     │
│ KONTAKTER     │───────────────────────────│  med god linjeavstand, venstre-  │
│ ◯ ekko      • │ speil            i går    │  stilt, høyst 680 pt bred.       │
│ ◯ speil       │ Et annet emne     [A]     │                                  │
│               │                           │                                  │
│ [+ Legg til   │                           │                                  │
│    kontakt]   │                           │                                  │
└───────────────┴───────────────────────────┴──────────────────────────────────┘
   sidebar           message list                 reading pane
```

- Window: default content size 1080×680, minimum 880×540. **No
  `.fullSizeContentView`** (review 1): the toolbar blurs what lies under it,
  and no capture probe has tested a protected layer blurred there. So no
  view sits under the toolbar; the snapshot tool checks that every
  ContentView's frame lies inside the window's `contentLayoutRect`.
  Still not miniaturizable, still not restorable, still no frame autosave.
- An `NSSplitViewController` with three items replaces the NSSplitView:
  1. sidebar: `NSSplitViewItem(sidebarWithViewController:)` (AppKit gives it
     the `.sidebar` NSVisualEffectView material), width 220, min 180, max 280;
  2. message list: width 340, min 300;
  3. reading pane: min 380, takes the rest (lowest holding priority).
  `splitView.autosaveName` stays nil (no state on disk). Every item has
  `canCollapse = false` and, on macOS 14+, `canCollapseFromWindowResize =
  false` (review 7): there is no View menu to bring a hidden pane back.
- The window title is the selected mailbox's fixed name («Innboks»,
  «Sendt»), else «Brev»; the subtitle stays empty, so the title is one line
  and does not move (review round 2). Never a name or address.
- The toolbar exists only on the mail screen. `RootViewController.show`
  sets it on the mail screen and removes it for every other screen, and
  clears the subtitle whenever it removes it (review 10). Adding or removing
  a toolbar would change the window's frame, so MainWindow puts the frame
  back after each change: the frame is the same on every screen (the tool
  checks it).

### 2.2 Toolbar

An `NSToolbar` with `toolbarStyle = .unified`, `displayMode = .iconOnly`,
`allowsUserCustomization = false`, `autosavesConfiguration = false`, and on
macOS 15+ `allowsDisplayModeCustomization = false`. Two items, both standard
`NSToolbarItem`s with an SF Symbol and a fixed label. Their target is the
mail screen itself (the controller that also answers the menu's ⌘N), so they
work whatever has focus:

| Item | Symbol | Action | Enabled when |
|---|---|---|---|
| Nytt brev | `square.and.pencil` | `newLetter(_:)` | a recipient is known (below) and it is not key-changed or blocked |
| Lås | `lock` | the mail screen's `onLock` (as the old Lås button) | always |

Flexible space between Nytt brev and Lås. No search field, no share item, no
sidebar toggle, no tracking separator item. **No Svar** (review 4): with a
mailbox selected, Nytt brev already goes to the selected letter's contact,
and an empty «Svar» without «Sv:» would only surprise Mail users.

Why standard items and not HumanButtons: HumanButton guards actions that
unlock, create keys, confirm, reset or send (HumanButton.swift). These two
do none of those; each is already reachable through the menu, which
accessibility can press (MainMenu.swift: "each action is harmless"). Every
button inside the compose sheet stays a HumanButton.

Recipient rules (the core has no recipient picker, and this spec adds none):

- Nytt brev: the contact selected in the sidebar; with a mailbox selected,
  the contact of the selected letter; otherwise disabled. The compose sheet
  opens empty, as today.

### 2.3 Sidebar (chrome frame, secure rows)

A vertical, flipped stack inside the sidebar's scroll view, top to bottom:

1. **Mailboxes** — `MailboxListView` (new, chrome): two rows, «Innboks»
   (`tray`) and «Sendt» (`paperplane`). Fixed text. No counts (there is no
   read flag). **AX sees each row as static text only** (review 3): no
   list, no rows, no AXSelected that can be set, no press or pick action.
   A selection comes only from `mouseDown` and `keyDown` (↑/↓), which reach
   the view only through `BrevApplication.sendEvent` and InputFilter; the
   view also drops a synthetic event itself. So no agent can switch
   mailboxes, which would make Rust decrypt every subject.
2. **Forespørsler** — section header (chrome), then `requestList`
   (SecureListView, asker's address). Both hidden while there are none.
3. **Kontakter** — section header (chrome), then `contactList`
   (SecureListView, the address as name). While there are no contacts, the
   header is followed by «Ingen kontakter ennå» (chrome, tertiary).
4. **Footer** (pinned to the bottom, outside the scroll view): a borderless
   HumanButton «Legg til kontakt» with `plus`. It opens the same
   ContactSheet the old «Kontakter» button opened.

One selection across the sidebar: `enum SidebarSelection { inbox, sent,
contact(id), request(peer) }`. Selecting a row in one list deselects the
others (as requests and contacts do today). **Start selection: the first
contact, as today** (review 2; DECISIONS.md, Q1). With no contacts it is
Innboks, which then reads nothing (there is no contact to read). Innboks
and Sendt are read only after a human selects them.

Row metrics: height 28, selection a rounded rect (radius 6) inset 8 pt from
each side, `selectedContentBackgroundColor` when the list has focus, else
`unemphasizedSelectedContentBackgroundColor`. Mailbox icons at x = 16
(16 pt symbols, `secondaryLabelColor`), text at x = 40. Contact rows draw a
`person.crop.circle` symbol at x = 16 (a CGImage made once per appearance
from the SF Symbol and drawn inside `drawContent`; an icon is not content)
and the name at x = 40, so all rows line up. A contact whose key changed
gets a 6 pt `systemOrange` dot at the trailing edge; a blocked contact's
name is drawn in `tertiaryLabelColor`. These are the ContactRow flags,
metadata only.

SecureListView gets a "fixed height" mode for this: its height is
`rows × rowHeight`, not "at least the scroll view", so two lists can stack
in one scroll view.

### 2.4 Message list (secure rows, chrome frame)

What it lists:

| Sidebar | Rows | Line 1 | Line 2 |
|---|---|---|---|
| Innboks | every thread with a received letter, all contacts, newest first | sender (contact name) | subject |
| Sendt | every thread with a sent letter, newest first | recipient (contact name) | subject |
| a contact | that contact's threads, both directions, newest first | subject (semibold) | «Mottatt» / «Sendt» (metadata) |
| a request | nothing (a request carries no text) | — | — |

How it is read: for Innboks and Sendt, `threads(contact)` for every contact,
then `messages(thread)` for the direction and date of each letter, then
`letterProof(message)` for each received letter's chip. A thread with letters
in both directions (older stores) is in both mailboxes. The sender line is a
`SecretText.copy()` of the contact's name, owned by the row.

Cost, said plainly: with C contacts and T threads, Innboks makes Rust
decrypt T subjects C times (each `threads(contact)` call opens all of them
and drops the others at once; the zeroing allocator wipes them). Swift keeps
what the list shows while the mailbox is open: T subjects and T name copies.
That is more plaintext than a contact's list, so it is a §1.10 matter, not
only a cost (review 2). Decision (DECISIONS.md D-0114, Q1):
Brev starts on the first contact, as today, and a mailbox is read only when
a human clicks it. While a human keeps a mailbox open, a sync that brought
letters reads it again. A core call `all_threads()` would make it T; it is a
core change and out of scope.

**No bodies are read to draw the list** (no previews, CLAUDE.md §1.10).
**No letter is opened on its own**: the reading pane stays empty until a
human selects a row. Today the newest thread is selected and its bodies are
decrypted at once; that goes. A sync or any other reload keeps the selected
letter **by thread id**; if that thread is gone, the reading pane is cleared
and no other row is selected (review 2). After a send, the list is read
again and the selection is kept the same way; the sent letter is not opened.

Row layout (height 56, the 16 pt left padding is where an unread dot would
go later):

```
x=16                                               right edge −16
│ ekko (13 semibold, labelColor)            12:04 (11, secondary) │  baseline 10 + ascent
│ Emnet her (13 regular, labelColor)             ✓ (seal)       │  baseline 30 + ascent
─────────────────────────────────────────────── hairline, inset 16
```

- Date: today → time («12:04»); this week → weekday («tirsdag»); older →
  «12.09.2026». `nb_NO` formatter. Metadata.
- Mark (received letters only, D-0115): a verified letter gets the symbol
  `checkmark.seal` (15 pt, `secondaryLabelColor`), meaning «Skrevet i
  Brev»; a failed one the chip «Ikke verifisert» in `systemOrange` inside a
  1 pt rounded rect. Drawn in the list's protected layer (meta, not
  content; not AX-visible, the list is opaque).
- Selection: rounded rect (radius 6) inset 8 × 2; colours as the sidebar.
  Text turns `alternateSelectedControlTextColor` only while focused.
- ↑/↓ move the selection (as today); Tab moves sidebar → list.

The list is a SecureListView with a new two-line row style:
`Row(text:, text2:, meta:, trailing:, chip:)`. `text` and `text2` are
SecretTexts the list owns and wipes; `meta`, `trailing` and `chip` are
fixed strings or dates.

**ContactBar** (the old ContactHeaderView, reshaped; property name `header`
kept for the tests). Shown at the top of the list column while a contact or
a request is selected, with a hairline under it. With a mailbox selected,
it shows **above the reading header** when the selected letter's contact
has a changed key or is blocked (review 5), so the warning and Godta ny
kode are never hidden behind a 6 pt dot:

- Contact: row 1 the address (ContactTextView, 13 semibold) and, right, the
  small HumanButton «Blokker» (hidden once blocked, as today). Row 2 the
  state (chrome, 11 pt secondary: «Venter på svar» / «Bekreftet med
  invitasjon» / «Blokkert»). Row 3 the label «Sikkerhetskode» (chrome, 11 pt
  secondary) above the code (ContactTextView, 13 regular).
- Key changed: a block below with a `systemOrange` 10 %-alpha fill and a
  1 pt orange left bar: contact.changed (chrome), «Ny kode:» + the new code
  (ContactTextView), «Godta ny kode» (HumanButton → ConfirmSheet, as today),
  accept.error when it failed.
- Request: row 1 the asker's address, row 3 its code, then request.body
  (chrome) and Godta / Avslå (HumanButtons, one click each, as today).
- `InterfaceText` gets `setWidth(_:)` so these texts wrap at the column's
  width (they have fixed widths of 180–560 pt today).

The old header line 1 («Du:» + own address + own code) leaves the main
window. The own address and code move to the Kontakter sheet (§2.7).

**Empty states** (chrome, centred in the list: a 40 pt SF Symbol in
`tertiaryLabelColor`, 8 pt, a 15 pt semibold line in `secondaryLabelColor`):

| Case | Symbol | Text |
|---|---|---|
| Innboks empty | `tray` | «Ingen brev» |
| Sendt empty | `paperplane` | «Ingen sendte brev» |
| Contact with no letters | `envelope` | «Ingen brev med denne kontakten» |

No explanation sentences under them (short copy, like the rest of Brev).
Two more cases (review 9, no new strings):

- A request is selected: no list empty state, and the reading pane is
  blank (no «Ingen brev valgt»).
- No contacts at all (a new user): the Innboks empty state also carries the
  one button «Legg til kontakt» (`sidebar.add`), which opens the Kontakter
  sheet like the sidebar footer.

### 2.5 Reading pane

A flipped scroll view on `textBackgroundColor`. While no letter is selected:
«Ingen brev valgt» (13 pt, `tertiaryLabelColor`, centred), as in Mail.

With a letter selected, a header, then the letter:

```
 24 ┌─────────────────────────────────────────────────────────────┐
    │ Emnet her (17 semibold)                                      │ ReadingHeaderView
  8 │ Fra: (13, secondary)  ekko (13 semibold)   12. sep. 2026 12:04│
  8 │ [✓ Skrevet i Brev]              (HumanButton, inline, small) │
 16 ├───────────────────────────── hairline ───────────────────────┤
 24 │ Brødtekst …                                                  │ SecureTextView
    └─────────────────────────────────────────────────────────────┘
```

- `ReadingHeaderView` (new, chrome frame): the subject and the name are two
  `ContactTextView(rows: 1, font:)`s (content, review 10: no new
  `SecureLineView`; each owns a `SecretText.copy()` of the row's text and
  wipes it on a new selection and on lock). Each draws only
  `TextLayout.firstLine` of its text, clipped at the view's edge, as the
  list does: a subject never wraps. «Fra:» for a received letter, «Til:»
  for a sent one (chrome). The date is metadata, drawn by a small meta view
  as LetterHeaderView does today.
- With a mailbox selected and the letter's contact key-changed or blocked,
  the ContactBar stands above this header (§2.4, review 5).
- The badge moves here, for received letters only: the same HumanButton
  with the same fixed title (`L10n.badge`), now with a leading symbol
  (`checkmark.seal` verified, `exclamationmark.triangle` not verified),
  `bezelStyle = .inline`, `controlSize = .small`. Its press opens ProofSheet,
  as today. Keep `mail.proofs` for the lock probe.
- Body: SecureTextView, New York 15 pt (§3.1), insets 24, and the text
  column at most 680 pt wide (a readable measure); left aligned.
- A legacy thread with more letters: LetterStackView stays and shows the
  letters under one header, each after a hairline and its own
  «Mottatt/Sendt <dato>» meta line and badge, as today.

### 2.6 Compose sheet

Still a sheet on the main window (keeps the parent's hardening, and a
sheet is simpler than a second window). Laid out like Mail's compose window,
640×540:

```
┌────────────────────────────────────────────────────────────┐
│ Til:   ekko                                                │ 36 pt row (RecipientView)
│ ────────────────────────────────────────────────────────── │ hairline, inset 16
│ Emne:  |                                                   │ 36 pt row (subject field, borderless)
│ ────────────────────────────────────────────────────────── │
│                                                            │
│  Brødtekst i New York 15 pt …                              │ body field, borderless, insets 16/24
│                                                            │
│ ────────────────────────────────────────────────────────── │
│ Sender …                              [Avbryt]  [Send ⌘↩]  │ 52 pt bar
└────────────────────────────────────────────────────────────┘
```

- Labels «Til:» and «Emne:» (chrome, 13 pt, `secondaryLabelColor`) at x = 16;
  the fields start at x = 72. No bezels or boxes around the fields: rows are
  divided by `separatorColor` hairlines. Background `textBackgroundColor`.
- Status and error texts (Sender …, compose.error, keychanged, notapproved,
  ratelimited, environment lines, net.error) sit left in the bottom bar,
  13 pt. Errors are `labelColor` with a small `exclamationmark.triangle` in
  `systemOrange` before them (calmer than red, and still easy to read).
- Buttons right: Avbryt (Escape), Prøv igjen (when shown), Send. Send is the
  default-looking button and keeps ⌘↩ in a field. All HumanButtons.
- Everything about the send steps, Hand, secure input and wiping stays
  exactly as it is. Only frames and fonts change.

### 2.7 Kontakter sheet

Width 520. A grouped form, like System Settings: three sections, each an
11 pt semibold section title (chrome) over a rounded group (`NSBox`
`.custom`, fill `controlBackgroundColor`, border `separatorColor`, radius 8):

1. «Deg»: «Adresse» + own address (ContactTextView) + Kopier adressen min;
   «Sikkerhetskode» + own code (ContactTextView, **new here**: it moves from
   the old header line 1, so a contact can still compare it).
2. «Inviter noen»: Lag invitasjon; the code on two lines (ContactTextView);
   Kopier koden; invite.note (11 pt secondary).
3. «Legg til kontakt»: the field (ContactField, with a 1 pt `separatorColor`
   rounded border drawn by its container), Legg til; «Invitert av:» +
   inviter + Godta invitasjonen when shown.

The result line under the groups; Lukk bottom right. Pasteboard rules do not
change: `ContactPasteboard.write(` stays in exactly two places in this file.

### 2.8 Confirm and proof sheets

- ConfirmSheet: alert-like. A 32 pt symbol (`exclamationmark.triangle` for
  reset, `key` for a new code) left, the title 13 pt bold, the body 13 pt,
  buttons bottom right. Reset's action button sets `hasDestructiveAction`.
  Still no default button, Escape is Avbryt.
- ProofSheet: title with the same symbol as the badge; the lines as today,
  13 pt, 8 pt apart; proof.attest («Appen er ikke bekreftet av Apple …») last, 11 pt secondary;
  Lukk bottom right.

### 2.9 Lock, onboarding, address page, notices (calmer)

All stay AppKit on `PageView` (no SwiftUI: one toolkit is simpler, and the
forbidden-API check already covers these files). PageView gets:

- an optional 48 pt SF Symbol at the top, `secondaryLabelColor`,
  hierarchical rendering;
- column width 400 (was 460), spacing 8/16/24 on the grid;
- title 22 semibold (as today), body 13 pt `secondaryLabelColor`;
- one primary button, `controlSize .large`, `keyEquivalent "\r"` where there
  is one today; secondary actions (Slett alt og start på nytt) as small
  `.inline`-style buttons under it, so the reset is never the loud option.

| Screen | Symbol | Notes |
|---|---|---|
| Lock | `lock` | «Brev er låst»; notice lines (sudo/SIP) under the title, 13 pt secondary; button «Lås opp med Touch ID» with `touchid` |
| First unlock | `touchid` | as today |
| Welcome | `envelope` | as today |
| Rules | `hand.raised` | the five rules as rows: symbol (`touchid`, `externaldrive.badge.xmark`, `hand.point.up.left`, `exclamationmark.bubble`, `doc.questionmark`) + text, left aligned; the checkbox; Opprett nøkler |
| Working | — | a small `NSProgressIndicator` (spinning) + «Oppretter nøkler …» |
| Address (invite, address) | `at` | the field in a rounded border as in §2.7 |
| Notice (unsafe start, damaged) | `exclamationmark.triangle` | NoticeView adopts PageView's style |

No new texts on these screens.

### 2.10 What is removed or merged

1. The button bar above the panes → the unified toolbar (Nytt brev, Lås).
2. The thread pane → merged into the message list (a thread is one letter).
3. The contacts pane → the sidebar's «Kontakter» section.
4. The requests block at the top of the contacts pane → the sidebar's
   «Forespørsler» section.
5. Header line 1 («Du:», own address, own code) → the Kontakter sheet.
6. Header line 2 and its blocks → the ContactBar, shown only for a selected
   contact or request.
7. The «Kontakter» button → «Legg til kontakt» in the sidebar footer.
8. «Sendt/Mottatt <dato>» above every letter → the reading header (Fra/Til +
   date); kept only between letters of an old multi-letter thread.
9. Auto-selecting the newest thread and opening its letter → removed.
10. «Ingen brev ennå» → the three empty states and «Ingen brev valgt».
11. Boxed compose fields → borderless rows with hairlines.
12. Strings no longer used: `mail.nothreads`, `header.me`, and `mail.new` /
    `mail.lock` (replaced by `toolbar.new` / `toolbar.lock`). They are
    removed, so `Localizable.strings` has no dead keys.

Not added (on purpose): search, unread counts or dots, flags, folders,
drafts, delete, archive, forward, print, share, attachments, rich text,
previews, avatars from content, a recipient picker, multiple windows, tabs,
Quick Look, drag, Services, tooltips.

### 2.11 New strings (nb, in Localizable.strings via L10n)

```
"mailbox.inbox" = "Innboks";
"mailbox.sent" = "Sendt";
"sidebar.add" = "Legg til kontakt";
"sidebar.nocontacts" = "Ingen kontakter ennå";
"toolbar.new" = "Nytt brev";
"toolbar.lock" = "Lås";
"list.empty.inbox" = "Ingen brev";
"list.empty.sent" = "Ingen sendte brev";
"list.empty.contact" = "Ingen brev med denne kontakten";
"list.received" = "Mottatt";
"list.sent" = "Sendt";
"reading.none" = "Ingen brev valgt";
"reading.from" = "Fra:";
"reading.to" = "Til:";
"contacts.section.me" = "Deg";
"contacts.section.invite" = "Inviter noen";
"contacts.section.add" = "Legg til kontakt";
"contacts.address" = "Adresse";
"contacts.code" = "Sikkerhetskode";
```

«Ikke verifisert» reuses `badge.unverified`. None takes a name, an address,
a subject or a code (the rule at the top of Localizable.strings).

## 3. Visual system

### 3.1 Typography

Chrome uses `NSFont.systemFont` (SF Pro). Content fonts are drawn by
TextLayout and must each be covered by GlyphFlush (§4.2).

| Element | Font | Size / weight | Colour | Kind |
|---|---|---|---|---|
| Window title / subtitle | system | system | system | chrome |
| Sidebar mailbox rows | SF | 13 regular | label | chrome |
| Sidebar section headers | SF | 11 semibold | secondaryLabel | chrome |
| Sidebar contact / request names | SF (F1) | 13 regular | label (tertiary if blocked) | content |
| List line 1 (sender / recipient) | SF (F2) | 13 semibold | label | content |
| List line 2 (subject) | SF (F1) | 13 regular | label | content |
| List date, «Mottatt/Sendt», chip | SF (meta) | 11 regular | secondaryLabel (chip «Ikke verifisert»: systemOrange) | metadata |
| ContactBar name | SF (F2) | 13 semibold | label | content |
| ContactBar state, labels | SF | 11 regular | secondaryLabel | chrome |
| Identity codes (bar, sheets) | SF (F1) | 13 regular | label | content |
| Reading header subject | SF (F3) | 17 semibold | label | content |
| Reading header «Fra:/Til:» | SF | 13 regular | secondaryLabel | chrome |
| Reading header name | SF (F2) | 13 semibold | label | content |
| Reading header date | SF (meta) | 11 regular | secondaryLabel | metadata |
| Badge button | SF | 11 (small control) | system | chrome |
| **Letter body** | **New York (F4)** | **15 regular, line height 22** | label | content |
| Compose «Til:/Emne:» | SF | 13 regular | secondaryLabel | chrome |
| Compose recipient, subject | SF (F1) | 13 regular | label | content |
| Compose body | New York (F4) | 15 regular, line height 22 | label | content |
| Empty-state line | SF | 15 semibold | secondaryLabel | chrome |
| Page title (lock, onboarding) | SF | 22 semibold | label | chrome |
| Page body | SF | 13 regular | secondaryLabel | chrome |
| Sheet titles | SF | 15 semibold | label | chrome |

**New York for the body: yes.** Brev means "letter", and a serif body on a
white page is the clearest way to say it. It is a system font
(`NSFontDescriptor.withDesign(.serif)`), so no font file ships. The compose
body uses the same font, so what you write looks like what they read. Names,
subjects, codes and every piece of chrome stay SF, so the app still reads as
a Mac app. Fallback: if the serif design ever returns nil, F4 is SF 15.

So there are four content fonts: F1 SF 13 regular (today's
`ContentView.contentFont`), F2 SF 13 semibold, F3 SF 17 semibold, F4 New York
15. That is the limit; a fifth needs a reason in DECISIONS.md.

### 3.2 Spacing

An 8 pt grid: 8, 16, 24, 32, 48. A 4 pt half step only inside a row
(label-to-field gaps, chip padding). Window and sheet margins 16 (lists,
sheets' bottom bars) or 24 (reading pane, pages, sheet content). Row heights
28 (sidebar), 56 (message list), 36 (compose header rows), 52 (bars).

### 3.3 Colour

System colours only, so light and dark come for free:
`windowBackgroundColor`, `controlBackgroundColor`, `textBackgroundColor`,
`labelColor`, `secondaryLabelColor`, `tertiaryLabelColor`, `separatorColor`,
`selectedContentBackgroundColor`, `unemphasizedSelectedContentBackgroundColor`,
`alternateSelectedControlTextColor`, `controlAccentColor` (the toolbar and
buttons use it by themselves), `systemOrange` (key change, «Ikke
verifisert», warnings). No hex values, no custom colour assets.

Content views already resolve colours through `color(_:)` against their
`effectiveAppearance` and redraw on `viewDidChangeEffectiveAppearance`, so
a light/dark switch redraws the protected layer. New content views must use
`color(_:)` too, and draw their symbol images per appearance.

## 4. Changes by file

| File | Change | Content or chrome |
|---|---|---|
| App/MainWindow.swift | size 1080×680, min 880×540, no `.fullSizeContentView`, toolbar set/cleared per screen with the frame kept, subtitle from mailbox (cleared with the toolbar) | chrome |
| App/RootViewController.swift | tell the window which screen is shown (toolbar on/off); NoticeView → page style | chrome |
| App/L10n.swift, nb.lproj/Localizable.strings | §2.11 added, unused keys removed | chrome |
| AppDelegate.swift | default window size | chrome |
| UI/MailToolbar.swift (new) | NSToolbar delegate: the two items, no customization, no autosave | chrome |
| UI/MailViewController.swift | NSSplitViewController with sidebar, list, reading pane; `SidebarSelection`; Innboks/Sendt reading (on a human's click only); no auto-open; selection kept by thread id; keep `header`, `requestList`, `proofs`, `newLetter`, `showContacts`, `answerSelected`, `blockSelected` | chrome frame holding secure views |
| UI/SidebarView.swift (new) | `MailboxListView` (chrome rows, AX static text only), section headers, the two SecureListViews, footer button | chrome + secure lists |
| UI/SecureListView.swift | fixed-height mode; two-line row style (`text2`, `trailing`, `chip`); rounded selection; leading symbol and trailing dot | **content** |
| UI/ContactHeaderView.swift → ContactBar | vertical layout for a 300 pt column; key-change and request blocks; own-address row removed; `ContactTextView(rows:font:)` | **content** (texts) + chrome (labels, buttons) |
| UI/ReadingHeaderView.swift (new) | subject + name (`ContactTextView(rows: 1, font:)`), Fra/Til, date, badge button | **content** (subject, name) + chrome |
| UI/LetterStackView.swift | header moves out; insets 24; max measure 680; per-letter meta line only for multi-letter threads | **content** (bodies) |
| UI/SecureTextView.swift | font F4; inset 24; max text width 680 | **content** |
| UI/SecureComposeView.swift | font per instance (F1 subject/address, F4 body); no border | **content** |
| UI/ComposeSheet.swift | Mail-like layout; 640×540; `init` internal (for the tool) | chrome frame + secure fields |
| UI/ContactSheet.swift | grouped form; own code added; `init` internal | chrome + secure texts |
| UI/ConfirmSheet.swift, UI/ProofSheet.swift | symbol, alert layout; a `make(...)` that builds without presenting | chrome |
| UI/PageView.swift, UI/InterfaceText.swift | symbol slot, colours per style, `setWidth(_:)`, section/caption styles | chrome |
| UI/OnboardingViewController.swift, UnlockViewController.swift, AddressViewController.swift | page style, symbols, rule rows | chrome (+ the address page's existing secure fields) |
| UI/OpaqueView.swift | `ContentView` gets the four content fonts as statics (F1–F4); metaFont unchanged | content base |
| Shared/TextLayout.swift | `GlyphFlush` keeps one attrs per content font and flushes each; `TextLayout(font:lineHeight:)` for the 22 pt body | content |
| Verify/SelfScan.swift | glyph control per content font (or at least F4, the body font) | test |
| tools/snapshot/* (new) | §5 | tool, never in Brev.app |
| tools/viewhost/main.swift, app/Tests/Lock/main.swift | follow the renamed panes and the new layout; same checks | tests |
| tools/verify/capture-probe*.swift | pane finding still works (AX scroll areas of sidebar, list, reading) | test |
| scripts/test.sh | new greps (§6.3); run the snapshot tool's `--check` | test |
| docs/DECISIONS.md, docs/VERIFY.md, CLAUDE.md | a decision entry for the redesign; rows that name "three panes" / "thread list"; CLAUDE.md §5 Phase 2's pane list gets a note | docs |

## 5. Offscreen snapshot tool

### 5.1 What it is

`tools/snapshot/` with `build.sh` and `main.swift`. Built like ViewHost
(tools/viewhost/build.sh): one `swiftc` call over
`app/Sources/{Shared,App,UI}`, `Keys/Attestor.swift`, the patched bindings
and the test archive (`allow-software-keys`, no launch guard). A test app
only, never linked into Brev.app, never signed with the team key. Output:
`core/target/snapshot/Snapshot.app` (bundle for `nb.lproj`).

Run: `"$(tools/snapshot/build.sh)" --out <dir> [--scene <name>] [--appearance light|dark|both] [--check]`.
Run the executable directly, never through `open` (no LaunchServices
activation).

### 5.2 Offscreen, always

- First line of `main`: `NSApplication.shared` (BrevApplication, from the
  shared sources) and `setActivationPolicy(.prohibited)`. No Dock icon, no
  menu bar, never active.
- Windows are made with `defer: false` and never ordered in: no
  `orderFront`, `makeKeyAndOrderFront`, `orderFrontRegardless`,
  `beginSheet`, `runModal`. Sheets are built with the new internal `init` /
  `make(...)` and rendered as their own windows.
- Layout and drawing: `layoutSubtreeIfNeeded()`, `displayIfNeeded()`, then
  `cacheDisplay(in:to:)` of the window's content view (its layer tree).
- No keychain, no Touch ID, no Secure Enclave: software keys and temporary
  stores, as ViewHost. The data folder is a fresh temp folder; the tool
  refuses to run if it would resolve to Brev's container.
- Its own `brev-relay` on 127.0.0.1 (a child process, fresh database),
  stopped at the end.
- Guard, checked after every scene and at exit (exit 1 if broken):
  `NSApp.windows.allSatisfy { !$0.isVisible }`, `NSApp.isActive == false`,
  and `CGWindowListCopyWindowInfo(.optionOnScreenOnly, …)` has no window with
  the tool's PID. That guard sees a window only after it flashed, so the
  tool also registers, before it makes any window, observers of
  `NSWindow.didBecomeKey`, `didBecomeMain`, `didChangeOcclusionState` (to
  visible) and `NSApplication.didBecomeActive` that print the failure and
  exit at once (review 6).
- No call that shows a window or takes focus exists in the tool's or the
  fixture's source: test.sh fails if `tools/fixture` or `tools/snapshot`
  names `orderFront`, `makeKeyAndOrderFront`, `activate(`, `runModal`,
  `beginSheet` or `.present(` (review 6).
- The compose scenes put their text in through the fields' `EditModel`
  (`model.insert`), never through focus or key events, so no
  SecureComposeView becomes first responder. After each compose scene the
  tool checks `SecureInput.isOn == false` and that
  `IsSecureEventInputEnabled()` is what it was before the tool started (off
  unless another app holds it).

### 5.3 Fake data

The fixture code in tools/viewhost/main.swift moves to
`tools/fixture/Fixture.swift`, compiled into both tools, and it holds only
the relay (start, root invite), `User` and `fake(_:)` (review 6). The
users («testvert», «ekko», «speil») and letters are made by each tool's own
main. ViewHost's behaviour and checks stay the same, apart from what the new
layout changes (§4). The tool adds a few letters with Norwegian
fake subjects and bodies (long and short), a sent letter, a contact with no
letters, a key change and two requests (the relay tricks ViewHost's
`--contacts` run already uses).

States the fixture cannot reach (a not-verified letter) are drawn as
view-level scenes: the tool builds a
SecureListView / ReadingHeaderView / ProofSheet directly with fake
`SecretText`s and a hand-made `Proof`.

### 5.4 Scenes

Each scene × light and dark (`window.appearance = .aqua / .darkAqua`), at 2×:

| Scene | What |
|---|---|
| `onboarding-welcome`, `onboarding-rules`, `onboarding-working`, `first-unlock` | onboarding pages (later pages reached by calling the page's action selectors directly, as ViewHost's "as a human's press") |
| `lock`, `lock-notice` | lock screen, and with the sudo notice |
| `notice-damaged`, `notice-unsafe` | NoticeViewController |
| `address-invite`, `address-register` | the address page, both steps |
| `mail-inbox`, `mail-inbox-letter`, `mail-inbox-keychanged`, `mail-sent`, `mail-contact`, `mail-contact-keychanged`, `mail-request`, `mail-empty` | the mail window in each state (empty = a new user with no contacts; inbox-keychanged = a letter from a contact whose key changed, with the ContactBar above the reading header) |
| `compose-empty`, `compose-filled` | compose sheet alone, and composited over the dimmed mail window |
| `contacts`, `contacts-invite` | Kontakter sheet, and with an invite code shown |
| `confirm-reset`, `confirm-key`, `proof-verified`, `proof-unverified` | the small sheets |
| `list-rows` | view-level: every row kind and chip, selected/unselected, focused/unfocused |
| `locked-after` | the mail window after the real lock sequence: blank |

### 5.5 How content shows in a snapshot

The protected layer is **not** in `cacheDisplay`'s output. That is by design
(OpaqueView.swift): the snapshot is what a capture could see. So each scene
writes two files:

1. `<scene>-<light|dark>.png` — **chrome only**, exactly what `cacheDisplay`
   gives, plus an overlay drawn by the tool: every ContentView's visible
   frame outlined with a 1 pt dashed `systemPink` line and a faint diagonal
   hatch. So a reviewer sees where content goes, and that nothing else
   shows text.
2. `<scene>-<light|dark>-preview.png` — the same, with the fake content
   composited in: for each visible ContentView the tool makes a CGContext
   over that view's rect and calls its `drawContent(in:rect:)` with the
   fake texts. This is the only way to judge fonts and spacing without
   running Brev. It exists only in the tool, only with fake data, and Brev
   itself never draws content outside the protected layer (a grep in
   test.sh keeps it so, §6.3).

Plus `report.txt` (check lines, as ViewHost prints them) and nothing else.

### 5.6 What the tool checks (`--check` runs these without writing PNGs)

- The offscreen guard of §5.2.
- Every window: `sharingType == .none`, `isRestorable == false`, not in the
  Windows menu; the toolbar has `autosavesConfiguration == false` and
  `allowsUserCustomization == false`; no `.fullSizeContentView`, and every
  ContentView's frame inside the window's `contentLayoutRect` (review 1).
- Every split view item: `canCollapse == false` (review 7).
- MailboxListView: AX sees only static text; `setAccessibilitySelected`,
  `accessibilityPerformPress` and `accessibilityPerformPick` on the view and
  on each row element change neither the selection nor what the list shows
  (review 3).
- Every ContentView: `protectedLayer.preventsCapture`, `ContentView.allOpaque`,
  no `toolTip`, no `menu`.
- The view tree holds no `NSTextField`, `NSTextView`, `NSTableView`,
  `NSOutlineView`, `NSSearchField`, no popover.
- `cacheDisplay` of each ContentView alone has no ink (the ViewHost check).
- The in-process AX tree holds no fake name, subject, body or code (the
  marker check ViewHost has), and does hold the fixed labels (control).
- Window title is «Brev» or a mailbox name; the subtitle is empty.
- The window frame is the same on the lock screen and the mail screen.
- Every letter body open in a scene was opened by a selection the tool made
  (no auto-open: after `start()` and after a sync the reading pane holds no
  letter; Session is a final class, so the tool checks the reading pane
  rather than counting `body(message:)` calls).
- After each compose scene: secure input off (above).
- `GlyphFlush.flush()` time per content font, printed (a budget of 50 ms
  per font, to keep the lock fast).

## 6. Security checklist per changed view

Every item is checked by a test, the snapshot tool (§5.6) or a grep, and
listed in docs/VERIFY.md where a row exists.

### 6.1 Per view

**MainWindow + toolbar**
- [ ] Hardening.apply unchanged; `sharingType .none`, not restorable, no tabs.
- [ ] Title «Brev» or a fixed mailbox name; subtitle empty.
- [ ] Toolbar: no customization, no autosave, no search/share items, no tooltips.
- [ ] Toolbar actions harmless (new letter, lock), same as the menu.
- [ ] Frame unchanged across lock/unlock (toolbar on/off).

**Sidebar (MailboxListView, section headers, footer)**
- [ ] Mailbox rows and headers: fixed text only; AX shows only those labels,
      as static text with no action (review 3).
- [ ] Contact and request rows: SecureListView (content view), AX-opaque.
- [ ] The vibrant material holds no content view state; content views draw
      on a cleared buffer as today (the lists already do).
- [ ] Footer button is a HumanButton.

**SecureListView (sidebar and message list)**
- [ ] Both SecretTexts per row owned and wiped by `setRows`/`clear`.
- [ ] Only the first line of each text drawn; no body read to draw a row.
- [ ] Dates and chips drawn with `drawMeta` (fixed strings / dates only).
- [ ] Symbol images are made from SF Symbols, never from content.
- [ ] `blank()` on new rows and on lock; pool released out of sight.

**ContactBar (was ContactHeaderView)**
- [ ] Addresses and codes only in ContactTextViews; labels are InterfaceText.
- [ ] `newCode` is still the exact code shown; Godta ny kode still goes
      through ConfirmSheet.
- [ ] Blokker, Godta, Avslå are HumanButtons.
- [ ] `clear()` wipes all texts on a new selection and on lock.

**ReadingHeaderView**
- [ ] Subject and name are copies owned by the header, wiped on a new
      selection and in `wipeAll()`.
- [ ] Badge: HumanButton, fixed L10n text, opens ProofSheet as a sheet.
- [ ] No popover, no tooltip.

**SecureTextView / LetterStackView (reading pane)**
- [ ] A body is opened only after a human selects a letter.
- [ ] `clear()` still wipes bodies and runs `GlyphFlush.flush()`.
- [ ] Only lines in sight become CTLines (unchanged).

**Compose sheet**
- [ ] HardenedWindow; Hardening.apply at init and via beginSheet.
- [ ] Secure event input on focus, synthetic input dropped, no pasteboard,
      no input client, Writing Tools off: unchanged (SecureComposeView).
- [ ] It opens empty: no prefill of subject or body.
- [ ] `composeStarted`/`composeClosed`, `cancelSend`, wipe on every close:
      unchanged.

**Kontakter sheet**
- [ ] Own code in a ContactTextView (content), not in a label.
- [ ] `ContactPasteboard.write(` in exactly two places (test.sh check).
- [ ] Field stays a ContactField; wipe on close and lock unchanged.

**Confirm / Proof sheets**
- [ ] Fixed text only; HumanButtons; no default button on ConfirmSheet.
- [ ] Built by `make(...)` but always presented through `beginSheet` on a
      HardenedWindow in the app.

**Pages (lock, onboarding, address, notice)**
- [ ] Only L10n text and SF Symbols; buttons HumanButtons as today.
- [ ] The address page's fields stay SecureComposeView / ContactField.

### 6.2 Fonts (GlyphFlush)

- [ ] `GlyphFlush` flushes every content font (F1–F4) in the lock sequence
      and on letter teardown.
- [ ] SelfScan's glyph control covers F4 at least (the body font), and the
      harness case that checks GlyphFlush runs per font.
- [ ] Only fonts F1–F4 are ever passed to `TextLayout` (a grep: `TextLayout(font:`
      only with `ContentView.fontF…`).

### 6.3 New greps in scripts/test.sh

- Any `drawContent(` call (also `x.drawContent(` and `super.drawContent(`)
  is made only in OpaqueView.swift in `app/Sources`; overrides
  (`func drawContent(`) and comments are fine (review 8).
- No `toolTip` in `app/Sources`.
- No `NSPopover`, `NSSearchField`, `NSSharingService`, `NSTableView`,
  `NSOutlineView`, `NSCollectionView`, `NSBrowser`, `NSTokenField`,
  `NSComboBox` in `app/Sources` (added to the FORBIDDEN list, review 8).
- `autosave` in any case, on a code line of `app/Sources`, only as
  `autosavesConfiguration = false` (review 8: `setFrameAutosaveName` and
  `autosaveName` both fail).
- `tools/fixture` and `tools/snapshot` name no `orderFront`,
  `makeKeyAndOrderFront`, `activate(`, `runModal`, `beginSheet`, `.present(`
  (review 6).

## 7. Order of work

Each step ends with `scripts/build.sh`, `scripts/build.sh --instance b`,
`scripts/test.sh`, the snapshot tool in both appearances, and a commit.

1. **Snapshot tool first**, against today's UI (baseline PNGs). Move the
   fixture; ViewHost unchanged in behaviour.
2. **Fonts**: F1–F4, GlyphFlush per font, TextLayout line height, SelfScan.
3. **Main window**: toolbar, split view controller, sidebar, message list,
   ContactBar, reading pane, empty states.
4. **Compose sheet** layout.
5. **Sheets**: Kontakter (own code), Confirm, Proof.
6. **Pages**: lock, onboarding, address, notice.
7. **Tests and docs**: ViewHost, lock probe, capture-probe, test.sh greps,
   VERIFY.md rows, a DECISIONS.md entry, CLAUDE.md note.

## 8. Open questions for the owner

- **Q1. Innboks across all contacts.** Closed (review 2): a §1.10 matter,
  decided in DECISIONS.md D-0114. Brev starts on the first
  contact; a mailbox is read only when a human clicks it. The owner can
  still choose the core call `all_threads()` later.
- **Q2. New York for the letter body.** Proposed yes (§3.1). Say no, and F4
  becomes SF 15.
- **Q3. Unread dot.** Needs `MessageRow.read` and a "mark read" call in the
  core. Left out; the row keeps room for it.
- **Q4. Recipient picker.** Nytt brev goes to the selected contact (or the
  selected letter's). A picker would need a secure list in the compose
  sheet. Left out.
