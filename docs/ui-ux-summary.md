# UI/UX summary

This document describes Agent Firewall's user experience as it is built today:
what each surface is, the design decisions behind it, how the pieces fit
together in one interaction model, and where the experience is known to be
weak. It is a summary of the shipped UI — the dashboard
(`src/agent_firewall/static/dash.html`), the phone approval page
(`src/agent_firewall/static/phone.html`), the native macOS popup
(`src/agent_firewall/popup.py`), and the public website (the `gh-pages`
branch) — not a redesign proposal. Recommendations are collected separately
at the end and are labelled as such.

## The one idea the whole UI serves

> Your AI agent stops at the line, and you decide what crosses it.

Every surface is organised around a single spatial metaphor: **the line**.
On one side is *On this device* — data that never leaves the user's Mac. On
the other side is *Sent to the cloud* — data a cloud model has seen. Between
them sits the gate, where an action is stopped and a person decides. The
website hero, the dashboard's main visual, and the wording of every approval
card are all expressions of that same line, so a user who has seen any one
surface already understands the others.

Three rules follow from it, and each is enforced by the interface, not just
stated in it:

1. **You see it before it happens.** Nothing sensitive moves until the user
   has seen a card naming the action, the exact facts (file, amount,
   destination), and the worst case.
2. **No answer means no.** Approval requests expire and become denials
   (90 seconds by default). The safe outcome is the default outcome on every
   surface: Deny is the popup's default button, the phone countdown reads
   "Denied automatically in …s", and a timed-out dialog returns Deny.
3. **Friction is proportional to risk.** Denying is one tap. Approving on the
   phone requires an 800 ms press-and-hold with a filling progress bar, so
   the consequential action is deliberately harder than the safe one.

## The four surfaces

### 1. Approval popup (macOS, native)

The moment of decision for Claude Code actions. Implemented as a native
AppleScript dialog, so it looks and behaves like the operating system, not
like a web app asking for trust.

- **Card structure, top to bottom:** a plain title ("Claude Code wants to
  read a sensitive file"), the facts as `label: value` lines, a fixed
  worst-case sentence, an optional AI-written detail, then one `⚠` line per
  reason (for example "Contains financial data", "Allowing sends this to
  Anthropic's cloud").
- **Buttons:** Deny (default) / Keep on my Mac (only when that option is
  possible, i.e. a single text file read) / Allow. The middle option is the
  product's distinctive move: instead of a binary yes/no, the user can let a
  local model read the file and pass only a short summary to the cloud agent.
- **Safety details in the implementation:** card text is passed through
  `argv`, so a file name can never become AppleScript source; a dialog that
  times out or is dismissed returns Deny.

### 2. Phone approval page

The same decision, on the phone, for when the user is away from the Mac.
A single self-contained page; no framework, no build step.

- **Cards stack newest-first in effect:** each pending request is a card with
  the same title / facts / worst-case / reasons structure as the desktop
  popup, so there is nothing new to learn. The worst case sits in its own
  dark-red block.
- **Hold to approve:** the Approve button must be held for 800 ms while a
  green fill sweeps across it; releasing early cancels. Deny and
  Keep on my Mac are ordinary taps. This asymmetry is the page's central UX
  decision.
- **Liveness and feedback:** the page polls every second, shows the
  auto-deny countdown on each card, vibrates once (200 ms) when a new card
  arrives, dims a card while its decision is being sent, and otherwise shows
  a calm idle state: "Nothing needs you right now."
- **Security as UX:** all displayed fields are rendered with `textContent`
  only, because every field on the card can be attacker-controlled. Access is
  via a URL token over plain HTTP — the docs restrict it to trusted networks
  and name TLS plus device-bound signatures as production work.

### 3. Dashboard

The reflective surface: where everything ended up, and where the user
teaches the firewall new rules. Served locally; a single page that polls
every 2 seconds.

- **The line, drawn at full width.** The header row carries the brand mark
  (a vertical gradient bar running local-green → denied-red → cloud-blue),
  the scan state, and a total "checked" counter that expands into
  "N files and N agent actions". Below it, the line visual: giant numerals
  (up to 150 px, weight 200) for *On this device* on the left and *Sent to
  the cloud* on the right, with the gate in the centre holding three stops —
  Denied, Sensitive, and Unreadable or unsure — between two glowing vertical
  rules that animate upward on load.
- **Every number is a filter.** The counters, the two sides, the three stops,
  and the checked total are all buttons with `aria-pressed`; selecting one
  filters the list below to that category and re-titles it. There is no
  separate "reports" view to discover.
- **The list.** Flagged files and agent actions, newest first, each row with
  a left border in its category colour, the target in monospace, a plain
  state label ("Kept on device", "No answer, denied", "Allowed by you"…),
  human labels for the data involved (Financial, Health, Identity,
  Credentials, Bait secret, Sensitive folder), the detection method in words
  (Text file, Scanned PDF, Image…), and a relative-friendly timestamp. A
  search box filters by file, command, or agent. Each category has its own
  written empty state that explains what *would* appear there.
- **Policy composer — tighten only.** "Add an idea or rule" offers three
  modes: Idea (saved, changes nothing), Always ask, and Block. There is
  deliberately **no "allow" mode**: a stolen dashboard link or a confused
  agent cannot use the UI to switch a protection off. Placeholders and hints
  rewrite themselves per mode, and the panel below shows Your rules, Your
  ideas, the Built-in rule groups (collapsed, with counts), and Settings
  translated into plain language ("Popup waits: 90 seconds, then denies").
- **Failure honesty:** if the firewall stops answering, a notice says the
  numbers may be out of date; a 403 explains that the page needs the full
  link, opened on the Mac the firewall is running on.

### 4. Public website (`gh-pages`)

The explanatory surface for people who have not installed anything yet.

- **Hero:** the headline "Your AI agent stops at the line", one lede
  sentence (money, health data, passwords), and the demo video framed by the
  same gate visual — *On this device* to its left, *Sent to the cloud* to
  its right.
- **A faithful popup mock** beside "You see it before it happens", using the
  real A05-style example (transactions.csv, the fixed worst-case sentence,
  the same three choices, Deny styled as the default).
- **The dashboard's five outcomes as prose:** Denied / Sensitive /
  Unreadable or unsure / On this device / Sent to the cloud, each with its
  one-line definition — the same taxonomy, in the same colours, as the
  dashboard itself.
- **Proof, with its limits attached:** "350 of 350" sensitive files found
  among 7,000 in 26 seconds, and "16 to 1" attacks that got out, firewall
  off vs. on — each figure carries a small-print line stating the conditions
  (synthetic files; a scripted model that always obeys the attacker; the one
  miss kept in on purpose). A "What it doesn't do yet" section lists the
  boundaries in plain language before the install instructions.

## One design language across all four

| Token | Value | Meaning everywhere it appears |
|---|---|---|
| `--local` | `#62e4b4` (mint) | Stayed on this device |
| `--cloud` | `#92ccff` (blue) | Sent to the cloud |
| `--denied` | `#ff808b` (red) | Denied / blocked |
| `--sensitive` | `#ffcb5e` (amber) | Sensitive data involved |
| `--unsure` | `#cdaeff` (violet) | Unreadable or unsure |
| `--night` / `--dusk` / `--haze` | `#15112e` / `#1f1944` / `#2d2660` | Dashboard and website background scale |

- **Typography:** one display stack (Avenir Next → system-ui) everywhere;
  numerals use tabular figures so counters do not jitter as they update;
  the phone page uses the system stack only, at 17 px, for one-handed
  reading.
- **Motion:** used sparingly and semantically — counters count up once on
  first load (800 ms ease-out), the gate lines rise on entry, the hold
  button fills while held. `prefers-reduced-motion` disables animation and
  transitions on the dashboard and website, and the counters render
  instantly.
- **Accessibility:** visible `:focus-visible` outlines, `aria-pressed` on
  every toggle-like control, `role="status"` live regions for scan state
  and form feedback, labelled search and textarea inputs, and touch targets
  sized for the phone page's full-width buttons.
- **Responsive behaviour:** the dashboard's line collapses at 800 px into a
  single column and the gate's vertical rules become horizontal ones;
  the two-column work area stacks at 1000 px; the website reflows its gate
  grid at 980 px and 620 px.

## The language rule: worst case first, in plain words

The UI's most distinctive content decision is how risk is worded, and it is
split in two on purpose (see `src/agent_firewall/worst_case.py`):

- **The guaranteed sentence is fixed, per action kind** — written by the
  project, never by a model: "This data leaves your Mac and can't be taken
  back." / "The money is gone and may not be recoverable." / "Anyone who
  gets this file could sign in as you."
- **A local model may add one specific sentence** ("It goes to …",
  "The amount is $…"), but it is shown separately and labelled
  "AI-written detail, may be wrong", and it only reaches the card if it
  passes filters that reject reassurance ("safe", "no risk", "don't
  worry"), invented numbers or addresses, and overstatement. The model sees
  only extracted facts, never file contents, and has 3 seconds; silence
  simply means the fixed sentence stands alone.

The result is a card a non-technical user can act on in seconds, whose most
important sentence the project can actually stand behind.

## The core flows

1. **First blocked file (the tutorial's path):** start the firewall → ask
   Claude Code to read a normal file (nothing happens — silence is the UX
   for safe actions) → ask for a sensitive file → popup → Deny (agent is
   told it could not read it), Keep on my Mac (local summary only), or Allow
   (contents go to the cloud) → the decision appears in the dashboard and
   in `audit.jsonl`, without file contents.
2. **Approve from the phone:** scan the QR code the firewall prints → leave
   the page open → a card arrives with vibration → hold to approve, tap to
   deny or keep local → first answer (phone or Mac) wins; no answer denies.
3. **Teach it a rule:** dashboard → Add an idea or rule → Always ask or Block
   → type the text to watch for → it applies from the next action, and can
   be deleted under Current policy.
4. **Review:** open the dashboard → read the line (where things ended up) →
   click a category → search within it → check scan state and settings.

## Measured results the UI reports

From the scripted evaluation (`demo.eval`, `results/latest.json`): with the
firewall off, 16 of 16 attacks got out and 9 canary secrets reached the
cloud; with it on, 1 of 16 got out (A14, a paraphrase leaked through an
allowed host — kept in the demo on purpose), 0 canaries reached the cloud,
and 0 of 7 benign tasks raised a false alarm. The background scan found
350 of 350 planted sensitive files among 7,000 in 26 seconds. These numbers
test the firewall's plumbing against a model that always falls for the
attack; the website states that caveat next to the figures.

## Strengths

- **One metaphor, four surfaces.** The line, the five outcomes, the colour
  tokens, and the card structure are identical on the website, dashboard,
  phone, and popup; learning one surface teaches all of them.
- **Safe defaults are structural,** not copy: default button, hold-to-
  approve asymmetry, auto-deny countdowns, fail-closed hooks.
- **Honesty is part of the interface:** labelled AI text, caveats beside the
  proof numbers, a published "what it does not stop" list, empty states
  that explain rather than apologise.
- **No model in the decision path,** and the UI says why: routing and
  review are deterministic because the text being reviewed can be hostile.
- **Rendering is defensive:** `textContent`-only DOM construction on both
  web surfaces, because file names and commands are attacker-controlled.

## Known UX gaps (from the project's own limits list)

- The phone page's plain-HTTP + URL-token design is demo-grade; the docs
  say so, but the page itself gives the user no in-context cue about which
  networks are safe.
- Keep on my Mac silently truncates files at 20,000 characters and a small
  model's arithmetic can be wrong — neither caveat reaches the approval
  card or the summary the user sees.
- The popup timeout (90 s) and the phone countdown can pressure a decision
  the user has not finished reading; there is no "ask me again" path, only
  deny-by-default.
- The dashboard explains tighten-only rules in its hints, but a first-time
  user looking for an "allow once, always" control gets no explanation of
  why it does not exist until they read the design doc.
- Scan coverage has edges the dashboard only hints at ("Scan finished"):
  pictures without words, PDFs with mixed text/scanned pages (OCR stops at
  10 pages), and files not yet scanned can all be miscounted until opened.

## Recommendations (proposals, not current behaviour)

1. Put the network warning on the phone page itself (one line under the
   header) instead of only in the docs.
2. When Keep on my Mac truncates a file or the summary's figures come from
   the local model, label the result card in the dashboard the same way
   AI worst-case text is labelled on the approval card.
3. Add a "snooze / decide later" state that keeps the deny-by-default
   guarantee but re-prompts once, for cards that expire unread.
4. Explain tighten-only in the composer the first time it is opened, in
   one sentence, next to the mode switch.
5. Show scan coverage honestly in the dashboard header: files checked,
   files partly read, files not yet scanned — the data already exists in
   the scan state.

---

*Contribution note: this summary was written from the code and docs on
`main` at `bf72cfa` (the merge of PRs #2–#5) and the `gh-pages` site. File
paths and token values above are taken from those sources; behaviour that
could not be verified from source is described as documentation states it.*
