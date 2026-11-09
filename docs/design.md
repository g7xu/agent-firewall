# Design and limits

## Threat model

The firewall protects you from your own agent after it has been tricked by something it read, such as a poisoned email, web page or skill, and from an agent's honest mistakes. It does not try to identify AI-written malware.

## One app behind each agent's plug

Each vendor's agent exposes its own extension point, and none of them has a reason to build a view across its competitors. The firewall turns every agent's request into the same review, so rules, popups and the audit record live in one place and a new agent needs only a connector.

Claude Code connects through a `PreToolUse` HTTP hook. Agents with no such hook can use the OpenAI-compatible proxy, which sees every prompt going up and every tool call coming back. Giving the proxy the only cloud key means the agent has no other route to the provider.

## Why hooks are set to block on failure

Claude Code lets an action through by default when a hook times out or its server is unreachable. A guardrail that disappears when it crashes isn't one, so the demo configuration sets `onFailure: block`. The cost is that Claude Code stops working in that project while the firewall is off.

## Why files are scanned before they are read

Once a read happens, the contents are already on their way to the model provider, so the check has to run first. Output from shell commands can only be judged afterward, which is why any command the firewall can't fully understand asks before running.

## Why no model makes these decisions

Tool results and model output are attacker-influenced. A model reviewing them can be injected by the same text, so routing and tool review are deterministic. A learned reviewer could later handle low-stakes reversible actions, but it should never be able to waive a hold on money, health records or data leaving the machine.

## Why the worst-case warning is mostly not written by AI

Every popup shows a fixed sentence for its kind of action. A small local model may add a more specific one, shown separately and labeled as possibly wrong. Filters can catch a sentence that reassures or invents a number, but they can't prove it doesn't understate the risk, so the model's text never replaces the guarantee. The model receives only extracted facts such as an amount or destination, never file contents or message bodies.

## Why Keep on my Mac rescans the summary

The local model reads the sensitive file, so that file can trick it into repeating what it should hide. Its summary is scanned again and discarded whole on any match. Redacting instead would leave a partly trusted sentence in front of the cloud model.

## How sensitive files are found with no setup

A background scan reads each folder on this machine and saves one result per file, so a popup can answer instantly. Quick text files go first, then PDFs and images, using poppler for text and Apple's on-device Vision framework for OCR. Results are checked against each file's size and modification time, and a changed file is read again.

A file the scan can't judge takes on the character of its folder when several of its neighbors are sensitive, so a blurry scan among tax returns counts as financial. Errors lean toward an extra popup. Paths are stored only as hashes, because a list of where private files live is sensitive in itself.

## Why typed rules can only tighten

The dashboard has no "allow" rule, so a stolen link or a confused agent can't use it to switch a protection off. Rules match decoded text, ignoring case, extra spaces and invisible characters, and can also match field names, which at worst causes an extra stop. File names and rule editing are limited to this Mac, because the page travels over plain HTTP on the network.

## Why labels instead of content matching

Once a session has read protected data it stays labeled. Scanning outbound content alone misses paraphrases and encodings, while the label survives them.

## What it does not stop

This list records known gaps, including ones found by adversarial testing. Recognizing dangerous things by name and pattern will always leave some. Stronger protection would run the agent in a sandbox that can reach only approved folders.

**Data and secrets**

- **Secrets with unremarkable names.** A project-wide search can read a file such as `secrets/prod.yaml` or `token.json` without a popup, because neither its name nor its contents match a pattern.
- **Unusual data formats.** A card number written with dots or unusual separators isn't recognized, and an unusual phrasing of health or financial data can reach the cloud.
- **Hard links.** A file with an innocent name can be a second name for a private key, which path checks can't see.
- **Symlinks on the proxy path, unless `AGENT_WORKDIR` is set.** The Claude Code connector always resolves them. Either way, a link created after review can race the check.
- **Leaks through allowed channels.** Paraphrased data sent to an allowed host passes. The demo's case A14 exists to show this.

**Keep on my Mac**

- **Long files are cut off.** The local model reads only the first 20,000 characters and nothing warns when it stops early, so totals for large files will be wrong.
- **Figures can be wrong.** A small model's arithmetic is unreliable. Its summary, including totals and categories, still goes to the cloud.
- **It is only offered for single text files opened with the Read tool.** Commands such as `cat` offer only Deny and Allow.

**Scale**

- **Not yet scanned.** A search reads at most 500 files that have no saved result, then asks because it can't vouch for the rest.
- **No watching for new files between scans.** A changed file is caught when an agent opens it, but folder totals can lag until the next start.
- **Pictures without words.** OCR reads text only, so a photo with no text counts as clean unless its folder is sensitive.
- **PDFs mixing text pages and scanned pages.** Only the text pages are read. OCR stops after 10 pages and marks the file as partly unread.

**Reach**

- **Cloud-hosted agents** that don't use a connector or this proxy, including vendors' consumer agents.
- **Actions the proxy never sees.** A harness can run code without a model tool call, and a client can parse tool calls out of plain text. The proxy reviews only structured tool calls and can't prevent a client from executing something other than what was approved.
- **Other API shapes.** Only `/v1/chat/completions` is implemented.
- **A compromised Mac account.** Anything running as the same user can tamper with the firewall or remove the hook. Managed settings can stop an agent disabling hooks, but they need an administrator.

The approval page uses plain HTTP with a URL token, which suits a demo network or phone hotspot only. Production needs TLS and device-bound signatures.
