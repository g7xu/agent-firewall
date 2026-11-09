# Design and limits

## Threat model

The firewall protects you from your own agent after it has been tricked by something it read, such as a poisoned email, web page or skill. It does not try to identify AI-written malware.

## Why a proxy

Local and cloud runtimes share the OpenAI-compatible chat format, so a harness adopts the firewall by changing one base URL. That single point sees every prompt going up and every tool call coming back. Giving the firewall the only cloud key means the agent has no other route to the provider.

## Why no model makes these decisions

Tool results and model output are attacker-influenced. A model reviewing them can be injected by the same text, so routing and tool review are deterministic. A learned reviewer could later handle low-stakes reversible actions, but it should never be able to waive a hold on money, health records or data leaving the machine.

## Why labels instead of content matching

Once a session has read protected data it stays labeled and local. Scanning outbound content alone misses paraphrases and encodings, while the label survives them.

## What it does not stop

- **Leaks through allowed channels.** Paraphrased data sent to an allowed host passes. The demo's case A14 exists to show this.
- **Actions the proxy never sees.** A harness can run code without a model tool call, and the proxy can't prevent a client from executing something other than what was approved. Full enforcement needs the tools themselves behind a gateway.
- **Other API shapes.** Only `/v1/chat/completions` is implemented.
- **Sensitive data the patterns miss.** Detection covers formats and keywords, so an unusual phrasing can reach the cloud. Canaries and session labels reduce this but don't remove it.
- **Symlinks, unless `AGENT_WORKDIR` is set.** A planted link makes an innocent relative name such as `notes.txt` open a key, and that is invisible in a tool call's text. Setting `AGENT_WORKDIR` makes the firewall resolve relative paths on disk before allowing them. That check still races a link created after review, and it only helps when the agent shares this machine and works in that directory. Closing it fully needs the tools themselves behind a gateway.
- **Where a relative path starts.** The firewall never sees the agent's working directory, so a plain name is only judged by its spelling, even if the agent happens to be running inside a secret directory.
- **Files a named search root contains.** `search_files` needs an explicit relative root, but what lies under that root is up to the tool.
- **Cloud-hosted agents** that don't send their model traffic through this proxy.
- **A compromised Mac account.** Anything running as the same user can tamper with the firewall.

The approval page uses plain HTTP with a URL token, which suits a demo network or phone hotspot only. Production needs TLS and device-bound signatures.
