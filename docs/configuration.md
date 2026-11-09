# Configuration reference

Settings are read from `.env` in the directory where the firewall starts.

| Variable | Required | Default | Description |
|---|---|---|---|
| `CLOUD_BASE_URL` | No | empty | OpenAI-compatible cloud endpoint. Empty keeps everything local. |
| `CLOUD_API_KEY` | No | empty | Injected by the firewall, so the agent never holds it. |
| `CLOUD_MODEL` | No | request's model | Model name sent to the cloud. |
| `LOCAL_BASE_URL` | Yes for protected data | `http://127.0.0.1:11434/v1` | OpenAI-compatible local endpoint, such as Ollama. |
| `LOCAL_MODEL` | Yes with Ollama | request's model | Model name sent to the local runtime. Also writes Keep on my Mac summaries. |
| `PROXY_PORT` | No | `8787` | Agent-facing port, bound to loopback. |
| `PHONE_PORT` | No | `8788` | Approval page port, bound to all interfaces. |
| `PHONE_TOKEN` | No | random per run | Secret in the phone URL. |
| `APPROVAL_TIMEOUT_SECONDS` | No | `90` | Unanswered approvals are treated as denied after this. |
| `ALLOWED_HOSTS` | No | empty | Hostnames agents may contact without asking. |
| `KNOWN_RECIPIENTS` | No | empty | Email addresses agents may write to without asking. |
| `CANARIES` | No | empty | Planted strings. A tool call containing one is blocked. |
| `AUDIT_PATH` | No | `audit.jsonl` | Append-only event log, holding labels and hashes only. |
| `AGENT_WORKDIR` | No | empty | The agent's working directory on this machine. Set it to hold relative paths that symlinks carry outside it. |
| `POPUP` | No | `mac` | `mac` shows a native dialog for Claude Code actions; any other value uses only the phone page. |
| `WORST_CASE_MODEL` | No | empty | Local model that adds a specific, labeled sentence under the fixed worst-case warning, served from `LOCAL_BASE_URL`. It has 3 seconds to answer. Empty shows only the fixed sentence. |
| `SCAN_ROOTS` | No | `~/Documents,~/Desktop,~/Downloads` | Folders scanned in the background. Each project an agent works in is added automatically. Empty scans only those projects. |
| `INDEX_PATH` | No | `~/.agent-firewall/index.sqlite` | Saved scan results, holding hashed paths and labels only. Empty turns off the background scan. |
| `POLICY_PATH` | No | `~/.agent-firewall/policy.json` | Ideas and rules typed into the dashboard. Empty keeps them in memory until restart. |
