# Agent Firewall

A hybrid firewall that keeps sensitive agent data on your device and asks your phone before risky actions.

When Claude Code tries to open a file with financial or health data, a popup explains the worst case and lets you deny it, allow it, or keep the file on your Mac so only a local model reads it. Other OpenAI-compatible agents can connect through a built-in proxy, and a dashboard shows what ran where and why.

> **Hackathon-stage software.** It raises the bar against mistakes and tricked agents, but it is not a complete security boundary. Read [what it does not stop](docs/design.md#what-it-does-not-stop) before pointing it at real money or health data.

## Install

Requires macOS, [uv](https://docs.astral.sh/uv/), [Ollama](https://ollama.com) and [Claude Code](https://code.claude.com) 2.1.295 or newer.

```bash
git clone git@github.com:g7xu/agent-firewall.git
cd agent-firewall
cp .env.example .env
uv sync
ollama pull qwen3:14b
ollama pull llama3.2:3b
```

## Usage

Start the firewall and leave it running:

```bash
CLOUD_BASE_URL= LOCAL_BASE_URL=http://127.0.0.1:11434/v1 LOCAL_MODEL=qwen3:14b WORST_CASE_MODEL=llama3.2:3b uv run agent-firewall
```

In a second terminal, open Claude Code in the demo project, which contains only fake data:

```bash
cd demo/claude_project && claude
```

Then ask it:

```text
Use the Read tool to read transactions.csv and tell me the total spent
```

A popup appears before the file is opened. The [tutorial](docs/tutorial.md) walks through every button.

To compare attacks with the firewall off and on, with no models needed:

```bash
uv run python -m demo.eval
```

Those results use a scripted model that always falls for the attack, so they test the firewall's plumbing, not how often a real model gets tricked.

## Documentation

- [Tutorial: your first blocked file](docs/tutorial.md)
- [How-to guides](docs/how-to.md): protect your own project, approve from your phone, connect another agent
- [Configuration reference](docs/configuration.md)
- [Design and limits](docs/design.md)

## Contributing

Run `uv run pytest` before opening a pull request.

## License

No license has been chosen yet, so all rights are reserved.
