# Agent Firewall

A hybrid firewall that keeps sensitive agent data on your device and asks your phone before risky actions.

## Install

Requires [uv](https://docs.astral.sh/uv/).

```bash
git clone git@github.com:g7xu/agent-firewall.git
cd agent-firewall
cp .env.example .env
uv sync
```

## Usage

Run the attack evaluation with the firewall off and on:

```bash
uv run python -m demo.eval
```

Try the live demo, using one terminal for each command:

```bash
uv run python -m demo.world
```

```bash
uv run agent-firewall
```

Scan the QR code with a phone on the same network, then run an attack that asks for approval:

```bash
uv run python -m demo.agent --case A05
```

Add `--no-firewall` to see the same attack succeed. Case A01 shows a planted secret being blocked with no prompt, and B07 is a legitimate refund to approve.

To protect a real agent, set the upstreams in `.env` and point the agent's OpenAI base URL at `http://127.0.0.1:8787/v1`. With Ollama, that means `LOCAL_BASE_URL=http://127.0.0.1:11434/v1` and a `LOCAL_MODEL` you have pulled.

The demo uses only synthetic data, and its tools never touch your system. A real agent's tools do, so try it under a separate macOS user with no real credentials.

## Documentation

- [Configuration reference](docs/configuration.md)
- [Design and limits](docs/design.md)

## Contributing

Run `uv run pytest` before opening a pull request.

## License

No license has been chosen yet, so all rights are reserved.
