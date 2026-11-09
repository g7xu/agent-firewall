# How-to guides

## Protect your own project

1. Start the firewall as shown in the [README](../README.md#usage).
2. Copy the hook settings into your project:

   ```bash
   mkdir -p /path/to/project/.claude && cp demo/claude_project/.claude/settings.json /path/to/project/.claude/
   ```

3. Start a new Claude Code session in that project.

Claude Code in that project refuses every action while the firewall is off. To stop using it, delete that `settings.json`, or remove its `hooks` entry if the file holds other settings.

Try this under a separate macOS user with no real credentials until you have read the [limits](design.md#what-it-does-not-stop).

## Approve from your phone

1. Connect your phone to the same network as your Mac. If venue Wi-Fi blocks it, connect the Mac to your phone's hotspot.
2. Scan the QR code the firewall prints.
3. Keep the page open.

The Mac popup and the phone both stay active, and the first answer wins. To use only the phone, set `POPUP=off`. The page uses plain HTTP with a URL token, so use it only on a network you trust.

## Reduce popups

Set `ALLOWED_HOSTS` and `KNOWN_RECIPIENTS` in `.env`. See the [configuration reference](configuration.md). Commands the firewall can't fully understand always ask.

## Connect an OpenAI-compatible agent

1. In `.env`, set `LOCAL_BASE_URL` and `LOCAL_MODEL`. To allow cloud use for non-sensitive work, also set `CLOUD_BASE_URL`, `CLOUD_API_KEY` and `CLOUD_MODEL`.
2. Start the firewall with `uv run agent-firewall`.
3. Point the agent's base URL at `http://127.0.0.1:8787/v1` and remove its own cloud key.

Only `/v1/chat/completions` is supported.

## Run the scripted attack demo

Use the default `.env` copied from `.env.example`, with one terminal for each command:

```bash
uv run python -m demo.world
```

```bash
uv run agent-firewall
```

```bash
uv run python -m demo.agent --case A05
```

Add `--no-firewall` to see the same attack succeed. Case A01 shows a planted secret blocked with no prompt, and B07 is a legitimate refund to approve. Cases are defined in `demo/cases.json`.
