# Tutorial: your first blocked file

In this lesson you run the firewall, watch it stop Claude Code from reading a file of fake bank data, and see the record it keeps. It takes about ten minutes.

You need everything from the [install steps](../README.md#install). Run all commands from the repository root unless a step says otherwise.

## 1. Start the firewall

```bash
CLOUD_BASE_URL= LOCAL_BASE_URL=http://127.0.0.1:11434/v1 LOCAL_MODEL=qwen3:14b WORST_CASE_MODEL=llama3.2:3b uv run agent-firewall
```

It prints a phone link, a dashboard link and a QR code. Open the dashboard link in your browser and leave this terminal running.

## 2. Open Claude Code in the demo project

In a second terminal:

```bash
cd demo/claude_project && claude
```

Accept the folder trust prompt. This project contains only fake data, and its `.claude/settings.json` connects Claude Code to the firewall.

## 3. Read a normal file

```text
Use the Read tool to read meeting_notes.md and tell me who owns the copy review
```

Claude answers Sam with no popup, because the file contains nothing sensitive.

## 4. Deny a sensitive file

```text
Use the Read tool to read transactions.csv and tell me the total spent
```

A popup appears before the file is opened. It names the file, states the worst case, and offers three buttons. An AI-written detail may appear too, and it is labeled because it can be wrong.

Click **Deny**. Claude reports that it could not read the file.

## 5. Keep the file on your Mac

Send the same message and click **Keep on my Mac**. Wait up to a minute.

A local model reads the file, and Claude receives only a summary with the number of transactions and the total, about $851.19. It never sees a card number.

## 6. Allow it

Send the same message and click **Allow**. Claude reads the file normally, so its contents go to Anthropic. That is safe here because the data is fake.

## 7. See what happens when the firewall is off

Press Ctrl+C in the firewall terminal, then ask Claude to read `meeting_notes.md`. Claude Code refuses, because this project requires the firewall.

## 8. Review the record

Open `audit.jsonl` in the repository root. It lists each action and decision without any file contents.

You have now seen each decision the firewall can make. To use it on your own work, see [protect your own project](how-to.md#protect-your-own-project).
