# AgentReplay

A tamper-evident, redacted record of what an AI agent did.

Give AgentReplay the events from an agent run (prompts, tool calls, answers). It redacts secrets in every string, then chains the events with SHA-256 so that editing, reordering, inserting or removing any event is detectable. It uses only the Python standard library and makes no network requests.

## Install

Requires Python 3.10 or newer.

```bash
pip install git+https://github.com/seun-john/agentreplay.git
```

## Use

```bash
agentreplay record events.json -o trace.json        # redact and chain
agentreplay verify trace.json --root-hash <hash>    # check integrity
agentreplay compare two-runs.json                   # compare two traces by content
```

`events.json` is `{"events": [{"type": "prompt", "text": "..."}, {"type": "tool_call", "tool": "read_file", "args": {"path": "a.txt"}}]}`. Each event must be an object; keys and structure are preserved.

`record` writes the chained events and a `root_hash`. **Store that hash somewhere the trace's owner cannot edit**: a ticket, an email to yourself, a signed commit. `verify` then reports `PASS` or `TAMPERED` per event, and compares the final hash with the one you kept:

| Finding | Meaning |
| --- | --- |
| `PASS` | The event's index, previous-hash link and own hash are all consistent. |
| `TAMPERED` | The event was edited, moved, or its neighbours changed. The message says which check failed. |
| `UNANCHORED` | The chain is internally consistent but you gave no independent root hash. |
| `NEEDS_REVIEW` | The trace is empty. |

`compare` takes `{"events": [...], "other_events": [...]}` and lists the positions whose content differs. It compares content only, so two recordings of the same run made at different times match.

All commands take `-o report.json`, `--html report.html` and `--strict`. Exit codes: 0 completed, 1 `--strict` and something other than `PASS`, `RECORDED` or `MATCH` was reported (an unanchored verification counts), 2 unusable input.

## Limits

- **Tamper-evident, not tamper-proof.** Anyone who can rewrite the whole file can rebuild a valid chain. Only an independently stored root hash catches that.
- Redaction is pattern-based (emails, phone numbers, cards, national IDs, API keys, passwords, private keys). Names and free-text identifiers are not caught. Read a trace before you share it.
- Only string values are redacted. Keys are left as they are.
- AgentReplay records what you give it. It does not capture agent activity, re-run a model or track cost.

## Develop

```bash
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest -q
```

MIT licence.
