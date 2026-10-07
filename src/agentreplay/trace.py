"""Hash-chained agent traces.

Each event is stored with its position, the hash of the previous event and its own hash, so
editing, reordering, inserting or removing an event breaks the chain from that point on.
This is tamper-evident, not tamper-proof: someone who can rewrite the whole file can
rebuild a valid chain. Keep the root hash somewhere they cannot reach (a ticket, an email,
a signed commit) and pass it to `verify --root-hash`.
"""

from __future__ import annotations

from typing import Any

from .core import InputError, digest, finding, report, require
from .redact import redact

GENESIS = "0" * 64


def _clean(value: Any) -> Any:
    """Redact every string value, keeping the shape of the event."""
    if isinstance(value, str):
        return redact(value)[0]
    if isinstance(value, list):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    return value


def record(data: dict[str, Any]) -> dict[str, Any]:
    events = require(data, "events", list)
    chain: list[dict[str, Any]] = []
    previous = GENESIS
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise InputError(f"Event {index} must be an object")
        body = {"index": index, "previous": previous, "event": _clean(event)}
        previous = digest(body)
        chain.append({**body, "hash": previous})
    return report(
        "AgentReplay",
        [
            finding(
                "RECORDED",
                "Events redacted and chained. Store the root hash somewhere separate.",
                events=len(chain),
                root_hash=previous,
            )
        ],
        events=chain,
        root_hash=previous,
        scope="recording and integrity checking only; no model re-runs or automatic capture",
    )


def verify(data: dict[str, Any], root_hash: str | None = None) -> dict[str, Any]:
    events = require(data, "events", list)
    out: list[dict[str, Any]] = []
    previous = GENESIS
    for index, event in enumerate(events):
        problems = []
        if not isinstance(event, dict):
            problems.append("not an object")
        else:
            if event.get("index") != index:
                problems.append(f"index is {event.get('index')!r}, expected {index}")
            if event.get("previous") != previous:
                problems.append("previous hash does not match the preceding event")
            body = {k: v for k, v in event.items() if k != "hash"}
            if event.get("hash") != digest(body):
                problems.append("content does not match its own hash")
        out.append(
            finding(
                "PASS" if not problems else "TAMPERED",
                "Hash-chain check." if not problems else "; ".join(problems),
                index=index,
            )
        )
        previous = event.get("hash", "") if isinstance(event, dict) else ""
    anchor = root_hash or data.get("expected_root_hash")
    if not events:
        out.append(finding("NEEDS_REVIEW", "The trace is empty."))
    elif anchor:
        match = previous == anchor
        out.append(
            finding(
                "PASS" if match else "TAMPERED",
                "Final hash matches the root hash you supplied."
                if match
                else "Final hash differs from the root hash you supplied; events were changed, "
                "added or removed after it was recorded.",
                root_hash=previous,
            )
        )
    else:
        out.append(
            finding(
                "UNANCHORED",
                "No root hash from an independent source was supplied, so a rewritten whole "
                "chain would not be detected.",
                root_hash=previous,
            )
        )
    return report("AgentReplay", out, root_hash=previous)


def compare(data: dict[str, Any]) -> dict[str, Any]:
    first = require(data, "events", list)
    second = require(data, "other_events", list)

    def key(event: Any) -> str:
        # Compare content only, so two traces recorded at different times still match.
        if isinstance(event, dict) and "event" in event:
            return digest(event["event"])
        return digest(event)

    a, b = [key(e) for e in first], [key(e) for e in second]
    changed = [i for i in range(max(len(a), len(b))) if i >= len(a) or i >= len(b) or a[i] != b[i]]
    return report(
        "AgentReplay",
        [
            finding(
                "DIFFERENT" if changed else "MATCH",
                f"{len(changed)} event position(s) differ."
                if changed
                else "Event content is identical.",
                changed_indices=changed,
                first_length=len(a),
                second_length=len(b),
            )
        ],
    )
