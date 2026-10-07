from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from agentreplay.cli import main
from agentreplay.core import InputError
from agentreplay.trace import compare, record, verify

EVENTS = [
    {"type": "prompt", "text": "Summarise the file for ada@example.com"},
    {"type": "tool_call", "tool": "read_file", "args": {"path": "a.txt"}},
    {"type": "answer", "text": "Done", "key": "sk-abcdefghijklmnopqrstuv"},
]


def chain() -> dict[str, Any]:
    return record({"events": EVENTS})


def statuses(result: dict[str, Any]) -> list[str]:
    return [f["status"] for f in result["findings"]]


def test_record_redacts_strings_and_keeps_shape() -> None:
    result = chain()
    assert result["events"][0]["event"]["text"] == "Summarise the file for [EMAIL_001]"
    assert result["events"][1]["event"]["args"] == {"path": "a.txt"}
    assert "sk-abc" not in json.dumps(result)
    assert result["events"][2]["event"]["key"] == "[TOKEN_001]"


def test_record_chain_links() -> None:
    events = chain()["events"]
    assert events[0]["previous"] == "0" * 64
    assert events[1]["previous"] == events[0]["hash"]


def test_verify_clean_chain_with_and_without_anchor() -> None:
    result = chain()
    assert statuses(verify({"events": result["events"]})) == ["PASS", "PASS", "PASS", "UNANCHORED"]
    anchored = verify({"events": result["events"]}, result["root_hash"])
    assert statuses(anchored)[-1] == "PASS"


def test_edit_is_detected_at_that_event() -> None:
    result = chain()
    edited = copy.deepcopy(result["events"])
    edited[1]["event"]["args"]["path"] = "secret.txt"
    got = statuses(verify({"events": edited}))
    assert got[:3] == ["PASS", "TAMPERED", "PASS"]


def test_removed_event_is_detected() -> None:
    events = chain()["events"]
    del events[1]
    assert "TAMPERED" in statuses(verify({"events": events}))


def test_reordered_events_are_detected() -> None:
    events = chain()["events"]
    events[0], events[1] = events[1], events[0]
    assert statuses(verify({"events": events})).count("TAMPERED") >= 2


def test_whole_chain_rewrite_is_caught_only_with_an_anchor() -> None:
    original = chain()
    forged = record({"events": [*EVENTS[:2], {"type": "answer", "text": "Different"}]})
    assert "TAMPERED" not in statuses(verify({"events": forged["events"]}))
    assert "TAMPERED" in statuses(verify({"events": forged["events"]}, original["root_hash"]))


def test_malformed_event_is_reported_not_raised() -> None:
    result = verify({"events": [1]})
    assert result["findings"][0]["status"] == "TAMPERED"
    assert "not an object" in result["findings"][0]["message"]


def test_empty_trace_needs_review() -> None:
    assert statuses(verify({"events": []})) == ["NEEDS_REVIEW"]


def test_record_rejects_non_object_events() -> None:
    with pytest.raises(InputError):
        record({"events": ["text"]})


def test_compare_ignores_recording_time_and_hash_context() -> None:
    a, b = chain()["events"], chain()["events"]
    assert statuses(compare({"events": a, "other_events": b})) == ["MATCH"]


def test_compare_reports_changed_and_extra_positions() -> None:
    other = [*EVENTS[:2], {"type": "answer", "text": "Changed"}, {"type": "extra"}]
    result = compare({"events": EVENTS, "other_events": other})
    assert result["findings"][0]["evidence"]["changed_indices"] == [2, 3]


def test_cli_round_trip(tmp_path: Path) -> None:
    src = tmp_path / "events.json"
    src.write_text(json.dumps({"events": EVENTS}), encoding="utf-8")
    recorded = tmp_path / "trace.json"
    assert main(["record", str(src), "-o", str(recorded)]) == 0
    root = json.loads(recorded.read_text(encoding="utf-8"))["root_hash"]
    out = tmp_path / "v.json"
    assert main(["verify", str(recorded), "--root-hash", root, "--strict", "-o", str(out)]) == 0
    assert main(["verify", str(recorded), "--root-hash", "0" * 64, "--strict", "-o", str(out)]) == 1


def test_cli_strict_unanchored_is_not_ok(tmp_path: Path) -> None:
    src = tmp_path / "events.json"
    src.write_text(json.dumps({"events": EVENTS}), encoding="utf-8")
    recorded = tmp_path / "trace.json"
    main(["record", str(src), "-o", str(recorded)])
    assert main(["verify", str(recorded), "--strict", "-o", str(tmp_path / "v.json")]) == 1


def test_cli_refuses_to_overwrite_its_input(tmp_path: Path) -> None:
    src = tmp_path / "events.json"
    src.write_text(json.dumps({"events": EVENTS}), encoding="utf-8")
    assert main(["record", str(src), "-o", str(src)]) == 2
    assert json.loads(src.read_text(encoding="utf-8"))["events"] == EVENTS
