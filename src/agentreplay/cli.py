"""Command line for AgentReplay."""

from __future__ import annotations

import argparse
from typing import Any

from .runner import Command, main_wrapper, run
from .trace import compare, record, verify


def _record(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    return record(data)


def _verify(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    return verify(data, args.root_hash)


def _compare(args: argparse.Namespace, data: Any) -> dict[str, Any]:
    return compare(data)


COMMANDS = {
    "record": Command(_record, "Redact and hash-chain a list of events", frozenset({"RECORDED"})),
    "verify": Command(
        _verify,
        "Check a recorded trace for tampering",
        frozenset({"PASS"}),
        options=[(("--root-hash",), {"help": "root hash you stored separately when recording"})],
    ),
    "compare": Command(_compare, "Compare two traces by content", frozenset({"MATCH"})),
}


def main(argv: list[str] | None = None) -> int:
    return run("agentreplay", "Tamper-evident records of what an agent did.", COMMANDS, argv)


if __name__ == "__main__":
    main_wrapper(main)
