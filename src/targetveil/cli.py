"""Command-line interface for offline TargetVeil use."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .engine import Sanitizer


PROFILES = (
    "balanced", "burp", "nmap", "nuclei", "ffuf", "bloodhound", "siem", "sqlmap",
    "web_discovery", "netexec", "mimikatz", "metasploit", "wireshark", "vuln_scanner",
    "cloud", "osint", "strict",
)


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _load_scope(path: str | None) -> tuple[list[tuple[str, str]], list[str], str | None]:
    if not path:
        return [], [], None
    data: Any = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("scope file must contain a JSON object")
    raw_values = data.get("sensitive_values", data.get("custom_values", []))
    if not isinstance(raw_values, list):
        raise ValueError("scope sensitive_values must be an array")
    values: list[tuple[str, str]] = []
    for entry in raw_values:
        if isinstance(entry, str):
            values.append(("CUSTOM", entry))
        elif isinstance(entry, dict):
            values.append((str(entry.get("type", "CUSTOM")), str(entry.get("value", ""))))
        else:
            raise ValueError("scope values must be strings or objects")
    allowlist = data.get("allowlist", [])
    if not isinstance(allowlist, list):
        raise ValueError("scope allowlist must be an array")
    selected_profile = data.get("profile")
    if selected_profile is not None and selected_profile not in PROFILES:
        raise ValueError(f"unknown scope profile: {selected_profile}")
    return values, [str(item) for item in allowlist], selected_profile


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="targetveil",
        description="Sanitize pentest prompts locally before using a public AI service.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("sanitize", "scan"):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("input", nargs="?", default="-", help="UTF-8 file or - for stdin")
        subparser.add_argument("--profile", choices=PROFILES, default=None)
        subparser.add_argument("--scope", help="Engagement .targetveil.json scope file")
        subparser.add_argument("--allow", action="append", default=[], help="Exact value to leave unchanged")
        subparser.add_argument(
            "--sensitive",
            action="append",
            default=[],
            metavar="TYPE=VALUE",
            help="Engagement-specific sensitive value",
        )
    sanitize_parser = subparsers.choices["sanitize"]
    sanitize_parser.add_argument("--mode", choices=("pseudonymize", "redact"), default="pseudonymize")
    sanitize_parser.add_argument("--json", action="store_true", help="Emit JSON result")
    scan_parser = subparsers.choices["scan"]
    scan_parser.add_argument("--show-values", action="store_true", help="Include originals in local output")
    return parser


def _manual_values(entries: list[str]) -> list[tuple[str, str]]:
    values: list[tuple[str, str]] = []
    for entry in entries:
        if "=" in entry:
            kind, value = entry.split("=", 1)
        else:
            kind, value = "CUSTOM", entry
        values.append((kind, value))
    return values


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        text = _read_text(args.input)
        scope_values, scope_allowlist, scope_profile = _load_scope(args.scope)
        profile = args.profile or scope_profile or "balanced"
        custom_values = scope_values + _manual_values(args.sensitive)
        allowlist = scope_allowlist + args.allow
        sanitizer = Sanitizer()

        if args.command == "scan":
            findings = sanitizer.scan(
                text,
                profile=profile,
                custom_values=custom_values,
                allow_terms=allowlist,
            )
            payload = [
                {
                    "type": item.entity_type,
                    "start": item.start,
                    "end": item.end,
                    "detector": item.detector,
                    "confidence": item.confidence,
                    **({"value": item.value} if args.show_values else {}),
                }
                for item in findings
            ]
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0

        result = sanitizer.sanitize(
            text,
            profile=profile,
            mode=args.mode,
            custom_values=custom_values,
            allow_terms=allowlist,
        )
        if args.json:
            print(
                json.dumps(
                    {
                        "safe": result.safe,
                        "counts": result.counts,
                        "sanitized_text": result.sanitized_text,
                        "residual_count": len(result.residual_findings),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            sys.stdout.write(result.sanitized_text)
            if result.sanitized_text and not result.sanitized_text.endswith("\n"):
                sys.stdout.write("\n")
        return 0 if result.safe else 2
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"targetveil: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
