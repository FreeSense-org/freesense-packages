#!/usr/bin/env python3
"""Reject invalid, stale, or nonexistent optional-package exclusions."""

from __future__ import annotations

from datetime import date, timedelta
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
ORIGIN = re.compile(r"^[A-Za-z0-9+_.-]+/[A-Za-z0-9+_.-]+$")
ISSUE = re.compile(r"^https://[^\s]+$")


def main() -> int:
    policy = json.loads((ROOT / "architecture-policy.json").read_text(encoding="utf-8"))
    if policy.get("schema_version") != "freesense.optional-package-architectures/v1":
        raise SystemExit("unsupported architecture policy schema")
    architectures = policy.get("architectures")
    if not isinstance(architectures, dict) or set(architectures) != {"amd64", "aarch64"}:
        raise SystemExit("architecture policy must define amd64 and aarch64")
    today = date.today()
    for architecture, settings in architectures.items():
        exclusions = settings.get("exclude") if isinstance(settings, dict) else None
        if not isinstance(exclusions, list):
            raise SystemExit(f"{architecture} exclusions must be a list")
        seen: set[str] = set()
        for entry in exclusions:
            if not isinstance(entry, dict) or set(entry) != {"origin", "reason", "issue", "review_date"}:
                raise SystemExit(f"{architecture} exclusion has invalid fields")
            origin = entry["origin"]
            if not isinstance(origin, str) or not ORIGIN.fullmatch(origin) or origin in seen:
                raise SystemExit(f"{architecture} exclusion has invalid or duplicate origin")
            seen.add(origin)
            if not (ROOT / origin / "Makefile").is_file():
                raise SystemExit(f"{architecture} exclusion origin does not exist: {origin}")
            if not isinstance(entry["reason"], str) or len(entry["reason"].strip()) < 20:
                raise SystemExit(f"{origin} exclusion needs a technical reason")
            if not isinstance(entry["issue"], str) or not ISSUE.fullmatch(entry["issue"]):
                raise SystemExit(f"{origin} exclusion needs an HTTPS issue URL")
            try:
                review = date.fromisoformat(entry["review_date"])
            except (TypeError, ValueError) as error:
                raise SystemExit(f"{origin} exclusion has an invalid review date") from error
            if review < today - timedelta(days=180) or review > today + timedelta(days=30):
                raise SystemExit(f"{origin} exclusion review date is stale or implausible")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
