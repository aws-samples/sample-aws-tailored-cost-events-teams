#!/usr/bin/env python3
"""
Local Teams channel simulator.

Reads the exact Adaptive Card payloads the Lambda wrote to S3 and renders
them in the terminal as they'd appear in the test-aws-notify channel.

Usage:
    uv run python simulator/teams_receiver.py           # render all from today
    uv run python simulator/teams_receiver.py --all     # render every object
    uv run python simulator/teams_receiver.py --tail    # poll every 5s for new events
    uv run python simulator/teams_receiver.py --file path/to/one.json

Bucket + profile come from the Terraform outputs (or env vars).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess  # nosec B404 - local-only operator tool, not deployed
import sys
import time
from datetime import datetime, timezone

try:
    import boto3
except ImportError:
    print("boto3 required: uv pip install boto3", file=sys.stderr)
    sys.exit(1)

# ANSI colors — stand in for Teams severity styling
RESET = "\033[0m"
DIM = "\033[2m"
BOLD = "\033[1m"
SEV_COLOR = {
    "critical": "\033[91m",   # red
    "warning":  "\033[93m",   # yellow
    "info":     "\033[94m",   # blue
}
BOX_CHARS = {
    "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "h": "-", "v": "|",
}

# Caller-supplied profile. Empty/unset falls back to the default credential
# chain (env vars, SSO, instance role, etc.).
PROFILE = os.environ.get("AWS_PROFILE") or None
REGION  = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


def tf_output(key: str) -> str | None:
    tf_dir = os.path.join(os.path.dirname(__file__), "..", "terraform")
    # Local-only operator helper. No untrusted input: terraform binary on PATH
    # and an internal output key. Not part of the deployed Lambda.
    try:
        out = subprocess.check_output(  # nosec B603 B607
            ["terraform", f"-chdir={tf_dir}", "output", "-raw", key],
            stderr=subprocess.DEVNULL,
        )
        return out.decode().strip()
    except Exception:
        return None


def get_bucket() -> str:
    env = os.environ.get("EVENT_BUCKET")
    if env:
        return env
    out = tf_output("event_bucket")
    if not out:
        print("cannot resolve bucket. Set EVENT_BUCKET env or run from repo with "
              "terraform state present.", file=sys.stderr)
        sys.exit(2)
    return out


def s3_client():
    session = boto3.Session(profile_name=PROFILE, region_name=REGION)
    return session.client("s3")


def list_keys(s3, bucket: str, prefix: str = "events/") -> list[tuple[str, datetime]]:
    paginator = s3.get_paginator("list_objects_v2")
    keys: list[tuple[str, datetime]] = []
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        for o in page.get("Contents", []):
            keys.append((o["Key"], o["LastModified"]))
    keys.sort(key=lambda k: k[1])
    return keys


def load(s3, bucket: str, key: str) -> dict:
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return json.loads(body)


def render(envelope: dict) -> None:
    severity = envelope.get("severity", "info")
    color = SEV_COLOR.get(severity, "")
    team = envelope.get("team_name", "?")
    tag = envelope.get("tag_value", "?")
    etype = envelope.get("event_type", "?")

    card = envelope.get("teams_payload", {})
    # Teams Workflows wraps a single Adaptive Card in attachments[0].content
    try:
        content = card["attachments"][0]["content"]
        body = content.get("body", [])
        actions = content.get("actions", [])
    except (KeyError, IndexError):
        body = []
        actions = []

    width = 88
    bar = BOX_CHARS["h"] * (width - 2)
    print()
    print(f"{DIM}{BOX_CHARS['tl']}{bar}{BOX_CHARS['tr']}{RESET}")
    header = f" [Teams] #{team}   tag={tag}   {etype}   severity={severity} "
    print(f"{DIM}{BOX_CHARS['v']}{RESET}{color}{BOLD}{header.ljust(width-2)}{RESET}{DIM}{BOX_CHARS['v']}{RESET}")
    print(f"{DIM}{BOX_CHARS['bl']}{bar}{BOX_CHARS['br']}{RESET}")

    for block in body:
        btype = block.get("type")
        if btype == "TextBlock":
            text = block.get("text", "")
            style = ""
            if block.get("weight") == "Bolder":
                style += BOLD
            if block.get("color") == "Attention":
                style += SEV_COLOR["critical"]
            elif block.get("color") == "Warning":
                style += SEV_COLOR["warning"]
            if block.get("isSubtle"):
                style += DIM
            for line in _wrap(text, width):
                print(f"  {style}{line}{RESET}")
        elif btype == "FactSet":
            for fact in block.get("facts", []):
                label = fact.get("title", "")
                value = fact.get("value", "")
                print(f"  {BOLD}{label:<20}{RESET} {value}")
        else:
            print(f"  {DIM}[{btype}]{RESET}")

    if actions:
        print(f"  {BOLD}[Action buttons]{RESET}")
        for a in actions:
            title = a.get("title", "?")
            url = a.get("url", "")
            style = a.get("style")
            marker = ">>" if style == "positive" else " >"
            print(f"  {BOLD}{marker}{RESET} {title}")
            print(f"     {DIM}{url}{RESET}")
    print()


def _wrap(text: str, width: int) -> list[str]:
    text = text.replace("**", "")
    if len(text) <= width - 4:
        return [text]
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + 1 > width - 4:
            out.append(line)
            line = word
        else:
            line = f"{line} {word}".strip()
    if line:
        out.append(line)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="render every object, not just today")
    ap.add_argument("--tail", action="store_true", help="poll every 5s for new events")
    ap.add_argument("--file", help="render a single local JSON file (no S3 required)")
    args = ap.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8") as f:
            render(json.load(f))
        return 0

    bucket = get_bucket()
    s3 = s3_client()
    print(f"{DIM}# bucket={bucket} profile={PROFILE}{RESET}")

    prefix = "events/"
    if not args.all and not args.tail:
        today = datetime.now(timezone.utc).strftime("%Y/%m/%d")
        # keys are events/<type>/<team>/YYYY/MM/DD/HHMMSS-...json — filter client-side
        keys = [k for k, _ in list_keys(s3, bucket, prefix) if f"/{today}/" in k]
        print(f"{DIM}# rendering {len(keys)} events from {today}{RESET}")
        for k in keys:
            render(load(s3, bucket, k))
        return 0

    if args.all:
        keys = [k for k, _ in list_keys(s3, bucket, prefix)]
        print(f"{DIM}# rendering {len(keys)} events (all){RESET}")
        for k in keys:
            render(load(s3, bucket, k))
        return 0

    # tail
    seen: set[str] = {k for k, _ in list_keys(s3, bucket, prefix)}
    print(f"{DIM}# tailing (ctrl-c to stop); baseline={len(seen)} objects{RESET}")
    try:
        while True:
            # nosemgrep: arbitrary-sleep -- intentional poll interval for --tail
            time.sleep(5)
            current = list_keys(s3, bucket, prefix)
            new = [(k, t) for k, t in current if k not in seen]
            for k, _t in new:
                render(load(s3, bucket, k))
                seen.add(k)
    except KeyboardInterrupt:
        print("\n# stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
