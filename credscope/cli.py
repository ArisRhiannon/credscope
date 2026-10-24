from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .core import inventory, runbook, to_markdown


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="credscope", description="After a compromise, list which credentials this dev machine or CI runner could reach (files and env var names) and print a rotation runbook. Never prints secret values; reads locally, no network.",
                                epilog="Exit codes: 0 nothing found, 1 credentials found, 2 usage error.")
    p.add_argument("-v", "--version", action="version", version=__version__)
    p.add_argument("--home", default=str(Path.home()), help="home directory to inspect (default: yours)")
    p.add_argument("--projects", nargs="*", default=[], metavar="DIR", help="also search these trees for .env files and project .npmrc tokens")
    p.add_argument("--no-env", action="store_true", help="do not look at environment variable names")
    p.add_argument("--format", choices=["md", "json", "text"], default="text")
    p.add_argument("-o", "--output", help="write to a file instead of stdout")
    a = p.parse_args(argv)
    if not Path(a.home).is_dir():
        print(f"credscope: not a directory: {a.home}", file=sys.stderr); return 2
    for d in a.projects:
        if not Path(d).is_dir():
            print(f"credscope: not a directory: {d}", file=sys.stderr); return 2
    items = inventory(a.home, env={} if a.no_env else None, projects=a.projects)
    book = runbook(items)
    if a.format == "json":
        text = json.dumps({"tool": "credscope", "version": __version__, "runbook": book}, indent=2)
    elif a.format == "md":
        text = to_markdown(book)
    else:
        text = "\n".join(f"{s['provider']:<11} {len(s['found'])} location(s): " + ", ".join(s["found"]) for s in book) or "credscope: no known credential locations found"
    if a.output:
        Path(a.output).write_text(text + "\n", encoding="utf-8")
        print(f"credscope: wrote {sum(len(s['found']) for s in book)} location(s) to {a.output}")
    else:
        print(text)
    return 1 if book else 0
