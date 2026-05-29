#!/usr/bin/env python3
"""Text editor for catalogs/tls_fp_blocklist.yaml — the promotion tooling's
single writer of the blocklist catalog.

We edit the file as TEXT (append / set-status / remove lines), never as a YAML
round-trip, so the `#` comment "passport" above each entry is preserved exactly.
The catalog is a strict flat map `"<fp>": <status>` (yaml.v3 KnownFields, status
∈ {active, staging}); a duplicate key would fail CI (validate-catalogs), so `add`
refuses to write an fp that already exists.

Subcommands (exit non-zero on error so bash callers can branch):
    list                         fp<TAB>status for every entry
    status <fp>                  print the entry's status, or exit 3 if absent
    add <fp> <status> --comment  append a comment block + `"<fp>": <status>`
    set-status <fp> <status>     change an existing entry's status [--note ...]
    remove <fp>                  delete the entry line + its passport comments

Target file: --file, else $CATALOGS_DIR/tls_fp_blocklist.yaml, else
<repo>/catalogs/tls_fp_blocklist.yaml (repo = two parents up from scripts/lib/).
"""
from __future__ import annotations
import argparse
import os
import re
import sys
from pathlib import Path

VALID_STATUS = ("active", "staging")
# fp token: L<prefix>_<hash_b>_<hash_c> (see infra/demo-stand/lua/ja4_compute.lua).
FP_RE = re.compile(r"^L[0-9A-Za-z]+_[0-9a-f]+_[0-9a-f]+$")


def default_file() -> Path:
    if os.environ.get("CATALOGS_DIR"):
        return Path(os.environ["CATALOGS_DIR"]) / "tls_fp_blocklist.yaml"
    return Path(__file__).resolve().parents[2] / "catalogs" / "tls_fp_blocklist.yaml"


def die(code: int, msg: str):
    sys.stderr.write(f"blocklist_catalog: {msg}\n")
    sys.exit(code)


def _key_of(line: str):
    """If `line` is an entry line, return (fp, status); else None."""
    s = line.strip()
    if not s or s.startswith("#") or ":" not in s:
        return None
    key, _, val = s.partition(":")
    fp = key.strip().strip('"').strip("'")
    status = val.split("#", 1)[0].strip().strip('"').strip("'")
    if not fp or not status:
        return None
    return fp, status


def load(path: Path):
    try:
        return path.read_text().splitlines(keepends=True)
    except OSError as e:
        die(1, f"cannot read {path}: {e}")


def entries(lines):
    out = {}
    for i, line in enumerate(lines):
        kv = _key_of(line)
        if kv:
            out[kv[0]] = (i, kv[1])
    return out


def write(path: Path, lines):
    path.write_text("".join(lines))


def cmd_list(path, args):
    for fp, (_, status) in entries(load(path)).items():
        print(f"{fp}\t{status}")


def cmd_status(path, args):
    e = entries(load(path))
    if args.fp not in e:
        die(3, f"{args.fp} not in catalog")
    print(e[args.fp][1])


def _comment_lines(text: str):
    """Render a (possibly multi-line) passport into `# ...` comment lines."""
    out = []
    for raw in text.splitlines():
        raw = raw.rstrip()
        if not raw:
            out.append("#\n")
        elif raw.lstrip().startswith("#"):
            out.append(raw + "\n")
        else:
            out.append(f"# {raw}\n")
    return out


def cmd_add(path, args):
    if args.status not in VALID_STATUS:
        die(2, f"invalid status {args.status!r} (active|staging)")
    if not FP_RE.match(args.fp):
        die(2, f"malformed fp {args.fp!r}")
    lines = load(path)
    if args.fp in entries(lines):
        die(2, f"{args.fp} already in catalog (duplicate key would fail CI)")
    block = []
    # Blank separator before the new block, unless the file already ends blank.
    if lines and lines[-1].strip() != "":
        block.append("\n")
    if args.comment:
        block.extend(_comment_lines(args.comment))
    block.append(f'"{args.fp}": {args.status}\n')
    write(path, lines + block)
    print(f"added {args.fp} -> {args.status}")


def cmd_set_status(path, args):
    if args.status not in VALID_STATUS:
        die(2, f"invalid status {args.status!r} (active|staging)")
    lines = load(path)
    e = entries(lines)
    if args.fp not in e:
        die(3, f"{args.fp} not in catalog")
    idx = e[args.fp][0]
    lines[idx] = f'"{args.fp}": {args.status}\n'
    if args.note:
        lines.insert(idx, f"#  ↳ {args.note}\n")
    write(path, lines)
    print(f"set {args.fp} -> {args.status}")


def cmd_remove(path, args):
    lines = load(path)
    e = entries(lines)
    if args.fp not in e:
        die(3, f"{args.fp} not in catalog")
    idx = e[args.fp][0]
    start = idx
    # Walk up over the contiguous passport comment block, stopping at a blank
    # line or non-comment (so we never eat the file header, which is separated
    # by a blank line).
    while start > 0 and lines[start - 1].lstrip().startswith("#"):
        start -= 1
    end = idx + 1
    # Also drop a single blank separator left dangling above the removed block.
    if start > 0 and lines[start - 1].strip() == "" and (start == 1 or lines[start - 2].strip() != ""):
        start -= 1
    del lines[start:end]
    write(path, lines)
    print(f"removed {args.fp}")


def main():
    ap = argparse.ArgumentParser(description="edit tls_fp_blocklist.yaml")
    ap.add_argument("--file", type=Path, default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    p = sub.add_parser("status"); p.add_argument("fp")
    p = sub.add_parser("add"); p.add_argument("fp"); p.add_argument("status"); p.add_argument("--comment", default="")
    p = sub.add_parser("set-status"); p.add_argument("fp"); p.add_argument("status"); p.add_argument("--note", default="")
    p = sub.add_parser("remove"); p.add_argument("fp")
    args = ap.parse_args()
    path = args.file or default_file()
    {"list": cmd_list, "status": cmd_status, "add": cmd_add,
     "set-status": cmd_set_status, "remove": cmd_remove}[args.cmd](path, args)


if __name__ == "__main__":
    main()
