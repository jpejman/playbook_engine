#!/usr/bin/env python3
"""
Service: VulnStrike Playbook Engine
Script: project_dump_v0_1_0.py
Version: v0.1.0
Timestamp (UTC): 2026-04-08

Purpose:
- Run from inside a project root
- Dump project structure and selected file contents into one output file
- Replace ad hoc PowerShell-based project dump workflows

Usage:
    python scripts/project_dump_v0_1_0.py
    python scripts/project_dump_v0_1_0.py --root .
    python scripts/project_dump_v0_1_0.py --output project_dump.md
    python scripts/project_dump_v0_1_0.py --include-contents
    python scripts/project_dump_v0_1_0.py --max-file-size-kb 256
    python scripts/project_dump_v0_1_0.py --extensions .py .md .json .yaml .yml .toml .env
"""

from __future__ import annotations

import argparse
import fnmatch
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Iterable, List


DEFAULT_EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
    "dist",
    "build",
    ".next",
    ".turbo",
    ".cache",
    ".tox",
    "coverage",
    "htmlcov",
    ".DS_Store",
}

DEFAULT_EXCLUDE_FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
    "*.pyd",
    "*.so",
    "*.dll",
    "*.exe",
    "*.bin",
    "*.jpg",
    "*.jpeg",
    "*.png",
    "*.gif",
    "*.webp",
    "*.ico",
    "*.pdf",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.7z",
    "*.mp4",
    "*.mp3",
    "*.wav",
    "*.sqlite",
    "*.db",
    "*.log",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def is_excluded_dir(path: Path, exclude_dirs: set[str]) -> bool:
    return path.name in exclude_dirs


def matches_any_pattern(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, pattern) for pattern in patterns)


def is_excluded_file(path: Path, exclude_patterns: set[str]) -> bool:
    return matches_any_pattern(path.name, exclude_patterns)


def safe_read_text(path: Path) -> str:
    encodings = ("utf-8", "utf-8-sig", "latin-1")
    for enc in encodings:
        try:
            return path.read_text(encoding=enc)
        except Exception:
            continue
    return "<<UNREADABLE TEXT FILE>>"


def build_tree_lines(root: Path, exclude_dirs: set[str], exclude_patterns: set[str]) -> List[str]:
    lines: List[str] = []

    def walk(current: Path, prefix: str = "") -> None:
        try:
            items = sorted(
                current.iterdir(),
                key=lambda p: (not p.is_dir(), p.name.lower())
            )
        except PermissionError:
            lines.append(f"{prefix}[PermissionDenied] {current.name}/")
            return

        filtered = []
        for item in items:
            if item.is_dir() and is_excluded_dir(item, exclude_dirs):
                continue
            if item.is_file() and is_excluded_file(item, exclude_patterns):
                continue
            filtered.append(item)

        for i, item in enumerate(filtered):
            connector = "└── " if i == len(filtered) - 1 else "├── "
            if item.is_dir():
                lines.append(f"{prefix}{connector}{item.name}/")
                extension = "    " if i == len(filtered) - 1 else "│   "
                walk(item, prefix + extension)
            else:
                lines.append(f"{prefix}{connector}{item.name}")

    lines.append(f"{root.name}/")
    walk(root)
    return lines


def collect_files(
    root: Path,
    exclude_dirs: set[str],
    exclude_patterns: set[str],
    include_extensions: list[str] | None,
) -> List[Path]:
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        current_dir = Path(dirpath)

        dirnames[:] = [
            d for d in dirnames
            if d not in exclude_dirs
        ]

        for filename in sorted(filenames):
            file_path = current_dir / filename
            if is_excluded_file(file_path, exclude_patterns):
                continue
            if include_extensions and file_path.suffix.lower() not in include_extensions:
                continue
            files.append(file_path)

    return sorted(files, key=lambda p: str(p.relative_to(root)).lower())


def write_dump(
    root: Path,
    output_path: Path,
    include_contents: bool,
    max_file_size_kb: int,
    include_extensions: list[str] | None,
    exclude_dirs: set[str],
    exclude_patterns: set[str],
) -> None:
    files = collect_files(root, exclude_dirs, exclude_patterns, include_extensions)
    tree_lines = build_tree_lines(root, exclude_dirs, exclude_patterns)

    with output_path.open("w", encoding="utf-8") as f:
        f.write(f"# Project Dump\n\n")
        f.write(f"- Timestamp (UTC): {utc_now_iso()}\n")
        f.write(f"- Root: {root.resolve()}\n")
        f.write(f"- Include contents: {include_contents}\n")
        f.write(f"- Max file size KB: {max_file_size_kb}\n")
        f.write(f"- File count: {len(files)}\n\n")

        f.write("## Directory Tree\n\n")
        f.write("```text\n")
        for line in tree_lines:
            f.write(line + "\n")
        f.write("```\n\n")

        f.write("## Files\n\n")
        for file_path in files:
            rel = file_path.relative_to(root)
            size_kb = file_path.stat().st_size / 1024
            f.write(f"### {rel}\n\n")
            f.write(f"- Size KB: {size_kb:.2f}\n")
            f.write(f"- Modified: {datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc).isoformat()}\n\n")

            if include_contents:
                if size_kb > max_file_size_kb:
                    f.write("```text\n")
                    f.write(f"<<SKIPPED: file exceeds size limit of {max_file_size_kb} KB>>\n")
                    f.write("```\n\n")
                else:
                    content = safe_read_text(file_path)
                    fence = "```"
                    f.write(f"{fence}text\n")
                    f.write(content)
                    if not content.endswith("\n"):
                        f.write("\n")
                    f.write(f"{fence}\n\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dump project structure and optional contents.")
    parser.add_argument("--root", default=".", help="Project root directory. Default: current directory")
    parser.add_argument("--output", default=None, help="Output file path. Default: project_dump_<timestamp>.md")
    parser.add_argument("--include-contents", action="store_true", help="Include file contents in dump")
    parser.add_argument("--max-file-size-kb", type=int, default=256, help="Max file size in KB to include contents")
    parser.add_argument(
        "--extensions",
        nargs="*",
        default=None,
        help="Optional list of extensions to include, e.g. .py .md .json",
    )
    parser.add_argument(
        "--exclude-dir",
        nargs="*",
        default=[],
        help="Additional directory names to exclude",
    )
    parser.add_argument(
        "--exclude-pattern",
        nargs="*",
        default=[],
        help="Additional file glob patterns to exclude",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: root path is not a directory: {root}")
        return 1

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_path = Path(args.output).resolve() if args.output else root / f"project_dump_{timestamp}.md"

    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    exclude_patterns = set(DEFAULT_EXCLUDE_FILE_PATTERNS) | set(args.exclude_pattern)

    include_extensions = None
    if args.extensions:
        include_extensions = [ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in args.extensions]

    write_dump(
        root=root,
        output_path=output_path,
        include_contents=args.include_contents,
        max_file_size_kb=args.max_file_size_kb,
        include_extensions=include_extensions,
        exclude_dirs=exclude_dirs,
        exclude_patterns=exclude_patterns,
    )

    print("PROJECT DUMP COMPLETE")
    print(f"ROOT: {root}")
    print(f"OUTPUT: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())