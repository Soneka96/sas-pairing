#!/usr/bin/env python3
"""Checks every internal Markdown link in the repository.

For each tracked `*.md` file: every inline link `[text](target)` and reference definition
`[label]: target` whose target is not external (`http:`, `https:`, `mailto:`) must name an
existing file or directory (relative to the linking file, or to the repository root for a leading
`/`), and a `#fragment` into a Markdown file must name one of its anchors: a GitHub heading slug
or an explicit `<a id="...">` / `id="..."` anchor. Links inside fenced code blocks and inline code
spans are ignored. Exit status 1 lists every broken link.

Usage: python3 tooling/check_markdown_links.py   (from anywhere inside the repository)
"""

import os
import re
import subprocess
import sys
import unicodedata
from urllib.parse import unquote

INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFERENCE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+\"[^\"]*\")?\s*$")
HEADING = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")
EXPLICIT = re.compile(r"""\bid\s*=\s*["']([^"']+)["']""")
FENCE = re.compile(r"^\s{0,3}(```|~~~)")
EXTERNAL = ("http://", "https://", "mailto:", "ftp://")


def repository_root():
    return subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def tracked_markdown(root):
    listed = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8")
    return sorted(path for path in listed.split("\0") if path)


def strip_code_spans(line):
    return re.sub(r"(`+)(.+?)\1", "", line)


def visible_lines(text):
    """The lines outside fenced code blocks, with inline code spans removed."""
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield number, strip_code_spans(line)


def slug(heading):
    """GitHub's heading anchor: rendered text, lowercased, punctuation dropped, spaces → '-'."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", heading)  # links keep their text
    text = re.sub(r"<[^>]+>", "", text)  # inline HTML
    text = text.replace("`", "")
    text = re.sub(r"(\*\*|__|\*)", "", text)
    text = text.strip().lower()
    kept = []
    for char in text:
        if char in (" ", "-", "_"):
            kept.append("-" if char == " " else char)
        elif unicodedata.category(char)[0] in ("L", "N"):
            kept.append(char)
    return "".join(kept)


def anchors_of(path, cache):
    if path not in cache:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        anchors, seen = set(), {}
        fenced = False
        for line in text.splitlines():
            if FENCE.match(line):
                fenced = not fenced
                continue
            if fenced:
                continue
            anchors.update(EXPLICIT.findall(line))
            match = HEADING.match(line)
            if match:
                base = slug(match.group(2))
                count = seen.get(base, 0)
                seen[base] = count + 1
                anchors.add(base if count == 0 else f"{base}-{count}")
        cache[path] = anchors
    return cache[path]


def main():
    root = repository_root()
    cache = {}
    broken = []
    checked = 0
    files = tracked_markdown(root)
    for relative in files:
        source = os.path.join(root, relative)
        with open(source, encoding="utf-8") as handle:
            text = handle.read()
        for number, line in visible_lines(text):
            targets = [match.group(1) for match in INLINE.finditer(line)]
            reference = REFERENCE.match(line)
            if reference:
                targets.append(reference.group(1))
            for target in targets:
                if target.startswith(EXTERNAL):
                    continue
                checked += 1
                path_part, _, fragment = target.partition("#")
                path_part = unquote(path_part)
                if not path_part:
                    resolved = source
                elif path_part.startswith("/"):
                    resolved = os.path.join(root, path_part.lstrip("/"))
                else:
                    resolved = os.path.normpath(
                        os.path.join(os.path.dirname(source), path_part)
                    )
                where = f"{relative}:{number}: {target}"
                if not os.path.exists(resolved):
                    broken.append(f"{where} (missing file)")
                    continue
                if fragment and resolved.endswith(".md") and os.path.isfile(resolved):
                    if unquote(fragment) not in anchors_of(resolved, cache):
                        broken.append(f"{where} (missing anchor)")
    for item in broken:
        print(item)
    print(
        f"checked {checked} internal links in {len(files)} Markdown files: "
        f"{len(broken)} broken"
    )
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
