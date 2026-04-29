"""
Unified diff parser for GitHub PR inline review comments.

Parses a standard git unified diff and produces:
  - A {filename: set[new_line_numbers]} map used to validate that a model-suggested
    line actually exists in the diff (prevents posting comments on phantom lines).
  - An annotated diff string with new-file line numbers prepended to each line,
    making it easy for the LLM to reference exact line numbers in its suggestions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class FileChange:
    path: str
    added_lines: set[int] = field(default_factory=set)   # new-file line numbers that appear in the diff
    context_lines: set[int] = field(default_factory=set) # context (unchanged) lines also visible in diff


def parse_diff(diff_text: str) -> dict[str, FileChange]:
    """Return {path: FileChange} for every file touched in the diff.

    Only lines that appear in the diff (added or context) are included — they
    are the only lines on which GitHub allows inline review comments.
    """
    files: dict[str, FileChange] = {}
    current: FileChange | None = None
    new_line = 0

    for raw in diff_text.splitlines():
        # New file header
        if raw.startswith("+++ b/"):
            path = raw[6:].strip()
            current = FileChange(path=path)
            files[path] = current
            new_line = 0
            continue

        # Skip old-file header and git metadata lines
        if raw.startswith(("--- ", "diff ", "index ", "new file", "deleted file", "old mode", "new mode")):
            continue

        # Hunk header: @@ -old_start,old_count +new_start,new_count @@
        if raw.startswith("@@ "):
            m = re.search(r"\+(\d+)(?:,\d+)?", raw)
            if m and current is not None:
                new_line = int(m.group(1))
            continue

        if current is None:
            continue

        if raw.startswith("+"):
            current.added_lines.add(new_line)
            new_line += 1
        elif raw.startswith("-"):
            pass   # deleted line — no new-file number
        elif raw.startswith("\\"):
            pass   # "\ No newline at end of file"
        else:
            # Context line
            current.context_lines.add(new_line)
            new_line += 1

    return files


def diff_lines_for_file(parsed: dict[str, FileChange], path: str) -> set[int]:
    """Return all new-file line numbers visible in the diff for a given file.

    Tries exact path match first, then basename match for robustness when the
    model returns a relative path without the `b/` prefix.
    """
    if path in parsed:
        fc = parsed[path]
        return fc.added_lines | fc.context_lines

    # Fuzzy match: model may return "src/auth.py" when diff key is "src/auth.py"
    for key, fc in parsed.items():
        if key.endswith(path) or path.endswith(key):
            return fc.added_lines | fc.context_lines

    return set()


def format_diff_with_line_numbers(diff_text: str) -> str:
    """Return the diff annotated with new-file line numbers.

    Each added (+) or context line is prefixed with its line number so the
    review LLM can reference accurate line positions.

    Example output:
        +++ b/src/auth.py
        @@ -10,6 +10,8 @@
        10:  def authenticate(user, pwd):
        11:+     query = f"SELECT * FROM users WHERE name='{user}'"
        12:+     cursor.execute(query)
        13:      return cursor.fetchone()
    """
    out: list[str] = []
    new_line = 0

    for raw in diff_text.splitlines():
        if raw.startswith("+++ b/"):
            out.append(raw)
            new_line = 0
        elif raw.startswith(("--- ", "diff ", "index ", "new file", "deleted file",
                              "old mode", "new mode")):
            out.append(raw)
        elif raw.startswith("@@ "):
            m = re.search(r"\+(\d+)(?:,\d+)?", raw)
            if m:
                new_line = int(m.group(1))
            out.append(raw)
        elif raw.startswith("+"):
            out.append(f"{new_line}:+{raw[1:]}")
            new_line += 1
        elif raw.startswith("-"):
            out.append(f"   -{raw[1:]}")   # no line number — removed line
        elif raw.startswith("\\"):
            out.append(raw)
        else:
            out.append(f"{new_line}: {raw[1:] if raw else ''}")
            new_line += 1

    return "\n".join(out)
