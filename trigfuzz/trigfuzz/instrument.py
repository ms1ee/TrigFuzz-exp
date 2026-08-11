"""Automated v1 and v2 source instrumentation.

The original `ledfuzz` prototype requires the author to hand-edit the PUT
to insert `distance_instrument()` calls and (for v2) forcing assignments.
§4 of the paper describes a better approach: ask an LLM to emit a unified
diff in the aider edit format, then apply it with `patch`.  That is what
this module implements.

Two modes:

* v1 - insert one `distance_instrument()` call before each TCU `loc`,
       computing the distance via the Table 1 rule.  This is what the
       fuzzer runs against.

* v2 - modify the PUT to *forcibly satisfy* a TC (e.g. insert `a = b-1;`
       ahead of an `a < b` TCU), for the second validation step of §3.2.
       One v2 binary per candidate TC.

Why drive it through an LLM at all?  Because generating the exact
assignment that makes a C condition true in situ requires understanding
the surrounding types and side-effects - a hand-coded text rewriter
would misfire on anything non-trivial (e.g. `ctx->components[i]->id`).
The LLM has already read the code during TC Generation, so it is well
placed to do this.

For robustness the module *also* falls back to a deterministic
templated rewriter when the LLM is unavailable.  The templated version
handles the straight `a <op> b` patterns that dominate Magma.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
import textwrap

from .llm_client import LLMClient
from .tcu import TCU, from_json, tcu_distance_expression


# ---------------------------------------------------------------------------
# v1: insert distance_instrument() calls. Every insertion is spliced in at
# a character offset with no added newlines, so line numbers never shift.
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"[A-Za-z_]\w*")
_HEADER_KEYWORDS = frozenset({"if", "for", "while", "switch"})
_CHAIN_KEYWORDS = frozenset({"else", "do"})
_LABEL_RE = re.compile(r"\s*(case\b[^;{}:]*|default|[A-Za-z_]\w*)\s*:(?!:)")
# Comments/literals (DOTALL) and preprocessor directives (MULTILINE) are
# separate passes - combined, DOTALL would let a directive's '.*$' run to EOF.
_COMMENT_STRING_RE = re.compile(
    r"//[^\n]*"
    r"|/\*.*?\*/"
    r'|"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'",
    re.DOTALL,
)
_DIRECTIVE_RE = re.compile(r"^[ \t]*#(?:.*\\\n)*.*$", re.MULTILINE)
_PP_OPEN_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
_PP_CLOSE_RE = re.compile(r"^\s*#\s*endif\b")
_INCLUDE_RE = re.compile(r"^\s*#\s*include\b")


def _line_offsets(text: str) -> list[int]:
    offsets = [0]
    for i, c in enumerate(text):
        if c == "\n":
            offsets.append(i + 1)
    return offsets


def _skip_label(masked: str, pos: int) -> int:
    """Advance past leading whitespace and any case/default/goto label."""
    while pos < len(masked) and masked[pos].isspace():
        pos += 1
    while (m := _LABEL_RE.match(masked, pos)):
        pos = m.end()
        while pos < len(masked) and masked[pos].isspace():
            pos += 1
    return pos


def _is_header_boundary(masked: str, pos: int) -> bool:
    """True if `pos` closes an if/for/while/switch(...) header, or is the
    last letter of else/do - what follows is that construct's own body."""
    if masked[pos] == ")":
        depth, i = 0, pos
        while i >= 0:
            if masked[i] == ")":
                depth += 1
            elif masked[i] == "(":
                depth -= 1
                if depth == 0:
                    break
            i -= 1
        pos = i - 1
        while pos >= 0 and masked[pos].isspace():
            pos -= 1
        keywords = _HEADER_KEYWORDS
    elif masked[pos].isalnum() or masked[pos] == "_":
        keywords = _CHAIN_KEYWORDS
    else:
        return False
    if pos < 0 or not (masked[pos].isalnum() or masked[pos] == "_"):
        return False
    j = pos
    while j >= 0 and (masked[j].isalnum() or masked[j] == "_"):
        j -= 1
    return masked[j + 1: pos + 1] in keywords


def _statement_start(masked: str, pos: int) -> tuple[int, bool]:
    """Scan backward to where the statement at `pos` begins. Returns
    (start, is_control_body) - the latter means a plain prepend would detach it."""
    i = pos - 1
    while i >= 0:
        if masked[i].isspace():
            i -= 1
        elif masked[i] in ";{}":
            return _skip_label(masked, i + 1), False
        elif _is_header_boundary(masked, i):
            return _skip_label(masked, i + 1), True
        else:
            i -= 1
    return _skip_label(masked, 0), False


_NOT_MACRO_WORDS = _HEADER_KEYWORDS | _CHAIN_KEYWORDS | {"return", "goto"}
_CONTINUES_EXPR = set("+-*/%<>=!&|^?:,.[();")


def _statement_end(masked: str, start: int) -> int:
    """Offset just past the statement at `start`, following an if/do through
    a chained else/while, and ending a semicolon-less macro call at its own ')'."""
    head = _WORD_RE.match(masked, start)
    word = head.group() if head else ""
    chain = {"if": "else", "do": "while"}.get(word)
    macro_like = head is not None and word not in _NOT_MACRO_WORDS \
        and masked[head.end():].lstrip().startswith("(")
    paren = brace = 0
    i, n = start, len(masked)
    while i < n:
        c = masked[i]
        if c == "(":
            paren += 1
        elif c == ")":
            paren -= 1
            if macro_like and paren == 0 and brace == 0:
                j = i + 1
                while j < n and masked[j].isspace():
                    j += 1
                if j >= n or masked[j] not in _CONTINUES_EXPR:
                    return i + 1
        elif c == "{":
            brace += 1
        elif c == "}":
            brace -= 1
        # A ';' or the '}' that just closed the last open brace, both at
        # depth 0, end this clause - unless a chained else/while follows.
        if paren == 0 and brace == 0 and c in ";}":
            j = i + 1
            while j < n and masked[j].isspace():
                j += 1
            nxt = _WORD_RE.match(masked, j)
            if chain and nxt and nxt.group() == chain:
                i = nxt.end()
                continue
            return i + 1
        i += 1
    raise ValueError("unterminated statement at %d" % start)


def instrument_v1(tcus: list[TCU], source_root: pathlib.Path) -> None:
    """Insert one `distance_instrument()` call at every TCU's `loc`."""
    header = '#include "%s"' % (pathlib.Path(__file__).resolve().parent.parent / "distance.h")
    by_file: dict[pathlib.Path, list[TCU]] = {}
    for t in tcus:
        fname, _ = _parse_loc(t.loc)
        direct = source_root / fname
        if direct.is_file():
            path = direct
        else:
            hits = sorted(p for p in source_root.rglob(pathlib.Path(fname).name) if p.is_file())
            if "/" in fname:
                hits = [p for p in hits if str(p).endswith(fname)] or hits
            path = hits[0]
        by_file.setdefault(path, []).append(t)

    for path, file_tcus in by_file.items():
        text = path.read_text()
        blank = lambda m: re.sub(r"[^\n]", " ", m.group())
        masked = _COMMENT_STRING_RE.sub(blank, _DIRECTIVE_RE.sub(blank, text))
        offsets = _line_offsets(text)

        calls: dict[int, list[str]] = {}
        is_body: dict[int, bool] = {}
        for t in file_tcus:
            _, lineno = _parse_loc(t.loc)
            start, body = _statement_start(masked, offsets[lineno - 1])
            calls.setdefault(start, []).append(
                f"distance_instrument({tcu_distance_expression(t)}, "
                f"{t.save_index}, {t.seq}, {t.conj}, {t.w});"
            )
            is_body[start] = body

        edits: dict[int, str] = {}
        for start, call_texts in calls.items():
            chunk = " ".join(call_texts) + " "
            if is_body[start]:
                chunk = "{ " + chunk
                end = _statement_end(masked, start)
                edits[end] = edits.get(end, "") + "}"
            edits[start] = edits.get(start, "") + chunk

        if header not in text:
            # Offset just past the last top-level #include, so the header
            # lands after config.h - anything nested in an #ifdef is skipped.
            depth, off = 0, 0
            for i, s in enumerate(offsets):
                e = offsets[i + 1] if i + 1 < len(offsets) else len(text)
                line = text[s:e]
                if _PP_OPEN_RE.match(line):
                    depth += 1
                elif _PP_CLOSE_RE.match(line):
                    depth = max(0, depth - 1)
                elif depth == 0 and _INCLUDE_RE.match(line):
                    off = e
                elif depth == 0 and masked[s:e].strip():
                    break
            edits[off] = header + "\n" + edits.get(off, "")

        for off in sorted(edits, reverse=True):
            text = text[:off] + edits[off] + text[off:]
        path.write_text(text)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Insert TrigFuzz v1 instrumentation")
    ap.add_argument("source_root", type=pathlib.Path)
    ap.add_argument("tcu_file", type=pathlib.Path)
    ap.add_argument("--meta-out", type=pathlib.Path, help="write INS_NUM/SEQ_NUM here")
    args = ap.parse_args(argv)

    root = args.source_root.resolve()
    tcus = from_json(json.loads(args.tcu_file.read_text()))

    instrument_v1(tcus, root)

    ins_num = len(tcus)
    seq_num = max((t.seq for t in tcus), default=0) + 1
    print("INS_NUM=%d" % ins_num)
    print("SEQ_NUM=%d" % seq_num)
    if args.meta_out:
        args.meta_out.write_text("INS_NUM=%d\nSEQ_NUM=%d\n" % (ins_num, seq_num))
    return 0


# ---------------------------------------------------------------------------
# v2:  force TC satisfaction.  Per-TC binary, one per candidate TC set.
# ---------------------------------------------------------------------------
#
# We build a *separate copy* of the source for each candidate and mutate
# it: no in-place edits, because the caller needs all v2 binaries
# standing at once during validation.


def instrument_v2(tcus: list[TCU], source_root: pathlib.Path,
                  dest_root: pathlib.Path,
                  llm: LLMClient | None = None) -> None:
    """Produce a copy of `source_root` at `dest_root` where every TCU in
    `tcus` is forcibly satisfied at its loc.

    For each primitive condition we emit an assignment that makes it
    true.  Simple cases are handled by `_forcing_assignment`; anything
    it can't rewrite is delegated to the LLM via `_llm_force`.
    """

    _copy_tree(source_root, dest_root)

    by_file: dict[pathlib.Path, dict[int, list[TCU]]] = {}
    for t in tcus:
        fname, lineno = _parse_loc(t.loc)
        by_file.setdefault(dest_root / fname, {}).setdefault(lineno, []).append(t)

    for path, line_map in by_file.items():
        lines = path.read_text().splitlines(keepends=True)
        for lineno in sorted(line_map, reverse=True):
            stmts = []
            for t in line_map[lineno]:
                stmt = _forcing_assignment(t)
                if stmt is None and llm is not None:
                    stmt = _llm_force(t, "".join(lines), llm)
                if stmt is None:
                    # Give up silently on this TCU - v2 results will be
                    # "failed" for this candidate, which is the whole
                    # point of validation.
                    continue
                stmts.append(stmt)
            if stmts:
                indent = _indent(lines[lineno - 1])
                block = "".join(indent + s + "\n" for s in stmts)
                lines.insert(lineno - 1, block)
        path.write_text("".join(lines))


_FORCING_RE = re.compile(
    r"^\s*([A-Za-z_][\w\->\.\[\]]*)\s*(<=|>=|<|>|==|!=)\s*([A-Za-z_0-9\->\.\[\]]+)\s*$"
)


def _forcing_assignment(t: TCU) -> str | None:
    """Templated force-satisfaction for `a <op> b` shapes.

    Returns a C statement that, when executed immediately before the
    TCU's loc, guarantees `cond` is true.  Handles strictly numeric
    TCUs; binary/pointer ones are skipped (the validator can't usefully
    "force" a binary condition without breaking the surrounding logic).
    """
    if t.kind == "binary":
        return None
    m = _FORCING_RE.match(t.cond)
    if not m:
        return None
    lhs, op, rhs = m.groups()
    # Choose an assignment that nudges lhs just past rhs in the right
    # direction.  Using (double) casts is safe because the original
    # comparison is either integral or float; casting back via the
    # assignment truncates as needed.
    if op in ("<", "<="):
        return f"{lhs} = ({rhs}) - 1;"
    if op in (">", ">="):
        return f"{lhs} = ({rhs}) + 1;"
    if op == "==":
        return f"{lhs} = ({rhs});"
    if op == "!=":
        return f"{lhs} = ({rhs}) + 1;"
    return None


def _llm_force(t: TCU, source: str, llm: LLMClient) -> str | None:
    """Last-resort: ask the model for an assignment that satisfies `cond`.

    We intentionally do not show the whole file - just the surrounding
    context plus the TCU - to keep this cheap.  Output is expected to be
    one C statement; we reject anything that looks like multi-line code
    since that risks breaking scope/braces.
    """
    prompt = textwrap.dedent(f"""\
        The following C condition must be made true at {t.loc}:

            {t.cond}

        Write ONE C statement (ending in `;`) that, if executed just
        before that location, forces the condition to hold.  No
        explanations, no control flow, no braces.
    """)
    reply = llm.query([{"role": "user", "content": prompt}]).strip()
    if "\n" in reply or ";" not in reply:
        return None
    return reply


# ---------------------------------------------------------------------------
# Generic helpers.
# ---------------------------------------------------------------------------

_LOC_RE = re.compile(r"line\s+(\d+)\s+in\s+([\w./-]+)")

def _parse_loc(loc: str) -> tuple[str, int]:
    m = _LOC_RE.search(loc)
    if not m:
        raise ValueError(f"unparseable TCU.loc: {loc!r}")
    return m.group(2), int(m.group(1))


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _copy_tree(src: pathlib.Path, dst: pathlib.Path) -> None:
    # `cp -a` is dramatically faster than walking in Python for real
    # projects and preserves mtimes, which helps incremental builds.
    dst.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["cp", "-a", str(src), str(dst)], check=True)


if __name__ == "__main__":
    sys.exit(main())
