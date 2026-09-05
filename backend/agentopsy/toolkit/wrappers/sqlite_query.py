"""sqlite3 wrapper — run ONE bounded read-only SELECT over a derived SQLite database.

Most modern artifacts are SQLite: a browser's `places.sqlite` / `History`, Windows'
`ActivitiesCache.db`, macOS quarantine, countless application stores. Before this
wrapper the agent could extract such a file and then only look at it: nothing in the
catalog could ask it a question. It is also the natural second half of `hindsight`,
whose default output IS a SQLite database with the visited URLs in its `timeline`
table, so "what did the user browse between these two dates" ends here.

The whole design is about opening a HOSTILE file safely and answering honestly.

**The database is never a path.** `database` is DERIVED_INPUT only: an `ArtifactRef`
of a previous run, resolved and re-hashed by the dispatcher (FORENSIC INVARIANTS 1-2).
There is no way to point this tool at an arbitrary file.

**Read-only is enforced three times over, and it was measured** (sqlite3 3.37.2 inside
the maletín, 2026-09-03; the database's SHA-256 was identical before and after every
one of these):

- `-readonly` plus the `mode=ro` URI: `UPDATE`, `INSERT` and `DROP TABLE` all fail with
  "attempt to write a readonly database" (exit 8).
- `-safe`: `ATTACH` is refused ("cannot run ATTACH in safe mode"), and so is `VACUUM
  INTO`, which uses ATTACH underneath and would otherwise write a whole new file. It
  also refuses the dot-commands that reach outside the database (`.shell`, `.system`,
  `.output`, `.import`, `.read`) and the `load_extension()` and `readfile()` functions.
- `-nofollow`: a symlink pointing at the database path is refused outright.

**`immutable=1` is deliberately NOT used, and this is the sharpest decision here.** It
would guarantee that not a single byte is written, and it is wrong for forensics:
measured on a database whose WAL had not been checkpointed, `immutable=1` answered
"no such table: urls" for a table holding two rows, because in WAL mode the schema
itself can live in the `-wal` file. That is not "a few rows missing", it is a database
that looks EMPTY, and a profile recovered from a machine that was powered off abruptly
is exactly the case that carries an uncheckpointed WAL. A false negative in an expert
report is worse than the side effect it avoids, and the side effect is small and
measured: reading a plain database creates nothing at all, and only a WAL database
whose `-shm` is missing gets its sidecars created next to it, which is precisely the
case where the WAL is the data we came for.

**One statement, and only a query.** The model sends SQL, so the wrapper refuses
anything that is not a single `SELECT`/`WITH`: no `;` chaining (measured: sqlite3
happily runs `SELECT 1; SELECT 2` and emits two JSON documents, which breaks the shape
of the artifact), no SQL comments (they are the classic way to smuggle a second verb
past a prefix check), no dot-commands.

**The result is bounded, and a truncation is never silent.** The query is wrapped as
``SELECT *, <max_rows> AS _agentopsy_cap FROM (<query>) LIMIT <max_rows+1>`` (verified
to hold for CTEs, ``ORDER BY`` and a query that already carries its own ``LIMIT``).
The one row beyond the cap is what proves there is more; the sentinel column is what
lets ``parse`` know the cap at all, since a ``parse`` only ever receives stdout and
would otherwise have no way to tell "exactly as many rows as you asked for" from
"more than you asked for". ``parse`` strips the column, drops the probe row and
reports ``truncated``, so the agent is told its answer is incomplete instead of being
handed a partial set that looks whole (RULE 2).
"""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import quote

ALLOWED_FLAGS = frozenset({"-readonly", "-safe", "-nofollow", "-batch", "-bail", "-json"})

#: Designed default and hard ceiling for the row cap. Both exist because the rows
#: travel INTO THE MODEL'S CONTEXT, and forensic tables are wide, not narrow: the
#: `timeline` table hindsight produces has 29 columns, so a few hundred rows is
#: already a very large answer. A query that needs more than the ceiling is a query
#: that should be narrowed or aggregated in SQL, not a bigger dump.
DEFAULT_MAX_ROWS = 200
MAX_ROWS_CEILING = 50_000

#: Upper bound on the SQL text itself. Generous for a real query, closed all the same.
_MAX_QUERY_CHARS = 4000

#: The column `build_argv` adds to carry the row cap into the result, so `parse` can
#: detect an overflow with nothing but stdout. It is stripped before the rows are
#: returned. An inner query that already selects a column by this name would collide
#: with it, which is why the name is one nobody writes by accident.
_CAP_COLUMN = "_agentopsy_cap"

#: A query must OPEN with one of these. Anything else (INSERT, UPDATE, DELETE, DROP,
#: ATTACH, PRAGMA, VACUUM, a dot-command...) is refused here, before sqlite3 is asked to
#: refuse it: the engine's own refusal is the backstop, not the gate.
_QUERY_START_RE = re.compile(r"^\s*(?:select|with)\b", re.IGNORECASE)

#: SQL comments are rejected rather than stripped. Stripping them correctly means
#: parsing string literals, and getting that subtly wrong is exactly how a second verb
#: slips past a prefix check.
_COMMENT_RE = re.compile(r"--|/\*")


def _validate_query(query: Any) -> str:
    if not query or not isinstance(query, str):
        raise ValueError("sqlite_query requires params.query: str")
    text = query.strip()
    if not text:
        raise ValueError("sqlite_query requires params.query: str (it was blank)")
    if len(text) > _MAX_QUERY_CHARS:
        raise ValueError(
            f"sqlite_query query is too long ({len(text)} chars, max "
            f"{_MAX_QUERY_CHARS}); narrow it or aggregate in SQL"
        )
    if _COMMENT_RE.search(text):
        raise ValueError(
            "sqlite_query rejects SQL comments ('--' and '/*'): send the query alone"
        )
    # One statement only. A single trailing ';' is a habit, not a second statement.
    text = text.rstrip().rstrip(";").rstrip()
    if ";" in text:
        raise ValueError(
            "sqlite_query runs exactly ONE statement: remove the ';' and send a "
            "single SELECT"
        )
    if not _QUERY_START_RE.match(text):
        raise ValueError(
            "sqlite_query only runs a read query: it must start with SELECT or WITH "
            f"(got {text[:40]!r}). The database is opened read-only, so INSERT, "
            "UPDATE, DELETE, DROP, ATTACH and PRAGMA cannot work here."
        )
    return text


def build_argv(params: dict[str, Any]) -> list[str]:
    """Compose argv for sqlite3.

    params:
        database (str, required): the SQLite file, resolved by the dispatcher from an
            ArtifactRef of a previous run (a `tsk_icat` extraction, or the
            `navegacion.sqlite` a `hindsight` run produced).
        query (str, required): ONE `SELECT` (or `WITH ... SELECT`). No `;`, no
            comments, no dot-commands.
        max_rows (int, optional): row cap, default `DEFAULT_MAX_ROWS`, ceiling
            `MAX_ROWS_CEILING`.
    """
    database = params.get("database")
    if not database or not isinstance(database, str):
        raise ValueError("sqlite_query requires params.database: str")

    query = _validate_query(params.get("query"))

    max_rows = params.get("max_rows", DEFAULT_MAX_ROWS)
    if isinstance(max_rows, bool) or not isinstance(max_rows, int):
        raise ValueError("sqlite_query max_rows must be an int")
    if max_rows < 1 or max_rows > MAX_ROWS_CEILING:
        raise ValueError(
            f"sqlite_query max_rows must be between 1 and {MAX_ROWS_CEILING}, "
            f"got {max_rows}"
        )

    # The path is percent-encoded because it goes into a URI: a recovered artifact
    # mirrors the evidence's own names, and those carry spaces ("Local Settings") and
    # the odd '#'. Only '/' stays literal.
    uri = "file:" + quote(database, safe="/") + "?mode=ro"

    # One extra row is asked for so the overflow is provable, and the cap travels IN
    # the result because `parse` receives nothing but stdout (see the module docstring).
    bounded = (
        f"SELECT *, {max_rows} AS {_CAP_COLUMN} FROM ({query}) LIMIT {max_rows + 1}"
    )

    return [
        "-readonly",
        "-safe",
        "-nofollow",
        # Never wait on a human: there is no terminal behind the exec-agent, and
        # stopping at the first error keeps a half-answer from looking like an answer.
        "-batch",
        "-bail",
        "-json",
        uri,
        bounded,
    ]


def parse(stdout: str) -> dict[str, Any]:
    """Read sqlite3's `-json` output.

    An empty result prints NOTHING (not `[]`), so a blank stdout is zero rows, not a
    malformed answer. The extra row `build_argv` asked for is dropped here and reported
    as `truncated`: an incomplete answer that does not say so is the failure mode this
    whole wrapper exists to avoid.
    """
    text = stdout.strip()
    if not text:
        return {
            "rows": [],
            "row_count": 0,
            "columns": [],
            "truncated": False,
            "note": "la consulta no devolvio ninguna fila",
        }
    try:
        rows = json.loads(text)
    except json.JSONDecodeError as exc:
        return {
            "rows": [],
            "row_count": 0,
            "columns": [],
            "truncated": False,
            "parse_error": f"sqlite3 -json no devolvio JSON valido: {exc}",
            "raw_head": text[:500],
        }
    if not isinstance(rows, list):
        return {
            "rows": [],
            "row_count": 0,
            "columns": [],
            "truncated": False,
            "parse_error": "sqlite3 -json no devolvio una lista de filas",
            "raw_head": text[:500],
        }

    # The cap rides in every row. Its absence means the output did not come from this
    # wrapper's argv, which is a contract break, not something to paper over.
    caps = {row.get(_CAP_COLUMN) for row in rows if isinstance(row, dict)}
    if rows and (len(caps) != 1 or not isinstance(next(iter(caps)), int)):
        return {
            "rows": [],
            "row_count": 0,
            "columns": [],
            "truncated": False,
            "parse_error": (
                f"las filas no traen la columna {_CAP_COLUMN!r} que fija la cota; "
                "la salida no viene del argv de este envoltorio"
            ),
            "raw_head": text[:500],
        }
    cap = next(iter(caps)) if caps else 0
    truncated = len(rows) > cap
    rows = [
        {k: v for k, v in row.items() if k != _CAP_COLUMN}
        for row in rows[:cap]
    ]

    columns = list(rows[0].keys()) if rows and isinstance(rows[0], dict) else []
    return {
        "rows": rows,
        "row_count": len(rows),
        "columns": columns,
        "truncated": truncated,
        "note": (
            "resultado ACOTADO: hay mas filas de las pedidas, afina la consulta "
            "(filtra por fecha, agrega con count/group by) antes de concluir"
        )
        if truncated
        else "resultado completo para la consulta enviada",
    }
