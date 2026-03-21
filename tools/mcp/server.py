"""
TRR MCP Server

Exposes two tools for the /trr-match skill:

  search_trrs         — filtered search over index.json + procedures.json;
                        returns lightweight summaries for fast technique
                        matching without reading any README files.

  get_procedure_detail — extracts only the Procedures and Available Emulation
                         Tests sections from a specific TRR README, on demand,
                         for disambiguation when a match is uncertain.

Run from the repository root:
    python3 tools/mcp/server.py
"""

import json
import os
import re
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Bootstrap: locate repo root (directory containing index.json)
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent  # tools/mcp -> tools -> repo root

INDEX_PATH = REPO_ROOT / "index.json"
PROCEDURES_PATH = REPO_ROOT / "tools" / "procedure_extraction" / "procedures.json"
REPORTS_DIR = REPO_ROOT / "reports"

# Sections of a TRR README that are useful for procedure matching
_DETAIL_SECTIONS = {"Procedures", "Available Emulation Tests"}


# ---------------------------------------------------------------------------
# Data loading helpers (loaded once at startup)
# ---------------------------------------------------------------------------

def _load_index() -> list[dict]:
    with open(INDEX_PATH, encoding="utf-8") as f:
        return json.load(f)


def _load_procedures() -> list[dict]:
    with open(PROCEDURES_PATH, encoding="utf-8") as f:
        return json.load(f)


def _build_test_map(procedures: list[dict]) -> dict[str, list[str]]:
    """Build a map of procedure_id -> list of test IDs."""
    m: dict[str, list[str]] = {}
    for row in procedures:
        pid = row.get("Procedure ID", "")
        raw = row.get("Test ID", "")
        ids = [t.strip() for t in raw.split(",") if t.strip()] if raw else []
        m[pid] = ids
    return m


# Load once at import time so repeated tool calls are fast
_INDEX: list[dict] = _load_index()
_TEST_MAP: dict[str, list[str]] = _build_test_map(_load_procedures())


# ---------------------------------------------------------------------------
# README section extractor
# ---------------------------------------------------------------------------

def _extract_sections(readme_text: str, wanted: set[str]) -> str:
    """Return only the H2 sections whose titles are in *wanted*."""
    lines = readme_text.splitlines(keepends=True)
    result: list[str] = []
    capturing = False

    for line in lines:
        stripped = line.rstrip("\n\r")
        if stripped.startswith("## "):
            heading = stripped[3:].strip()
            capturing = heading in wanted
        if capturing:
            result.append(line)

    return "".join(result).strip()


def _find_readmes(trr_id: str) -> list[Path]:
    """Return all README.md paths for the given TRR ID (case-insensitive)."""
    folder = REPORTS_DIR / trr_id.lower()
    if not folder.is_dir():
        return []
    return sorted(folder.rglob("README.md"))


# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "trr-matcher",
    instructions=(
        "Tools for matching threat intelligence to TRR procedures. "
        "Use search_trrs first. Call get_procedure_detail only when a match "
        "is uncertain and the procedure narrative would help disambiguate."
    ),
)


@mcp.tool()
def search_trrs(
    keywords: str | None = None,
    attack_ids: list[str] | None = None,
    tactic: str | None = None,
    platform: str | None = None,
) -> list[dict]:
    """Search TRRs by keyword, ATT&CK ID, tactic, and/or platform.

    Returns lightweight TRR summaries including procedure titles and
    linked emulation test IDs. No README files are read.

    Args:
        keywords: Free-text search across TRR name and procedure titles.
                  Case-insensitive substring match.
        attack_ids: ATT&CK technique IDs to match (e.g. ["T1003.006"]).
                    A TRR matches if any of its external_ids is in this list.
        tactic: Tactic to filter by (e.g. "Credential Access").
                Case-insensitive substring match.
        platform: Platform to filter by (e.g. "Windows", "Active Directory").
                  Case-insensitive substring match.

    Returns:
        List of matching TRRs. Each entry contains:
          id, name, tactics, platforms, external_ids,
          procedures: {procedure_id: {title, test_ids}}
    """
    kw_lower = keywords.lower() if keywords else None
    atk_upper = {a.upper() for a in attack_ids} if attack_ids else None
    tactic_lower = tactic.lower() if tactic else None
    platform_lower = platform.lower() if platform else None

    results = []

    for trr in _INDEX:
        trr_id: str = trr.get("id", "")
        name: str = trr.get("name", "")
        tactics: list[str] = trr.get("tactics", [])
        platforms: list[str] = trr.get("platforms", [])
        external_ids: list[str] = trr.get("external_ids", [])
        proc_summaries: dict[str, str] = trr.get("procedures", {})

        # --- ATT&CK ID filter ---
        if atk_upper:
            if not any(eid.upper() in atk_upper for eid in external_ids):
                continue

        # --- Tactic filter ---
        if tactic_lower:
            if not any(tactic_lower in t.lower() for t in tactics):
                continue

        # --- Platform filter ---
        if platform_lower:
            if not any(platform_lower in p.lower() for p in platforms):
                continue

        # --- Keyword filter ---
        if kw_lower:
            searchable = name.lower() + " " + " ".join(
                t.lower() for t in proc_summaries.values()
            )
            if kw_lower not in searchable:
                continue

        # Build procedure map with test IDs
        procedures: dict[str, dict] = {}
        for letter, title in proc_summaries.items():
            # Procedure IDs in procedures.json use the full ID format,
            # e.g. "TRR0011.AD.A". The index uses just the letter.
            # We match by checking for any key ending in ".{LETTER}".
            matches = [
                pid for pid in _TEST_MAP
                if pid.startswith(trr_id) and pid.endswith(f".{letter}")
            ]
            test_ids: list[str] = []
            for pid in matches:
                test_ids.extend(_TEST_MAP[pid])

            # Use the full procedure ID if we found one, else construct it
            full_pid = matches[0] if matches else f"{trr_id}.?.{letter}"
            procedures[full_pid] = {"title": title, "test_ids": test_ids}

        results.append(
            {
                "id": trr_id,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
                "external_ids": external_ids,
                "procedures": procedures,
            }
        )

    return results


@mcp.tool()
def get_procedure_detail(trr_id: str) -> dict:
    """Return the Procedures and Available Emulation Tests sections of a TRR.

    Reads only the relevant sections from the TRR README(s), stripping the
    Technique Overview, Technical Background, and References sections that
    are not useful for procedure matching.

    Use this tool only when search_trrs results are ambiguous and reading
    the procedure narrative would help confirm or rule out a match.

    Args:
        trr_id: The TRR ID (e.g. "TRR0011"). Case-insensitive.

    Returns:
        A dict with:
          id: the TRR ID
          readmes: list of {path, content} — one per platform README found.
                   content contains only the Procedures and Available
                   Emulation Tests sections.
        Returns an error key if the TRR is not found.
    """
    readmes = _find_readmes(trr_id)
    if not readmes:
        return {
            "id": trr_id,
            "error": f"No README files found for {trr_id}. "
                     f"Check that the TRR exists in the reports/ directory.",
        }

    results = []
    for readme_path in readmes:
        try:
            text = readme_path.read_text(encoding="utf-8")
            detail = _extract_sections(text, _DETAIL_SECTIONS)
            rel_path = str(readme_path.relative_to(REPO_ROOT))
            results.append({"path": rel_path, "content": detail})
        except OSError as exc:
            results.append(
                {"path": str(readme_path), "error": str(exc)}
            )

    return {"id": trr_id, "readmes": results}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
