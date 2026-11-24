#!/usr/bin/env python3
"""RDP Wrapper upstream monitor v1.2.2.

Collects public issue/comment activity, extracts INI candidates, and classifies
reported compatibility context. It never downloads, installs, or publishes INI.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

UPSTREAM_OWNER = "stascorp"
UPSTREAM_REPO = "rdpwrap"
API_ROOT = "https://api.github.com"
STATE_PATH = Path("monitor-state.json")
DATABASE_PATH = Path("compatibility-candidates.json")
PRODUCTION_INI_PATH = Path("rdpwrap.ini")
COMPARISON_PATH = Path("production-comparison.json")
PER_PAGE = 100
MAX_CANDIDATES_IN_SUMMARY = 50
MAX_CANDIDATE_LENGTH = 16000

INI_MARKERS = (
    "SingleUserPatch", "DefPolicyPatch", "LocalOnlyPatch", "SLInitOffset", "SLInitHook",
)
VERSION_RE = re.compile(r"(?<![\d.])10\.0\.\d{4,5}\.\d{1,7}(?!\d)")
SECTION_RE = re.compile(r"^\s*\[([^\]\r\n]+)\]\s*$")
KEY_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=")
FENCE_RE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
URL_RE = re.compile(r"https?://[^\s<>\]\[()\"']+", re.IGNORECASE)

FAILURE_PATTERNS = {
    "service_crash_report": re.compile(r"\b(?:crash(?:es|ed|ing)?|crashing)\b", re.IGNORECASE),
    "service_start_failure": re.compile(
        r"\b(?:fails? to start|failed to start|won['’]?t start|does not start|cannot start|unable to start)\b",
        re.IGNORECASE,
    ),
    "service_error_1067": re.compile(r"\b(?:error\s*1067|1067\s*error)\b", re.IGNORECASE),
    "blue_screen_or_bsod": re.compile(r"\b(?:blue\s+screen|bsod|bugcheck)\b", re.IGNORECASE),
    "patch_failure_report": re.compile(
        r"\bafter\s+(?:adding|applying|installing|using)\s+(?:the\s+)?(?:new\s+)?patch(?:es|\s+codes?)?\b",
        re.IGNORECASE,
    ),
    "not_working_report": re.compile(r"\b(?:not working|doesn['’]?t work|does not work|stopped working)\b", re.IGNORECASE),
}
TRIAGE_PATTERNS = {
    "not_rdp_wrapper_bug": re.compile(r"\bnot\s+(?:an?\s+)?rdp\s+wrapper\s+bug\b", re.IGNORECASE),
    "not_a_bug_in_rdp_wrapper": re.compile(r"\bnot\s+a\s+bug\s+in\s+rdp\s+wrapper\b", re.IGNORECASE),
    "direct_to_support": re.compile(r"\bplease\s+contact\b.{0,80}\bsupport\b", re.IGNORECASE),
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=str(path.parent), delete=False) as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
        temp_name = handle.name
    Path(temp_name).replace(path)


def load_since() -> tuple[datetime, bool, str]:
    """Choose a scan window; upgrading a v1 database triggers 30-day enrichment."""
    now = utc_now()
    if not DATABASE_PATH.exists():
        return now - timedelta(days=30), True, "initial 30-day candidate database backfill"
    try:
        existing = json.loads(DATABASE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RuntimeError(f"Cannot inspect {DATABASE_PATH}: {exc}") from exc
    if existing.get("schema_version", 1) < 2 or not isinstance(existing.get("issues"), dict):
        return now - timedelta(days=30), True, "v1.2 30-day compatibility enrichment backfill"
    if not STATE_PATH.exists():
        return now - timedelta(days=7), True, "initial 7-day scan"
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        checkpoint = parse_time(state["last_checked"])
        return checkpoint - timedelta(minutes=2), False, "since last checkpoint"
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"Cannot read {STATE_PATH}: {exc}") from exc


def load_database() -> dict:
    if not DATABASE_PATH.exists():
        return {
            "schema_version": 2,
            "upstream": f"{UPSTREAM_OWNER}/{UPSTREAM_REPO}",
            "updated_at": None,
            "candidates": {},
            "issues": {},
        }
    try:
        data = json.loads(DATABASE_PATH.read_text(encoding="utf-8"))
        schema = data.get("schema_version", 1)
        if schema not in (1, 2) or not isinstance(data.get("candidates"), dict):
            raise ValueError("unsupported candidate database schema")
        # Backward-compatible v1.1 -> v1.2 migration. Candidate hashes/content
        # and existing source records are preserved; new metadata is enriched
        # during the 30-day backfill.
        data["schema_version"] = 2
        data.setdefault("issues", {})
        if not isinstance(data["issues"], dict):
            data["issues"] = {}
        data.setdefault("upstream", f"{UPSTREAM_OWNER}/{UPSTREAM_REPO}")
        data.setdefault("updated_at", None)
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(f"Cannot read {DATABASE_PATH}: {exc}") from exc


def get_github_token() -> str:
    """Return the Actions-provided token; never fall back to anonymous API calls."""
    return (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip()


def api_get(url: str):
    token = get_github_token()
    if not token:
        raise RuntimeError(
            "GitHub API authentication token is missing. The monitor will not make "
            "unauthenticated requests because they are limited to 60 requests/hour. "
            "Set GH_TOKEN: ${{ secrets.GITHUB_TOKEN }} on the monitor step in the workflow."
        )

    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "johnson4860-rdp-update-monitor/1.2.2",
        "Authorization": f"Bearer {token}",
    }
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        if exc.code == 403:
            remaining = exc.headers.get("X-RateLimit-Remaining", "unknown")
            limit = exc.headers.get("X-RateLimit-Limit", "unknown")
            reset = exc.headers.get("X-RateLimit-Reset", "unknown")
            resource = exc.headers.get("X-RateLimit-Resource", "unknown")
            raise RuntimeError(
                "GitHub API returned 403 despite a token being configured "
                f"(resource={resource}, rate-limit={remaining}/{limit}, reset={reset}). "
                f"Response: {detail}"
            ) from exc
        if exc.code == 401:
            raise RuntimeError(
                "GitHub API rejected the Actions token (HTTP 401). Check that the "
                "workflow uses ${{ secrets.GITHUB_TOKEN }} and that the token is not overridden. "
                f"Response: {detail}"
            ) from exc
        raise RuntimeError(f"GitHub API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Unable to reach GitHub API: {exc}") from exc


def check_api_authentication() -> None:
    """Prove the Actions token is being applied and print quota without exposing it."""
    if not get_github_token():
        raise RuntimeError(
            "GH_TOKEN is not available to the monitor step. Add this exact step-level "
            "environment entry: GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}"
        )
    payload = api_get(f"{API_ROOT}/rate_limit")
    core = (payload.get("resources") or {}).get("core") or {}
    limit = core.get("limit", "unknown")
    remaining = core.get("remaining", "unknown")
    reset = core.get("reset", "unknown")
    print("GitHub API authentication: token supplied (value hidden)")
    print(f"GitHub REST core quota: {remaining}/{limit} requests remaining; reset epoch={reset}")
    if limit == 60:
        raise RuntimeError(
            "GitHub API is still using the unauthenticated 60-request quota. "
            "The workflow token did not authenticate the request; verify GH_TOKEN mapping."
        )


def get_pages(url: str, params: dict) -> list:
    results = []
    page = 1
    while True:
        query = dict(params)
        query.update({"per_page": PER_PAGE, "page": page})
        separator = "&" if "?" in url else "?"
        data = api_get(url + separator + urlencode(query))
        if not isinstance(data, list):
            raise RuntimeError(f"Unexpected GitHub API response from {url}")
        results.extend(data)
        if len(data) < PER_PAGE:
            return results
        page += 1


def is_ini_text(text: str) -> bool:
    lower = (text or "").lower()
    return any(marker.lower() in lower for marker in INI_MARKERS)


def format_ini_block(raw: str) -> str:
    """Normalize flattened GitHub text without inventing missing section headers."""
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    text = re.sub(
        r"\s+(?=(?:\[[^\]\n]{1,120}\]|[A-Za-z_][A-Za-z0-9_.-]*\s*=))",
        "\n",
        text,
    )
    lines = text.splitlines()
    cleaned = []
    for index, raw_line in enumerate(lines):
        line = raw_line.strip()
        if line.startswith(">"):
            line = line[1:].lstrip()
        if line.endswith("\\") and index + 1 < len(lines):
            next_line = lines[index + 1].strip().lstrip(">").lstrip()
            if SECTION_RE.match(next_line) or KEY_RE.match(next_line):
                line = line[:-1].rstrip()
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def canonical_candidate(text: str) -> str:
    return "\n".join(line.strip() for line in text.replace("\r", "").split("\n") if line.strip())


def candidate_hash(text: str) -> str:
    return hashlib.sha256(canonical_candidate(text).encode("utf-8")).hexdigest()


def extract_unfenced_candidate(text: str) -> list[str]:
    content = text or ""
    starts = []
    for pattern in (
        r"\[\s*10\.0\.[^\]\r\n]+\]",
        r"\bSingleUserPatch(?:\.[A-Za-z0-9_.-]+)?\s*=",
        r"\bDefPolicyPatch(?:\.[A-Za-z0-9_.-]+)?\s*=",
    ):
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            starts.append(match.start())
    if not starts:
        return []
    normalized = format_ini_block(content[min(starts):])
    collected = []
    started = False
    for line in normalized.splitlines():
        stripped = line.strip()
        is_entry = bool(SECTION_RE.match(stripped) or KEY_RE.match(stripped))
        is_comment = stripped.startswith((";", "#"))
        if not stripped:
            if started:
                collected.append("")
            continue
        if is_entry or is_comment:
            collected.append(stripped)
            started = True
        elif started:
            break
    candidate = "\n".join(collected).strip()
    return [candidate] if candidate and is_ini_text(candidate) else []


def extract_ini_candidates(text: str) -> list[dict]:
    source = text or ""
    raw_blocks = []
    for match in FENCE_RE.finditer(source):
        block = format_ini_block(match.group(1))
        if block and is_ini_text(block):
            raw_blocks.append(block)
    outside = FENCE_RE.sub("\n", source)
    raw_blocks.extend(extract_unfenced_candidate(outside))

    unique = {}
    duplicate_occurrences = 0
    for block in raw_blocks:
        normalized = format_ini_block(block)
        if not normalized or not is_ini_text(normalized):
            continue
        digest = candidate_hash(normalized)
        if digest in unique:
            duplicate_occurrences += 1
        else:
            unique[digest] = normalized
    return [
        {"sha256": digest, "content": content, "duplicate_occurrences": duplicate_occurrences}
        for digest, content in unique.items()
    ]


def inspect_candidate(content: str) -> dict:
    sections = []
    ini_targets, main_targets, slinit_targets = set(), set(), set()
    for line in content.splitlines():
        match = SECTION_RE.match(line)
        if not match:
            continue
        section = match.group(1).strip()
        sections.append(section)
        version_match = re.fullmatch(r"(10\.0\.\d{4,5}\.\d{1,7})(-SLInit)?", section, re.IGNORECASE)
        if version_match:
            version = version_match.group(1)
            ini_targets.add(version)
            if version_match.group(2):
                slinit_targets.add(version)
            else:
                main_targets.add(version)

    warnings = []
    if not main_targets:
        if slinit_targets:
            warnings.append("SLInit section is present, but the main [10.0.x.x] section header is missing.")
        else:
            warnings.append("No complete [10.0.x.x] primary section header was detected; candidate may be partial.")
    expected_keys = ("SingleUserPatch", "DefPolicyPatch", "LocalOnlyPatch", "SLInitHook")
    lower_content = content.lower()
    missing = [key for key in expected_keys if key.lower() not in lower_content]
    if missing:
        warnings.append("Common patch key(s) not detected: " + ", ".join(missing) + ".")
    return {
        "sections": sections,
        "ini_target_versions": sorted(ini_targets),
        "main_section_versions": sorted(main_targets),
        "slinit_section_versions": sorted(slinit_targets),
        "warnings": warnings,
        "missing_common_keys": missing,
        "is_complete": bool(main_targets) and not missing,
    }


def extract_urls(text: str) -> list[str]:
    found = []
    for raw in URL_RE.findall(text or ""):
        link = raw.rstrip(".,;:!?")
        low = link.lower()
        if (
            ".zip" in low or ".ini" in low or "user-attachments" in low
            or "gist.github.com" in low or "pastebin" in low
        ) and link not in found:
            found.append(link)
    return found


def extract_version_strings(text: str) -> list[str]:
    return sorted(set(VERSION_RE.findall(text or "")))


def extract_os_metadata(title: str) -> dict:
    title = title or ""
    releases = []
    release_re = re.compile(
        r"\bWindows\s+(10|11)\b(?:\s+(?:Pro|Home|Enterprise|Education|Workstation))?\s*(22H2|23H2|24H2|25H2|26H2)?",
        re.IGNORECASE,
    )
    for match in release_re.finditer(title):
        os_name = f"Windows {match.group(1)}"
        if match.group(2):
            os_name += f" {match.group(2).upper()}"
        if os_name not in releases:
            releases.append(os_name)

    build_hints = set()
    explicit_build_re = re.compile(
        r"\b(?:build|compilation|compilacion|compilación)\s*(?:number|no\.?|#|:)?\s*(\d{4,5}\.\d{3,7})\b",
        re.IGNORECASE,
    )
    build_hints.update(explicit_build_re.findall(title))

    # Windows-specific dotted numeric hint following a Windows release. Do not
    # mislabel a 10.0.x.x tuple as an OS build; keep it in its own field.
    os_version_hints = set()
    for version_match in re.finditer(r"\b10\.0\.\d{4,5}\.\d{1,7}\b", title):
        # Only treat this as a Windows title hint when the Windows product
        # name appears before the version token. A leading 10.0.x.x value,
        # as in the Windows 10 termsrv sample title, remains unclassified.
        if re.search(r"\bWindows\s+(?:10|11)\b", title[:version_match.start()], re.IGNORECASE):
            os_version_hints.add(version_match.group(0))

    # Legacy title pattern, e.g. Windows 10 Pro 22H2 19045.7846 x86.
    windows_numeric_re = re.compile(
        r"\bWindows\s+(?:10|11)\b.{0,120}?(?<![\d.])(\d{4,5}\.\d{3,7})(?!\d)",
        re.IGNORECASE,
    )
    for match in windows_numeric_re.finditer(title):
        token = match.group(1)
        start = match.start(1)
        if title[:start].endswith("10.0."):
            os_version_hints.add(f"10.0.{token}")
        elif token not in os_version_hints:
            build_hints.add(token)

    return {
        "os_releases": releases,
        "os_build_hints": sorted(build_hints),
        "os_version_hints": sorted(os_version_hints),
    }


def extract_explicit_termsrv_versions(text: str) -> list[str]:
    found = set()
    version = r"10\.0\.\d{4,5}\.\d{1,7}"
    patterns = (
        rf"termsrv(?:\.dll)?[^\n]{{0,120}}?({version})",
        rf"({version})[^\n]{{0,120}}?termsrv(?:\.dll)?",
    )
    for pattern in patterns:
        found.update(re.findall(pattern, text or "", re.IGNORECASE))
    return sorted(found)


def duplicate_issue_references(text: str) -> list[int]:
    found = set()
    for match in re.finditer(r"(?:duplicate(?:\s+of)?|duplicates)\s*[:#]?\s*#?(\d{1,7})", text or "", re.IGNORECASE):
        found.add(int(match.group(1)))
    for match in re.finditer(r"github\.com/stascorp/rdpwrap/issues/(\d+)", text or "", re.IGNORECASE):
        found.add(int(match.group(1)))
    return sorted(found)


def detect_failure_signals(text: str) -> list[str]:
    content = text or ""
    return [name for name, pattern in FAILURE_PATTERNS.items() if pattern.search(content)]


def detect_triage_notes(comments: list[dict]) -> list[dict]:
    notes = []
    for comment in comments:
        body = comment.get("body") or ""
        matched = [name for name, pattern in TRIAGE_PATTERNS.items() if pattern.search(body)]
        if matched:
            notes.append({
                "signals": matched,
                "author": (comment.get("user") or {}).get("login", "unknown"),
                "created_at": comment.get("created_at"),
                "updated_at": comment.get("updated_at"),
                "url": comment.get("html_url"),
                "excerpt": re.sub(r"\s+", " ", body).strip()[:500],
            })
    return notes


def build_version_relationships(
    all_versions: list[str], os_metadata: dict, termsrv_versions: list[str], ini_target_versions: list[str]
) -> list[dict]:
    roles: dict[str, set[str]] = {}
    def add(role: str, values: list[str]) -> None:
        for value in values:
            roles.setdefault(value, set()).add(role)
    add("os_build_hint", os_metadata.get("os_build_hints", []))
    add("os_version_hint_from_title", os_metadata.get("os_version_hints", []))
    add("termsrv_dll_explicit", termsrv_versions)
    add("ini_section_target", ini_target_versions)
    for value in all_versions:
        if value not in roles:
            roles.setdefault(value, set()).add("other_version_identifier")
    return [
        {"version": value, "roles": sorted(value_roles)}
        for value, value_roles in sorted(roles.items())
    ]


def classify_issue(
    labels: list[str], duplicate_refs: list[int], failure_signals: list[str], title: str = ""
) -> str:
    label_set = {label.lower() for label in labels}
    if failure_signals:
        return "reported_failure"
    if "duplicate" in label_set or duplicate_refs:
        return "duplicate_issue"
    if "invalid" in label_set:
        return "maintainer_labeled_invalid"
    if "add build" in label_set or re.search(r"\bnot supported\b", title, re.IGNORECASE):
        return "compatibility_request"
    return "general_activity"


def source_key(source: dict) -> str:
    return source.get("source_url") or f"{source.get('source_type')}:{source.get('issue_number')}"


def candidate_review_classification(details: dict, sources: list[dict]) -> str:
    if any(source.get("failure_signals") for source in sources):
        return "reported_failure"
    if not details.get("is_complete", False):
        return "incomplete"
    return "unverified"


def add_candidate_to_database(database: dict, candidate: dict, source: dict, now_text: str) -> tuple[str, bool]:
    digest = candidate["sha256"]
    details = inspect_candidate(candidate["content"])
    existing = database["candidates"].get(digest)
    new_candidate = existing is None
    if existing is None:
        existing = {
            "candidate_id": digest[:16],
            "sha256": digest,
            "content": candidate["content"],
            "status": "unverified",
            "review_classification": "unverified",
            "completeness": "complete" if details["is_complete"] else "incomplete",
            "first_seen": now_text,
            "last_seen": now_text,
            "ini_target_versions": details["ini_target_versions"],
            "main_section_versions": details["main_section_versions"],
            "slinit_section_versions": details["slinit_section_versions"],
            "sections": details["sections"],
            "warnings": details["warnings"],
            "review_flags": [],
            "sources": [],
        }
        database["candidates"][digest] = existing
    else:
        existing["last_seen"] = now_text
        existing.setdefault("review_flags", [])
        existing.setdefault("sources", [])
        existing.setdefault("completeness", "incomplete" if not details["is_complete"] else "complete")

    known_source_keys = {source_key(item): index for index, item in enumerate(existing.get("sources", []))}
    key = source_key(source)
    added_source = key not in known_source_keys
    if added_source:
        existing["sources"].append(source)
    else:
        # Refresh metadata for edited issue descriptions/comments without
        # duplicating their provenance URL.
        existing["sources"][known_source_keys[key]] = source

    all_sources = existing.get("sources", [])
    all_failure_signals = sorted({signal for item in all_sources for signal in item.get("failure_signals", [])})
    flags = set(existing.get("review_flags", []))
    if all_failure_signals:
        flags.add("reported_failure_context")
    if any(item.get("issue_classification") == "duplicate_issue" for item in all_sources):
        flags.add("source_issue_marked_duplicate")
    if any("invalid" in [label.lower() for label in item.get("labels", [])] for item in all_sources):
        flags.add("source_issue_labeled_invalid")
    if any(item.get("triage_notes") for item in all_sources):
        flags.add("maintainer_or_triage_note_present")
    if details["warnings"]:
        flags.add("parser_warning")
    existing["review_flags"] = sorted(flags)
    existing["reported_failure_signals"] = all_failure_signals
    existing["review_classification"] = candidate_review_classification(details, all_sources)
    existing["completeness"] = "complete" if details["is_complete"] else "incomplete"
    existing["warnings"] = details["warnings"]
    existing["sections"] = details["sections"]
    existing["ini_target_versions"] = details["ini_target_versions"]
    existing["main_section_versions"] = details["main_section_versions"]
    existing["slinit_section_versions"] = details["slinit_section_versions"]
    return ("new" if new_candidate else ("source-added" if added_source else "existing"), new_candidate)


def markdown_safe(value: str) -> str:
    return (value or "").replace("\r", "").strip()


def get_recent_comments(issue_number: int, since_text: str) -> list[dict]:
    url = f"{API_ROOT}/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{issue_number}/comments"
    return get_pages(url, {"since": since_text, "sort": "updated", "direction": "asc"})


def format_candidate_source(source: dict) -> str:
    label = "Issue description" if source.get("source_type") == "issue_body" else f"Comment by @{source.get('author', 'unknown')}"
    created = source.get("created_at") or "creation date unknown"
    updated = source.get("updated_at")
    edited = f"; last edited `{updated}`" if updated and updated != created else ""
    link = source.get("source_url") or source.get("issue_url") or ""
    return f"{label} — created `{created}`{edited} — {link}"


def upsert_issue_record(database: dict, issue_record: dict) -> None:
    key = str(issue_record["number"])
    previous = database.setdefault("issues", {}).get(key, {})
    first_seen = previous.get("first_seen") or issue_record.get("monitor_seen_at")
    issue_record["first_seen"] = first_seen
    issue_record["last_seen"] = issue_record.get("monitor_seen_at")
    database["issues"][key] = issue_record



def parse_ini_document(text: str) -> dict:
    """Parse INI sections for comparison without changing the source text.

    Section and key names are compared case-insensitively. Values are trimmed
    but otherwise kept exact so a real value change is not hidden.
    """
    sections: dict[str, dict[str, str]] = {}
    section_display: dict[str, str] = {}
    unsectioned_entries: list[dict] = []
    duplicate_keys: list[dict] = []
    current_section: str | None = None

    for line_number, raw_line in enumerate((text or "").replace("\ufeff", "").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith((";", "#")):
            continue
        section_match = SECTION_RE.match(line)
        if section_match:
            display = section_match.group(1).strip()
            key = display.casefold()
            current_section = key
            section_display.setdefault(key, display)
            sections.setdefault(key, {})
            continue
        if "=" not in line:
            continue
        raw_key, raw_value = line.split("=", 1)
        display_key = raw_key.strip()
        value = raw_value.strip()
        if not display_key:
            continue
        key_norm = display_key.casefold()
        if current_section is None:
            unsectioned_entries.append({
                "line": line_number,
                "key": display_key,
                "value": value,
            })
            continue
        values = sections.setdefault(current_section, {})
        if key_norm in values:
            duplicate_keys.append({
                "section": section_display.get(current_section, current_section),
                "key": display_key,
                "line": line_number,
                "previous_value": values[key_norm],
                "replacement_value": value,
            })
        values[key_norm] = value
    return {
        "sections": sections,
        "section_display": section_display,
        "unsectioned_entries": unsectioned_entries,
        "duplicate_keys": duplicate_keys,
    }


def extract_main_updated(text: str) -> str | None:
    parsed = parse_ini_document(text)
    main = parsed["sections"].get("main", {})
    return main.get("updated")


def compare_candidate_to_production(candidate: dict, production_text: str) -> dict:
    """Compare one upstream candidate against production by section and key/value."""
    candidate_text = candidate.get("content", "")
    candidate_parsed = parse_ini_document(candidate_text)
    production_parsed = parse_ini_document(production_text)
    details = inspect_candidate(candidate_text)

    section_results = []
    flags: set[str] = set()
    value_differences = []
    candidate_only_keys = []
    production_only_keys = []
    new_sections = []
    exact_sections = 0
    partial_sections = 0

    for section_key in sorted(candidate_parsed["sections"].keys()):
        section_name = candidate_parsed["section_display"].get(section_key, section_key)
        candidate_values = candidate_parsed["sections"][section_key]
        if section_key not in production_parsed["sections"]:
            new_sections.append(section_name)
            flags.add("new_section")
            section_results.append({
                "section": section_name,
                "status": "new_section",
                "candidate_key_count": len(candidate_values),
                "production_key_count": 0,
                "value_differences": [],
                "candidate_only_keys": sorted(candidate_values.keys()),
                "candidate_entries": [
                    {"key": key, "value": value}
                    for key, value in sorted(candidate_values.items())
                ],
                "production_only_keys": [],
            })
            continue

        production_values = production_parsed["sections"][section_key]
        section_value_differences = []
        section_candidate_only = []
        section_production_only = []
        for key, candidate_value in sorted(candidate_values.items()):
            if key not in production_values:
                record = {"section": section_name, "key": key, "candidate_value": candidate_value}
                section_candidate_only.append(record)
                candidate_only_keys.append(record)
            elif candidate_value != production_values[key]:
                record = {
                    "section": section_name,
                    "key": key,
                    "candidate_value": candidate_value,
                    "production_value": production_values[key],
                }
                section_value_differences.append(record)
                value_differences.append(record)
        for key, production_value in sorted(production_values.items()):
            if key not in candidate_values:
                record = {"section": section_name, "key": key, "production_value": production_value}
                section_production_only.append(record)
                production_only_keys.append(record)

        if section_value_differences:
            section_status = "value_difference"
            flags.add("value_difference")
        elif section_candidate_only:
            section_status = "candidate_has_new_keys"
            flags.add("new_keys")
        elif section_production_only:
            section_status = "production_has_extra_keys"
            partial_sections += 1
            flags.add("production_has_extra_keys")
        else:
            section_status = "exact_match"
            exact_sections += 1
        section_results.append({
            "section": section_name,
            "status": section_status,
            "candidate_key_count": len(candidate_values),
            "production_key_count": len(production_values),
            "value_differences": section_value_differences,
            "candidate_only_keys": [item["key"] for item in section_candidate_only],
            "production_only_keys": [item["key"] for item in section_production_only],
        })

    if candidate_parsed["unsectioned_entries"]:
        flags.add("unsectioned_entries")
    if candidate_parsed["duplicate_keys"]:
        flags.add("duplicate_ini_keys")
    if details.get("warnings"):
        flags.add("parser_warning")

    incomplete = bool(
        not details.get("is_complete")
        or candidate_parsed["unsectioned_entries"]
        or candidate_parsed["duplicate_keys"]
    )
    difference_kinds = sum(bool(flag) for flag in (new_sections, value_differences, candidate_only_keys, production_only_keys))
    if incomplete:
        status = "incomplete"
    elif difference_kinds > 1:
        status = "mixed_difference"
    elif value_differences:
        status = "value_difference"
    elif new_sections:
        status = "new_section"
    elif candidate_only_keys:
        status = "new_keys"
    elif production_only_keys:
        status = "partial_match"
    else:
        status = "exact_match"

    return {
        "candidate_id": candidate.get("candidate_id") or candidate.get("sha256", "")[:16],
        "sha256": candidate.get("sha256"),
        "ini_target_versions": details.get("ini_target_versions", []),
        "candidate_review_classification": candidate.get("review_classification", "unverified"),
        "comparison_status": status,
        "comparison_flags": sorted(flags),
        "section_results": section_results,
        "new_sections": sorted(new_sections),
        "value_differences": value_differences,
        "candidate_only_keys": candidate_only_keys,
        "production_only_keys": production_only_keys,
        "unsectioned_entries": candidate_parsed["unsectioned_entries"],
        "duplicate_keys": candidate_parsed["duplicate_keys"],
        "parser_warnings": details.get("warnings", []),
        "source_count": len(candidate.get("sources", [])),
        "sources": [
            {
                "source_type": source.get("source_type"),
                "issue_number": source.get("issue_number"),
                "author": source.get("author"),
                "source_url": source.get("source_url") or source.get("issue_url"),
                "created_at": source.get("created_at"),
                "updated_at": source.get("updated_at"),
            }
            for source in candidate.get("sources", [])
        ],
    }


def build_production_comparison(database: dict, production_text: str, baseline_commit: str | None = None) -> dict:
    production_parsed = parse_ini_document(production_text)
    comparisons = []
    for candidate in database.get("candidates", {}).values():
        comparisons.append(compare_candidate_to_production(candidate, production_text))
    priority = {
        "value_difference": 0,
        "mixed_difference": 1,
        "new_section": 2,
        "new_keys": 3,
        "incomplete": 4,
        "partial_match": 5,
        "exact_match": 6,
    }
    comparisons.sort(key=lambda item: (
        priority.get(item["comparison_status"], 99),
        item.get("ini_target_versions", []),
        item["candidate_id"],
    ))
    counts: dict[str, int] = {}
    for item in comparisons:
        status = item["comparison_status"]
        counts[status] = counts.get(status, 0) + 1
    return {
        "schema_version": 1,
        "generated_at": iso_utc(utc_now()),
        "baseline": {
            "path": str(PRODUCTION_INI_PATH),
            "sha256": hashlib.sha256(production_text.encode("utf-8")).hexdigest(),
            "main_updated": extract_main_updated(production_text),
            "git_commit": baseline_commit,
            "section_count": len(production_parsed["sections"]),
        },
        "candidate_count": len(comparisons),
        "status_counts": counts,
        "comparisons": comparisons,
    }


def build_comparison_report(comparison: dict) -> str:
    baseline = comparison["baseline"]
    lines = [
        "## Upstream INI vs Production INI comparison",
        "",
        f"- Production baseline: `{baseline['path']}`",
        f"- Production SHA-256: `{baseline['sha256']}`",
        f"- `[Main] Updated`: `{baseline.get('main_updated') or 'not detected'}`",
        f"- Baseline commit: `{baseline.get('git_commit') or 'not provided'}`",
        f"- Production sections parsed: `{baseline['section_count']}`",
        f"- Unique upstream candidates compared: `{comparison['candidate_count']}`",
        "- Comparison is read-only; it does not modify `rdpwrap.ini`.",
        "",
        "### Comparison totals",
        "",
        "| Result | Candidates |",
        "|---|---:|",
    ]
    for status in ("new_section", "value_difference", "new_keys", "mixed_difference", "partial_match", "exact_match", "incomplete"):
        count = comparison["status_counts"].get(status, 0)
        lines.append(f"| `{status}` | {count} |")
    lines.extend(["", "### Full candidate comparison list", ""])
    if not comparison["comparisons"]:
        lines.append("No upstream INI candidates are recorded yet.")
        return "\n".join(lines) + "\n"

    labels = {
        "new_section": "NEW SECTION — not in Production",
        "value_difference": "VALUE DIFFERENCE",
        "new_keys": "NEW KEYS — absent from Production section",
        "mixed_difference": "MIXED DIFFERENCES",
        "partial_match": "PARTIAL MATCH — Production has additional keys",
        "exact_match": "EXACT MATCH",
        "incomplete": "INCOMPLETE — comparison is partial only",
    }
    for item in comparison["comparisons"]:
        versions = ", ".join(item.get("ini_target_versions", [])) or "no target version detected"
        lines.extend([
            f"#### `{item['candidate_id']}` — {labels.get(item['comparison_status'], item['comparison_status'])}",
            f"- INI target version(s): `{versions}`",
            f"- Candidate review status: `{item.get('candidate_review_classification', 'unverified')}`",
            f"- SHA-256: `{item['sha256']}`",
            f"- Sources: `{item['source_count']}`",
        ])
        source_links = []
        for source in item.get("sources", []):
            url = source.get("source_url") or ""
            if url and url not in source_links:
                source_links.append(url)
        for url in source_links[:5]:
            lines.append(f"  - Source: {url}")
        if len(source_links) > 5:
            lines.append(f"  - {len(source_links) - 5} additional source link(s) stored in `compatibility-candidates.json`.")
        if item.get("comparison_flags"):
            lines.append("- Comparison flags: " + ", ".join(f"`{flag}`" for flag in item["comparison_flags"]))
        if item.get("section_results"):
            lines.append("- Section results:")
            for section in item["section_results"]:
                lines.append(
                    f"  - `{section['section']}`: `{section['status']}` "
                    f"(candidate keys: {section['candidate_key_count']}; production keys: {section['production_key_count']})"
                )
                if section.get("candidate_entries"):
                    for entry in section["candidate_entries"][:50]:
                        lines.append(f"    - `{entry['key']}` = `{entry['value']}`")
                    if len(section["candidate_entries"]) > 50:
                        lines.append(f"    - {len(section['candidate_entries']) - 50} additional entries are stored in the JSON report.")
        if item.get("value_differences"):
            lines.append("- Value differences:")
            for difference in item["value_differences"][:30]:
                lines.append(
                    f"  - `{difference['section']}` / `{difference['key']}`: "
                    f"candidate=`{difference['candidate_value']}`; production=`{difference['production_value']}`"
                )
            if len(item["value_differences"]) > 30:
                lines.append(f"  - {len(item['value_differences']) - 30} additional value difference(s) in JSON report.")
        if item.get("candidate_only_keys"):
            lines.append("- Candidate key(s) missing from Production:")
            for entry in item["candidate_only_keys"][:30]:
                lines.append(f"  - `{entry['section']}` / `{entry['key']}` = `{entry['candidate_value']}`")
        if item.get("production_only_keys"):
            lines.append("- Production has additional key(s) not present in Candidate:")
            for entry in item["production_only_keys"][:30]:
                lines.append(f"  - `{entry['section']}` / `{entry['key']}` = `{entry['production_value']}`")
        if item.get("unsectioned_entries"):
            keys = ", ".join(entry["key"] for entry in item["unsectioned_entries"][:30])
            lines.append(f"- Unsectioned candidate entries (not compared): `{keys}`")
        if item.get("parser_warnings"):
            lines.append("- Parser warning(s): " + " ".join(item["parser_warnings"]))
        if item.get("duplicate_keys"):
            lines.append(f"- Duplicate keys inside Candidate: `{len(item['duplicate_keys'])}`")
        lines.append("")

    lines.extend([
        "### Comparison rules",
        "- Section names and key names are compared case-insensitively; values are compared exactly after trimming surrounding whitespace.",
        "- Candidate-only keys mean the Candidate contains settings absent from the same Production section.",
        "- Production-only keys mean the Production section contains additional settings; this is reported as a partial match, not an exact match.",
        "- A missing main section or unsectioned key/value lines make the Candidate `incomplete`; valid sections may still show their individual comparison result.",
        "- A comparison match is not a compatibility test. No Candidate is automatically promoted to Verified or Published.",
    ])
    return "\n".join(lines) + "\n"

def build_report(issues: list[dict], since: datetime, scan_type: str, database: dict, event_counts: dict) -> str:
    checked_at = utc_now()
    lines = [
        "# RDP Wrapper upstream monitor v1.2.2",
        "",
        f"- Checked at (UTC): `{iso_utc(checked_at)}`",
        f"- Upstream: [`{UPSTREAM_OWNER}/{UPSTREAM_REPO}`](https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO})",
        f"- Activity window starts: `{iso_utc(since)}`",
        f"- Scan type: `{scan_type}`",
        "- Collection only: the monitor does **not** download, install, or publish INI files.",
        "- Classification is signal-based triage, not proof that a configuration is compatible or defective.",
        "",
    ]
    real_issues = [item for item in issues if "pull_request" not in item]
    real_issues.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
    if not real_issues:
        lines.extend(["## Result", "No new or updated upstream issues were found in this scan."])
        return "\n".join(lines) + "\n"

    lines.extend([f"## Result: {len(real_issues)} issue(s) updated", ""])
    candidate_counter = 0

    for issue in real_issues:
        number = issue.get("number")
        title = markdown_safe(issue.get("title", "(untitled)"))
        issue_url = issue.get("html_url", f"https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{number}")
        state = issue.get("state", "unknown")
        updated = issue.get("updated_at", "unknown")
        labels = [label.get("name", "") for label in issue.get("labels", [])]
        label_text = ", ".join(labels) or "none"
        issue_body = issue.get("body") or ""
        comments = get_recent_comments(number, iso_utc(since)) if issue.get("comments", 0) else []

        os_metadata = extract_os_metadata(title)
        texts = [title, issue_body] + [comment.get("body") or "" for comment in comments]
        all_text = "\n\n".join(texts)
        versions = extract_version_strings(all_text)
        termsrv_versions = extract_explicit_termsrv_versions(all_text)
        links = extract_urls(all_text)
        duplicate_refs = duplicate_issue_references(all_text)
        failure_signals = detect_failure_signals(all_text)
        triage_notes = detect_triage_notes(comments)
        issue_classification = classify_issue(labels, duplicate_refs, failure_signals, title)

        source_payloads = []
        context = {
            "issue_classification": issue_classification,
            "failure_signals": failure_signals,
            "triage_notes": triage_notes,
            "duplicate_issue_refs": duplicate_refs,
            "os_releases": os_metadata["os_releases"],
            "os_build_hints": os_metadata["os_build_hints"],
            "os_version_hints": os_metadata["os_version_hints"],
            "termsrv_versions_explicit": termsrv_versions,
            "labels": labels,
            "issue_state": state,
        }
        if issue_body.strip():
            source_payloads.append((issue_body, {
                **context,
                "issue_number": number,
                "issue_title": title,
                "issue_url": issue_url,
                "source_type": "issue_body",
                "source_url": issue_url,
                "author": (issue.get("user") or {}).get("login", "unknown"),
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
            }))
        for comment in comments:
            source_payloads.append((comment.get("body") or "", {
                **context,
                "issue_number": number,
                "issue_title": title,
                "issue_url": issue_url,
                "source_type": "comment",
                "source_url": comment.get("html_url") or issue_url,
                "author": (comment.get("user") or {}).get("login", "unknown"),
                "created_at": comment.get("created_at"),
                "updated_at": comment.get("updated_at"),
            }))

        issue_candidates = {}
        issue_duplicate_count = 0
        for source_text, source in source_payloads:
            for candidate in extract_ini_candidates(source_text):
                issue_duplicate_count += candidate["duplicate_occurrences"]
                digest = candidate["sha256"]
                if digest in issue_candidates:
                    issue_duplicate_count += 1
                    first_source = issue_candidates[digest]["source"]
                    if source_key(source) != source_key(first_source):
                        outcome, _ = add_candidate_to_database(database, candidate, source, iso_utc(checked_at))
                        if outcome in event_counts:
                            event_counts[outcome] += 1
                    continue
                outcome, _ = add_candidate_to_database(database, candidate, source, iso_utc(checked_at))
                if outcome in event_counts:
                    event_counts[outcome] += 1
                candidate["database_outcome"] = outcome
                candidate["source"] = source
                issue_candidates[digest] = candidate

        ini_targets = sorted({version for item in issue_candidates.values() for version in inspect_candidate(item["content"])["ini_target_versions"]})
        version_relationships = build_version_relationships(versions, os_metadata, termsrv_versions, ini_targets)
        upsert_issue_record(database, {
            "number": number,
            "title": title,
            "url": issue_url,
            "state": state,
            "labels": labels,
            "created_at": issue.get("created_at"),
            "updated_at": updated,
            "monitor_seen_at": iso_utc(checked_at),
            "issue_classification": issue_classification,
            "failure_signals": failure_signals,
            "triage_notes": triage_notes,
            "duplicate_issue_refs": duplicate_refs,
            "os_metadata": os_metadata,
            "termsrv_versions_explicit": termsrv_versions,
            "ini_target_versions": ini_targets,
            "other_version_identifiers": [v for v in versions if not any(rel["version"] == v and rel["roles"] != ["other_version_identifier"] for rel in version_relationships)],
            "version_relationships": version_relationships,
            "candidate_sha256s": sorted(issue_candidates.keys()),
            "attachment_links": links,
        })

        if failure_signals:
            headline_status = "Reported failure signal — review required"
        elif issue_candidates:
            classes = {database["candidates"][digest].get("review_classification") for digest in issue_candidates}
            if "incomplete" in classes:
                headline_status = "INI candidate found — incomplete configuration warning"
            else:
                headline_status = "INI configuration found — review and verify"
        elif any(".zip" in link.lower() for link in links):
            headline_status = "termsrv / ZIP attachment found — waiting for INI"
        else:
            headline_status = "new issue activity — review"

        lines.extend([
            f"## [#{number} — {title}]({issue_url})",
            f"- Status: **{headline_status}**",
            f"- Issue classification: `{issue_classification}`",
            f"- GitHub state: `{state}`",
            f"- Last updated: `{updated}`",
            f"- Labels: `{label_text}`",
            f"- OS release hint(s) from title: `{', '.join(os_metadata['os_releases']) if os_metadata['os_releases'] else 'not detected'}`",
            f"- OS Build hint(s) from title: `{', '.join(os_metadata['os_build_hints']) if os_metadata['os_build_hints'] else 'not separately stated'}`",
            f"- Windows 10.0 version hint(s) from title (not automatically called OS Build or termsrv): `{', '.join(os_metadata['os_version_hints']) if os_metadata['os_version_hints'] else 'not detected'}`",
            f"- INI section target version(s): `{', '.join(ini_targets) if ini_targets else 'not detected'}`",
            f"- termsrv.dll version explicitly associated in text: `{', '.join(termsrv_versions) if termsrv_versions else 'not explicitly stated'}`",
            f"- Other 10.0 version identifier(s): `{', '.join([v for v in versions if v not in termsrv_versions and v not in ini_targets and v not in os_metadata['os_version_hints']]) or 'not detected'}`",
            f"- Recent comments found: `{len(comments)}`",
        ])
        if failure_signals:
            lines.append("- Reported failure signal(s): " + ", ".join(f"`{signal}`" for signal in failure_signals))
        if triage_notes:
            lines.append("- Triage note(s): " + "; ".join(
                f"@{note['author']} ({', '.join(note['signals'])}): {note['excerpt']}" for note in triage_notes
            ))
        if duplicate_refs:
            refs = ", ".join(f"[#{ref}](https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{ref})" for ref in duplicate_refs)
            lines.append(f"- Related / duplicate issue reference(s): {refs}")
        lines.append("- Version relationships:")
        if version_relationships:
            for relation in version_relationships:
                lines.append(f"  - `{relation['version']}`: {', '.join(relation['roles'])}")
        else:
            lines.append("  - none detected")
        if links:
            lines.append("- Attachment / reference links:")
            lines.extend(f"  - {link}" for link in links)
        else:
            lines.append("- Attachment / reference links: none detected in issue body or recent comments")
        if issue_duplicate_count:
            lines.append(f"- Duplicate INI copies suppressed in this issue: `{issue_duplicate_count}`")
            event_counts["duplicates"] += issue_duplicate_count

        if comments:
            lines.extend(["", "### Recent comments"])
            for comment in comments:
                author = (comment.get("user") or {}).get("login", "unknown")
                created = comment.get("created_at") or "creation date unknown"
                updated_comment = comment.get("updated_at")
                edited = f"; edited `{updated_comment}`" if updated_comment and updated_comment != created else ""
                comment_url = comment.get("html_url") or issue_url
                body = markdown_safe(comment.get("body") or "(empty comment)")
                if len(body) > 1400:
                    body = body[:1400] + "… [comment truncated]"
                lines.extend([f"- **@{author}** — created `{created}`{edited} — [open comment]({comment_url})", "", "  " + body.replace("\n", "\n  ")])

        if issue_candidates:
            lines.extend(["", "### Unique INI candidate(s)"])
            for candidate in issue_candidates.values():
                candidate_counter += 1
                if candidate_counter > MAX_CANDIDATES_IN_SUMMARY:
                    lines.append("Additional candidates are recorded in `compatibility-candidates.json` but omitted from this Summary limit.")
                    break
                digest = candidate["sha256"]
                stored = database["candidates"].get(digest, {})
                candidate_details = inspect_candidate(candidate["content"])
                lines.extend([
                    f"#### Candidate `{digest[:16]}` ({candidate['database_outcome']})",
                    f"- SHA-256: `{digest}`",
                    f"- Review classification: `{stored.get('review_classification', 'unverified')}`",
                    f"- INI completeness: `{stored.get('completeness', 'unknown')}`",
                    f"- INI section(s): `{', '.join(candidate_details['sections']) if candidate_details['sections'] else 'none detected'}`",
                ])
                if stored.get("review_flags"):
                    lines.append("- Review flag(s): " + ", ".join(f"`{flag}`" for flag in stored["review_flags"]))
                if stored.get("reported_failure_signals"):
                    lines.append("- Related failure signal(s): " + ", ".join(f"`{flag}`" for flag in stored["reported_failure_signals"]))
                for stored_source in stored.get("sources", []):
                    lines.append(f"- Source: {format_candidate_source(stored_source)}")
                if candidate_details["warnings"]:
                    lines.append("- Parser warning(s): " + " ".join(candidate_details["warnings"]))
                lines.extend(["", "```ini", candidate["content"][:MAX_CANDIDATE_LENGTH], "```", ""])
        lines.append("")

    issue_class_counts = {}
    for record in database.get("issues", {}).values():
        key = record.get("issue_classification", "unknown")
        issue_class_counts[key] = issue_class_counts.get(key, 0) + 1
    candidate_class_counts = {}
    for record in database["candidates"].values():
        key = record.get("review_classification", "unverified")
        candidate_class_counts[key] = candidate_class_counts.get(key, 0) + 1

    lines.extend([
        "---",
        "## Candidate database changes",
        f"- New unique candidates: `{event_counts['new']}`",
        f"- Existing candidates with a new source: `{event_counts['source-added']}`",
        f"- Already-recorded candidate/source pairs: `{event_counts['existing']}`",
        f"- Duplicate copies suppressed in this scan: `{event_counts['duplicates']}`",
        f"- Total unique candidates recorded: `{len(database['candidates'])}`",
        f"- Issue records stored: `{len(database.get('issues', {}))}`",
        "",
        "### Candidate review classifications",
    ])
    for key, count in sorted(candidate_class_counts.items()):
        lines.append(f"- `{key}`: `{count}`")
    lines.extend(["", "### Issue classifications"])
    for key, count in sorted(issue_class_counts.items()):
        lines.append(f"- `{key}`: `{count}`")
    lines.extend([
        "",
        "## Database and safety",
        "- Unique INI candidates are stored once by canonical-content SHA-256; additional source links are attached to the same record.",
        "- Candidate `review_classification` is triage metadata. `reported_failure` means an issue contains a failure signal; it does not prove the INI caused it.",
        "- Issue labels such as `duplicate` or `invalid` are recorded separately; they do not prove an INI is valid or invalid.",
        "- `termsrv.dll` is only assigned when the text explicitly associates a version with termsrv; a title-only 10.0.x.x value remains a Windows title version hint.",
        "- Source creation time is shown separately from last-edited time; Issue `updated_at` is not treated as the actual posting time of an INI.",
        "- No candidate is automatically promoted to `verified` or `published`.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    # Read the production baseline before making API calls, so a missing file
    # fails fast and does not consume GitHub API quota.
    if not PRODUCTION_INI_PATH.is_file():
        raise RuntimeError(
            f"Production baseline {PRODUCTION_INI_PATH} was not found in the checked-out repository. "
            "The comparison step cannot continue without the real production rdpwrap.ini."
        )
    production_text = PRODUCTION_INI_PATH.read_text(encoding="utf-8-sig")
    baseline_commit = os.environ.get("GITHUB_SHA")

    print("Checking authenticated GitHub API access...")
    check_api_authentication()
    started_at = utc_now()
    since, _first_run, scan_type = load_since()
    since_text = iso_utc(since)
    database = load_database()
    event_counts = {"new": 0, "source-added": 0, "existing": 0, "duplicates": 0}

    issues_url = f"{API_ROOT}/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues"
    issues = get_pages(issues_url, {
        "state": "all",
        "sort": "updated",
        "direction": "desc",
        "since": since_text,
    })
    report = build_report(issues, since, scan_type, database, event_counts)

    # Compare every stored upstream Candidate against the Production rdpwrap.ini
    # from this exact checked-out repository commit. Do not fetch a second copy
    # from raw.githubusercontent.com and do not modify the production file.
    comparison = build_production_comparison(database, production_text, baseline_commit)
    comparison_report = build_comparison_report(comparison)
    report = report.rstrip() + "\n\n" + comparison_report
    atomic_write_json(COMPARISON_PATH, comparison)

    checked_at_text = iso_utc(utc_now())
    database["schema_version"] = 2
    database["updated_at"] = checked_at_text
    database["candidates"] = dict(sorted(
        database["candidates"].items(),
        key=lambda item: item[1].get("first_seen", ""),
        reverse=True,
    ))
    database["issues"] = dict(sorted(
        database.get("issues", {}).items(),
        key=lambda item: int(item[0]),
        reverse=True,
    ))
    atomic_write_json(DATABASE_PATH, database)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary_file:
            summary_file.write(report)
    print(report)
    # Record scan start rather than finish so activity during the run is picked up next time.
    atomic_write_json(STATE_PATH, {"last_checked": iso_utc(started_at)})
    print(f"Saved {len(database['candidates'])} unique INI candidate(s) and {len(database['issues'])} issue record(s).")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"::error::{exc}", file=sys.stderr)
        raise SystemExit(1)
