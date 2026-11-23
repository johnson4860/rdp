#!/usr/bin/env python3
"""RDP Wrapper upstream issue monitor v1.1.

Collects public upstream issue/comment activity and extracts INI candidates.
It never downloads, installs, or publishes an INI to the production location.
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
PER_PAGE = 100
MAX_CANDIDATES_IN_SUMMARY = 50
MAX_CANDIDATE_LENGTH = 16000

INI_MARKERS = (
    "SingleUserPatch",
    "DefPolicyPatch",
    "LocalOnlyPatch",
    "SLInitOffset",
    "SLInitHook",
)

VERSION_RE = re.compile(r"(?<![\d.])10\.0\.\d{4,5}\.\d{1,7}(?!\d)")
SECTION_RE = re.compile(r"^\s*\[([^\]\r\n]+)\]\s*$")
KEY_RE = re.compile(r"^\s*[A-Za-z_][A-Za-z0-9_.-]*\s*=")
FENCE_RE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)
URL_RE = re.compile(r"https?://[^\s<>\]\[()\"']+", re.IGNORECASE)


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
    """Backfill once when the v1.1 candidate DB is first created.

    This matters when upgrading v1.0: monitor-state.json already exists, but the
    new candidate database does not. A 30-day backfill imports recent findings.
    """
    now = utc_now()
    if not DATABASE_PATH.exists():
        return now - timedelta(days=30), True, "initial 30-day candidate database backfill"
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
            "schema_version": 1,
            "upstream": f"{UPSTREAM_OWNER}/{UPSTREAM_REPO}",
            "updated_at": None,
            "candidates": {},
        }
    try:
        data = json.loads(DATABASE_PATH.read_text(encoding="utf-8"))
        if data.get("schema_version") != 1 or not isinstance(data.get("candidates"), dict):
            raise ValueError("unsupported candidate database schema")
        return data
    except (OSError, ValueError, TypeError) as exc:
        raise RuntimeError(f"Cannot read {DATABASE_PATH}: {exc}") from exc


def api_get(url: str):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "johnson4860-rdp-update-monitor/1.1",
    }
    # GitHub Actions supplies this token automatically. No PAT/secret setup is needed.
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        if exc.code == 403:
            remaining = exc.headers.get("X-RateLimit-Remaining", "unknown")
            reset = exc.headers.get("X-RateLimit-Reset", "unknown")
            raise RuntimeError(
                f"GitHub API returned 403 (rate-limit remaining={remaining}, reset={reset}): {detail}"
            ) from exc
        raise RuntimeError(f"GitHub API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Unable to reach GitHub API: {exc}") from exc


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
    """Convert flattened GitHub text to readable INI lines without inventing keys."""
    text = (raw or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    # Some issue bodies paste the complete INI as one long line. Split only at
    # recognizable section headers and key=value assignments.
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
        # A trailing backslash is sometimes used as a Markdown hard line break.
        # Remove it only when the next line is clearly another INI entry.
        if line.endswith("\\") and index + 1 < len(lines):
            next_line = lines[index + 1].strip().lstrip(">").lstrip()
            if SECTION_RE.match(next_line) or KEY_RE.match(next_line):
                line = line[:-1].rstrip()
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def canonical_candidate(text: str) -> str:
    """Canonical whitespace form for deduplication; original readable form is stored."""
    return "\n".join(line.strip() for line in text.replace("\r", "").split("\n") if line.strip())


def candidate_hash(text: str) -> str:
    canonical = canonical_candidate(text)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def extract_unfenced_candidate(text: str) -> list[str]:
    """Extract an un-fenced INI segment and stop when ordinary prose resumes."""
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
    """Extract fenced and plain-text candidates, deduplicated within the source."""
    source = text or ""
    raw_blocks = []
    fenced_matches = list(FENCE_RE.finditer(source))
    for match in fenced_matches:
        block = format_ini_block(match.group(1))
        if block and is_ini_text(block):
            raw_blocks.append(block)

    # Also inspect text outside code fences; this catches plain-text comments.
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
    ini_targets = set()
    main_targets = set()
    slinit_targets = set()
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
    }


def extract_urls(text: str) -> list[str]:
    found = []
    for raw in URL_RE.findall(text or ""):
        link = raw.rstrip(".,;:!?")
        low = link.lower()
        if (
            ".zip" in low
            or ".ini" in low
            or "user-attachments" in low
            or "gist.github.com" in low
            or "pastebin" in low
        ) and link not in found:
            found.append(link)
    return found


def extract_version_strings(text: str) -> list[str]:
    return sorted(set(VERSION_RE.findall(text or "")))


def extract_os_metadata(title: str) -> dict:
    title = title or ""
    releases = []
    for match in re.finditer(r"\bWindows\s+(10|11)\b(?:\s+(?:Pro|Home|Enterprise|Education|Workstation)\b)?(?:\s+(22H2|23H2|24H2|25H2|26H2))?", title, re.IGNORECASE):
        os_name = f"Windows {match.group(1)}"
        if match.group(2):
            os_name += f" {match.group(2).upper()}"
        if os_name not in releases:
            releases.append(os_name)

    build_hints = set()
    marker_pattern = re.compile(
        r"\b(?:build|compilation|compilacion|compilación)\s*(?:number|no\.?|#|:)?\s*(\d{4,5}\.\d{3,7})\b",
        re.IGNORECASE,
    )
    build_hints.update(marker_pattern.findall(title))
    # Some issue titles omit the word 'Build' but show the Windows version first.
    windows_pattern = re.compile(
        r"\bWindows\s+(?:10|11)\b.{0,120}?(?<![\d.])(\d{4,5}\.\d{3,7})(?!\d)",
        re.IGNORECASE,
    )
    build_hints.update(windows_pattern.findall(title))

    return {"os_releases": releases, "os_build_hints": sorted(build_hints)}


def extract_explicit_termsrv_versions(text: str) -> list[str]:
    """Only classify a version as termsrv when the text explicitly associates it."""
    found = set()
    version = r"10\.0\.\d{4,5}\.\d{1,7}"
    patterns = (
        rf"termsrv(?:\.dll)?[^\n]{{0,100}}?({version})",
        rf"({version})[^\n]{{0,100}}?termsrv(?:\.dll)?",
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


def source_key(source: dict) -> str:
    return source.get("source_url") or f"{source.get('source_type')}:{source.get('issue_number')}"


def add_candidate_to_database(database: dict, candidate: dict, source: dict, now_text: str) -> tuple[str, bool]:
    digest = candidate["sha256"]
    existing = database["candidates"].get(digest)
    new_candidate = existing is None
    if existing is None:
        details = inspect_candidate(candidate["content"])
        existing = {
            "candidate_id": digest[:16],
            "sha256": digest,
            "content": candidate["content"],
            "status": "unverified",
            "first_seen": now_text,
            "last_seen": now_text,
            "ini_target_versions": details["ini_target_versions"],
            "main_section_versions": details["main_section_versions"],
            "slinit_section_versions": details["slinit_section_versions"],
            "sections": details["sections"],
            "warnings": details["warnings"],
            "sources": [],
        }
        database["candidates"][digest] = existing
    else:
        existing["last_seen"] = now_text

    known_source_keys = {source_key(item) for item in existing.get("sources", [])}
    added_source = source_key(source) not in known_source_keys
    if added_source:
        existing.setdefault("sources", []).append(source)
    return ("new" if new_candidate else ("source-added" if added_source else "existing"), new_candidate)


def markdown_safe(value: str) -> str:
    return (value or "").replace("\r", "").strip()


def get_recent_comments(issue_number: int, since_text: str) -> list[dict]:
    url = f"{API_ROOT}/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{issue_number}/comments"
    return get_pages(url, {"since": since_text, "sort": "updated", "direction": "asc"})


def format_candidate_source(source: dict) -> str:
    label = "Issue description" if source.get("source_type") == "issue_body" else f"Comment by @{source.get('author', 'unknown')}"
    when = source.get("updated_at") or source.get("created_at") or "date unknown"
    link = source.get("source_url") or source.get("issue_url") or ""
    return f"{label} — `{when}` — {link}"


def build_report(issues: list[dict], since: datetime, scan_type: str, database: dict, event_counts: dict) -> str:
    checked_at = utc_now()
    lines = [
        "# RDP Wrapper upstream monitor v1.1",
        "",
        f"- Checked at (UTC): `{iso_utc(checked_at)}`",
        f"- Upstream: [`{UPSTREAM_OWNER}/{UPSTREAM_REPO}`](https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO})",
        f"- Activity window starts: `{iso_utc(since)}`",
        f"- Scan type: `{scan_type}`",
        "- Collection only: the monitor does **not** download, install, or publish INI files.",
        "",
        "## Candidate database changes",
        "Candidate totals are calculated after processing all updated issues below.",
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
        texts = [issue_body] + [comment.get("body") or "" for comment in comments]
        all_text = "\n\n".join([title] + texts)
        versions = extract_version_strings(all_text)
        termsrv_versions = extract_explicit_termsrv_versions(all_text)
        links = extract_urls(all_text)
        duplicate_refs = duplicate_issue_references(all_text)

        source_payloads = []
        if issue_body.strip():
            source_payloads.append((issue_body, {
                "issue_number": number,
                "issue_title": title,
                "issue_url": issue_url,
                "source_type": "issue_body",
                "source_url": issue_url,
                "author": (issue.get("user") or {}).get("login", "unknown"),
                "created_at": issue.get("created_at"),
                "updated_at": issue.get("updated_at"),
                "issue_state": state,
                "labels": labels,
            }))
        for comment in comments:
            source_payloads.append((comment.get("body") or "", {
                "issue_number": number,
                "issue_title": title,
                "issue_url": issue_url,
                "source_type": "comment",
                "source_url": comment.get("html_url") or issue_url,
                "author": (comment.get("user") or {}).get("login", "unknown"),
                "created_at": comment.get("created_at"),
                "updated_at": comment.get("updated_at"),
                "issue_state": state,
                "labels": labels,
            }))

        issue_candidates = {}
        issue_duplicate_count = 0
        for source_text, source in source_payloads:
            for candidate in extract_ini_candidates(source_text):
                issue_duplicate_count += candidate["duplicate_occurrences"]
                digest = candidate["sha256"]
                if digest in issue_candidates:
                    issue_duplicate_count += 1
                    # Add a second Issue/Comment link when the identical config
                    # came from a distinct source, but do not count repeated
                    # copies inside the same source as extra database events.
                    first_source = issue_candidates[digest]["source"]
                    if source_key(source) != source_key(first_source):
                        outcome, _ = add_candidate_to_database(database, candidate, source, iso_utc(checked_at))
                        if outcome in event_counts:
                            event_counts[outcome] += 1
                    continue
                outcome, _ = add_candidate_to_database(database, candidate, source, iso_utc(checked_at))
                if outcome in event_counts:
                    event_counts[outcome] += 1
                issue_candidates[digest] = candidate
                # Keep source-level outcome for this issue's compact report.
                candidate["database_outcome"] = outcome
                candidate["source"] = source

        details = []
        status_bits = []
        if issue_candidates:
            status_bits.append("INI configuration found — review and verify")
        elif any(".zip" in link.lower() for link in links):
            status_bits.append("termsrv / ZIP attachment found — waiting for INI")
        else:
            status_bits.append("new issue activity — review")

        lines.extend([
            f"## [#{number} — {title}]({issue_url})",
            f"- Status: **{status_bits[0]}**",
            f"- GitHub state: `{state}`",
            f"- Last updated: `{updated}`",
            f"- Labels: `{label_text}`",
            f"- OS release hint(s) from title: `{', '.join(os_metadata['os_releases']) if os_metadata['os_releases'] else 'not detected'}`",
            f"- OS Build hint(s) from title: `{', '.join(os_metadata['os_build_hints']) if os_metadata['os_build_hints'] else 'not separately stated'}`",
            f"- INI section target version(s): `{', '.join(sorted({v for c in issue_candidates.values() for v in inspect_candidate(c['content'])['ini_target_versions']})) or 'not detected'}`",
            f"- termsrv.dll version explicitly associated in text: `{', '.join(termsrv_versions) if termsrv_versions else 'not explicitly stated'}`",
            f"- Other 10.0 version identifier(s): `{', '.join(versions) if versions else 'not detected'}`",
            f"- Recent comments found: `{len(comments)}`",
        ])
        if duplicate_refs:
            refs = ", ".join(f"[#{ref}](https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{ref})" for ref in duplicate_refs)
            lines.append(f"- Related / duplicate issue reference(s): {refs}")
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
                date = comment.get("updated_at") or comment.get("created_at") or "unknown"
                comment_url = comment.get("html_url") or issue_url
                body = markdown_safe(comment.get("body") or "(empty comment)")
                if len(body) > 1400:
                    body = body[:1400] + "… [comment truncated]"
                lines.extend([f"- **@{author}** — `{date}` — [open comment]({comment_url})", "", "  " + body.replace("\n", "\n  ")])

        if issue_candidates:
            lines.extend(["", "### Unique INI candidate(s) — not yet verified"])
            for candidate in issue_candidates.values():
                candidate_counter += 1
                if candidate_counter > MAX_CANDIDATES_IN_SUMMARY:
                    lines.append("Additional candidates are recorded in `compatibility-candidates.json` but omitted from this Summary limit.")
                    break
                digest = candidate["sha256"]
                candidate_details = inspect_candidate(candidate["content"])
                lines.extend([
                    f"#### Candidate `{digest[:16]}` ({candidate['database_outcome']})",
                    f"- SHA-256: `{digest}`",
                    f"- INI section(s): `{', '.join(candidate_details['sections']) if candidate_details['sections'] else 'none detected'}`",
                ])
                stored_record = database["candidates"].get(digest, {})
                for stored_source in stored_record.get("sources", []):
                    lines.append(f"- Source: {format_candidate_source(stored_source)}")
                if candidate_details["warnings"]:
                    lines.append("- Parser warning(s): " + " ".join(candidate_details["warnings"]))
                lines.extend(["", "```ini", candidate["content"][:MAX_CANDIDATE_LENGTH], "```", ""])

        lines.append("")

    lines.extend([
        "---",
        "## Candidate database totals",
        f"- New unique candidates: `{event_counts['new']}`",
        f"- Existing candidates with a new source: `{event_counts['source-added']}`",
        f"- Already-recorded candidate/source pairs: `{event_counts['existing']}`",
        f"- Duplicate copies suppressed within this scan: `{event_counts['duplicates']}`",
        f"- Total unique candidates recorded: `{len(database['candidates'])}`",
        "",
        "## Database and safety",
        "- Unique INI candidates and their sources are persisted in `compatibility-candidates.json`.",
        "- Identical INI contents are stored once by SHA-256; additional source links are attached to that record.",
        "- Candidate status remains `unverified`; this monitor does not infer that a closed issue or a comment proves compatibility.",
        "- Verify the exact OS build and `termsrv.dll` file version before considering a candidate for production.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
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
    checked_at_text = iso_utc(utc_now())
    database["updated_at"] = checked_at_text
    database["candidates"] = dict(sorted(
        database["candidates"].items(),
        key=lambda item: item[1].get("first_seen", ""),
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
    print(f"Saved {len(database['candidates'])} unique INI candidate(s) to {DATABASE_PATH}.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"::error::{exc}", file=sys.stderr)
        raise SystemExit(1)
