#!/usr/bin/env python3
"""Monitor new activity in stascorp/rdpwrap without changing rdpwrap.ini."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

UPSTREAM_OWNER = "stascorp"
UPSTREAM_REPO = "rdpwrap"
API_ROOT = "https://api.github.com"
STATE_PATH = Path("monitor-state.json")
PER_PAGE = 100

INI_MARKERS = (
    "SingleUserPatch",
    "DefPolicyPatch",
    "LocalOnlyPatch",
    "SLInitOffset",
    "SLInitHook",
)

VERSION_RE = re.compile(r"(?<!\d)10\.0\.\d{4,5}\.\d{1,7}(?!\d)")
URL_RE = re.compile(r"https?://[^\s<>\]\[()\"']+", re.IGNORECASE)
FENCE_RE = re.compile(r"```[^\n`]*\n(.*?)```", re.DOTALL)


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_since() -> tuple[datetime, bool]:
    """First run scans the previous 7 days; later runs use a saved checkpoint."""
    if not STATE_PATH.exists():
        return utc_now() - timedelta(days=7), True

    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        checkpoint = parse_time(state["last_checked"])
        # Small overlap protects against timing boundaries between scheduled runs.
        return checkpoint - timedelta(minutes=2), False
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise RuntimeError(f"Cannot read {STATE_PATH}: {exc}") from exc


def api_get(url: str):
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "johnson4860-rdp-update-monitor",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        if exc.code == 403:
            remaining = exc.headers.get("X-RateLimit-Remaining", "unknown")
            reset = exc.headers.get("X-RateLimit-Reset", "unknown")
            raise RuntimeError(
                f"GitHub API returned 403 (rate-limit remaining={remaining}, reset={reset}): {detail}"
            ) from exc
        raise RuntimeError(f"GitHub API returned HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise RuntimeError(f"Unable to reach GitHub API: {exc}") from exc


def get_pages(url: str, params: dict):
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
            break
        page += 1
    return results


def is_ini_text(text: str) -> bool:
    return any(marker.lower() in text.lower() for marker in INI_MARKERS)


def extract_ini_blocks(text: str) -> list[str]:
    blocks = []
    for match in FENCE_RE.finditer(text or ""):
        candidate = match.group(1).strip()
        if candidate and is_ini_text(candidate):
            blocks.append(candidate)

    # Also catch INI pasted as plain text without Markdown fences.
    if not blocks and is_ini_text(text or ""):
        lines = (text or "").splitlines()
        start = next(
            (index for index, line in enumerate(lines) if "SingleUserPatch" in line or "[10.0." in line),
            None,
        )
        if start is not None:
            candidate = "\n".join(lines[start:]).strip()
            if candidate:
                blocks.append(candidate[:12000])
    return blocks


def extract_links(text: str) -> list[str]:
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


def extract_versions(text: str) -> list[str]:
    return sorted(set(VERSION_RE.findall(text or "")))


def markdown_safe(value: str) -> str:
    return (value or "").replace("\r", "").strip()


def get_recent_comments(issue_number: int, since_text: str):
    url = f"{API_ROOT}/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{issue_number}/comments"
    return get_pages(url, {"since": since_text, "sort": "updated", "direction": "asc"})


def build_report(issues: list[dict], since: datetime, first_run: bool) -> str:
    checked_at = utc_now()
    lines = [
        "# RDP Wrapper upstream monitor",
        "",
        f"- Checked at (UTC): `{iso_utc(checked_at)}`",
        f"- Upstream: [`{UPSTREAM_OWNER}/{UPSTREAM_REPO}`](https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO})",
        f"- Activity window starts: `{iso_utc(since)}`",
        f"- Scan type: `{'initial 7-day scan' if first_run else 'since last checkpoint'}`",
        "- This monitor only collects information. It does **not** download, install, or publish INI files.",
        "",
    ]

    real_issues = [item for item in issues if "pull_request" not in item]
    real_issues.sort(key=lambda item: item.get("updated_at", ""), reverse=True)

    if not real_issues:
        lines.extend(["## Result", "No new or updated upstream issues were found in this scan."])
        return "\n".join(lines) + "\n"

    lines.extend([f"## Result: {len(real_issues)} issue(s) updated", ""])

    for issue in real_issues:
        number = issue.get("number")
        title = markdown_safe(issue.get("title", "(untitled)"))
        issue_url = issue.get("html_url", f"https://github.com/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues/{number}")
        state = issue.get("state", "unknown")
        updated = issue.get("updated_at", "unknown")
        labels = ", ".join(label.get("name", "") for label in issue.get("labels", [])) or "none"
        issue_body = issue.get("body") or ""

        comments = []
        if issue.get("comments", 0):
            comments = get_recent_comments(number, iso_utc(since))

        texts = [issue_body]
        texts.extend(comment.get("body") or "" for comment in comments)
        all_text = "\n\n".join(texts)
        versions = extract_versions(title + "\n" + all_text)
        links = extract_links(all_text)
        ini_blocks = []
        for source_text in texts:
            ini_blocks.extend(extract_ini_blocks(source_text))

        has_termsrv_zip = any(".zip" in link.lower() for link in links)
        if ini_blocks:
            status = "INI configuration found — review and verify"
        elif has_termsrv_zip:
            status = "termsrv / ZIP attachment found — waiting for INI"
        else:
            status = "new issue activity — review"

        lines.extend([
            f"## [#{number} — {title}]({issue_url})",
            f"- Status: **{status}**",
            f"- GitHub state: `{state}`",
            f"- Last updated: `{updated}`",
            f"- Labels: `{labels}`",
            f"- Windows/termsrv version(s): `{', '.join(versions) if versions else 'not detected'}`",
            f"- Recent comments found: `{len(comments)}`",
        ])

        if links:
            lines.append("- Attachment / reference links:")
            for link in links:
                lines.append(f"  - {link}")
        else:
            lines.append("- Attachment / reference links: none detected in recent content")

        if comments:
            lines.append("- Recent comments:")
            for comment in comments:
                author = (comment.get("user") or {}).get("login", "unknown")
                date = comment.get("updated_at") or comment.get("created_at") or "unknown"
                body = markdown_safe(comment.get("body") or "(empty comment)")
                if len(body) > 1800:
                    body = body[:1800] + "… [comment truncated]"
                lines.extend([f"  - **{author}** — `{date}`", "", "    " + body.replace("\n", "\n    ")])

        if ini_blocks:
            lines.extend(["", "### INI candidate(s) — not yet verified"])
            for index, block in enumerate(ini_blocks, start=1):
                lines.extend([f"**Candidate {index}**", "```ini", block, "```", ""])

        lines.append("")

    lines.extend([
        "---",
        "## Next action",
        "Review the linked upstream issue and verify any INI candidate against the exact `termsrv.dll` build before publishing it to the production `rdpwrap.ini`.",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    started_at = utc_now()
    since, first_run = load_since()
    since_text = iso_utc(since)

    issues_url = f"{API_ROOT}/repos/{UPSTREAM_OWNER}/{UPSTREAM_REPO}/issues"
    issues = get_pages(
        issues_url,
        {
            "state": "all",
            "sort": "updated",
            "direction": "desc",
            "since": since_text,
        },
    )

    report = build_report(issues, since, first_run)

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as summary_file:
            summary_file.write(report)
    print(report)

    # Save the scan start time, not its finish time. Any updates arriving while
    # this scan is running will therefore be picked up on the next run.
    STATE_PATH.write_text(
        json.dumps({"last_checked": iso_utc(started_at)}, indent=2) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # Fail the job visibly; do not advance the checkpoint.
        print(f"::error::{exc}", file=sys.stderr)
        raise SystemExit(1)
