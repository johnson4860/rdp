import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "rdp_issue_monitor.py"
SPEC = importlib.util.spec_from_file_location("rdp_issue_monitor", SCRIPT)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


INI_28000 = """[10.0.28000.3614]
SingleUserPatch.x64=1
SingleUserOffset.x64=2CE31
SingleUserCode.x64=mov_eax_1_nop_2
DefPolicyPatch.x64=1
DefPolicyOffset.x64=AD1CD
DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp
LocalOnlyPatch.x64=1
LocalOnlyOffset.x64=A5207
LocalOnlyCode.x64=jmpshort
SLInitHook.x64=1
SLInitOffset.x64=C0988
SLInitFunc.x64=New_CSLQuery_Initialize

[10.0.28000.3614-SLInit]
bServerSku.x64=13BE1C
bRemoteConnAllowed.x64=13BE34
bFUSEnabled.x64=13BE44
bAppServerAllowed.x64=13BE28
bMultimonAllowed.x64=13BE38
lMaxUserSessions.x64=13BE20
ulMaxDebugSessions.x64=13BE40
bInitialized.x64=13BE18"""

INI_26100_INCOMPLETE = """SingleUserPatch.x64=1
SingleUserOffset.x64=AC67B
SingleUserCode.x64=mov_eax_1_nop_2
DefPolicyPatch.x64=1
DefPolicyOffset.x64=A981D
DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp
LocalOnlyPatch.x64=1
LocalOnlyOffset.x64=9FB01
LocalOnlyCode.x64=jmpshort
SLInitHook.x64=1
SLInitOffset.x64=C0838
SLInitFunc.x64=New_CSLQuery_Initialize
[10.0.26100.10068-SLInit]
bServerSku.x64=135344
bRemoteConnAllowed.x64=13535C
bFUSEnabled.x64=13536C
bAppServerAllowed.x64=135350
bMultimonAllowed.x64=135360
lMaxUserSessions.x64=135348
ulMaxDebugSessions.x64=135368
bInitialized.x64=135340"""


class IniParserTests(unittest.TestCase):
    def test_issue_4564_complete_two_section_candidate(self):
        candidate = monitor.extract_ini_candidates(INI_28000)[0]
        details = monitor.inspect_candidate(candidate["content"])
        self.assertEqual(details["ini_target_versions"], ["10.0.28000.3614"])
        self.assertEqual(len(details["sections"]), 2)
        self.assertTrue(details["is_complete"])
        self.assertEqual(details["warnings"], [])

    def test_issue_4567_missing_primary_section_is_incomplete(self):
        candidate = monitor.extract_ini_candidates(INI_26100_INCOMPLETE)[0]
        details = monitor.inspect_candidate(candidate["content"])
        self.assertEqual(details["ini_target_versions"], ["10.0.26100.10068"])
        self.assertEqual(details["main_section_versions"], [])
        self.assertEqual(details["slinit_section_versions"], ["10.0.26100.10068"])
        self.assertFalse(details["is_complete"])
        self.assertTrue(any("main" in warning.lower() for warning in details["warnings"]))
        self.assertNotIn("[10.0.26100.10068]", candidate["content"])

    def test_flattened_ini_keeps_section_headers_and_line_breaks(self):
        flat = "[10.0.28000.3614] SingleUserPatch.x64=1 DefPolicyPatch.x64=1 LocalOnlyPatch.x64=1 SLInitHook.x64=1 [10.0.28000.3614-SLInit] bServerSku.x64=13BE1C"
        formatted = monitor.format_ini_block(flat)
        self.assertIn("\nSingleUserPatch.x64=1", formatted)
        self.assertIn("\n[10.0.28000.3614-SLInit]\n", formatted)

    def test_duplicate_ini_blocks_are_suppressed_by_hash(self):
        text = f"```ini\n{INI_28000}\n```\n\n```ini\n{INI_28000}\n```"
        candidates = monitor.extract_ini_candidates(text)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["duplicate_occurrences"], 1)


class VersionIntelligenceTests(unittest.TestCase):
    def test_issue_4569_distinguishes_os_build_and_other_version(self):
        metadata = monitor.extract_os_metadata("10.0.19041.7811 - Windows 10 Pro 22H2 19045.7846 x86")
        self.assertEqual(metadata["os_releases"], ["Windows 10 22H2"])
        self.assertEqual(metadata["os_build_hints"], ["19045.7846"])
        self.assertEqual(metadata["os_version_hints"], [])

    def test_issue_4568_keeps_10_0_title_version_separate_from_os_build(self):
        metadata = monitor.extract_os_metadata("Windows 11 26H2 (10.0.26100.10021) - Not Supported")
        self.assertEqual(metadata["os_releases"], ["Windows 11 26H2"])
        self.assertEqual(metadata["os_build_hints"], [])
        self.assertEqual(metadata["os_version_hints"], ["10.0.26100.10021"])

    def test_issue_4567_explicit_compilation_is_os_build_hint(self):
        metadata = monitor.extract_os_metadata("Codigo para rdpwrap.ini compilacion 26200.10075")
        self.assertEqual(metadata["os_build_hints"], ["26200.10075"])
        self.assertEqual(metadata["os_version_hints"], [])


    def test_issue_4564_title_version_and_ini_target_are_two_roles(self):
        metadata = monitor.extract_os_metadata("Windows 11 26H2 10.0.28000.3614 - Not supported")
        rels = monitor.build_version_relationships(
            ["10.0.28000.3614"], metadata, [], ["10.0.28000.3614"]
        )
        self.assertEqual(rels[0]["version"], "10.0.28000.3614")
        self.assertEqual(
            rels[0]["roles"],
            ["ini_section_target", "os_version_hint_from_title"],
        )

    def test_termsrv_version_requires_explicit_association(self):
        self.assertEqual(
            monitor.extract_explicit_termsrv_versions("termsrv.dll version: 10.0.26100.10068"),
            ["10.0.26100.10068"],
        )
        self.assertEqual(
            monitor.extract_explicit_termsrv_versions("Windows 11 (10.0.26100.10021)"),
            [],
        )

    def test_version_relationships_can_assign_multiple_roles(self):
        metadata = {"os_build_hints": ["26200.10075"], "os_version_hints": []}
        relationships = monitor.build_version_relationships(
            ["10.0.26100.10068"], metadata,
            ["10.0.26100.10068"], ["10.0.26100.10068"],
        )
        self.assertEqual(relationships[0]["version"], "10.0.26100.10068")
        self.assertEqual(
            relationships[0]["roles"],
            ["ini_section_target", "termsrv_dll_explicit"],
        )
        self.assertEqual(relationships[1]["roles"], ["os_build_hint"])


class IssueClassificationTests(unittest.TestCase):
    def test_issue_4566_detects_failure_report_and_triage_note(self):
        title = "Remote Desktop Service keeps crashing after adding patch codes for 10.0.26100.10068"
        self.assertIn("service_crash_report", monitor.detect_failure_signals(title))
        self.assertIn("patch_failure_report", monitor.detect_failure_signals(title))
        comments = [{
            "body": "Not RDP Wrapper bug. Please contact Telegram support chat for help.",
            "user": {"login": "binarymaster"},
            "created_at": "2026-11-21T08:34:17Z",
            "html_url": "https://github.com/stascorp/rdpwrap/issues/4566#issuecomment-1",
        }]
        notes = monitor.detect_triage_notes(comments)
        self.assertEqual(len(notes), 1)
        self.assertIn("not_rdp_wrapper_bug", notes[0]["signals"])

    def test_not_supported_title_is_not_misclassified_as_failure(self):
        title = "Windows 11 26H2 (10.0.26100.10021) - Not Supported"
        self.assertEqual(monitor.detect_failure_signals(title), [])
        self.assertEqual(monitor.classify_issue(["add build"], [], []), "compatibility_request")
        self.assertEqual(monitor.classify_issue([], [], [], title), "compatibility_request")

    def test_duplicate_and_invalid_labels_are_separate_from_failure(self):
        self.assertEqual(monitor.classify_issue(["duplicate"], [4563], []), "duplicate_issue")
        self.assertEqual(monitor.classify_issue(["invalid"], [], []), "maintainer_labeled_invalid")
        self.assertEqual(monitor.classify_issue(["invalid"], [], ["service_crash_report"]), "reported_failure")

    def test_candidate_gets_reported_failure_classification(self):
        candidate = monitor.extract_ini_candidates(INI_28000)[0]
        database = {"schema_version": 2, "upstream": "stascorp/rdpwrap", "updated_at": None, "candidates": {}, "issues": {}}
        source = {
            "source_type": "issue_body",
            "source_url": "https://github.com/stascorp/rdpwrap/issues/4566",
            "issue_number": 4566,
            "failure_signals": ["service_crash_report"],
            "issue_classification": "reported_failure",
            "labels": ["invalid"],
            "triage_notes": [{"signals": ["not_rdp_wrapper_bug"]}],
        }
        monitor.add_candidate_to_database(database, candidate, source, "2026-11-23T00:00:00Z")
        stored = next(iter(database["candidates"].values()))
        self.assertEqual(stored["review_classification"], "reported_failure")
        self.assertIn("reported_failure_context", stored["review_flags"])
        self.assertIn("source_issue_labeled_invalid", stored["review_flags"])
        self.assertIn("maintainer_or_triage_note_present", stored["review_flags"])


class DatabaseTests(unittest.TestCase):
    def test_same_candidate_merges_sources_and_updates_existing_source(self):
        candidate = monitor.extract_ini_candidates(INI_28000)[0]
        database = {"schema_version": 2, "upstream": "stascorp/rdpwrap", "updated_at": None, "candidates": {}, "issues": {}}
        source = {"source_type": "issue_body", "source_url": "https://github.com/stascorp/rdpwrap/issues/1", "created_at": "2026-11-20T00:00:00Z", "updated_at": "2026-11-20T00:00:00Z", "failure_signals": []}
        self.assertEqual(monitor.add_candidate_to_database(database, candidate, source, "2026-11-23T00:00:00Z")[0], "new")
        edited_source = {**source, "updated_at": "2026-11-23T00:00:00Z", "labels": ["add build"]}
        self.assertEqual(monitor.add_candidate_to_database(database, candidate, edited_source, "2026-11-23T00:01:00Z")[0], "existing")
        second_source = {"source_type": "comment", "source_url": "https://github.com/stascorp/rdpwrap/issues/1#issuecomment-2", "created_at": "2026-11-23T00:02:00Z", "failure_signals": []}
        self.assertEqual(monitor.add_candidate_to_database(database, candidate, second_source, "2026-11-23T00:02:00Z")[0], "source-added")
        stored = next(iter(database["candidates"].values()))
        self.assertEqual(len(stored["sources"]), 2)
        self.assertEqual(stored["sources"][0]["updated_at"], "2026-11-23T00:00:00Z")

    def test_v1_database_migrates_without_losing_candidate(self):
        candidate = monitor.extract_ini_candidates(INI_28000)[0]
        old_db = {
            "schema_version": 1,
            "upstream": "stascorp/rdpwrap",
            "updated_at": None,
            "candidates": {candidate["sha256"]: {"sha256": candidate["sha256"], "content": candidate["content"], "status": "unverified", "sources": []}},
        }
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "compatibility-candidates.json"
            path.write_text(json.dumps(old_db), encoding="utf-8")
            with patch.object(monitor, "DATABASE_PATH", path):
                migrated = monitor.load_database()
                self.assertEqual(migrated["schema_version"], 2)
                self.assertIn(candidate["sha256"], migrated["candidates"])
                self.assertEqual(migrated["issues"], {})

    def test_v1_database_triggers_30_day_enrichment_backfill(self):
        with tempfile.TemporaryDirectory() as folder:
            folder_path = Path(folder)
            db = folder_path / "compatibility-candidates.json"
            state = folder_path / "monitor-state.json"
            db.write_text(json.dumps({"schema_version": 1, "candidates": {}}), encoding="utf-8")
            state.write_text(json.dumps({"last_checked": "2026-11-23T00:00:00Z"}), encoding="utf-8")
            with patch.object(monitor, "DATABASE_PATH", db), patch.object(monitor, "STATE_PATH", state):
                since, first, scan = monitor.load_since()
                self.assertTrue(first)
                self.assertIn("30-day", scan)
                self.assertTrue((monitor.utc_now() - since).days in (29, 30))


    def test_incomplete_candidate_is_not_promoted(self):
        candidate = monitor.extract_ini_candidates(INI_26100_INCOMPLETE)[0]
        database = {"schema_version": 2, "upstream": "stascorp/rdpwrap", "updated_at": None, "candidates": {}, "issues": {}}
        source = {"source_type": "issue_body", "source_url": "https://github.com/stascorp/rdpwrap/issues/4567", "failure_signals": [], "issue_classification": "duplicate_issue", "labels": ["duplicate"]}
        monitor.add_candidate_to_database(database, candidate, source, "2026-11-23T00:00:00Z")
        stored = next(iter(database["candidates"].values()))
        self.assertEqual(stored["review_classification"], "incomplete")
        self.assertEqual(stored["completeness"], "incomplete")
        self.assertIn("source_issue_marked_duplicate", stored["review_flags"])

    def test_candidate_source_display_uses_creation_time_not_issue_updated_time(self):
        source = {
            "source_type": "issue_body",
            "source_url": "https://github.com/stascorp/rdpwrap/issues/4",
            "created_at": "2026-11-20T08:00:00Z",
            "updated_at": "2026-11-23T08:00:00Z",
        }
        formatted = monitor.format_candidate_source(source)
        self.assertIn("created `2026-11-20T08:00:00Z`", formatted)
        self.assertIn("last edited `2026-11-23T08:00:00Z`", formatted)

    def test_issue_record_upsert_preserves_first_seen(self):
        database = {"issues": {}}
        monitor.upsert_issue_record(database, {"number": 4564, "monitor_seen_at": "2026-11-22T00:00:00Z", "title": "old"})
        monitor.upsert_issue_record(database, {"number": 4564, "monitor_seen_at": "2026-11-23T00:00:00Z", "title": "new"})
        record = database["issues"]["4564"]
        self.assertEqual(record["first_seen"], "2026-11-22T00:00:00Z")
        self.assertEqual(record["title"], "new")
        self.assertEqual(record["last_seen"], "2026-11-23T00:00:00Z")


class GitHubAuthenticationTests(unittest.TestCase):
    def test_missing_token_fails_before_any_anonymous_request(self):
        with patch.dict("os.environ", {}, clear=True), patch.object(monitor, "urlopen") as opener:
            with self.assertRaisesRegex(RuntimeError, "token is missing"):
                monitor.api_get("https://api.github.com/rate_limit")
            opener.assert_not_called()

    def test_gh_token_is_preferred(self):
        with patch.dict("os.environ", {"GH_TOKEN": "gh-token", "GITHUB_TOKEN": "github-token"}, clear=True):
            self.assertEqual(monitor.get_github_token(), "gh-token")

    def test_api_get_sends_bearer_token_without_printing_it(self):
        class FakeResponse:
            def __enter__(self):
                return self
            def __exit__(self, exc_type, exc, tb):
                return False
            def read(self):
                return b'{"ok": true}'

        with patch.dict("os.environ", {"GH_TOKEN": "test-token"}, clear=True), \
             patch.object(monitor, "urlopen", return_value=FakeResponse()) as opener:
            self.assertEqual(monitor.api_get("https://api.github.com/rate_limit"), {"ok": True})
            request = opener.call_args.args[0]
            self.assertEqual(request.get_header("Authorization"), "Bearer test-token")

    def test_auth_check_rejects_unauthenticated_60_per_hour_quota(self):
        payload = {"resources": {"core": {"limit": 60, "remaining": 0, "reset": 123}}}
        with patch.dict("os.environ", {"GH_TOKEN": "test-token"}, clear=True), \
             patch.object(monitor, "api_get", return_value=payload):
            with self.assertRaisesRegex(RuntimeError, "unauthenticated 60-request quota"):
                monitor.check_api_authentication()

    def test_workflow_injects_automatic_token_at_monitor_step(self):
        workflow_path = SCRIPT.parents[2] / ".github" / "workflows" / "rdp-monitor.yml"
        workflow_text = workflow_path.read_text(encoding="utf-8")
        self.assertIn("GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}", workflow_text)
        self.assertIn("issues: read", workflow_text)



class ProductionComparisonTests(unittest.TestCase):
    BASELINE = """; production RDP Wrapper INI
[Main]
Updated=2026-07-21

[10.0.28000.3614]
SingleUserPatch.x64=1
SingleUserOffset.x64=2CE31
SingleUserCode.x64=mov_eax_1_nop_2
DefPolicyPatch.x64=1
DefPolicyOffset.x64=AD1CD
DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp
LocalOnlyPatch.x64=1
LocalOnlyOffset.x64=A5207
LocalOnlyCode.x64=jmpshort
SLInitHook.x64=1
SLInitOffset.x64=C0988
SLInitFunc.x64=New_CSLQuery_Initialize
ExtraProductionKey.x64=present

[10.0.28000.3614-SLInit]
bServerSku.x64=13BE1C
bRemoteConnAllowed.x64=13BE34
bFUSEnabled.x64=13BE44
bAppServerAllowed.x64=13BE28
bMultimonAllowed.x64=13BE38
lMaxUserSessions.x64=13BE20
ulMaxDebugSessions.x64=13BE40
bInitialized.x64=13BE18
"""

    def make_candidate(self, content, review="unverified", candidate_id="abc123"):
        return {
            "candidate_id": candidate_id,
            "sha256": monitor.candidate_hash(content),
            "content": content,
            "review_classification": review,
            "sources": [{
                "source_type": "comment",
                "issue_number": 4564,
                "author": "sample-user",
                "source_url": "https://github.com/stascorp/rdpwrap/issues/4564#issuecomment-1",
                "created_at": "2026-11-21T04:59:53Z",
            }],
        }

    def test_case_and_whitespace_normalized_but_extra_production_key_is_partial_match(self):
        candidate_text = INI_28000.replace("SingleUserOffset.x64=2CE31", " singleuseroffset.X64 = 2CE31 ")
        baseline = self.BASELINE.replace("[10.0.28000.3614]", "[10.0.28000.3614]  ")
        result = monitor.compare_candidate_to_production(self.make_candidate(candidate_text), baseline)
        self.assertEqual(result["comparison_status"], "partial_match")
        # Production intentionally has one additional key in the main section.
        self.assertIn("production_has_extra_keys", result["comparison_flags"])

    def test_exact_match_when_section_and_values_are_same(self):
        baseline = self.BASELINE.replace("ExtraProductionKey.x64=present\n", "")
        result = monitor.compare_candidate_to_production(self.make_candidate(INI_28000), baseline)
        self.assertEqual(result["comparison_status"], "exact_match")
        self.assertEqual(len(result["section_results"]), 2)

    def test_value_difference_is_reported_with_both_values(self):
        candidate_text = INI_28000.replace("SingleUserOffset.x64=2CE31", "SingleUserOffset.x64=2CE32")
        baseline = self.BASELINE.replace("ExtraProductionKey.x64=present\n", "")
        result = monitor.compare_candidate_to_production(self.make_candidate(candidate_text), baseline)
        self.assertEqual(result["comparison_status"], "value_difference")
        difference = next(item for item in result["value_differences"] if item["key"] == "singleuseroffset.x64")
        self.assertEqual(difference["candidate_value"], "2CE32")
        self.assertEqual(difference["production_value"], "2CE31")

    def test_new_section_is_reported_when_version_not_in_production(self):
        content = INI_28000.replace("28000.3614", "28000.9999")
        result = monitor.compare_candidate_to_production(self.make_candidate(content), self.BASELINE)
        self.assertEqual(result["comparison_status"], "new_section")
        self.assertEqual(result["new_sections"], ["10.0.28000.9999", "10.0.28000.9999-SLInit"])

    def test_candidate_only_key_is_reported(self):
        baseline = self.BASELINE.replace("ExtraProductionKey.x64=present\n", "")
        candidate_text = INI_28000.replace(
            "SingleUserCode.x64=mov_eax_1_nop_2",
            "SingleUserCode.x64=mov_eax_1_nop_2\nCandidateOnly.x64=ABC",
        )
        result = monitor.compare_candidate_to_production(self.make_candidate(candidate_text), baseline)
        self.assertEqual(result["comparison_status"], "new_keys")
        self.assertTrue(any(item["key"] == "candidateonly.x64" for item in result["candidate_only_keys"]))

    def test_incomplete_candidate_reports_unsectioned_entries_and_compares_valid_section(self):
        result = monitor.compare_candidate_to_production(
            self.make_candidate(INI_26100_INCOMPLETE), self.BASELINE
        )
        self.assertEqual(result["comparison_status"], "incomplete")
        self.assertGreater(len(result["unsectioned_entries"]), 0)
        self.assertTrue(any(item["section"].endswith("-SLInit") for item in result["section_results"]))

    def test_section_and_key_names_are_case_insensitive(self):
        baseline = """[10.0.28000.3614]
singleuserpatch.X64=1
singleuseroffset.x64=2CE31
singleusercode.X64=mov_eax_1_nop_2
"""
        candidate = """[10.0.28000.3614]
SingleUserPatch.x64=1
SingleUserOffset.x64=2CE31
SingleUserCode.x64=mov_eax_1_nop_2
"""
        # Candidate is structurally incomplete because common fields are missing,
        # but names/case do not create a false value difference.
        result = monitor.compare_candidate_to_production(self.make_candidate(candidate), baseline)
        self.assertNotIn("value_difference", result["comparison_flags"])
        self.assertEqual(result["section_results"][0]["status"], "exact_match")

    def test_production_comparison_includes_baseline_hash_and_main_updated(self):
        database = {"candidates": {"hash": self.make_candidate(INI_28000)}}
        result = monitor.build_production_comparison(database, self.BASELINE, "commit123")
        self.assertEqual(result["baseline"]["main_updated"], "2026-07-21")
        self.assertEqual(result["baseline"]["git_commit"], "commit123")
        self.assertEqual(len(result["baseline"]["sha256"]), 64)
        self.assertEqual(result["candidate_count"], 1)

    def test_summary_lists_production_comparison_and_candidate_sources(self):
        baseline = self.BASELINE.replace("ExtraProductionKey.x64=present\n", "")
        database = {"candidates": {"hash": self.make_candidate(INI_28000)}}
        result = monitor.build_production_comparison(database, baseline)
        report = monitor.build_comparison_report(result)
        self.assertIn("Upstream INI vs Production INI comparison", report)
        self.assertIn("EXACT MATCH", report)
        self.assertIn("issuecomment-1", report)
        self.assertIn("read-only", report)


    def test_new_section_plus_partial_match_is_mixed_difference(self):
        candidate_text = INI_28000 + "\n\n[10.0.28000.9999]\nSingleUserPatch.x64=1\n"
        baseline = self.BASELINE
        result = monitor.compare_candidate_to_production(self.make_candidate(candidate_text), baseline)
        self.assertEqual(result["comparison_status"], "mixed_difference")
        self.assertIn("new_section", result["comparison_flags"])
        self.assertIn("production_has_extra_keys", result["comparison_flags"])


    def test_workflow_commits_comparison_json_and_checks_out_production_ini(self):
        workflow_path = SCRIPT.parents[2] / ".github" / "workflows" / "rdp-monitor.yml"
        workflow = workflow_path.read_text(encoding="utf-8")
        self.assertIn("git add monitor-state.json compatibility-candidates.json production-comparison.json", workflow)
        self.assertIn("actions/checkout", workflow)



if __name__ == "__main__":
    unittest.main(verbosity=2)
