import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "rdp_issue_monitor.py"
SPEC = importlib.util.spec_from_file_location("rdp_issue_monitor", SCRIPT)
monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(monitor)


class IniParserTests(unittest.TestCase):
    def test_issue_4564_multisection_candidate_is_preserved(self):
        text = """[10.0.28000.3614]
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
        candidates = monitor.extract_ini_candidates(text)
        self.assertEqual(len(candidates), 1)
        details = monitor.inspect_candidate(candidates[0]["content"])
        self.assertEqual(details["ini_target_versions"], ["10.0.28000.3614"])
        self.assertEqual(len(details["sections"]), 2)
        self.assertEqual(details["warnings"], [])

    def test_identical_candidate_blocks_are_deduplicated(self):
        block = """[10.0.26100.10068-SLInit]
bServerSku.x64=135344
bRemoteConnAllowed.x64=13535C
SingleUserPatch.x64=1
DefPolicyPatch.x64=1
LocalOnlyPatch.x64=1
SLInitHook.x64=1"""
        text = f"```ini\n{block}\n```\n\n```ini\n{block}\n```"
        candidates = monitor.extract_ini_candidates(text)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["duplicate_occurrences"], 1)

    def test_missing_primary_section_is_reported_not_invented(self):
        flattened = (
            "SingleUserPatch.x64=1 SingleUserOffset.x64=AC67B "
            "SingleUserCode.x64=mov_eax_1_nop_2 DefPolicyPatch.x64=1 "
            "DefPolicyOffset.x64=A981D DefPolicyCode.x64=CDefPolicy_Query_r9d_rdi_jmp "
            "LocalOnlyPatch.x64=1 LocalOnlyOffset.x64=9FB01 LocalOnlyCode.x64=jmpshort "
            "SLInitHook.x64=1 SLInitOffset.x64=C0838 SLInitFunc.x64=New_CSLQuery_Initialize "
            "[10.0.26100.10068-SLInit] bServerSku.x64=135344 "
            "bRemoteConnAllowed.x64=13535C bFUSEnabled.x64=13536C "
            "bAppServerAllowed.x64=135350 bMultimonAllowed.x64=135360 "
            "lMaxUserSessions.x64=135348 ulMaxDebugSessions.x64=135368 bInitialized.x64=135340"
        )
        candidates = monitor.extract_ini_candidates(flattened)
        self.assertEqual(len(candidates), 1)
        content = candidates[0]["content"]
        self.assertNotIn("[10.0.26100.10068]", content)
        details = monitor.inspect_candidate(content)
        self.assertIn("10.0.26100.10068", details["slinit_section_versions"])
        self.assertTrue(any("main" in warning.lower() for warning in details["warnings"]))

    def test_os_build_and_ini_target_are_separate(self):
        metadata = monitor.extract_os_metadata(
            "Codigo para rdpwrap.ini compilacion 26200.10075"
        )
        self.assertEqual(metadata["os_build_hints"], ["26200.10075"])
        self.assertEqual(monitor.extract_version_strings("10.0.26100.10068"), ["10.0.26100.10068"])

    def test_database_merges_sources_for_same_candidate(self):
        block = """[10.0.28000.3614]
SingleUserPatch.x64=1
DefPolicyPatch.x64=1
LocalOnlyPatch.x64=1
SLInitHook.x64=1"""
        candidate = monitor.extract_ini_candidates(block)[0]
        database = {"schema_version": 1, "upstream": "stascorp/rdpwrap", "updated_at": None, "candidates": {}}
        source_a = {"source_type": "issue_body", "source_url": "https://github.com/stascorp/rdpwrap/issues/1"}
        source_b = {"source_type": "comment", "source_url": "https://github.com/stascorp/rdpwrap/issues/1#issuecomment-2"}
        self.assertEqual(monitor.add_candidate_to_database(database, candidate, source_a, "2026-11-23T00:00:00Z")[0], "new")
        self.assertEqual(monitor.add_candidate_to_database(database, candidate, source_b, "2026-11-23T00:00:00Z")[0], "source-added")
        stored = next(iter(database["candidates"].values()))
        self.assertEqual(len(stored["sources"]), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
