# RDP Issue Monitor v1.2 — expected classification examples

This file explains how v1.2 classifies the sample Issues discussed during development. The labels below are triage signals, not compatibility certification.

| Issue | v1.2 Issue classification | Candidate result | Important distinction |
|---|---|---|---|
| #4569 | `general_activity` | No INI found; ZIP attachment noted | `19045.7846` is an OS Build hint; leading `10.0.19041.7811` remains an unclassified version unless the text explicitly calls it termsrv.dll. |
| #4568 | `compatibility_request` | No INI found; ZIP attachment noted | `10.0.26100.10021` in the Windows title is a title version hint, not automatically an OS Build or termsrv.dll version. |
| #4567 | `duplicate_issue` | `incomplete` if the primary `[10.0.x.x]` section is missing | `26200.10075` is parsed as the explicit compilation/OS Build hint; `10.0.26100.10068-SLInit` remains the only actual INI section detected. |
| #4564 | `compatibility_request` | `unverified` when both main and SLInit sections are present | The comment source is retained with its author and created date. The title version and INI target can be recorded as separate roles for the same version. |
| #4566 | `reported_failure` | `reported_failure` when a candidate is associated with that issue | The service-crash wording is recorded as a reported failure signal; “Not RDP Wrapper bug” is separately retained as a triage note. Neither signal alone proves whether the INI is good or bad. |

## Important semantics

- `reported_failure` means the Issue text contains a matching failure description. It does not prove the INI caused the reported problem.
- `incomplete` means the parser did not find a primary version section or required common patch keys. It does not attempt to repair the INI.
- `duplicate_issue` describes the Issue/label relationship, not duplicate INI content.
- `maintainer_labeled_invalid` records the upstream `invalid` label. It is not a local technical verdict on every candidate attached to that Issue.
- The `termsrv.dll` role is assigned only when the source text explicitly associates a version with `termsrv` or `termsrv.dll`.
- The `issues` object and `candidates` object are both saved in `compatibility-candidates.json` schema version 2.
