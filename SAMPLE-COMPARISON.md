# Sample: Upstream INI vs Production INI comparison

This is a synthetic illustration of the v1.2.2 report. The first real GitHub Actions run will compare the actual checked-out `rdpwrap.ini` with all Candidates in `compatibility-candidates.json`.

| Candidate | Target | Example result | Meaning |
|---|---|---|---|
| `fa699b64efdd5027` | `10.0.28000.3614` | `new_section` | Production has no section with this exact name. |
| `610ed31fc1c1da9e` | `10.0.26100.10068` | `value_difference` or `new_section` | Determined from the actual current Production file, not inferred from Issue titles. |
| `2431dba60cf09c26` | incomplete main section | `incomplete` | Its unsectioned main keys are not assigned to a guessed section; any valid section is still compared. |

A comparison result is a textual comparison, not a functional RDP compatibility test.
