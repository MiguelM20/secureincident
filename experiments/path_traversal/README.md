# Experiment 3: Path Traversal (CWE-22)

**Environment:** Only an isolated pytest `tmp_path` with synthetic incident data. Do not deploy the vulnerable patch in Docker or commit it to `main`.

## Vulnerability

The report generator accepts a client-supplied filename. The vulnerable patch removes filename restrictions, the random basename prefix, and the `is_relative_to()` containment check. The resulting `root / "../outside-report.txt"` resolves outside the Report Service's authorized temporary working directory. The experiment proves the file is written beyond the intended boundary before the service's normal cleanup removes it.

- Vulnerable component: `services/report_service/app.py`, `_validated_filename()` and `generate_report()`.
- Misplaced trust: the path supplied by the requester is assumed to stay inside the report workspace.
- Security effect: an attacker controls where a report file is created within the service's file-system permissions.
- Scope: the test writes only synthetic report text under pytest's private temporary directory, never system files.
- Corrective controls: basename allowlist, random filename prefix, resolved-path containment check, exclusive creation.
- Regression: `tests/test_report_service.py::test_path_traversal_denied_with_no_write_or_report`.

## Minimal reproduction (from `main` in the repository root)

1. Stop Docker without deleting volumes: `docker compose down`.
2. Create a separate branch: `git switch -c experiment/path-traversal`.
3. Extract the experiment ZIP into the repository root.
4. Apply the flaw: `git apply experiments/path_traversal/vulnerable.patch`.
5. Run the exploit with output saved as evidence:
   `RUN_PATH_TRAVERSAL_EXPERIMENT=1 python -m pytest tests/test_path_traversal_experiment.py -q -s | tee docs/evidence/path-traversal-vulnerable.txt`
6. Commit the controlled vulnerable state (separate branch):
   `git add services/report_service/app.py tests/test_path_traversal_experiment.py experiments/path_traversal docs/evidence/path-traversal-vulnerable.txt`
   `git commit -m "test: demonstrate CWE-22 path traversal"`
7. Undo the flaw: `git apply -R experiments/path_traversal/vulnerable.patch`.
8. Verify the fix:
   `python -m pytest tests/test_report_service.py::test_path_traversal_denied_with_no_write_or_report -q | tee docs/evidence/path-traversal-fixed.txt`
9. Commit the fix:
   `git add services/report_service/app.py docs/evidence/path-traversal-fixed.txt`
   `git commit -m "fix: enforce report output path boundary"`
10. Push experiment branch and return to secure main:
    `git push -u origin experiment/path-traversal`
    `git switch main`

Keep the experimental exploit test outside the final release gates; it is skipped by default.
