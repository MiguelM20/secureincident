"""Controlled CWE-22 reproduction; the directory is created by pytest's tmp_path.

Skipped during normal test runs. Run explicitly with RUN_PATH_TRAVERSAL_EXPERIMENT=1
only on the experiment branch with the vulnerable patch applied.
"""
import os
from pathlib import Path

import pytest

from test_report_service import bearer, setup  # reuse the tested three-service fixture


@pytest.mark.skipif(os.getenv("RUN_PATH_TRAVERSAL_EXPERIMENT") != "1",
                    reason="Deliberate exploit demo, excluded from normal suite")
def test_report_path_traversal_creates_file_outside_work_directory(setup, monkeypatch):
    gateway, _, temp_root = setup
    expected_root = (temp_root / "workdir").resolve()
    escaped_file = (temp_root / "outside-report.txt").resolve()
    assert not escaped_file.exists()
    seen = []
    real_unlink = Path.unlink

    def capture_before_cleanup(path: Path, *args, **kwargs):
        if path == escaped_file:
            # The report is written beyond the allowed directory, and then
            # normally cleaned up by the application in its finally block.
            assert path.exists()
            seen.append(path.read_text(encoding="utf-8"))
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", capture_before_cleanup)
    response = gateway.post(
        "/incidents/101/reports",
        headers=bearer(gateway, "alice"),
        json={"filename": "../outside-report.txt"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["incident_id"] == 101
    assert not escaped_file.is_relative_to(expected_root)
    assert len(seen) == 1 and "Incident ID: 101" in seen[0]
    assert not escaped_file.exists(), "temporary test file must be cleaned up"
    print("CWE-22: Alice's report was written outside the report workdir (synthetic temp path)")
