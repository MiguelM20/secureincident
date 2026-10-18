"""Small dependency used by the Report Service, with no network or DB access."""

from collections.abc import Mapping


def _single_line(value: object) -> str:
    """Represent incident metadata as data, not as new report fields."""
    return " ".join(str(value).split())


def render_incident(incident: Mapping[str, object]) -> str:
    """Return a deterministic, readable text report for one incident record."""
    required = {"id", "owner_id", "title", "description", "severity", "status"}
    if not required.issubset(incident):
        raise ValueError("Missing incident fields")
    if type(incident["id"]) is not int or incident["id"] <= 0:
        raise ValueError("Invalid incident ID")
    if type(incident["owner_id"]) is not int or incident["owner_id"] <= 0:
        raise ValueError("Invalid owner ID")
    labels = [
        ("Incident ID", incident["id"]),
        ("Owner ID", incident["owner_id"]),
        ("Title", incident["title"]),
        ("Severity", incident["severity"]),
        ("Status", incident["status"]),
        ("Description", incident["description"]),
    ]
    report = "SecureIncident Investigation Report\n" + "=" * 35 + "\n"
    report += "\n".join(f"{label}: {_single_line(value)}" for label, value in labels)
    return report + "\n"
