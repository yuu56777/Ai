from pathlib import Path
from typing import List, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).parent.parent.parent / "templates"

_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)

_template = _env.get_template("report.html")


def _recommendations(verdict: str) -> List[str]:
    if verdict == "malicious":
        return [
            "Immediately delete or quarantine the file.",
            "Ensure your antivirus definitions are up to date.",
            "Avoid sharing this file with others.",
        ]
    if verdict == "suspicious":
        return [
            "Treat the file with caution and do not execute macros.",
            "Consider scanning with additional tools.",
            "Verify the source of the file manually.",
        ]
    return [
        "No malicious indicators detected; keep software patched and stay vigilant.",
    ]


def render_html(job: Dict) -> str:
    """Return an HTML report for the given job dict."""
    context = {
        "verdict": job.get("verdict", "unknown"),
        "sha256": job.get("sha256", ""),
        "vt_summary": job.get("vt_summary", {}),
        "recommendations": _recommendations(job.get("verdict", "unknown")),
    }
    return _template.render(**context)