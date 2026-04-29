from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


def _severity_color(severity: str) -> colors.Color:
    normalized = severity.upper()
    if normalized == "CRITICAL":
        return colors.HexColor("#B00020")
    if normalized == "HIGH":
        return colors.HexColor("#D84315")
    if normalized == "MEDIUM":
        return colors.HexColor("#F9A825")
    if normalized == "LOW":
        return colors.HexColor("#2E7D32")
    return colors.black


def _safe_vulns(vulnerabilities: Any) -> List[Dict[str, Any]]:
    if not isinstance(vulnerabilities, list):
        return []
    safe: List[Dict[str, Any]] = []
    for v in vulnerabilities:
        if not isinstance(v, Mapping):
            continue
        safe.append(
            {
                "title": str(v.get("title", "Unknown vulnerability")),
                "severity": str(v.get("severity", "MEDIUM")).upper(),
                "description": str(v.get("description", "")),
                "line": int(v.get("line", 0) or 0),
                "fix": str(v.get("fix", "")),
            }
        )
    return safe


def generate_audit_report(
    analysis_response: Mapping[str, Any], output_dir: str | None = None
) -> str:
    """
    Generate a professional PDF from /analyze response and return file path.
    Expected shape:
    {
      "risk_score": number,
      "vulnerabilities": [{title, severity, description, line, fix}],
      "exploit_story": string
    }
    """
    risk_score = int(analysis_response.get("risk_score", 0) or 0)
    vulnerabilities = _safe_vulns(analysis_response.get("vulnerabilities", []))
    exploit_story = str(analysis_response.get("exploit_story", ""))

    base_dir = Path(output_dir) if output_dir else Path(__file__).resolve().parents[2] / "reports"
    base_dir.mkdir(parents=True, exist_ok=True)
    filename = f"shieldchain_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    output_path = base_dir / filename

    doc = SimpleDocTemplate(
        str(output_path),
        pagesize=A4,
        leftMargin=0.65 * inch,
        rightMargin=0.65 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="ShieldChain Audit Report",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        leading=28,
        textColor=colors.HexColor("#0B1D3A"),
        spaceAfter=12,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#0B1D3A"),
        spaceBefore=10,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["BodyText"],
        fontSize=10.5,
        leading=14,
        spaceAfter=6,
    )

    story: List[Any] = []
    story.append(Paragraph("ShieldChain Audit Report", title_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 8))

    risk_table = Table(
        [["Risk Score", str(risk_score)]],
        colWidths=[2.0 * inch, 1.0 * inch],
    )
    risk_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#E6EEF8")),
                ("BACKGROUND", (1, 0), (1, 0), colors.HexColor("#F4F7FB")),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0B1D3A")),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B0BEC5")),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(risk_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Vulnerabilities", heading_style))
    if not vulnerabilities:
        story.append(Paragraph("No vulnerabilities reported.", body_style))
    else:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            sev_color = _severity_color(vuln["severity"])
            vuln_title = (
                f"<b>{idx}. {vuln['title']}</b> "
                f'(<font color="{sev_color.hexval()}"><b>{vuln["severity"]}</b></font>)'
            )
            story.append(Paragraph(vuln_title, body_style))
            story.append(Paragraph(f"<b>Line:</b> {vuln['line']}", body_style))
            story.append(Paragraph(f"<b>Description:</b> {vuln['description']}", body_style))
            story.append(Paragraph(f"<b>Fix Suggestion:</b> {vuln['fix']}", body_style))
            story.append(Spacer(1, 6))

    story.append(Paragraph("Exploit Story", heading_style))
    story.append(Paragraph(exploit_story or "No exploit story provided.", body_style))

    doc.build(story)
    return str(output_path)
