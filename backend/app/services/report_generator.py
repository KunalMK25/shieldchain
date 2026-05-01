from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Mapping

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# PDF styling constants matching design
BG_COLOR = "#0B1D3A"
ACCENT = "#00C2D4"
SECONDARY = "#1B4C8C"
CRITICAL_C = "#EF4444"
HIGH_C = "#F97316"
MEDIUM_C = "#EAB308"
LOW_C = "#22C55E"


def _severity_color(severity: str) -> colors.Color:
    normalized = severity.upper()
    if normalized == "CRITICAL":
        return colors.HexColor(CRITICAL_C)
    if normalized == "HIGH":
        return colors.HexColor(HIGH_C)
    if normalized == "MEDIUM":
        return colors.HexColor(MEDIUM_C)
    if normalized == "LOW":
        return colors.HexColor(LOW_C)
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
    analysis_response: Mapping[str, Any],
    contract_name: str = "Unknown Contract",
    output_dir: str | None = None,
) -> tuple[str, str]:
    """
    Generate a professional PDF from /analyze response and return (pdf_path, report_id).
    
    Args:
        analysis_response: Analysis data with risk_score, vulnerabilities, exploit_story,
                          score_breakdown (optional), improvement_priority (optional)
        contract_name: Name of the contract being audited
        output_dir: Optional output directory (defaults to backend/reports/)
    
    Returns:
        tuple[str, str]: (pdf_path, report_id) where report_id is the timestamp string
                        e.g. ("path/to/file.pdf", "20260429_204933")
    """
    risk_score = int(analysis_response.get("risk_score", 0) or 0)
    vulnerabilities = _safe_vulns(analysis_response.get("vulnerabilities", []))
    exploit_story = str(analysis_response.get("exploit_story", ""))
    score_breakdown = analysis_response.get("score_breakdown")
    improvement_priority = analysis_response.get("improvement_priority")

    base_dir = Path(output_dir) if output_dir else Path(__file__).resolve().parents[2] / "reports"
    base_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate timestamp for filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_id = timestamp
    filename = f"shieldchain_audit_{report_id}.pdf"
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
    
    # Header: ShieldChain Security Audit + contract name + timestamp
    story.append(Paragraph("ShieldChain Security Audit", title_style))
    story.append(Paragraph(f"<b>Contract:</b> {html.escape(contract_name)}", body_style))
    story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
    story.append(Spacer(1, 12))

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
    story.append(Spacer(1, 16))

    # Section 3: Score Breakdown
    if score_breakdown and isinstance(score_breakdown, dict):
        story.append(Paragraph("Score Breakdown", heading_style))
        
        # Reasoning paragraph
        reasoning = str(score_breakdown.get("reasoning", ""))
        if reasoning:
            story.append(Paragraph(html.escape(reasoning), body_style))
            story.append(Spacer(1, 6))
        
        # Positives bullet list
        positives = score_breakdown.get("positives", [])
        if positives and isinstance(positives, list):
            story.append(Paragraph("<b>Positive Security Aspects:</b>", body_style))
            for positive in positives:
                story.append(Paragraph(f"• {html.escape(str(positive))}", body_style))
            story.append(Spacer(1, 6))
        
        # Severity count table
        severity_data = [
            ["Severity", "Count"],
            ["CRITICAL", str(score_breakdown.get("critical_count", 0))],
            ["HIGH", str(score_breakdown.get("high_count", 0))],
            ["MEDIUM", str(score_breakdown.get("medium_count", 0))],
            ["LOW", str(score_breakdown.get("low_count", 0))],
        ]
        severity_table = Table(severity_data, colWidths=[2.0 * inch, 1.0 * inch])
        severity_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(SECONDARY)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B0BEC5")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F4F7FB")),
                ]
            )
        )
        story.append(severity_table)
        story.append(Spacer(1, 16))

    # Section 4: Vulnerabilities
    story.append(Paragraph("Vulnerabilities", heading_style))
    if not vulnerabilities:
        story.append(Paragraph("No vulnerabilities reported.", body_style))
    else:
        for idx, vuln in enumerate(vulnerabilities, start=1):
            sev_color = _severity_color(vuln["severity"])
            vuln_title = (
                f"<b>{idx}. {html.escape(vuln['title'])}</b> "
                f'(<font color="{sev_color.hexval()}"><b>{vuln["severity"]}</b></font>)'
            )
            story.append(Paragraph(vuln_title, body_style))
            story.append(Paragraph(f"<b>Line:</b> {vuln['line']}", body_style))
            story.append(Paragraph(f"<b>Description:</b> {html.escape(vuln['description'])}", body_style))
            story.append(Paragraph(f"<b>Fix Suggestion:</b> {html.escape(vuln['fix'])}", body_style))
            story.append(Spacer(1, 6))
    story.append(Spacer(1, 10))

    # Section 5: Improvement Priority
    if improvement_priority and isinstance(improvement_priority, list) and improvement_priority:
        story.append(Paragraph("Improvement Priority", heading_style))
        
        priority_data = [["Priority", "Fix", "Effort", "Severity"]]
        for item in improvement_priority:
            if isinstance(item, dict):
                priority_data.append([
                    str(item.get("order", "")),
                    str(item.get("fix", "")),
                    str(item.get("effort", "")),
                    str(item.get("severity", "")),
                ])
        
        if len(priority_data) > 1:  # Has data beyond header
            priority_table = Table(priority_data, colWidths=[0.6 * inch, 3.0 * inch, 0.9 * inch, 0.9 * inch])
            priority_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(SECONDARY)),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B0BEC5")),
                        ("ALIGN", (0, 0), (0, -1), "CENTER"),
                        ("ALIGN", (1, 0), (1, -1), "LEFT"),
                        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F4F7FB")),
                    ]
                )
            )
            story.append(priority_table)
            story.append(Spacer(1, 16))

    # Section 6: Exploit Narrative (moved here after priority list)
    story.append(Paragraph("Exploit Narrative", heading_style))
    story.append(Paragraph(html.escape(exploit_story) if exploit_story else "No exploit story provided.", body_style))
    story.append(Spacer(1, 16))

    # Section 7: Dynamic Analysis Results (only if dynamic_audit_log is present)
    dynamic_audit_log = analysis_response.get("dynamic_audit_log")
    if dynamic_audit_log and isinstance(dynamic_audit_log, list) and len(dynamic_audit_log) > 0:
        story.append(Paragraph("Dynamic Analysis Results", heading_style))
        
        # Summary row: Contract ID, Total Txs, Anomalies Found, Risk Adjustment
        contract_id = str(analysis_response.get("contract_id", "N/A"))
        total_txs = len(dynamic_audit_log)
        anomalies_found = int(analysis_response.get("anomalies_found", 0) or 0)
        dynamic_risk_adjustment = int(analysis_response.get("dynamic_risk_adjustment", 0) or 0)
        
        summary_data = [
            ["Contract ID", "Total Txs", "Anomalies Found", "Risk Adjustment"],
            [contract_id[:20] + "..." if len(contract_id) > 20 else contract_id, 
             str(total_txs), 
             str(anomalies_found), 
             f"+{dynamic_risk_adjustment}" if dynamic_risk_adjustment >= 0 else str(dynamic_risk_adjustment)]
        ]
        summary_table = Table(summary_data, colWidths=[2.5 * inch, 1.0 * inch, 1.2 * inch, 1.2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BG_COLOR)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor(ACCENT)),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor(BG_COLOR)),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 10))
        
        # Fuzzing transactions table
        story.append(Paragraph("<b>Fuzzing Transactions:</b>", body_style))
        story.append(Spacer(1, 4))
        
        tx_data = [["Timestamp", "Function", "Parameters", "Result/Error", "Status"]]
        for entry in dynamic_audit_log:
            if not isinstance(entry, Mapping):
                continue
            
            timestamp = str(entry.get("timestamp", ""))[:19]  # Truncate to YYYY-MM-DDTHH:MM:SS
            function_called = str(entry.get("function_called", ""))
            parameters = str(entry.get("parameters", {}))
            if len(parameters) > 30:
                parameters = parameters[:27] + "..."
            
            result_or_error = str(entry.get("result", "")) if entry.get("result") else str(entry.get("error", ""))
            if len(result_or_error) > 30:
                result_or_error = result_or_error[:27] + "..."
            
            status = str(entry.get("status", "NORMAL")).upper()
            
            tx_data.append([timestamp, function_called, parameters, result_or_error, status])
        
        tx_table = Table(tx_data, colWidths=[1.3 * inch, 1.0 * inch, 1.5 * inch, 1.5 * inch, 0.8 * inch])
        
        # Build table style with row colors based on status
        tx_table_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BG_COLOR)),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#B0BEC5")),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]
        
        # Apply row colors based on status
        for row_idx, entry in enumerate(dynamic_audit_log, start=1):
            if not isinstance(entry, Mapping):
                continue
            status = str(entry.get("status", "NORMAL")).upper()
            if status == "FLAGGED":
                tx_table_style.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor(CRITICAL_C)))
                tx_table_style.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.white))
            elif status == "SUSPICIOUS":
                tx_table_style.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor(HIGH_C)))
                tx_table_style.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.white))
            else:  # NORMAL
                tx_table_style.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.white))
                tx_table_style.append(("TEXTCOLOR", (0, row_idx), (-1, row_idx), colors.HexColor(BG_COLOR)))
        
        tx_table.setStyle(TableStyle(tx_table_style))
        story.append(tx_table)
        story.append(Spacer(1, 10))
        
        # Anomaly details list
        anomaly_entries = [e for e in dynamic_audit_log if isinstance(e, Mapping) and e.get("anomaly")]
        if anomaly_entries:
            story.append(Paragraph("<b>Anomaly Details:</b>", body_style))
            for entry in anomaly_entries:
                severity = str(entry.get("severity", "UNKNOWN"))
                function_name = str(entry.get("function_called", ""))
                reason = str(entry.get("reason", ""))
                tx_hash = str(entry.get("transaction_hash", ""))
                
                anomaly_text = (
                    f"• <b>{html.escape(severity)}</b> in <i>{html.escape(function_name)}</i>: "
                    f"{html.escape(reason)}"
                )
                story.append(Paragraph(anomaly_text, body_style))
                
                # Horizon link
                if tx_hash and not tx_hash.startswith("timeout_"):
                    horizon_link = f'<link href="https://stellar.expert/explorer/testnet/tx/{tx_hash}" color="{ACCENT}">View on Horizon</link>'
                    story.append(Paragraph(f"  {horizon_link}", body_style))
            
            story.append(Spacer(1, 6))
        
        # Risk adjustment explanation
        if dynamic_risk_adjustment != 0:
            adjustment_text = (
                f"<b>Risk Adjustment:</b> {'+' if dynamic_risk_adjustment >= 0 else ''}{dynamic_risk_adjustment} pts "
                f"due to {anomalies_found} anomalous transaction{'s' if anomalies_found != 1 else ''}"
            )
            story.append(Paragraph(adjustment_text, body_style))
        
        story.append(Spacer(1, 16))

    # Footer
    footer_text = "Generated by ShieldChain | Powered by Groq LLaMA 3.3 70B"
    footer_style = ParagraphStyle(
        "Footer",
        parent=styles["Normal"],
        fontSize=8,
        textColor=colors.HexColor("#666666"),
        alignment=1,  # Center alignment
    )
    story.append(Paragraph(footer_text, footer_style))

    doc.build(story)
    return (str(output_path), report_id)
