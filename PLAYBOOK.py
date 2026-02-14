from __future__ import annotations

from datetime import datetime
from io import BytesIO
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    ListFlowable,
    ListItem,
    Table,
    TableStyle,
    PageBreak,
)


def _safe_str(x: Any) -> str:
    if x is None:
        return ""
    return str(x)


def _join_list(x: Any) -> str:
    if isinstance(x, list):
        return ", ".join([_safe_str(i) for i in x])
    return _safe_str(x)


def _mitigation_playbook_for_finding(f: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    Heuristic playbook builder (offline) that maps common hunting outputs/tags to actions.
    Keeps guidance practical but generic; adapt to your IR policy.
    """
    tags = set([_safe_str(x).lower() for x in (f.get("tags") or [])])
    iocs = f.get("indicators_of_compromise") or []

    containment = [
        "Confirm scope: identify affected hosts/users and the time window from the evidence.",
        "Preserve evidence: export raw log evidence + relevant EDR/SIEM results; capture volatile data if required.",
    ]
    if iocs:
        containment.append(
            "Block/contain validated IOCs (firewall/proxy/DNS/EDR indicators) after confirming business impact."
        )
    if ("suspicious login" in tags) or ("credential access" in tags):
        containment += [
            "Lock or disable suspected accounts if compromise is likely; enforce password reset and MFA re-registration.",
            "Review sign-in risk: impossible travel, unfamiliar devices, and Conditional Access outcomes.",
        ]
    if "persistence" in tags:
        containment += [
            "Isolate impacted endpoint(s) if persistence is confirmed or highly suspected.",
            "Collect evidence: autoruns/scheduled tasks/services/Run keys for remediation.",
        ]
    if ("c2" in tags) or ("data exfiltration" in tags):
        containment += [
            "Isolate host and block egress to suspicious destinations while validating false positives.",
            "Pivot: identify other hosts communicating with the same destinations (IP/domain).",
        ]

    eradication = [
        "Identify initial access vector and remove malicious artifacts (files, tasks, services, registry keys).",
        "Hunt laterally: search for the same hash/process/command line/remote IP across the environment.",
    ]
    if iocs:
        eradication.append("Add validated IOCs to blocklists and SIEM/EDR detections (watchlists/indicators).")
    if "malware" in tags:
        eradication.append("Run full EDR scan on affected endpoints and validate quarantine/cleanup results.")

    recovery = [
        "Reimage/restore systems if integrity is uncertain; validate patches and secure baselines before rejoin.",
        "Monitor for recurrence: enable temporary high-signal detections for observed TTPs for 7–14 days.",
    ]

    hardening = [
        "Apply least privilege: remove unnecessary local admin and restrict remote admin tools.",
        "Ensure endpoint protections are enforced (EDR tamper protection, real-time protection, ASR where appropriate).",
        "Review logging coverage to ensure required tables/fields are captured for future investigations.",
    ]
    if ("execution" in tags) or ("unusual command" in tags):
        hardening += [
            "Restrict scripting where appropriate (PowerShell CLM / allow-listing / signed scripts).",
            "Add detections for the suspicious command lines observed in the evidence.",
        ]
    if "privilege escalation" in tags:
        hardening += [
            "Review privileged group memberships / PIM eligibility; enforce just-in-time access.",
            "Patch known privilege escalation vectors on endpoints and servers.",
        ]

    comms = [
        "Update the incident ticket: timeline, impacted assets, IOCs, actions taken, and open risks.",
        "Notify stakeholders per incident response policy and document decisions (especially if regulated).",
    ]

    return {
        "Immediate triage": [
            f"Validate finding: {f.get('title', '(untitled)')}",
            "Confirm activity is expected for the user/host; check change windows and business context.",
        ],
        "Containment": containment,
        "Eradication": eradication,
        "Recovery": recovery,
        "Hardening & detections": hardening,
        "Communication": comms,
    }


def build_playbook_pdf(
    query_context: Dict[str, Any],
    findings: List[Dict[str, Any]],
    generated_by: str = "custom_agent",
) -> bytes:
    """
    Create a PDF playbook (no external converters required).
    """
    buf = BytesIO()
    pdf = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        title="Threat Mitigation Playbook",
        author=generated_by,
    )
    styles = getSampleStyleSheet()
    story: List[Any] = []

    # Header
    story.append(Paragraph("Threat Mitigation Playbook", styles["Title"]))
    story.append(
        Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} • {_safe_str(generated_by)}",
            styles["Normal"],
        )
    )
    story.append(Spacer(1, 0.2 * inch))

    # Hunt context
    story.append(Paragraph("Hunt context", styles["Heading1"]))
    ctx_rows = [
        ["Table", _safe_str(query_context.get("table_name", ""))],
        ["Time range (hours)", _safe_str(query_context.get("time_range_hours", ""))],
        ["Fields", _join_list(query_context.get("fields", []))],
        ["Device filter", _safe_str(query_context.get("device_name", ""))],
        ["Caller filter", _safe_str(query_context.get("caller", ""))],
        ["UserPrincipalName filter", _safe_str(query_context.get("user_principal_name", ""))],
        ["KQL limit", _safe_str(query_context.get("limit", ""))],
    ]
    t = Table(ctx_rows, colWidths=[1.8 * inch, 4.9 * inch])
    t.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (0, 0), (0, -1), colors.whitesmoke),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 0.2 * inch))

    # How to use
    story.append(Paragraph("How to use this playbook", styles["Heading1"]))
    howto_items = [
        "Use each finding’s sections as a checklist.",
        "Prioritize High confidence findings first, then Medium.",
        "Validate false positives and business impact before blocking/isolating systems.",
    ]
    story.append(
        ListFlowable(
            [ListItem(Paragraph(x, styles["Normal"])) for x in howto_items],
            bulletType="bullet",
        )
    )
    story.append(PageBreak())

    # Findings
    story.append(Paragraph("Findings & Mitigation Steps", styles["Heading1"]))

    if not findings:
        story.append(
            Paragraph(
                "No suspicious findings were returned. Consider widening the time range, selecting a different table, "
                "or adding pivots (IP/hash/process/user) for deeper analysis.",
                styles["Normal"],
            )
        )
    else:
        for idx, f in enumerate(findings, start=1):
            title = _safe_str(f.get("title") or f"Finding {idx}")
            conf = _safe_str(f.get("confidence") or "")
            story.append(Spacer(1, 0.15 * inch))
            story.append(Paragraph(f"{idx}. {title}", styles["Heading2"]))
            if conf:
                story.append(Paragraph(f"Confidence: {conf}", styles["Normal"]))

            mitre = f.get("mitre") or {}
            if isinstance(mitre, dict) and any(mitre.values()):
                mitre_line = " • ".join(
                    [x for x in [_safe_str(mitre.get("id")), _safe_str(mitre.get("tactic")), _safe_str(mitre.get("technique"))] if x]
                )
                if mitre_line:
                    story.append(Paragraph(f"MITRE: {mitre_line}", styles["Normal"]))

            summary = _safe_str(f.get("summary") or f.get("description") or "")
            if summary:
                story.append(Paragraph(summary, styles["Normal"]))

            iocs = f.get("indicators_of_compromise") or []
            if iocs:
                story.append(Paragraph("Indicators of compromise (IOCs)", styles["Heading3"]))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_safe_str(x), styles["Normal"])) for x in iocs],
                        bulletType="bullet",
                    )
                )

            # Evidence (optional, capped)
            log_lines = f.get("log_lines") or []
            if log_lines:
                story.append(Paragraph("Evidence (log lines)", styles["Heading3"]))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_safe_str(x), styles["Normal"])) for x in log_lines[:15]],
                        bulletType="bullet",
                    )
                )

            # Mitigation sections (correct keys)
            steps = _mitigation_playbook_for_finding(f)
            for section_title, items in steps.items():
                if not items:
                    continue
                story.append(Paragraph(section_title, styles["Heading3"]))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_safe_str(x), styles["Normal"])) for x in items],
                        bulletType="bullet",
                    )
                )

            analyst_notes = f.get("recommendations") or []
            if analyst_notes:
                story.append(Paragraph("Analyst notes", styles["Heading3"]))
                story.append(
                    ListFlowable(
                        [ListItem(Paragraph(_safe_str(x), styles["Normal"])) for x in analyst_notes],
                        bulletType="bullet",
                    )
                )

    # Footer note
    story.append(Spacer(1, 0.2 * inch))
    story.append(
        Paragraph(
            "<i>Note: This playbook provides standard incident response guidance. Adapt to your organisation’s IR policy, change controls, and regulatory obligations.</i>",
            styles["Normal"],
        )
    )

    pdf.build(story)
    return buf.getvalue()