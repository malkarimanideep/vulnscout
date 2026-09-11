from fpdf import FPDF
from datetime import datetime

class ExecutiveReport(FPDF):
    def header(self):
        self.set_fill_color(15, 23, 42)
        self.rect(0, 0, 210, 20, "F")
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(255, 255, 255)
        self.cell(0, 10, "  VULNSCOUT | EXECUTIVE APPLICATION SECURITY & EXPOSURE REPORT", ln=True)
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Confidential - SOC2 / NIST CSF Audit - Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", align="C")

def build_pdf_report(posture_data: dict, filepath: str = "audit_report.pdf"):
    pdf = ExecutiveReport()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Executive Summary Card
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "1. Executive Posture Overview", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(71, 85, 105)
    pdf.multi_cell(0, 6, f"This document outlines continuous endpoint detection, container exposures, and software composition analysis (SCA) findings captured for host '{posture_data['telemetry']['hostname']}'.")
    pdf.ln(4)

    # Metrics Table
    pdf.set_fill_color(241, 245, 249)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(45, 8, "Overall Risk Score", 1, 0, "C", True)
    pdf.cell(45, 8, "Active Sockets", 1, 0, "C", True)
    pdf.cell(45, 8, "SCA Vulnerabilities", 1, 0, "C", True)
    pdf.cell(45, 8, "Containers Audited", 1, 1, "C", True)

    pdf.set_font("Helvetica", "", 10)
    pdf.cell(45, 8, f"{posture_data['exposure_score']} / 100", 1, 0, "C")
    pdf.cell(45, 8, str(len(posture_data['sockets'])), 1, 0, "C")
    pdf.cell(45, 8, str(len(posture_data['sbom_vulns'])), 1, 0, "C")
    pdf.cell(45, 8, str(len(posture_data['containers'])), 1, 1, "C")
    pdf.ln(8)

    # Software Composition Analysis (SCA) & CVE Backlog
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(15, 23, 42)
    pdf.cell(0, 8, "2. Prioritized CVEs & Exploit Prediction (EPSS)", ln=True)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(226, 232, 240)
    pdf.cell(40, 7, "Vulnerability", 1, 0, "L", True)
    pdf.cell(30, 7, "Package", 1, 0, "L", True)
    pdf.cell(25, 7, "Severity", 1, 0, "C", True)
    pdf.cell(25, 7, "EPSS Rate", 1, 0, "C", True)
    pdf.cell(35, 7, "Remediation SLA", 1, 0, "C", True)
    pdf.cell(35, 7, "Status", 1, 1, "C", True)

    pdf.set_font("Helvetica", "", 8)
    for v in posture_data['sbom_vulns']:
        pdf.cell(40, 6, v['cve_id'], 1)
        pdf.cell(30, 6, v['package'], 1)
        pdf.cell(25, 6, v['severity'], 1, 0, "C")
        pdf.cell(25, 6, v['epss'], 1, 0, "C")
        pdf.cell(35, 6, v['sla_deadline'], 1, 0, "C")
        pdf.cell(35, 6, v['status'], 1, 1, "C")
    
    if not posture_data['sbom_vulns']:
        pdf.cell(190, 6, "No open critical or high CVEs identified in local packages.", 1, 1, "C")

    pdf.ln(8)

    # Attack Surface Network Daemons
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 8, "3. Network Attack Surface & MITRE ATT&CK Mapping", ln=True)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_fill_color(226, 232, 240)
    pdf.cell(25, 7, "Port", 1, 0, "C", True)
    pdf.cell(45, 7, "Daemon / Process", 1, 0, "L", True)
    pdf.cell(30, 7, "PID", 1, 0, "C", True)
    pdf.cell(90, 7, "MITRE ATT&CK Classification", 1, 1, "L", True)

    pdf.set_font("Helvetica", "", 8)
    for s in posture_data['sockets']:
        pdf.cell(25, 6, f"{s['port']}/{s['protocol']}", 1, 0, "C")
        pdf.cell(45, 6, s['process_name'], 1)
        pdf.cell(30, 6, str(s['pid']), 1, 0, "C")
        pdf.cell(90, 6, f"{s['mitre']['technique']} - {s['mitre']['name']}", 1, 1)

    pdf.output(filepath)
    return filepath
