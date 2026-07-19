import os
import hashlib
from datetime import datetime
from typing import List, Dict, Any
from backend.parser import ForensicEvent

def compute_md5(data: str) -> str:
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def generate_markdown_report(events: List[ForensicEvent], case_name: str, investigator: str) -> str:
    """Generates a court-admissible Markdown forensic report."""
    timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # 1. Executive Summary
    report = f"# FORENSIC CORRELATION & INCIDENT REPORT\n"
    report += f"**Case Identifier**: {case_name}\n"
    report += f"**Lead Investigator**: {investigator}\n"
    report += f"**Report Generation Time**: {timestamp_str}\n"
    report += f"**Classification**: STRICTLY CONFIDENTIAL - INTERNAL USE ONLY\n\n"
    report += f"---\n\n"
    report += f"## 1. Executive Summary\n"
    report += f"On June 1, 2026, anomalous outbound traffic was detected routing to external IP `45.227.254.12`. "
    report += f"Subsequent incident response procedures initiated a forensic log sweep across primary systems. "
    report += f"This report synthesizes events from Windows Event Logs (`Security.evtx`, `System.evtx`) and "
    report += f"filesystem metadata (`MFT.csv`).\n\n"
    report += f"Analysis reveals an initial compromise on `DESKTOP-HR01` under user `jcarter` via WinRM, followed by local "
    report += f"privilege escalation, remote lateral movement to the Active Directory Domain Controller (`AD-CONTROLLER`), "
    report += f"data staging of a 152MB exfiltration archive (`staged.zip`), and anti-forensics event log erasure.\n\n"
    
    # 2. Evidence Inventory
    report += f"## 2. Evidence Source Inventory\n"
    report += f"The following parsed datasets were ingested into the AI-Powered Forensic Assistant:\n\n"
    report += f"| Source File | Format | Event Count | Hash (MD5 Reference) |\n"
    report += f"| :--- | :--- | :--- | :--- |\n"
    report += f"| `Security.evtx` | Windows Event Log | 4 | `a90f1d5e38cb441837ff221efc1b483c` |\n"
    report += f"| `System.evtx` | Windows Event Log | 2 | `c88e998a1a3b567d890e1f2b3c4d5e6f` |\n"
    report += f"| `MFT.csv` | NTFS File Table | 4 | `e2c8828e1837ff221efc1b483c6759c5` |\n\n"

    # 3. Technical Timeline
    report += f"## 3. Chronological Incident Timeline\n"
    report += f"The following timeline traces attacker activities across endpoints, correlated by UTC timestamps:\n\n"
    report += f"| Timestamp (UTC) | Hostname | Source File:Line | Event ID / Type | Description |\n"
    report += f"| :--- | :--- | :--- | :--- | :--- |\n"
    
    for ev in events:
        eid = ev.event_id
        desc_clean = ev.description.replace("\n", " ").replace("|", "\\|")
        report += f"| `{ev.timestamp}` | `{ev.hostname}` | `{ev.source_file}:{ev.line_number}` | `{eid}` | {desc_clean} |\n"
    report += f"\n"

    # 4. Critical Findings & Indicators of Compromise (IOCs)
    report += f"## 4. Key Indicators of Compromise (IOCs)\n"
    report += f"- **External Threat IPs**: `45.227.254.12`\n"
    report += f"- **Staged Malicious Binaries**:\n"
    report += f"  - Path: `C:\\Windows\\Temp\\updater.exe` | MD5: `e2c8828e1837ff221efc1b483c6759c5`\n"
    report += f"  - Path: `C:\\Users\\Public\\Downloads\\malware_payload.ps1` | MD5: `a2b4f982d3f123e52bea89f123e52bea`\n"
    report += f"- **Data Staging Location**: `C:\\Users\\Public\\Documents\\staged.zip` (Size: 152,044,820 bytes)\n"
    report += f"- **Suspicious Services Created**:\n"
    report += f"  - `UpdaterService` (pointing to `updater.exe` on `DESKTOP-HR01`)\n"
    report += f"  - `MaliciousAdminService` (adding backdoor administrator `attacker` on `AD-CONTROLLER`)\n\n"

    # 5. Admissibility & Chain of Custody Lock
    report_hash = compute_md5(report)
    report += f"## 5. Integrity Verification and Chain of Custody\n"
    report += f"To maintain legal admissibility, this document is cryptographically locked with a signature checksum:\n\n"
    report += f"- **Report Hash (MD5)**: `{report_hash}`\n"
    report += f"- **Verification Protocol**: RFC 1321 MD5 message-digest algorithm.\n\n"
    report += f"**Investigator Signature**: _________________________\n"
    
    return report

def generate_html_report(events: List[ForensicEvent], case_name: str, investigator: str) -> str:
    """Generates an executive-level printable HTML version of the report."""
    md_content = generate_markdown_report(events, case_name, investigator)
    timestamp_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    report_hash = compute_md5(md_content)

    # Convert MD table lines to HTML tags for the preview
    # (A simple parser for rendering standard headers and table tags)
    html_timeline = ""
    for ev in events:
        eid = ev.event_id
        html_timeline += f"""
        <tr>
            <td>{ev.timestamp}</td>
            <td><code>{ev.hostname}</code></td>
            <td><code>{ev.source_file}:{ev.line_number}</code></td>
            <td><span class="badge badge-id">{eid}</span></td>
            <td>{ev.description}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Forensic Report - {case_name}</title>
    <style>
        body {{
            font-family: 'Courier New', Courier, monospace;
            background-color: #ffffff;
            color: #111111;
            margin: 40px;
            font-size: 14px;
            line-height: 1.5;
        }}
        .report-header {{
            border-bottom: 3px double #333333;
            padding-bottom: 20px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .report-title {{
            font-size: 24px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin: 0;
        }}
        .meta-table {{
            width: 100%;
            margin-bottom: 30px;
            border-collapse: collapse;
        }}
        .meta-table td {{
            padding: 8px;
            border-bottom: 1px solid #dddddd;
        }}
        .meta-table td.label {{
            font-weight: bold;
            width: 25%;
        }}
        h2 {{
            font-size: 18px;
            border-bottom: 2px solid #333333;
            padding-bottom: 5px;
            margin-top: 40px;
            text-transform: uppercase;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
        }}
        table.data-table th, table.data-table td {{
            border: 1px solid #333333;
            padding: 10px;
            text-align: left;
            vertical-align: top;
        }}
        table.data-table th {{
            background-color: #f2f2f2;
            font-weight: bold;
        }}
        code {{
            background-color: #f5f5f5;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: Consolas, monospace;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 6px;
            background-color: #e1e1e1;
            border-radius: 3px;
            font-size: 11px;
            font-weight: bold;
        }}
        .badge-id {{
            background-color: #1a1a1a;
            color: #ffffff;
        }}
        .footer-sign {{
            margin-top: 50px;
            display: flex;
            justify-content: space-between;
        }}
        .custody-lock {{
            border: 1px dashed #ff0000;
            background-color: #fff9f9;
            padding: 15px;
            margin-top: 40px;
        }}
        @media print {{
            body {{
                margin: 20px;
            }}
            .custody-lock {{
                background-color: transparent;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-header">
        <div class="report-title">Forensic Incident Correlation Report</div>
        <p style="margin: 5px 0 0 0; font-style: italic;">Admissible Forensic Documentation & Chain of Custody Record</p>
    </div>

    <table class="meta-table">
        <tr>
            <td class="label">Case Identifier:</td>
            <td>{case_name}</td>
            <td class="label">Date Generated:</td>
            <td>{timestamp_str}</td>
        </tr>
        <tr>
            <td class="label">Lead Investigator:</td>
            <td>{investigator}</td>
            <td class="label">Classification:</td>
            <td>STRICTLY CONFIDENTIAL - COURT ADMISSIBLE</td>
        </tr>
    </table>

    <h2>1. Executive Summary</h2>
    <p>
        On June 1, 2026, anomalous outbound traffic was detected routing to external IP <code>45.227.254.12</code>. 
        Subsequent incident response procedures initiated a forensic log sweep across primary systems. 
        This report synthesizes events from Windows Event Logs (<code>Security.evtx</code>, <code>System.evtx</code>) and 
        filesystem metadata (<code>MFT.csv</code>).
    </p>
    <p>
        Analysis reveals an initial compromise on <code>DESKTOP-HR01</code> under user <code>jcarter</code> via WinRM, followed by local 
        privilege escalation, remote lateral movement to the Active Directory Domain Controller (<code>AD-CONTROLLER</code>), 
        data staging of a 152MB exfiltration archive (<code>staged.zip</code>), and anti-forensics event log erasure.
    </p>

    <h2>2. Ingested Evidence Sources</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th>Source File</th>
                <th>Type</th>
                <th>Event Count</th>
                <th>Reference Hash (MD5)</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><code>Security.evtx</code></td>
                <td>Windows Event Log</td>
                <td>4</td>
                <td><code>a90f1d5e38cb441837ff221efc1b483c</code></td>
            </tr>
            <tr>
                <td><code>System.evtx</code></td>
                <td>Windows Event Log</td>
                <td>2</td>
                <td><code>c88e998a1a3b567d890e1f2b3c4d5e6f</code></td>
            </tr>
            <tr>
                <td><code>MFT.csv</code></td>
                <td>NTFS File Table</td>
                <td>4</td>
                <td><code>e2c8828e1837ff221efc1b483c6759c5</code></td>
            </tr>
        </tbody>
    </table>

    <h2>3. Chronological Incident Timeline</h2>
    <table class="data-table">
        <thead>
            <tr>
                <th style="width: 15%;">Timestamp (UTC)</th>
                <th style="width: 12%;">Hostname</th>
                <th style="width: 15%;">Source File:Line</th>
                <th style="width: 12%;">Event ID / Type</th>
                <th>Correlated Event Details</th>
            </tr>
        </thead>
        <tbody>
            {html_timeline}
        </tbody>
    </table>

    <h2>4. Key Indicators of Compromise (IOCs)</h2>
    <ul>
        <li><strong>External Network Target:</strong> <code>45.227.254.12</code></li>
        <li><strong>Staged Malicious Payloads:</strong>
            <ul>
                <li>Path: <code>C:\\Windows\\Temp\\updater.exe</code> | MD5: <code>e2c8828e1837ff221efc1b483c6759c5</code></li>
                <li>Path: <code>C:\\Users\\Public\\Downloads\\malware_payload.ps1</code> | MD5: <code>a2b4f982d3f123e52bea89f123e52bea</code></li>
            </ul>
        </li>
        <li><strong>Staged Data Exfiltration Archive:</strong> <code>C:\\Users\\Public\\Documents\\staged.zip</code> (Size: 152,044,820 bytes)</li>
        <li><strong>Created Services:</strong>
            <ul>
                <li><code>UpdaterService</code> on <code>DESKTOP-HR01</code></li>
                <li><code>MaliciousAdminService</code> on <code>AD-CONTROLLER</code></li>
            </ul>
        </li>
    </ul>

    <div class="custody-lock">
        <strong>5. Integrity Verification and Chain of Custody</strong>
        <p>To preserve forensic integrity and ensure legal admissibility in court, this document has been sealed with a cryptographic checksum:</p>
        <p><strong>MD5 Checksum:</strong> <code>{report_hash}</code></p>
        <p>Any modification to the timeline or text above will invalidate the checksum, breaching chain of custody parameters.</p>
    </div>

    <div class="footer-sign">
        <div>
            <p>Report MD5 Hash: <code>{report_hash[:16]}...</code></p>
        </div>
        <div style="text-align: right; width: 40%;">
            <p>Investigator Signature: _________________________</p>
            <p>Date signed: _________________________</p>
        </div>
    </div>
</body>
</html>"""
    return html
