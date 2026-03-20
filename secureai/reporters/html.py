"""
SecureAI Platform — HTML Report Generator
==========================================
Generates professional HTML security reports from scan findings.

Why HTML reports:
- Shareable with non-technical stakeholders
- Professional appearance for interviews and demos
- Self-contained — single file, no dependencies
- Printable to PDF from any browser

The report includes:
- Executive summary (for managers)
- Technical findings table (for engineers)
- Severity breakdown chart
- Remediation recommendations
- Timestamp and scan metadata
"""

import os
from datetime import datetime
from secureai.utils.output import console


class HTMLReporter:
    """
    Generates professional HTML security reports.

    Args:
        output_dir: directory to write reports to (default: reports/)
    """

    def __init__(self, output_dir: str = "reports/"):
        self.output_dir = output_dir

        # Create output directory if it doesn't exist
        # exist_ok=True prevents error if directory already exists
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, findings: list) -> str:
        """
        Generates an HTML report from a list of findings.

        Args:
            findings: list of finding dicts from scanners

        Returns:
            path to the generated report file
        """
        # Count findings by severity for summary
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "LOW").upper()
            if sev in counts:
                counts[sev] += 1

        # Generate timestamp for report filename
        # Format: YYYY-MM-DD-HHMMSS for easy sorting
        timestamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
        report_path = os.path.join(
            self.output_dir, f"secureai-report-{timestamp}.html"
        )

        # Build the HTML report
        html = self._build_html(findings, counts, timestamp)

        # Write to file
        with open(report_path, "w") as f:
            f.write(html)

        return report_path

    def _build_html(
        self, findings: list, counts: dict, timestamp: str
    ) -> str:
        """
        Builds the complete HTML report as a string.
        Uses inline CSS — no external dependencies, fully portable.
        """
        # Generate findings rows for the HTML table
        findings_rows = ""
        for finding in findings:
            severity = finding.get("severity", "LOW")
            color_map = {
                "CRITICAL": "#dc2626",
                "HIGH": "#ea580c",
                "MEDIUM": "#d97706",
                "LOW": "#2563eb"
            }
            color = color_map.get(severity, "#6b7280")

            findings_rows += f"""
            <tr>
                <td>
                    <span style="
                        background: {color};
                        color: white;
                        padding: 2px 8px;
                        border-radius: 4px;
                        font-size: 12px;
                        font-weight: bold;
                    ">{severity}</span>
                </td>
                <td>{finding.get('title', 'N/A')}</td>
                <td><code>{finding.get('file', 'N/A')}</code></td>
                <td>{finding.get('remediation', 'See documentation')}</td>
            </tr>
            """

        total = sum(counts.values())

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureAI Security Report — {timestamp}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont,
                         'Segoe UI', sans-serif;
            background: #f8fafc;
            color: #1e293b;
            padding: 2rem;
        }}
        .header {{
            background: #1e293b;
            color: white;
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
        }}
        .header h1 {{ font-size: 24px; margin-bottom: 4px; }}
        .header p {{ color: #94a3b8; font-size: 14px; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid #e2e8f0;
        }}
        .card .number {{
            font-size: 36px;
            font-weight: bold;
            margin-bottom: 4px;
        }}
        .card .label {{
            font-size: 12px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .critical .number {{ color: #dc2626; }}
        .high .number {{ color: #ea580c; }}
        .medium .number {{ color: #d97706; }}
        .low .number {{ color: #2563eb; }}
        .section {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid #e2e8f0;
        }}
        .section h2 {{
            font-size: 16px;
            margin-bottom: 1rem;
            color: #1e293b;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            text-align: left;
            padding: 8px 12px;
            background: #f1f5f9;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #64748b;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #f1f5f9;
            font-size: 14px;
            vertical-align: top;
        }}
        code {{
            background: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 12px;
            font-family: 'Courier New', monospace;
        }}
        .footer {{
            text-align: center;
            color: #94a3b8;
            font-size: 12px;
            margin-top: 2rem;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SecureAI Platform — Security Report</h1>
        <p>Generated: {timestamp} | Total Findings: {total}</p>
        <p>Jemel Padilla | Cloud Security Engineer</p>
    </div>

    <div class="summary">
        <div class="card critical">
            <div class="number">{counts['CRITICAL']}</div>
            <div class="label">Critical</div>
        </div>
        <div class="card high">
            <div class="number">{counts['HIGH']}</div>
            <div class="label">High</div>
        </div>
        <div class="card medium">
            <div class="number">{counts['MEDIUM']}</div>
            <div class="label">Medium</div>
        </div>
        <div class="card low">
            <div class="number">{counts['LOW']}</div>
            <div class="label">Low</div>
        </div>
    </div>

    <div class="section">
        <h2>Executive Summary</h2>
        <p style="color: #64748b; line-height: 1.6;">
            SecureAI Platform scanned your infrastructure and found
            <strong>{total} security findings</strong>.
            {'<span style="color: #dc2626; font-weight: bold;">' +
             str(counts['CRITICAL']) +
             ' CRITICAL findings require immediate attention.</span>'
             if counts['CRITICAL'] > 0 else
             'No CRITICAL findings detected.'}
            Review all HIGH severity findings within 48 hours.
        </p>
    </div>

    <div class="section">
        <h2>Findings</h2>
        {'<p style="color: #16a34a;">No findings detected.</p>'
         if not findings else f"""
        <table>
            <thead>
                <tr>
                    <th width="10%">Severity</th>
                    <th width="25%">Finding</th>
                    <th width="25%">Location</th>
                    <th width="40%">Remediation</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>"""}
    </div>

    <div class="footer">
        <p>SecureAI Platform — AI-powered cloud security auditing</p>
        <p>github.com/JayKnowSo | linkedin.com/in/jemelpadilla</p>
    </div>
</body>
</html>"""