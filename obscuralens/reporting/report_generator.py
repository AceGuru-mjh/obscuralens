"""
Report Generator Module
Generates comprehensive OSINT reports in multiple formats
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Template

from .. import __version__
from ..config import config


class ReportGenerator:
    """Generate OSINT reports in multiple formats"""

    def __init__(self, output_dir: Optional[str] = None):
        self.output_dir = Path(output_dir or config.app_config.report_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_html_report(self, data: Dict[str, Any],
                            title: str = "OSINT Report") -> str:
        """
        Generate an HTML report file.

        Args:
            data: Report data
            title: Report title

        Returns:
            Path to generated report
        """
        html_content = self.render_html(data, title)

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        output_path = self.output_dir / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return str(output_path)

    def render_html(self, data: Dict[str, Any],
                    title: str = "OSINT Report") -> str:
        """Render a report as an HTML string."""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #ffffff;
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        h1 {
            color: #00ff88;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }

        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
        }

        .section {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #00ff88;
        }

        .section h2 {
            color: #00ff88;
            margin-bottom: 15px;
            font-size: 1.5em;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
        }

        .info-item {
            background: rgba(0, 0, 0, 0.2);
            padding: 15px;
            border-radius: 8px;
        }

        .info-label {
            color: #888;
            font-size: 0.9em;
            margin-bottom: 5px;
        }

        .info-value {
            color: #ffffff;
            font-size: 1.1em;
            font-weight: bold;
        }

        .status-success {
            color: #00ff88;
        }

        .status-error {
            color: #ff4757;
        }

        .status-warning {
            color: #ffe66d;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        th {
            background: rgba(0, 255, 136, 0.1);
            color: #00ff88;
        }

        tr:hover {
            background: rgba(255, 255, 255, 0.05);
        }

        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
            color: #888;
        }

        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }

        .badge-success {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
        }

        .badge-error {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
        }

        .badge-warning {
            background: rgba(255, 230, 109, 0.2);
            color: #ffe66d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>{{ title }}</h1>
        <p class="subtitle">Generated on {{ timestamp }}</p>

        {% for section in sections %}
        <div class="section">
            <h2>{{ section.title }}</h2>

            {% if section.type == 'grid' %}
            <div class="info-grid">
                {% for key, value in section.data.items() %}
                <div class="info-item">
                    <div class="info-label">{{ key }}</div>
                    <div class="info-value">{{ value }}</div>
                </div>
                {% endfor %}
            </div>

            {% elif section.type == 'table' %}
            <table>
                <thead>
                    <tr>
                        {% for col in section.columns %}
                        <th>{{ col }}</th>
                        {% endfor %}
                    </tr>
                </thead>
                <tbody>
                    {% for row in section.rows %}
                    <tr>
                        {% for cell in row %}
                        <td>{{ cell }}</td>
                        {% endfor %}
                    </tr>
                    {% endfor %}
                </tbody>
            </table>

            {% elif section.type == 'text' %}
            <p>{{ section.content }}</p>

            {% elif section.type == 'status' %}
            <span class="badge badge-{{ section.status_class }}">
                {{ section.status }}
            </span>
            {% endif %}
        </div>
        {% endfor %}

        <div class="footer">
            <p>Generated by ObscuraLens v{{ version }} | Advanced OSINT Tool</p>
        </div>
    </div>
</body>
</html>
        """

        template = Template(template_str)

        return template.render(
            title=title,
            version=__version__,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            sections=data.get('sections', [])
        )

    def generate_json_report(self, data: Dict[str, Any],
                            title: str = "OSINT Report") -> str:
        """
        Generate a JSON report

        Args:
            data: Report data
            title: Report title

        Returns:
            Path to generated report
        """
        report_data = {
            'title': title,
            'timestamp': datetime.now().isoformat(),
            'data': data
        }

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        output_path = self.output_dir / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        return str(output_path)

    def generate_csv_report(self, data: List[Dict[str, Any]],
                           filename: str = "report.csv") -> str:
        """
        Generate a CSV report

        Args:
            data: List of dictionaries
            filename: Output filename

        Returns:
            Path to generated report
        """
        if not data:
            return ""

        output_path = self.output_dir / filename

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)

        return str(output_path)

    def generate_markdown_report(self, data: Dict[str, Any],
                                title: str = "OSINT Report") -> str:
        """
        Generate a Markdown report file.

        Args:
            data: Report data
            title: Report title

        Returns:
            Path to generated report
        """
        md_content = self.render_markdown(data, title)

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        output_path = self.output_dir / filename

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_content)

        return str(output_path)

    def render_markdown(self, data: Dict[str, Any],
                        title: str = "OSINT Report") -> str:
        """Render a report as a Markdown string."""
        md_content = f"# {title}\n\n"
        md_content += f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        md_content += "---\n\n"

        for section in data.get('sections', []):
            md_content += f"## {section['title']}\n\n"

            if section['type'] == 'grid':
                for key, value in section['data'].items():
                    md_content += f"- **{key}:** {value}\n"
                md_content += "\n"

            elif section['type'] == 'table':
                if section['rows']:
                    md_content += "| " + " | ".join(section['columns']) + " |\n"
                    md_content += "| " + " | ".join(["---"] * len(section['columns'])) + " |\n"
                    for row in section['rows']:
                        md_content += "| " + " | ".join(str(cell) for cell in row) + " |\n"
                    md_content += "\n"

            elif section['type'] == 'text':
                md_content += f"{section['content']}\n\n"

            elif section['type'] == 'status':
                status_emoji = "✅" if section['status_class'] == 'success' else "❌" if section['status_class'] == 'error' else "⚠️"
                md_content += f"{status_emoji} **Status:** {section['status']}\n\n"

        md_content += "---\n\n"
        md_content += f"*Generated by ObscuraLens v{__version__}*\n"

        return md_content

    def generate_pdf_report(self, data: Dict[str, Any],
                           title: str = "OSINT Report") -> str:
        """
        Generate a PDF report

        Args:
            data: Report data
            title: Report title

        Returns:
            Path to generated report
        """
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import inch
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
        except ImportError:
            return "ReportLab library not installed. Install with: pip install reportlab"

        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        output_path = self.output_dir / filename

        doc = SimpleDocTemplate(str(output_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#00ff88'),
            spaceAfter=30
        )
        story.append(Paragraph(title, title_style))
        story.append(Spacer(1, 12))

        # Timestamp
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles['Normal']
        ))
        story.append(Spacer(1, 20))

        # Sections
        for section in data.get('sections', []):
            story.append(Paragraph(section['title'], styles['Heading2']))
            story.append(Spacer(1, 12))

            if section['type'] == 'grid':
                table_data = [[key, str(value)] for key, value in section['data'].items()]
                table = Table(table_data, colWidths=[2*inch, 4*inch])
                table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#1a1a2e')),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                    ('BACKGROUND', (1, 0), (1, -1), colors.HexColor('#16213e')),
                    ('GRID', (0, 0), (-1, -1), 1, colors.grey)
                ]))
                story.append(table)

            elif section['type'] == 'text':
                story.append(Paragraph(section['content'], styles['Normal']))

            story.append(Spacer(1, 20))

        doc.build(story)

        return str(output_path)
