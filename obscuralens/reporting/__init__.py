"""
Report generation modules
"""

from .report_generator import ReportGenerator
from .sections import (
    batch_sections,
    domain_sections,
    email_sections,
    ip_sections,
    phone_sections,
    sections_for,
    sources_table,
    username_sections,
)
from .template_render import (
    available_templates,
    render_markdown_report,
    render_report,
    render_standalone_html_report,
)

__all__ = [
    'ReportGenerator',
    'ip_sections', 'phone_sections', 'username_sections', 'email_sections',
    'domain_sections', 'batch_sections', 'sections_for', 'sources_table',
    'available_templates', 'render_report',
    'render_markdown_report', 'render_standalone_html_report',
]
