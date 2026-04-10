"""Forensic report generator implementation.

Provides `ForensicReportGenerator` for creating detailed forensic reports
in JSON and PDF formats.
"""
import json
import os
import html
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image

from ..utils.exiftool_formatter import ExifToolStyleFormatter


class ForensicReportGenerator:
    """Generates forensic reports in multiple formats."""

    def __init__(self, config: Dict[str, Any] | None = None):
        self.config = config or {}

    def generate(self, title: str | None = None, analysis_results: Dict[str, Any] | None = None, 
                 output_format: str = 'json', output_path: str | None = None, 
                 output_dir: str | None = None, formats: List[str] | None = None) -> Dict[str, Any]:
        """
        Generate forensic reports.
        
        Args:
            title: Report title.
            analysis_results: Dictionary containing analysis data.
            output_format: Primary format (deprecated, use formats).
            output_path: Specific output path (optional).
            output_dir: Directory to save reports.
            formats: List of formats to generate ['json', 'pdf'].
            
        Returns:
            Dictionary of generated report paths.
        """
        if not analysis_results:
            return {'error': 'No analysis results provided'}

        # Determine output location
        if output_dir:
            out_dir_path = Path(output_dir)
        elif output_path:
            out_dir_path = Path(output_path).parent
        else:
            out_dir_path = Path('results/reports')
        
        out_dir_path.mkdir(parents=True, exist_ok=True)
        
        # Base filename — always use image name
        image_path = analysis_results.get('evidence_integrity', {}).get('file_path') or \
                     analysis_results.get('image_path')
        base_name = Path(image_path).stem if image_path else f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # Case info (used for folder naming at call site, kept here for reference)
        case_info = analysis_results.get('case_info', {})

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_paths = {}
        
        target_formats = formats or [output_format]
        if 'both' in target_formats:
            target_formats = ['json', 'pdf']
        elif 'all' in target_formats:
            target_formats = ['pdf', 'html', 'txt']

        # Generate JSON
        if 'json' in target_formats:
            json_path = out_dir_path / f"{base_name}_{timestamp}.json"
            self._write_json(analysis_results, json_path)
            report_paths['json'] = str(json_path)

        # Generate HTML
        if 'html' in target_formats:
            html_path = out_dir_path / f"{base_name}_{timestamp}.html"
            self._write_html(title or "Forensic Analysis Report", analysis_results, html_path)
            report_paths['html'] = str(html_path)

        # Generate PDF
        if 'pdf' in target_formats:
            pdf_path = out_dir_path / f"{base_name}_{timestamp}.pdf"
            self._write_pdf(title or "Forensic Analysis Report", analysis_results, pdf_path)
            report_paths['pdf'] = str(pdf_path)

        # Generate Text
        if 'txt' in target_formats or 'text' in target_formats:
            txt_path = out_dir_path / f"{base_name}_{timestamp}.txt"
            self._write_text(analysis_results, txt_path)
            report_paths['txt'] = str(txt_path)

        return report_paths

    def _is_portrait_mobile_screenshot(self, data: Dict[str, Any]) -> bool:
        origin = data.get('origin_detection', {}) or {}
        screenshot_info = origin.get('screenshot_device_info', {}) or {}
        dev_type = str(screenshot_info.get('device_type') or '')
        capture_mode = str(screenshot_info.get('capture_mode') or '')
        os_detected = str(screenshot_info.get('os_detected') or '')
        source_inf = str(origin.get('source_inference') or '')
        android_screenshot = bool(
            screenshot_info.get('android_screenshot_analysis', {})
            .get('is_android_screenshot')
        )

        return (
            'Portrait' in dev_type
            or 'Portrait' in capture_mode
            or (
                android_screenshot and
                'Android' in os_detected and
                ('Android Screenshot' in source_inf or 'Mobile Device (Portrait)' in source_inf or source_inf == 'Camera')
            )
        )

    def _display_interpretation(self, data: Dict[str, Any]) -> str:
        risk = data.get('risk_assessment', {}) or {}
        if self._is_portrait_mobile_screenshot(data):
            return 'SYNTHETIC_CONTENT'
        return self._normalize_interpretation_label(risk.get('unified_interpretation', 'UNKNOWN'))

    def _display_detected_software(self, data: Dict[str, Any]) -> List[Any]:
        history = data.get('modification_history', {}) or {}
        software = list(history.get('software_detected', []) or [])
        if software:
            return software
        if self._is_portrait_mobile_screenshot(data):
            return ['Android']
        return []

    def _get_ai_origin_agent(self, data: Dict[str, Any]) -> str | None:
        c2pa = data.get('c2pa', {}) or data.get('metadata', {}).get('c2pa', {}) or {}
        agent_name = str(c2pa.get('Actions Software Agent Name') or '').strip()
        return agent_name or None

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _is_named_camera_device(self, value: Any) -> bool:
        text = str(value or '').strip()
        if not text or text.lower() in {'unknown', 'camera', 'screenshot', 'unknown device', 'mobile device', 'none', 'none none', 'null', 'null null'}:
            return False
        disallowed_tokens = ['screenshot', 'desktop', 'laptop', 'windowed application capture', 'mobile device', 'virtual']
        return not any(token in text.lower() for token in disallowed_tokens)

    def _resolve_camera_device_name(self, data: Dict[str, Any], fallback: Any = 'Unknown') -> str:
        origin = self._as_dict(data.get('origin_detection'))
        metadata = self._as_dict(data.get('metadata'))
        summary = self._as_dict(metadata.get('summary'))
        exif = self._as_dict(metadata.get('exif'))
        features = self._as_dict(origin.get('features'))

        candidates = [
            origin.get('capture_device_inference'),
            features.get('capture_device_inference'),
            f"{summary.get('camera_make', '')} {summary.get('camera_model', '')}".strip(),
            f"{exif.get('Make', '')} {exif.get('Model', '')}".strip(),
            f"{exif.get('Image Make', '')} {exif.get('Image Model', '')}".strip(),
            f"{exif.get('EXIF Make', '')} {exif.get('EXIF Model', '')}".strip(),
            summary.get('camera_model'),
            exif.get('Model'),
            exif.get('Image Model'),
            exif.get('EXIF Model'),
            fallback,
        ]

        for candidate in candidates:
            text = str(candidate or '').strip()
            if self._is_named_camera_device(text):
                return text

        return str(fallback or 'Unknown').strip() or 'Unknown'

    def _format_origin_strings(self, data: Dict[str, Any]) -> tuple[str, str]:
        """Format the Origin and Source Inference strings based on broad category and specific device rules."""
        origin = self._as_dict(data.get('origin_detection'))
        features = self._as_dict(origin.get('features'))
        screenshot_info = self._as_dict(origin.get('screenshot_device_info'))
        origin_label = origin.get('primary_origin', 'Unknown')
        source_inf = origin.get('source_inference', 'Unknown')
        capture_device = self._resolve_camera_device_name(data, fallback=(
            origin.get('capture_device_inference')
            or features.get('capture_device_inference')
            or source_inf
        ))
        
        if origin_label in ['camera_original', 'camera_post_processed']:
            display_source = "Camera"
        elif origin_label == 'synthetic_ai_generated':
            display_source = "AI Generated"
        elif origin_label == 'screenshot_capture':
            display_source = "Screenshot"
        elif origin_label in ['software_reencoded', 'software_generated']:
            display_source = "Software Re-encoded / Generated"
        else:
            display_source = "Unknown"

        if display_source == "Unknown" and self._is_named_camera_device(capture_device):
            display_source = "Camera"

        display_origin = capture_device
        dev_type = screenshot_info.get('device_type', '') or ''
        os_detected = screenshot_info.get('os_detected', '') or ''
        software_blob = str(
            features.get('software')
            or features.get('capture_device_inference')
            or ''
        ).lower()
        windows_detected = os_detected == "Windows (10/11)" or any(token in software_blob for token in ["windows 11", "windows 10", "windows camera", "microsoft camera"])
        android_screenshot = bool(
            self._as_dict(screenshot_info.get('android_screenshot_analysis'))
            .get('is_android_screenshot')
        )
        if self._is_portrait_mobile_screenshot(data):
            display_source = "Screenshot"
            display_origin = "Mobile Device (Portrait)"
        elif android_screenshot:
            display_source = "Screenshot"
            display_origin = "Android"
        elif origin_label == 'screenshot_capture':
            display_origin = "DESKTOP/LAPTOP"
        elif origin_label == 'synthetic_ai_generated':
            display_origin = self._get_ai_origin_agent(data) or "AI Generated"
        
        if display_origin == "Mobile Device (Portrait)":
            pass
        elif "Android Screenshot" in str(display_origin):
            display_origin = "Android"
        elif str(display_origin).strip().lower() in {"none", "none none"} and origin_label == 'screenshot_capture':
            display_origin = "DESKTOP/LAPTOP"
        elif display_source == "Camera" and windows_detected:
            display_origin = "Desktop / Laptop"
        elif display_source == "Camera" and self._is_named_camera_device(capture_device):
            display_origin = capture_device
        elif display_origin in ["Camera", "Screenshot", "Unknown", "Unknown Device", "Mobile Device"]:
            if "Desktop" in dev_type:
                display_origin = "Desktop / Laptop"
            elif "Mobile" in dev_type or "Android" in dev_type:
                display_origin = "Android"
            elif origin_label == 'synthetic_ai_generated':
                display_origin = self._get_ai_origin_agent(data) or "AI Generated"
            else:
                display_origin = 'SYNTHETIC CONTENT' if origin_label == 'origin_unverified' else origin_label
                
        display_origin = display_origin.replace(" Screenshot", "").replace(" (Full Screen Capture)", "").replace(" (Windowed Application Capture)", "").replace(" (Portrait Screen Capture)", "")
        return display_origin, display_source

    def _normalize_interpretation_label(self, interpretation: Any) -> str:
        value = str(interpretation or 'UNKNOWN')
        if value == 'AUTHENTIC_WITH_POST_PROCESSING':
            return 'camera_post_processed'
        return value

    def _write_json(self, data: Dict[str, Any], path: Path) -> None:
        """Write data to JSON file."""
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, default=str)

    def _render_kv_table_html(self, payload: Dict[str, Any]) -> str:
        """Render a dictionary as a simple two-column HTML table."""
        if not isinstance(payload, dict) or not payload:
            return "<p>No data available.</p>"

        rows = []
        for key, value in payload.items():
            if isinstance(value, dict):
                if key in {'features', 'decision_trace'} and value:
                    nested_items = "".join(
                        [f"<li><strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}</li>" for k, v in value.items()]
                    )
                    rendered = f"<ul style='margin: 0; padding-left: 20px;'>{nested_items}</ul>"
                elif len(value) <= 6:
                    nested_items = "".join(
                        [f"<li><strong>{html.escape(str(k))}:</strong> {html.escape(str(v))}</li>" for k, v in value.items()]
                    )
                    rendered = f"<ul style='margin: 0; padding-left: 20px;'>{nested_items}</ul>"
                else:
                    rendered = f"{len(value)} fields"
            elif isinstance(value, list):
                if key == 'flags' and all(not isinstance(v, (dict, list)) for v in value):
                    if value:
                        rendered_items = "".join([f"<li>{html.escape(str(v))}</li>" for v in value])
                        rendered = f"<ul style='margin: 0; padding-left: 20px;'>{rendered_items}</ul>"
                    else:
                        rendered = "No flags"
                elif all(not isinstance(v, (dict, list)) for v in value) and len(value) <= 5:
                    rendered = ", ".join([html.escape(str(v)) for v in value]) if value else "0 items"
                else:
                    rendered = f"{len(value)} items"
            else:
                rendered = html.escape(str(value))
            rows.append(f"<tr><td>{html.escape(str(key))}</td><td>{rendered}</td></tr>")

        return f"""
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            {''.join(rows)}
        </table>
        """

    def _render_module_outputs_html(self, module_outputs: Dict[str, Any]) -> str:
        """Render explainability module outputs as readable cards."""
        if not isinstance(module_outputs, dict) or not module_outputs:
            return "<p>No module outputs available.</p>"

        cards = []
        for module_name, module_payload in module_outputs.items():
            if isinstance(module_payload, dict):
                summary_table = self._render_kv_table_html(module_payload)
            else:
                summary_table = self._render_kv_table_html({'value': module_payload})

            cards.append(f"""
            <div class="finding" style="border: 1px solid #d1d5da; border-radius: 8px; padding: 14px; margin-bottom: 12px; background: #fff;">
                <h3 style="margin: 0 0 8px 0; color: #2c3e50;">{html.escape(str(module_name).replace('_', ' ').title())}</h3>
                {summary_table}
            </div>
            """)

        return "".join(cards)

    def _render_forensic_reasoning_html(self, reasoning: Dict[str, Any]) -> str:
        """Render explain_forensic_reasoning as structured HTML sections."""
        if not isinstance(reasoning, dict) or not reasoning:
            return ""

        plain = reasoning.get('0_plain_language_summary', {})
        risk = reasoning.get('1_multi_domain_risk_assessment', {})
        severities = reasoning.get('2_evidence_severity_classification', [])
        conflict = reasoning.get('3_model_conflict_analysis', {})
        calibration = reasoning.get('4_bayesian_calibration_commentary', {})
        unified = reasoning.get('5_unified_interpretation_improved_classification', 'INCONCLUSIVE')
        confidence = reasoning.get('6_forensic_confidence_index', {})
        narrative = reasoning.get('7_narrative_forensic_summary', '')
        deterministic = conflict.get('deterministic_aggregation', {})
        bayesian = conflict.get('bayesian_predictive_model', {})

        severity_rows = ""
        for item in severities:
            severity_rows += (
                f"<tr><td>{html.escape(str(item.get('indicator', 'N/A')))}</td>"
                f"<td>{html.escape(str(item.get('severity', 'LOW')))}</td>"
                f"<td>{html.escape(str(item.get('reason', '')))}</td></tr>"
            )
        if not severity_rows:
            severity_rows = "<tr><td colspan='3'>No flagged indicators.</td></tr>"

        dominance = conflict.get('dominance_factors', [])
        dominance_html = "".join([f"<li>{html.escape(str(x))}</li>" for x in dominance]) or "<li>No dominance factors recorded.</li>"
        supports_html = "".join([f"<li>{html.escape(str(x))}</li>" for x in plain.get('what_supports_this', [])]) or "<li>No additional support points.</li>"
        limits_html = "".join([f"<li>{html.escape(str(x))}</li>" for x in plain.get('what_this_does_not_prove', [])]) or "<li>No limitations listed.</li>"

        return f"""
        <h2>Explain Output (Forensic Reasoning)</h2>
        <div class="metadata-box">
            <h3>0. Plain-Language Summary</h3>
            <p><strong>Simple Verdict:</strong> {html.escape(str(plain.get('simple_verdict', 'N/A')))}</p>
            <p><strong>Confidence:</strong> {html.escape(str(plain.get('plain_confidence', 'N/A')))}</p>
            <p><strong>What supports this:</strong></p>
            <ul>{supports_html}</ul>
            <p><strong>What this does not prove:</strong></p>
            <ul>{limits_html}</ul>
            <p>{html.escape(str(plain.get('recommended_reading', '')))}</p>

            <h3>1. Multi-Domain Risk Assessment</h3>
            {self._render_kv_table_html(risk)}

            <h3>2. Evidence Severity Classification</h3>
            <table>
                <tr><th>Indicator</th><th>Severity</th><th>Reason</th></tr>
                {severity_rows}
            </table>

            <h3>3. Model Conflict Analysis</h3>
            <p><strong>Conflict Detected:</strong> {conflict.get('conflict_detected', False)}</p>
            <p><strong>Deterministic Aggregation:</strong></p>
            {self._render_kv_table_html(deterministic)}
            <p><strong>Bayesian Predictive Model:</strong></p>
            {self._render_kv_table_html(bayesian)}
            <ul>{dominance_html}</ul>

            <h3>4. Bayesian Calibration Commentary</h3>
            <p><strong>Likelihood Overweighted:</strong> {calibration.get('likelihood_overweighted', False)}</p>
            <p>{html.escape(str(calibration.get('commentary', '')))}</p>

            <h3>5. Unified Interpretation (Improved Classification)</h3>
            <p><strong>{html.escape(str(unified))}</strong></p>

            <h3>6. Forensic Confidence Index</h3>
            <p><strong>Level:</strong> {html.escape(str(confidence.get('level', 'LOW')))}</p>
            <p>{html.escape(str(confidence.get('basis', '')))}</p>

            <h3>7. Narrative Forensic Summary</h3>
            <p>{html.escape(str(narrative))}</p>
        </div>
        """

    def _render_modification_history_html(self, history: Dict[str, Any]) -> str:
        """Render modification-history summary for HTML reports."""
        if not isinstance(history, dict) or not history:
            return "<p>No modification history available.</p>"

        event_rows = []
        for event in history.get('events', []):
            event_rows.append(
                f"<tr><td>{html.escape(str(event.get('event', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('timestamp', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('source', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('confidence', 'N/A')))}</td>"
                f"<td>{html.escape(str(event.get('details', '')))}</td></tr>"
            )

        if not event_rows:
            event_rows.append("<tr><td colspan='5'>No history events detected.</td></tr>")

        software_html = "".join([f"<li>{html.escape(str(item))}</li>" for item in history.get('software_detected', [])]) or "<li>No software markers detected.</li>"
        xmp_html = "".join([f"<li>{html.escape(str(item))}</li>" for item in history.get('xmp_history_entries', [])]) or "<li>No XMP history entries detected.</li>"

        return f"""
        <div class="metadata-box">
            <p><strong>Status:</strong> {html.escape(str(history.get('status', 'unknown')))}</p>
            <p><strong>Confidence:</strong> {html.escape(str(history.get('confidence', 'low')))}</p>
            <p><strong>Likely Modified:</strong> {html.escape(str(history.get('likely_modified', False)))}</p>
            <p><strong>Summary:</strong> {html.escape(str(history.get('summary', 'No summary available.')))}</p>
            <p><strong>Original Capture Time:</strong> {html.escape(str(history.get('original_capture_time', 'N/A')))}</p>
            <p><strong>Digitized Time:</strong> {html.escape(str(history.get('digitized_time', 'N/A')))}</p>
            <p><strong>File Modified Time:</strong> {html.escape(str(history.get('file_modified_time', 'N/A')))}</p>
            <p><strong>Software Detected:</strong></p>
            <ul>{software_html}</ul>
            <p><strong>XMP History Entries:</strong></p>
            <ul>{xmp_html}</ul>
            <table>
                <tr><th>Event</th><th>Timestamp</th><th>Source</th><th>Confidence</th><th>Details</th></tr>
                {''.join(event_rows)}
            </table>
        </div>
        """

    def _render_html_table(self, headers: List[str], rows: List[List[Any]]) -> str:
        """Render a simple HTML table with escaped content."""
        if not rows:
            return "<p>No data available.</p>"

        header_html = "".join([f"<th>{html.escape(str(header))}</th>" for header in headers])
        row_html = []
        for row in rows:
            cols = "".join([f"<td>{html.escape(self._compact_pdf_cell(cell, max_chars=500))}</td>" for cell in row])
            row_html.append(f"<tr>{cols}</tr>")
        return f"<table><tr>{header_html}</tr>{''.join(row_html)}</table>"

    def _render_html_bullets(self, items: List[Any], empty_text: str) -> str:
        """Render a bullet list matching PDF content blocks."""
        if not items:
            return f"<p>{html.escape(empty_text)}</p>"
        rendered = "".join([f"<li>{html.escape(self._compact_pdf_cell(item, max_chars=400))}</li>" for item in items])
        return f"<ul>{rendered}</ul>"

    def _render_html_kv_section(self, title: str, payload: Dict[str, Any]) -> str:
        """Render a titled key/value section for HTML."""
        if not payload:
            return ""
        rows = self._pdf_rows_from_mapping(payload)
        return f"""
        <h3>{html.escape(title)}</h3>
        <div class="metadata-box">
            {self._render_html_table(['Field', 'Value'], rows)}
        </div>
        """

    def _render_chatbox_identification_html(self, payload: Dict[str, Any]) -> str:
        """Render persisted MetaForensic AI chatbox identification details."""
        if not isinstance(payload, dict) or not payload:
            return ""

        summary_rows = [
            ['Question', payload.get('question', 'N/A')],
            ['Selected Module', payload.get('selected_module', 'N/A')],
            ['Normalized Intent', payload.get('normalized_intent', 'N/A')],
            ['Answer', payload.get('answer', 'N/A')],
            ['Confidence', f"{payload.get('confidence_percent', 'N/A')}% ({payload.get('confidence_level', 'N/A')})"],
            ['Summary', payload.get('summary', 'N/A')],
        ]
        return f"""
        <h2>MetaForensic AI Chatbox Identification</h2>
        <div class="metadata-box">
            {self._render_html_table(['Item', 'Details'], summary_rows)}
            <h3>Candidate Modules</h3>
            {self._render_html_bullets(payload.get('candidate_modules', []), 'No candidate modules recorded.')}
            <h3>Evidence Used</h3>
            {self._render_html_bullets(payload.get('evidence', []), 'No evidence lines recorded.')}
        </div>
        """

    def _summarize_for_pdf(self, value: Any) -> str:
        """Create concise, PDF-friendly summaries for complex values."""
        if isinstance(value, dict):
            return f"{len(value)} fields"
        if isinstance(value, list):
            if not value:
                return "0 items"
            if all(not isinstance(v, (dict, list)) for v in value):
                preview = ", ".join(str(v) for v in value[:3])
                suffix = " ..." if len(value) > 3 else ""
                return f"{len(value)} items: {preview}{suffix}"
            return f"{len(value)} items"
        return str(value)

    def _compact_pdf_cell(self, value: Any, max_chars: int = 400) -> str:
        """Normalize and truncate table cell text to keep rows printable in PDF."""
        if isinstance(value, (dict, list)):
            text = json.dumps(value, default=str)
        else:
            text = str(value)

        text = text.replace("\r\n", "\n").replace("\r", "\n")
        text = " | ".join(part.strip() for part in text.split("\n") if part.strip())

        if len(text) > max_chars:
            text = f"{text[:max_chars]} ... [truncated]"

        # Insert break opportunities in long unbroken tokens.
        return re.sub(r"(\S{60})", r"\1 ", text)

    def _write_html(self, title: str, data: Dict[str, Any], path: Path) -> None:
        """Generate a professional HTML forensic report."""
        include_raw = bool(data.get('include_raw', False))
        explain_mode = data.get('ai_mode') == 'explain' and not include_raw
        risk = data.get('risk_assessment', {})
        interpretation = self._display_interpretation(data)
        explainability = data.get('explainability_breakdown', {})
        explain_reasoning = data.get('explain_forensic_reasoning', {})
        modification_history = data.get('modification_history', {})
        assist = data.get('assist_suggestions', {})
        chatbox_identification = data.get('chatbox_identification', {})
        risk_score = risk.get('risk_score', risk.get('score', data.get('risk_score', 0)))
        level = risk.get('level', 'LOW')
        display_origin, display_source = self._format_origin_strings(data)
        origin_label = data.get('origin_detection', {}).get('primary_origin', 'Unknown')

        summary_rows = [
            ['Case Evidence', data.get('image_path') or data.get('evidence_integrity', {}).get('file_path', 'N/A')],
            ['Risk Score', f"{risk_score:.1f}/100 ({level})"],
            ['Unified Interpretation', interpretation],
            ['Primary Origin', display_origin],
            ['Source Inference', display_source],
            ['GPS Location', (data.get('location') or data.get('metadata', {}).get('location', {})).get('full_address') or (data.get('location') or data.get('metadata', {}).get('location', {})).get('location_name', 'No GPS data extracted')],
            ['Analysis Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        screenshot_rows = self._screenshot_device_rows(data) if origin_label == 'screenshot_capture' else []

        conclusion_rows = [
            ['Interpretation', interpretation.replace('_', ' ')],
            ['Risk Level', f"{risk.get('level', 'UNKNOWN')} ({risk.get('risk_score', 0):.1f}/100)"],
            ['Flag Count', str(len(data.get('flags', [])))],
            ['Explanation Count', str(len(data.get('explanations', [])))],
        ]

        domains = data.get('domains', {})
        screenshot_html = ""
        if screenshot_rows:
            screenshot_html = f"""
            <h2>Screenshot Device Analysis</h2>
            <div class=\"metadata-box\">{self._render_html_table(['Attribute', 'Value'], screenshot_rows)}</div>
            """
            screenshot_info = data.get('origin_detection', {}).get('screenshot_device_info', {}) or {}
            for label, items in [
                ('Key Evidence', screenshot_info.get('key_evidence', [])),
                ('Digital Markers', screenshot_info.get('digital_markers', [])),
                ('Limitations', screenshot_info.get('limitations', [])),
            ]:
                if items:
                    screenshot_html += f"<h3>{label}</h3><ul>" + ''.join(f"<li>{html.escape(str(item))}</li>" for item in items) + "</ul>"
        domain_html = ""
        if domains:
            fmt = domains.get('image_format', {})
            mfr = domains.get('manufacturer', {})
            domain_rows = [
                ['Format Domain', f"{fmt.get('label', 'N/A')} | {fmt.get('expertise', {}).get('forensics', 'No forensic note available')}"],
                ['Manufacturer Domain', f"{mfr.get('label', 'N/A')} | {mfr.get('expertise', {}).get('notes', 'No manufacturer note available')}"],
            ]
            domain_html = f"""
            <h2>Forensic Domain Expertise</h2>
            <div class="explanation-note"><strong>Explanation:</strong> This section provides specialized forensic context regarding the file format and device manufacturer, outlining known behaviors and artifacts specific to them.</div>
            <div class="metadata-box">{self._render_html_table(['Domain', 'Assessment'], domain_rows)}</div>
            """

        explanations_html = ""
        explanations = data.get('explanations', [])
        if explanations:
            explanation_blocks = []
            for index, exp in enumerate(explanations, start=1):
                exp_rows = [
                    ['Confidence', exp.get('confidence', 'N/A')],
                    ['Observation', exp.get('observation', 'N/A')],
                    ['Metadata Triggers', json.dumps(exp.get('triggers', {}), default=str)],
                    ['Forensic Logic', exp.get('logic', 'N/A')],
                    ['Expert Significance', exp.get('significance', 'N/A')],
                ]
                causes = exp.get('causes', {})
                explanation_blocks.append(f"""
                <div class="metadata-box">
                    <h3>Finding {index}: {html.escape(str(exp.get('title', 'Untitled finding')))} [{html.escape(str(exp.get('severity', 'INFO')))}]</h3>
                    {self._render_html_table(['Field', 'Explanation'], exp_rows)}
                    <h4 style="margin-top:15px; color:#2c3e50;">Causation Analysis</h4>
                    <p><strong>Legitimate Cause:</strong> {html.escape(str(causes.get('legitimate', 'N/A')))}</p>
                    <p><strong>Malicious Cause:</strong> {html.escape(str(causes.get('malicious', 'N/A')))}</p>
                </div>
                """)
            explanations_html = f"""
            <h2>Forensic Justifications (XAI)</h2>
            <div class="explanation-note"><strong>Explanation:</strong> Details the specific anomalies or flags found during the analysis, alongside expert significance and potential causes (both legitimate and malicious).</div>
            {''.join(explanation_blocks)}
            """

        modification_history_html = ""
        if modification_history:
            history_rows = [
                ['Status', modification_history.get('status', 'unknown')],
                ['Confidence', modification_history.get('confidence', 'low')],
                ['Likely Modified', modification_history.get('likely_modified', False)],
                ['Summary', modification_history.get('summary', 'No summary available.')],
                ['Original Capture Time', modification_history.get('original_capture_time', 'N/A')],
                ['Digitized Time', modification_history.get('digitized_time', 'N/A')],
                ['File Modified Time', modification_history.get('file_modified_time', 'N/A')],
            ]
            events_html = ""
            events = modification_history.get('events', [])
            if events:
                event_rows = []
                for event in events:
                    event_rows.append([
                        event.get('event', 'N/A'),
                        event.get('timestamp', 'N/A'),
                        event.get('source', 'N/A'),
                        f"{event.get('confidence', 'N/A')} | {event.get('details', '')}",
                    ])
                events_html = f"""
                <h3>Chronology of Events</h3>
                {self._render_html_table(['Event', 'Timestamp', 'Source', 'Assessment'], event_rows)}
                """
            modification_history_html = f"""
            <h2>Modification History</h2>
            <div class="explanation-note"><strong>Explanation:</strong> Outlines the file's lifecycle, identifying any editing software footprints and a chronological timeline of modifications.</div>
            <div class="metadata-box">
                {self._render_html_table(['History Item', 'Details'], history_rows)}
                <h3>Detected Software</h3>
                {self._render_html_bullets(self._display_detected_software(data), 'No software markers detected.')}
                <h3>XMP History Entries</h3>
                {self._render_html_bullets(modification_history.get('xmp_history_entries', []), 'No XMP history entries detected.')}
                {events_html}
            </div>
            """

        explainability_html = ""
        if explainability and not explain_mode:
            explain_rows = [
                ['Pipeline Mode', explainability.get('pipeline_mode', 'N/A')],
                ['Explanation Count', explainability.get('explanation_count', 0)],
                ['Explanation Titles', ", ".join(str(x) for x in explainability.get('explanation_titles', [])) or 'None'],
            ]
            module_outputs_html = ""
            module_outputs = explainability.get('module_outputs', {})
            if module_outputs:
                module_cards = []
                for module_name, module_payload in module_outputs.items():
                    if isinstance(module_payload, dict):
                        content = self._render_html_table(['Field', 'Value'], self._pdf_rows_from_mapping(module_payload))
                    else:
                        content = f"<p>{html.escape(self._summarize_for_pdf(module_payload))}</p>"
                    module_cards.append(f"""
                    <div class="metadata-box">
                        <h3>{html.escape(str(module_name).replace('_', ' ').title())}</h3>
                        {content}
                    </div>
                    """)
                module_outputs_html = f"<h3>Module Outputs</h3>{''.join(module_cards)}"

            explainability_html = f"""
            <h2>Explainability Breakdown</h2>
            <div class="explanation-note"><strong>Explanation:</strong> Gives visibility into the internal logic of the AI reasoning pipeline and how individual modules contributed to the findings.</div>
            <div class="metadata-box">
                {self._render_html_table(['Explainability Item', 'Value'], explain_rows)}
            </div>
            {self._render_html_kv_section('Decision Trace', explainability.get('decision_trace', {}))}
            {module_outputs_html}
            """

        explain_reasoning_html = ""
        if explain_reasoning:
            plain = explain_reasoning.get('0_plain_language_summary', {})
            plain_html = ""
            if plain:
                plain_rows = [
                    ['Simple Verdict', plain.get('simple_verdict', 'N/A')],
                    ['Confidence', plain.get('plain_confidence', 'N/A')],
                ]
                plain_html = f"""
                <h3>0. Plain-Language Summary</h3>
                <div class="metadata-box">
                    {self._render_html_table(['Field', 'Value'], plain_rows)}
                    <h4>What supports this</h4>
                    {self._render_html_bullets(plain.get('what_supports_this', []), 'No support points listed.')}
                    <h4>What this does not prove</h4>
                    {self._render_html_bullets(plain.get('what_this_does_not_prove', []), 'No limitations listed.')}
                    <p style="margin-top:15px; font-style:italic;">{html.escape(str(plain.get('recommended_reading', '')))}</p>
                </div>
                """

            severity_rows = []
            for item in explain_reasoning.get('2_evidence_severity_classification', []):
                severity_rows.append([item.get('indicator', 'N/A'), item.get('severity', 'LOW'), item.get('reason', '')])

            conflict = explain_reasoning.get('3_model_conflict_analysis', {})
            deterministic = conflict.get('deterministic_aggregation', {})
            bayesian = conflict.get('bayesian_predictive_model', {})
            calibration = explain_reasoning.get('4_bayesian_calibration_commentary', {})
            confidence = explain_reasoning.get('6_forensic_confidence_index', {})

            explain_reasoning_html = f"""
            <h2>Detailed Forensic Reasoning</h2>
            <div class="explanation-note"><strong>Explanation:</strong> A step-by-step cognitive trace of how the final conclusion was reached, including multi-domain risk assessment, conflict resolution between models, and Bayesian calibration.</div>
            {plain_html}
            {self._render_html_kv_section('1. Multi-Domain Risk Assessment', explain_reasoning.get('1_multi_domain_risk_assessment', {}))}
            <h3>2. Evidence Severity Classification</h3>
            <div class="metadata-box">
                {self._render_html_table(['Indicator', 'Severity', 'Reason'], severity_rows)}
            </div>
            <h3>3. Model Conflict Analysis</h3>
            <div class="metadata-box">
                {self._render_html_table(['Field', 'Value'], [['Conflict Detected', conflict.get('conflict_detected', False)]])}
                {self._render_html_kv_section('Deterministic Aggregation', deterministic)}
                {self._render_html_kv_section('Bayesian Predictive Model', bayesian)}
                <h4>Dominance Factors</h4>
                {self._render_html_bullets(conflict.get('dominance_factors', []), 'No dominance factors recorded.')}
            </div>
            <h3>4. Bayesian Calibration Commentary</h3>
            <div class="metadata-box">
                {self._render_html_table(['Field', 'Value'], [['Likelihood Overweighted', calibration.get('likelihood_overweighted', False)]])}
                <p>{html.escape(str(calibration.get('commentary', '')))}</p>
            </div>
            <h3>5. Unified Interpretation</h3>
            <div class="metadata-box"><p style="font-weight:600;">{html.escape(str(explain_reasoning.get('5_unified_interpretation_improved_classification', 'INCONCLUSIVE')))}</p></div>
            <h3>6. Forensic Confidence Index</h3>
            <div class="metadata-box">
                {self._render_html_table(['Field', 'Value'], [['Level', confidence.get('level', 'LOW')], ['Basis', confidence.get('basis', '')]])}
            </div>
            <h3>7. Narrative Forensic Summary</h3>
            <div class="metadata-box"><p>{html.escape(str(explain_reasoning.get('7_narrative_forensic_summary', '')))}</p></div>
            """

        assist_html = ""
        if assist:
            assist_rows = [
                ['Suggested Structural Finding', assist.get('suggested_structural_finding', 'N/A')],
                ['Suggested Interpretation', assist.get('suggested_interpretation', 'N/A')],
                ['Suggested Risk Level', assist.get('suggested_risk_level', 'N/A')],
                ['Final Decision', assist.get('final_decision', 'Pending Analyst Confirmation')],
            ]
            assist_html = f"""
            <h2>Assist Mode (Analyst Augmentation)</h2>
            <div class="explanation-note"><strong>Explanation:</strong> Provides actionable recommendations for human analysts to review and verify the findings.</div>
            <div class="metadata-box">
                {self._render_html_table(['Assist Item', 'Value'], assist_rows)}
                <h3>Suggested Follow-up</h3>
                {self._render_html_bullets(assist.get('suggested_follow_up', []), 'No follow-up steps recorded.')}
            </div>
            """

        flags_html = ""
        flags = data.get('flags', [])
        if flags:
            flags_html = f"""
            <h2>Detected Issues</h2>
            <div class="explanation-note"><strong>Explanation:</strong> A quick summary of the isolated metadata anomalies and suspicious characteristics detected.</div>
            <div class="metadata-box">
                {self._render_html_bullets(flags, 'No issues detected.')}
            </div>
            """

        geospatial_html = ""
        location = data.get('location') or data.get('metadata', {}).get('location')
        if location:
            geo_rows = [
                ['Full Address', location.get('full_address', 'N/A')],
                ['Location Name', location.get('location_name', 'N/A')],
                ['Country', f"{location.get('country', 'N/A')} ({location.get('country_code', 'N/A')})"],
                ['Coordinates', f"{location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}"],
            ]
            alt = location.get('altitude')
            if alt and str(alt) not in ['N/A', 'Unknown', 'None', '']:
                geo_rows.append(['Altitude', f"{alt} meters"])
            geo_rows.append(['Status', location.get('status', 'resolved')])
            maps_url = f"https://www.google.com/maps/place/{location.get('latitude')},{location.get('longitude')}"
            geospatial_html = f"""
            <h2>Geospatial Intelligence</h2>
            <div class="explanation-note"><strong>Explanation:</strong> Details the real-world location where the image was captured, including administrative names and environmental altitude.</div>
            <div class="metadata-box">
                {self._render_html_table(['Domain', 'Details'], geo_rows)}
                <p style="margin-top: 15px;"><strong>Google Maps:</strong> <a href="{maps_url}" target="_blank">{maps_url}</a></p>
            </div>
            """
        
        manufacturer_html = ""
        # Check both top-level and metadata-level for manufacturer_specific
        mfr_spec = data.get('manufacturer_specific') or data.get('metadata', {}).get('manufacturer_specific')
        if mfr_spec:
            mfr_rows = [[k, v] for k, v in mfr_spec.items()]
            manufacturer_html = f"""
            <h2>Manufacturer Specific Hardware State</h2>
            <div class="explanation-note"><strong>Explanation:</strong> Specialized device performance markers extracted from manufacturer-specific metadata blocks (e.g., vivo UserComment).</div>
            <div class="metadata-box">
                {self._render_html_table(['Attribute', 'Value'], mfr_rows)}
            </div>
            """

        chatbox_html = self._render_chatbox_identification_html(chatbox_identification)

        metadata_html = ""
        if not explain_mode:
            flat_metadata = ExifToolStyleFormatter._flatten_metadata(data.get('metadata', {}) or {})
            raw_metadata_html = f"""
            <h2>Investigative Raw Metadata</h2>
            <div class="explanation-note"><strong>Explanation:</strong> The unfiltered metadata extracted from the file, providing raw data for manual cross-referencing.</div>
            <div class="raw-box">{html.escape(ExifToolStyleFormatter.format(data.get('metadata', {})))}</div>
            """
            if flat_metadata:
                # Filter out the noisy/technical fields requested by the user for a cleaner report
                USER_EXCLUDED_ATTRS = {
                    'Aperture', 'Aperturevalue', 'Bitspersample', 'Bluematrixcolumn', 'Bluetrc',
                    'Chromaticadaptation', 'Chronology of Events', 'Circleofconfusion', 'Cmmflags',
                    'Colorcomponents', 'Colorspace', 'Colorspacedata', 'Componentsconfiguration',
                    'Confidence', 'Connectionspaceilluminant', 'Createdate', 'Date/Time Original',
                    'Datetimeoriginal', 'Deviceattributes', 'Devicemanufacturer', 'Devicemodel',
                    'Digitalzoomratio', 'Digitized Time', 'Dimensions', 'Directory',
                    'Encodingprocess', 'Exifbyteorder', 'Exiftool Version', 'Exiftoolversion',
                    'Exifversion', 'Exif Version', 'Exposurecompensation', 'Exposuremode', 'Exposureprogram',
                    'Exposuretime', 'File Modified Time', 'File Type', 'Fileaccessdate',
                    'Filecreatedate', 'Filemodifydate', 'Filename', 'Filepermissions',
                    'Filesize', 'Filetype', 'Filetypeextension', 'Flash', 'Flashpixversion',
                    'Fnumber', 'Focallength', 'Focallength35Efl', 'Focallengthin35Mmformat',
                    'Forensic Flags', 'Forensics', 'Fov', 'Gpsaltitude', 'Gpsaltituderef',
                    'Gpsdatestamp', 'Gpsdatetime', 'Gpslatitude', 'Gpslatituderef',
                    'Gpslongitude', 'Gpslongituderef', 'Gpsposition', 'Gpsprocessingmethod',
                    'Gpstimestamp', 'Greenmatrixcolumn', 'Greentrc', 'Has Geotag',
                    'Hyperfocaldistance', 'Imageheight', 'Imagesize', 'Imagewidth',
                    'Interopindex', 'Is Raw', 'Iso', 'Label', 'Lightsource', 'Lightvalue',
                    'Likely Modified', 'Makernoteunknowntext',
                    'Maxaperturevalue', 'Mediawhitepoint', 'Megapixels', 'Meteringmode',
                    'Mimetype', 'Modification Status', 'Modification Summary',
                    'Modifydate', 'Modules', 'Notes', 'Orientation', 'Origin Assessment',
                    'Original Capture Time', 'Primaryplatform', 'Profileclass',
                    'Profilecmmtype', 'Profileconnectionspace', 'Profilecopyright',
                    'Profilecreator', 'Profiledatetime', 'Profiledescription',
                    'Profilefilesignature', 'Profileid', 'Profileversion', 'Redmatrixcolumn',
                    'Redtrc', 'Renderingintent', 'Resolutionunit', 'Scalefactor35Efl',
                    'Scenecapturetype', 'Scenetype', 'Sensingmethod', 'Shutterspeed',
                    'Shutterspeedvalue', 'Software', 'Software Detected', 'Sourcefile',
                    'Standards Present', 'Subseccreatedate', 'Subsecdatetimeoriginal',
                    'Subsecmodifydate', 'Subsectime', 'Subsectimedigitized',
                    'Subsectimeoriginal', 'Timestamp Issues', 'Usercomment', 'Warning',
                    'Whitebalance', 'XMP History Entries', 'Xresolution', 'Ycbcrpositioning',
                    'Ycbcrsubsampling', 'Yresolution'
                }
                
                metadata_rows = [
                    [key, value] for key, value in sorted(flat_metadata.items())
                    if key not in USER_EXCLUDED_ATTRS
                ]
                
                if metadata_rows:
                    metadata_html = f"""
                    {raw_metadata_html}
                    <div class="metadata-box">
                        {self._render_html_table(['Attribute', 'Value'], metadata_rows)}
                    </div>
                    """
                else:
                    # If all filtered out, just show the raw block
                    metadata_html = raw_metadata_html
            else:
                metadata_html = raw_metadata_html
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --primary: #1e293b;
            --secondary: #3b82f6;
            --accent: #ef4444;
            --bg-main: #f8fafc;
            --card-bg: #ffffff;
            --text-main: #334155;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --success: #10b981;
            --warning: #f59e0b;
        }}
        body {{ 
            font-family: 'Inter', system-ui, -apple-system, sans-serif; 
            margin: 0; 
            background-color: var(--bg-main); 
            color: var(--text-main); 
            line-height: 1.6; 
        }}
        .container {{
            max-width: 1100px;
            margin: 40px auto;
            padding: 0 20px;
        }}
        header {{
            background: linear-gradient(135deg, var(--primary) 0%, #334155 100%);
            color: #fff;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 40px;
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        }}
        h1 {{ margin: 0; font-size: 2.2rem; font-weight: 700; letter-spacing: -0.02em; }}
        .report-meta {{ margin-top: 10px; color: #cbd5e1; font-weight: 500; }}
        h2 {{ 
            color: var(--primary); 
            margin: 40px 0 20px; 
            font-size: 1.5rem; 
            border-bottom: 2px solid var(--border); 
            padding-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        h2::before {{
            content: '';
            display: inline-block;
            width: 4px;
            height: 24px;
            background: var(--secondary);
            border-radius: 2px;
        }}
        h3 {{ color: var(--secondary); font-size: 1.25rem; margin-top: 25px; }}
        
        .summary {{ 
            background: var(--card-bg); 
            padding: 25px; 
            border-radius: 12px; 
            border-left: 5px solid var(--secondary); 
            box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); 
            margin-bottom: 30px;
        }}
        
        .metadata-box {{ 
            background: var(--card-bg); 
            border: 1px solid var(--border); 
            border-radius: 12px; 
            padding: 25px; 
            margin: 20px 0; 
            box-shadow: 0 1px 3px 0 rgba(0,0,0,0.1); 
            transition: transform 0.2s, box-shadow 0.2s;
            max-height: 600px;
            overflow-y: auto;
        }}
        .metadata-box:hover {{
            box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
        }}
        
        .explanation-note {{
            background-color: #eff6ff;
            border-left: 4px solid var(--secondary);
            color: #1e3a8a;
            padding: 15px 20px;
            border-radius: 0 8px 8px 0;
            margin: 15px 0;
            font-size: 0.95rem;
        }}
        
        .raw-box {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 20px;
            border-radius: 12px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 0.85rem;
            white-space: pre-wrap;
            overflow-x: auto;
            border-left: 5px solid var(--secondary);
            box-shadow: inset 0 2px 4px 0 rgba(0,0,0,0.1);
        }}

        table {{ width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 15px; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: #f1f5f9; color: var(--primary); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }}
        th:first-child {{ border-top-left-radius: 8px; }}
        th:last-child {{ border-top-right-radius: 8px; }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background-color: #f8fafc; }}
        
        ul {{ margin: 0; padding-left: 20px; }}
        li {{ margin-bottom: 6px; }}
        
        footer {{ 
            margin-top: 60px; 
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center; 
            font-size: 0.85rem; 
            color: var(--text-muted); 
            padding-bottom: 40px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{title}</h1>
            <div class="report-meta">Generated by MetaForensicAI Enterprise v1.0.0 | Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        </header>

        <div class="explanation-note">
            <strong>Report Overview:</strong> This report provides a comprehensive digital forensic analysis of the submitted media file. It breaks down unified conclusions, domain expertise, metadata, and explainable AI justifications to help verify authenticity and integrity.
        </div>
        
        <div class="summary">
            {self._render_html_table(['Item', 'Details'], summary_rows)}
        </div>

        {screenshot_html}{domain_html}

        <h2>Unified Forensic Conclusion</h2>
        <div class="explanation-note"><strong>Explanation:</strong> Synthesizes all findings into a final interpretation and assigns an actionable risk level indicating the likelihood of manipulation or synthesis.</div>
        <div class="metadata-box">
            {self._render_html_table(['Conclusion Item', 'Finding'], conclusion_rows)}
        </div>

        {geospatial_html}
        {manufacturer_html}
        {explanations_html}
        {modification_history_html}
        {explainability_html}
        {explain_reasoning_html}
        {chatbox_html}
        {assist_html}
        {flags_html}
        {metadata_html}

        <footer>
            &copy; {datetime.now().year} MetaForensicAI Enterprise | Forensic Integrity Guaranteed
        </footer>
    </div>
</body>
</html>"""
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _safe_para(self, text: str, style: Any) -> Any:
        """Wrap text in a Paragraph, escaping any XML-unsafe characters."""
        import html as html_mod
        if text is None:
            text = ''
        # Escape &, <, > but preserve already-safe bold/italic tags used intentionally
        # Strategy: escape everything then restore known safe tags
        safe = html_mod.escape(str(text), quote=False)
        # Restore intentional ReportLab inline tags (including those with attributes like <font color='red'>)
        # We look for &lt;tag followed by space or &gt; and restore them
        for tag in ['b', 'i', 'u', 'br', 'font']:
            # Restore opening tags with attributes: &lt;font ...&gt; -> <font ...>
            # Use regex for more robust restoration of tags with attributes
            import re
            safe = re.sub(f'&lt;{tag}([^&]*?)&gt;', f'<{tag}\\1>', safe, flags=re.IGNORECASE)
            # Restore closing tags: &lt;/tag&gt; -> </tag>
            safe = re.sub(f'&lt;/{tag}&gt;', f'</{tag}>', safe, flags=re.IGNORECASE)
        
        # Special case for br/
        safe = safe.replace('&lt;br/&gt;', '<br/>')
        try:
            return Paragraph(safe, style)
        except Exception:
            # Last resort: strip all tags
            import re
            plain = re.sub(r'<[^>]+>', '', safe)
            return Paragraph(plain, style)

    def _screenshot_device_rows(self, data: Dict[str, Any]) -> List[List[str]]:
        """Build report rows for screenshot device analysis."""
        info = data.get('origin_detection', {}).get('screenshot_device_info', {}) or {}
        confidence = info.get('confidence_score', {}) if isinstance(info.get('confidence_score', {}), dict) else {}
        rows = [
            ['Device Type', info.get('device_type', 'N/A')],
            ['Possible Device Models', ', '.join(info.get('possible_device_models', [])) or 'N/A'],
            ['OS Detected', info.get('os_detected', 'N/A')],
            ['Capture Mode', info.get('capture_mode', 'N/A')],
            ['Typography', info.get('typography', 'N/A')],
            ['Platform / OS Confidence', f"{confidence.get('platform_os_identification', 'N/A')}%"],
            ['Specific Hardware Confidence', f"{confidence.get('specific_hardware', 'N/A')}%"],
            ['Final Verdict', info.get('final_verdict', 'N/A')],
        ]
        android_analysis = info.get('android_screenshot_analysis', {}) if isinstance(info.get('android_screenshot_analysis', {}), dict) else {}
        if android_analysis:
            rows.extend([
                ['Android Screenshot Match', 'Yes' if android_analysis.get('is_android_screenshot') else 'No'],
                ['Android Screenshot Confidence', f"{android_analysis.get('confidence', 'N/A')}%"],
                ['Android Version', android_analysis.get('android_version') or 'Unknown'],
                ['Android Device Model', android_analysis.get('device_model') or 'Unknown'],
                ['Screenshot Method', android_analysis.get('screenshot_method') or 'Unknown'],
            ])
        return rows

    def _build_pdf_styles(self) -> Dict[str, Any]:
        """Create PDF styles for a more structured report layout."""
        styles = getSampleStyleSheet()
        styles['Title'].fontSize = 20
        styles['Title'].leading = 24
        styles['Heading2'].spaceBefore = 10
        styles['Heading2'].spaceAfter = 6
        styles['Heading3'].spaceBefore = 6
        styles['Heading3'].spaceAfter = 4
        styles['Normal'].leading = 14
        styles['Italic'].leading = 14

        if 'SectionLabel' not in styles:
            styles.add(ParagraphStyle(
                name='SectionLabel',
                parent=styles['Heading2'],
                fontSize=13,
                leading=16,
                textColor=colors.HexColor("#1f3b5b"),
                spaceBefore=10,
                spaceAfter=6,
            ))
        if 'SubLabel' not in styles:
            styles.add(ParagraphStyle(
                name='SubLabel',
                parent=styles['Heading3'],
                fontSize=11,
                leading=13,
                textColor=colors.HexColor("#374151"),
                spaceBefore=6,
                spaceAfter=4,
            ))
        if 'Small' not in styles:
            styles.add(ParagraphStyle(
                name='Small',
                parent=styles['Normal'],
                fontSize=9,
                leading=12,
            ))
        return styles

    def _pdf_rows_from_mapping(self, payload: Dict[str, Any]) -> List[List[Any]]:
        """Convert a dictionary into PDF table rows."""
        rows: List[List[Any]] = []
        if not isinstance(payload, dict):
            return rows
        for key, value in payload.items():
            rows.append([str(key).replace('_', ' ').title(), self._compact_pdf_cell(value, max_chars=220)])
        return rows

    def _append_pdf_table(
        self,
        story: List[Any],
        styles: Dict[str, Any],
        headers: List[str],
        rows: List[List[Any]],
        col_widths: List[int],
    ) -> None:
        """Append a styled PDF table with wrapped cells."""
        if not rows:
            story.append(self._safe_para("No data available.", styles['Normal']))
            return

        table_rows: List[List[Any]] = [[
            self._safe_para(f"<font color='white'><b>{header}</b></font>", styles['Small']) for header in headers
        ]]
        for row in rows:
            table_rows.append([
                self._safe_para(self._compact_pdf_cell(cell), styles['Small']) for cell in row
            ])

        table = Table(table_rows, colWidths=col_widths, repeatRows=1)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1f3b5b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f7fafc")]),
            ('BOX', (0, 0), (-1, -1), 0.6, colors.HexColor("#9ca3af")),
            ('INNERGRID', (0, 0), (-1, -1), 0.4, colors.HexColor("#d1d5db")),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(table)
        story.append(Spacer(1, 10))

    def _append_pdf_bullets(self, story: List[Any], styles: Dict[str, Any], items: List[Any], empty_text: str) -> None:
        """Append a simple bullet list using wrapped paragraphs."""
        if not items:
            story.append(self._safe_para(empty_text, styles['Normal']))
            return
        for item in items:
            story.append(self._safe_para(f"- {self._compact_pdf_cell(item, max_chars=320)}", styles['Normal']))

    def _append_pdf_kv_section(
        self,
        story: List[Any],
        styles: Dict[str, Any],
        title: str,
        payload: Dict[str, Any],
        col_widths: List[int] | None = None,
    ) -> None:
        """Append a titled key/value table section."""
        if not payload:
            return
        story.append(self._safe_para(title, styles['SubLabel']))
        self._append_pdf_table(
            story,
            styles,
            ['Field', 'Value'],
            self._pdf_rows_from_mapping(payload),
            col_widths or [170, 350],
        )

    def _write_pdf(self, title: str, data: Dict[str, Any], path: Path) -> None:
        """Write data to PDF file using ReportLab."""
        include_raw = bool(data.get('include_raw', False))
        explain_mode = data.get('ai_mode') == 'explain' and not include_raw
        doc = SimpleDocTemplate(str(path), pagesize=letter)
        styles = self._build_pdf_styles()
        story = []

        story.append(self._safe_para(title, styles['Title']))
        story.append(Spacer(1, 12))

        risk = data.get('risk_assessment', {})
        risk_score = risk.get('risk_score', risk.get('score', data.get('risk_score', 0)))
        level = risk.get('level', 'LOW')
        display_origin, display_source = self._format_origin_strings(data)
        origin_label = data.get('origin_detection', {}).get('primary_origin', 'Unknown')

        story.append(self._safe_para("Executive Summary", styles['SectionLabel']))
        summary_rows = [
            ['Case Evidence', data.get('image_path') or data.get('evidence_integrity', {}).get('file_path', 'N/A')],
            ['Risk Score', f"{risk_score:.1f}/100 ({level})"],
            ['Unified Interpretation', self._display_interpretation(data)],
            ['Primary Origin', display_origin],
            ['Source Inference', display_source],
            ['GPS Location', (data.get('location') or data.get('metadata', {}).get('location', {})).get('full_address') or (data.get('location') or data.get('metadata', {}).get('location', {})).get('location_name', 'No GPS data extracted')],
            ['Analysis Date', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
        ]
        
        app_name = data.get('app_detection', {}).get('app', 'Unknown')
        if app_name != 'Unknown':
            conf = data.get('app_detection', {}).get('confidence', 0)
            try:
                conf = float(conf)
            except:
                conf = 0.0
            summary_rows.insert(5, ['Detected Application', f"{app_name} ({conf:.1f}% conf)"])
        self._append_pdf_table(story, styles, ['Item', 'Details'], summary_rows, [150, 370])
        screenshot_rows = self._screenshot_device_rows(data) if origin_label == 'screenshot_capture' else []

        if screenshot_rows:
            story.append(self._safe_para("Screenshot Device Analysis", styles['SectionLabel']))
            self._append_pdf_table(story, styles, ['Attribute', 'Value'], screenshot_rows, [170, 350])
            screenshot_info = data.get('origin_detection', {}).get('screenshot_device_info', {}) or {}
            story.append(self._safe_para("Key Evidence", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, screenshot_info.get('key_evidence', []), "No screenshot-specific evidence extracted.")
            story.append(Spacer(1, 6))
            story.append(self._safe_para("Digital Markers", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, screenshot_info.get('digital_markers', []), "No digital markers extracted.")
            story.append(Spacer(1, 6))

        if origin_label == 'screenshot_capture':
            story.append(self._safe_para("Forensic Limitations", styles['SectionLabel']))
            story.append(self._safe_para(
                "This identification is based on visual UI indicators and resolution mapping. "
                "While the software and OS are identified with high certainty, the specific physical hardware "
                "(e.g., Dell vs. HP) cannot be definitively determined from a windowed application screenshot alone "
                "as hardware-specific metadata is typically stripped during capture.",
                styles['Normal']
            ))
            story.append(Spacer(1, 10))

        location = data.get('location') or data.get('metadata', {}).get('location')
        if location:
            story.append(self._safe_para("Geospatial Intelligence", styles['SectionLabel']))
            geo_rows = [
                ['Full Address', location.get('full_address', 'N/A')],
                ['Location Name', location.get('location_name', 'N/A')],
                ['Country', f"{location.get('country', 'N/A')} ({location.get('country_code', 'N/A')})"],
                ['Coordinates', f"{location.get('latitude', 'N/A')}, {location.get('longitude', 'N/A')}"],
            ]
            alt = location.get('altitude')
            if alt and str(alt) not in ['N/A', 'Unknown', 'None', '']:
                geo_rows.append(['Altitude', f"{alt}m"])
            self._append_pdf_table(story, styles, ['Attribute', 'Value'], geo_rows, [150, 370])
            maps_url = f"https://www.google.com/maps/place/{location.get('latitude')},{location.get('longitude')}"
            story.append(self._safe_para(f"<b>Google Maps:</b> {maps_url}", styles['Normal']))
            story.append(Spacer(1, 10))

        mfr_spec = data.get('manufacturer_specific') or data.get('metadata', {}).get('manufacturer_specific')
        if mfr_spec:
            story.append(self._safe_para("Manufacturer Specific Hardware State", styles['SectionLabel']))
            mfr_rows = [[k, v] for k, v in mfr_spec.items()]
            self._append_pdf_table(story, styles, ['Attribute', 'Value'], mfr_rows, [150, 370])
            story.append(Spacer(1, 10))

        domains = data.get('domains', {})
        if domains:
            story.append(self._safe_para("Forensic Domain Expertise", styles['SectionLabel']))
            fmt = domains.get('image_format', {})
            mfr = domains.get('manufacturer', {})
            domain_rows = [
                ['Format Domain', f"{fmt.get('label', 'N/A')} | {fmt.get('expertise', {}).get('forensics', 'No forensic note available')}"],
                ['Manufacturer Domain', f"{mfr.get('label', 'N/A')} | {mfr.get('expertise', {}).get('notes', 'No manufacturer note available')}"],
            ]
            self._append_pdf_table(story, styles, ['Domain', 'Assessment'], domain_rows, [150, 370])

        interpretation = self._display_interpretation(data)
        story.append(self._safe_para("Unified Forensic Conclusion", styles['SectionLabel']))
        conclusion_rows = [
            ['Interpretation', interpretation.replace('_', ' ')],
            ['Risk Level', f"{risk.get('level', 'UNKNOWN')} ({risk.get('risk_score', 0):.1f}/100)"],
            ['Flag Count', str(len(data.get('flags', [])))],
            ['Explanation Count', str(len(data.get('explanations', [])))],
        ]
        self._append_pdf_table(story, styles, ['Conclusion Item', 'Finding'], conclusion_rows, [160, 360])

        explanations = data.get('explanations', [])
        if explanations:
            story.append(self._safe_para("Forensic Justifications (XAI)", styles['SectionLabel']))
            for index, exp in enumerate(explanations, start=1):
                story.append(self._safe_para(
                    f"Finding {index}: {exp.get('title', 'Untitled finding')} [{exp.get('severity', 'INFO')}]",
                    styles['SubLabel']
                ))
                exp_rows = [
                    ['Confidence', exp.get('confidence', 'N/A')],
                    ['Observation', exp.get('observation', 'N/A')],
                    ['Metadata Triggers', json.dumps(exp.get('triggers', {}), default=str)],
                    ['Forensic Logic', exp.get('logic', 'N/A')],
                    ['Expert Significance', exp.get('significance', 'N/A')],
                ]
                self._append_pdf_table(story, styles, ['Field', 'Explanation'], exp_rows, [130, 390])
                causes = exp.get('causes', {})
                story.append(self._safe_para(f"<b>Legitimate Cause:</b> {causes.get('legitimate', 'N/A')}", styles['Normal']))
                story.append(self._safe_para(f"<b>Malicious Cause:</b> {causes.get('malicious', 'N/A')}", styles['Normal']))
                story.append(Spacer(1, 10))

        modification_history = data.get('modification_history', {})
        if modification_history:
            story.append(self._safe_para("Modification History", styles['SectionLabel']))
            history_rows = [
                ['Status', modification_history.get('status', 'unknown')],
                ['Confidence', modification_history.get('confidence', 'low')],
                ['Likely Modified', modification_history.get('likely_modified', False)],
                ['Summary', modification_history.get('summary', 'No summary available.')],
                ['Original Capture Time', modification_history.get('original_capture_time', 'N/A')],
                ['Digitized Time', modification_history.get('digitized_time', 'N/A')],
                ['File Modified Time', modification_history.get('file_modified_time', 'N/A')],
            ]
            self._append_pdf_table(story, styles, ['History Item', 'Details'], history_rows, [150, 370])
            story.append(self._safe_para("Detected Software", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, self._display_detected_software(data), "No software markers detected.")
            story.append(Spacer(1, 6))
            story.append(self._safe_para("XMP History Entries", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, modification_history.get('xmp_history_entries', []), "No XMP history entries detected.")
            story.append(Spacer(1, 6))
            events = modification_history.get('events', [])
            if events:
                story.append(self._safe_para("Chronology of Events", styles['SubLabel']))
                event_rows = []
                for event in events:
                    event_rows.append([
                        event.get('event', 'N/A'),
                        event.get('timestamp', 'N/A'),
                        event.get('source', 'N/A'),
                        f"{event.get('confidence', 'N/A')} | {event.get('details', '')}",
                    ])
                self._append_pdf_table(story, styles, ['Event', 'Timestamp', 'Source', 'Assessment'], event_rows, [100, 110, 90, 240])

        explainability = data.get('explainability_breakdown', {})
        if explainability and not explain_mode:
            story.append(self._safe_para("Explainability Breakdown", styles['SectionLabel']))
            explain_rows = [
                ['Pipeline Mode', explainability.get('pipeline_mode', 'N/A')],
                ['Explanation Count', explainability.get('explanation_count', 0)],
                ['Explanation Titles', ", ".join(str(x) for x in explainability.get('explanation_titles', [])) or 'None'],
            ]
            self._append_pdf_table(story, styles, ['Explainability Item', 'Value'], explain_rows, [150, 370])

            decision_trace = explainability.get('decision_trace', {})
            self._append_pdf_kv_section(story, styles, "Decision Trace", decision_trace)

            module_outputs = explainability.get('module_outputs', {})
            if module_outputs:
                story.append(self._safe_para("Module Outputs", styles['SubLabel']))
                for module_name, module_payload in module_outputs.items():
                    story.append(self._safe_para(str(module_name).replace('_', ' ').title(), styles['Small']))
                    if isinstance(module_payload, dict):
                        self._append_pdf_table(story, styles, ['Field', 'Value'], self._pdf_rows_from_mapping(module_payload), [170, 350])
                    else:
                        story.append(self._safe_para(self._summarize_for_pdf(module_payload), styles['Normal']))
                    story.append(Spacer(1, 6))

        explain_reasoning = data.get('explain_forensic_reasoning', {})
        if explain_reasoning:
            story.append(self._safe_para("Explain Output (Forensic Reasoning)", styles['SectionLabel']))

            plain = explain_reasoning.get('0_plain_language_summary', {})
            if plain:
                story.append(self._safe_para("0. Plain-Language Summary", styles['SubLabel']))
                plain_rows = [
                    ['Simple Verdict', plain.get('simple_verdict', 'N/A')],
                    ['Confidence', plain.get('plain_confidence', 'N/A')],
                ]
                self._append_pdf_table(story, styles, ['Field', 'Value'], plain_rows, [140, 380])
                story.append(self._safe_para("What supports this", styles['Small']))
                self._append_pdf_bullets(story, styles, plain.get('what_supports_this', []), "No support points listed.")
                story.append(Spacer(1, 4))
                story.append(self._safe_para("What this does not prove", styles['Small']))
                self._append_pdf_bullets(story, styles, plain.get('what_this_does_not_prove', []), "No limitations listed.")
                story.append(self._safe_para(str(plain.get('recommended_reading', '')), styles['Normal']))
                story.append(Spacer(1, 8))

            explain_risk = explain_reasoning.get('1_multi_domain_risk_assessment', {})
            self._append_pdf_kv_section(story, styles, "1. Multi-Domain Risk Assessment", explain_risk)

            story.append(self._safe_para("2. Evidence Severity Classification", styles['SubLabel']))
            severity_rows = []
            for item in explain_reasoning.get('2_evidence_severity_classification', []):
                severity_rows.append([item.get('indicator', 'N/A'), item.get('severity', 'LOW'), item.get('reason', '')])
            self._append_pdf_table(story, styles, ['Indicator', 'Severity', 'Reason'], severity_rows, [150, 80, 290])

            conflict = explain_reasoning.get('3_model_conflict_analysis', {})
            deterministic = conflict.get('deterministic_aggregation', {})
            bayesian = conflict.get('bayesian_predictive_model', {})
            story.append(self._safe_para("3. Model Conflict Analysis", styles['SubLabel']))
            self._append_pdf_table(story, styles, ['Field', 'Value'], [['Conflict Detected', conflict.get('conflict_detected', False)]], [140, 380])
            self._append_pdf_kv_section(story, styles, "Deterministic Aggregation", deterministic)
            self._append_pdf_kv_section(story, styles, "Bayesian Predictive Model", bayesian)
            story.append(self._safe_para("Dominance Factors", styles['Small']))
            self._append_pdf_bullets(story, styles, conflict.get('dominance_factors', []), "No dominance factors recorded.")

            calibration = explain_reasoning.get('4_bayesian_calibration_commentary', {})
            story.append(self._safe_para("4. Bayesian Calibration Commentary", styles['SubLabel']))
            self._append_pdf_table(story, styles, ['Field', 'Value'], [['Likelihood Overweighted', calibration.get('likelihood_overweighted', False)]], [160, 360])
            story.append(self._safe_para(f"{calibration.get('commentary', '')}", styles['Normal']))

            story.append(self._safe_para("5. Unified Interpretation (Improved Classification)", styles['SubLabel']))
            story.append(self._safe_para(f"{explain_reasoning.get('5_unified_interpretation_improved_classification', 'INCONCLUSIVE')}", styles['Normal']))

            confidence = explain_reasoning.get('6_forensic_confidence_index', {})
            story.append(self._safe_para("6. Forensic Confidence Index", styles['SubLabel']))
            confidence_rows = [['Level', confidence.get('level', 'LOW')], ['Basis', confidence.get('basis', '')]]
            self._append_pdf_table(story, styles, ['Field', 'Value'], confidence_rows, [120, 400])

            story.append(self._safe_para("7. Narrative Forensic Summary", styles['SubLabel']))
            story.append(self._safe_para(f"{explain_reasoning.get('7_narrative_forensic_summary', '')}", styles['Normal']))
            story.append(Spacer(1, 12))

        chatbox_identification = data.get('chatbox_identification', {})
        if chatbox_identification:
            story.append(self._safe_para("MetaForensic AI Chatbox Identification", styles['SectionLabel']))
            chatbox_rows = [
                ['Question', chatbox_identification.get('question', 'N/A')],
                ['Selected Module', chatbox_identification.get('selected_module', 'N/A')],
                ['Normalized Intent', chatbox_identification.get('normalized_intent', 'N/A')],
                ['Answer', chatbox_identification.get('answer', 'N/A')],
                ['Confidence', f"{chatbox_identification.get('confidence_percent', 'N/A')}% ({chatbox_identification.get('confidence_level', 'N/A')})"],
                ['Summary', chatbox_identification.get('summary', 'N/A')],
            ]
            self._append_pdf_table(story, styles, ['Item', 'Details'], chatbox_rows, [150, 370])
            story.append(self._safe_para("Candidate Modules", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, chatbox_identification.get('candidate_modules', []), "No candidate modules recorded.")
            story.append(Spacer(1, 4))
            story.append(self._safe_para("Evidence Used", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, chatbox_identification.get('evidence', []), "No evidence lines recorded.")
            story.append(Spacer(1, 8))

        assist = data.get('assist_suggestions', {})
        if assist:
            story.append(self._safe_para("Assist Mode (Analyst Augmentation)", styles['SectionLabel']))
            assist_rows = [
                ['Suggested Structural Finding', assist.get('suggested_structural_finding', 'N/A')],
                ['Suggested Interpretation', assist.get('suggested_interpretation', 'N/A')],
                ['Suggested Risk Level', assist.get('suggested_risk_level', 'N/A')],
                ['Final Decision', assist.get('final_decision', 'Pending Analyst Confirmation')],
            ]
            self._append_pdf_table(story, styles, ['Assist Item', 'Value'], assist_rows, [170, 350])
            story.append(self._safe_para("Suggested Follow-up", styles['SubLabel']))
            self._append_pdf_bullets(story, styles, assist.get('suggested_follow_up', []), "No follow-up steps recorded.")
            story.append(Spacer(1, 8))

        flags = data.get('flags', [])
        if flags:
            story.append(self._safe_para("Detected Issues", styles['SectionLabel']))
            self._append_pdf_bullets(story, styles, flags, "No issues detected.")
            story.append(Spacer(1, 8))

        if not explain_mode:
            metadata = data.get('metadata', {}) or {}
            flat_metadata = ExifToolStyleFormatter._flatten_metadata(metadata)

            if flat_metadata:
                normal_style = styles['Small']
                normal_style.wordWrap = 'CJK'
                t_data: List[List[Any]] = [[
                    self._safe_para("<font color='white'><b>Attribute</b></font>", styles['Small']),
                    self._safe_para("<font color='white'><b>Value</b></font>", styles['Small'])
                ]]
                for key, value in sorted(flat_metadata.items()):
                    key_p = self._safe_para(self._compact_pdf_cell(key, max_chars=120), normal_style)
                    value_p = self._safe_para(self._compact_pdf_cell(value, max_chars=400), normal_style)
                    t_data.append([key_p, value_p])
                t = Table(t_data, colWidths=[200, 300], repeatRows=1)
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1f3b5b")),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f7fafc")]),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING', (0, 0), (-1, -1), 6),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ]))
                story.append(t)

        doc.build(story)

    def _write_text(self, data: Dict[str, Any], path: Path) -> None:
        """Write data to text file using ExifTool-style formatting."""
        metadata = data.get('metadata', {})
        formatted_text = ExifToolStyleFormatter.format(metadata)
        risk = data.get('risk_assessment', {})
        risk_score = risk.get('risk_score', risk.get('score', data.get('risk_score', 0)))
        level = risk.get('level', 'LOW')
        interpretation = self._display_interpretation(data)
        display_origin, display_source = self._format_origin_strings(data)
        origin_label = data.get('origin_detection', {}).get('primary_origin', 'Unknown')
        
        loc_data = data.get('location') or data.get('metadata', {}).get('location', {})
        gps_addr = loc_data.get('full_address') or loc_data.get('location_name', 'No GPS data extracted')

        summary_lines = [
            "=== EXECUTIVE SUMMARY ===",
            f"Case Evidence       : {data.get('image_path') or data.get('evidence_integrity', {}).get('file_path', 'N/A')}",
            f"Risk Score          : {risk_score:.1f}/100 ({level})",
            f"Interpretation      : {interpretation}",
            f"Primary Origin      : {display_origin}",
            f"Source Inference    : {display_source}",
            f"GPS Full Address    : {gps_addr}",
            f"Analysis Date       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
        screenshot_rows = self._screenshot_device_rows(data) if origin_label == 'screenshot_capture' else []
        
        if origin_label == 'screenshot_capture':
            if screenshot_rows:
                summary_lines.append("=== SCREENSHOT DEVICE ANALYSIS ===")
                for label, value in screenshot_rows:
                    summary_lines.append(f"{label:<28}: {value}")
                screenshot_info = data.get('origin_detection', {}).get('screenshot_device_info', {}) or {}
                for section, items in [
                    ('Key Evidence', screenshot_info.get('key_evidence', [])),
                    ('Digital Markers', screenshot_info.get('digital_markers', [])),
                    ('Limitations', screenshot_info.get('limitations', [])),
                ]:
                    if items:
                        summary_lines.append(f"{section}:")
                        for item in items:
                            summary_lines.append(f"  - {item}")
                summary_lines.append("")
            summary_lines.extend([
                "=== FORENSIC LIMITATIONS ===",
                "This identification is based on visual UI indicators and resolution mapping.",
                "While the software and OS are identified with high certainty, the specific physical hardware",
                "(e.g., Dell vs. HP) cannot be definitively determined from a windowed application screenshot alone.",
                ""
            ])

        history = data.get('modification_history', {})
        history_lines = []
        if isinstance(history, dict) and history:
            history_lines.append("=== MODIFICATION HISTORY ===")
            history_lines.append(f"Status              : {history.get('status', 'unknown')}")
            history_lines.append(f"Confidence          : {history.get('confidence', 'low')}")
            history_lines.append(f"Likely Modified     : {history.get('likely_modified', False)}")
            history_lines.append(f"Original Capture    : {history.get('original_capture_time', 'N/A')}")
            history_lines.append(f"Digitized Time      : {history.get('digitized_time', 'N/A')}")
            history_lines.append(f"File Modified Time  : {history.get('file_modified_time', 'N/A')}")
            history_lines.append(f"Summary             : {history.get('summary', 'No summary available.')}")
            software = self._display_detected_software(data)
            if software:
                history_lines.append(f"Software Detected   : {', '.join(str(item) for item in software)}")
            xmp_entries = history.get('xmp_history_entries', []) or []
            if xmp_entries:
                history_lines.append("XMP History Entries :")
                for item in xmp_entries:
                    history_lines.append(f"  - {item}")
            events = history.get('events', []) or []
            if events:
                history_lines.append("Events:")
                for event in events:
                    history_lines.append(
                        f"  - {event.get('event', 'N/A')} | {event.get('timestamp', 'N/A')} | {event.get('source', 'N/A')} | {event.get('confidence', 'N/A')} | {event.get('details', '')}"
                    )
        
        with open(path, 'w', encoding='utf-8') as f:
            if summary_lines:
                f.write("\n".join(summary_lines))
                f.write("\n")
            if history_lines:
                f.write("\n".join(history_lines))
                f.write("\n\n")
            f.write(formatted_text)


__all__ = ['ForensicReportGenerator']
