import streamlit as st
import os
import sys
from pathlib import Path
from PIL import Image
import tempfile
import plotly.express as px
import plotly.graph_objects as go
import json
import logging
import re

# Ensure src modules can be imported
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

try:
    from src.main import MetaForensicAI
    from src.reporting.report_generator import ForensicReportGenerator
    from src.utils.exiftool_formatter import ExifToolStyleFormatter
    import streamlit.components.v1 as components
    import pandas as pd
except ImportError as e:
    st.error(f"Failed to import MetaForensicAI backend. Please run this app from the root of the repository. Details: {e}")
    st.stop()

st.set_page_config(page_title="MetaForensic AI", page_icon=":mag:", layout="wide")

# CSS adjustments for cleaner UI
st.markdown("""
<style>
[data-testid="stToolbar"] {
    display: none !important;
}
[data-testid="stDecoration"] {
    display: none !important;
}
[data-testid="stStatusWidget"] {
    display: none !important;
}
#MainMenu {
    visibility: hidden;
}
header {
    visibility: hidden;
}
footer {
    visibility: hidden;
}

.metric-box {
    background-color: #1E1E1E;
    border-radius: 10px;
    padding: 20px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
    margin-bottom: 20px;
    border-left: 5px solid #00A676;
}
.metric-box-warn {
    border-left: 5px solid #F4A261;
}
.metric-box-danger {
    border-left: 5px solid #E63946;
}
h1, h2, h3 {
    color: #E0E0E0;
}
</style>
""", unsafe_allow_html=True)

st.title("MetaForensic AI")
st.markdown("### METADATA EXTRACTION AND IMAGE ANALYSIS SYSTEM")
st.divider()

@st.cache_resource
def get_analyzer():
    # Cache the backend to avoid reloading models on every file upload interaction
    return MetaForensicAI()

analyzer = get_analyzer()


def _sanitize_report_part(value: str, fallback: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]+", "_", (value or "").strip())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or fallback


def _report_base_name(analyst_name_value: str, case_id_value: str) -> str:
    analyst_part = _sanitize_report_part(analyst_name_value, "Analyst")
    case_part = _sanitize_report_part(case_id_value, "Case")
    return f"{analyst_part}_{case_part}"


def _rename_report_file(original_path: str, base_name: str) -> str:
    if not original_path or not os.path.exists(original_path):
        return original_path

    source_path = Path(original_path)
    target_path = source_path.with_name(f"{base_name}{source_path.suffix}")

    if source_path == target_path:
        return str(source_path)

    if target_path.exists():
        counter = 2
        while True:
            candidate = source_path.with_name(f"{base_name}_{counter}{source_path.suffix}")
            if not candidate.exists():
                target_path = candidate
                break
            counter += 1

    source_path.replace(target_path)
    return str(target_path)


def _is_named_camera_device(value: str) -> bool:
    text = str(value or "").strip()
    if not text or text.lower() in {"unknown", "camera", "screenshot", "unknown device", "mobile device", "none", "none none", "null", "null null"}:
        return False
    disallowed_tokens = ["screenshot", "desktop", "laptop", "windowed application capture", "mobile device", "virtual"]
    return not any(token in text.lower() for token in disallowed_tokens)


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _resolve_primary_origin_display(analysis_results: dict) -> str:
    try:
        display_origin, _ = ForensicReportGenerator()._format_origin_strings(analysis_results)
        return str(display_origin or "Unknown")
    except Exception:
        origin = _as_dict(analysis_results.get('origin_detection'))
        return str(origin.get('primary_origin', 'Unknown'))

# Sidebar Config
st.sidebar.header("Analysis Configuration")
case_id = st.sidebar.text_input("Case ID (Optional)", "STREAMLIT-SEC-1")
analyst_name = st.sidebar.text_input("Analyst Name (Optional)", "Admin")
ai_mode = "explain"

st.sidebar.markdown("---")
st.sidebar.info("Upload standard image files directly or drag and drop. The MetaForensic AI pipeline will automatically parse anomalies, ELA, and metadata.")

if 'folder_process_list' not in st.session_state:
    st.session_state.folder_process_list = []
if 'analysis_results_cache' not in st.session_state:
    st.session_state.analysis_results_cache = {}

input_mode = st.radio("Select Input Method:", ["Select Files / Drag-Drop", "Local Folder Path"])

process_list = []

if input_mode == "Select Files / Drag-Drop":
    st.session_state.folder_process_list = []
    uploaded_files = st.file_uploader(
        "Drop Image files here for Forensic Analysis", 
        type=["jpg", "jpeg", "png", "webp", "heic", "tiff"],
        accept_multiple_files=True
    )
    if uploaded_files:
        for f in uploaded_files:
            # Check if file already analyzed
            if f.name not in st.session_state.analysis_results_cache:
                tmp = tempfile.NamedTemporaryFile(delete=False, suffix=Path(f.name).suffix)
                tmp.write(f.getvalue())
                tmp.close()
                process_list.append({"name": f.name, "path": tmp.name, "is_tmp": True, "file_obj": f})
            else:
                process_list.append({"name": f.name, "path": "", "is_tmp": False, "file_obj": f})
else:
    folder_path = st.text_input("Enter the absolute path to a local folder (e.g. C:\Evidence\Case1):")
    if folder_path and os.path.isdir(folder_path):
        valid_exts = {".jpg", ".jpeg", ".png", ".webp", ".heic", ".tiff"}
        if st.button("Start Folder Batch Analysis"):
            new_list = []
            for root, _, files in os.walk(folder_path):
                for file in files:
                    if Path(file).suffix.lower() in valid_exts:
                        new_list.append({"name": file, "path": os.path.join(root, file), "is_tmp": False})
            st.session_state.folder_process_list = new_list
            if not new_list:
                st.warning("No valid images found in the specified folder.")
    elif folder_path:
        st.error("Directory not found. Please enter a valid absolute path.")

    process_list = st.session_state.folder_process_list

if process_list:
    for item in process_list:
        st.markdown(f"## Case Evidence: `{item['name']}`")
        
        # 1. Preview
        try:
            preview_src = item.get('file_obj') or item.get('path')
            if preview_src:
                st.image(preview_src, width=400)
        except Exception:
            st.warning("Preview not available for this format.")
        
        # 2. Analyze
        try:
            if item['name'] not in st.session_state.analysis_results_cache:
                with st.spinner(f"Executing Forensic Modules for {item['name']}... Please wait."):
                    analysis_results = analyzer.analyze_image(item['path'], case_info={"case_id": case_id}, ai_mode=ai_mode)
                    if item.get('is_tmp') and item.get('path') and os.path.exists(item['path']):
                        os.remove(item['path'])
                
                    rg = ForensicReportGenerator()
                    report_paths = rg.generate("Forensic Analysis Report", analysis_results, output_dir=tempfile.gettempdir(), formats=["pdf", "txt", "html"])
                    report_base_name = _report_base_name(analyst_name, case_id)
                    report_paths["pdf"] = _rename_report_file(report_paths.get("pdf"), report_base_name)
                    report_paths["txt"] = _rename_report_file(report_paths.get("txt"), report_base_name)
                    
                    st.session_state.analysis_results_cache[item['name']] = {
                        'results': analysis_results,
                        'reports': report_paths
                    }
                    st.success("Analysis Complete!")
            
            # Fetch from cache
            cache_data = st.session_state.analysis_results_cache.get(item['name'])
            if not cache_data:
                continue
                
            analysis_results = cache_data['results']
            combined_raw = analysis_results
            report_paths = cache_data['reports']
            html_path = report_paths.get('html')
            pdf_path = report_paths.get('pdf')
            txt_path = report_paths.get('txt')
            
            # 4. Display Dashboard
            tab_exec, tab_ai, tab_raw, tab_chat = st.tabs(["Executive Summary", "AI Explanations", "Investigative Raw Metadata", "Chatbox"])
        
            with tab_exec:
                risk = analysis_results.get('risk_assessment', {})
                risk_score = risk.get('risk_score', 0)
                risk_level = risk.get('level', 'UNKNOWN')
            
                # Determine color scheme
                box_class = "metric-box"
                if risk_level == "MEDIUM": box_class = "metric-box metric-box-warn"
                if risk_level in ["HIGH", "CRITICAL"]: box_class = "metric-box metric-box-danger"
            
                st.markdown(f"""
                <div class="{box_class}">
                    <h2>Risk Level: {risk_level}</h2>
                    <p><strong>Forensic Score:</strong> {risk_score:.1f}/100</p>
                    <p><strong>Unified Interpretation:</strong> {risk.get('unified_interpretation', 'Unknown')}</p>
                </div>
                """, unsafe_allow_html=True)
            
                col1, col2 = st.columns(2)
            
                # Origin Matrix
                with col1:
                    st.markdown("### Origin Detection")
                    origin = analysis_results.get('origin_detection', {})
                    source_inference = origin.get('source_inference', 'Unknown')
                    capture_device = origin.get('capture_device_inference', 'Unknown')
                    if str(source_inference).strip() in {'', 'Unknown'} and str(capture_device).strip() not in {'', 'Unknown'}:
                        source_inference = "Camera"
                    st.info(f"**Primary Origin:** {_resolve_primary_origin_display(analysis_results)}")
                    st.info(f"**Source Inference:** {source_inference}")
                
                    if origin.get("capture_device_inference"):
                         st.write(f"Capture Device Inference: `{origin.get('capture_device_inference')}`")
                
                # Authentication Matrix
                with col2:
                    st.markdown("### Authenticity & Integrity")
                    auth = analysis_results.get('artifact_analysis', {})
                    ela = auth.get('ela_results', {})
                    st.write(f"**ELA Intensity Status:** {ela.get('ela_intensity', 'N/A')}")
                    st.write(f"**Q-Table Status:** {auth.get('qtable_audit', {}).get('status', 'SKIPPED')}")
                
                    timestamp_anomalies = analysis_results.get('timestamp_analysis', {}).get('issues', [])
                    if timestamp_anomalies:
                        st.error(f"{len(timestamp_anomalies)} Timestamp conflicts detected!")
                    else:
                        st.success("No Temporal Conflicts Found.")
            
                # Render a gauge chart for Risk
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = risk_score,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Evidence Manipulation Risk (%)"},
                    gauge = {
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "white"},
                        'steps': [
                            {'range': [0, 30], 'color': "green"},
                            {'range': [30, 70], 'color': "yellow"},
                            {'range': [70, 100], 'color': "red"}],
                    }
                ))
                st.plotly_chart(fig, use_container_width=True, key=f"gauge_{item['name']}")

            with tab_ai:
                st.header("Forensic AI Explanations & Native Report")
            
                # Render download buttons
                st.markdown("### Export Forensic Reports")
                col_dl1, col_dl2 = st.columns(2)
            
                if pdf_path and os.path.exists(pdf_path):
                    with open(pdf_path, "rb") as f:
                        col_dl1.download_button("Download PDF Report", f, file_name=os.path.basename(pdf_path), mime="application/pdf")
            
                if txt_path and os.path.exists(txt_path):
                    with open(txt_path, "r", encoding="utf-8") as f:
                        col_dl2.download_button("Download Text Report", f.read(), file_name=os.path.basename(txt_path), mime="text/plain")
                    
                st.divider()
                st.markdown("### Interactive Digital Report")
                if html_path and os.path.exists(html_path):
                    with open(html_path, "r", encoding="utf-8") as f:
                        html_content = f.read()
                    
                    # Inject a dark mode theme dynamically for the GUI to match Streamlit default dark
                    dark_mode_css = """
                    <style>
[data-testid="stToolbar"] {
    display: none !important;
}
[data-testid="stDecoration"] {
    display: none !important;
}
[data-testid="stStatusWidget"] {
    display: none !important;
}
#MainMenu {
    visibility: hidden;
}
header {
    visibility: hidden;
}
footer {
    visibility: hidden;
}                        :root {
                            --primary: #818cf8 !important;
                            --secondary: #3b82f6 !important;
                            --accent: #f87171 !important;
                            --bg-main: transparent !important;
                            --card-bg: #1E1E1E !important;
                            --text-main: #e2e8f0 !important;
                            --text-muted: #94a3b8 !important;
                            --border: #334155 !important;
                            --success: #34d399 !important;
                            --warning: #fbbf24 !important;
                        }
                        body { background-color: transparent !important; color: #e2e8f0 !important; }
                        .summary, .metadata-box { background-color: #1E1E1E !important; border-color: #334155 !important; box-shadow: none !important; }
                        .explanation-note { background-color: #0f172a !important; color: #93c5fd !important; border-left-color: #3b82f6 !important; }
                        th { background-color: #334155 !important; color: #f8fafc !important; border-bottom: 1px solid #475569 !important; }
                        tr:hover td { background-color: #1e293b !important; }
                        td { border-bottom: 1px solid #334155 !important; }
                        h2 { color: #818cf8 !important; border-bottom: 2px solid #334155 !important; }
                        h3 { color: #60a5fa !important; }
                    </style>
                    """
                    html_content = html_content.replace("</style>", "</style>\n" + dark_mode_css)
                
                    components.html(html_content, height=1200, scrolling=True)
                else:
                    st.error("HTML Interactive Report failed to generate.")

            with tab_raw:
                st.header("Investigative Raw Metadata")
                st.markdown("The unfiltered metadata extracted from the file, providing raw data for manual cross-referencing.")
            
                # Render the raw ExifTool-style console formatted text
                st.code(ExifToolStyleFormatter.format(combined_raw.get('metadata', {})), language="yaml")
            
                # Build the filtered Attributes Table identically to the HTML report
                flat_metadata = ExifToolStyleFormatter._flatten_metadata(combined_raw.get('metadata', {}) or {})
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
                    {"Attribute": key, "Value": str(value)} for key, value in sorted(flat_metadata.items())
                    if key not in USER_EXCLUDED_ATTRS
                ]
            
                if metadata_rows:
                    st.markdown("### Significant Extracted Attributes")
                    st.dataframe(pd.DataFrame(metadata_rows), use_container_width=True, hide_index=True)

            with tab_chat:
                st.header("Forensic Chatbox")
                st.markdown(f"Ask the AI assistant questions about evidence `{item['name']}`.")
                from src.interface.natural_language_processor import NaturalLanguageProcessor
                nlp = NaturalLanguageProcessor()
                
                chat_key = f"chat_{item['name']}"
                if chat_key not in st.session_state:
                     suggested = nlp.get_suggested_questions(combined_raw)
                     intro = "Ask in natural language, short prompts, or broken English. Examples:\n" + "\n".join(
                         [f"- {q}" for q in suggested[:4]]
                     )
                     st.session_state[chat_key] = [{"role": "assistant", "content": intro}]

                suggested_questions = nlp.get_suggested_questions(combined_raw)
                st.caption("Suggested questions")
                st.markdown("\n".join([f"- {q}" for q in suggested_questions]))
                
                # Render existing messages
                for msg in st.session_state[chat_key]:
                     if msg["role"] == "user":
                          st.chat_message("user").markdown(msg["content"])
                     else:
                          st.chat_message("assistant").markdown(msg["content"])
                
                # Accept new input
                if prompt := st.chat_input(f"Ask about {item['name']}...", key=f"input_{item['name']}"):
                     st.session_state[chat_key].append({"role": "user", "content": prompt})
                     st.chat_message("user").markdown(prompt)
                          
                     parsed = nlp.parse(prompt)
                     response = nlp.respond(parsed, combined_raw)
                     
                     st.chat_message("assistant").markdown(response)
                     st.session_state[chat_key].append({"role": "assistant", "content": response})

        except Exception as e:
            st.error(f"Analysis Failed Execution: {e}")
            logging.error(e, exc_info=True)
            if item.get('is_tmp') and os.path.exists(item.get('path', '')):
                os.remove(item['path'])




