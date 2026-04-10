# MetaForensicAI - Detailed Project Requirements and Technologies

This document provides a comprehensive list of all tools, libraries, and technologies utilized in the MetaForensicAI project, categorized by their functional roles.

## 1. Image & Multimedia Processing
- **Pillow / pillow-heif**: Foundational libraries for image loading, format validation, reading embedded color profiles, structural validation and handling HEIF/HEIC Apple formats.
- **opencv-python (OpenCV)**: Used for advanced pixel-level forensic operations (e.g., Error Level Analysis, noise variation, structural analysis) and transformations.

## 2. Metadata Extraction & Provenance
- **exifread & piexif**: Python-native reading and parsing of EXIF and metadata markers.
- **pyexiv2**: Currently being integrated as a robust C++ binding for EXIF, IPTC and XMP metadata extraction.
- **ExifTool (External Perl tool)**: A robust, platform-independent tool natively integrated for advanced metadata extractions like C2PA (Content Authenticity Initiative) data and specialized manufacturer notes.

## 3. Machine Learning & Data Science
- **scikit-learn**: For risk scoring, clustering algorithms, decision heuristics and traditional machine learning integration.
- **torch (PyTorch) & torchvision**: Configured as an optional dependency for deep learning features, utilized for CNNs and Transformer-based manipulation detection and image content analysis.
- **numpy, pandas, & scipy**: Used for statistical calculation, large-scale matrix operations, managing evidence correlation datasets and scientific calculations.
- **joblib**: For loading and saving trained AI models computationally efficiently.

## 4. Utilities, Formatting & Output Generation
- **reportlab**: Used to generate forensic PDF reports algorithmically from findings.
- **Jinja2**: For templating HTML reports.
- **rich**: For stylized, colorful command-line outputs, tables and traceback formatting for investigator-facing CLI tools.
- **json5 & PyYAML**: To manage configuration files (forensic_config.yaml) and structured JSON results.
- **ImageHash**: Used for generating perceptual hashes (pHash, aHash, wHash) to correlate duplicate or modified evidence copies visually.

## 5. System, Networking & Command-Line Interfaces (CLI)
- **click & prompt-toolkit**: Provide advanced command-line navigation and interactive prompts.
- **psutil**: To monitor system memory usage during large batch forensic operations and chunking large folders.
- **requests**: For contacting external APIs, resolving GPS coordinates (reverse geocoding features) or verifying threat intelligence hashes online.
- **tqdm**: Command-line progress bars during analysis steps.
- **tzlocal, pytz, python-dateutil**: Comprehensive timezone and timestamp checking across metadata extraction logic.

## 6. Code Quality, Development & Testing (Development/Testing only)
- **pytest & pytest-cov**: For unit and integration testing of the forensic modules.
- **black, isort, & flake8**: Code formatting, sorting imports and identifying syntactical bugs.
- **mypy**: Static type checking for code reliability.

## 7. Potential Frameworks (Configured as Optional/Currently Unused)
- **flask & flask-cors**: The configuration lists the ability to serve the system via a web interface, though the core currently uses Streamlit for the GUI.
- **sqlite**: Handled via Python's standard library to preserve forensic findings and chain-of-custody in a persistent database format.

## 8. GUI Dashboard (Streamlit)
- **streamlit**: Powers the interactive forensic dashboard and natural language chatbox.
- **plotly**: Handles interactive data visualizations and risk-scoring gauges.
