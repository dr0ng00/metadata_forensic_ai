
```text
###############################################################################################
##                                                                                           ##
##  ##     ## ######## ########    ###    ########     ###    ########    ###                ##
##  ###   ### ##          ##      ## ##   ##     ##   ## ##      ##      ## ##               ##
##  #### #### ##          ##     ##   ##  ##     ##  ##   ##     ##     ##   ##              ##
##  ## ### ## ######      ##    ##     ## ##     ## ##     ##    ##    ##     ##             ##
##  ##     ## ##          ##    ######### ##     ## #########    ##    #########             ##
##  ##     ## ##          ##    ##     ## ##     ## ##     ##    ##    ##     ##             ##
##  ##     ## ########    ##    ##     ## ########  ##     ##    ##    ##     ##             ##
##                                                                                           ##
##  ########  #######  ########  ######## ##    ##  ######  ####  ######      ###    ####    ##
##  ##       ##     ## ##     ## ##       ###   ## ##    ##  ##  ##    ##    ## ##    ##     ##
##  ##       ##     ## ##     ## ##       ####  ## ##        ##  ##         ##   ##   ##     ##
##  ######   ##     ## ########  ######   ## ## ##  ######   ##  ##        ##     ##  ##     ##
##  ##       ##     ## ##   ##   ##       ##  ####       ##  ##  ##        #########  ##     ##
##  ##       ##     ## ##    ##  ##       ##   ### ##    ##  ##  ##    ##  ##     ##  ##     ##
##  ##        #######  ##     ## ######## ##    ##  ######  ####  ######   ##     ## ####    ##
##                                                                                           ##
##                  METADATA EXTRACTION AND IMAGE ANALYSIS SYSTEM                            ##
##                                                                                           ##
###############################################################################################
```




# MetaForensicAI

AI-assisted digital image forensics focused on metadata extraction, provenance analysis, origin classification, explainable risk scoring, and report generation.  

## Overview

MetaForensicAI analyzes image evidence using a multi-stage forensic pipeline built around:

- evidence integrity checks and hashing
- EXIF/XMP/IPTC and file metadata extraction
- origin detection for camera, screenshot, social-media redistribution, and synthetic/AI-like signals
- structural analysis such as compression and artifact inspection
- contextual and timestamp consistency checks
- explainable risk scoring and report generation

The project exposes the same core engine through:

- a CLI entrypoint via `forensicai.py`
- the main package in `src`
- a FastAPI backend in `src/interface/forensic_api.py`

## Features

- forensic-style image intake with integrity metadata
- metadata extraction with Python fallback and ExifTool support
- origin and redistribution detection
- artifact and compression analysis
- Bayesian and rule-based risk assessment
- explainability output for analyst review
- PDF, HTML, JSON, and text report generation
- batch processing support
- API integration for uploaded evidence workflows

## Repository Layout

```
.
|-- forensicai.py              # main CLI launcher
|-- src/                       # application package
|   |-- analysis/              # scoring, artifact, contextual, and correlation logic
|   |-- core/                  # extraction, evidence handling, origin detection
|   |-- explanation/           # explainability layer
|   |-- interface/             # CLI assistant and FastAPI backend
|   |-- reporting/             # report generation
|   `-- utils/                 # support utilities
|-- config/                    # default config and forensic rules
|-- scripts/
|   |-- analysis/              # focused helper scripts
|   |-- dataset/               # dataset prep/statistics utilities
|   |-- experiments/           # one-off generators and debugging helpers
|   `-- verification/          # manual verification scripts
|-- tests/                     # automated test suite
|   `-- manual/                # manual checks excluded from default pytest discovery
`-- results/                   # generated reports and exports
```

## Requirements

- Python 3.8+
- Windows, Linux, or macOS
- ExifTool recommended for full metadata extraction

Core Python dependencies are listed in `requirements.txt`.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/dr0ng00/metadata_forensic_ai.git
cd metadata_forensic_ai
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
.venv\Scripts\activate
```

On PowerShell, if needed:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. ExifTool

The project can fall back to Python-based extraction, but ExifTool is preferred for higher-fidelity metadata access.

- On Windows, the project may attempt to prepare ExifTool automatically when native extraction is first needed.
- If ExifTool is already available in PATH, it will be used directly.

## Quick Start

### Graphical User Interface (GUI)

Launch the Streamlit-based web interface for visual analysis:

```bash
python forensicai.py --gui
```

### Interactive Wizard (Recommended)

Launch the guided setup to select targets and analysis options through a series of prompts:

```bash
python forensicai.py
```

### Command Line Examples

Analyze a single image:

```bash
python forensicai.py --image path/to/evidence.jpg --report all
```

Analyze a directory (Batch Mode):

```bash
python forensicai.py --batch path/to/folder --report json
```

Compare multiple images:

```bash
python forensicai.py --compare image1.jpg image2.jpg --compare-type metadata
```

Interactive AI assistant:

```bash
python forensicai.py --image path/to/evidence.jpg --ask
```

Explain mode:

```bash
python forensicai.py --image path/to/evidence.jpg --ai-mode explain --report html
```

## CLI Usage

```
usage: forensicai.py [-h] [--image IMAGE | --batch BATCH] [--output OUTPUT] [--ai-mode {explain}] [--ask [ASK]]
                     [--report {pdf,json,html,txt,json-cli,raw-cli,both,all,none}] [--config CONFIG] [--case-id CASE_ID]
                     [--analyst ANALYST] [--max-images MAX_IMAGES] [--verbose] [--debug]

Metadata Extraction And Image Analysis System

options:
  -h, --help            show this help message and exit
  --image, -i IMAGE     Path to image file for analysis
  --batch, -b BATCH     Path to directory for batch analysis
  --output, -o OUTPUT   Output directory for reports (default: ./results)
  --ai-mode {explain}   MetaForensic AI analysis mode (current option: explain)
  --ask [ASK]           Launch MetaForensic AI chatbox after analysis, optionally with an initial question.
  --report, -r {pdf,json,html,txt,json-cli,raw-cli,both,all,none}
                        Report format. Use "json-cli" for narrative or "raw-cli" for raw metadata to stdout. (default: all)
  --config, -c CONFIG   Path to configuration file
  --case-id CASE_ID     Case identifier for reporting
  --analyst ANALYST     Analyst name for reporting
  --max-images MAX_IMAGES
                        Maximum number of images for batch analysis
  --verbose, -v         Enable verbose logging
  --debug, -d           Enable debug mode with detailed output

Examples:
  forensicai.py --image evidence.jpg
  forensicai.py --batch evidence_folder/ --output reports/
  forensicai.py --image evidence.jpg --report pdf --verbose
```

### Supported Report Formats

- **pdf** - Professional PDF report with charts and visualizations
- **html** - Interactive HTML report with detailed findings
- **txt** - Plain text summary report
- **json-cli** - Narrative JSON output to stdout
- **raw-cli** - Raw metadata output to stdout
- **both** - PDF and JSON formats
- **all** - All available formats (default)
- **none** - No report generation

The main implementation lives in `src/main.py`.

## API Usage

Run the API server module directly:

```bash
python -m src.interface.forensic_api
```

Default behavior:

- listens on `0.0.0.0:8000`
- exposes `/`, `/analyze`, `/cases/{case_id}`, and `/health`

Example health check:

```bash
curl http://127.0.0.1:8000/health
```

## Verification and Support Scripts

Manual verification scripts are grouped by purpose:

- `scripts/verification`
- `scripts/experiments`
- `scripts/analysis`
- `scripts/dataset`

Examples:

```bash
python scripts/verification/verify_api.py
python scripts/verification/verify_phase3.py
python scripts/experiments/create_gps_test_image.py
```

## Testing

Run the default automated test suite:

```bash
pytest
```

Manual checks under `tests/manual` are intentionally excluded from default test discovery.

## Output

Generated artifacts typically land under `results` and related report folders, depending on the CLI options used.

Common output formats:

- JSON
- HTML
- PDF
- TXT

## Configuration

Primary configuration files:

- `config/default_config.yaml`
- `config/forensic_rules.json`

You can pass a custom config file to the CLI with:

```bash
python forensicai.py --config path/to/config.yaml --image path/to/evidence.jpg
```

## Development Notes

- package metadata is defined in `pyproject.toml`
- the project currently contains some in-progress source changes outside this README
- the top-level launcher remains `forensicai.py`

