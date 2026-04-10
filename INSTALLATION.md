# Installation and Setup Guide

## Metadata Extraction and Image Analysis System

---

## TABLE OF CONTENTS

1. [System Requirements](#system-requirements)
2. [Pre-Installation Checklist](#pre-installation-checklist)
3. [Step-by-Step Installation](#step-by-step-installation)
4. [ExifTool Installation](#exiftool-installation)
5. [Python Environment Setup](#python-environment-setup)
6. [Dependency Installation](#dependency-installation)
7. [Configuration](#configuration)
8. [Verification and Testing](#verification-and-testing)
9. [Troubleshooting](#troubleshooting)
10. [Docker Installation](#docker-installation)

---

## SYSTEM REQUIREMENTS

### Operating Systems

**Supported:**
- Windows 10/11 (Professional or higher recommended)
- Ubuntu 18.04+ (Focal, Jammy, Kinetic)
- Fedora 30+
- Debian 10+
- macOS 10.14+ (Intel and Apple Silicon)
- CentOS 7+

**Not Tested (but may work):**
- Older Windows versions (7, 8)
- Early-stage Linux distributions
- Older macOS versions

### Hardware Requirements

**Minimum (Basic Analysis):**
| Component | Specification |
|-----------|---------------|
| CPU       | Intel Core i5 / AMD Ryzen 3 |
| RAM       | 8 GB (6 GB minimum possible) |
| Storage   | 10 GB free space (SSD recommended) |
| Network   | Internet connection for dependencies |

**Recommended (Production/Batch Processing):**
| Component | Specification |
|-----------|---------------|
| CPU       | Intel Core i7/i9 or AMD Ryzen 7 |
| RAM       | 16-32 GB |
| Storage   | 50+ GB SSD (for datasets and results) |
| GPU       | NVIDIA CUDA-capable (optional, for ML acceleration) |
| Network   | 1 Gbps+ for cloud deployment |

### Software Prerequisites

**Required:**
- Python 3.8+ (3.10+ recommended)
- pip (Python package manager)
- ExifTool (standalone binary)
- Git (optional, for cloning repository)

**Optional:**
- Docker & Docker Compose (for containerized deployment)
- CUDA Toolkit 11.0+ (for GPU acceleration)
- NVIDIA cuDNN (for GPU ML acceleration)

---

## PRE-INSTALLATION CHECKLIST

Before starting installation, verify:

- [ ] Operating system is supported
- [ ] Python 3.8+ is installed: `python --version` or `python3 --version`
- [ ] pip is installed: `pip --version` or `pip3 --version`
- [ ] Git is installed (optional): `git --version`
- [ ] At least 10 GB free disk space
- [ ] Administrator/sudo access if required
- [ ] Internet connection available

---

## STEP-BY-STEP INSTALLATION

### Installation Steps Overview

```
1. System Preparation
   ├─→ Verify Python installation
   ├─→ Update pip
   └─→ Install ExifTool

2. Project Setup
   ├─→ Clone/download project
   ├─→ Create virtual environment
   └─→ Activate environment

3. Dependency Installation
   ├─→ Install Python packages
   ├─→ Verify installations
   └─→ Install optional dependencies

4. Configuration
   ├─→ Copy default config
   ├─→ Customize settings
   └─→ Verify configuration

5. Verification
   ├─→ Run basic tests
   ├─→ Process sample image
   └─→ Verify output
```

### Step 1: Verify Python Installation

**Windows:**
```bash
python --version
```

**Linux/macOS:**
```bash
python3 --version
```

**Expected Output:**
```
Python 3.8.0
# or higher (3.9, 3.10, 3.11, 3.12 supported)
```

If Python is not installed, download from https://www.python.org/downloads/ and install.

### Step 2: Update pip

**Windows:**
```bash
python -m pip install --upgrade pip
```

**Linux/macOS:**
```bash
python3 -m pip install --upgrade pip
```

### Step 3: Clone or Download Project

**Option A: Clone with Git**
```bash
git clone https://github.com/your-repo/metadata_extraction_and_image_analysis_system.git
cd metadata_extraction_and_image_analysis_system
```

**Option B: Download ZIP**
1. Download ZIP from repository
2. Extract to desired location
3. Open terminal/command prompt in extracted directory

### Step 4: Create Python Virtual Environment

**Windows:**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

**Linux/macOS:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

**Verify Activation:**
You should see `(venv)` prefix in your terminal prompt.

### Step 5: Install ExifTool

ExifTool is a critical dependency that must be installed separately.

#### Windows Installation

**Option A: Using Chocolatey**
```bash
# If Chocolatey installed:
choco install exiftool
```

**Option B: Manual Installation**
1. Download from https://exiftool.org/
2. Extract to a known location (e.g., `C:\tools\exiftool\`)
3. Add to PATH:
   - Right-click "This PC" → Properties
   - Click "Advanced system settings"
   - Click "Environment Variables"
   - Under "System variables", click "New"
   - Variable name: `EXIFTOOL_PATH`
   - Variable value: `C:\tools\exiftool\`
   - Click OK and restart terminal

**Verify Installation:**
```bash
exiftool -ver
```

#### Linux Installation

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install exiftool

# Verify
exiftool -ver
```

**Fedora/CentOS:**
```bash
sudo dnf install perl-Image-ExifTool

# Verify
exiftool -ver
```

**Manual Installation:**
```bash
# Download and compile
wget http://www.exiftool.org/Image-ExifTool-12.60.tar.gz
tar -xzf Image-ExifTool-12.60.tar.gz
cd Image-ExifTool-12.60
perl Makefile.PL
make
sudo make install

# Verify
exiftool -ver
```

#### macOS Installation

**Using Homebrew:**
```bash
brew install exiftool

# Verify
exiftool -ver
```

**Manual Installation:**
```bash
# Download and extract
wget http://www.exiftool.org/Image-ExifTool-12.60.tar.gz
tar -xzf Image-ExifTool-12.60.tar.gz
cd Image-ExifTool-12.60
perl Makefile.PL
make
sudo make install

# Verify
exiftool -ver
```

### Step 6: Install Python Dependencies

**With Virtual Environment Activated:**

```bash
# Upgrade pip, setuptools, wheel
pip install --upgrade pip setuptools wheel

# Install project dependencies
pip install -r requirements.txt
```

**Installation Output:**
```
Collecting pillow==9.5.0
Downloading pillow-9.5.0-cp310-cp310-win_amd64.whl (2.2 MB)
  Downloading pillow-9.5.0-cp310-cp310-win_amd64.whl (2.2 MB)
Installing collected packages: pillow, numpy, ...
Successfully installed pillow-9.5.0 numpy-1.24.3 ...
```

**Expected Installation Time:**
- Fast connection: 5-15 minutes
- Slow connection: 15-45 minutes

### Step 7: Verify Installation

Test that all components are properly installed:

**Python:**
```bash
python --version
```

**ExifTool:**
```bash
exiftool -ver
```

**Key Python Packages:**
```bash
python -c "import pillow; print('Pillow OK')"
python -c "import pandas; print('Pandas OK')"
python -c "import sklearn; print('Scikit-learn OK')"
```

**Full System Verification:**
```bash
python -c "from src.core.metadata_extractor import MetadataExtractor; print('System ready!')"
```

---

## PYTHON ENVIRONMENT SETUP

### Using venv (Built-in)

**Creation:**
```bash
python -m venv venv
```

**Activation:**
```bash
# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate
```

**Deactivation:**
```bash
deactivate
```

### Using Anaconda/Miniconda (Alternative)

**Installation:**
Download from https://www.conda.io/projects/conda/en/latest/user-guide/install/

**Creation:**
```bash
conda create -n forensic python=3.10
```

**Activation:**
```bash
conda activate forensic
```

**Install Dependencies:**
```bash
pip install -r requirements.txt
```

### Using Poetry (Advanced)

**Installation:**
```bash
pip install poetry
```

**Setup:**
```bash
poetry install
poetry shell
```

---

## DEPENDENCY INSTALLATION

### Core Dependencies

The `requirements.txt` includes essential packages:

```
# Image Processing
Pillow==9.5.0
pillow-heif==0.15.0
opencv-python==4.8.0

# Data Analysis
pandas==2.0.3
numpy==1.24.3
scipy==1.11.2

# Machine Learning
scikit-learn==1.3.1
tensorflow==2.13.0
keras==2.13.1

# Web Frameworks
Flask==2.3.3
FastAPI==0.103.1
Streamlit==1.28.1

# Utilities
PyYAML==6.0.1
exifread==3.0.0
cryptography==41.0.4

# ... and 20+ additional packages
```

### Optional Dependencies

**For GPU Acceleration:**
```bash
pip install tensorflow-gpu cuda-toolkit cupy
```

**For Advanced ML:**
```bash
pip install xgboost lightgbm pytorch
```

**For Development:**
```bash
pip install pytest pytest-cov black flake8 mypy
```

**For Documentation:**
```bash
pip install sphinx sphinx-rtd-theme
```

---

## CONFIGURATION

### Step 1: Copy Default Configuration

```bash
# From project root
cp config/default_config.yaml config/active_config.yaml
```

### Step 2: Basic Configuration

Edit `config/active_config.yaml`:

```yaml
system:
  forensic_mode: true                    # Enable forensic features
  exiftool_path: "exiftool"             # ExifTool binary location
  hash_algorithms:
    - sha256
    - sha3_256
    - blake2b

analysis:
  extract_metadata: true
  detect_origin: true
  detect_authenticity: true
  enable_explanations: true

logging:
  level: INFO                           # DEBUG, INFO, WARNING, ERROR
  forensic_log: true
  chain_of_custody: true
  log_file: "logs/forensic.log"
```

### Step 3: Advanced Configuration

For detailed configuration options, see `config/default_config.yaml` with examples:

```yaml
# ML Model Configuration
ml_models:
  origin_detector:
    model_type: "ensemble"
    classifiers:
      - "logistic_regression"
      - "svm"
      - "random_forest"
      - "decision_tree"

# Output Configuration
output:
  formats:
    - "json"
    - "html"
    - "txt"
  include_images_in_html: true
  compression: "gzip"

# Forensic Settings
forensic:
  standard: "ISO 27037"
  chain_of_custody: true
  immutable_logs: true
  audit_retention_days: 365
```

---

## VERIFICATION AND TESTING

### Basic Functionality Test

**Test Script:**
```bash
python -c "
from src.core.metadata_extractor import MetadataExtractor
from src.core.forensic_analyzer import MetadataAuthenticityAnalyzer

print('✓ Imports successful')

# Test metadata extraction
try:
    analyzer = MetadataAuthenticityAnalyzer()
    print('✓ Analyzer initialization successful')
except Exception as e:
    print(f'✗ Error: {e}')
"
```

### Process Sample Image

```bash
# Copy a test image or download one
python -c "
from src.core.forensic_analyzer import MetadataAuthenticityAnalyzer
import json

# Initialize
analyzer = MetadataAuthenticityAnalyzer()

# Analyze
image_path = 'test_images/sample.jpg'  # Use an actual image
results = analyzer.analyze_image(image_path)

# Display results
print(json.dumps(results, indent=2, default=str))
"
```

### Launch GUI

```bash
python forensicai.py --gui
```

### Run Unit Tests

```bash
# Run all tests
pytest tests/ -v

# Run specific test module
pytest tests/test_metadata_analyzer.py -v

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

**Expected test output:**
```
tests/test_metadata_analyzer.py::test_exif_extraction PASSED
tests/test_metadata_analyzer.py::test_gps_parsing PASSED
tests/test_origin_detector.py::test_classification PASSED
...
======= 42 passed in 12.34s =======
```

### Check Installation

```bash
# Create simple verification script
cat > verify_installation.py << 'EOF'
#!/usr/bin/env python
import sys

print("Metadata Extraction and Image Analysis System - Installation Verification")
print("=" * 70)

# Check Python version
print(f"Python version: {sys.version}")
assert sys.version_info >= (3, 8), "Python 3.8+ required"
print("✓ Python version OK")

# Check key packages
packages = [
    'PIL', 'pandas', 'numpy', 'sklearn', 'tensorflow',
    'cv2', 'flask', 'yaml', 'exifread'
]

for package in packages:
    try:
        __import__(package)
        print(f"✓ {package} installed")
    except ImportError:
        print(f"✗ {package} NOT installed")
        sys.exit(1)

# Check ExifTool
import subprocess
try:
    result = subprocess.run(['exiftool', '-ver'], capture_output=True)
    print(f"✓ ExifTool version: {result.stdout.decode().strip()}")
except FileNotFoundError:
    print("✗ ExifTool not found in PATH")
    sys.exit(1)

# Check system modules
try:
    from src.core.metadata_extractor import MetadataExtractor
    from src.core.forensic_analyzer import MetadataAuthenticityAnalyzer
    from src.explanation.report_generator import ReportGenerator
    print("✓ Core modules imported successfully")
except ImportError as e:
    print(f"✗ Failed to import core modules: {e}")
    sys.exit(1)

print("=" * 70)
print("✓ Installation verification PASSED!")
print("System is ready for use.")
EOF

python verify_installation.py
```

---

## TROUBLESHOOTING

### Common Issues and Solutions

#### Issue 1: "ExifTool not found"

**Cause:** ExifTool not installed or not in PATH

**Solutions:**
```bash
# Check if installed
exiftool -ver

# If not found, install based on your OS:
# Windows:
choco install exiftool

# Ubuntu:
sudo apt-get install exiftool

# macOS:
brew install exiftool

# After installation, restart your terminal
```

#### Issue 2: "Module not found" errors

**Cause:** Dependencies not installed

**Solutions:**
```bash
# Verify virtual environment is activated
# Should see (venv) in prompt

# Reinstall dependencies
pip install --upgrade -r requirements.txt

# Check specific package
pip show pillow
```

#### Issue 3: "Permission denied" on Linux/macOS

**Cause:** File permission issues

**Solutions:**
```bash
# Make scripts executable
chmod +x src/interface/cli_assistant.py

# Fix ownership if needed
sudo chown -R $USER:$USER /path/to/project
```

#### Issue 4: "CUDA not available" (GPU-related)

**Cause:** TensorFlow trying to use non-existent GPU

**Solutions:**
```bash
# Set CPU-only mode
export TF_CPP_MIN_LOG_LEVEL=2
export CUDA_VISIBLE_DEVICES=-1

# Or install CPU-only TensorFlow
pip install tensorflow-cpu
```

#### Issue 5: "Pillow/PIL import error"

**Cause:** Pillow not properly installed

**Solutions:**
```bash
# Reinstall Pillow
pip uninstall pillow
pip install --force-reinstall pillow

# For HEIF support
pip install pillow-heif

# Test
python -c "from PIL import Image; print('PIL OK')"
```

#### Issue 6: Memory errors on large batches

**Cause:** Insufficient RAM for parallel processing

**Solutions:**
```yaml
# Modify config/active_config.yaml
batch_processing:
  max_workers: 2          # Reduce from default 4 or 8
  memory_limit: 2048      # Limit per worker in MB
```

### Debugging

**Enable Debug Logging:**
```yaml
# In config/active_config.yaml
logging:
  level: DEBUG
  forensic_log: true
  log_file: "logs/debug.log"
```

**Run with Verbose Output:**
```bash
python -v src/interface/cli_assistant.py --image test.jpg
```

---

## DOCKER INSTALLATION

### Option 1: Using Pre-built Docker Image

```bash
# Pull image (if available)
docker pull your-registry/forensic-analyzer:latest

# Run container
docker run -it -v $(pwd)/images:/data your-registry/forensic-analyzer:latest \
  python src/interface/cli_assistant.py --image /data/sample.jpg
```

### Option 2: Build Docker Image

**Dockerfile (create in project root):**
```dockerfile
FROM python:3.10-slim

# Install ExifTool
RUN apt-get update && apt-get install -y \
    exiftool \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose API port
EXPOSE 8000

# Default command
CMD ["python", "src/interface/cli_assistant.py"]
```

**Build Image:**
```bash
docker build -t forensic-analyzer:latest .
```

**Run Container:**
```bash
docker run -it -p 8000:8000 -v $(pwd)/images:/app/images forensic-analyzer:latest
```

---

**Installation Guide Version:** 1.0  
**Last Updated:** March 2026
