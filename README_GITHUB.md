# 🔍 Metadata Extraction & Image Analysis System for Digital Forensics

<div align="center">

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-blue)]()

A comprehensive digital forensics framework for authenticating images, detecting manipulation, and identifying origins through intelligent metadata extraction and AI-powered analysis.

[Features](#-features) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Installation](#-installation)

</div>

---

## 🎯 Overview

The **Metadata Extraction and Image Analysis System** is a production-grade forensic platform designed to analyze digital images and authenticate their origins. It combines deep metadata extraction, machine learning classification, and probabilistic inference to detect manipulation, identify image sources, and verify authenticity while maintaining forensic integrity standards.

### Why This Project?

Digital images are critical evidence in forensic investigations, yet distinguishing authentic photographs from AI-generated content, edited images, and screenshots has become increasingly challenging. This system addresses that gap.

---

## ✨ Features

### Core Capabilities
- **🔬 Deep Metadata Extraction** - Comprehensive EXIF, XMP, and embedded forensic artifact extraction
- **🎯 Origin Classification** - Identify image sources: camera-captured, edited, AI-generated, screenshots, synthetic
- **✅ Authenticity Verification** - Detect manipulation signs and inconsistencies
- **⏰ Timestamp Analysis** - Validate temporal consistency and exposure data
- **🤖 ML-Powered Analysis** - Logistic Regression, SVM, Random Forest, and Decision Tree classifiers
- **📊 Bayesian Inference** - Probabilistic confidence scoring and uncertainty quantification
- **🔗 Evidence Correlation** - Multi-signal fusion for comprehensive forensic assessment
- **📋 Forensic Compliance** - ISO 27037, NIST SP 800-86, and ACPO Guidelines adherence
- **🔐 Chain of Custody** - Complete audit trails and cryptographic hashing
- **📈 Batch Processing** - Analyze multiple images simultaneously with progress tracking
- **📑 Multi-format Reporting** - JSON, HTML, TXT, CSV, and PDF output formats

### Supported Image Formats
JPEG, PNG, TIFF, HEIF, RAW, WebP, and more

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager
- ExifTool (automatically configured during installation)

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/dr0ng00/metadata_forensic_ai.git
cd metadata_forensic_ai
```

#### 2. Create Virtual Environment
```bash
python -m venv .venv

# On Windows
.venv\Scripts\activate

# On Linux/macOS
source .venv/bin/activate
```

#### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 4. Run Initial Setup
```bash
python scripts/setup_forensic_env.py
```

### Basic Usage

#### Analyze a Single Image
```python
from src.main import ForensicAnalyzer

analyzer = ForensicAnalyzer()
results = analyzer.analyze_image("path/to/image.jpg")

print(f"Origin: {results['origin_detection']['predicted_origin']}")
print(f"Authenticity Score: {results['authenticity']['confidence_score']}")
print(f"Risk Level: {results['risk_assessment']['risk_level']}")
```

#### Batch Analysis
```python
from src.main import ForensicAnalyzer

analyzer = ForensicAnalyzer()
image_paths = ["image1.jpg", "image2.png", "image3.jpg"]
results = analyzer.batch_analyze(image_paths, output_format="html")

# Results saved to results/ directory
```

#### Command Line Interface
```bash
# Analyze single image
python forensic.py analyze --image path/to/image.jpg --output results.json

# Batch processing
python forensic.py batch --input-dir ./images --output-dir ./results

# Generate report
python forensic.py report --json results.json --format html
```

---

## 📁 Project Structure

```
.
├── src/                          # Main source code
│   ├── main.py                   # Primary API entry point
│   ├── analysis/                 # Analysis modules
│   ├── core/                     # Core forensic logic
│   ├── models/                   # ML models
│   ├── reporting/                # Report generation
│   └── utils/                    # Utility functions
├── scripts/                      # Utility scripts
│   ├── batch_analyzer.py         # Batch processing
│   ├── setup_forensic_env.py     # Environment setup
│   └── verification/             # Verification utilities
├── config/                       # Configuration files
│   ├── forensic_rules.json       # Forensic analysis rules
│   ├── default_config.yaml       # Default configuration
│   └── chatbox_prompt_corpus.json# NLP configurations
├── tests/                        # Unit and integration tests
├── results/                      # Analysis results directory
├── pyproject.toml                # Project metadata
├── requirements.txt              # Python dependencies
└── README.md                     # Detailed documentation
```

---

## 📚 Documentation

- **[Installation Guide](INSTALLATION.md)** - Comprehensive setup instructions
- **[Architecture Documentation](ARCHITECTURE.md)** - System design and module details
- **[Requirements Guide](REQUIREMENTS_EXHAUSTIVE.md)** - Complete dependency information
- **[API Reference](docs/API_REFERENCE.md)** - Detailed API documentation *(if available)*

---

## 🔧 Configuration

The system uses YAML configuration files for customization:

```yaml
# config/default_config.yaml
analysis:
  enable_authentication: true
  enable_origin_detection: true
  enable_manipulation_detection: true
  
output:
  formats: ["json", "html", "txt"]
  include_visualizations: true
  
ml_models:
  origin_classifier: "random_forest"
  confidence_threshold: 0.75
```

See [Installation Guide](INSTALLATION.md#configuration) for detailed configuration options.

---

## 🧪 Testing

Run the test suite:

```bash
# All tests
pytest tests/

# Specific test module
pytest tests/test_metadata_analyzer.py -v

# With coverage
pytest tests/ --cov=src --cov-report=html
```

Key test files:
- `test_metadata_analyzer.py` - Metadata extraction tests
- `test_origin_detector.py` - Origin classification tests
- `test_evidence_correlator.py` - Evidence fusion tests
- `test_integration.py` - End-to-end integration tests

---

## 📊 Performance & Accuracy

Expected performance metrics (see full results in technical documentation):

| Metric | Value |
|--------|-------|
| Origin Classification Accuracy | 92-96% |
| Manipulation Detection F1-Score | 0.89-0.93 |
| Average Analysis Time (Single Image) | 2-5 seconds |
| Batch Processing Throughput | 50-100 images/minute |
| Memory Usage (per image) | 100-300 MB |

*Results vary based on image characteristics and hardware configuration*

---

## 🛠️ Dependencies

### Core Libraries
- **Pillow** (>= 10.0.0) - Image processing
- **exifread** (>= 3.0.0) - EXIF metadata extraction
- **piexif** (>= 1.1.3) - EXIF manipulation
- **scikit-learn** (>= 1.3.0) - Machine learning models
- **numpy** & **pandas** - Data processing
- **ExifTool** - External metadata extraction tool

### Full dependency list in [requirements.txt](requirements.txt)

---

## 🚦 System Requirements

### Minimum
- CPU: Intel Core i5 / AMD Ryzen 3
- RAM: 8 GB
- Storage: 10 GB SSD
- Python 3.8+

### Recommended
- CPU: Intel Core i7/i9 or AMD Ryzen 7
- RAM: 16-32 GB
- Storage: 50+ GB SSD
- GPU: NVIDIA CUDA-capable (optional)

See [Installation Guide](INSTALLATION.md#system-requirements) for OS-specific details.

---

## 📝 Usage Examples

### Example 1: Authenticate an Image
```python
from src.main import ForensicAnalyzer

analyzer = ForensicAnalyzer()
results = analyzer.analyze_image("suspect_image.jpg")

if results['authenticity']['is_authentic']:
    print("Image appears to be authentic")
else:
    print(f"Manipulation indicators: {results['authenticity']['indicators']}")
```

### Example 2: Identify Image Source
```python
origin = results['origin_detection']['predicted_origin']
confidence = results['origin_detection']['confidence']

print(f"Image Source: {origin} ({confidence:.2%} confidence)")
```

### Example 3: Generate Forensic Report
```python
from src.reporting.report_generator import ReportGenerator

generator = ReportGenerator()
report = generator.generate_report(
    analysis_results=results,
    format="html",
    include_chain_of_custody=True
)
report.save("forensic_report.html")
```

---

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code style guidelines
- Pull request process
- Development setup
- Testing requirements

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** - see [LICENSE](LICENSE) file for details.

---

## 📖 Citation

If you use this system in your research or forensic work, please cite:

```bibtex
@software{forensic_image_analysis_2026,
  title={Metadata ForensicAI},
  author={Sivamani},
  year={2026},
  url={https://github.com/dr0ng00/metadata_forensic_ai}
}
```

---

## 🐛 Issues & Support

- **Bug Reports**: [GitHub Issues](https://github.com/dr0ng00/metadata_forensic_ai/issues)
- **Documentation**: See [README.md](README.md) and [INSTALLATION.md](INSTALLATION.md)
- **Troubleshooting**: Check [INSTALLATION.md#troubleshooting](INSTALLATION.md#troubleshooting)

### Common Issues
| Issue | Solution |
|-------|----------|
| ExifTool not found | Run `python scripts/setup_forensic_env.py` |
| Import errors | Ensure all dependencies installed: `pip install -r requirements.txt` |
| Memory issues | Reduce batch size or use streaming mode |

---

## 📊 Forensic Standards Compliance

This system adheres to leading forensic integrity standards:

- ✅ **ISO 27037** - Guidelines for identification, collection, acquisition and preservation of digital evidence
- ✅ **NIST SP 800-86** - Guide to Integrating Forensic Techniques into Incident Response
- ✅ **ACPO Guidelines** - Good Practice Guide for Digital Evidence
- ✅ **Chain of Custody** - Complete audit trails and cryptographic verification

---

## 🔐 Security & Privacy

- All analysis performed locally - no data sent to external services
- Cryptographic hashing for file integrity verification
- Complete audit trails for compliance and traceability
- Sensitive metadata can be redacted for privacy

---

## 🎓 Learn More

- [Full Architecture Documentation](ARCHITECTURE.md)
- [Installation & Setup Guide](INSTALLATION.md)
- [Comprehensive Requirements Guide](REQUIREMENTS_EXHAUSTIVE.md)
- [Journal Manuscript](publication/JOURNAL_MANUSCRIPT_DRAFT.md)

---

<div align="center">

**Made with ❤️ for Digital Forensics & Image Authentication**

[⬆ Back to top](#-metadata-extraction--image-analysis-system-for-digital-forensics)

</div>
