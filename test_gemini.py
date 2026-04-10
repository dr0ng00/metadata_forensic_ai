
import sys
from pathlib import Path

# Add src to sys.path
root_dir = Path(r"c:\metadata_extraction_and_image_analysis_system")
sys.path.insert(0, str(root_dir))

from src.core.origin_detector import OriginDetector

def test_gemini_detection():
    detector = OriginDetector()
    
    # Simulate metadata for a Gemini image
    metadata = {
        'summary': {
            'software': 'Google Gemini',
            'camera_make': None,
            'camera_model': None
        },
        'exif': {
            'Software': 'Google Gemini',
            'Image Software': 'Google Gemini'
        },
        'xmp': {},
        'c2pa': {},
        'image_info': {
            'width': 1024,
            'height': 1024,
            'mode': 'RGB'
        },
        'raw_exiftool': {}
    }
    
    result = detector.detect(metadata)
    print(f"--- TEST RESULTS ---")
    print(f"Classification: {result['final_classification']}")
    print(f"Primary Origin: {result['primary_origin']}")
    print(f"Confidence: {result['confidence_score']}")
    
    signals = result.get('forensic_signals_detected', {})
    print(f"--- SIGNALS ---")
    for key, val in signals.items():
        print(f"  {key}: {val}")
    
    print(f"--- REASONING ---")
    print(result['reasoning'])
    
    print(f"--- EVIDENCE ---")
    for ev in result['evidence_used']:
        print(f"  - {ev}")

if __name__ == "__main__":
    test_gemini_detection()
