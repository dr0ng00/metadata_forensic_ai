import sys
from pathlib import Path
import json
import os

# Set CWD to project root
os.chdir(r"c:\metadata_extraction_and_image_analysis_system")
sys.path.insert(0, str(Path.cwd() / "src"))

from core.metadata_extractor import EnhancedMetadataExtractor
from core.origin_detector import OriginDetector

def test_screenshot_detection(image_path):
    print(f"--- Analyzing Image: {Path(image_path).name} ---")
    
    extractor = EnhancedMetadataExtractor()
    metadata = extractor.extract(image_path)
    
    detector = OriginDetector()
    results = detector.detect(metadata, image_path=image_path)
    
    print(f"Primary Origin: {results['primary_origin']}")
    print(f"Final Classification: {results['final_classification']}")
    print(f"Confidence: {results['confidence_score']}")
    print(f"Source Inference: {results.get('source_inference')}")
    print(f"Reasoning: {results['reasoning']}")
    print("\nEvidence Used:")
    for ev in results['evidence_used']:
        print(f"- {ev}")
        
    print("\nFull Result Segment (JSON):")
    print(json.dumps({
        'screenshot_strength': results['features']['signal_vector']['screenshot_strength'],
        'source_inference': results['source_inference']
    }, indent=2))

if __name__ == "__main__":
    test_path = r"C:\Users\modha\.gemini\antigravity\brain\8a3b29dc-2921-4440-b97b-d2c687faaabb\.tempmediaStorage\media_8a3b29dc-2921-4440-b97b-d2c687faaabb_1773930627566.png"
    if Path(test_path).exists():
        test_screenshot_detection(test_path)
    else:
        print(f"Error: Test image not found at {test_path}")
