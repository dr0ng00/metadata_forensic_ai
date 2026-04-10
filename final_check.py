import sys, os
from pathlib import Path
sys.path.insert(0, str(Path.cwd() / "src"))

from core.metadata_extractor import EnhancedMetadataExtractor
from core.origin_detector import OriginDetector

image_path = r"C:\Users\modha\.gemini\antigravity\brain\8a3b29dc-2921-4440-b97b-d2c687faaabb\.tempmediaStorage\media_8a3b29dc-2921-4440-b97b-d2c687faaabb_1773930627566.png"
extractor = EnhancedMetadataExtractor()
meta = extractor.extract(image_path)
detector = OriginDetector()
res = detector.detect(meta, image_path=image_path)
print(f"Primary Origin: {res['primary_origin']}")
print(f"Confidence: {res['confidence_score']}")
print(f"Signals: {res['features']['signal_vector']}")
print(f"Inference: {res['source_inference']}")
