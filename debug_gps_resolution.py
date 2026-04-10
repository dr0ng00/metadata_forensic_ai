
import sys
import os
from pathlib import Path

# Add project root to sys.path
root_path = Path.cwd()
sys.path.insert(0, str(root_path))

# Use full imports from src
from src.core.metadata_extractor import EnhancedMetadataExtractor
import json

from src.utils.exiftool_wrapper import ExifToolWrapper
wrapper = ExifToolWrapper()
img_path = r"C:\Users\modha\Pictures\IMG_20220619_145259.jpg"

import subprocess
import json
result = subprocess.run(
    [wrapper.exiftool_path, '-G', '-a', '-s', '-j', '-n', img_path],
    capture_output=True, text=True
)
raw = json.loads(result.stdout)[0]
print("Keys containing 'GPS':")
print([k for k in raw.keys() if 'GPS' in k])

# Also check if organized keys map correctly
print("\nGroup mapping for 'GPS':", wrapper._organize_metadata(raw).get('gps'))

organized = wrapper._organize_metadata(raw)
print("\nOrganized 'gps' group keys:")
if isinstance(organized.get('gps'), dict):
    print(list(organized.get('gps', {}).keys()))
else:
    print(organized.get('gps'))

# Also test resolution
from src.utils.gps_resolver import GPSLocationResolver
resolver = GPSLocationResolver()
location = resolver.resolve_location(organized.get('gps'))
print("\nResolved location name:", location.get('location_name') if location else None)
