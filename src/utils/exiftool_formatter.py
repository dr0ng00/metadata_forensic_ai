"""ExifTool-style metadata formatter.

Provides aligned text formatting for forensic metadata reports,
mimicking the output of the ExifTool utility.
"""
from typing import Any, Dict

class ExifToolStyleFormatter:
    """Formats metadata dictionaries into aligned ExifTool-style text."""

    # Map internal keys to professional ExifTool-style names
    # Ensure all mapping keys are stripped and clean.
    DISPLAY_MAPPING = {
        'width': 'Image Width',
        'height': 'Image Height',
        'format': 'File Type',
        'size': 'Image Size',
        'datetime_original': 'Date/Time Original',
        'camera_make': 'Camera Make',
        'camera_model': 'Camera Model',
        'software': 'Software',
        'size_bytes': 'File Size (Bytes)',
        'mime_type': 'MIME Type',
        'Profile Size': 'ICC Profile Size',
        'JUMD Label': 'JUMD Label',
        'JUMD Type': 'JUMD Type',
        'Validation Results Active Manifest Success Code': 'Validation Results Active Manifest Success Code',
        'Validation Results Active Manifest Success Url': 'Validation Results Active Manifest Success Url',
        'Validation Results Active Manifest Success Explanation': 'Validation Results Active Manifest Success Explanation',
        'Actions Software Agent Name': 'Actions Software Agent Name',
        'Actions Digital Source Type': 'Actions Digital Source Type',
        'Actions Description': 'Actions Description',
        'Actions Action': 'Actions Action',
        'Claim Generator Info Name': 'Claim Generator Info Name',
        'Claim Generator Info Version': 'Claim Generator Info Version',
        'Claim Generator Info Org Contentauth C2 Pa Rs': 'Claim Generator Info Version',
        'Instance ID': 'Instance ID',
        'Active Manifest Url': 'Active Manifest Url',
        'Claim Signature Url': 'Claim Signature Url',
        'Relationship': 'Relationship',
        'Actions Parameters Ingredients Url': 'Actions Parameters Ingredients Url',
        'Created Assertions Url': 'Created Assertions Url',
        'location_name': 'GPS Location',
        'city': 'GPS City',
        'state': 'GPS State/Region',
        'country': 'GPS Country',
        'country_code': 'GPS Country Code',
        'latitude': 'GPS Latitude',
        'longitude': 'GPS Longitude',
        'image_accuracy': 'Image Accuracy / GPS Precision (DOP)',
        'coordinates': 'GPS Coordinates',
        'full_address': 'GPS Full Address',
        'status': 'Modification Status',
        'likely_modified': 'Likely Modified',
        'original_capture_time': 'Original Capture Time',
        'digitized_time': 'Digitized Time',
        'file_modified_time': 'File Modified Time',
        'software_detected': 'Software Detected',
        'xmp_history_entries': 'XMP History Entries',
        'origin_assessment': 'Origin Assessment',
        'origin_status': 'Forensic Classification (REAL vs MANIPULATED)',
        'timestamp_issues': 'Timestamp Issues',
        'forensic_flags': 'Forensic Flags',
        'events': 'Chronology of Events',
        'summary': 'Modification Summary',
        'JpegThumbnail': 'JPEG Thumbnail',
    }

    @staticmethod
    def format(metadata: Dict[str, Any]) -> str:
        """
        Produce an aligned text report from metadata.
        
        Args:
            metadata: Nested or flat metadata dictionary.
            
        Returns:
            Formatted text string.
        """
        # 1. Flatten the metadata for easier display
        flat_metadata = ExifToolStyleFormatter._flatten_metadata(metadata)
        
        # 2. Filter internal keys and those requested for removal
        EXCLUDED_KEYS = [
            'absolute_path', 
            'Exifbyteorder', 
            'Exiftool Version', 
            'Exiftoolversion', 
            'Exifversion',
            'exiftool_version',
            'Exif Version'
        ]
        final_data = {
            str(k).strip(): str(v).strip() 
            for k, v in flat_metadata.items() 
            if str(k).strip() not in EXCLUDED_KEYS
        }
        
        if not final_data:
            return "No metadata available."
            
        # 3. Calculate max key length for alignment
        max_key_len = 0
        for k in final_data.keys():
            # Filter control characters and limit length
            clean_name = "".join(char for char in k if char.isprintable())
            max_key_len = max(max_key_len, len(clean_name))
            
        # Add some padding and enforce range
        max_key_len = min(max(max_key_len + 2, 32), 40) 

        lines = []
        # Sort keys to keep them semi-grouped if they are from internal modules
        for key in sorted(final_data.keys()):
            val_str = final_data[key]
            
            # Remove any non-printable characters from key for safe display
            clean_key = "".join(char for char in str(key) if char.isprintable())
            
            # Format aligned string
            line = f"{clean_key:<{max_key_len}} : {val_str}"
            lines.append(line)

        return "\n".join(lines)

    @staticmethod
    def _flatten_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively flatten a nested dictionary with professional naming and strip group colon."""
        items = {}
        if not isinstance(metadata, dict):
            return {}
            
        for k, v in metadata.items():
            if str(v).strip().upper() == "ABSENT":
                continue
            
            if isinstance(v, dict):
                # Recursively flatten dictionaries
                items.update(ExifToolStyleFormatter._flatten_metadata(v))
            else:
                # Remove tag group prefix like 'File:' or 'EXIF:'
                key = str(k).strip()
                clean_k = key.split(':', 1)[-1].strip() if ':' in key else key
                
                # Remove case-insensitive 'Exif' prefix if present
                if clean_k.lower().startswith('exif'):
                    clean_k = clean_k[4:].lstrip(' _-:')
                
                # Check mapping using both original and clean key
                display_name = ExifToolStyleFormatter.DISPLAY_MAPPING.get(key) or \
                               ExifToolStyleFormatter.DISPLAY_MAPPING.get(clean_k)
                
                if not display_name:
                    # Provide default formatting (e.g. image_width -> Image Width)
                    display_name = clean_k.replace('_', ' ').title()
                
                # Double-check that 'Exif ' didn't slip through via the display mapping or formatting
                if display_name.lower().startswith('exif'):
                    display_name = display_name[4:].lstrip(' _-:')
                
                # Filter out technical versioning and metadata headers as requested
                EXCLUDED_TAGS = ['Exifbyteorder', 'ExiftoolVersion', 'Exiftool Version', 'Exifversion', 'Standards Present', 'StandardsPresent', 'ExifVersion']
                if clean_k in EXCLUDED_TAGS or key in EXCLUDED_TAGS or display_name in EXCLUDED_TAGS:
                    continue

                items[display_name] = ExifToolStyleFormatter._format_value(display_name, v)
        return items

    @staticmethod
    def _format_value(field_name: str, value: Any) -> str:
        """Convert values to readable strings and summarize binary payloads."""
        if isinstance(value, (list, tuple)):
            return ", ".join(ExifToolStyleFormatter._format_value(field_name, item) for item in value)

        if isinstance(value, (bytes, bytearray)):
            return ExifToolStyleFormatter._summarize_binary(field_name, len(value))

        text = str(value).strip()
        if not text:
            return ""

        if ExifToolStyleFormatter._is_binary_field(field_name) or ExifToolStyleFormatter._looks_binary_text(text):
            return ExifToolStyleFormatter._summarize_binary(field_name, len(text))

        return " ".join(text.split())

    @staticmethod
    def _is_binary_field(field_name: str) -> bool:
        name = str(field_name).lower()
        return any(token in name for token in ['thumbnail', 'previewimage', 'preview image'])

    @staticmethod
    def _looks_binary_text(text: str) -> bool:
        if "\x00" in text:
            return True

        if len(text) < 32:
            return False

        non_printable = sum(1 for char in text if not char.isprintable() and char not in "\r\n\t")
        replacement_chars = text.count("\ufffd")
        printable_ratio = sum(1 for char in text if char.isprintable() or char in "\r\n\t") / max(len(text), 1)

        return non_printable > 0 or replacement_chars > 0 or printable_ratio < 0.85

    @staticmethod
    def _summarize_binary(field_name: str, size: int) -> str:
        label = "Embedded thumbnail data omitted" if ExifToolStyleFormatter._is_binary_field(field_name) else "Binary data omitted"
        if size > 0:
            return f"{label} ({size} bytes)"
        return label

__all__ = ['ExifToolStyleFormatter']
