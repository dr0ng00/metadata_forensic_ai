"""Tests for OriginDetector."""
import unittest
from src.core import OriginDetector


class TestOriginDetector(unittest.TestCase):
    def test_initialization(self):
        detector = OriginDetector()
        self.assertIsNotNone(detector)

    def test_detect(self):
        detector = OriginDetector()
        result = detector.detect({'test': 'metadata'})
        self.assertIn('primary_origin', result)
        self.assertIn('confidence', result)

    def test_detects_windows_screenshot_from_filename_pattern(self):
        detector = OriginDetector()
        metadata = {
            'summary': {},
            'exif': {},
            'image_info': {
                'width': 1920,
                'height': 1080,
                'absolute_path': r'C:\Users\tester\Pictures\Screenshot 2026-03-19 125501.png',
            },
        }

        result = detector.detect(metadata)

        self.assertEqual(result['primary_origin'], 'screenshot_capture')
        self.assertEqual(result['source_inference'], 'Windows Screenshot')
        self.assertEqual(result['features']['source_inference'], 'Windows Screenshot')
        self.assertEqual(result['screenshot_device_info']['os_detected'], 'Windows (10/11)')

    def test_detects_macos_screenshot_from_filename_pattern(self):
        detector = OriginDetector()
        metadata = {
            'summary': {},
            'exif': {},
            'image_info': {
                'width': 1512,
                'height': 982,
                'absolute_path': '/Users/tester/Desktop/Screen Shot 2026-03-19 at 12.55.01 PM.png',
            },
        }

        result = detector.detect(metadata)

        self.assertEqual(result['primary_origin'], 'screenshot_capture')
        self.assertEqual(result['source_inference'], 'macOS Screenshot')
        self.assertEqual(result['features']['source_inference'], 'macOS Screenshot')
        self.assertEqual(result['screenshot_device_info']['os_detected'], 'macOS')

    def test_detects_android_screenshot_from_mobile_filename_pattern(self):
        detector = OriginDetector()
        metadata = {
            'summary': {},
            'exif': {},
            'image_info': {
                'width': 1080,
                'height': 2400,
                'absolute_path': r'C:\Users\tester\Pictures\Screenshot_2026-03-24-10-15-30-123_com.example.app.png',
            },
        }

        result = detector.detect(metadata)

        self.assertEqual(result['primary_origin'], 'screenshot_capture')
        self.assertEqual(result['source_inference'], 'Android Screenshot')
        self.assertEqual(result['features']['source_inference'], 'Android Screenshot')
        self.assertEqual(result['screenshot_device_info']['os_detected'], 'Android')
        self.assertEqual(result['screenshot_device_info']['device_type'], 'Android Screenshot (Full Screen Capture)')
        android_analysis = result['screenshot_device_info']['android_screenshot_analysis']
        self.assertTrue(android_analysis['is_android_screenshot'])
        self.assertGreaterEqual(android_analysis['confidence'], 65.0)
        self.assertEqual(android_analysis['screenshot_method'], 'Standard Android screenshot capture')

    def test_detects_landscape_android_screenshot_from_mobile_filename_pattern(self):
        detector = OriginDetector()
        metadata = {
            'summary': {},
            'exif': {},
            'image_info': {
                'width': 2400,
                'height': 1080,
                'absolute_path': r'C:\Users\tester\Pictures\Screenshots\Screenshot_2026-03-24-10-15-30-123_com.example.app.png',
            },
        }

        result = detector.detect(metadata)

        self.assertEqual(result['primary_origin'], 'screenshot_capture')
        self.assertEqual(result['source_inference'], 'Android Screenshot')
        self.assertEqual(result['screenshot_device_info']['os_detected'], 'Android')
        self.assertEqual(result['screenshot_device_info']['device_type'], 'Android Screenshot (Full Screen Capture)')
        android_analysis = result['screenshot_device_info']['android_screenshot_analysis']
        self.assertTrue(android_analysis['is_android_screenshot'])
        self.assertGreaterEqual(android_analysis['confidence'], 65.0)

    def test_android_screenshot_is_not_reduced_to_camera_when_model_metadata_exists(self):
        detector = OriginDetector()
        metadata = {
            'summary': {
                'camera_model': 'SM-S928B',
            },
            'exif': {
                'Model': 'SM-S928B',
                'Software': 'com.android.systemui',
            },
            'raw_exiftool': {
                'Model': 'SM-S928B',
                'AndroidVersion': '14',
            },
            'image_info': {
                'width': 1080,
                'height': 2400,
                'absolute_path': r'C:\Phone\Pictures\Screenshots\Screenshot_20260324-101530.png',
            },
        }

        result = detector.detect(metadata)

        self.assertEqual(result['primary_origin'], 'screenshot_capture')
        self.assertEqual(result['source_inference'], 'Android Screenshot')
        self.assertNotEqual(result['source_inference'], 'Camera')

    def test_android_inference_does_not_map_edited_image_to_camera_post_processed(self):
        detector = OriginDetector()
        features = {
            'source_inference': 'Android Screenshot',
            'signal_vector': {
                'camera_exif_strength': 0.0,
                'camera_pipeline_strength': 0.1,
            },
        }

        legacy_label = detector._to_legacy_label(detector.CLASS_EDITED, features)

        self.assertEqual(legacy_label, 'software_reencoded')

    def test_windows_camera_software_suppresses_android_screenshot_inference(self):
        detector = OriginDetector()
        metadata = {
            'summary': {
                'software': 'Windows Camera Windows 11',
            },
            'exif': {
                'Software': 'Windows Camera Windows 11',
            },
            'image_info': {
                'width': 1080,
                'height': 2400,
                'absolute_path': r'C:\Users\tester\Pictures\IMG_0001.jpg',
            },
        }

        result = detector.detect(metadata)

        android_analysis = result['screenshot_device_info']['android_screenshot_analysis']
        self.assertFalse(android_analysis['is_android_screenshot'])
        self.assertEqual(result['capture_device_inference'], 'Windows Camera App (Webcam)')

    def test_normalizes_unknown_source_inference_for_camera_origin(self):
        detector = OriginDetector()

        detector._extract_features = lambda metadata, image_path=None: {  # type: ignore[method-assign]
            'source_inference': 'Unknown',
            'platform_hint': None,
            'screenshot_device_info': {},
        }
        detector._classify = lambda features: {  # type: ignore[method-assign]
            'legacy_label': 'camera_original',
            'confidence_score': 0.91,
            'reasoning': 'Camera-origin indicators detected.',
            'final_classification': detector.CLASS_CAMERA,
            'evidence_used': ['Camera Make/Model present.'],
            'forensic_signals_detected': {},
        }

        result = detector.detect({'summary': {}, 'exif': {}})

        self.assertEqual(result['primary_origin'], 'camera_original')
        self.assertEqual(result['source_inference'], 'Camera')
        self.assertEqual(result['features']['source_inference'], 'Camera')
        self.assertEqual(result['capture_device_inference'], 'Unknown')
        self.assertEqual(result['features']['capture_device_inference'], 'Unknown')

    def test_normalizes_named_camera_source_inference_for_camera_origin(self):
        detector = OriginDetector()

        detector._extract_features = lambda metadata, image_path=None: {  # type: ignore[method-assign]
            'source_inference': 'Apple iPhone 15',
            'platform_hint': None,
            'screenshot_device_info': {},
        }
        detector._classify = lambda features: {  # type: ignore[method-assign]
            'legacy_label': 'camera_original',
            'confidence_score': 0.94,
            'reasoning': 'Camera-origin indicators detected.',
            'final_classification': detector.CLASS_CAMERA,
            'evidence_used': ['Camera Make/Model present.'],
            'forensic_signals_detected': {},
        }

        result = detector.detect({'summary': {}, 'exif': {}})

        self.assertEqual(result['source_inference'], 'Camera')
        self.assertEqual(result['features']['source_inference'], 'Camera')
        self.assertEqual(result['capture_device_inference'], 'Apple iPhone 15')
        self.assertEqual(result['features']['capture_device_inference'], 'Apple iPhone 15')

    def test_ai_generated_output_removes_screenshot_specific_origin_fields(self):
        detector = OriginDetector()

        detector._extract_features = lambda metadata, image_path=None: {  # type: ignore[method-assign]
            'source_inference': 'Desktop / Laptop Screenshot',
            'platform_hint': None,
            'c2pa': {'Actions Software Agent Name': 'GPT-4o'},
            'screenshot_device_info': {
                'device_type': 'Desktop / Laptop Screenshot',
                'os_detected': 'Desktop OS (Unresolved)',
            },
        }
        detector._classify = lambda features: {  # type: ignore[method-assign]
            'legacy_label': 'synthetic_ai_generated',
            'confidence_score': 0.97,
            'reasoning': 'Strong AI-generation indicators detected.',
            'final_classification': detector.CLASS_AI,
            'evidence_used': ['AI metadata signature matched known generative tool/provenance marker.'],
            'forensic_signals_detected': {},
        }

        result = detector.detect({'summary': {}, 'exif': {}})

        self.assertEqual(result['primary_origin'], 'synthetic_ai_generated')
        self.assertEqual(result['source_inference'], 'GPT-4o')
        self.assertEqual(result['capture_device_inference'], 'GPT-4o')
        self.assertEqual(result['features']['source_inference'], 'GPT-4o')
        self.assertEqual(result['features']['capture_device_inference'], 'GPT-4o')
        self.assertEqual(result['screenshot_device_info'], {})
        self.assertEqual(result['features']['screenshot_device_info'], {})


if __name__ == '__main__':
    unittest.main()
