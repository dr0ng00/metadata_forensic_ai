"""Tests for origin refinement behavior."""
import unittest

from src.main import MetaForensicAI


class TestMainOriginRefinement(unittest.TestCase):
    def test_android_screenshot_refinement_does_not_become_camera_post_processed(self):
        app = MetaForensicAI()
        origin_results = {
            'primary_origin': 'software_reencoded',
            'source_inference': 'SM-S928B',
            'screenshot_device_info': {
                'android_screenshot_analysis': {
                    'is_android_screenshot': True,
                }
            },
            'features': {
                'camera_signature_strength': 4,
                'source_inference': 'SM-S928B',
            },
        }

        refined = app._refine_origin_with_artifacts(
            origin_results=origin_results,
            metadata={},
            artifact_findings={'qtable_audit': {'signature_match': 'Software_Modification'}},
            auth_results={'flags': ['Software tag present']},
        )

        self.assertEqual(refined['primary_origin'], 'screenshot_capture')
        self.assertEqual(refined['source_inference'], 'Android Screenshot')

    def test_portrait_android_screenshot_gets_android_detected_software_fallback(self):
        app = MetaForensicAI()
        origin_results = {
            'primary_origin': 'screenshot_capture',
            'source_inference': 'Android Screenshot',
            'features': {
                'software_fields': {},
            },
            'screenshot_device_info': {
                'device_type': 'Android Screenshot (Portrait Screen Capture)',
                'capture_mode': 'Portrait Screen Capture',
                'os_detected': 'Android',
                'android_screenshot_analysis': {
                    'is_android_screenshot': True,
                },
            },
        }

        history = app._build_modification_history_summary(
            metadata={'summary': {}, 'exif': {}, 'xmp': {}, 'file_info': {}},
            origin_results=origin_results,
            auth_results={},
            timestamp_results={},
            artifact_findings={},
        )

        self.assertEqual(history['software_detected'], ['Android'])

    def test_named_camera_capture_device_promotes_unknown_source_to_camera(self):
        app = MetaForensicAI()
        origin_results = {
            'primary_origin': 'origin_unverified',
            'source_inference': 'Unknown',
            'capture_device_inference': 'Samsung Galaxy S23',
            'features': {
                'source_inference': 'Unknown',
                'capture_device_inference': 'Samsung Galaxy S23',
                'camera_signature_strength': 2,
            },
            'screenshot_device_info': {
                'android_screenshot_analysis': {
                    'is_android_screenshot': False,
                }
            },
        }

        refined = app._refine_origin_with_artifacts(
            origin_results=origin_results,
            metadata={},
            artifact_findings={'qtable_audit': {}, 'ela_results': {}},
            auth_results={'flags': []},
        )

        self.assertEqual(refined['primary_origin'], 'origin_unverified')
        self.assertEqual(refined['source_inference'], 'Camera')
        self.assertEqual(refined['capture_device_inference'], 'Samsung Galaxy S23')
        self.assertEqual(refined['features']['capture_device_inference'], 'Samsung Galaxy S23')


if __name__ == '__main__':
    unittest.main()
