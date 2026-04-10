"""Tests for unified interpretation correlation."""
import unittest

from src.analysis.evidence_correlator import EvidenceCorrelator


class TestEvidenceCorrelator(unittest.TestCase):
    def test_android_screenshot_is_not_promoted_to_camera_post_processed(self):
        correlator = EvidenceCorrelator()
        ml_results = {
            'primary_origin': 'screenshot_capture',
            'features': {
                'source_inference': 'Android Screenshot',
            },
            'screenshot_device_info': {
                'android_screenshot_analysis': {
                    'is_android_screenshot': True,
                }
            },
        }

        result = correlator.correlate(ml_results=ml_results, rule_results={'flags': []}, stat_results={'issues': []})

        self.assertEqual(result['unified_interpretation'], 'SYNTHETIC_CONTENT')


if __name__ == '__main__':
    unittest.main()
