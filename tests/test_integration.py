"""Integration tests for MetaForensicAI."""
import io
import sys
import tempfile
import unittest
from unittest import mock

from src import MetaForensicAI, ForensicEvidenceHandler, MetadataAuthenticityAnalyzer, ForensicReportGenerator
from src import main as main_module


class TestMetaForensicAIIntegration(unittest.TestCase):
    def test_main_import(self):
        system = MetaForensicAI()
        self.assertEqual(system.config['system']['version'], '1.0.0')
        self.assertIsNotNone(system.evidence_handler)
        self.assertIsNotNone(system.metadata_extractor)

    def test_analyze_image_missing_file(self):
        system = MetaForensicAI()
        with self.assertRaisesRegex(ValueError, 'Evidence integrity check failed'):
            system.analyze_image('test.jpg')
    
    def test_core_modules_integration(self):
        handler = ForensicEvidenceHandler()
        analyzer = MetadataAuthenticityAnalyzer()
        self.assertIsNotNone(handler)
        self.assertIsNotNone(analyzer)

    def test_refine_origin_sets_camera_source_for_camera_post_processed(self):
        system = MetaForensicAI()
        refined = system._refine_origin_with_artifacts(
            origin_results={
                'primary_origin': 'software_reencoded',
                'source_inference': 'Unknown',
                'features': {
                    'source_inference': 'Unknown',
                    'camera_signature_strength': 4,
                },
            },
            metadata={},
            artifact_findings={
                'qtable_audit': {'signature_match': 'Software_Modification'},
                'ela_results': {},
            },
            auth_results={'flags': ['Software tag detected']},
        )

        self.assertEqual(refined['primary_origin'], 'camera_post_processed')
        self.assertEqual(refined['source_inference'], 'Camera')
        self.assertEqual(refined['features']['source_inference'], 'Camera')

    def test_report_generation_does_not_mutate_raw_origin_fields(self):
        generator = ForensicReportGenerator()
        analysis_results = {
            'origin_detection': {
                'primary_origin': 'camera_original',
                'source_inference': 'Camera',
                'capture_device_inference': 'Android',
                'features': {'capture_device_inference': 'Android'},
            },
            'risk_assessment': {'risk_score': 0, 'level': 'LOW', 'unified_interpretation': 'AUTHENTIC'},
            'metadata': {},
            'location': {},
            'flags': [],
            'explanations': [],
            'evidence_integrity': {'file_path': 'sample.jpg'},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            generator.generate(analysis_results=analysis_results, formats=['json'], output_dir=tmpdir)

        self.assertEqual(analysis_results['origin_detection']['primary_origin'], 'camera_original')
        self.assertEqual(analysis_results['origin_detection']['source_inference'], 'Camera')

    def test_json_cli_report_uses_forensic_system_for_portrait_detection(self):
        mock_results = {
            'risk_assessment': {
                'risk_score': 21.5,
                'level': 'LOW',
                'unified_interpretation': 'LIKELY_AUTHENTIC',
            },
            'origin_detection': {
                'primary_origin': 'screenshot_capture',
                'confidence': 0.91,
                'details': 'portrait screenshot detected',
                'source_inference': 'Android Screenshot',
                'capture_device_inference': 'Android Screenshot',
                'features': {},
                'screenshot_device_info': {
                    'device_type': 'Android Screenshot (Portrait Screen Capture)',
                    'capture_mode': 'Portrait Screen Capture',
                    'os_detected': 'Android',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': True,
                    },
                },
            },
            'bayesian_risk': {
                'predictive_risk_score': 35.0,
                'risk_level': 'MEDIUM',
            },
            'evidence_integrity': {
                'file_path': 'sample.jpg',
                'file_size_bytes': 123,
                'hashes': {'sha256': 'abc'},
            },
            'modification_history': {},
            'explanations': [],
            'metadata': {},
            'flags': [],
        }

        fake_system = mock.Mock()
        fake_system.analyze_image.return_value = mock_results
        fake_system.generate_reports.return_value = {}
        fake_system._is_portrait_mobile_screenshot.return_value = True

        argv = ['prog', '--image', 'sample.jpg', '--report', 'json-cli']
        stdout = io.StringIO()

        with mock.patch.object(main_module, 'MetaForensicAI', return_value=fake_system), \
             mock.patch.object(sys, 'argv', argv), \
             mock.patch('sys.stdout', stdout):
            main_module.main()

        fake_system._is_portrait_mobile_screenshot.assert_called_once_with(mock_results['origin_detection'])
        output = stdout.getvalue()
        self.assertIn('Forensic Interpretation: SYNTHETIC_CONTENT', output)
        self.assertIn('--- END FORENSIC NARRATIVE REPORT ---', output)


if __name__ == '__main__':
    unittest.main()
