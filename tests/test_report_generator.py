"""Tests for report formatting of screenshot origins."""
import unittest

from src.reporting.report_generator import ForensicReportGenerator


class TestReportGenerator(unittest.TestCase):
    def test_formats_android_screenshot_origin_from_device_info(self):
        generator = ForensicReportGenerator()
        data = {
            'risk_assessment': {
                'unified_interpretation': 'camera_post_processed',
            },
            'modification_history': {
                'software_detected': [],
            },
            'origin_detection': {
                'primary_origin': 'screenshot_capture',
                'source_inference': 'Android Screenshot',
                'capture_device_inference': 'Android Screenshot',
                'screenshot_device_info': {
                    'device_type': 'Android Screenshot (Portrait Screen Capture)',
                    'os_detected': 'Android',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': True,
                        'confidence': 82.5,
                        'android_version': None,
                        'device_model': None,
                        'screenshot_method': 'Standard Android screenshot capture',
                    },
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'Mobile Device (Portrait)')
        self.assertEqual(display_source, 'Screenshot')
        self.assertEqual(generator._display_interpretation(data), 'SYNTHETIC_CONTENT')
        self.assertEqual(generator._display_detected_software(data), ['Android'])

        rows = generator._screenshot_device_rows(data)
        row_map = {label: value for label, value in rows}
        self.assertEqual(row_map['Android Screenshot Match'], 'Yes')
        self.assertEqual(row_map['Android Screenshot Confidence'], '82.5%')
        self.assertEqual(row_map['Screenshot Method'], 'Standard Android screenshot capture')

    def test_android_screenshot_output_overrides_camera_display(self):
        generator = ForensicReportGenerator()
        data = {
            'origin_detection': {
                'primary_origin': 'camera_post_processed',
                'source_inference': 'Camera',
                'capture_device_inference': 'Camera',
                'screenshot_device_info': {
                    'device_type': 'Android Screenshot (Full Screen Capture)',
                    'os_detected': 'Android',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': True,
                        'confidence': 91.0,
                        'android_version': '14',
                        'device_model': 'SM-S928B',
                        'screenshot_method': 'Standard Android screenshot capture',
                    },
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'Android')
        self.assertEqual(display_source, 'Screenshot')
        self.assertEqual(generator._display_interpretation(data), 'camera_post_processed')

    def test_portrait_android_screenshot_output_overrides_camera_post_processed_display(self):
        generator = ForensicReportGenerator()
        data = {
            'risk_assessment': {
                'unified_interpretation': 'camera_post_processed',
            },
            'modification_history': {
                'software_detected': [],
            },
            'origin_detection': {
                'primary_origin': 'camera_post_processed',
                'source_inference': 'Camera',
                'capture_device_inference': 'Camera',
                'screenshot_device_info': {
                    'device_type': 'Android Screenshot (Portrait Screen Capture)',
                    'capture_mode': 'Portrait Screen Capture',
                    'os_detected': 'Android',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': True,
                        'confidence': 91.0,
                        'android_version': '14',
                        'device_model': 'SM-S928B',
                        'screenshot_method': 'Standard Android screenshot capture',
                    },
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'Mobile Device (Portrait)')
        self.assertEqual(display_source, 'Screenshot')
        self.assertEqual(generator._display_interpretation(data), 'SYNTHETIC_CONTENT')
        self.assertEqual(generator._display_detected_software(data), ['Android'])

    def test_windows_camera_output_maps_primary_origin_to_desktop_laptop(self):
        generator = ForensicReportGenerator()
        data = {
            'origin_detection': {
                'primary_origin': 'camera_post_processed',
                'source_inference': 'Camera',
                'capture_device_inference': 'Camera',
                'features': {
                    'software': 'windows camera windows 11',
                },
                'screenshot_device_info': {
                    'device_type': 'Windows Camera App (Webcam)',
                    'os_detected': 'Windows (10/11)',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': False,
                    },
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'Desktop / Laptop')
        self.assertEqual(display_source, 'Camera')

    def test_windows_camera_software_maps_primary_origin_to_desktop_laptop_without_os_detected(self):
        generator = ForensicReportGenerator()
        data = {
            'origin_detection': {
                'primary_origin': 'camera_post_processed',
                'source_inference': 'Camera',
                'capture_device_inference': 'Camera',
                'features': {
                    'software': 'windows camera windows 11',
                },
                'screenshot_device_info': {
                    'device_type': '',
                    'os_detected': '',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': False,
                    },
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'Desktop / Laptop')
        self.assertEqual(display_source, 'Camera')

    def test_ai_generated_output_uses_actions_software_agent_name_for_primary_origin(self):
        generator = ForensicReportGenerator()
        data = {
            'metadata': {
                'c2pa': {
                    'Actions Software Agent Name': 'GPT-4o',
                },
            },
            'origin_detection': {
                'primary_origin': 'synthetic_ai_generated',
                'source_inference': 'Unknown',
                'capture_device_inference': 'Unknown',
                'features': {
                    'software': 'android generative ai mobile app',
                },
                'screenshot_device_info': {
                    'device_type': '',
                    'os_detected': 'Android',
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'GPT-4o')
        self.assertEqual(display_source, 'AI Generated')

    def test_ai_generated_output_falls_back_to_ai_generated_without_actions_agent_name(self):
        generator = ForensicReportGenerator()
        data = {
            'origin_detection': {
                'primary_origin': 'synthetic_ai_generated',
                'source_inference': 'Unknown',
                'capture_device_inference': 'Unknown',
                'features': {
                    'software': 'windows 11 desktop generative ai app',
                },
                'screenshot_device_info': {
                    'device_type': '',
                    'os_detected': 'Windows (10/11)',
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'AI Generated')
        self.assertEqual(display_source, 'AI Generated')

    def test_named_camera_device_maps_unknown_source_to_camera_in_report_output(self):
        generator = ForensicReportGenerator()
        data = {
            'origin_detection': {
                'primary_origin': 'origin_unverified',
                'source_inference': 'Unknown',
                'capture_device_inference': 'Samsung Galaxy S23',
                'features': {
                    'capture_device_inference': 'Samsung Galaxy S23',
                },
                'screenshot_device_info': {
                    'device_type': '',
                    'os_detected': '',
                    'android_screenshot_analysis': {
                        'is_android_screenshot': False,
                    },
                },
            }
        }

        display_origin, display_source = generator._format_origin_strings(data)

        self.assertEqual(display_origin, 'Samsung Galaxy S23')
        self.assertEqual(display_source, 'Camera')


if __name__ == '__main__':
    unittest.main()
