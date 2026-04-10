"""Tests for chatbox natural-language responses."""
import unittest

from src.interface.natural_language_processor import NaturalLanguageProcessor


def _base_context() -> dict:
    return {
        "metadata": {
            "summary": {
                "dimensions": "1536x1024",
                "format": "PNG",
                "datetime_original": None,
                "camera_make": None,
                "camera_model": None,
                "software": None,
            },
            "exif": {},
            "location": {"coordinates": None},
        },
        "artifact_analysis": {
            "ela_results": {"ela_intensity": "HIGH", "max_difference": 81.0},
            "qtable_audit": {"status": "SKIPPED", "reason": "Not a JPEG file"},
        },
        "contextual_analysis": {
            "issues": [],
            "findings": {"gps_trustworthy": True},
        },
        "timestamp_analysis": {"issues": []},
        "correlation": {"unified_interpretation": "SYNTHETIC_CONTENT"},
        "risk_assessment": {
            "risk_score": 38.5,
            "level": "MEDIUM",
            "unified_interpretation": "SYNTHETIC_CONTENT",
        },
        "origin_detection": {
            "primary_origin": "synthetic_ai_generated",
            "is_synthetic": True,
            "source_inference": "AI Generated",
            "capture_device_inference": "GPT-4o",
            "details": "Strong AI-generation indicators detected from metadata/frequency signals.",
            "screenshot_device_info": {},
        },
        "modification_history": {"likely_modified": False},
        "explanations": [],
    }


class TestNaturalLanguageProcessor(unittest.TestCase):
    def test_synthetic_prompt_in_broken_english_gets_explanation(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()

        response = nlp.respond("this image ai or real ah explain", context)

        self.assertIn("Answer:", response)
        self.assertTrue("synthetic" in response.lower() or "ai" in response.lower())
        self.assertNotIn("unable to answer", response.lower())
        self.assertNotIn("not sure", response.lower())

    def test_screenshot_prompt_returns_device_type_explanation(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()
        context["origin_detection"] = {
            "primary_origin": "screenshot_capture",
            "is_synthetic": False,
            "source_inference": "Screenshot",
            "capture_device_inference": "Desktop / Laptop",
            "details": "Indicators are consistent with an operating-system or application screenshot.",
            "screenshot_device_info": {
                "device_type": "Desktop / Laptop (Windowed Application Capture)",
                "capture_mode": "Windowed Application Capture",
                "final_verdict": "Digital screenshot indicators detected.",
            },
        }
        context["correlation"]["unified_interpretation"] = "SYNTHETIC_CONTENT"

        response = nlp.respond("which type screenshot this one", context)

        self.assertIn("screenshot", response.lower())
        self.assertIn("desktop / laptop", response.lower())
        self.assertNotIn("not identified", response.lower())

    def test_camera_post_processed_prompt_explains_non_malicious_possibility(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()
        context["metadata"]["summary"].update(
            {
                "format": "JPEG",
                "datetime_original": "2023:02:09 15:10:37",
                "camera_make": "vivo",
                "camera_model": "V2207",
                "software": "MediaTek Camera Application",
            }
        )
        context["metadata"]["location"] = {
            "full_address": "Vizianagaram Main Road, Muddadapeta, Andhra Pradesh, India"
        }
        context["artifact_analysis"]["qtable_audit"] = {"signature_match": "Software_Modification"}
        context["risk_assessment"] = {
            "risk_score": 21.5,
            "level": "LOW",
            "unified_interpretation": "camera_post_processed",
        }
        context["correlation"]["unified_interpretation"] = "camera_post_processed"
        context["origin_detection"] = {
            "primary_origin": "camera_post_processed",
            "is_synthetic": False,
            "source_inference": "Camera",
            "capture_device_inference": "vivo V2207",
            "details": "Camera metadata is preserved; artifacts/software suggest post-capture processing.",
            "screenshot_device_info": {},
        }
        context["modification_history"] = {"likely_modified": True}

        response = nlp.respond("edited or just resaved? explain clearly", context)

        self.assertTrue("camera image" in response.lower() or "camera" in response.lower())
        self.assertTrue("re-saved" in response.lower() or "processed after capture" in response.lower())
        self.assertIn("not automatically mean malicious", response.lower())

    def test_suggested_questions_cover_current_result_type(self):
        nlp = NaturalLanguageProcessor()
        questions = nlp.get_suggested_questions(_base_context())

        self.assertGreaterEqual(len(questions), 4)
        self.assertTrue(any("AI generated" in q or "AI" in q for q in questions))

    def test_telugu_style_deepfake_prompt_is_understood(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()

        response = nlp.respond("Anna, is this deepfake? cheppu", context)

        self.assertIn("Answer:", response)
        self.assertIn("Question type explanation:", response)
        self.assertTrue("synthetic" in response.lower() or "ai" in response.lower())

    def test_telugu_style_location_prompt_returns_location_value(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()
        context["metadata"]["location"] = {
            "full_address": "Raghu Engineering College, Vizianagaram Main Road, Muddadapeta, Bheemunipatnam, Visakhapatnam, Andhra Pradesh, India",
            "coordinates": "17.994347586783334, 83.41625182644445",
        }

        response = nlp.respond("Check once, which place is this? anna", context)

        self.assertIn("Raghu Engineering College", response)
        self.assertIn("Question type explanation:", response)
        self.assertNotIn("No location", response)

    def test_metadata_details_prompt_returns_summary(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()
        context["metadata"]["summary"].update(
            {
                "format": "JPEG",
                "dimensions": "1280x720",
                "software": "Windows 11",
            }
        )

        response = nlp.respond("Bro, show metadata details? correct?", context)

        self.assertIn("Format: JPEG", response)
        self.assertIn("Dimensions: 1280x720", response)
        self.assertIn("Software: Windows 11", response)

    def test_risk_prompt_from_corpus_returns_risk_level(self):
        nlp = NaturalLanguageProcessor()
        context = _base_context()

        response = nlp.respond("Tell me honestly, what is the risk level? please", context)

        self.assertIn("Risk is MEDIUM", response)
        self.assertIn("Question type explanation:", response)


if __name__ == "__main__":
    unittest.main()
