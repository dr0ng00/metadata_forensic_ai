"""Tests for EvidenceRiskScorer."""
import unittest
from src.analysis import EvidenceRiskScorer


class TestEvidenceRiskScorer(unittest.TestCase):
    def test_initialization(self):
        scorer = EvidenceRiskScorer()
        self.assertIsNotNone(scorer)
    
    def test_score(self):
        scorer = EvidenceRiskScorer()
        result = scorer.score({'findings': []})
        self.assertIn('risk_score', result)
        self.assertIn('level', result)

    def test_score_accepts_camera_post_processed_interpretation(self):
        scorer = EvidenceRiskScorer()
        result = scorer.score({
            'correlation': {
                'unified_interpretation': 'camera_post_processed',
                'confidence_modifier': 1.0,
            }
        })
        self.assertEqual(result['unified_interpretation'], 'camera_post_processed')
        self.assertIn('camera_post_processed', result['findings_summary'])


if __name__ == '__main__':
    unittest.main()
