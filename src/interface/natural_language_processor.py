"""Natural language processing utilities for the forensic chatbox.

This module turns vague, direct, broken-English, and Indian/Telugu-style
prompts into forensic Q&A responses backed by the existing analysis pipeline.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List


class NaturalLanguageProcessor:
    """Route chatbox prompts to resilient forensic answers."""

    def __init__(self, model: Any | None = None):
        self.model = model
        self.current_mode = "explain_forensic"
        self.jargon_map = {
            "XMP": "Extended Metadata",
            "IPTC": "Media Metadata",
            "bitstream": "digital file data",
            "heuristics": "analysis rules",
            "quantization": "compression",
            "MakerNotes": "Manufacturer Data",
        }
        self.intent_hints = {
            "summary": ["summary", "overall", "tell me about this", "what is this", "explain this"],
            "authenticity": ["real", "fake", "authentic", "edited", "manipulated", "tampered", "original or fake"],
            "origin": ["origin", "source", "from where", "what type", "camera or screenshot", "ai or camera"],
            "risk": ["risk", "score", "danger", "suspicious", "severity", "trust", "safe to use"],
            "device": ["device", "camera", "phone", "model", "make", "which mobile", "what device"],
            "location": ["location", "gps", "where", "coordinates", "map", "place"],
            "time": ["date", "time", "when", "timeline", "timestamp", "captured when", "modified"],
            "software": ["software", "edited by", "photoshop", "windows", "android", "editor"],
            "dimensions": ["resolution", "dimension", "size", "width", "height"],
            "format": ["format", "type", "png", "jpeg", "jpg", "file type"],
            "screenshot": ["screenshot", "screen shot", "screen capture", "desktop screenshot", "mobile screenshot"],
            "synthetic": ["ai", "synthetic", "gpt", "deepfake", "generated", "machine generated"],
            "metadata": ["metadata", "exif", "metadata issue", "metadata missing"],
        }
        self.prompt_corpus = self._load_prompt_corpus()
        self.canonical_prompts = self.prompt_corpus.get("canonical_prompts", [])
        self.category_explanations = {
            "trustworthiness": "These questions ask whether the evidence should be trusted overall. The chatbox answers from risk, origin, timestamp, and metadata consistency together.",
            "edit_detection": "These questions ask whether the image was edited, tampered, photoshopped, or changed after capture. The answer uses compression, metadata, and correlation signals.",
            "metadata_details": "These questions ask for raw or summarized metadata. The chatbox surfaces the strongest factual fields such as format, dimensions, device, software, and timestamps.",
            "location_value": "These questions ask where the image was taken. The chatbox checks GPS or resolved location fields and explains whether the location is direct metadata or unavailable.",
            "coordinates_value": "These questions ask for numeric coordinates. The chatbox returns GPS coordinates when present and explains if no coordinate data exists.",
            "gps_presence": "These questions ask whether GPS exists at all. The chatbox checks for location tags and clarifies if the file preserves none.",
            "synthetic_detection": "These questions ask whether the image is AI-generated, machine-generated, synthetic, or a deepfake. The answer uses origin classification and synthetic evidence signals.",
            "time_value": "These questions ask when the image was taken or modified. The chatbox reports capture time when available and explains missing timestamps.",
            "metadata_integrity": "These questions ask whether metadata is missing, damaged, present, or trustworthy. The answer uses EXIF presence and metadata integrity checks.",
            "timestamp_integrity": "These questions ask whether the timestamp is correct or changed. The answer uses timestamp audit and contextual consistency.",
            "risk_level": "These questions ask how risky or suspicious the file is. The answer uses the combined risk score and level.",
            "device_type": "These questions ask whether the image comes from mobile, DSLR, desktop screenshot, or another source type.",
            "device_value": "These questions ask for the specific phone, camera, or device that captured the image.",
            "real_fake": "These questions ask in plain language whether the image is real or fake. The answer uses origin, manipulation, and risk outputs together."
        }

    def set_mode(self, mode: str) -> bool:
        valid_modes = ["explain_basic", "explain_forensic", "explain_security", "explain_legal"]
        if mode in valid_modes:
            self.current_mode = mode
            return True
        return False

    def _filter_jargon(self, text: str) -> str:
        if self.current_mode != "explain_legal":
            return text
        filtered = text
        for tech, plain in self.jargon_map.items():
            filtered = filtered.replace(tech, plain)
        return filtered

    def _load_prompt_corpus(self) -> Dict[str, Any]:
        corpus_path = Path(__file__).resolve().parents[2] / "config" / "chatbox_prompt_corpus.json"
        if not corpus_path.exists():
            return {"canonical_prompts": [], "noise_prefixes": [], "noise_suffixes": [], "noise_tokens": []}
        try:
            return json.loads(corpus_path.read_text(encoding="utf-8"))
        except Exception:
            return {"canonical_prompts": [], "noise_prefixes": [], "noise_suffixes": [], "noise_tokens": []}

    def _normalize_prompt(self, text: str) -> str:
        normalized = (text or "").strip().lower()
        normalized = normalized.replace("can’t", "can't")
        for prefix in self.prompt_corpus.get("noise_prefixes", []):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):].strip()
        for suffix in self.prompt_corpus.get("noise_suffixes", []):
            if normalized.endswith(suffix):
                normalized = normalized[:-len(suffix)].strip()
        normalized = re.sub(r"[^\w\s]", " ", normalized)
        tokens = [
            token
            for token in normalized.split()
            if token not in set(self.prompt_corpus.get("noise_tokens", []))
        ]
        return re.sub(r"\s+", " ", " ".join(tokens)).strip()

    def _match_canonical_prompt(self, normalized_text: str) -> Dict[str, Any] | None:
        if not normalized_text:
            return None
        best_match = None
        best_score = 0.0
        text_tokens = set(normalized_text.split())
        for item in self.canonical_prompts:
            prompt = item.get("prompt", "")
            prompt_tokens = set(prompt.split())
            if not prompt_tokens:
                continue
            overlap = len(text_tokens & prompt_tokens)
            union = len(text_tokens | prompt_tokens) or 1
            score = overlap / union
            if normalized_text == prompt:
                return {**item, "match_score": 1.0}
            if prompt in normalized_text or normalized_text in prompt:
                score = max(score, 0.82)
            if score > best_score:
                best_score = score
                best_match = item
        if best_match and best_score >= 0.45:
            return {**best_match, "match_score": round(best_score, 2)}
        return None

    def parse(self, text: str) -> Dict[str, Any]:
        raw_text = (text or "").strip()
        lowered = raw_text.lower()
        normalized = self._normalize_prompt(raw_text)
        hints = [name for name, keywords in self.intent_hints.items() if any(k in lowered or k in normalized for k in keywords)]
        canonical_match = self._match_canonical_prompt(normalized)
        return {
            "intent": "chatbox_query",
            "entities": {},
            "text": lowered,
            "raw_text": raw_text,
            "normalized_text": normalized,
            "hints": hints,
            "canonical_match": canonical_match,
        }

    def get_suggested_questions(self, context: Dict[str, Any] | None = None) -> List[str]:
        facts = self._extract_facts(context or {})
        questions = [
            "Is this image real, edited, screenshot, or AI generated?",
            "Can I trust this image?",
            "Show metadata details.",
        ]

        if facts["has_location"]:
            questions.append("Where was this image taken? Explain using GPS.")
            questions.append("What are the coordinates?")
        else:
            questions.append("Does this file have any GPS or location information?")

        if facts["has_device"]:
            questions.append("Which device or camera captured this image?")
        else:
            questions.append("Why can't the system identify a camera device here?")

        if facts["is_screenshot"]:
            questions.append("Is this desktop screenshot or mobile screenshot? Why?")
        elif facts["is_synthetic"]:
            questions.append("Why does the system think this is AI generated?")
        else:
            questions.append("Was this photo processed after capture? Explain.")

        return questions[:6]

    def respond(self, parsed: Dict[str, Any] | str, context: Dict[str, Any] | None = None) -> str:
        if not context:
            return "No analysis context is available for this question."

        if isinstance(parsed, str):
            parsed = self.parse(parsed)

        question = parsed.get("raw_text") or parsed.get("text") or "Explain this result."
        canonical_match = parsed.get("canonical_match")
        direct_answer = self._answer_direct_question(question, parsed, context)
        if direct_answer:
            return direct_answer

        qa = self._answer_with_router(question, context, canonical_match)
        if qa:
            return self._format_qa_response(question, qa, context, canonical_match)

        return self._format_fallback_answer(question, context, canonical_match)

    def _answer_with_router(
        self,
        question: str,
        context: Dict[str, Any],
        canonical_match: Dict[str, Any] | None = None,
    ) -> Dict[str, Any] | None:
        try:
            from src.main import answer_forensic_question

            forced_intent = canonical_match.get("forced_intent") if canonical_match else None
            qa = answer_forensic_question(question, [context], forced_intent=forced_intent)
            if isinstance(qa, dict) and qa.get("answer") is not None:
                return qa
        except Exception:
            return None
        return None

    def _answer_direct_question(
        self,
        question: str,
        parsed: Dict[str, Any],
        context: Dict[str, Any],
    ) -> str | None:
        facts = self._extract_facts(context)
        match = parsed.get("canonical_match") or {}
        category = match.get("category")
        normalized = parsed.get("normalized_text", "")

        if category == "metadata_details" or "metadata" in normalized and "show" in normalized:
            metadata_lines = [
                f"**Answer:** Format: {facts['format'] or 'Unknown'}, Dimensions: {facts['dimensions'] or 'Unknown'}, Device: {self._device_label(facts)}, Software: {facts['software'] or 'Not detected'}, Capture time: {facts['datetime_original'] or 'Not available'}",
                "**Confidence:** High (90%)",
                "",
                "**Explanation:** This is a direct metadata summary prepared from the extracted forensic output.",
            ]
            return "\n".join(metadata_lines)

        if category == "location_value":
            answer = facts["gps_address"] or "No location could be resolved from the current output."
            return self._simple_direct_response(answer, category, facts)

        if category == "coordinates_value":
            answer = facts["gps_coordinates"] or "No GPS coordinates are present in the current output."
            return self._simple_direct_response(answer, category, facts)

        if category == "gps_presence":
            answer = "Yes. GPS/location data is available." if facts["has_location"] else "No. GPS/location data is not available."
            return self._simple_direct_response(answer, category, facts)

        if category == "device_value":
            answer = self._device_label(facts)
            return self._simple_direct_response(answer, category, facts)

        if category == "time_value":
            parts = []
            if facts["datetime_original"]:
                parts.append(f"capture time: {facts['datetime_original']}")
            if facts["file_modified_time"]:
                parts.append(f"file modified time: {facts['file_modified_time']}")
            answer = ", ".join(parts) if parts else "No reliable capture or modification time is available."
            return self._simple_direct_response(answer, category, facts)

        if category == "device_type":
            answer = self._device_type_label(facts)
            return self._simple_direct_response(answer, category, facts)

        return None

    def _simple_direct_response(self, answer: str, category: str, facts: Dict[str, Any]) -> str:
        notes = self._question_specific_notes(category, facts)
        category_note = self.category_explanations.get(category, "The answer is prepared directly from the available forensic fields.")
        lines = [
            f"**Answer:** {answer}",
            "**Confidence:** High (88%)",
            "",
            "**Explanation:** This answer was prepared directly from the extracted forensic fields.",
            "",
            f"**Question type explanation:** {category_note}",
        ]
        if notes:
            lines.append("")
            lines.append("**Smart explanation:**")
            for note in notes[:4]:
                lines.append(f"- {note}")
        return "\n".join(lines)

    def _format_qa_response(
        self,
        question: str,
        qa: Dict[str, Any],
        context: Dict[str, Any],
        canonical_match: Dict[str, Any] | None = None,
    ) -> str:
        facts = self._extract_facts(context)
        answer = self._humanize_answer(qa.get("answer"), facts, qa, context, canonical_match)
        confidence = qa.get("confidence_level", "Moderate")
        confidence_percent = qa.get("confidence_percent", 0)
        reasoning = qa.get("reasoning") or qa.get("reasoning_summary") or "The answer comes from the analyzed forensic outputs."
        evidence = qa.get("evidence") or []

        lines = [
            f"**Answer:** {answer}",
            f"**Confidence:** {confidence} ({confidence_percent}%)",
            "",
            f"**Explanation:** {self._filter_jargon(reasoning)}",
        ]

        category = canonical_match.get("category") if canonical_match else None
        category_note = self.category_explanations.get(category)
        if category_note:
            lines.append("")
            lines.append(f"**Question type explanation:** {self._filter_jargon(category_note)}")

        if evidence:
            lines.append("")
            lines.append("**What the system used:**")
            for item in evidence[:5]:
                lines.append(f"- {self._filter_jargon(str(item))}")

        smart_notes = self._smart_explanation_notes(question, facts, context, category)
        if smart_notes:
            lines.append("")
            lines.append("**Smart explanation:**")
            for note in smart_notes:
                lines.append(f"- {self._filter_jargon(note)}")

        return "\n".join(lines)

    def _format_fallback_answer(
        self,
        question: str,
        context: Dict[str, Any],
        canonical_match: Dict[str, Any] | None = None,
    ) -> str:
        facts = self._extract_facts(context)
        summary = self._build_plain_summary(facts, context)
        category = canonical_match.get("category") if canonical_match else None
        notes = self._smart_explanation_notes(question, facts, context, category)
        lines = [
            f"**Answer:** {summary}",
            "**Confidence:** Moderate",
            "",
            "**Explanation:** I matched your prompt to the closest forensic result available and answered from the extracted output.",
        ]
        if category and category in self.category_explanations:
            lines.append("")
            lines.append(f"**Question type explanation:** {self.category_explanations[category]}")
        if notes:
            lines.append("")
            lines.append("**Smart explanation:**")
            for note in notes:
                lines.append(f"- {note}")
        return "\n".join(lines)

    def _extract_facts(self, context: Dict[str, Any]) -> Dict[str, Any]:
        metadata = context.get("metadata", {}) if isinstance(context.get("metadata", {}), dict) else {}
        summary = metadata.get("summary", {}) if isinstance(metadata.get("summary", {}), dict) else {}
        exif = metadata.get("exif", {}) if isinstance(metadata.get("exif", {}), dict) else {}
        origin = context.get("origin_detection", {}) if isinstance(context.get("origin_detection", {}), dict) else {}
        risk = context.get("risk_assessment", {}) if isinstance(context.get("risk_assessment", {}), dict) else {}
        correlation = context.get("correlation", {}) if isinstance(context.get("correlation", {}), dict) else {}
        artifact = context.get("artifact_analysis", {}) if isinstance(context.get("artifact_analysis", {}), dict) else {}
        contextual = context.get("contextual_analysis", {}) if isinstance(context.get("contextual_analysis", {}), dict) else {}
        modification = context.get("modification_history", {}) if isinstance(context.get("modification_history", {}), dict) else {}
        screenshot_info = origin.get("screenshot_device_info", {}) if isinstance(origin.get("screenshot_device_info", {}), dict) else {}
        location = metadata.get("location", {}) if isinstance(metadata.get("location", {}), dict) else {}
        explanations = context.get("explanations", []) if isinstance(context.get("explanations", []), list) else []
        file_info = metadata.get("file_info", {}) if isinstance(metadata.get("file_info", {}), dict) else {}

        primary_origin = str(origin.get("primary_origin", "unknown"))
        source_inference = origin.get("source_inference") or "Unknown"
        unified = risk.get("unified_interpretation") or correlation.get("unified_interpretation") or "Unknown"

        device_make = summary.get("camera_make") or exif.get("Make") or exif.get("Image Make")
        device_model = summary.get("camera_model") or exif.get("Model") or exif.get("Image Model")
        software = summary.get("software") or exif.get("Software") or exif.get("Image Software")
        datetime_original = summary.get("datetime_original") or exif.get("Date/Time Original") or exif.get("DateTimeOriginal")
        dimensions = summary.get("dimensions") or (metadata.get("composite", {}) or {}).get("Image Size")
        file_format = summary.get("format") or (metadata.get("image_info", {}) or {}).get("format")
        gps_address = (
            location.get("full_address")
            or exif.get("GPS Full Address")
            or exif.get("GPS Location")
            or exif.get("GPS Coordinates")
        )
        gps_coordinates = (
            location.get("coordinates")
            or exif.get("GPS Coordinates")
            or (
                f"{exif.get('GPS Latitude')}, {exif.get('GPS Longitude')}"
                if exif.get("GPS Latitude") and exif.get("GPS Longitude")
                else None
            )
        )

        ela = (artifact.get("ela_results", {}) or {}).get("ela_intensity")
        qtable_sig = (artifact.get("qtable_audit", {}) or {}).get("signature_match")
        contextual_issues = contextual.get("issues", []) or []
        likely_modified = modification.get("likely_modified")
        exif_present = bool(exif)

        return {
            "primary_origin": primary_origin,
            "source_inference": source_inference,
            "unified_interpretation": str(unified),
            "risk_level": str(risk.get("level", "Unknown")),
            "risk_score": risk.get("risk_score", 0),
            "device_make": device_make,
            "device_model": device_model,
            "software": software,
            "datetime_original": datetime_original,
            "dimensions": dimensions,
            "format": file_format,
            "gps_address": gps_address,
            "gps_coordinates": gps_coordinates,
            "file_modified_time": modification.get("file_modified_time") or file_info.get("File Modification Date/Time"),
            "capture_device_inference": origin.get("capture_device_inference"),
            "screenshot_device_type": screenshot_info.get("device_type"),
            "screenshot_capture_mode": screenshot_info.get("capture_mode"),
            "screenshot_verdict": screenshot_info.get("final_verdict"),
            "has_location": bool(gps_address or gps_coordinates),
            "has_device": bool(device_make or device_model or origin.get("capture_device_inference")),
            "is_screenshot": primary_origin == "screenshot_capture",
            "is_synthetic": bool(origin.get("is_synthetic")) or primary_origin in {"synthetic_ai_generated", "ai_generated"},
            "is_camera_post_processed": primary_origin == "camera_post_processed",
            "is_camera_original": primary_origin == "camera_original",
            "likely_modified": likely_modified,
            "ela_intensity": ela,
            "qtable_signature": qtable_sig,
            "contextual_issues": contextual_issues,
            "explanations": explanations,
            "exif_present": exif_present,
        }

    def _device_label(self, facts: Dict[str, Any]) -> str:
        if facts["device_make"] or facts["device_model"]:
            return " ".join([str(x) for x in [facts["device_make"], facts["device_model"]] if x])
        if facts.get("capture_device_inference"):
            return str(facts["capture_device_inference"])
        if facts["is_screenshot"] and facts.get("screenshot_device_type"):
            return str(facts["screenshot_device_type"])
        return "Device could not be identified from the current output."

    def _device_type_label(self, facts: Dict[str, Any]) -> str:
        if facts["is_screenshot"]:
            return f"Screenshot source: {facts.get('screenshot_device_type') or 'digital screenshot'}"
        if facts["is_camera_original"] or facts["is_camera_post_processed"]:
            device = self._device_label(facts)
            return f"Camera-origin content. Best device evidence: {device}"
        if facts["is_synthetic"]:
            return "Synthetic/AI content, not direct camera capture."
        return f"Closest source inference: {facts.get('source_inference') or facts.get('unified_interpretation')}"

    def _humanize_answer(
        self,
        router_answer: Any,
        facts: Dict[str, Any],
        qa: Dict[str, Any],
        context: Dict[str, Any],
        canonical_match: Dict[str, Any] | None = None,
    ) -> str:
        raw = str(router_answer or "").upper()
        category = canonical_match.get("category") if canonical_match else None
        if qa.get("normalized_intent") == "metadata_tag_lookup":
            return str(router_answer)

        if category == "risk_level":
            return f"Risk is {facts['risk_level']} ({facts['risk_score']}/100)."
        if category in {"location_value", "coordinates_value", "gps_presence"}:
            return facts["gps_address"] or facts["gps_coordinates"] or "No location data is available."
        if category == "device_value":
            return self._device_label(facts)
        if category == "device_type":
            return self._device_type_label(facts)
        if category == "time_value":
            if facts["datetime_original"]:
                return f"Recorded capture time is {facts['datetime_original']}."
            if facts["file_modified_time"]:
                return f"Recorded file modified time is {facts['file_modified_time']}."
            return "No reliable capture time is available."
        if category == "metadata_integrity":
            return "Metadata is present but must be interpreted for integrity." if facts["exif_present"] else "Metadata is sparse or missing in this file."

        if raw == "YES":
            if facts["is_synthetic"]:
                return "Yes. The result supports AI or synthetic origin."
            if facts["is_screenshot"]:
                return "Yes. The result supports screenshot origin."
            if facts["is_camera_original"]:
                return "Yes. The file shows camera-origin evidence."
            return "Yes. The forensic output supports that conclusion."
        if raw == "NO":
            if facts["is_synthetic"]:
                return "No. This is not being treated as a normal camera photo."
            return "No. The forensic output does not support that conclusion."
        if raw == "LIKELY":
            return "Likely yes. The output leans in that direction."
        if raw == "UNLIKELY":
            return "Likely no. The output leans away from that conclusion."

        if facts["is_synthetic"]:
            return "Most likely this is AI or synthetic content."
        if facts["is_screenshot"]:
            device_type = facts.get("screenshot_device_type") or "digital screen capture"
            return f"Most likely this is a screenshot, specifically {device_type}."
        if facts["is_camera_post_processed"]:
            return "Most likely this is a real camera image that was saved or processed after capture."
        if facts["is_camera_original"]:
            return "Most likely this is direct camera-captured content."
        return self._build_plain_summary(facts, context)

    def _build_plain_summary(self, facts: Dict[str, Any], context: Dict[str, Any]) -> str:
        if facts["is_synthetic"]:
            return "The analysis classifies this as synthetic or AI-generated content."
        if facts["is_screenshot"]:
            device_type = facts.get("screenshot_device_type") or "digital screenshot"
            return f"The analysis classifies this as a screenshot from {device_type}."
        if facts["is_camera_post_processed"]:
            return "The analysis classifies this as a camera image with post-capture processing or re-saving."
        if facts["is_camera_original"]:
            return "The analysis classifies this as camera-origin content."

        unified = facts.get("unified_interpretation", "Unknown")
        return f"The closest available conclusion is {str(unified).replace('_', ' ').title()}."

    def _question_specific_notes(self, category: str, facts: Dict[str, Any]) -> List[str]:
        notes: List[str] = []
        if category in {"location_value", "coordinates_value", "gps_presence"}:
            if facts["has_location"]:
                notes.append(f"Resolved location data: {facts['gps_address'] or facts['gps_coordinates']}.")
            else:
                notes.append("The current output does not preserve usable GPS fields.")
        if category in {"device_value", "device_type"}:
            notes.append(f"Best available device evidence: {self._device_label(facts)}.")
        if category == "metadata_integrity":
            notes.append("Metadata presence does not guarantee metadata integrity. The system still checks whether fields are missing, stripped, or inconsistent.")
        if category == "time_value":
            if facts["datetime_original"]:
                notes.append(f"Capture time from metadata: {facts['datetime_original']}.")
            if facts["file_modified_time"]:
                notes.append(f"Filesystem modified time: {facts['file_modified_time']}.")
        return notes

    def _smart_explanation_notes(
        self,
        question: str,
        facts: Dict[str, Any],
        context: Dict[str, Any],
        category: str | None = None,
    ) -> List[str]:
        notes: List[str] = []
        lowered = (question or "").lower()

        if category:
            notes.extend(self._question_specific_notes(category, facts))

        if facts["is_synthetic"]:
            notes.append("The output points to synthetic origin because camera-style metadata is weak or missing and the origin classifier favors AI generation.")
        if facts["is_screenshot"]:
            device_type = facts.get("screenshot_device_type") or "Unknown device type"
            capture_mode = facts.get("screenshot_capture_mode") or "Unknown capture mode"
            notes.append(f"Screenshot evidence is strong: inferred device type is {device_type} and capture mode is {capture_mode}.")
        if facts["is_camera_post_processed"]:
            notes.append("This does not automatically mean malicious editing. It usually means the file was re-saved, exported, or processed after the original capture.")
        if facts["software"]:
            notes.append(f"Software markers found: {facts['software']}. That helps explain post-capture processing or export.")
        if facts["has_location"]:
            notes.append(f"Location-related data is available: {facts['gps_address'] or facts['gps_coordinates']}.")
        else:
            notes.append("No usable GPS location is available in the current output.")
        if facts["datetime_original"]:
            notes.append(f"Original capture time recorded in metadata: {facts['datetime_original']}.")
        else:
            notes.append("Original capture time is missing, so timeline certainty is lower.")
        if facts["device_make"] or facts["device_model"]:
            device = " ".join([str(x) for x in [facts["device_make"], facts["device_model"]] if x])
            notes.append(f"Device attribution from metadata: {device}.")
        elif facts.get("capture_device_inference"):
            notes.append(f"Device inference from origin analysis: {facts['capture_device_inference']}.")
        else:
            notes.append("The file does not preserve a reliable camera make/model signature.")
        if facts["ela_intensity"] == "HIGH":
            notes.append("High ELA variance was detected. That is a structural warning signal, but by itself it is not final proof of tampering.")
        if facts["qtable_signature"] == "Software_Modification":
            notes.append("The JPEG compression profile matches software re-saving rather than untouched camera output.")
        for issue in facts["contextual_issues"][:2]:
            notes.append(f"Contextual issue detected: {issue}")

        if not any(token in lowered for token in ["why", "explain", "how"]):
            notes = notes[:5]

        deduped: List[str] = []
        for note in notes:
            if note not in deduped:
                deduped.append(note)
        return deduped[:6]


__all__ = ["NaturalLanguageProcessor"]
