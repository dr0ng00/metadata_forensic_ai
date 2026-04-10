"""Origin detector implementation.

Multi-signal origin classifier:
- EXIF camera fields
- JPEG quantization / re-encoding traces
- file structure markers (APP/XMP/ICC)
- natural sensor-noise proxy + demosaicing hints
- editing software indicators
- stripped metadata likelihood
- AI/synthetic indicators
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import re
import statistics

import numpy as np
from PIL import Image, ImageFilter


class OriginDetector:
    """Detects digital image origin using forensic signal fusion."""

    CLASS_CAMERA = "Camera Captured Image"
    CLASS_EDITED = "Edited / Re-encoded Image"
    CLASS_AI = "AI Generated Image"
    CLASS_SYNTHETIC = "Synthetic Graphic / Illustration"
    CLASS_SCREENSHOT = "Digital Screenshot"
    CLASS_UNKNOWN = "Unknown Origin"

    def __init__(self):
        self.model = None

    def detect(self, metadata: Dict[str, Any], image_path: str | None = None) -> Dict[str, Any]:
        """Run origin detection and emit modern + legacy-compatible outputs."""
        if not metadata:
            return {'error': 'No metadata provided', 'primary_origin': 'unknown'}

        features = self._extract_features(metadata, image_path=image_path)
        capture_device_inference = features.get('source_inference', 'Unknown')
        decision = self._classify(features)
        if decision['legacy_label'] == 'synthetic_ai_generated':
            normalized_source = self._resolve_ai_agent_name(features) or 'AI Generated'
            capture_device_inference = normalized_source
            features['screenshot_device_info'] = {}
        else:
            normalized_source = self._normalize_source_inference(
                source_inference=capture_device_inference,
                legacy_label=decision['legacy_label'],
            )
        features['source_inference'] = normalized_source
        features['capture_device_inference'] = capture_device_inference

        return {
            'primary_origin': decision['legacy_label'],
            'confidence': decision['confidence_score'],
            'features': features,
            'details': decision['reasoning'],
            'is_synthetic': decision['final_classification'] in {self.CLASS_AI, self.CLASS_SYNTHETIC},
            'platform_fingerprint': features.get('platform_hint'),
            'source_inference': normalized_source,
            'capture_device_inference': capture_device_inference,
            'screenshot_device_info': features.get('screenshot_device_info', {}),
            'final_classification': decision['final_classification'],
            'reasoning': decision['reasoning'],
            'evidence_used': decision['evidence_used'],
            'confidence_score': decision['confidence_score'],
            'forensic_signals_detected': decision['forensic_signals_detected'],
        }

    def _extract_features(self, metadata: Dict[str, Any], image_path: str | None = None) -> Dict[str, Any]:
        summary = self._as_dict(metadata.get('summary'))
        exif = self._as_dict(metadata.get('exif'))
        xmp = self._as_dict(metadata.get('xmp'))
        c2pa = self._as_dict(metadata.get('c2pa'))
        icc = self._as_dict(metadata.get('icc_profile'))
        image_info = self._as_dict(metadata.get('image_info'))
        raw_exiftool = self._as_dict(metadata.get('raw_exiftool'))

        software_fields = self._extract_software_fields(metadata)
        software_tokens = " | ".join(str(v).lower() for v in software_fields.values() if v)

        exif_presence = self._camera_exif_presence(summary=summary, exif=exif)
        camera_exif_strength = sum(exif_presence.values()) / 5.0
        metadata_density = len(exif)

        software_signals = self._score_software_signals(software_tokens)
        ai_meta_signals = self._score_ai_metadata_signals(
            software_tokens, xmp=xmp, c2pa=c2pa, exif=exif,
            image_path=image_path,
            png_chunks=self._as_dict(metadata.get('png_chunks')),
        )
        metadata_stripped_likelihood = self._score_metadata_stripped(
            metadata_density=metadata_density,
            camera_exif_strength=camera_exif_strength,
            has_xmp=bool(xmp),
            has_icc=bool(icc),
        )
        structure = self._extract_file_structure_markers(exif=exif, xmp=xmp, icc=icc, raw_exiftool=raw_exiftool)
        visual = self._extract_visual_signals(image_path=image_path)
        qtables = self._extract_qtable_signals(image_path=image_path)
        demosaic_strength = self._score_demosaic_hints(exif=exif, raw_exiftool=raw_exiftool)

        has_gps = bool(exif.get('GPSLatitude') or exif.get('GPS GPSLatitude'))
        has_datetime_original = bool(summary.get('datetime_original') or exif.get('DateTimeOriginal') or exif.get('EXIF DateTimeOriginal'))
        ai_structural_score = self._score_ai_structural_signals(
            metadata_density=metadata_density,
            camera_exif_strength=camera_exif_strength,
            image_info=image_info,
            has_gps=has_gps,
            has_datetime_original=has_datetime_original,
        )

        reencode_strength = self._bounded(
            0.50 * qtables['software_qtable_score'] +
            0.25 * qtables['double_compression_score'] +
            0.15 * software_signals['platform_reencode_score'] +
            0.10 * metadata_stripped_likelihood
        )
        camera_pipeline_strength = self._bounded(
            0.40 * visual['natural_noise_score'] +
            0.30 * demosaic_strength +
            0.30 * structure['camera_structure_score']
        )
        synthetic_graphic_strength = self._bounded(
            0.45 * visual['smooth_gradient_score'] +
            0.35 * visual['uniform_texture_score'] +
            0.20 * (1.0 - camera_pipeline_strength)
        )
        ai_indicator_strength = self._bounded(
            0.50 * ai_meta_signals['ai_metadata_score'] +
            0.30 * ai_structural_score +
            0.20 * visual['ai_frequency_anomaly_score']
        )
        edit_software_strength = self._bounded(
            0.70 * software_signals['editing_software_score'] +
            0.30 * structure['editing_container_score']
        )
        
        screenshot_strength = self._score_screenshot_signals(
            metadata_density=metadata_density,
            camera_exif_strength=camera_exif_strength,
            image_info=image_info,
            visual=visual,
            software_tokens=software_tokens,
            exif=exif,
            raw_exiftool=raw_exiftool,
        )

        make = str(summary.get('camera_make') or exif.get('Make') or exif.get('Image Make') or exif.get('EXIF Make') or '').strip()
        if not make:
            make = str(next((v for k, v in list(exif.items()) + list(xmp.items()) if 'make' in str(k).lower() and 'profile' not in str(k).lower()), '')).strip()

        model = str(summary.get('camera_model') or exif.get('Model') or exif.get('Image Model') or exif.get('EXIF Model') or '').strip()
        if not model:
            model = str(next((v for k, v in list(exif.items()) + list(xmp.items()) if 'model' in str(k).lower() and 'lens' not in str(k).lower() and 'profile' not in str(k).lower()), '')).strip()

        camera_name = f"{make} {model}".strip() if make or model else "Unknown"

        webcam_indicators = {
            'photo booth': 'Apple Photo Booth (macOS Webcam)',
            'windows camera': 'Windows Camera App (Webcam)',
            'logitech': 'Logitech Webcam',
            'obs virtual camera': 'OBS Virtual Camera',
            'manycam': 'ManyCam Virtual Camera',
            'snap camera': 'Snap Camera',
            'facetime': 'Apple FaceTime Camera',
            'epoccam': 'Elgato EpocCam',
            'camtasia': 'Camtasia Capture'
        }
        
        for k, v in webcam_indicators.items():
            if k in software_tokens.lower() and camera_name == "Unknown":
                camera_name = v
                camera_exif_strength = max(camera_exif_strength, 0.40)
                break

        source_inf = screenshot_strength['inference']
        android_screenshot_match = bool(
            screenshot_strength.get('device_info', {})
            .get('android_screenshot_analysis', {})
            .get('is_android_screenshot')
        )
        if not android_screenshot_match and camera_exif_strength >= 0.4 and camera_name and camera_name != "Unknown":
            source_inf = camera_name

        if source_inf == screenshot_strength['inference'] and screenshot_strength['score'] < 0.60 and not android_screenshot_match:
            resolutions = ["Desktop / Laptop (Full Screen)", "Mobile Device", "Desktop / Laptop Screenshot", "Mobile Device (Portrait)", "Desktop / Laptop (Windowed Application Capture)", "Unknown"]
            if source_inf in resolutions:
                source_inf = camera_name if camera_name != "Unknown" else "Camera"

        return {
            'software': software_tokens,
            'software_fields': software_fields,
            'metadata_density': metadata_density,
            'resolution': f"{image_info.get('width')}x{image_info.get('height')}",
            'aspect_ratio': round(image_info.get('width', 0) / image_info.get('height', 1), 2) if image_info.get('height') else 0.0,
            'dpi': exif.get('XResolution') or exif.get('Image XResolution'),
            'has_gps': has_gps,
            'thumbnail_present': 'thumbnail' in " ".join(k.lower() for k in exif.keys()),
            'c2pa': c2pa,
            'platform_hint': software_signals['platform_hint'],
            'has_camera_make': bool(exif_presence['make']),
            'has_camera_model': bool(exif_presence['model']),
            'has_lens_model': bool(exif_presence['lens']),
            'has_datetime_original': has_datetime_original,
            'camera_signature_strength': int(round(camera_exif_strength * 5)),
            'signal_vector': {
                'camera_exif_strength': camera_exif_strength,
                'camera_pipeline_strength': camera_pipeline_strength,
                'edit_software_strength': edit_software_strength,
                'reencode_strength': reencode_strength,
                'metadata_stripped_likelihood': metadata_stripped_likelihood,
                'synthetic_graphic_strength': synthetic_graphic_strength,
                'ai_indicator_strength': ai_indicator_strength,
                'screenshot_strength': screenshot_strength['score'],
                'conflict_level': self._estimate_conflict_level(
                    camera_exif_strength=camera_exif_strength,
                    camera_pipeline_strength=camera_pipeline_strength,
                    edit_software_strength=edit_software_strength,
                    reencode_strength=reencode_strength,
                    synthetic_graphic_strength=synthetic_graphic_strength,
                    ai_indicator_strength=ai_indicator_strength,
                ),
            },
            'source_inference': source_inf,
            'screenshot_device_info': screenshot_strength['device_info'],
            'raw_signals': {
                'exif_presence': exif_presence,
                'file_structure': structure,
                'visual': visual,
                'qtables': qtables,
                'software_signals': software_signals,
                'ai_meta_signals': ai_meta_signals,
                'ai_structural_score': ai_structural_score,
                'demosaic_strength': demosaic_strength,
                'screenshot_signals': screenshot_strength['signals'],
            }
        }

    def _classify(self, features: Dict[str, Any]) -> Dict[str, Any]:
        signals = features.get('signal_vector', {})
        camera_exif_strength = float(signals.get('camera_exif_strength', 0.0))
        camera_pipeline_strength = float(signals.get('camera_pipeline_strength', 0.0))
        edit_software_strength = float(signals.get('edit_software_strength', 0.0))
        reencode_strength = float(signals.get('reencode_strength', 0.0))
        metadata_stripped_likelihood = float(signals.get('metadata_stripped_likelihood', 0.0))
        synthetic_graphic_strength = float(signals.get('synthetic_graphic_strength', 0.0))
        ai_indicator_strength = float(signals.get('ai_indicator_strength', 0.0))
        conflict_level = float(signals.get('conflict_level', 0.0))

        import logging
        logger = logging.getLogger('OriginDetector')
        logger.debug(f"Classifying signals: AI={ai_indicator_strength}, Camera={camera_exif_strength}, Screenshot={signals.get('screenshot_strength', 0.0)}, Edited={edit_software_strength}")

        evidence_used: List[str] = []
        android_screenshot_match = bool(
            features.get('screenshot_device_info', {})
            .get('android_screenshot_analysis', {})
            .get('is_android_screenshot')
        )
        if ai_indicator_strength >= 0.75 or (ai_indicator_strength >= 0.60 and camera_pipeline_strength < 0.35):
            final_class = self.CLASS_AI
            reasoning = "Strong AI-generation indicators detected from metadata/frequency signals."
            evidence_used.extend(self._evidence_for_ai(features))
        elif (
            camera_exif_strength >= 0.40 and
            camera_pipeline_strength >= 0.60 and
            edit_software_strength < 0.45 and
            reencode_strength < 0.45
        ):
            final_class = self.CLASS_CAMERA
            reasoning = "Strong camera metadata fields and camera pipeline consistency with low editing/re-encoding evidence."
            evidence_used.extend(self._evidence_for_camera(features))
        elif android_screenshot_match:
            final_class = self.CLASS_SCREENSHOT
            reasoning = "Indicators are consistent with an Android mobile screenshot rather than optical camera capture."
            evidence_used.extend(self._evidence_for_screenshot(features))
        elif signals.get('screenshot_strength', 0.0) >= 0.60:
            final_class = self.CLASS_SCREENSHOT
            reasoning = "Image signals match a digital screenshot: lack of camera noise, specific desktop/mobile UI resolution, or alpha channel presence."
            evidence_used.extend(self._evidence_for_screenshot(features))
        elif (
            edit_software_strength >= 0.55 or
            reencode_strength >= 0.55 or
            (metadata_stripped_likelihood >= 0.60 and (reencode_strength >= 0.45 or edit_software_strength >= 0.45))
        ):
            final_class = self.CLASS_EDITED
            reasoning = "Editing or re-encoding traces are present; stripped metadata is not treated as camera evidence."
            evidence_used.extend(self._evidence_for_edited(features))
        elif (
            synthetic_graphic_strength >= 0.70 and
            camera_pipeline_strength < 0.35 and
            camera_exif_strength < 0.40 and
            ai_indicator_strength < 0.60
        ):
            final_class = self.CLASS_SYNTHETIC
            reasoning = "Visual/noise profile is non-photographic and lacks camera acquisition structure."
            evidence_used.extend(self._evidence_for_synthetic(features))
        else:
            final_class = self.CLASS_UNKNOWN
            reasoning = "Evidence is insufficient or conflicting for a definitive origin class."
            evidence_used.extend(self._evidence_for_unknown(features))

        confidence_score = self._estimate_confidence(
            final_class=final_class,
            camera_exif_strength=camera_exif_strength,
            camera_pipeline_strength=camera_pipeline_strength,
            edit_software_strength=edit_software_strength,
            reencode_strength=reencode_strength,
            synthetic_graphic_strength=synthetic_graphic_strength,
            ai_indicator_strength=ai_indicator_strength,
            screenshot_strength=float(signals.get('screenshot_strength', 0.0)),
            conflict_level=conflict_level,
        )

        return {
            'final_classification': final_class,
            'legacy_label': self._to_legacy_label(final_class, features),
            'reasoning': reasoning,
            'evidence_used': self._dedupe(evidence_used),
            'confidence_score': confidence_score,
            'forensic_signals_detected': {k: round(float(v), 4) for k, v in signals.items()},
        }
    def _camera_exif_presence(self, summary: Dict[str, Any], exif: Dict[str, Any]) -> Dict[str, int]:
        has_make = bool(summary.get('camera_make') or exif.get('Make') or exif.get('Image Make') or exif.get('EXIF Make'))
        has_model = bool(summary.get('camera_model') or exif.get('Model') or exif.get('Image Model') or exif.get('EXIF Model'))
        has_lens = bool(exif.get('LensModel') or exif.get('EXIF LensModel') or exif.get('Lens Type'))
        has_exposure = bool(exif.get('ExposureTime') or exif.get('EXIF ExposureTime'))
        has_iso = bool(exif.get('ISOSpeedRatings') or exif.get('EXIF ISOSpeedRatings') or exif.get('ISO'))
        return {'make': int(has_make), 'model': int(has_model), 'lens': int(has_lens), 'exposure': int(has_exposure), 'iso': int(has_iso)}

    def _extract_software_fields(self, metadata: Dict[str, Any]) -> Dict[str, str]:
        exif = self._as_dict(metadata.get('exif'))
        summary = self._as_dict(metadata.get('summary'))
        xmp = self._as_dict(metadata.get('xmp'))

        candidates: List[str] = ['Software', 'ProcessingSoftware', 'CreatorTool', 'HistorySoftwareAgent', 'XMPToolkit', 'Generator', 'Producer', 'Comment']
        field_values: Dict[str, str] = {}
        for field in candidates:
            value = None
            for key in [field, f"Image {field}", f"EXIF {field}", f"XMP {field}", f"XMP:{field}"]:
                raw = exif.get(key)
                if raw:
                    value = str(raw).strip()
                    break
            if not value and field == 'Software' and summary.get('software'):
                value = str(summary.get('software')).strip()
            if not value and isinstance(xmp, dict):
                for k, v in xmp.items():
                    if field.lower() in str(k).lower() and v:
                        value = str(v).strip()
                        break
            if value:
                field_values[field] = value
        return field_values

    def _score_software_signals(self, software_tokens: str) -> Dict[str, Any]:
        s = (software_tokens or "").lower()
        editing_tokens = ['photoshop', 'lightroom', 'pixlr', 'inshot', 'picsart', 'snapseed', 'gimp', 'affinity', 'canva']
        platform_tokens = ['whatsapp', 'instagram', 'facebook', 'telegram', 'wechat', 'messenger']

        edit_hits = sum(1 for t in editing_tokens if t in s)
        platform_hits = sum(1 for t in platform_tokens if t in s)
        platform_hint = next((p for p in platform_tokens if p in s), None)

        return {
            'editing_software_score': self._bounded(edit_hits / 2.0),
            'platform_reencode_score': self._bounded(platform_hits / 2.0),
            'platform_hint': platform_hint,
        }

    def _score_ai_metadata_signals(self, software_tokens: str, xmp: Dict[str, Any], c2pa: Dict[str, Any], exif: Dict[str, Any], image_path: str | None = None, png_chunks: Dict[str, Any] | None = None) -> Dict[str, float]:
        # Build a broad text blob from all metadata fields — AI tools embed names in various places
        text_blob = " | ".join(
            [software_tokens]
            + [f"{k}:{v}" for k, v in xmp.items()]
            + [f"{k}:{v}" for k, v in c2pa.items()]
            + [f"{k}:{v}" for k, v in exif.items()]
            + [f"{k}:{v}" for k, v in (png_chunks or {}).items()]
        ).lower()

        # Also scan the filename — many AI tools produce characteristic filenames
        if image_path:
            text_blob += " | " + Path(image_path).name.lower()

        ai_tokens = [
            # DeepSeek (image generator + OCR/VL model markers)
            'deepseek', 'deepseek-vl', 'deepseek-ocr', 'deepseek_ocr',
            'deepseek-r1', 'deepseek-v2', 'deepseek-v3',
            # DeepSeek OCR structural markers
            '<|ref|>', '<|/ref|>', '<|det|>', '<|/det|>',
            'result_ori.mmd', 'result.mmd', '_det.mmd', '_layouts.pdf',
            'result_with_boxes',
            # Google Gemini / Imagen
            'gemini', 'gemini_generated', 'gemini generated', 'imagen', 'google imagen',
            'generated_image', 'generated image',
            # OpenAI / DALL-E
            'dall-e', 'dall·e', 'dalle', 'openai', 'chatgpt', 'gpt-4o', 'gpt4',
            # Midjourney
            'midjourney', 'mid journey',
            # Stable Diffusion ecosystem
            'stable diffusion', 'stablediffusion', 'sdxl', 'sd3', 'sd 3',
            'stable diffusion 3', 'stable diffusion xl',
            'automatic1111', 'a1111', 'comfyui', 'comfy ui', 'invoke ai', 'invokeai',
            'flux.1', 'flux1', 'black forest labs',
            # Adobe
            'firefly', 'adobe firefly',
            # Other commercial tools
            'leonardo.ai', 'leonardo ai', 'ideogram', 'krea', 'krea.ai',
            'playground ai', 'playgroundai', 'playground v2',
            'canva ai', 'canva text to image',
            'nightcafe', 'night cafe', 'dreamstudio', 'dream studio',
            'bluewillow', 'blue willow', 'bing image creator', 'bing create',
            'adobe express', 'getimg', 'getimg.ai',
            # Open source models
            'juggernaut', 'realvisxl', 'dreamshaper', 'dream shaper',
            'animatediff', 'animate diff',
            # Generic AI markers
            'ai generated', 'ai-generated', 'generative ai', 'text-to-image',
            'text to image', 'diffusion model', 'generative', 'image synthesis',
            'neural network generated', 'gan generated', 'latent diffusion',
        ]

        hits = sum(1 for t in ai_tokens if t in text_blob)

        # Strong signal: SD/ComfyUI/DeepSeek PNG parameter chunk patterns
        # e.g. "Steps: 20, Sampler: DPM++, CFG scale: 7, Seed: 123456"
        sd_param_score = 0.0
        if png_chunks:
            chunks_blob = " ".join(str(v).lower() for v in png_chunks.values())
            sd_indicators = ['steps:', 'sampler:', 'cfg scale:', 'cfg:', 'seed:', 'model hash:', 'negative prompt:']
            sd_hits = sum(1 for s in sd_indicators if s in chunks_blob)
            if sd_hits >= 2:
                sd_param_score = 1.0  # definitive — this is a diffusion model output
            elif sd_hits == 1:
                sd_param_score = 0.6

            # DeepSeek OCR/VL markers in PNG metadata or companion text
            deepseek_ocr_indicators = ['<|ref|>', '<|det|>', 'result_ori.mmd', '_det.mmd', 'deepseek']
            if any(ind in chunks_blob for ind in deepseek_ocr_indicators):
                sd_param_score = max(sd_param_score, 1.0)

        c2pa_source = str(c2pa.get('Actions Digital Source Type', '')).lower()
        c2pa_ai = 1.0 if 'trainedalgorithmicmedia' in c2pa_source else 0.0

        # Also catch Google SynthID / Generative AI description in C2PA fields
        c2pa_blob = " ".join(str(v).lower() for v in c2pa.values())
        if any(t in c2pa_blob for t in ['google generative ai', 'synthid', 'generative ai', 'trainedalgorithmicmedia']):
            c2pa_ai = 1.0

        return {'ai_metadata_score': self._bounded(max(c2pa_ai, sd_param_score, hits / 2.0))}

    def _score_metadata_stripped(self, metadata_density: int, camera_exif_strength: float, has_xmp: bool, has_icc: bool) -> float:
        base = 0.0
        if metadata_density <= 1:
            base += 0.65
        elif metadata_density <= 3:
            base += 0.40
        elif metadata_density <= 6:
            base += 0.20
        base += 0.35 * (1.0 - camera_exif_strength)
        if has_xmp:
            base -= 0.10
        if has_icc:
            base -= 0.05
        return self._bounded(base)

    def _extract_file_structure_markers(self, exif: Dict[str, Any], xmp: Dict[str, Any], icc: Dict[str, Any], raw_exiftool: Dict[str, Any]) -> Dict[str, float]:
        all_keys = " | ".join(list(exif.keys()) + list(raw_exiftool.keys())).lower()
        has_app0_jfif = int(any(k in all_keys for k in ['jfif', 'app0']))
        has_app1_exif = int(any(k in all_keys for k in ['exif', 'app1']))
        has_xmp = int(bool(xmp))
        has_icc = int(bool(icc))
        has_dqt = int(any(k in all_keys for k in ['dqt', 'quantization']))

        camera_structure = self._bounded(0.30 * has_app0_jfif + 0.35 * has_app1_exif + 0.20 * has_dqt + 0.15 * has_icc)
        editing_container = self._bounded(0.50 * has_xmp + 0.25 * has_icc + 0.25 * int('creatortool' in all_keys or 'historysoftwareagent' in all_keys))
        return {'camera_structure_score': camera_structure, 'editing_container_score': editing_container}

    def _extract_qtable_signals(self, image_path: str | None) -> Dict[str, float]:
        if not image_path:
            return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}
        try:
            with Image.open(image_path) as img:
                if str(img.format).upper() != 'JPEG':
                    return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}
                qtables = getattr(img, 'quantization', {}) or {}
                luma = list(qtables.get(0, []))
                if not luma:
                    return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}
                very_low = sum(1 for x in luma[:16] if x <= 3)
                sharp_steps = sum(1 for i in range(1, min(len(luma), 32)) if abs(luma[i] - luma[i - 1]) >= 20)
                software_qtable = self._bounded(0.12 * very_low + 0.08 * sharp_steps)
                double_compression = self._bounded(0.05 * sum(1 for x in luma[:32] if x % 2 == 1))
                return {'software_qtable_score': software_qtable, 'double_compression_score': double_compression}
        except Exception:
            return {'software_qtable_score': 0.0, 'double_compression_score': 0.0}

    def _extract_visual_signals(self, image_path: str | None) -> Dict[str, float]:
        if not image_path:
            return {'natural_noise_score': 0.0, 'smooth_gradient_score': 0.0, 'uniform_texture_score': 0.0, 'ai_frequency_anomaly_score': 0.0}
        try:
            with Image.open(image_path) as img:
                gray = img.convert('L')
                max_side = max(gray.size)
                if max_side > 1024:
                    scale = 1024.0 / max_side
                    gray = gray.resize((max(1, int(gray.size[0] * scale)), max(1, int(gray.size[1] * scale))))

                pixel_count = gray.width * gray.height
                gray_data = gray.getdata()
                pixels = [self._pixel_to_int(gray_data[i]) for i in range(pixel_count)]
                blur = gray.filter(ImageFilter.GaussianBlur(radius=1.2))
                blur_data = blur.getdata()
                residual = [abs(pixels[i] - self._pixel_to_int(blur_data[i])) for i in range(pixel_count)]
                noise_std = statistics.pstdev(residual) if len(residual) > 1 else 0.0

                natural_noise_score = self._bounded(1.0 - abs(noise_std - 8.0) / 8.0)
                smooth_gradient_score = self._bounded(max(0.0, (5.0 - noise_std) / 5.0))
                unique_tones = len(set(pixels))
                uniform_texture_score = self._bounded(max(0.0, (80.0 - min(unique_tones, 80)) / 80.0))

                edge = gray.filter(ImageFilter.FIND_EDGES)
                edge_data = edge.getdata()
                edge_vals = [self._pixel_to_int(edge_data[i]) for i in range(pixel_count)]
                edge_std = statistics.pstdev(edge_vals) if len(edge_vals) > 1 else 0.0
                ai_frequency_anomaly_score = self._bounded(max(0.0, (18.0 - edge_std) / 18.0))

                return {
                    'natural_noise_score': natural_noise_score,
                    'smooth_gradient_score': smooth_gradient_score,
                    'uniform_texture_score': uniform_texture_score,
                    'ai_frequency_anomaly_score': ai_frequency_anomaly_score,
                }
        except Exception:
            return {'natural_noise_score': 0.0, 'smooth_gradient_score': 0.0, 'uniform_texture_score': 0.0, 'ai_frequency_anomaly_score': 0.0}

    def _score_ai_structural_signals(
        self,
        metadata_density: int,
        camera_exif_strength: float,
        image_info: Dict[str, Any],
        has_gps: bool,
        has_datetime_original: bool,
    ) -> float:
        """
        Score structural fingerprints common to AI-generated images.
        AI tools produce images with no camera EXIF, no GPS, no datetime,
        stripped metadata, and characteristic output resolutions.
        """
        score = 0.0

        # No camera EXIF at all — strong AI indicator
        if camera_exif_strength < 0.10:
            score += 0.35

        # Very sparse metadata (AI images typically have <5 EXIF fields)
        if metadata_density <= 2:
            score += 0.25
        elif metadata_density <= 5:
            score += 0.10

        # No GPS and no original datetime — real camera photos almost always have these
        if not has_gps:
            score += 0.05
        if not has_datetime_original:
            score += 0.10

        # Common AI output resolutions: square or standard diffusion sizes
        width = int(image_info.get('width') or 0)
        height = int(image_info.get('height') or 0)
        ai_resolutions = {
            (512, 512), (768, 768), (1024, 1024), (1024, 1792), (1792, 1024),
            (1024, 1536), (1536, 1024), (1280, 720), (720, 1280),
            (1344, 768), (768, 1344), (1216, 832), (832, 1216),
            (1152, 896), (896, 1152), (1568, 672), (672, 1568),
            (2048, 2048), (1024, 576), (576, 1024),
        }
        if (width, height) in ai_resolutions:
            score += 0.20

        return self._bounded(score)

    def _score_demosaic_hints(self, exif: Dict[str, Any], raw_exiftool: Dict[str, Any]) -> float:
        keys = " | ".join([str(k).lower() for k in list(exif.keys()) + list(raw_exiftool.keys())])
        hints = ['cfapattern', 'bayer', 'blacklevel', 'whitelinear', 'colormatrix', 'makernotes']
        hits = sum(1 for h in hints if h in keys)
        return self._bounded(hits / 3.0)

    def _score_screenshot_signals(
        self,
        metadata_density: int,
        camera_exif_strength: float,
        image_info: Dict[str, Any],
        visual: Dict[str, Any],
        software_tokens: str,
        exif: Dict[str, Any],
        raw_exiftool: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Score for digital screenshot indicators and infer source device."""
        score = 0.0
        details = []
        inference = "Unknown"

        software_blob = (software_tokens or "").lower()
        absolute_path = str(image_info.get('absolute_path') or "")
        filename = Path(absolute_path).name.lower() if absolute_path else ""
        text_blob = f"{software_blob} | {filename}"
        android_analysis = self._analyze_android_mobile_screenshot(
            metadata_density=metadata_density,
            camera_exif_strength=camera_exif_strength,
            image_info=image_info,
            visual=visual,
            software_blob=software_blob,
            filename=filename,
            exif=exif,
            raw_exiftool=raw_exiftool,
        )

        windows_tokens = [
            'snipping tool', 'snippingtool', 'snip & sketch', 'snip_and_sketch',
            'screenclip', 'screen clipping', 'printscreen', 'print screen',
            'prtsc', 'captures\\'
        ]
        mac_tokens = [
            'screen shot', 'screen_shot', 'screencapture', 'screencaptureui',
            'capture screen'
        ]
        android_tokens = [
            'screenshot_', 'screenshot-', 'screenrecord', 'com.android.systemui',
            'oneui', 'miui', 'coloros', 'oxygenos', 'funtouch'
        ]
        generic_screenshot_tokens = ['screenshot']
        screenshot_tools = windows_tokens + mac_tokens + android_tokens + generic_screenshot_tokens + ['captura', 'greenshot']

        if camera_exif_strength < 0.3:
            score += 0.3
            details.append("Minimal camera metadata presence")

        if visual.get('natural_noise_score', 0) < 0.2:
            score += 0.3
            details.append("Absence of natural sensor noise (digital-perfect surfaces)")

        if image_info.get('mode') == 'RGBA':
            score += 0.4
            details.append("Alpha channel (RGBA) present (common in screenshots)")

        matched_tokens = [t for t in screenshot_tools if t in text_blob]
        if matched_tokens:
            score += 0.5
            details.append("Screenshot signature (metadata or filename) matched")
            if any(t in text_blob for t in mac_tokens):
                inference = "macOS Screenshot"
            elif any(t in text_blob for t in android_tokens):
                inference = "Android Screenshot"
            elif any(t in text_blob for t in windows_tokens):
                inference = "Windows Screenshot"
            elif any(t in text_blob for t in generic_screenshot_tokens):
                inference = "Generic Screenshot"

        if android_analysis['score'] >= 0.60:
            score += 0.15
            details.append("Android mobile screenshot heuristics matched")
            if inference in {"Unknown", "Generic Screenshot", "Mobile Device", "Mobile Device (Portrait)"}:
                inference = "Android Screenshot"

        if metadata_density <= 2 and camera_exif_strength < 0.3:
            score += 0.1
            details.append("Metadata profile is sparse and non-camera-like")

        w = int(image_info.get('width') or 0)
        h = int(image_info.get('height') or 0)
        long_edge = max(w, h)
        short_edge = min(w, h) if min(w, h) else 1
        aspect_ratio = long_edge / short_edge if short_edge else 0.0

        desktop_res = {(1920, 1080), (1366, 768), (2560, 1440), (3840, 2160), (1280, 1024), (1024, 768)}
        mobile_res = {
            (720, 1280), (720, 1520), (720, 1600),
            (1080, 1920), (1080, 2152), (1080, 2244), (1080, 2280), (1080, 2340), (1080, 2400), (1080, 2460),
            (1170, 2532), (1200, 1920), (1284, 2778),
            (1440, 2560), (1440, 2960), (1440, 3040), (1440, 3120),
            (1536, 2152), (1600, 2560), (1768, 2208),
        }
        screen_resolution_score = 0.0
        capture_mode = "Unknown"

        if camera_exif_strength < 0.5:
            if (w, h) in desktop_res or (h, w) in desktop_res:
                if inference in {"Unknown", "Generic Screenshot"}:
                    inference = "Windows Screenshot" if inference == "Generic Screenshot" else "Desktop / Laptop (Full Screen)"
                capture_mode = "Full Screen Capture"
                score += 0.2
                screen_resolution_score = 1.0
            elif (w, h) in mobile_res or (h, w) in mobile_res:
                if inference in {"Unknown", "Generic Screenshot"}:
                    inference = "Android Screenshot" if inference == "Generic Screenshot" else "Mobile Device"
                capture_mode = "Full Screen Capture"
                score += 0.2
                screen_resolution_score = 1.0
            elif (
                w > h and
                w >= 1600 and
                h >= 700 and
                aspect_ratio >= 1.7 and
                camera_exif_strength < 0.3 and
                visual.get('natural_noise_score', 0) < 0.2
            ):
                if inference in {"Unknown", "Generic Screenshot"}:
                    inference = "Android Screenshot" if inference == "Generic Screenshot" else "Mobile Device (Landscape)"
                capture_mode = "Landscape Screen Capture"
                score += 0.18
                screen_resolution_score = 0.9
                details.append("Landscape aspect ratio and low-noise surface are consistent with a mobile screenshot")
            elif w > h and w >= 1200 and 1.2 <= aspect_ratio <= 2.4:
                if inference in {"Unknown", "Generic Screenshot"}:
                    inference = "Windows Screenshot" if inference == "Generic Screenshot" else "Desktop / Laptop Screenshot"
                capture_mode = "Desktop / Laptop Screenshot"
                score += 0.2
                screen_resolution_score = 0.85
                details.append("Resolution and aspect ratio are consistent with a desktop display or window capture")
            elif w < h and h >= 1600 and aspect_ratio >= 1.7:
                if inference in {"Unknown", "Generic Screenshot"}:
                    inference = "Android Screenshot" if inference == "Generic Screenshot" else "Mobile Device (Portrait)"
                capture_mode = "Portrait Screen Capture"
                score += 0.15
                screen_resolution_score = 0.75
            elif w > h and h < 900 and w >= 900:
                if inference in {"Unknown", "Generic Screenshot"}:
                    inference = "Windows Screenshot" if inference == "Generic Screenshot" else "Desktop / Laptop (Windowed Application Capture)"
                capture_mode = "Windowed Application Capture"
                score += 0.15
                screen_resolution_score = 0.8
                details.append("Irregular image height is consistent with a cropped desktop application window")

        os_detected = "Unknown"
        if "Windows" in inference:
            os_detected = "Windows (10/11)"
        elif "macOS" in inference:
            os_detected = "macOS"
        elif "Android" in inference:
            os_detected = "Android"
        elif "Desktop" in inference:
            os_detected = "Desktop OS (Unresolved)"
        elif "Mobile" in inference:
            os_detected = "Mobile OS (Unresolved)"

        device_type = inference
        if inference in {"Windows Screenshot", "macOS Screenshot"} and capture_mode != "Unknown":
            device_type = f"Desktop / Laptop ({capture_mode})"
        elif inference == "Android Screenshot" and capture_mode != "Unknown":
            device_type = f"Android Screenshot ({capture_mode})"
        elif inference == "Mobile Device (Landscape)":
            device_type = "Android Screenshot (Landscape Screen Capture)"

        possible_device_models = []
        if os_detected == "Windows (10/11)":
            possible_device_models = [
                "Generic Windows PC / Laptop",
                "Virtual Machine (VM) Instance",
                "Laptop with External Monitor",
            ]
        elif os_detected == "macOS":
            possible_device_models = ["MacBook", "iMac", "Mac mini / Mac Studio with external display"]
        elif os_detected == "Android":
            possible_device_models = ["Generic Android phone", "Samsung Galaxy device", "Xiaomi / OnePlus / vivo handset"]
        elif "Desktop" in device_type:
            possible_device_models = ["Generic desktop / laptop environment", "Virtual machine guest OS", "Remote desktop session window"]
        elif "Mobile" in device_type:
            possible_device_models = ["Generic mobile device", "Android handset", "iPhone / Android handset"]

        evidence = []
        if w and h:
            evidence.append(f"Resolution {w} x {h} with aspect ratio ~{aspect_ratio:.2f}:1")
        if matched_tokens:
            evidence.append(f"Screenshot naming or software signature matched: {matched_tokens[0]}")
        evidence.extend(details)
        evidence.extend(android_analysis['evidence'])

        digital_markers = []
        if camera_exif_strength < 0.3:
            digital_markers.append("Camera metadata is absent or minimal")
        if visual.get('natural_noise_score', 0) < 0.2:
            digital_markers.append("Natural sensor noise is absent")
        if image_info.get('mode') == 'RGBA':
            digital_markers.append("Image preserves an alpha channel")
        digital_markers.extend(android_analysis['digital_markers'])

        platform_confidence = 55
        if os_detected != "Unknown":
            platform_confidence = 80 if matched_tokens else 68
            if os_detected in {"Windows (10/11)", "macOS", "Android"}:
                platform_confidence += 10
        if android_analysis['is_android_screenshot']:
            platform_confidence = max(platform_confidence, int(android_analysis['confidence']))
        hardware_confidence = 30 if possible_device_models else 20
        if capture_mode == "Windowed Application Capture":
            hardware_confidence = 45
        elif capture_mode == "Full Screen Capture":
            hardware_confidence = 55

        device_info = {
            'device_type': device_type,
            'possible_device_models': possible_device_models,
            'os_detected': os_detected,
            'capture_mode': capture_mode,
            'ui_elements': [],
            'typography': 'Not analyzed from pixels by current pipeline.',
            'key_evidence': evidence,
            'digital_markers': digital_markers,
            'android_screenshot_analysis': {
                'is_android_screenshot': android_analysis['is_android_screenshot'],
                'confidence': android_analysis['confidence'],
                'score': android_analysis['points'],
                'max_score': android_analysis['max_points'],
                'android_version': android_analysis['android_version'],
                'device_model': android_analysis['device_model'],
                'screenshot_method': android_analysis['screenshot_method'],
                'factors': android_analysis['factors'],
                'recommendations': android_analysis['recommendations'],
            },
            'confidence_score': {
                'platform_os_identification': min(95, platform_confidence),
                'specific_hardware': min(70, hardware_confidence),
            },
            'final_verdict': f"Digital screenshot indicators detected. Inferred source: {device_type}.",
            'limitations': [
                'Identification is based on metadata sparsity, filename/tool signatures, and resolution heuristics.',
                'The current pipeline does not perform OCR, window-control recognition, or font identification on screenshot pixels.',
                'Specific physical hardware cannot be conclusively identified from a screenshot alone.',
            ],
        }

        final_score = max(self._bounded(score), android_analysis['score'])
        return {
            'score': final_score,
            'details': details,
            'inference': inference,
            'device_info': device_info,
            'signals': {
                'matched_tokens': matched_tokens,
                'screen_resolution_score': round(screen_resolution_score, 4),
                'metadata_strip_score': round(self._bounded((1.0 - camera_exif_strength) + (0.2 if metadata_density <= 2 else 0.0)), 4),
                'capture_mode': capture_mode,
                'os_detected': os_detected,
                'android_screenshot_score': round(android_analysis['score'], 4),
                'android_screenshot_confidence': round(android_analysis['confidence'], 2),
            }
        }

    def _is_windows_camera_software(self, software_blob: str, filename: str, absolute_path: str) -> bool:
        text_blob = f"{software_blob} | {filename} | {absolute_path}".lower()
        windows_camera_tokens = [
            'windows camera',
            'microsoft camera',
            'windows 11',
            'windows 10',
        ]
        return any(token in text_blob for token in windows_camera_tokens)

    def _analyze_android_mobile_screenshot(
        self,
        metadata_density: int,
        camera_exif_strength: float,
        image_info: Dict[str, Any],
        visual: Dict[str, Any],
        software_blob: str,
        filename: str,
        exif: Dict[str, Any],
        raw_exiftool: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Specialized Android/mobile screenshot analysis without affecting other origin paths."""
        width = int(image_info.get('width') or 0)
        height = int(image_info.get('height') or 0)
        long_edge = max(width, height)
        short_edge = min(width, height) if min(width, height) else 1
        aspect_ratio = long_edge / short_edge if short_edge else 0.0
        absolute_path = str(image_info.get('absolute_path') or "").lower()
        text_blob = f"{software_blob} | {filename} | {absolute_path}"

        if self._is_windows_camera_software(software_blob, filename, absolute_path):
            return {
                'is_android_screenshot': False,
                'confidence': 0.0,
                'score': 0.0,
                'points': 0,
                'max_points': 100,
                'android_version': None,
                'device_model': None,
                'screenshot_method': 'Unknown',
                'factors': {'windows_camera_override': 'Windows camera software markers suppress Android screenshot inference'},
                'recommendations': ['Windows camera software markers are present; treat as desktop/laptop camera capture unless stronger screenshot evidence exists.'],
                'evidence': ['Windows camera software marker found in metadata or filename/path'],
                'digital_markers': [],
            }

        android_resolutions = {
            (720, 1280), (720, 1520), (720, 1600),
            (1080, 1920), (1080, 2244), (1080, 2280), (1080, 2340),
            (1080, 2400), (1080, 2460), (1080, 2152),
            (1170, 2532), (1200, 1920), (1284, 2778),
            (1440, 2560), (1440, 2960), (1440, 3040), (1440, 3120),
            (1536, 2152), (1600, 2560), (1768, 2208),
        }
        android_software_tokens = [
            'android', 'adb', 'screencap', 'com.android.systemui',
            'oneui', 'miui', 'coloros', 'oxygenos', 'funtouch', 'realme ui',
            'lineageos', 'xperia',
        ]
        screenshot_folder_tokens = ['screenshots', 'screen shots', 'dcim\\screenshots', 'pictures\\screenshots']
        factors: Dict[str, Any] = {}
        evidence: List[str] = []
        digital_markers: List[str] = []
        points = 0
        max_points = 100

        if any(token in text_blob for token in android_software_tokens):
            points += 20
            factors['android_software'] = 'Android software or ROM markers detected'
            evidence.append("Android software marker found in filename/path/metadata")

        if any(token in absolute_path for token in screenshot_folder_tokens):
            points += 15
            factors['screenshot_folder'] = 'File path includes a screenshot folder'
            evidence.append("File path is consistent with an Android screenshot storage folder")

        if re.search(r'screenshot[_-]\d{4,8}[-_]\d{2,6}', filename):
            points += 15
            factors['android_filename'] = 'Android-style screenshot filename matched'
            evidence.append("Filename follows a common Android screenshot naming pattern")
        elif filename.startswith('screenshot_') or filename.startswith('screenshot-'):
            points += 10
            factors['android_filename'] = 'Android-style screenshot prefix matched'
            evidence.append("Filename starts with an Android screenshot prefix")

        if (width, height) in android_resolutions or (height, width) in android_resolutions:
            points += 18
            factors['android_resolution'] = f"Resolution {width}x{height} matches a common Android screen"
            evidence.append(f"Resolution {width} x {height} matches a common Android display size")
        elif width < height and height >= 1600 and aspect_ratio >= 1.7:
            points += 12
            factors['android_aspect_ratio'] = f"Portrait mobile aspect ratio {aspect_ratio:.2f}"
            evidence.append("Portrait aspect ratio is consistent with a mobile screenshot")
        elif width > height and width >= 1600 and height >= 700 and aspect_ratio >= 1.7:
            points += 12
            factors['android_landscape_aspect_ratio'] = f"Landscape mobile aspect ratio {aspect_ratio:.2f}"
            evidence.append("Landscape aspect ratio is consistent with a mobile screenshot")

        if camera_exif_strength < 0.3:
            points += 8
            factors['camera_metadata_absent'] = 'Camera EXIF is absent or minimal'
            digital_markers.append("Camera EXIF is absent or minimal")

        if metadata_density <= 2:
            points += 5
            factors['sparse_metadata'] = 'Metadata density is typical of screenshots'

        if visual.get('natural_noise_score', 0.0) < 0.2:
            points += 7
            factors['digital_surface'] = 'Low sensor-noise profile consistent with a screen capture'
            digital_markers.append("Low natural-noise profile consistent with a digital screen capture")

        ui_points, ui_factors, ui_evidence = self._analyze_mobile_ui_bands(image_info)
        points += ui_points
        factors.update(ui_factors)
        evidence.extend(ui_evidence)

        device_model = str(
            exif.get('Model')
            or exif.get('Image Model')
            or exif.get('EXIF Model')
            or raw_exiftool.get('Model')
            or raw_exiftool.get('DeviceModel')
            or ''
        ).strip() or None
        android_version = str(
            raw_exiftool.get('AndroidVersion')
            or raw_exiftool.get('Android Version')
            or raw_exiftool.get('OS Version')
            or ''
        ).strip() or None

        screenshot_method = None
        if 'adb' in text_blob:
            screenshot_method = 'ADB capture'
        elif 'three finger' in text_blob:
            screenshot_method = 'Three-finger gesture'
        elif 'palm swipe' in text_blob:
            screenshot_method = 'Palm swipe gesture'
        elif any(key in filename for key in ('screenshot_', 'screenshot-')):
            screenshot_method = 'Standard Android screenshot capture'

        score = self._bounded(points / max_points)
        confidence = round(score * 100, 2)
        is_android_screenshot = confidence >= 65.0

        recommendations: List[str] = []
        if is_android_screenshot:
            if not device_model:
                recommendations.append("Android screenshot indicators are strong, but device model metadata is not available.")
            if not android_version:
                recommendations.append("Android version could not be extracted from metadata.")
        else:
            recommendations.append("Android screenshot evidence is limited; treat as a generic screenshot unless more metadata is available.")

        return {
            'is_android_screenshot': is_android_screenshot,
            'confidence': confidence,
            'score': score,
            'points': points,
            'max_points': max_points,
            'android_version': android_version,
            'device_model': device_model,
            'screenshot_method': screenshot_method or 'Unknown',
            'factors': factors,
            'recommendations': recommendations,
            'evidence': self._dedupe(evidence),
            'digital_markers': self._dedupe(digital_markers),
        }

    def _analyze_mobile_ui_bands(self, image_info: Dict[str, Any]) -> tuple[int, Dict[str, str], List[str]]:
        """Inspect top/bottom bands for mobile screenshot UI framing cues."""
        absolute_path = str(image_info.get('absolute_path') or "")
        if not absolute_path:
            return 0, {}, []

        try:
            with Image.open(absolute_path) as img:
                rgb = img.convert('RGB')
                arr = np.array(rgb)
        except Exception:
            return 0, {}, []

        height, width = arr.shape[:2]
        if height < 400 or width < 200:
            return 0, {}, []

        band_height = min(90, max(24, height // 28))
        top_band = arr[:band_height, :, :]
        bottom_band = arr[-band_height:, :, :]

        factors: Dict[str, str] = {}
        evidence: List[str] = []
        points = 0

        top_variance = float(np.var(top_band))
        bottom_variance = float(np.var(bottom_band))
        top_brightness = float(np.mean(top_band))
        bottom_brightness = float(np.mean(bottom_band))

        if 120.0 <= top_variance <= 4500.0:
            points += 5
            factors['status_bar_band'] = 'Top band variance is consistent with status-bar UI content'
            evidence.append("Top screen band variance is consistent with a mobile status bar")

        if 40.0 <= bottom_variance <= 3200.0:
            points += 5
            factors['navigation_bar_band'] = 'Bottom band variance is consistent with navigation or gesture UI'
            evidence.append("Bottom screen band variance is consistent with mobile navigation or gesture UI")

        if bottom_brightness < 90.0 or top_brightness < 90.0:
            points += 5
            factors['ui_band_brightness'] = 'Dark UI framing detected at the screen edge'
            evidence.append("Dark UI framing is present on the top or bottom edge of the screenshot")

        return points, factors, evidence

    def _estimate_conflict_level(self, camera_exif_strength: float, camera_pipeline_strength: float, edit_software_strength: float, reencode_strength: float, synthetic_graphic_strength: float, ai_indicator_strength: float) -> float:
        c1 = 1.0 if (camera_exif_strength > 0.7 and (edit_software_strength > 0.6 or reencode_strength > 0.6)) else 0.0
        c2 = 1.0 if (camera_pipeline_strength > 0.6 and ai_indicator_strength > 0.6) else 0.0
        c3 = 1.0 if (synthetic_graphic_strength > 0.7 and camera_exif_strength > 0.7) else 0.0
        return self._bounded((c1 + c2 + c3) / 2.0)

    def _estimate_confidence(self, final_class: str, camera_exif_strength: float, camera_pipeline_strength: float, edit_software_strength: float, reencode_strength: float, synthetic_graphic_strength: float, ai_indicator_strength: float, screenshot_strength: float, conflict_level: float) -> float:
        if final_class == self.CLASS_CAMERA:
            score = 0.60 + 0.20 * camera_exif_strength + 0.20 * camera_pipeline_strength
        elif final_class == self.CLASS_EDITED:
            score = 0.58 + 0.22 * max(edit_software_strength, reencode_strength) + 0.10 * reencode_strength
        elif final_class == self.CLASS_AI:
            score = 0.62 + 0.30 * ai_indicator_strength
        elif final_class == self.CLASS_SYNTHETIC:
            score = 0.56 + 0.30 * synthetic_graphic_strength
        elif final_class == self.CLASS_SCREENSHOT:
            score = 0.65 + 0.25 * screenshot_strength
        else:
            score = 0.40 + 0.20 * (1.0 - conflict_level)
        score -= 0.15 * conflict_level
        return round(self._bounded(score), 4)

    def _to_legacy_label(self, final_class: str, features: Dict[str, Any]) -> str:
        if final_class == self.CLASS_CAMERA:
            return 'camera_original'
        if final_class == self.CLASS_EDITED:
            signals = features.get('signal_vector', {})
            source_inf = features.get('source_inference', 'Unknown')
            is_camera = source_inf != "Unknown" and not any(
                t in source_inf for t in ["Screenshot", "Desktop", "Mobile Device", "Application Capture", "Virtual", "Android"]
            )
            if float(signals.get('camera_exif_strength', 0.0)) >= 0.40 or float(signals.get('camera_pipeline_strength', 0.0)) >= 0.60 or is_camera:
                return 'camera_post_processed'
            return 'software_reencoded'
        if final_class == self.CLASS_AI:
            return 'synthetic_ai_generated'
        if final_class == self.CLASS_SYNTHETIC:
            return 'software_generated'
        if final_class == self.CLASS_SCREENSHOT:
            return 'screenshot_capture'
        return 'origin_unverified'

    def _evidence_for_ai(self, features: Dict[str, Any]) -> List[str]:
        raw = features.get('raw_signals', {})
        out: List[str] = []
        if raw.get('ai_meta_signals', {}).get('ai_metadata_score', 0) > 0:
            out.append("AI metadata signature matched known generative tool/provenance marker.")
        if raw.get('visual', {}).get('ai_frequency_anomaly_score', 0) > 0.4:
            out.append("Abnormal frequency/edge behavior detected.")
        return out or ["AI evidence threshold exceeded."]

    def _evidence_for_camera(self, features: Dict[str, Any]) -> List[str]:
        exif_presence = features.get('raw_signals', {}).get('exif_presence', {})
        out = []
        if exif_presence.get('make') and exif_presence.get('model'):
            out.append("Camera Make/Model present.")
        if exif_presence.get('lens'):
            out.append("LensModel present.")
        if exif_presence.get('exposure') and exif_presence.get('iso'):
            out.append("ExposureTime and ISO present.")
        out.append("Camera pipeline consistency from noise/demosaic/structure signals.")
        return out

    def _evidence_for_edited(self, features: Dict[str, Any]) -> List[str]:
        signals = features.get('signal_vector', {})
        raw = features.get('raw_signals', {})
        out = []
        if signals.get('metadata_stripped_likelihood', 0) >= 0.60:
            out.append("Metadata appears stripped or sparse.")
        if raw.get('software_signals', {}).get('editing_software_score', 0) > 0:
            out.append("Editing software markers detected.")
        if signals.get('reencode_strength', 0) >= 0.45:
            out.append("Compression/re-encoding indicators detected.")
        return out or ["Re-encoding/editing evidence exceeded decision threshold."]

    def _evidence_for_synthetic(self, features: Dict[str, Any]) -> List[str]:
        return [
            "Smooth gradients and uniform digital textures detected.",
            "No strong camera-pipeline evidence (sensor noise/demosaicing/metadata core fields).",
        ]

    def _evidence_for_screenshot(self, features: Dict[str, Any]) -> List[str]:
        raw = features.get('raw_signals', {})
        out = ["Image exhibits digital screenshot characteristics."]
        if features.get('source_inference') != "Unknown":
            out.append(f"Source inferred as: {features.get('source_inference')}")
        return out

    def _evidence_for_unknown(self, features: Dict[str, Any]) -> List[str]:
        signals = features.get('signal_vector', {})
        if float(signals.get('conflict_level', 0.0)) >= 0.5:
            return ["Competing signals conflict across camera/edited/synthetic hypotheses."]
        return ["Insufficient signal strength for a definitive origin class."]

    def _normalize_source_inference(self, source_inference: Any, legacy_label: str) -> str:
        source = str(source_inference or "Unknown").strip() or "Unknown"
        if legacy_label in {'camera_original', 'camera_post_processed'}:
            return "Camera"
        return source

    def _resolve_ai_agent_name(self, features: Dict[str, Any]) -> str:
        c2pa = self._as_dict(features.get('c2pa'))
        return str(c2pa.get('Actions Software Agent Name') or '').strip()

    def _as_dict(self, value: Any) -> Dict[str, Any]:
        return value if isinstance(value, dict) else {}

    def _pixel_to_int(self, value: Any) -> int:
        if isinstance(value, tuple):
            return int(value[0]) if value else 0
        if value is None:
            return 0
        return int(value)

    def _bounded(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def _dedupe(self, items: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for item in items:
            if item not in seen:
                out.append(item)
                seen.add(item)
        return out


__all__ = ['OriginDetector']
