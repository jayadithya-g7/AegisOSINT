"""
AegisOSINT - Visual Logo & Clone Detector
Implements multi-metric perceptual hashing (dHash, pHash, aHash, wHash),
Hamming distance analysis, color histogram correlation, and brand clone classification.
"""

import io
import os
import math
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image, ImageDraw, ImageFont

try:
    import imagehash
    IMAGEHASH_AVAILABLE = True
except ImportError:
    IMAGEHASH_AVAILABLE = False


class VisualMatcher:
    """Performs visual forensic matching between suspect assets/logos and authentic brand assets."""

    def __init__(self, reference_dir: Optional[str] = None):
        self.reference_dir = reference_dir or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "data", "reference_logos"
        )
        os.makedirs(self.reference_dir, exist_ok=True)
        self._ensure_sample_reference_logos()

    def _ensure_sample_reference_logos(self):
        """Generates crisp synthetic reference logos for demo & benchmarking if not present."""
        brands = {
            "paypal": {"bg": "#003087", "fg": "#0079C1", "text": "PayPal", "shape": "double_p"},
            "binance": {"bg": "#181A20", "fg": "#F0B90B", "text": "BINANCE", "shape": "diamond"},
            "apple": {"bg": "#000000", "fg": "#FFFFFF", "text": "Apple", "shape": "apple"},
            "microsoft": {"bg": "#FFFFFF", "fg": "#00A4EF", "text": "Microsoft", "shape": "squares"},
            "netflix": {"bg": "#141414", "fg": "#E50914", "text": "NETFLIX", "shape": "n_arc"},
            "chase": {"bg": "#117AC9", "fg": "#FFFFFF", "text": "CHASE", "shape": "octagon"},
            "metamask": {"bg": "#FFFFFF", "fg": "#F6851B", "text": "MetaMask", "shape": "fox"}
        }

        for brand, cfg in brands.items():
            path = os.path.join(self.reference_dir, f"{brand}.png")
            if not os.path.exists(path):
                img = Image.new("RGBA", (256, 256), color=cfg["bg"])
                draw = ImageDraw.Draw(img)
                # Draw recognizable distinctive emblem
                if cfg["shape"] == "double_p":
                    draw.polygon([(60, 40), (140, 40), (160, 90), (120, 130), (60, 130)], fill="#0079C1")
                    draw.polygon([(90, 80), (170, 80), (190, 130), (150, 170), (90, 170)], fill="#00457C")
                elif cfg["shape"] == "diamond":
                    draw.polygon([(128, 40), (190, 128), (128, 216), (66, 128)], fill=cfg["fg"])
                    draw.polygon([(128, 80), (160, 128), (128, 176), (96, 128)], fill=cfg["bg"])
                elif cfg["shape"] == "squares":
                    draw.rectangle([(60, 60), (120, 120)], fill="#F25022")
                    draw.rectangle([(136, 60), (196, 120)], fill="#7FBA00")
                    draw.rectangle([(60, 136), (120, 196)], fill="#00A4EF")
                    draw.rectangle([(136, 136), (196, 196)], fill="#FFB900")
                elif cfg["shape"] == "n_arc":
                    draw.rectangle([(70, 50), (100, 206)], fill=cfg["fg"])
                    draw.rectangle([(156, 50), (186, 206)], fill=cfg["fg"])
                    draw.polygon([(70, 50), (100, 50), (186, 206), (156, 206)], fill="#B81D24")
                else:
                    draw.ellipse([(60, 60), (196, 196)], fill=cfg["fg"])

                img.save(path, "PNG")

    def load_image(self, image_input: Any) -> Image.Image:
        """Loads an image from file path, bytes, or returns as PIL Image in RGB."""
        if isinstance(image_input, Image.Image):
            return image_input.convert("RGB")
        elif isinstance(image_input, (bytes, bytearray)):
            return Image.open(io.BytesIO(image_input)).convert("RGB")
        elif isinstance(image_input, str):
            if os.path.exists(image_input):
                return Image.open(image_input).convert("RGB")
            else:
                raise FileNotFoundError(f"Image not found at path: {image_input}")
        raise ValueError("Unsupported image input format.")

    def compute_hashes(self, image: Image.Image) -> Dict[str, str]:
        """Calculates perceptual, difference, average, and wavelet hashes."""
        if IMAGEHASH_AVAILABLE:
            ahash = str(imagehash.average_hash(image))
            phash = str(imagehash.phash(image))
            dhash = str(imagehash.dhash(image))
            whash = str(imagehash.whash(image))
            return {
                "ahash": ahash,
                "phash": phash,
                "dhash": dhash,
                "whash": whash
            }
        else:
            # Fallback manual 64-bit dhash implementation
            dhash_val = self._manual_dhash(image)
            return {
                "ahash": dhash_val,
                "phash": dhash_val,
                "dhash": dhash_val,
                "whash": dhash_val
            }

    def _manual_dhash(self, image: Image.Image, hash_size: int = 8) -> str:
        """Manual difference hash implementation for robustness."""
        resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
        pixels = list(resized.getdata())
        difference = []
        for row in range(hash_size):
            for col in range(hash_size):
                pixel_left = pixels[row * (hash_size + 1) + col]
                pixel_right = pixels[row * (hash_size + 1) + col + 1]
                difference.append(pixel_left > pixel_right)
        decimal_val = 0
        hex_str = []
        for index, val in enumerate(difference):
            if val:
                decimal_val += 2 ** (index % 4)
            if index % 4 == 3:
                hex_str.append(hex(decimal_val)[2:])
                decimal_val = 0
        return "".join(hex_str)

    def compare_images(self, suspect_image_input: Any, reference_image_input: Any) -> Dict[str, Any]:
        """
        Calculates multi-dimensional visual clone similarity metrics:
        - dHash Hamming distance
        - pHash Hamming distance
        - Normalized perceptual similarity %
        - Color palette correlation
        - Clone classification tier
        """
        img_suspect = self.load_image(suspect_image_input)
        img_ref = self.load_image(reference_image_input)

        hashes_suspect = self.compute_hashes(img_suspect)
        hashes_ref = self.compute_hashes(img_ref)

        if IMAGEHASH_AVAILABLE:
            h_phash = imagehash.hex_to_hash(hashes_suspect["phash"]) - imagehash.hex_to_hash(hashes_ref["phash"])
            h_dhash = imagehash.hex_to_hash(hashes_suspect["dhash"]) - imagehash.hex_to_hash(hashes_ref["dhash"])
            h_ahash = imagehash.hex_to_hash(hashes_suspect["ahash"]) - imagehash.hex_to_hash(hashes_ref["ahash"])
            h_whash = imagehash.hex_to_hash(hashes_suspect["whash"]) - imagehash.hex_to_hash(hashes_ref["whash"])
        else:
            h_phash = sum(c1 != c2 for c1, c2 in zip(hashes_suspect["phash"], hashes_ref["phash"]))
            h_dhash = h_phash
            h_ahash = h_phash
            h_whash = h_phash

        # Normalized similarity from Hamming distance (64-bit space)
        # Weighted metric giving higher importance to pHash and dHash
        weighted_hamming = (0.45 * h_phash) + (0.35 * h_dhash) + (0.20 * h_whash)
        perceptual_similarity = max(0.0, min(100.0, round((1.0 - (weighted_hamming / 64.0)) * 100.0, 2)))

        # Color palette correlation
        color_sim = self._calculate_color_similarity(img_suspect, img_ref)

        # Composite visual match score
        composite_score = round((0.75 * perceptual_similarity) + (0.25 * color_sim), 2)

        # Categorize clone threat level
        if composite_score >= 88.0:
            verdict = "CONFIRMED_CLONED_LOGO"
            threat_severity = "CRITICAL"
            explanation = "Extremely high perceptual and structural similarity; deliberate cloned logo intended for brand impersonation."
        elif composite_score >= 70.0:
            verdict = "SUSPICIOUS_LOOKALIKE"
            threat_severity = "HIGH"
            explanation = "Substantial visual congruence with authentic brand emblem; modified or altered lookalike variant."
        elif composite_score >= 50.0:
            verdict = "PARTIAL_VISUAL_SIMILARITY"
            threat_severity = "MEDIUM"
            explanation = "Moderate structural resemblance or overlapping color palette; manual review recommended."
        else:
            verdict = "DISTINCT_VISUAL_IDENTITY"
            threat_severity = "LOW"
            explanation = "Low visual correlation; distinct graphical iconography."

        return {
            "perceptual_similarity_pct": perceptual_similarity,
            "color_palette_similarity_pct": color_sim,
            "composite_visual_score": composite_score,
            "verdict": verdict,
            "threat_severity": threat_severity,
            "explanation": explanation,
            "hamming_distances": {
                "phash": h_phash,
                "dhash": h_dhash,
                "ahash": h_ahash,
                "whash": h_whash
            },
            "hashes": {
                "suspect": hashes_suspect,
                "reference": hashes_ref
            }
        }

    def _calculate_color_similarity(self, img1: Image.Image, img2: Image.Image) -> float:
        """Computes color histogram Bhattacharyya/intersection coefficient."""
        i1 = img1.resize((64, 64)).convert("RGB")
        i2 = img2.resize((64, 64)).convert("RGB")

        hist1 = i1.histogram()
        hist2 = i2.histogram()

        sum1 = sum(hist1) or 1
        sum2 = sum(hist2) or 1
        h1_norm = [x / sum1 for x in hist1]
        h2_norm = [x / sum2 for x in hist2]

        # Histogram intersection
        intersection = sum(min(a, b) for a, b in zip(h1_norm, h2_norm))
        return round(intersection * 100.0, 2)

    def match_against_brand_library(self, suspect_image_input: Any) -> Dict[str, Any]:
        """Compares suspect image against all stored reference brand logos."""
        best_match = None
        highest_score = -1.0
        all_matches = []

        ref_files = [f for f in os.listdir(self.reference_dir) if f.lower().endswith(('.png', '.jpg', '.jpeg', '.webp'))]
        for ref_file in ref_files:
            brand_name = os.path.splitext(ref_file)[0].title()
            ref_path = os.path.join(self.reference_dir, ref_file)
            comparison = self.compare_images(suspect_image_input, ref_path)
            score = comparison["composite_visual_score"]
            match_entry = {
                "brand": brand_name,
                "reference_file": ref_file,
                **comparison
            }
            all_matches.append(match_entry)
            if score > highest_score:
                highest_score = score
                best_match = match_entry

        all_matches.sort(key=lambda x: x["composite_visual_score"], reverse=True)

        return {
            "top_match": best_match,
            "all_ranked_matches": all_matches
        }
