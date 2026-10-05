import base64
import re
import time

from guard.models import ScanResult

INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)",
    r"disregard\s+(all\s+)?(previous|prior|above)",
    r"forget\s+(everything|all)\s+(you|that)",
    r"you\s+are\s+now\s+(a|an|in)\s+",
    r"new\s+instructions?\s*:",
    r"system\s*:\s*",
    r"override\s+(your\s+)?(instructions|rules|safety)",
    r"act\s+as\s+(if|though)\s+you",
    r"jailbreak",
    r"DAN\s+mode",
    r"developer\s+mode\s+enabled",
    r"pretend\s+(you\s+are|to\s+be)",
]

FLIP_TOKEN_PATTERNS = [
    r"_[A-Z]{4,}$",
    r"\[/?INST\]",
    r"<\|im_start\|>",
    r"<\|im_end\|>",
]

ENCODING_PATTERNS = [
    (r"^[A-Za-z0-9+/]{40,}={0,2}$", "base64"),
    (r"^[0-9a-fA-F]{40,}$", "hex"),
    (r"^[A-Za-z0-9+/]{20,}$", "base64_likely"),
]

HOMOGLYPH_PATTERN = re.compile(
    r"[\u0430\u0435\u043E\u0440\u0441\u0445\u0443]"
    r"|[\uFF41-\uFF5A]"
    r"|[\u200B-\u200F\u2028-\u202F]"
)


class PreFilter:
    def __init__(self):
        self._compiled_injection = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]
        self._compiled_flip = [re.compile(p) for p in FLIP_TOKEN_PATTERNS]

    def scan(self, text):
        start = time.perf_counter()
        triggered = []
        matched_preview = ""

        for pattern in self._compiled_injection:
            m = pattern.search(text)
            if m:
                triggered.append("injection_phrase")
                matched_preview = m.group(0)[:80]
                break

        if not triggered:
            for pattern in self._compiled_flip:
                m = pattern.search(text)
                if m:
                    triggered.append("flip_token")
                    matched_preview = m.group(0)[:80]
                    break

        if not triggered:
            stripped = text.strip()
            for pattern, enc_type in ENCODING_PATTERNS:
                if re.match(pattern, stripped):
                    try:
                        decoded = base64.b64decode(stripped).decode("utf-8", errors="ignore")
                        if len(decoded) > 5:
                            triggered.append(f"encoded_{enc_type}")
                            matched_preview = decoded[:80]
                    except Exception:
                        pass
                    break

        if not triggered and HOMOGLYPH_PATTERN.search(text):
            triggered.append("homoglyph")

        if not triggered and re.search(r"\.\./|\.\.\\|%2e%2e", text, re.IGNORECASE):
            triggered.append("path_traversal")

        latency = (time.perf_counter() - start) * 1000
        is_safe = len(triggered) == 0

        return ScanResult(
            is_safe=is_safe,
            layer_name="pre_filter",
            threat_level="CRITICAL" if not is_safe else "CLEAN",
            layers_triggered=triggered,
            matched_preview=matched_preview,
            confidence=1.0 if not is_safe else 0.0,
            reason=f"Triggered: {', '.join(triggered)}" if triggered else "Clean",
            latency_ms=latency,
        )
