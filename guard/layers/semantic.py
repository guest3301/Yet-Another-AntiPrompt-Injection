import time

from guard.models import ScanResult

try:
    from bastion_prompt_protection import Guard
    _bastion_available = True
except ImportError:
    _bastion_available = False


class SemanticClassifier:
    def __init__(self, threshold: float = 0.5):
        self._available = _bastion_available
        self.threshold = threshold
        if not self._available:
            return
        self.guard = Guard()

    def classify(self, text: str) -> ScanResult:
        start = time.perf_counter()

        if not self._available:
            return ScanResult(
                is_safe=True,
                layer_name="semantic",
                reason="ONNX classifier not installed",
                latency_ms=0.0,
            )

        result = self.guard.protect(text)

        is_attack = result.risk >= self.threshold
        latency = (time.perf_counter() - start) * 1000

        return ScanResult(
            is_safe=not is_attack,
            layer_name="semantic",
            threat_level="CRITICAL" if is_attack else "CLEAN",
            layers_triggered=[result.stage_reached] if result.stage_reached else [],
            matched_preview="",
            confidence=result.risk,
            reason=(
                f"ONNX classifier risk={result.risk:.3f} "
                f"label={result.label} stage={result.stage_reached}"
            ),
            latency_ms=latency,
        )