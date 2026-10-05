import time

from guard.explain import ExplainLog
from guard.layers.firewall import ActionFirewall
from guard.layers.pre_filter import PreFilter
from guard.layers.semantic import SemanticClassifier


class PromptInjectionGuard:
    def __init__(self, log_path="explain_log.jsonl"):
        self.pre_filter = PreFilter()
        self.semantic = SemanticClassifier()
        self.firewall = ActionFirewall()
        self.log = ExplainLog(log_path)

    def check_input(self, text, provenance):
        start = time.perf_counter()
        results = []

        pf = self.pre_filter.scan(text)
        results.append(pf)
        if not pf.is_safe:
            self.log.record("pre_filter_block", text, pf)
            return self._blocked(pf, start, results)

        sem = self.semantic.classify(text)
        results.append(sem)
        if not sem.is_safe:
            self.log.record("semantic_block", text, sem)
            return self._blocked(sem, start, results)

        return {
            "blocked": False,
            "layer": "passed",
            "reason": "All layers passed",
            "detail": {r.layer_name: r.__dict__ for r in results},
            "latency_ms": (time.perf_counter() - start) * 1000,
        }

    def check_action(self, proposal, user_role="viewer"):
        allowed, reason = self.firewall.authorize(proposal, user_role)
        self.log.record(
            "action_authorized" if allowed else "action_denied",
            str(proposal.args),
            {"action": proposal.action, "reason": reason, "role": user_role},
        )
        return {"allowed": allowed, "reason": reason}

    def _blocked(self, scan, start, all_results):
        return {
            "blocked": True,
            "layer": scan.layer_name,
            "reason": scan.reason,
            "matched_preview": scan.matched_preview,
            "threat_level": scan.threat_level,
            "detail": {r.layer_name: r.__dict__ for r in all_results},
            "latency_ms": (time.perf_counter() - start) * 1000,
        }
