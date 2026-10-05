from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class TrustLevel(str, Enum):
    SYSTEM = "system"
    USER = "user"
    RETRIEVAL = "untrusted"
    TOOL_OUTPUT = "untrusted"
    INTER_AGENT = "untrusted"


class Intent(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    EXECUTE = "execute"
    SEND = "send"
    PURCHASE = "purchase"
    TRANSFER = "transfer"


DESTRUCTIVE_INTENTS = {
    Intent.DELETE, Intent.WRITE, Intent.EXECUTE,
    Intent.SEND, Intent.PURCHASE, Intent.TRANSFER,
}

UNTRUSTED_LEVELS = {
    TrustLevel.RETRIEVAL,
    TrustLevel.TOOL_OUTPUT,
    TrustLevel.INTER_AGENT,
}


@dataclass
class Provenance:
    source: str
    trust_level: TrustLevel
    origin_id: str = ""
    transform_chain: list[str] = field(default_factory=list)
    timestamp: float = 0.0


@dataclass
class ScanResult:
    is_safe: bool
    layer_name: str
    threat_level: str = "CLEAN"
    layers_triggered: list[str] = field(default_factory=list)
    matched_preview: str = ""
    confidence: float = 0.0
    reason: str = ""
    latency_ms: float = 0.0


@dataclass
class ActionProposal:
    action: str
    intent: Intent
    args: dict[str, Any] = field(default_factory=dict)
    provenance: Optional[Provenance] = None
    human_confirmed: bool = False
