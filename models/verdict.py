from dataclasses import dataclass
from enum import Enum
from typing import Optional


class VerdictCategory(Enum):
    BANNED = "BANNED"
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    POTENTIAL_BYPASS = "POTENTIAL BYPASS"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(Enum):
    HWID_MATCH = "100% (HWID Match)"
    IP_TIME_MATCH = "20-30% (IP + Time Match)"
    IP_TIME_CLOSE_MATCH = "40-50% (IP + Close Time Match)"
    IP_MATCH = "1-10% (IP Match)"
    NO_MATCH = "No Match Found"


@dataclass
class Verdict:
    category: VerdictCategory
    confidence: Optional[ConfidenceLevel] = None
    reason: Optional[str] = None
    hwid_erased: bool = False

    def __str__(self) -> str:
        base = f"{self.category.value}"
        if self.confidence:
            base += f" - {self.confidence.value}"
        if self.reason:
            base += f" - {self.reason}"
        if self.hwid_erased:
            base += " / HWID Erased"
        return base
