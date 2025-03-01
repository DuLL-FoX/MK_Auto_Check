from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict


@dataclass
class PlayerConnection:
    time: datetime
    ip_address: str
    hwid: str
    user_name: str
    user_id: str


@dataclass
class Player:
    user_id: str
    nicknames: List[str] = field(default_factory=list)
    status: str = "unknown"
    ban_counts: int = 0
    ban_reasons: List[str] = field(default_factory=list)
    suspected_vpn: bool = False
    connection_link: str = "N/A"
    associated_ips: Dict[str, List[str]] = field(default_factory=dict)
    associated_hwids: Dict[str, List[str]] = field(default_factory=dict)
    shared_hwid_nicknames: List[str] = field(default_factory=list)
    hwid_erased: bool = False
    complaint_count: int = 0
    complaint_links: str = "N/A"

    @property
    def primary_nickname(self) -> str:
        return self.nicknames[0] if self.nicknames else "Unknown"

    @property
    def has_complaints(self) -> bool:
        return self.complaint_count > 0
