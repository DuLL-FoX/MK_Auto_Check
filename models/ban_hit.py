from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime
from .player import Player


@dataclass
class BanHit:
    ban_hit_id: str
    ban_hit_link: str
    user_id: str
    user_name: str
    ip_address: str
    hwid: str
    time: datetime
    ban_time: Optional[datetime] = None
    ban_expires: Optional[datetime] = None
    hwid_erased: bool = False


@dataclass
class BanBypassCheck:
    ban_hit: BanHit
    banned_player: Player
    potential_bypassers: List[Player] = field(default_factory=list)
    bypass_confidence: str = "No Match Found"
    complaint_links: List[Dict[str, Any]] = field(default_factory=list)
