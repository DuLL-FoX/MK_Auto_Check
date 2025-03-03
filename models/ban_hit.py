from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

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
    banned_user_name: Optional[str] = None


@dataclass
class BanBypassCheck:
    ban_hit: BanHit
    banned_player: Player
    potential_bypassers: List[Player] = field(default_factory=list)
    bypass_confidence: str = "No Match Found"
    complaint_links: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "ban_hit_id": self.ban_hit.ban_hit_id,
            "ban_hit_link": self.ban_hit.ban_hit_link,
            "banned_user_name": self.banned_player.nicknames[0] if self.banned_player.nicknames else "Unknown",
            "banned_user_id": self.banned_player.user_id,
            "ban_time": self.ban_hit.ban_time.isoformat() if self.ban_hit.ban_time else None,
            "ban_expires": self.ban_hit.ban_expires.isoformat() if self.ban_hit.ban_expires else None,
            "ip_address": self.ban_hit.ip_address,
            "hwid": self.ban_hit.hwid,
            "hwid_erased": self.ban_hit.hwid_erased,
            "status": self.banned_player.status.lower(),
            "ban_counts": self.banned_player.ban_counts,
            "ban_reasons": self.banned_player.ban_reasons,
            "connection_link": self.banned_player.connection_link,
            "bypass_confidence": self.bypass_confidence,
            "potential_bypassers": []
        }

        for bypasser in self.potential_bypassers:
            bypasser_data = {
                "user_id": bypasser.user_id,
                "nicknames": bypasser.nicknames,
                "primary_nickname": bypasser.primary_nickname,
                "status": bypasser.status.lower(),
                "ban_counts": bypasser.ban_counts,
                "ban_reasons": bypasser.ban_reasons,
                "connection_link": bypasser.connection_link,
                "associated_ips": bypasser.associated_ips,
                "associated_hwids": bypasser.associated_hwids,
                "shared_hwid_nicknames": bypasser.shared_hwid_nicknames,
                "evidence": {
                    "shared_hwids": [],
                    "shared_ips": []
                }
            }

            for ip, shared_nicks in bypasser.associated_ips.items():
                if ip in self.banned_player.associated_ips:
                    bypasser_data["evidence"]["shared_ips"].append({
                        "ip": ip,
                        "shared_with": list(set(shared_nicks) & set(self.banned_player.associated_ips.get(ip, [])))
                    })

            for hwid, shared_nicks in bypasser.associated_hwids.items():
                if hwid in self.banned_player.associated_hwids:
                    bypasser_data["evidence"]["shared_hwids"].append({
                        "hwid": hwid,
                        "shared_with": list(set(shared_nicks) & set(self.banned_player.associated_hwids.get(hwid, [])))
                    })

            result["potential_bypassers"].append(bypasser_data)

        # Add complaint links
        result["complaint_links"] = self.complaint_links

        return result
