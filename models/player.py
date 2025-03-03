from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class Player:
    user_id: str
    nicknames: List[str]
    status: str = "unknown"
    ban_counts: int = 0
    ban_reasons: List[str] = field(default_factory=list)
    connection_link: str = "N/A"
    associated_ips: Dict[str, List[str]] = field(default_factory=dict)
    associated_hwids: Dict[str, List[str]] = field(default_factory=dict)
    shared_hwid_nicknames: List[str] = field(default_factory=list)
    denied_logins: List[Dict[str, str]] = field(default_factory=list)
    hwid_erased: bool = False
    complaint_links: List[Dict[str, Any]] = field(default_factory=list)
    login_priorities: Dict[str, int] = field(default_factory=dict)
    login_timestamps: Dict[str, str] = field(default_factory=dict)
    raw_message: Optional[str] = None

    @property
    def primary_nickname(self) -> str:
        if not self.nicknames:
            return "Unknown"

        login_nicks = [nick for nick, priority in self.login_priorities.items()
                       if priority == 1 and nick in self.nicknames]
        if login_nicks:
            if len(login_nicks) > 1 and self.login_timestamps:
                login_nicks.sort(key=lambda n: self.login_timestamps.get(n, ""), reverse=True)
            return login_nicks[0]

        if self.login_timestamps and set(self.nicknames) & set(self.login_timestamps.keys()):
            valid_nicks = [n for n in self.nicknames if n in self.login_timestamps]
            return sorted(valid_nicks, key=lambda n: self.login_timestamps.get(n, ""), reverse=True)[0]

        return self.nicknames[0]