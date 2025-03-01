import re
import time
import logging
from typing import Dict, Union, List, Any, Optional, Tuple, Set
from urllib.parse import urljoin, quote_plus
from functools import lru_cache
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup, Tag
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

N_A = "N/A"
TIMEOUT = 60

logger = logging.getLogger(__name__)
perf_logger = logging.getLogger(__name__ + ".performance")


@dataclass
class ConnectionData:
    user_name: str
    user_id: str
    time: str
    ip_address: str
    hwid: str
    status: str
    server: str
    trust_score: str
    ban_hits_link: Optional[str] = None
    connection_id: Optional[str] = None
    is_denied_banned: bool = False

    def get(self, key: str, default=None):
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_name": self.user_name,
            "user_id": self.user_id,
            "time": self.time,
            "ip_address": self.ip_address,
            "hwid": self.hwid,
            "status": self.status,
            "server": self.server,
            "trust_score": self.trust_score,
            "ban_hits_link": self.ban_hits_link,
            "connection_id": self.connection_id
        }

class AdminPanel:
    BASE_ADMIN_URL = "https://admin.deadspace14.net"
    PLAYERS_URL = f"{BASE_ADMIN_URL}/Players"
    ACCOUNT_URL = "https://account.spacestation14.com"
    CONNECTIONS_URL = f"{BASE_ADMIN_URL}/Connections"
    BAN_HITS_URL_PATTERN = f"{BASE_ADMIN_URL}/Connections/Hits"
    PLAYER_INFO_URL_PATTERN = f"{BASE_ADMIN_URL}/Players/Info/{{}}"
    BANS_URL = f"{BASE_ADMIN_URL}/Bans"

    LOGIN_RETRY_LIMIT = 3

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.session = self._create_session()
        self.login_attempts = 0
        self._is_authenticated = False
        self._request_metrics = {"total": 0, "slow_requests": 0, "errors": 0}
        self._setup_loggers()

    def _setup_loggers(self):
        if not perf_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            perf_logger.addHandler(handler)
            perf_logger.setLevel(logging.INFO)

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retries, pool_connections=150, pool_maxsize=150)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible)",
        })
        return session

    def login(self) -> bool:
        if self._is_authenticated:
            return True
        while self.login_attempts < self.LOGIN_RETRY_LIMIT:
            self.login_attempts += 1
            logger.info(f"Login attempt {self.login_attempts}/{self.LOGIN_RETRY_LIMIT}")
            try:
                if self._attempt_login():
                    self._is_authenticated = True
                    return True
            except Exception as e:
                logger.error(f"Login error: {str(e)}")
            logger.warning(f"Login attempt {self.login_attempts} failed")
        logger.error(f"Login failed after {self.LOGIN_RETRY_LIMIT} attempts")
        return False

    def _attempt_login(self) -> bool:
        try:
            response = self.session.get(self.PLAYERS_URL, allow_redirects=True, timeout=TIMEOUT)
            response.raise_for_status()
            if response.url == self.PLAYERS_URL:
                return True
            if self.ACCOUNT_URL not in response.url:
                return False
            soup = BeautifulSoup(response.text, "html.parser")
            token_input = soup.select_one("input[name='__RequestVerificationToken']")
            if not token_input:
                logger.error("Anti-forgery token not found")
                return False
            token = token_input.get("value")
            payload = {
                "Input.EmailOrUsername": self.username,
                "Input.Password": self.password,
                "__RequestVerificationToken": token
            }
            sso_login_url = response.url
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": sso_login_url,
                "Origin": self.ACCOUNT_URL,
            }
            response = self.session.post(sso_login_url, data=payload, headers=headers,
                                         allow_redirects=True, timeout=TIMEOUT)
            response.raise_for_status()
            if f"{self.BASE_ADMIN_URL}/signin-oidc" in response.text:
                soup = BeautifulSoup(response.text, "html.parser")
                form = soup.select_one("form")
                if not form:
                    logger.error("Redirect form not found")
                    return False
                redirect_action_url = form.get("action")
                inputs = form.select("input")
                form_data = {inp.get("name"): inp.get("value", "") for inp in inputs}
                response = self.session.post(
                    redirect_action_url,
                    data=form_data,
                    headers={"Referer": response.url},
                    allow_redirects=True,
                    timeout=TIMEOUT
                )
                response.raise_for_status()
                if "Logout" in response.text or "Players" in response.text:
                    logger.info("Successfully authenticated")
                    self.login_attempts = 0
                    return True
                else:
                    return False
            else:
                return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error: {str(e)}")
            return False

    def _ensure_authenticated(self) -> bool:
        if not self._is_authenticated:
            return self.login()
        return True

    def _parse_connection_row(self, row: Tag) -> Optional[ConnectionData]:
        try:
            cols = row.select("td")
            if len(cols) < 8:
                return None
            ban_hits_link = None
            connection_id = None
            if len(cols) >= 9 and cols[8].select_one("a"):
                ban_hits_link = urljoin(self.BASE_ADMIN_URL, cols[8].select_one("a")["href"])
                if ban_hits_link and "connection=" in ban_hits_link:
                    connection_id = ban_hits_link.split("connection=")[-1].split("&")[0]
            user_name_el = cols[0].select_one("strong")
            user_name = user_name_el.text.strip() if user_name_el else cols[0].text.strip()
            status_el = cols[5].select_one("strong")
            status = status_el.text.strip() if status_el else cols[5].text.strip()
            return ConnectionData(
                user_name=user_name,
                user_id=cols[1].text.strip(),
                time=cols[2].text.strip(),
                ip_address=cols[3].text.strip(),
                hwid=cols[4].text.strip(),
                status=status,
                server=cols[6].text.strip(),
                trust_score=cols[7].text.strip(),
                ban_hits_link=ban_hits_link,
                connection_id=connection_id,
                is_denied_banned=("Denied: Banned" in status)
            )
        except Exception as e:
            logger.error(f"Error parsing connection row: {str(e)}")
            return None

    def _parse_connections_table(self, soup: BeautifulSoup) -> List[ConnectionData]:
        connections = []
        table = soup.select_one("table.table")
        if not table:
            return connections
        tbody = table.select_one("tbody")
        if not tbody:
            return connections
        for row in tbody.select("tr"):
            connection = self._parse_connection_row(row)
            if connection:
                connections.append(connection)
        return connections

    def _get_next_page_link(self, soup: BeautifulSoup) -> Optional[str]:
        next_page_link = soup.select_one("a.btn[href*='page=']")
        if next_page_link and "Next" in next_page_link.text and "disabled" not in next_page_link.get("class", []):
            return urljoin(self.BASE_ADMIN_URL, next_page_link["href"])
        next_page_link = soup.select_one("a.page-link[rel='next']")
        if next_page_link:
            return urljoin(self.BASE_ADMIN_URL, next_page_link["href"])
        return None

    def fetch_paginated_data(self, url: str, max_pages: int = 0) -> List[ConnectionData]:
        if not self._ensure_authenticated():
            logger.error("Not authenticated, cannot fetch data")
            return []
        all_connections = []
        current_url = url
        page_num = 1
        pages_fetched = 0
        start_time = time.time()
        while current_url:
            if max_pages > 0 and pages_fetched >= max_pages:
                break
            try:
                self._request_metrics["total"] += 1
                req_start = time.time()
                response = self.session.get(current_url, timeout=TIMEOUT)
                req_time = time.time() - req_start
                if req_time > 1.0:
                    self._request_metrics["slow_requests"] += 1
                    perf_logger.info(f"Slow request ({req_time:.2f}s): {current_url}")
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                connections = self._parse_connections_table(soup)
                all_connections.extend(connections)
                next_page_url = self._get_next_page_link(soup)
                if next_page_url:
                    current_url = next_page_url
                    page_num += 1
                    pages_fetched += 1
                else:
                    current_url = None
            except requests.exceptions.RequestException as e:
                self._request_metrics["errors"] += 1
                logger.error(f"Error on page {page_num}: {str(e)}")
                break
            except Exception as e:
                self._request_metrics["errors"] += 1
                logger.error(f"Error parsing page {page_num}: {str(e)}")
                break
        total_time = time.time() - start_time
        logger.info(f"Fetched {len(all_connections)} connections from {pages_fetched + 1} page(s) in {total_time:.2f}s")
        return all_connections

    def fetch_ban_hit_connections(self, max_pages: int = 0) -> List[Dict[str, Any]]:
        url = f"{self.CONNECTIONS_URL}?showSet=true&search=&showBanned=true"
        connections = self.fetch_paginated_data(url, max_pages)
        return [conn.to_dict() for conn in connections]

    def fetch_ban_info(self, ban_hits_link: str) -> Dict[str, str]:
        if not self._ensure_authenticated():
            return {}
        ban_info: Dict[str, str] = {}
        try:
            if ban_hits_link and "connection=" in ban_hits_link:
                ban_hit_id = ban_hits_link.split("connection=")[-1].split("&")[0]
                ban_info["ban_hit_id"] = ban_hit_id
            start_time = time.time()
            response = self.session.get(ban_hits_link, timeout=TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            dl = soup.select_one("dl")
            if dl:
                dt_tags = dl.select("dt")
                dd_tags = dl.select("dd")
                info = {dt.get_text(strip=True).rstrip(":"): dd.get_text(strip=True)
                        for dt, dd in zip(dt_tags, dd_tags)}
                ban_info.update({
                    "banned_user_name": info.get("Name", ""),
                    "user_id": info.get("User ID", ""),
                    "ip_address": info.get("IP", ""),
                    "hwid": info.get("HWID", ""),
                    "time": info.get("Time", ""),
                })
            table = soup.select_one("table.table")
            if table:
                rows = table.select("tr")
                for row in rows:
                    cols = row.select("td")
                    if len(cols) >= 6:
                        ban_info["ban_time"] = cols[2].get_text(strip=True)
                        ban_info["expires"] = cols[4].get_text(strip=True)
                        link_tag = cols[6].select_one("a")
                        if link_tag:
                            m = re.search(r"/Bans/Hits/(\d+)", link_tag.get("href", ""))
                            if m:
                                ban_info["ban_id"] = m.group(1)
                        break
            elapsed = time.time() - start_time
            if elapsed > 1.0:
                perf_logger.info(f"Slow ban info fetch: {elapsed:.2f}s for {ban_hits_link}")
        except requests.exceptions.RequestException as e:
            self._request_metrics["errors"] += 1
            logger.error(f"Error fetching ban info: {str(e)}")
        except Exception as e:
            logger.error(f"Error parsing ban info: {str(e)}")
        return ban_info

    def get_connections_url(self, user_id: str = "", search: str = "", show_accepted: str = "true",
                            show_banned: str = "true", show_whitelist: str = "true", show_full: str = "true",
                            show_panic: str = "true") -> str:
        search_term = quote_plus(user_id if user_id else search)
        url = (f"{self.BASE_ADMIN_URL}/Connections?perPage=2000&showSet=true"
               f"&search={search_term}&showAccepted={show_accepted}&showBanned={show_banned}"
               f"&showWhitelist={show_whitelist}&showFull={show_full}&showPanic={show_panic}")
        return url

    def fetch_connections_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        url = self.get_connections_url(user_id=user_id)
        connections = self.fetch_paginated_data(url)
        return [conn.to_dict() for conn in connections]

    def check_account_on_site(self, url: str, single_user: bool = False) -> Union[
        List[Dict[str, Any]], Dict[str, Union[str, List[str], bool, int]]]:
        connections = self.fetch_paginated_data(url)
        if single_user:
            return self.aggregate_single_user_info(connections)
        return [conn.to_dict() for conn in connections]

    @lru_cache(maxsize=200)
    def fetch_player_info(self, user_id: str) -> Dict[str, Union[int, List[str]]]:
        if not self._ensure_authenticated():
            return {"ban_counts": 0, "ban_reasons": []}
        info_result = {"ban_counts": 0, "ban_reasons": []}
        info_url = self.PLAYER_INFO_URL_PATTERN.format(user_id)
        try:
            start_time = time.time()
            resp = self.session.get(info_url, timeout=TIMEOUT)
            resp.raise_for_status()
            soup = BeautifulSoup(resp.text, "html.parser")
            ban_section = soup.select_one("h2:contains('Bans')")
            if ban_section:
                ban_table = ban_section.find_next("table")
                if ban_table:
                    ban_body = ban_table.select_one("tbody")
                    if ban_body:
                        for row in ban_body.select("tr"):
                            cols = row.select("td")
                            if len(cols) >= 2:
                                reason = cols[1].get_text(strip=True)
                                info_result["ban_reasons"].append(reason)
                    info_result["ban_counts"] = len(info_result["ban_reasons"])
            elapsed = time.time() - start_time
            if elapsed > 1.0:
                perf_logger.info(f"Slow player info fetch: {elapsed:.2f}s for user {user_id}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.debug(f"Player profile not found: {user_id}")
            else:
                self._request_metrics["errors"] += 1
                logger.error(f"HTTP error for {user_id}: {str(e)}")
        except requests.exceptions.RequestException as e:
            self._request_metrics["errors"] += 1
            logger.error(f"Request error for {user_id}: {str(e)}")
        return info_result

    def aggregate_single_user_info(self, connections: List[Union[ConnectionData, Dict[str, Any]]]) -> Dict[
        str, Union[str, List[str], bool, int]]:
        if not connections:
            return {
                "status": "unknown",
                "nicknames": [],
                "raw_html_snippet": [],
                "suspected_vpn": False,
                "ban_counts": 0,
                "ban_reasons": [],
                "shared_hwid_nicknames": [],
                "associated_ips": {},
                "associated_hwids": {},
                "user_id": "N/A",
                "connection_link": "N/A",
                "denied_banned_connections": []
            }
        result: Dict[str, Any] = {
            "status": "unknown",
            "nicknames": set(),
            "suspected_vpn": False,
            "ban_counts": 0,
            "ban_reasons": set(),
            "shared_hwid_nicknames": set(),
            "associated_ips": {},
            "associated_hwids": {},
            "user_id": "N/A",
            "connection_link": "N/A",
            "denied_banned_connections": []
        }
        all_ips = {}
        all_hwids = {}
        banned_found = False
        denied_banned_found = False
        connection_id = None
        for connection in connections:
            if isinstance(connection, ConnectionData):
                nickname = connection.user_name
                ip_address = connection.ip_address
                hwid = connection.hwid
                status = connection.status
                user_id = connection.user_id
                time = connection.time
                server = connection.server
                is_denied_banned = connection.is_denied_banned
                connection_id = connection_id or connection.connection_id
            else:
                nickname = connection.get("user_name", "")
                ip_address = connection.get("ip_address", "")
                hwid = connection.get("hwid", "")
                status = connection.get("status", "")
                user_id = connection.get("user_id", "")
                time = connection.get("time", "")
                server = connection.get("server", "")
                is_denied_banned = "Denied: Banned" in status
                connection_id = connection_id or connection.get("connection_id", "")
            if user_id and result["user_id"] == "N/A":
                result["user_id"] = user_id
            result["nicknames"].add(nickname)
            if ip_address and ip_address != N_A:
                all_ips.setdefault(ip_address, set()).add(nickname)
            if hwid and hwid != N_A:
                all_hwids.setdefault(hwid, set()).add(nickname)
            if "Accepted" in status:
                result["status"] = "clean"
            if is_denied_banned:
                denied_banned_found = True
                result["denied_banned_connections"].append({
                    "user_name": nickname,
                    "time": time,
                    "ip_address": ip_address,
                    "hwid": hwid,
                    "server": server,
                    "status": status
                })
            if "Banned" in status:
                banned_found = True
        if denied_banned_found:
            result["status"] = "banned"
            result["ban_counts"] = max(result["ban_counts"], 1)
        elif banned_found:
            result["status"] = "banned"
        if connection_id:
            result["connection_link"] = f"{self.BASE_ADMIN_URL}/Connections/Info/{connection_id}"
        user_id = result["user_id"]
        if user_id and user_id != "N/A" and not denied_banned_found:
            player_info = self.fetch_player_info(user_id)
            result["ban_counts"] = player_info.get("ban_counts", 0)
            result["ban_reasons"].update(player_info.get("ban_reasons", []))
        result["associated_ips"] = {ip: list(nicks) for ip, nicks in all_ips.items()}
        result["associated_hwids"] = {hwid: list(nicks) for hwid, nicks in all_hwids.items()}
        for hwid, nicks in all_hwids.items():
            if len(nicks) > 1 and hwid != N_A:
                result["shared_hwid_nicknames"].update(nicks)
        if result["ban_counts"] > 0:
            if result["ban_counts"] >= 5:
                result["status"] = "suspicious"
            elif result["status"] not in ("suspicious", "banned"):
                result["status"] = "banned"
        result["raw_html_snippet"] = []
        for conn in connections[:100]:
            if isinstance(conn, ConnectionData):
                result["raw_html_snippet"].append({"time": conn.time, "status": conn.status})
            else:
                result["raw_html_snippet"].append({"time": conn.get("time", ""), "status": conn.get("status", "")})
        result["nicknames"] = list(result["nicknames"])
        result["ban_reasons"] = list(result["ban_reasons"])
        result["shared_hwid_nicknames"] = list(result["shared_hwid_nicknames"])
        return result

    def aggregate_player_info(self, partial_results_list: List[Dict[str, Any]]) -> List[
        Dict[str, Union[str, List[str], bool, int]]]:
        if not partial_results_list:
            return []
        merged_results = []
        used = [False] * len(partial_results_list)
        for i, result_i in enumerate(partial_results_list):
            if used[i]:
                continue
            merged_dict = {
                "status": result_i["status"],
                "nicknames": set(result_i["nicknames"]),
                "suspected_vpn": result_i["suspected_vpn"],
                "ban_counts": result_i["ban_counts"],
                "ban_reasons": set(result_i["ban_reasons"]),
                "shared_hwid_nicknames": set(result_i["shared_hwid_nicknames"]),
                "associated_ips": result_i["associated_ips"].copy(),
                "associated_hwids": result_i["associated_hwids"].copy(),
                "user_id": result_i.get("user_id", "N/A"),
                "connection_link": result_i.get("connection_link", "N/A"),
                "denied_banned_connections": result_i.get("denied_banned_connections", []).copy(),
            }
            used[i] = True
            merged_nicknames = set(result_i["nicknames"])
            for j in range(i + 1, len(partial_results_list)):
                if used[j]:
                    continue
                result_j = partial_results_list[j]
                if merged_nicknames.intersection(result_j["nicknames"]):
                    used[j] = True
                    merged_nicknames.update(result_j["nicknames"])
                    merged_dict["nicknames"].update(result_j["nicknames"])
                    merged_dict["ban_reasons"].update(result_j["ban_reasons"])
                    merged_dict["shared_hwid_nicknames"].update(result_j["shared_hwid_nicknames"])
                    merged_dict["ban_counts"] = max(merged_dict["ban_counts"], result_j["ban_counts"])
                    merged_dict["suspected_vpn"] = merged_dict["suspected_vpn"] or result_j["suspected_vpn"]
                    merged_dict["status"] = self._merge_statuses(merged_dict["status"], result_j["status"])
                    if merged_dict["user_id"] == "N/A" and result_j.get("user_id") != "N/A":
                        merged_dict["user_id"] = result_j.get("user_id")
                    if merged_dict["connection_link"] == "N/A" and result_j.get("connection_link") != "N/A":
                        merged_dict["connection_link"] = result_j.get("connection_link")
                    merged_dict["denied_banned_connections"].extend(result_j.get("denied_banned_connections", []))
                    for ip, nicks in result_j["associated_ips"].items():
                        if ip in merged_dict["associated_ips"]:
                            current_nicks = set(merged_dict["associated_ips"][ip])
                            current_nicks.update(nicks)
                            merged_dict["associated_ips"][ip] = list(current_nicks)
                        else:
                            merged_dict["associated_ips"][ip] = nicks.copy() if isinstance(nicks, list) else nicks
                    for hwid, nicks in result_j["associated_hwids"].items():
                        if hwid in merged_dict["associated_hwids"]:
                            current_nicks = set(merged_dict["associated_hwids"][hwid])
                            current_nicks.update(nicks)
                            merged_dict["associated_hwids"][hwid] = list(current_nicks)
                        else:
                            merged_dict["associated_hwids"][hwid] = nicks.copy() if isinstance(nicks, list) else nicks
            merged_dict["nicknames"] = list(merged_dict["nicknames"])
            merged_dict["ban_reasons"] = list(merged_dict["ban_reasons"])
            merged_dict["shared_hwid_nicknames"] = list(merged_dict["shared_hwid_nicknames"])
            merged_results.append(merged_dict)
        return merged_results

    def _merge_statuses(self, status_a: str, status_b: str) -> str:
        priority = {"suspicious": 4, "banned": 3, "unknown": 2, "clean": 1}
        return status_a if priority.get(status_a, 2) > priority.get(status_b, 2) else status_b

    def get_request_metrics(self) -> Dict[str, int]:
        return dict(self._request_metrics)
