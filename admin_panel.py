import logging
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Union, List, Any, Optional
from urllib.parse import urljoin, quote_plus

import requests
from bs4 import BeautifulSoup, Tag
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config_system import get_config
from utils.performance_monitor import PerformanceStats

N_A = "N/A"

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
    def __init__(self, username: str, password: str) -> None:
        self.logger = logging.getLogger(__name__)
        self.username = username
        self.password = password
        cfg = get_config()
        self.BASE_ADMIN_URL = cfg.api.base_admin_url
        self.ACCOUNT_URL = cfg.api.account_url
        self.PLAYERS_URL = f"{self.BASE_ADMIN_URL}/Players"
        self.CONNECTIONS_URL = f"{self.BASE_ADMIN_URL}/Connections"
        self.BAN_HITS_URL_PATTERN = f"{self.BASE_ADMIN_URL}/Connections/Hits"
        self.PLAYER_INFO_URL_PATTERN = f"{self.BASE_ADMIN_URL}/Players/Info/{{}}"
        self.BANS_URL = f"{self.BASE_ADMIN_URL}/Bans"
        self.LOGIN_RETRY_LIMIT = cfg.api.login_retry_limit
        self.TIMEOUT = cfg.api.request_timeout
        self.SLOW_REQUEST_THRESHOLD = 5.0
        self.session = self._create_session()
        self.login_attempts = 0
        self._is_authenticated = False
        self._auth_token_timestamp = 0
        self._auth_token_ttl = 1800
        self._request_metrics = {"total": 0, "slow_requests": 0, "errors": 0}
        self._setup_loggers()
        self.perf_stats = PerformanceStats(self.perf_logger)
        self._response_cache = {}
        self.logger.info(
            f"AdminPanel initialized with URLs: BASE={self.BASE_ADMIN_URL}, CONNECTIONS={self.CONNECTIONS_URL}")

    def _setup_loggers(self):
        from utils.logging_utils import get_logger
        self.perf_logger = get_logger(f"{__name__}.performance")

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(
            max_retries=retries,
            pool_connections=150,
            pool_maxsize=150,
            pool_block=False
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible)",
            "Connection": "keep-alive"
        })
        return session

    def login(self) -> bool:
        if self._is_authenticated and (time.time() - self._auth_token_timestamp) < self._auth_token_ttl:
            return True
        while self.login_attempts < self.LOGIN_RETRY_LIMIT:
            self.login_attempts += 1
            self.logger.info(f"Login attempt {self.login_attempts}/{self.LOGIN_RETRY_LIMIT}")
            try:
                start_time = time.time()
                result = self._attempt_login()
                elapsed = time.time() - start_time
                self.perf_stats.record("login", elapsed)
                if result:
                    self._is_authenticated = True
                    self._auth_token_timestamp = time.time()
                    self.login_attempts = 0
                    return True
            except Exception as e:
                self.logger.error(f"Login error: {str(e)}")
            self.logger.warning(f"Login attempt {self.login_attempts} failed")
        self.logger.error(f"Login failed after {self.LOGIN_RETRY_LIMIT} attempts")
        return False

    def _attempt_login(self) -> bool:
        try:
            response = self.session.get(self.PLAYERS_URL, allow_redirects=False, timeout=self.TIMEOUT)
            if response.status_code == 200:
                self.logger.debug("Already logged in (direct access to PLAYERS_URL)")
                return True
            response = self.session.get(self.PLAYERS_URL, allow_redirects=True, timeout=self.TIMEOUT)
            response.raise_for_status()
            if response.url == self.PLAYERS_URL:
                self.logger.debug("Already logged in (direct access to PLAYERS_URL)")
                return True
            if self.ACCOUNT_URL not in response.url:
                self.logger.warning(f"Unexpected redirect URL: {response.url}")
                return False
            soup = BeautifulSoup(response.text, "lxml")
            token_input = soup.select_one("input[name='__RequestVerificationToken']")
            if not token_input:
                self.logger.error("Anti-forgery token not found")
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
            response = self.session.post(
                sso_login_url,
                data=payload,
                headers=headers,
                allow_redirects=True,
                timeout=self.TIMEOUT
            )
            response.raise_for_status()
            if f"{self.BASE_ADMIN_URL}/signin-oidc" in response.text:
                soup = BeautifulSoup(response.text, "lxml")
                form = soup.select_one("form")
                if not form:
                    self.logger.error("Redirect form not found")
                    return False
                redirect_action_url = form.get("action")
                inputs = form.select("input")
                form_data = {inp.get("name"): inp.get("value", "") for inp in inputs}
                response = self.session.post(
                    redirect_action_url,
                    data=form_data,
                    headers={"Referer": response.url},
                    allow_redirects=True,
                    timeout=self.TIMEOUT
                )
                response.raise_for_status()
                if "Logout" in response.text or "Players" in response.text:
                    self.logger.info("Successfully authenticated")
                    return True
                else:
                    self.logger.warning("Authentication failed - no logout or players links in response")
                    return False
            else:
                self.logger.warning("No signin-oidc found in response")
                return False
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Network error during login: {str(e)}")
            return False

    def _ensure_authenticated(self) -> bool:
        if not self._is_authenticated or (time.time() - self._auth_token_timestamp) >= self._auth_token_ttl:
            return self.login()
        return True

    def _parse_connection_row(self, row: Tag) -> Optional[ConnectionData]:
        try:
            cols = row.select("td")
            if len(cols) < 8:
                self.logger.warning(f"Too few columns in connection row: {len(cols)}")
                return None
            ban_hits_link = None
            connection_id = None
            if len(cols) >= 9:
                link_tag = cols[8].select_one("a")
                if link_tag:
                    ban_hits_link = urljoin(self.BASE_ADMIN_URL, link_tag["href"])
                    if ban_hits_link and "connection=" in ban_hits_link:
                        connection_id = ban_hits_link.split("connection=")[-1].split("&")[0]
            user_name_el = cols[0].select_one("strong")
            user_name = user_name_el.text.strip() if user_name_el else cols[0].text.strip()
            user_id = cols[1].text.strip()
            time_val = cols[2].text.strip()
            ip_address = cols[3].text.strip()
            hwid = cols[4].text.strip()
            status_el = cols[5].select_one("strong")
            status = status_el.text.strip() if status_el else cols[5].text.strip()
            server = cols[6].text.strip()
            trust_score = cols[7].text.strip()
            return ConnectionData(
                user_name=user_name,
                user_id=user_id,
                time=time_val,
                ip_address=ip_address,
                hwid=hwid,
                status=status,
                server=server,
                trust_score=trust_score,
                ban_hits_link=ban_hits_link,
                connection_id=connection_id,
                is_denied_banned=("Denied: Banned" in status)
            )
        except Exception as e:
            self.logger.error(f"Error parsing connection row: {str(e)}")
            return None

    def _parse_connections_table(self, soup: BeautifulSoup) -> List[ConnectionData]:
        connections = []
        table = soup.select_one("table.table")
        if not table:
            self.logger.warning("No table.table found in the HTML")
            return connections
        tbody = table.select_one("tbody")
        if not tbody:
            self.logger.warning("No tbody found in the table")
            return connections
        rows = tbody.select("tr")
        self.logger.debug(f"Found {len(rows)} rows in the connections table")
        connections = [conn for row in rows if (conn := self._parse_connection_row(row))]
        return connections

    def _get_next_page_link(self, soup: BeautifulSoup) -> Optional[str]:
        next_page_link = soup.select_one("a.page-link[rel='next']")
        if next_page_link:
            link = urljoin(self.BASE_ADMIN_URL, next_page_link["href"])
            return link
        next_page_link = soup.select_one("a.btn[href*='page=']")
        if next_page_link and "Next" in next_page_link.text and "disabled" not in next_page_link.get("class", []):
            link = urljoin(self.BASE_ADMIN_URL, next_page_link["href"])
            return link
        return None

    def _get_cached_response(self, url: str) -> Optional[str]:
        cache_entry = self._response_cache.get(url)
        if cache_entry:
            timestamp, html = cache_entry
            if time.time() - timestamp < 300:
                return html
        return None

    def _cache_response(self, url: str, html: str) -> None:
        if len(self._response_cache) > 1000:
            oldest_keys = sorted(self._response_cache.keys(),
                                 key=lambda k: self._response_cache[k][0])[:200]
            for key in oldest_keys:
                del self._response_cache[key]
        self._response_cache[url] = (time.time(), html)

    def fetch_paginated_data(self, url: str, max_pages: int = 0) -> List[ConnectionData]:
        self.logger.info(f"Fetching paginated data from URL: {url}")
        if not self._ensure_authenticated():
            self.logger.error("Not authenticated, cannot fetch data")
            return []
        all_connections = []
        current_url = url
        page_num = 1
        pages_fetched = 0
        start_time = time.time()
        while current_url:
            if max_pages > 0 and pages_fetched >= max_pages:
                self.logger.info(f"Reached max pages limit ({max_pages})")
                break
            try:
                self._request_metrics["total"] += 1
                req_start = time.time()
                self.logger.debug(f"Fetching page {page_num} from URL: {current_url}")
                cached_html = self._get_cached_response(current_url)
                if cached_html:
                    self.logger.debug(f"Using cached response for page {page_num}")
                    html_content = cached_html
                else:
                    response = self.session.get(current_url, timeout=self.TIMEOUT)
                    response.raise_for_status()
                    html_content = response.text
                    self._cache_response(current_url, html_content)
                req_time = time.time() - req_start
                if req_time > self.SLOW_REQUEST_THRESHOLD:
                    self._request_metrics["slow_requests"] += 1
                    log_url = current_url
                    if len(log_url) > 60:
                        log_url = log_url[:57] + "..."
                    self.perf_logger.debug(f"Slow request ({req_time:.2f}s): {log_url}")
                self.logger.debug(f"Page {page_num} response length: {len(html_content)}")
                soup = BeautifulSoup(html_content, "lxml")
                connections = self._parse_connections_table(soup)
                self.logger.debug(f"Found {len(connections)} connections on page {page_num}")
                all_connections.extend(connections)
                next_page_url = self._get_next_page_link(soup)
                if next_page_url:
                    current_url = next_page_url
                    page_num += 1
                    pages_fetched += 1
                else:
                    self.logger.debug(f"No more pages after page {page_num}")
                    current_url = None
            except requests.exceptions.RequestException as e:
                self._request_metrics["errors"] += 1
                self.logger.error(f"HTTP error on page {page_num}: {str(e)}")
                break
            except Exception as e:
                self._request_metrics["errors"] += 1
                self.logger.error(f"Error parsing page {page_num}: {str(e)}")
                break
        total_time = time.time() - start_time
        self.perf_stats.record("fetch_paginated_data", total_time)
        self.logger.info(
            f"Fetched {len(all_connections)} connections from {pages_fetched + 1} page(s) in {total_time:.2f}s")
        if self.perf_stats.should_log_summary():
            for line in self.perf_stats.get_summary():
                self.perf_logger.info(line)
        return all_connections

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
        self.logger.info(f"Fetching connections for user_id: {user_id}")
        start_time = time.time()
        connections = self.fetch_paginated_data(url)
        elapsed = time.time() - start_time
        self.perf_stats.record(f"fetch_connections", elapsed)
        connection_dicts = [conn.to_dict() for conn in connections]
        self.logger.debug(f"Found {len(connection_dicts)} connections for user_id: {user_id}")
        return connection_dicts

    def check_account_on_site(self, url: str, single_user: bool = False) -> Union[
        List[Dict[str, Any]], Dict[str, Union[str, List[str], bool, int]]]:
        self.logger.info(f"Checking account on site: url={url}, single_user={single_user}")
        start_time = time.time()
        connections = self.fetch_paginated_data(url)
        elapsed = time.time() - start_time
        self.perf_stats.record("check_account", elapsed)
        self.logger.info(f"Found {len(connections)} connections for URL: {url}")
        if single_user:
            self.logger.debug("Aggregating single user info")
            result = self.aggregate_single_user_info(connections)
            self.logger.info(f"Aggregated result for single user, status: {result.get('status', 'unknown')}")
            essential_keys = ['status', 'nicknames', 'associated_ips', 'associated_hwids', 'user_id']
            missing_keys = [k for k in essential_keys if k not in result]
            if missing_keys:
                self.logger.warning(f"Missing essential keys in aggregated result: {missing_keys}")
            return result
        connection_dicts = [conn.to_dict() for conn in connections]
        self.logger.debug(f"Returning {len(connection_dicts)} connection dicts")
        return connection_dicts

    @lru_cache(maxsize=500)
    def fetch_player_info(self, user_id: str) -> Dict[str, Union[int, List[Dict[str, str]]]]:
        if not self._ensure_authenticated():
            return {"ban_counts": 0, "ban_reasons": []}
        info_result = {"ban_counts": 0, "ban_reasons": []}
        info_url = self.PLAYER_INFO_URL_PATTERN.format(user_id)
        try:
            start_time = time.time()
            cached_html = self._get_cached_response(info_url)
            if cached_html:
                html_content = cached_html
            else:
                resp = self.session.get(info_url, timeout=self.TIMEOUT)
                resp.raise_for_status()
                html_content = resp.text
                self._cache_response(info_url, html_content)
            soup = BeautifulSoup(html_content, "lxml")

            player_name = "Unknown"
            name_header = soup.select_one("h1")
            if name_header:
                name_text = name_header.get_text(strip=True)
                if "information for" in name_text.lower():
                    player_name = name_text.split("information for")[-1].strip()

            ban_table = soup.select_one("h2:contains('Bans') + table, h2:contains('Bans') ~ table")
            if ban_table:
                ban_body = ban_table.select_one("tbody")
                if ban_body:
                    ban_info = []
                    rows = ban_body.select("tr")
                    for row in rows:
                        cols = row.select("td")
                        if cols and len(cols) >= 2:
                            ban_reason = cols[1].get_text(strip=True)
                            ban_username = player_name
                            name_col = cols[0].select_one("strong")
                            if name_col:
                                ban_username = name_col.get_text(strip=True)

                            ban_info.append({
                                "reason": ban_reason,
                                "username": ban_username
                            })

                    info_result["ban_reasons"] = ban_info
                    info_result["ban_counts"] = len(ban_info)
            elapsed = time.time() - start_time
            self.perf_stats.record("fetch_player_info", elapsed)
            if elapsed > self.SLOW_REQUEST_THRESHOLD:
                self.perf_logger.debug(f"Slow player info fetch: {elapsed:.2f}s for user {user_id}")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.logger.debug(f"Player profile not found: {user_id}")
            else:
                self._request_metrics["errors"] += 1
                self.logger.error(f"HTTP error for {user_id}: {str(e)}")
        except requests.exceptions.RequestException as e:
            self._request_metrics["errors"] += 1
            self.logger.error(f"Request error for {user_id}: {str(e)}")
        return info_result

    def aggregate_single_user_info(self, connections: List[Union[ConnectionData, Dict[str, Any]]]) -> Dict[
        str, Union[str, List[str], bool, int]]:
        self.logger.info(f"Aggregating user info from {len(connections)} connections")
        if not connections:
            self.logger.warning("No connections provided to aggregate_single_user_info")
            empty_result = {
                "status": "unknown",
                "nicknames": [],
                "raw_html_snippet": [],
                "ban_counts": 0,
                "ban_reasons": [],
                "shared_hwid_nicknames": [],
                "associated_ips": {},
                "associated_hwids": {},
                "user_id": "N/A",
                "connection_link": "N/A",
                "denied_banned_connections": []
            }
            return empty_result
        result: Dict[str, Any] = {
            "status": "unknown",
            "nicknames": set(),
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
        all_user_ids = set()
        all_nicknames = set()
        all_statuses = set()
        for connection in connections:
            if isinstance(connection, ConnectionData):
                nickname = connection.user_name
                ip_address = connection.ip_address
                hwid = connection.hwid
                status = connection.status
                user_id = connection.user_id
                time_val = connection.time
                server = connection.server
                is_denied_banned = connection.is_denied_banned
                connection_id = connection_id or connection.connection_id
            else:
                nickname = connection.get("user_name", "")
                ip_address = connection.get("ip_address", "")
                hwid = connection.get("hwid", "")
                status = connection.get("status", "")
                user_id = connection.get("user_id", "")
                time_val = connection.get("time", "")
                server = connection.get("server", "")
                is_denied_banned = "Denied: Banned" in status
                connection_id = connection_id or connection.get("connection_id", "")
            if user_id:
                all_user_ids.add(user_id)
            if nickname:
                all_nicknames.add(nickname)
            if status:
                all_statuses.add(status)
            if user_id and user_id != "N/A" and result["user_id"] == "N/A":
                result["user_id"] = user_id
            if nickname:
                result["nicknames"].add(nickname)
            if ip_address and ip_address != N_A:
                if ip_address not in all_ips:
                    all_ips[ip_address] = set()
                if nickname:
                    all_ips[ip_address].add(nickname)
            if hwid and hwid != N_A:
                if hwid not in all_hwids:
                    all_hwids[hwid] = set()
                if nickname:
                    all_hwids[hwid].add(nickname)
            if status:
                if "Accepted" in status:
                    result["status"] = "clean"
                if is_denied_banned:
                    denied_banned_found = True
                    result["denied_banned_connections"].append({
                        "user_name": nickname,
                        "time": time_val,
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
            self.logger.debug("Set status to 'banned' due to denied_banned connections")
        elif banned_found:
            result["status"] = "banned"
            self.logger.debug("Set status to 'banned' due to banned connections")
        if connection_id:
            result["connection_link"] = f"{self.BASE_ADMIN_URL}/Connections/Info/{connection_id}"
        user_id = result["user_id"]
        if user_id and user_id != "N/A" and not denied_banned_found:
            try:
                player_info = self.fetch_player_info(user_id)
                result["ban_counts"] = player_info.get("ban_counts", 0)

                ban_reasons_info = player_info.get("ban_reasons", [])
                for ban_info in ban_reasons_info:
                    reason_tuple = (ban_info["reason"], ban_info["username"])
                    result["ban_reasons"].add(reason_tuple)

            except Exception as e:
                self.logger.error(f"Error fetching player info for {user_id}: {str(e)}")
        result["associated_ips"] = {ip: list(nicks) for ip, nicks in all_ips.items()} if all_ips else {}
        result["associated_hwids"] = {hwid: list(nicks) for hwid, nicks in all_hwids.items()} if all_hwids else {}
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
        result["nicknames"] = list(result["nicknames"]) if result["nicknames"] else []

        result["ban_reasons"] = [{"reason": reason, "username": username}
                                 for reason, username in result["ban_reasons"]]

        result["shared_hwid_nicknames"] = list(result["shared_hwid_nicknames"]) if result[
            "shared_hwid_nicknames"] else []
        for key in ['associated_ips', 'associated_hwids']:
            if key not in result or result[key] is None:
                result[key] = {}
        if 'nicknames' not in result or result['nicknames'] is None:
            result['nicknames'] = []
        if 'ban_reasons' not in result or result['ban_reasons'] is None:
            result['ban_reasons'] = []
        if 'shared_hwid_nicknames' not in result or result['shared_hwid_nicknames'] is None:
            result['shared_hwid_nicknames'] = []
        self.logger.info(
            f"Aggregation complete: status={result['status']}, user_id={result['user_id']}, nicknames count={len(result['nicknames'])}")
        return result

    def _merge_statuses(self, status_a: str, status_b: str) -> str:
        priority = {"suspicious": 4, "banned": 3, "unknown": 2, "clean": 1}
        return status_a if priority.get(status_a, 2) > priority.get(status_b, 2) else status_b

    def fetch_ban_hit_connections(self, max_pages: int = 0) -> List[Dict[str, str]]:
        url = f"{self.CONNECTIONS_URL}?showSet=true&search=&showBanned=true"
        self.logger.info(f"Fetching ban hit connections, max_pages={max_pages}")
        connections = self.fetch_paginated_data(url, max_pages=max_pages)
        ban_hit_connections = [
            conn.to_dict() for conn in connections
            if "Denied: Banned" in conn.status and conn.ban_hits_link
        ]
        self.logger.info(f"Found {len(ban_hit_connections)} ban hit connections")
        return ban_hit_connections

    def fetch_ban_info(self, ban_hits_link: str) -> Dict[str, str]:
        if not ban_hits_link:
            return {}
        if not self._ensure_authenticated():
            return {}
        ban_info = {}
        try:
            cached_html = self._get_cached_response(ban_hits_link)
            if cached_html:
                html_content = cached_html
            else:
                response = self.session.get(ban_hits_link, timeout=self.TIMEOUT)
                response.raise_for_status()
                html_content = response.text
                self._cache_response(ban_hits_link, html_content)
            soup = BeautifulSoup(html_content, 'lxml')
            dl = soup.find("dl")
            if dl:
                dt_tags = dl.find_all("dt")
                dd_tags = dl.find_all("dd")
                info = {dt.get_text(strip=True).rstrip(":"): dd.get_text(strip=True)
                        for dt, dd in zip(dt_tags, dd_tags)}
                ban_info.update({
                    "banned_user_name": info.get("Name", ""),
                    "user_id": info.get("User ID", ""),
                    "ip_address": info.get("IP", ""),
                    "hwid": info.get("HWID", ""),
                    "time": info.get("Time", ""),
                })
            table = soup.find("table", class_="table")
            if table:
                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) >= 6:
                        ban_info["ban_time"] = cols[2].get_text(strip=True)
                        ban_info["expires"] = cols[4].get_text(strip=True)
                        break
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error fetching ban info from {ban_hits_link}: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing ban info from {ban_hits_link}: {e}", exc_info=True)
        return ban_info
