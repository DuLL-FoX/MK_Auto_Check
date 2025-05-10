import logging
import time
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Union, List, Any, Optional, Tuple
from urllib.parse import urljoin, quote_plus
import threading
from collections import OrderedDict

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
        self._response_cache: OrderedDict[str, Tuple[float, str]] = OrderedDict()
        self._RESPONSE_CACHE_MAX_SIZE = 1000
        self._RESPONSE_CACHE_TTL = 300
        self._thread_lock = threading.RLock()
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
        with self._thread_lock:
            if self._is_authenticated and (time.time() - self._auth_token_timestamp) < self._auth_token_ttl:
                return True


            current_attempts = 0
            while current_attempts < self.LOGIN_RETRY_LIMIT:
                current_attempts += 1
                self.login_attempts = current_attempts
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
                if link_tag and link_tag.has_attr("href"):
                    raw_link = link_tag["href"]
                    if raw_link and raw_link.strip() != "#":
                        potential_ban_hits_link = urljoin(self.BASE_ADMIN_URL, raw_link)
                        if "connection=" in potential_ban_hits_link:
                            ban_hits_link = potential_ban_hits_link
                            try:
                                connection_id_part = ban_hits_link.split("connection=")[1]
                                connection_id = connection_id_part.split("&")[0]
                            except IndexError:
                                self.logger.warning(
                                    f"Could not parse connection_id from ban_hits_link: {ban_hits_link}")
                                connection_id = None

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
            self.logger.error(f"Error parsing connection row: {str(e)}", exc_info=True)
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

        is_search_page_context = False
        form_element = soup.select_one("form[action*='search='], form input[name='search']")
        if form_element:
            is_search_page_context = True

        if not rows and is_search_page_context:

            self.logger.info(
                f"Found 0 <tr> rows in <tbody> on what appears to be a search results page. "
                f"This likely means the search yielded no matching connections. "
                f"HTML length: {len(soup.prettify())}. Tbody content snippet: {tbody.prettify()[:500]}"
            )

        self.logger.debug(f"Found {len(rows)} rows in the connections table to process.")
        for row_idx, row in enumerate(rows):
            conn = self._parse_connection_row(row)
            if conn:
                connections.append(conn)
            else:
                self.logger.warning(
                    f"Failed to parse connection data from row {row_idx}. Row content snippet: {row.prettify()[:300]}")
        return connections

    def _get_next_page_link(self, soup: BeautifulSoup) -> Optional[str]:
        next_page_link_tag = soup.select_one("a.page-link[rel='next']")
        if next_page_link_tag and next_page_link_tag.has_attr('href'):
            href = next_page_link_tag['href']
            if href and href.strip() != '#':
                return urljoin(self.BASE_ADMIN_URL, href)

        potential_next_buttons = soup.select("a.btn")
        for btn_link_tag in potential_next_buttons:
            if "Next" not in btn_link_tag.get_text():
                continue

            if "disabled" in btn_link_tag.get("class", []):
                continue

            if not btn_link_tag.has_attr("href"):
                continue

            href_value = btn_link_tag["href"]
            if not href_value or href_value.strip() == "#":
                continue

            href_lower = href_value.lower()
            if "page=" in href_lower or "pageindex=" in href_lower:
                return urljoin(self.BASE_ADMIN_URL, href_value)

        return None

    def _get_cached_response(self, url: str) -> Optional[str]:
        cache_entry = self._response_cache.get(url)
        if cache_entry:
            timestamp, html = cache_entry
            if time.time() - timestamp < self._RESPONSE_CACHE_TTL:
                self._response_cache.move_to_end(url)
                return html
            else:
                del self._response_cache[url]
        return None

    def _cache_response(self, url: str, html: str) -> None:
        self._response_cache[url] = (time.time(), html)
        self._response_cache.move_to_end(url)

        while len(self._response_cache) > self._RESPONSE_CACHE_MAX_SIZE:
            self._response_cache.popitem(last=False)

    def fetch_paginated_data(self, url: str, max_pages: int = 0) -> List[ConnectionData]:
        with self._thread_lock:
            self.logger.info(
                f"Fetching paginated data from URL: {url}, max_pages={max_pages if max_pages > 0 else 'unlimited'}")
            if not self._ensure_authenticated():
                self.logger.error("Not authenticated, cannot fetch data")
                return []

            all_connections: List[ConnectionData] = []
            current_url: Optional[str] = url
            page_num = 1
            pages_fetched = 0

            start_time_total = time.time()
            while current_url:
                if max_pages > 0 and pages_fetched >= max_pages:
                    self.logger.info(f"Reached max pages limit ({max_pages}) after fetching {pages_fetched} pages.")
                    break

                self.logger.debug(f"Fetching page {page_num} from URL: {current_url}")

                try:
                    self._request_metrics["total"] += 1
                    req_start_time = time.time()

                    html_content: Optional[str] = self._get_cached_response(current_url)
                    if html_content:
                        self.logger.debug(f"Using cached response for page {page_num} URL: {current_url}")
                    else:
                        self.logger.debug(f"Cache miss for page {page_num} URL: {current_url}. Fetching live.")
                        response = self.session.get(current_url, timeout=self.TIMEOUT)
                        response.raise_for_status()
                        html_content = response.text
                        self._cache_response(current_url, html_content)

                    req_elapsed_time = time.time() - req_start_time
                    if req_elapsed_time > self.SLOW_REQUEST_THRESHOLD:
                        self._request_metrics["slow_requests"] += 1
                        log_url_display = current_url if len(current_url) <= 70 else current_url[:67] + "..."
                        self.perf_logger.debug(f"Slow request ({req_elapsed_time:.2f}s): {log_url_display}")

                    if not html_content:
                        self.logger.error(f"Failed to get HTML content for page {page_num} URL: {current_url}")
                        break

                    self.logger.debug(f"Page {page_num} response length: {len(html_content)}. Parsing...")
                    soup = BeautifulSoup(html_content, "lxml")

                    connections_on_page = self._parse_connections_table(soup)
                    self.logger.debug(f"Found {len(connections_on_page)} connections on page {page_num}")
                    all_connections.extend(connections_on_page)

                    pages_fetched += 1

                    current_url = self._get_next_page_link(soup)
                    if current_url:
                        self.logger.debug(f"Next page link found: {current_url}")
                        page_num += 1
                    else:
                        self.logger.debug(f"No more pages found after page {page_num - 1 if page_num > 1 else 1}.")
                        break

                except requests.exceptions.HTTPError as e:
                    self._request_metrics["errors"] += 1
                    self.logger.error(f"HTTP error on page {page_num} for URL {current_url}: {str(e)}")
                    if e.response.status_code == 401 or e.response.status_code == 403:
                        self.logger.warning(
                            "Authentication may have expired. Attempting re-login on next _ensure_authenticated call.")
                        self._is_authenticated = False
                    break
                except requests.exceptions.RequestException as e:
                    self._request_metrics["errors"] += 1
                    self.logger.error(f"Request error on page {page_num} for URL {current_url}: {str(e)}")
                    break
                except Exception as e:
                    self._request_metrics["errors"] += 1
                    self.logger.error(f"Error processing page {page_num} for URL {current_url}: {str(e)}",
                                      exc_info=True)
                    break

            total_elapsed_time = time.time() - start_time_total
            self.perf_stats.record("fetch_paginated_data", total_elapsed_time)
            self.logger.info(
                f"Fetched {len(all_connections)} connections from {pages_fetched} page(s) in {total_elapsed_time:.2f}s"
            )

            if self.perf_stats.should_log_summary():
                for line in self.perf_stats.get_summary():
                    self.perf_logger.info(line)
            return all_connections

    def get_connections_url(self, user_id: str = "", search: str = "", show_accepted: str = "true",
                            show_banned: str = "true", show_whitelist: str = "true", show_full: str = "true",
                            show_panic: str = "true") -> str:
        search_term = quote_plus(user_id if user_id else search)
        url = (f"{self.BASE_ADMIN_URL}/Connections?perPage=1000&showSet=true"
               f"&search={search_term}&showAccepted={show_accepted}&showBanned={show_banned}"
               f"&showWhitelist={show_whitelist}&showFull={show_full}&showPanic={show_panic}")
        return url

    def fetch_connections_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        url = self.get_connections_url(user_id=user_id)
        self.logger.info(f"Fetching connections for user_id: {user_id} from URL: {url}")
        start_time = time.time()
        connections = self.fetch_paginated_data(url)
        elapsed = time.time() - start_time
        self.perf_stats.record(f"fetch_connections_for_user", elapsed)
        connection_dicts = [conn.to_dict() for conn in connections]
        self.logger.debug(f"Found {len(connection_dicts)} connections for user_id: {user_id}")
        return connection_dicts

    def check_account_on_site(self, url: str, single_user: bool = False) -> Union[
        List[Dict[str, Any]], Dict[str, Union[str, List[str], bool, int]]]:
        self.logger.info(f"Checking account on site: url={url}, single_user={single_user}")
        start_time = time.time()
        connections_data = self.fetch_paginated_data(url)
        elapsed = time.time() - start_time
        self.perf_stats.record("check_account_on_site", elapsed)
        self.logger.info(f"Found {len(connections_data)} connections for URL: {url}")

        if single_user:
            self.logger.debug("Aggregating single user info from connections data.")
            result = self.aggregate_single_user_info(
                connections_data)
            self.logger.info(f"Aggregated result for single user, status: {result.get('status', 'unknown')}")
            essential_keys = ['status', 'nicknames', 'associated_ips', 'associated_hwids', 'user_id']
            missing_keys = [k for k in essential_keys if k not in result or result[k] is None]
            if missing_keys:
                self.logger.warning(
                    f"Missing or None essential keys in aggregated result: {missing_keys} for URL {url}")
            return result

        connection_dicts = [conn.to_dict() for conn in connections_data]
        self.logger.debug(f"Returning {len(connection_dicts)} raw connection dicts.")
        return connection_dicts

    @lru_cache(maxsize=500)
    def fetch_player_info(self, user_id: str) -> Dict[str, Union[int, List[Dict[str, str]]]]:
        with self._thread_lock:
            if not self._ensure_authenticated():
                self.logger.warning(f"Not authenticated, cannot fetch player info for {user_id}")
                return {"ban_counts": 0, "ban_reasons": []}

            info_result: Dict[str, Union[int, List[Dict[str, str]]]] = {"ban_counts": 0, "ban_reasons": []}
            info_url = self.PLAYER_INFO_URL_PATTERN.format(user_id)
            self.logger.debug(f"Fetching player info from URL: {info_url}")

            start_time = time.time()
            try:
                html_content: Optional[str] = self._get_cached_response(info_url)
                if html_content:
                    self.logger.debug(f"Using cached response for player info: {user_id}")
                else:
                    self.logger.debug(f"Cache miss for player info: {user_id}. Fetching live.")
                    self._request_metrics["total"] += 1
                    resp = self.session.get(info_url, timeout=self.TIMEOUT)
                    resp.raise_for_status()
                    html_content = resp.text
                    self._cache_response(info_url, html_content)

                if not html_content:
                    self.logger.error(f"Failed to get HTML content for player info: {user_id}")
                    return info_result

                soup = BeautifulSoup(html_content, "lxml")

                player_name = "Unknown"
                name_header = soup.select_one("h1")
                if name_header:
                    name_text = name_header.get_text(strip=True)
                    if "information for" in name_text.lower():
                        player_name = name_text.lower().split("information for", 1)[-1].strip()
                        original_case_name_part = name_text.split("information for ", 1)
                        if len(original_case_name_part) > 1:
                            player_name = original_case_name_part[1].strip()
                        else:
                            player_name = name_text.split("information for", 1)[-1].strip()

                bans_header = soup.find("h2", string=lambda t: t and "Bans" in t and "Role Bans" not in t)
                ban_table = None
                if bans_header:
                    ban_table = bans_header.find_next_sibling("table", class_="table")

                if ban_table:
                    ban_body = ban_table.select_one("tbody")
                    if ban_body:
                        ban_info_list: List[Dict[str, str]] = []
                        rows = ban_body.select("tr")
                        for row_idx, row in enumerate(rows):
                            cols = row.select("td")
                            if cols and len(cols) >= 2:
                                ban_reason = cols[1].get_text(strip=True)

                                banned_username_for_entry = player_name
                                name_cell_content = cols[0].select_one("strong")
                                if name_cell_content:
                                    banned_username_for_entry = name_cell_content.get_text(strip=True)
                                elif cols[0].get_text(strip=True) and cols[0].get_text(
                                        strip=True).lower() != player_name.lower():
                                    potential_name = cols[0].get_text(strip=True)
                                    if not any(x in potential_name for x in ["N/A", "User ID", "IP", "HWID"]):
                                        banned_username_for_entry = potential_name

                                ban_info_list.append({
                                    "reason": ban_reason,
                                    "username": banned_username_for_entry
                                })
                            else:
                                self.logger.warning(
                                    f"Ban table row {row_idx} for {user_id} has < 2 columns: {row.prettify()[:200]}")

                        info_result["ban_reasons"] = ban_info_list
                        info_result["ban_counts"] = len(ban_info_list)
                else:
                    self.logger.debug(f"No bans table found for player {user_id} on their info page.")

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    self.logger.debug(f"Player profile not found (404) for user_id: {user_id} at {info_url}")
                else:
                    self._request_metrics["errors"] += 1
                    self.logger.error(f"HTTP error fetching player info for {user_id} from {info_url}: {str(e)}")
            except requests.exceptions.RequestException as e:
                self._request_metrics["errors"] += 1
                self.logger.error(f"Request error fetching player info for {user_id} from {info_url}: {str(e)}")
            except Exception as e:
                self._request_metrics["errors"] += 1
                self.logger.error(f"Error parsing player info for {user_id} from {info_url}: {str(e)}", exc_info=True)

            elapsed_time = time.time() - start_time
            self.perf_stats.record("fetch_player_info", elapsed_time)
            if elapsed_time > self.SLOW_REQUEST_THRESHOLD:
                self.perf_logger.debug(f"Slow player info fetch: {elapsed_time:.2f}s for user {user_id}")

            return info_result

    def aggregate_single_user_info(self, connections: List[Union[ConnectionData, Dict[str, Any]]]) -> Dict[
        str, Union[str, List[str], bool, int]]:
        self.logger.info(f"Aggregating user info from {len(connections)} connections")

        result: Dict[str, Any] = {
            "status": "unknown",
            "nicknames": set(),
            "ban_counts": 0,
            "ban_reasons": set(),
            "shared_hwid_nicknames": set(),
            "associated_ips": {},
            "associated_hwids": {},
            "user_id": N_A,
            "connection_link": N_A,
            "denied_banned_connections": []
        }

        if not connections:
            self.logger.warning("No connections provided to aggregate_single_user_info. Returning empty aggregation.")
            result["nicknames"] = []
            result["ban_reasons"] = []
            result["shared_hwid_nicknames"] = []
            return result

        all_ips: Dict[str, set] = {}
        all_hwids: Dict[str, set] = {}

        banned_status_found_in_connections = False
        denied_banned_status_found_in_connections = False

        first_valid_connection_id: Optional[str] = None

        for conn_data in connections:
            if isinstance(conn_data, ConnectionData):
                nickname = conn_data.user_name
                ip_address = conn_data.ip_address
                hwid = conn_data.hwid
                status_text = conn_data.status
                current_user_id = conn_data.user_id
                time_val = conn_data.time
                server = conn_data.server
                current_connection_id = conn_data.connection_id
                is_denied_banned_flag = conn_data.is_denied_banned
            elif isinstance(conn_data, dict):
                nickname = conn_data.get("user_name", "")
                ip_address = conn_data.get("ip_address", "")
                hwid = conn_data.get("hwid", "")
                status_text = conn_data.get("status", "")
                current_user_id = conn_data.get("user_id", "")
                time_val = conn_data.get("time", "")
                server = conn_data.get("server", "")
                current_connection_id = conn_data.get("connection_id")
                is_denied_banned_flag = "Denied: Banned" in status_text
            else:
                self.logger.warning(f"Unexpected connection data type: {type(conn_data)}")
                continue

            if current_user_id and current_user_id != N_A and result["user_id"] == N_A:
                result["user_id"] = current_user_id

            if not first_valid_connection_id and current_connection_id:
                first_valid_connection_id = current_connection_id

            if nickname:
                result["nicknames"].add(nickname)

            if ip_address and ip_address != N_A:
                all_ips.setdefault(ip_address, set()).add(nickname)

            if hwid and hwid != N_A:
                all_hwids.setdefault(hwid, set()).add(nickname)

            if status_text:
                if "Accepted" in status_text and result[
                    "status"] == "unknown":
                    result["status"] = "clean"

                if is_denied_banned_flag:
                    denied_banned_status_found_in_connections = True
                    result["denied_banned_connections"].append({
                        "user_name": nickname, "time": time_val, "ip_address": ip_address,
                        "hwid": hwid, "server": server, "status": status_text
                    })
                elif "Banned" in status_text:
                    banned_status_found_in_connections = True

        if denied_banned_status_found_in_connections:
            result["status"] = "banned"
            result["ban_counts"] = max(result["ban_counts"], 1)
            self.logger.debug("Status set to 'banned' due to 'Denied: Banned' connections.")
        elif banned_status_found_in_connections and result["status"] != "banned":
            result["status"] = "banned"
            self.logger.debug("Status set to 'banned' due to 'Banned' status in connections.")

        if first_valid_connection_id:
            result["connection_link"] = f"{self.BASE_ADMIN_URL}/Connections/Info/{first_valid_connection_id}"

        final_user_id_for_fetch = result["user_id"]
        if final_user_id_for_fetch and final_user_id_for_fetch != N_A:
            self.logger.debug(f"Fetching player-specific ban info for user_id: {final_user_id_for_fetch}")
            player_page_info = self.fetch_player_info(final_user_id_for_fetch)

            result["ban_counts"] = max(result["ban_counts"], player_page_info.get("ban_counts", 0))

            for ban_entry in player_page_info.get("ban_reasons", []):
                if isinstance(ban_entry, dict) and "reason" in ban_entry and "username" in ban_entry:
                    result["ban_reasons"].add((ban_entry["reason"], ban_entry["username"]))
                else:
                    self.logger.warning(f"Malformed ban entry from fetch_player_info: {ban_entry}")

        result["associated_ips"] = {ip: list(nicks) for ip, nicks in all_ips.items()}
        result["associated_hwids"] = {hwid: list(nicks) for hwid, nicks in all_hwids.items()}

        for hwid, nicks_set in all_hwids.items():
            if len(nicks_set) > 1 and hwid != N_A:
                result["shared_hwid_nicknames"].update(nicks_set)

        if result["ban_counts"] > 0:
            if result["status"] != "banned":
                if result["ban_counts"] >= 5:
                    result["status"] = "suspicious"
                else:
                    result["status"] = "banned"
            elif result["status"] == "banned" and result["ban_counts"] >= 5:
                result["status"] = "suspicious"

        result["nicknames"] = sorted(list(result["nicknames"]))
        result["ban_reasons"] = [{"reason": r, "username": u} for r, u in
                                 sorted(list(result["ban_reasons"]))]
        result["shared_hwid_nicknames"] = sorted(list(result["shared_hwid_nicknames"]))

        result["raw_html_snippet"] = []
        for conn_preview in connections[:100]:
            if isinstance(conn_preview, ConnectionData):
                result["raw_html_snippet"].append({"time": conn_preview.time, "status": conn_preview.status})
            elif isinstance(conn_preview, dict):
                result["raw_html_snippet"].append(
                    {"time": conn_preview.get("time", ""), "status": conn_preview.get("status", "")})

        self.logger.info(
            f"Aggregation complete for user_id '{result['user_id']}': status={result['status']}, "
            f"nicknames_count={len(result['nicknames'])}, ban_counts={result['ban_counts']}"
        )
        return result

    def _merge_statuses(self, status_a: str, status_b: str) -> str:
        priority = {"suspicious": 4, "banned": 3, "unknown": 2, "clean": 1}
        return status_a if priority.get(status_a.lower(), 2) > priority.get(status_b.lower(), 2) else status_b

    def fetch_ban_hit_connections(self, max_pages: int = 0) -> List[Dict[str, str]]:
        url = f"{self.CONNECTIONS_URL}?showSet=true&search=&showBanned=true&perPage=1000"
        self.logger.info(f"Fetching ban hit connections, max_pages={max_pages if max_pages > 0 else 'unlimited'}")

        connections_data = self.fetch_paginated_data(url, max_pages=max_pages)

        ban_hit_connections_list = [
            conn.to_dict() for conn in connections_data
            if conn.is_denied_banned and conn.ban_hits_link
        ]
        self.logger.info(
            f"Found {len(ban_hit_connections_list)} connections with 'Denied: Banned' status and a ban_hits_link.")
        return ban_hit_connections_list

    def fetch_ban_info(self, ban_hits_link: str) -> Dict[str, str]:
        with self._thread_lock:
            if not ban_hits_link:
                self.logger.warning("fetch_ban_info called with empty ban_hits_link.")
                return {}
            if not self._ensure_authenticated():
                self.logger.warning(f"Not authenticated, cannot fetch ban info from {ban_hits_link}")
                return {}

            ban_info_dict: Dict[str, str] = {}
            self.logger.debug(f"Fetching ban info from URL: {ban_hits_link}")

            start_time = time.time()
            try:
                html_content: Optional[str] = self._get_cached_response(ban_hits_link)
                if html_content:
                    self.logger.debug(f"Using cached response for ban info: {ban_hits_link}")
                else:
                    self.logger.debug(f"Cache miss for ban info: {ban_hits_link}. Fetching live.")
                    self._request_metrics["total"] += 1
                    response = self.session.get(ban_hits_link, timeout=self.TIMEOUT)
                    response.raise_for_status()
                    html_content = response.text
                    self._cache_response(ban_hits_link, html_content)

                if not html_content:
                    self.logger.error(f"Failed to get HTML content for ban info: {ban_hits_link}")
                    return ban_info_dict

                soup = BeautifulSoup(html_content, 'lxml')

                dl_element = soup.select_one("dl.row, dl")
                if dl_element:
                    dt_tags = dl_element.find_all("dt")
                    dd_tags = dl_element.find_all("dd")

                    info_from_dl = {
                        dt.get_text(strip=True).rstrip(":").lower().replace(" ", "_"): dd.get_text(strip=True)
                        for dt, dd in zip(dt_tags, dd_tags)
                    }

                    ban_info_dict["banned_user_name"] = info_from_dl.get("name", "")
                    ban_info_dict["user_id"] = info_from_dl.get("user_id", "")
                    if not ban_info_dict["user_id"]:
                        ban_info_dict["user_id"] = info_from_dl.get("user id", "")
                    ban_info_dict["ip_address"] = info_from_dl.get("ip", "")
                    ban_info_dict["hwid"] = info_from_dl.get("hwid", "")
                    ban_info_dict["time"] = info_from_dl.get("time", "")

                table_element = soup.find("table", class_="table")
                if table_element:
                    table_body = table_element.select_one("tbody")
                    rows = table_body.select("tr") if table_body else table_element.select("tr")

                    for row in rows:
                        cols = row.find_all("td")
                        if len(cols) >= 6:
                            ban_info_dict["ban_time"] = cols[2].get_text(strip=True)
                            ban_info_dict["expires"] = cols[4].get_text(strip=True)
                            break

                if not ban_info_dict:
                    self.logger.warning(
                        f"Could not parse detailed ban info from {ban_hits_link}. Page structure might have changed or info not present.")

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    self.logger.warning(f"Ban hits link not found (404): {ban_hits_link}")
                else:
                    self._request_metrics["errors"] += 1
                    self.logger.error(f"HTTP error fetching ban info from {ban_hits_link}: {e}")
            except requests.exceptions.RequestException as e:
                self._request_metrics["errors"] += 1
                self.logger.error(f"Request error fetching ban info from {ban_hits_link}: {e}")
            except Exception as e:
                self._request_metrics["errors"] += 1
                self.logger.error(f"Error parsing ban info from {ban_hits_link}: {e}", exc_info=True)

            elapsed_time = time.time() - start_time
            self.perf_stats.record("fetch_ban_info", elapsed_time)
            if elapsed_time > self.SLOW_REQUEST_THRESHOLD:
                self.perf_logger.debug(f"Slow ban info fetch: {elapsed_time:.2f}s for link: {ban_hits_link}")

            return ban_info_dict