import asyncio
import logging
import time
from dataclasses import dataclass
from typing import Dict, Union, List, Any, Optional, Tuple, OrderedDict
from urllib.parse import urljoin, quote_plus

import aiohttp
from selectolax.parser import HTMLParser, Node

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
            "connection_id": self.connection_id,
            "is_denied_banned": self.is_denied_banned
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
        self.TIMEOUT = aiohttp.ClientTimeout(total=cfg.api.request_timeout)
        self.SLOW_REQUEST_THRESHOLD = 5.0
        
        self._connector = aiohttp.TCPConnector(limit_per_host=50, limit=150, ssl=False)
        self._client_session: Optional[aiohttp.ClientSession] = None
        
        self.login_attempts = 0
        self._is_authenticated = False
        self._auth_token_timestamp = 0
        self._auth_token_ttl = 1800
        self._request_metrics = {"total": 0, "slow_requests": 0, "errors": 0}
        self._setup_loggers()
        self.perf_stats = PerformanceStats(self.perf_logger)
        
        self._response_cache: OrderedDict[str, Tuple[float, str]] = OrderedDict()
        self._RESPONSE_CACHE_MAX_SIZE = 1000
        self._RESPONSE_CACHE_TTL = 1800

        self._async_lock = asyncio.Lock()
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                f"AdminPanel (async) initialized with URLs: BASE={self.BASE_ADMIN_URL}, CONNECTIONS={self.CONNECTIONS_URL}")

    async def _initialise(self):
        await self.close()

        self._connector = aiohttp.TCPConnector(limit_per_host=8, limit=10, ssl=False)
        self._client_session: Optional[aiohttp.ClientSession] = None

        self.login_attempts = 0
        self._is_authenticated = False
        self._request_metrics = {
            "total": 0,
            "cache_hits": 0,
            "cache_misses": 0,
        }
        self._response_cache: OrderedDict[str, Tuple[str, float]] = OrderedDict()

    def _setup_loggers(self):
        from utils.logging_utils import get_logger
        self.perf_logger = get_logger(f"{__name__}.performance")

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._client_session is None or self._client_session.closed:
            self._client_session = aiohttp.ClientSession(
                connector=self._connector,
                timeout=self.TIMEOUT,
                headers={
                    "User-Agent": "Mozilla/5.0 (compatible; MyAppBot/1.0)",
                    "Connection": "keep-alive"
                },
                cookie_jar=aiohttp.CookieJar(unsafe=True)
            )
        return self._client_session

    async def close(self):
        if self._client_session and not self._client_session.closed:
            await self._client_session.close()
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Aiohttp client session closed.")
        
        if self._connector and not self._connector.closed:
            await self._connector.close()
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Aiohttp TCPConnector closed.")
        
        self._client_session = None

    async def login(self) -> bool:
        async with self._async_lock:
            if self._is_authenticated and (time.time() - self._auth_token_timestamp) < self._auth_token_ttl:
                return True

            session = await self._get_session()
            current_attempts = 0
            while current_attempts < self.LOGIN_RETRY_LIMIT:
                current_attempts += 1
                self.login_attempts = current_attempts
                if self.logger.isEnabledFor(logging.INFO):
                    self.logger.info(f"Login attempt {self.login_attempts}/{self.LOGIN_RETRY_LIMIT}")
                try:
                    start_time = time.time()
                    result = await self._attempt_login(session)
                    elapsed = time.time() - start_time
                    self.perf_stats.record("login", elapsed)
                    if result:
                        self._is_authenticated = True
                        self._auth_token_timestamp = time.time()
                        self.login_attempts = 0
                        return True
                except Exception as e:
                    self.logger.error(f"Login error: {str(e)}", exc_info=True)
                if self.logger.isEnabledFor(logging.WARNING):
                    self.logger.warning(f"Login attempt {self.login_attempts} failed")
                await asyncio.sleep(1)
            
            self.logger.error(f"Login failed after {self.LOGIN_RETRY_LIMIT} attempts")
            self._is_authenticated = False
            return False

    async def _attempt_login(self, session: aiohttp.ClientSession) -> bool:
        try:
            async with session.get(self.PLAYERS_URL, allow_redirects=False) as response:
                if response.status == 200:
                    if self.logger.isEnabledFor(logging.DEBUG):
                        self.logger.debug("Already logged in (direct access to PLAYERS_URL)")
                    return True
            
            async with session.get(self.PLAYERS_URL, allow_redirects=True) as response:
                response_text = await response.text()
                response.raise_for_status()

                if str(response.url) == self.PLAYERS_URL:
                    if self.logger.isEnabledFor(logging.DEBUG):
                        self.logger.debug("Already logged in (redirected to PLAYERS_URL)")
                    return True
                
                if self.ACCOUNT_URL not in str(response.url):
                    self.logger.warning(f"Unexpected redirect URL: {response.url}")
                    return False

                soup = HTMLParser(response_text)
                token_input = soup.css_first("input[name='__RequestVerificationToken']")
                if not token_input or not token_input.attributes.get("value"):
                    self.logger.error("Anti-forgery token not found")
                    return False
                token = token_input.attributes["value"]

                payload = {
                    "Input.EmailOrUsername": self.username,
                    "Input.Password": self.password,
                    "__RequestVerificationToken": token
                }
                sso_login_url = str(response.url)
                headers = {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Referer": sso_login_url,
                    "Origin": self.ACCOUNT_URL.rstrip('/'),
                }

            async with session.post(sso_login_url, data=payload, headers=headers, allow_redirects=True) as response:
                response_text = await response.text()
                response.raise_for_status()
                
                if f"{self.BASE_ADMIN_URL}/signin-oidc" in response_text:
                    soup_oidc = HTMLParser(response_text)
                    form = soup_oidc.css_first("form[action*='signin-oidc']")
                    if not form: form = soup_oidc.css_first("form")
                    
                    if not form:
                        self.logger.error("signin-oidc: Redirect form not found on page.")
                        if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Page content for missing oidc form:\n{response_text[:1000]}")
                        if "Logout" in response_text or "Players" in response_text:
                            self.logger.info("Successfully authenticated (oidc page but logout/players link found).")
                            return True
                        return False

                    redirect_action_url = form.attributes.get("action")
                    if not redirect_action_url:
                        self.logger.error("signin-oidc: Redirect form action URL not found.")
                        return False
                    
                    redirect_action_url = urljoin(str(response.url), redirect_action_url)
                    inputs = form.css("input")
                    form_data = {inp.attributes.get("name"): inp.attributes.get("value", "") for inp in inputs if inp.attributes.get("name")}
                    
                    async with session.post(redirect_action_url, data=form_data, headers={"Referer": str(response.url)}, allow_redirects=True) as final_response:
                        final_response_text = await final_response.text()
                        final_response.raise_for_status()
                        if "Logout" in final_response_text or "Players" in final_response_text or self.BASE_ADMIN_URL in str(final_response.url):
                            self.logger.info("Successfully authenticated after OIDC redirect.")
                            return True
                        else:
                            self.logger.warning("Authentication failed after OIDC - no logout/players links in final response.")
                            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Final OIDC response text (snippet): {final_response_text[:1000]}")
                            return False
                elif "Logout" in response_text or "Players" in response_text or self.BASE_ADMIN_URL in str(response.url):
                    self.logger.info("Successfully authenticated.")
                    return True
                else:
                    self.logger.warning("Authentication failed - no OIDC, logout, or players links in response.")
                    if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Login response text (snippet): {response_text[:1000]}")
                    return False
        
        except aiohttp.ClientError as e:
            self.logger.error(f"Network error during login: {str(e)}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error during login: {str(e)}", exc_info=True)
            return False

    async def _ensure_authenticated(self) -> bool:
        async with self._async_lock:
            if not self._is_authenticated or (time.time() - self._auth_token_timestamp) >= self._auth_token_ttl:
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug("Authentication required or expired. Attempting login.")
                return await self.login()
        return True

    def _parse_connection_row(self, row_node: Node) -> Optional[ConnectionData]:
        try:
            cols = row_node.css("td")
            if len(cols) < 8:
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Too few columns in connection row: {len(cols)}. Row HTML: {row_node.html[:200]}")
                return None

            ban_hits_link, connection_id = None, None
            if len(cols) >= 9:
                link_tag = cols[8].css_first("a")
                if link_tag:
                    raw_link = link_tag.attributes.get("href")
                    if raw_link and raw_link.strip() != "#":
                        potential_ban_hits_link = urljoin(self.BASE_ADMIN_URL, raw_link)
                        if "connection=" in potential_ban_hits_link:
                            ban_hits_link = potential_ban_hits_link
                            try:
                                connection_id = ban_hits_link.split("connection=")[1].split("&")[0]
                            except IndexError:
                                if self.logger.isEnabledFor(logging.WARNING):
                                    self.logger.warning(f"Could not parse connection_id from ban_hits_link: {ban_hits_link}")
            
            user_name_el = cols[0].css_first("strong")
            user_name = user_name_el.text(strip=True) if user_name_el else cols[0].text(strip=True)
            user_id = cols[1].text(strip=True)
            time_val = cols[2].text(strip=True)
            ip_address = cols[3].text(strip=True)
            hwid = cols[4].text(strip=True)
            status_el = cols[5].css_first("strong")
            status = status_el.text(strip=True) if status_el else cols[5].text(strip=True)
            server = cols[6].text(strip=True)
            trust_score = cols[7].text(strip=True)

            return ConnectionData(
                user_name=user_name, user_id=user_id, time=time_val, ip_address=ip_address,
                hwid=hwid, status=status, server=server, trust_score=trust_score,
                ban_hits_link=ban_hits_link, connection_id=connection_id,
                is_denied_banned=("Denied: Banned" in status)
            )
        except Exception as e:
            self.logger.error(f"Error parsing connection row: {str(e)}", exc_info=True)
            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Problematic row HTML: {row_node.html[:500]}")
            return None

    def _parse_connections_table(self, soup: HTMLParser) -> List[ConnectionData]:
        connections = []
        table = soup.css_first("table.table")
        if not table:
            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug("No table.table found in the HTML")
            return connections
        
        tbody = table.css_first("tbody")
        if not tbody:
            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug("No tbody found in the table")
            return connections

        rows = tbody.css("tr")
        is_search_page_context = bool(soup.css_first("form[action*='search='], form input[name='search']"))

        if not rows and is_search_page_context and self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                f"Found 0 <tr> rows in <tbody> on what appears to be a search results page. "
            )
        
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Found {len(rows)} rows in the connections table to process.")
        for row_idx, row_node in enumerate(rows):
            conn = self._parse_connection_row(row_node)
            if conn:
                connections.append(conn)
            elif self.logger.isEnabledFor(logging.WARNING):
                 self.logger.warning(
                    f"Failed to parse connection data from row {row_idx}. Row content snippet (debug): {row_node.html[:300]}")
        return connections

    def _get_next_page_link(self, soup: HTMLParser) -> Optional[str]:
        next_page_link_tag = soup.css_first("a.page-link[rel='next']")
        if next_page_link_tag:
            href = next_page_link_tag.attributes.get('href')
            if href and href.strip() != '#':
                return urljoin(self.BASE_ADMIN_URL, href)

        potential_next_buttons = soup.css("a.btn")
        for btn_link_tag in potential_next_buttons:
            if "Next" not in btn_link_tag.text(strip=True): continue
            if "disabled" in btn_link_tag.attributes.get("class", ""): continue
            href_value = btn_link_tag.attributes.get("href")
            if not href_value or href_value.strip() == "#": continue
            if "page=" in href_value.lower() or "pageindex=" in href_value.lower():
                 return urljoin(self.BASE_ADMIN_URL, href_value)
        return None

    async def _get_cached_response(self, url: str) -> Optional[str]:
        async with self._async_lock:
            cache_entry = self._response_cache.get(url)
            if cache_entry:
                timestamp, html = cache_entry
                if time.time() - timestamp < self._RESPONSE_CACHE_TTL:
                    self._response_cache.move_to_end(url)
                    return html
                else:
                    del self._response_cache[url]
            return None

    async def _cache_response(self, url: str, html: str) -> None:
        async with self._async_lock:
            self._response_cache[url] = (html, time.time())
            if len(self._response_cache) > self._RESPONSE_CACHE_MAX_SIZE:
                self._response_cache.popitem(last=False)
    
    async def _get_cached_response_corrected(self, url: str) -> Optional[str]:
        async with self._async_lock:
            cache_entry = self._response_cache.get(url)
            if cache_entry:
                html, timestamp = cache_entry
                if time.time() - timestamp < self._RESPONSE_CACHE_TTL:
                    self._response_cache.move_to_end(url)
                    return html
                else:
                    del self._response_cache[url]
            return None
    
    _get_cached_response = _get_cached_response_corrected

    async def _make_request(self, url: str) -> Optional[str]:
        if not await self._ensure_authenticated():
            self.logger.error(f"Authentication failed before making request to {url}")
            return None

        session = await self._get_session()
        try:
            async with session.get(url) as response:
                if response.status in (401, 403):
                    self.logger.warning(
                        f"Request to {url} failed with status {response.status}. Re-authenticating and retrying once.")
                    if not await self.login():
                        self.logger.error("Re-login attempt failed. Aborting request.")
                        return None

                    async with session.get(url) as retry_response:
                        retry_response.raise_for_status()
                        return await retry_response.text()

                response.raise_for_status()
                return await response.text()

        except aiohttp.ClientError as e:
            self.logger.error(f"Aiohttp client error during request to {url}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error during request to {url}: {e}", exc_info=True)
            return None

    async def fetch_paginated_data(self, url: str, max_pages: int = 0) -> List[ConnectionData]:
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                f"Fetching paginated data from URL: {url}, max_pages={max_pages if max_pages > 0 else 'unlimited'}")

        all_connections: List[ConnectionData] = []
        current_url: Optional[str] = url
        page_num = 1
        pages_fetched = 0
        start_time_total = time.time()

        while current_url:
            if max_pages > 0 and pages_fetched >= max_pages:
                if self.logger.isEnabledFor(logging.INFO):
                    self.logger.info(f"Reached max pages limit ({max_pages}) after fetching {pages_fetched} pages.")
                break

            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Fetching page {page_num} from URL: {current_url}")

            req_start_time = time.time()
            html_content: Optional[str] = await self._get_cached_response(current_url)
            from_cache = bool(html_content)

            if not html_content:
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f"Cache miss for page {page_num} URL: {current_url}. Fetching live.")

                html_content = await self._make_request(current_url)

                if html_content:
                    await self._cache_response(current_url, html_content)

            req_elapsed_time = time.time() - req_start_time
            if req_elapsed_time > self.SLOW_REQUEST_THRESHOLD and not from_cache:
                self._request_metrics["slow_requests"] += 1
                log_url_display = current_url[:67] + "..." if len(current_url) > 70 else current_url
                if self.perf_logger.isEnabledFor(logging.DEBUG):
                    self.perf_logger.debug(f"Slow request ({req_elapsed_time:.2f}s): {log_url_display}")

            if not html_content:
                self.logger.error(
                    f"Failed to get HTML content for page {page_num} URL: {current_url}. Stopping pagination here.")
                break

            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Page {page_num} response length: {len(html_content)}. Parsing...")

            soup = HTMLParser(html_content)
            connections_on_page = self._parse_connections_table(soup)
            all_connections.extend(connections_on_page)
            pages_fetched += 1

            is_likely_search_page = "search=" in current_url.lower()
            if not connections_on_page and is_likely_search_page and page_num == 1:
                if self.logger.isEnabledFor(logging.INFO):
                    self.logger.info(
                        f"Search results page {current_url} (page {page_num}) yielded no connections. Assuming end of relevant results.")
                current_url = None
            else:
                current_url = self._get_next_page_link(soup)

            if current_url:
                page_num += 1

        total_elapsed_time = time.time() - start_time_total
        self.perf_stats.record("fetch_paginated_data", total_elapsed_time)
        if self.logger.isEnabledFor(logging.INFO):
            self.logger.info(
                f"Fetched {len(all_connections)} connections from {pages_fetched} page(s) in {total_elapsed_time:.2f}s")
        return all_connections

    def get_connections_url(self, user_id: str = "", search: str = "", show_accepted: str = "true",
                            show_banned: str = "true", show_whitelist: str = "true", show_full: str = "true",
                            show_panic: str = "true") -> str:
        search_term = quote_plus(user_id if user_id else search)
        return (f"{self.BASE_ADMIN_URL}/Connections?perPage=200&showSet=true"
               f"&search={search_term}&showAccepted={show_accepted}&showBanned={show_banned}"
               f"&showWhitelist={show_whitelist}&showFull={show_full}&showPanic={show_panic}")

    async def fetch_connections_for_user(self, user_id: str) -> List[Dict[str, Any]]:
        url = self.get_connections_url(user_id=user_id)
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Fetching connections for user_id: {user_id} from URL: {url}")
        start_time = time.time()
        connections = await self.fetch_paginated_data(url)
        elapsed = time.time() - start_time
        self.perf_stats.record(f"fetch_connections_for_user", elapsed)
        connection_dicts = [conn.to_dict() for conn in connections]
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Found {len(connection_dicts)} connections for user_id: {user_id}")
        return connection_dicts

    async def check_account_on_site(self, url: str, single_user: bool = False) -> Union[
        List[Dict[str, Any]], Dict[str, Union[str, List[str], bool, int]]]:
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Checking account on site: url={url}, single_user={single_user}")
        start_time = time.time()
        connections_data = await self.fetch_paginated_data(url)
        elapsed = time.time() - start_time
        self.perf_stats.record("check_account_on_site", elapsed)
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Found {len(connections_data)} connections for URL: {url}")

        if single_user:
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug("Aggregating single user info from connections data.")
            result = await self.aggregate_single_user_info(connections_data)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Aggregated result for single user, status: {result.get('status', 'unknown')}")
            return result

        connection_dicts = [conn.to_dict() for conn in connections_data]
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Returning {len(connection_dicts)} raw connection dicts.")
        return connection_dicts

    async def fetch_player_info(self, user_id: str) -> Dict[str, Union[int, List[Dict[str, str]]]]:
        if not await self._ensure_authenticated():
            if self.logger.isEnabledFor(logging.WARNING):
                self.logger.warning(f"Not authenticated, cannot fetch player info for {user_id}")
            return {"ban_counts": 0, "ban_reasons": []}

        info_result: Dict[str, Union[int, List[Dict[str, str]]]] = {"ban_counts": 0, "ban_reasons": []}
        info_url = self.PLAYER_INFO_URL_PATTERN.format(user_id)
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Fetching player info from URL: {info_url}")

        start_time = time.time()
        session = await self._get_session()
        from_cache = False
        try:
            html_content: Optional[str] = await self._get_cached_response(info_url)
            from_cache = bool(html_content)
            if not html_content:
                if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Cache miss for player info: {user_id}. Fetching live.")
                self._request_metrics["total"] += 1
                async with session.get(info_url) as resp:
                    resp.raise_for_status()
                    html_content = await resp.text()
                await self._cache_response(info_url, html_content)
            elif self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"Using cached response for player info: {user_id}")

            if not html_content:
                self.logger.error(f"Failed to get HTML content for player info: {user_id}")
                return info_result

            soup = HTMLParser(html_content)
            player_name = "Unknown"
            name_header = soup.css_first("h1")
            if name_header:
                name_text = name_header.text(strip=True)
                if "information for" in name_text.lower():
                    parts = name_text.split("information for ", 1)
                    if len(parts) > 1: player_name = parts[1].strip()
                    else:
                        parts_no_space = name_text.lower().split("information for", 1)
                        if len(parts_no_space) > 1: player_name = name_text[len(name_text) - len(parts_no_space[1]):].strip()

            ban_table_node = None
            for h2_node in soup.css("h2"):
                text = h2_node.text(strip=True)
                if "Bans" in text and "Role Bans" not in text:
                    current_node = h2_node.next
                    while current_node:
                        if current_node.tag == 'table' and 'table' in current_node.attributes.get('class', ''):
                            ban_table_node = current_node; break
                        if current_node.tag == 'h2': break
                        current_node = current_node.next
                    break

            if ban_table_node:
                ban_body = ban_table_node.css_first("tbody")
                if ban_body:
                    ban_info_list: List[Dict[str, str]] = []
                    rows = ban_body.css("tr")
                    for row_idx, row_node in enumerate(rows):
                        cols = row_node.css("td")
                        if cols and len(cols) >= 2:
                            ban_reason = cols[1].text(strip=True)
                            banned_username_for_entry = player_name
                            name_cell_content_strong = cols[0].css_first("strong")
                            if name_cell_content_strong: banned_username_for_entry = name_cell_content_strong.text(strip=True)
                            else:
                                potential_name_in_cell = cols[0].text(strip=True)
                                if potential_name_in_cell and potential_name_in_cell.lower() != player_name.lower():
                                    if not any(x in potential_name_in_cell for x in ["N/A", "User ID", "IP", "HWID"]):
                                        banned_username_for_entry = potential_name_in_cell
                            ban_info_list.append({"reason": ban_reason, "username": banned_username_for_entry})
                        elif self.logger.isEnabledFor(logging.WARNING):
                             self.logger.warning(f"Ban table row {row_idx} for {user_id} has < 2 columns: {row_node.html[:200]}")
                    info_result["ban_reasons"] = ban_info_list
                    info_result["ban_counts"] = len(ban_info_list)
            elif self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(f"No bans table found for player {user_id} on their info page.")
        
        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Player profile not found (404) for user_id: {user_id} at {info_url}")
            else:
                self._request_metrics["errors"] += 1
                self.logger.error(f"HTTP error fetching player info for {user_id} from {info_url}: {str(e)}")
        except aiohttp.ClientError as e:
            self._request_metrics["errors"] += 1
            self.logger.error(f"Request error fetching player info for {user_id} from {info_url}: {str(e)}")
        except Exception as e:
            self._request_metrics["errors"] += 1
            self.logger.error(f"Error parsing player info for {user_id} from {info_url}: {str(e)}", exc_info=True)

        elapsed_time = time.time() - start_time
        self.perf_stats.record("fetch_player_info", elapsed_time)
        if elapsed_time > self.SLOW_REQUEST_THRESHOLD and not from_cache:
             if self.perf_logger.isEnabledFor(logging.DEBUG):
                self.perf_logger.debug(f"Slow player info fetch: {elapsed_time:.2f}s for user {user_id}")
        return info_result

    async def aggregate_single_user_info(self, connections: List[Union[ConnectionData, Dict[str, Any]]]) -> Dict[
        str, Union[str, List[str], bool, int]]:
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Aggregating user info from {len(connections)} connections")

        result: Dict[str, Any] = {
            "status": "unknown", "nicknames": set(), "ban_counts": 0, "ban_reasons": set(),
            "shared_hwid_nicknames": set(), "associated_ips": {}, "associated_hwids": {},
            "user_id": N_A, "connection_link": N_A, "denied_banned_connections": []
        }

        if not connections:
            self.logger.warning("No connections provided to aggregate_single_user_info. Returning empty aggregation.")
            result["nicknames"], result["ban_reasons"], result["shared_hwid_nicknames"] = [], [], []
            return result

        all_ips, all_hwids = {}, {}
        banned_status_found, denied_banned_status_found = False, False
        first_valid_conn_id = None

        for conn_data in connections:
            if isinstance(conn_data, ConnectionData):
                nickname, ip, hwid_val, status_txt, curr_uid, time_val, srv, curr_conn_id, is_den_ban = \
                    conn_data.user_name, conn_data.ip_address, conn_data.hwid, conn_data.status, conn_data.user_id, \
                    conn_data.time, conn_data.server, conn_data.connection_id, conn_data.is_denied_banned
            elif isinstance(conn_data, dict):
                nickname, ip, hwid_val, status_txt, curr_uid, time_val, srv, curr_conn_id = \
                    conn_data.get("user_name", ""), conn_data.get("ip_address", ""), conn_data.get("hwid", ""), \
                    conn_data.get("status", ""), conn_data.get("user_id", ""), conn_data.get("time", ""), \
                    conn_data.get("server", ""), conn_data.get("connection_id")
                is_den_ban = "Denied: Banned" in status_txt
            else:
                self.logger.warning(f"Unexpected connection data type: {type(conn_data)}"); continue

            if curr_uid and curr_uid != N_A and result["user_id"] == N_A: result["user_id"] = curr_uid
            if not first_valid_conn_id and curr_conn_id: first_valid_conn_id = curr_conn_id
            if nickname: result["nicknames"].add(nickname)
            if ip and ip != N_A: all_ips.setdefault(ip, set()).add(nickname)
            if hwid_val and hwid_val != N_A: all_hwids.setdefault(hwid_val, set()).add(nickname)

            if status_txt:
                if "Accepted" in status_txt and result["status"] == "unknown": result["status"] = "clean"
                if is_den_ban:
                    denied_banned_status_found = True
                    result["denied_banned_connections"].append({
                        "user_name": nickname, "time": time_val, "ip_address": ip,
                        "hwid": hwid_val, "server": srv, "status": status_txt })
                elif "Banned" in status_txt: banned_status_found = True
        
        if denied_banned_status_found:
            result["status"], result["ban_counts"] = "banned", max(result["ban_counts"], 1)
            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug("Status set to 'banned' due to 'Denied: Banned' connections.")
        elif banned_status_found and result["status"] != "banned":
            result["status"] = "banned"
            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug("Status set to 'banned' due to 'Banned' status in connections.")


        if first_valid_conn_id: result["connection_link"] = f"{self.BASE_ADMIN_URL}/Connections/Info/{first_valid_conn_id}"

        final_uid_fetch = result["user_id"]
        if final_uid_fetch and final_uid_fetch != N_A:
            if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Fetching player-specific ban info for user_id: {final_uid_fetch}")
            player_page_info = await self.fetch_player_info(final_uid_fetch)
            result["ban_counts"] = max(result["ban_counts"], player_page_info.get("ban_counts", 0))
            for ban_entry in player_page_info.get("ban_reasons", []):
                if isinstance(ban_entry, dict) and "reason" in ban_entry and "username" in ban_entry:
                    result["ban_reasons"].add((ban_entry["reason"], ban_entry["username"]))
                elif self.logger.isEnabledFor(logging.WARNING): self.logger.warning(f"Malformed ban entry from fetch_player_info: {ban_entry}")
        
        result["associated_ips"] = {ip_k: sorted(list(nicks_v)) for ip_k, nicks_v in all_ips.items()}
        result["associated_hwids"] = {hwid_k: sorted(list(nicks_v)) for hwid_k, nicks_v in all_hwids.items()}
        for hwid_k, nicks_s in all_hwids.items():
            if len(nicks_s) > 1 and hwid_k != N_A: result["shared_hwid_nicknames"].update(nicks_s)
        
        if result["ban_counts"] > 0 and result["status"] != "banned": result["status"] = "banned"
        if result["ban_counts"] >= 5 and result["status"] == "banned" : result["status"] = "suspicious"

        result["nicknames"] = sorted(list(result["nicknames"]))
        result["ban_reasons"] = [{"reason": r, "username": u} for r, u in sorted(list(result["ban_reasons"]))]
        result["shared_hwid_nicknames"] = sorted(list(result["shared_hwid_nicknames"]))
        result["raw_html_snippet"] = []
        for conn_prev in connections[:10]:
             if isinstance(conn_prev, ConnectionData):
                result["raw_html_snippet"].append({"time": conn_prev.time, "status": conn_prev.status, "user_name": conn_prev.user_name})
             elif isinstance(conn_prev, dict):
                result["raw_html_snippet"].append(
                    {"time": conn_prev.get("time", ""), "status": conn_prev.get("status", ""), "user_name": conn_prev.get("user_name", "")})

        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                f"Aggregation complete for user_id '{result['user_id']}': status={result['status']}, "
                f"nicknames_count={len(result['nicknames'])}, ban_counts={result['ban_counts']}" )
        return result

    async def fetch_ban_hit_connections(self, max_pages: int = 0) -> List[Dict[str, str]]:
        url = f"{self.CONNECTIONS_URL}?showSet=true&search=&showBanned=true&perPage=200"
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Fetching ban hit connections, max_pages={max_pages if max_pages > 0 else 'unlimited'}")

        connections_data = await self.fetch_paginated_data(url, max_pages=max_pages)
        ban_hit_list = [conn.to_dict() for conn in connections_data if conn.is_denied_banned and conn.ban_hits_link]
        if self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(f"Found {len(ban_hit_list)} connections with 'Denied: Banned' status and a ban_hits_link.")
        return ban_hit_list

    async def fetch_ban_info(self, ban_hits_link: str) -> Dict[str, str]:
        if not ban_hits_link:
            if self.logger.isEnabledFor(logging.WARNING): self.logger.warning("fetch_ban_info called with empty ban_hits_link.")
            return {}
        if not await self._ensure_authenticated():
            if self.logger.isEnabledFor(logging.WARNING): self.logger.warning(f"Not authenticated, cannot fetch ban info from {ban_hits_link}")
            return {}

        ban_info: Dict[str, str] = {}
        if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Fetching ban info from URL: {ban_hits_link}")
        
        start_time = time.time()
        session = await self._get_session()
        from_cache = False
        try:
            html_content: Optional[str] = await self._get_cached_response(ban_hits_link)
            from_cache = bool(html_content)
            if not html_content:
                if self.logger.isEnabledFor(logging.DEBUG): self.logger.debug(f"Cache miss for ban info: {ban_hits_link}. Fetching live.")
                self._request_metrics["total"] += 1
                async with session.get(ban_hits_link) as response:
                    response.raise_for_status()
                    html_content = await response.text()
                await self._cache_response(ban_hits_link, html_content)
            elif self.logger.isEnabledFor(logging.DEBUG):
                 self.logger.debug(f"Using cached response for ban info: {ban_hits_link}")

            if not html_content:
                self.logger.error(f"Failed to get HTML content for ban info: {ban_hits_link}")
                return ban_info

            soup = HTMLParser(html_content)
            dl_element = soup.css_first("dl.row, dl")
            if dl_element:
                dt_nodes, dd_nodes = dl_element.css("dt"), dl_element.css("dd")
                info_dl = { dt.text(strip=True).rstrip(":").lower().replace(" ", "_"): dd.text(strip=True)
                            for dt, dd in zip(dt_nodes, dd_nodes) if dt and dd }
                ban_info["banned_user_name"] = info_dl.get("name", "")
                ban_info["user_id"] = info_dl.get("user_id", info_dl.get("user_id", ""))
                ban_info["ip_address"] = info_dl.get("ip", "")
                ban_info["hwid"] = info_dl.get("hwid", "")
                ban_info["time"] = info_dl.get("time", "")

            table = soup.css_first("table.table")
            if table:
                tbody = table.css_first("tbody")
                rows_src = tbody if tbody else table
                rows = rows_src.css("tr") if rows_src else []
                for row in rows:
                    cols = row.css("td")
                    if len(cols) >= 6:
                        ban_info["ban_time"], ban_info["expires"] = cols[2].text(strip=True), cols[4].text(strip=True)
                        break
            
            if not ban_info and self.logger.isEnabledFor(logging.WARNING):
                 self.logger.warning(f"Could not parse detailed ban info from {ban_hits_link}.")

        except aiohttp.ClientResponseError as e:
            if e.status == 404:
                if self.logger.isEnabledFor(logging.WARNING): self.logger.warning(f"Ban hits link not found (404): {ban_hits_link}")
            else:
                self._request_metrics["errors"] += 1
                self.logger.error(f"HTTP error fetching ban info from {ban_hits_link}: {e}")
        except aiohttp.ClientError as e:
            self._request_metrics["errors"] += 1; self.logger.error(f"Request error fetching ban info from {ban_hits_link}: {e}")
        except Exception as e:
            self._request_metrics["errors"] += 1; self.logger.error(f"Error parsing ban info from {ban_hits_link}: {e}", exc_info=True)

        elapsed = time.time() - start_time
        self.perf_stats.record("fetch_ban_info", elapsed)
        if elapsed > self.SLOW_REQUEST_THRESHOLD and not from_cache:
            if self.perf_logger.isEnabledFor(logging.DEBUG):
                self.perf_logger.debug(f"Slow ban info fetch: {elapsed:.2f}s for link: {ban_hits_link}")
        return ban_info