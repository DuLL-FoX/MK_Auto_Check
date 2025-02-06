import logging
import re
from typing import Dict, Union, List, Any
from urllib.parse import urljoin, quote_plus

import requests
from bs4 import BeautifulSoup

N_A = "N/A"

class AdminPanel:
    BASE_ADMIN_URL = "https://admin.deadspace14.net"
    PLAYERS_URL = f"{BASE_ADMIN_URL}/Players"
    ACCOUNT_URL = "https://account.spacestation14.com"
    CONNECTIONS_URL = f"{BASE_ADMIN_URL}/Connections"
    BAN_HITS_URL_PATTERN = f"{BASE_ADMIN_URL}/Connections/Hits"
    PLAYER_INFO_URL_PATTERN = f"{BASE_ADMIN_URL}/Players/Info/{{}}"
    CONNECTIONS_URL_PATTERN = f"{BASE_ADMIN_URL}/Connections?showSet=true&search={{}}&showAccepted={{}}&showBanned={{}}&showWhitelist={{}}&showFull={{}}&showPanic={{}}&perPage=2000"
    BANS_URL = f"{BASE_ADMIN_URL}/Bans"

    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.session = requests.Session()

    def login(self) -> bool:
        try:
            response = self.session.get(self.PLAYERS_URL, allow_redirects=True)
            response.raise_for_status()
            logging.info(f"Successfully accessed initial URL: {self.PLAYERS_URL}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error accessing admin site: {e}")
            return False

        if self.ACCOUNT_URL not in response.url:
            logging.warning("Expected SSO login page not reached. Check if SSO is down.")
            return False

        soup = BeautifulSoup(response.text, "html.parser")
        token_input = soup.find("input", {"name": "__RequestVerificationToken"})
        if not token_input:
            logging.error("Could not find anti-forgery token on login page.")
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
            "User-Agent": "Mozilla/5.0 (compatible)"
        }
        try:
            response = self.session.post(sso_login_url, data=payload, headers=headers, allow_redirects=True)
            response.raise_for_status()
            logging.info("Login request successful.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during login request: {e}")
            return False

        if f"{self.BASE_ADMIN_URL}/signin-oidc" in response.text:
            soup = BeautifulSoup(response.text, "html.parser")
            form = soup.find("form")
            if not form:
                logging.error("Could not find the redirect form after login.")
                return False

            redirect_action_url = form.get("action")
            inputs = form.find_all("input")
            form_data = {inp.get("name"): inp.get("value", "") for inp in inputs}
            try:
                response = self.session.post(redirect_action_url, data=form_data, headers={"Referer": response.url},
                                             allow_redirects=True)
                response.raise_for_status()
                logging.info("Redirect form submission successful.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error submitting redirect form: {e}")
                return False

            if "Logout" in response.text or "Players" in response.text:
                logging.info("Successfully authenticated to admin.deadspace14.net!")
                return True
            else:
                logging.warning("The final redirect to admin.deadspace14.net failed or was unexpected.")
                return False
        else:
            logging.warning("Did not get the expected redirect form from SSO. Possibly incorrect credentials.")
            return False

    def fetch_ban_hit_connections(self, max_pages: int = 0) -> List[Dict[str, str]]:
        ban_hit_connections = []
        url = f"{self.CONNECTIONS_URL}?showSet=true&search=&showBanned=true"
        current_url = url
        page_num = 1
        pages_fetched = 0
        while current_url:
            if max_pages > 0 and pages_fetched >= max_pages:
                logging.info(f"Reached max pages limit: {max_pages}.")
                break
            try:
                response = self.session.get(current_url)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, "html.parser")
                logging.info(f"Fetched ban hit connections page {page_num}: {current_url}")
                table = soup.find("table", class_="table")
                if not table:
                    logging.warning("No connection table found.")
                    break
                tbody = table.find("tbody")
                if not tbody:
                    logging.warning("No tbody in table.")
                    break
                rows = tbody.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) >= 9:
                        connection_data = {
                            "user_name": cols[0].strong.text.strip() if cols[0].strong else cols[0].text.strip(),
                            "user_id": cols[1].text.strip(),
                            "time": cols[2].text.strip(),
                            "ip_address": cols[3].text.strip(),
                            "hwid": cols[4].text.strip(),
                            "status": cols[5].strong.text.strip() if cols[5].strong else cols[5].text.strip(),
                            "server": cols[6].text.strip(),
                            "trust_score": cols[7].text.strip(),
                            "ban_hits_link": urljoin(self.BASE_ADMIN_URL, cols[8].find("a")["href"]) if cols[8].find(
                                "a") else None,
                        }
                        ban_hit_connections.append(connection_data)
                next_page_link = soup.find("a", class_="btn", string=re.compile(r"Next"))
                if next_page_link and "disabled" not in next_page_link.get("class", []):
                    current_url = urljoin(self.BASE_ADMIN_URL, next_page_link["href"])
                    page_num += 1
                    pages_fetched += 1
                else:
                    current_url = None
            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching page {page_num}: {e}")
                break
            except Exception as e:
                logging.error(f"Error parsing page {page_num}: {e}", exc_info=True)
                break
        logging.info(f"Fetched {len(ban_hit_connections)} ban hits from {pages_fetched} pages.")
        return ban_hit_connections

    def fetch_ban_info(self, ban_hits_link: str) -> Dict[str, str]:
        ban_info = {}
        try:
            response = self.session.get(ban_hits_link)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            # Попытка извлечь основные данные из блока <dl>
            dl = soup.find("dl")
            if dl:
                dt_tags = dl.find_all("dt")
                dd_tags = dl.find_all("dd")
                info = {}
                for dt, dd in zip(dt_tags, dd_tags):
                    key = dt.get_text(strip=True).rstrip(":")
                    info[key] = dd.get_text(strip=True)
                ban_info["banned_user_name"] = info.get("Name", "")
                ban_info["user_id"] = info.get("User ID", "")
                ban_info["ip_address"] = info.get("IP", "")
                ban_info["hwid"] = info.get("HWID", "")
                ban_info["time"] = info.get("Time", "")
            # Если в странице присутствует таблица с подробностями (например, для ban_time, expires)
            table = soup.find("table", class_="table")
            if table:
                rows = table.find_all("tr")
                for row in rows:
                    cols = row.find_all("td")
                    if len(cols) >= 6:
                        ban_info["ban_time"] = cols[2].get_text(strip=True)
                        ban_info["expires"] = cols[4].get_text(strip=True)
                        link_tag = cols[6].find("a")
                        if link_tag:
                            m = re.search(r"/Bans/Hits/(\d+)", link_tag.get("href", ""))
                            if m:
                                ban_info["ban_id"] = m.group(1)
                        break
            logging.info(f"Fetched ban info from: {ban_hits_link}")
        except Exception as e:
            logging.error(f"Error fetching ban info from {ban_hits_link}: {e}", exc_info=True)
        return ban_info

    def fetch_connections_for_user(self, user_id: str) -> List[Dict[str, str]]:
        connections = []
        url = self.get_connections_url(user_id=user_id)
        try:
            response = self.session.get(url)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            logging.info(f"Fetched connections for user ID {user_id}: {url}")
            table = soup.find('table', class_='table')
            if not table:
                logging.warning(f"No connection table found for user ID {user_id}.")
                return []
            tbody = table.find('tbody')
            if not tbody:
                logging.warning(f"No tbody found in connection table for user ID {user_id}.")
                return []
            rows = tbody.find_all('tr')
            for row in rows:
                cols = row.find_all('td')
                if len(cols) >= 8:
                    connection_data = {
                        'user_name': cols[0].strong.text.strip() if cols[0].strong else cols[0].text.strip(),
                        'user_id': cols[1].text.strip(),
                        'time': cols[2].text.strip(),
                        'ip_address': cols[3].text.strip(),
                        'hwid': cols[4].text.strip(),
                        'status': cols[5].strong.text.strip() if cols[5].strong else cols[5].text.strip(),
                        'server': cols[6].text.strip(),
                        'trust_score': cols[7].text.strip(),
                    }
                    connections.append(connection_data)
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching connections for user ID {user_id}: {e}")
        except Exception as e:
            logging.error(f"Error parsing connections for user ID {user_id}: {e}", exc_info=True)
        return connections

    def get_connections_url(self, user_id: str = "", search: str = "", show_accepted: str = "true",
                            show_banned: str = "true", show_whitelist: str = "true", show_full: str = "true",
                            show_panic: str = "true") -> str:
        search_term = user_id if user_id else quote_plus(search)
        return self.CONNECTIONS_URL_PATTERN.format(search_term, show_accepted, show_banned, show_whitelist, show_full,
                                                   show_panic)

    def check_account_on_site(self, url: str, single_user: bool = False) -> Union[
        List[Dict[str, str]], Dict[str, Union[str, List[str], bool, int]]]:
        connections = []
        try:
            current_url = url
            page_num = 1
            while current_url:
                resp = self.session.get(current_url)
                resp.raise_for_status()
                soup = BeautifulSoup(resp.text, "html.parser")
                logging.debug(f"Successfully fetched and parsed URL: {current_url}")
                table = soup.find('table', class_='table')
                if not table:
                    logging.warning(f"No connection table found at {current_url}.")
                    return {} if single_user else []
                tbody = table.find('tbody')
                if not tbody:
                    logging.warning(f"No tbody found in connection table at {current_url}.")
                    return {} if single_user else []
                rows = tbody.find_all('tr')
                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 8:
                        connection_data = {
                            'user_name': cols[0].strong.text.strip() if cols[0].strong else cols[0].text.strip(),
                            'user_id': cols[1].text.strip(),
                            'time': cols[2].text.strip(),
                            'ip_address': cols[3].text.strip(),
                            'hwid': cols[4].text.strip(),
                            'status': cols[5].strong.text.strip() if cols[5].strong else cols[5].text.strip(),
                            'server': cols[6].text.strip(),
                            'trust_score': cols[7].text.strip(),
                        }
                        connections.append(connection_data)
                next_page_link = soup.find("a", class_="page-link", rel="next")
                if next_page_link:
                    current_url = f"{self.BASE_ADMIN_URL}{next_page_link['href']}"
                    page_num += 1
                else:
                    current_url = None
            if single_user:
                return self.aggregate_single_user_info(connections)
            return connections
        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking {url}: {e}")
            return {} if single_user else []
        except Exception as e:
            logging.error(f"Exception checking {url}: {e}", exc_info=True)
            return {} if single_user else []

    def aggregate_single_user_info(self, connections: List[Dict[str, str]]) -> Dict[
        str, Union[str, List[str], bool, int]]:
        result: Dict[str, Any] = {
            "status": "unknown",
            "nicknames": [],
            "raw_html_snippet": [],
            "suspected_vpn": False,
            "ban_counts": 0,
            "ban_reasons": [],
            "shared_hwid_nicknames": [],
            "associated_ips": {},
            "associated_hwids": {}
        }
        all_nicknames = set()
        all_ips = {}
        all_hwids = {}
        banned_found = False
        for connection in connections:
            nickname = connection['user_name']
            ip_address = connection['ip_address']
            hwid = connection['hwid']
            status = connection['status']
            all_nicknames.add(nickname)
            if ip_address and ip_address != N_A:
                all_ips.setdefault(ip_address, set()).add(nickname)
            if hwid and hwid != N_A:
                all_hwids.setdefault(hwid, set()).add(nickname)
            if "Accepted" in status:
                result["status"] = "clean"
            if "Denied: Banned" in status:
                banned_found = True
        if banned_found:
            result["status"] = "banned"
        result["nicknames"] = list(all_nicknames)
        result["associated_ips"] = {ip: list(nicks) for ip, nicks in all_ips.items()}
        result["associated_hwids"] = {hwid: list(nicks) for hwid, nicks in all_hwids.items()}
        user_id = connections[0]['user_id'] if connections else None
        if user_id:
            player_info = self.fetch_player_info(user_id)
            result["ban_counts"] = player_info["ban_counts"]
            result["ban_reasons"] = player_info["ban_reasons"]
            result["raw_html_snippet"] = [{"time": conn["time"], "status": conn["status"]} for conn in
                                          connections[:100]]
            if result["ban_counts"] > 0:
                if result["ban_counts"] >= 5:
                    result["status"] = "suspicious"
                else:
                    if result["status"] not in ("suspicious", "banned"):
                        result["status"] = "banned"
        shared_hwid_nicks = set()
        for hwid, nicks in result["associated_hwids"].items():
            if len(nicks) > 1 and hwid != N_A:
                shared_hwid_nicks.update(nicks)
        result["shared_hwid_nicknames"] = list(shared_hwid_nicks)
        return result

    def fetch_player_info(self, user_id: str) -> Dict[str, Union[int, List[str]]]:
        info_result = {
            "ban_counts": 0,
            "ban_reasons": []
        }
        info_url = self.PLAYER_INFO_URL_PATTERN.format(user_id)
        try:
            resp = self.session.get(info_url)
            resp.raise_for_status()
            logging.debug(f"Successfully fetched player info for user ID: {user_id}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error fetching player info for {user_id}: {e}")
            return info_result
        soup = BeautifulSoup(resp.text, "html.parser")
        ban_table = None
        for h2 in soup.find_all("h2"):
            if h2.text.strip().lower() == "bans":
                ban_table = h2.find_next("table")
                break
        if ban_table:
            ban_body = ban_table.find("tbody")
            if not ban_body:
                return info_result
            ban_rows = ban_body.find_all("tr", recursive=False)
            for row in ban_rows:
                cols = row.find_all("td", recursive=False)
                if len(cols) < 2:
                    continue
                reason_col = cols[1].get_text(strip=True)
                info_result["ban_reasons"].append(reason_col)
            info_result["ban_counts"] = len(info_result["ban_reasons"])
            logging.debug(f"Found {info_result['ban_counts']} bans for user ID: {user_id}")
        return info_result

    def aggregate_player_info(self, partial_results_list: List[Dict[str, Any]]) -> List[
        Dict[str, Union[str, List[str], bool, int]]]:
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
            }
            used[i] = True
            merged_nicknames = set(result_i["nicknames"])
            for j in range(i + 1, len(partial_results_list)):
                if used[j]:
                    continue
                result_j = partial_results_list[j]
                if merged_nicknames.intersection(set(result_j["nicknames"])):
                    used[j] = True
                    merged_nicknames.update(result_j["nicknames"])
                    merged_dict["nicknames"].update(result_j["nicknames"])
                    merged_dict["ban_reasons"].update(result_j["ban_reasons"])
                    merged_dict["shared_hwid_nicknames"].update(result_j["shared_hwid_nicknames"])
                    merged_dict["ban_counts"] += result_j["ban_counts"]
                    merged_dict["suspected_vpn"] = merged_dict["suspected_vpn"] or result_j["suspected_vpn"]
                    merged_dict["status"] = self._merge_statuses(merged_dict["status"], result_j["status"])
                    for ip, nicks in result_j["associated_ips"].items():
                        merged_dict["associated_ips"].setdefault(ip, []).extend(
                            [nick for nick in nicks if nick not in merged_dict["associated_ips"].get(ip, [])])
                    for hwid, nicks in result_j["associated_hwids"].items():
                        merged_dict["associated_hwids"].setdefault(hwid, []).extend(
                            [nick for nick in nicks if nick not in merged_dict["associated_hwids"].get(hwid, [])])
            merged_dict["nicknames"] = list(merged_dict["nicknames"])
            merged_dict["ban_reasons"] = list(merged_dict["ban_reasons"])
            merged_dict["shared_hwid_nicknames"] = list(merged_dict["shared_hwid_nicknames"])
            merged_results.append(merged_dict)
        return merged_results

    def _merge_statuses(self, status_a: str, status_b: str) -> str:
        priority = {"suspicious": 4, "banned": 3, "unknown": 2, "clean": 1}
        return status_a if priority.get(status_a, 2) > priority.get(status_b, 2) else status_b
