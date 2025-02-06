import logging
import re
from typing import Dict, Union, List, Any
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

N_A = "N/A"

class AdminPanel:
    BASE_ADMIN_URL = "https://admin.deadspace14.net"
    PLAYERS_URL = f"{BASE_ADMIN_URL}/Players"
    ACCOUNT_URL = "https://account.spacestation14.com"
    CONNECTIONS_URL = f"{BASE_ADMIN_URL}/Connections"

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
            response = self.session.post(
                sso_login_url, data=payload, headers=headers, allow_redirects=True
            )
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
                response = self.session.post(
                    redirect_action_url,
                    data=form_data,
                    headers={"Referer": response.url},
                    allow_redirects=True
                )
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
        """
        Fetches the list of banned connections from the admin panel,
        optionally limiting the number of pages fetched.
        Returns a list of dictionaries, each containing connection details.

        Args:
            max_pages (int): Maximum number of pages to fetch. 0 for unlimited.
        """
        ban_hit_connections = []
        url = f"{self.CONNECTIONS_URL}?showSet=true&search=&showBanned=true"
        current_url = url
        page_num = 1
        pages_fetched = 0

        while current_url:
            if max_pages > 0 and pages_fetched >= max_pages:
                logging.info(f"Reached maximum pages limit: {max_pages}. Stopping fetching ban hit connections.")
                break

            try:
                response = self.session.get(current_url)
                response.raise_for_status()
                soup = BeautifulSoup(response.text, 'html.parser')
                logging.info(f"Fetched ban hit connections page {page_num}: {current_url}")

                table = soup.find('table', class_='table')
                if not table:
                    logging.warning("No connection table found on page.")
                    break

                tbody = table.find('tbody')
                if not tbody:
                    logging.warning("No tbody found in connection table.")
                    break

                rows = tbody.find_all('tr')
                if not rows:
                    logging.info("No banned connections found on this page.")

                for row in rows:
                    cols = row.find_all('td')
                    if len(cols) >= 9:
                        connection_data = {
                            'user_name': cols[0].strong.text.strip() if cols[0].strong else cols[0].text.strip(),
                            'user_id': cols[1].text.strip(),
                            'time': cols[2].text.strip(),
                            'ip_address': cols[3].text.strip(),
                            'hwid': cols[4].text.strip(),
                            'status': cols[5].strong.text.strip() if cols[5].strong else cols[5].text.strip(),
                            'server': cols[6].text.strip(),
                            'trust_score': cols[7].text.strip(),
                            'ban_hits_link': urljoin(self.BASE_ADMIN_URL, cols[8].find('a')['href']) if cols[8].find(
                                'a') else None
                        }
                        ban_hit_connections.append(connection_data)

                next_page_link = soup.find("a", class_="btn", string=re.compile(r"Next"))
                if next_page_link and 'disabled' not in next_page_link.get('class', []):
                    current_url = urljoin(self.BASE_ADMIN_URL, next_page_link['href'])
                    page_num += 1
                    pages_fetched += 1
                else:
                    current_url = None

            except requests.exceptions.RequestException as e:
                logging.error(f"Error fetching ban hit connections page {page_num}: {e}")
                break
            except Exception as e:
                logging.error(f"Error parsing ban hit connections page {page_num}: {e}", exc_info=True)
                break

        logging.info(f"Total ban hit connections fetched: {len(ban_hit_connections)} from {pages_fetched} page(s).")
        return ban_hit_connections


    def check_account_on_site(self, url: str) -> Dict[str, Union[str, List[str], bool, int]]:

        result: Dict[str, Any] = {
            "status": "unknown",
            "nicknames": [],
            "raw_html_snippet": "",
            "suspected_vpn": False,
            "ban_counts": 0,
            "ban_reasons": [],
            "shared_hwid_nicknames": [],
            "associated_ips": {},
            "associated_hwids": {}
        }

        try:
            current_url = url
            all_nicknames = set()
            all_ips = {}
            all_hwids = {}
            page_num = 1
            while current_url:
                resp = self.session.get(current_url)
                resp.raise_for_status()
                html = resp.text
                if page_num == 1:
                    result["raw_html_snippet"] = html[:500]

                soup = BeautifulSoup(html, "html.parser")
                logging.debug(f"Successfully fetched and parsed URL: {current_url}")

                table_rows = soup.find_all("tr")
                banned_found = False
                nicknames = set()

                for row in table_rows:
                    cols = row.find_all("td")
                    if len(cols) < 6:
                        continue

                    nickname_col = cols[0].get_text(strip=True)
                    ip_col = cols[3].get_text(strip=True)
                    hwid_col = cols[4].get_text(strip=True)
                    status_col = cols[5].get_text(strip=True)

                    if nickname_col:
                        nicknames.add(nickname_col)

                    if ip_col and ip_col != N_A:
                        if ip_col not in all_ips:
                            all_ips[ip_col] = set()
                        all_ips[ip_col].add(nickname_col)

                    if hwid_col and hwid_col != N_A:
                        if hwid_col not in all_hwids:
                            all_hwids[hwid_col] = set()
                        all_hwids[hwid_col].add(nickname_col)

                    if "Accepted" in status_col:
                        result["status"] = "clean"
                    if "Denied: Banned" in status_col:
                        banned_found = True
                    elif "Accepted" in status_col:
                        pass

                if banned_found:
                    result["status"] = "banned"

                result["nicknames"].extend(list(nicknames))

                next_page_link = soup.find("a", class_="page-link", rel="next")
                if next_page_link:
                    current_url = f"{self.BASE_ADMIN_URL}{next_page_link['href']}"
                    page_num += 1
                else:
                    current_url = None

            result["associated_ips"] = {ip: list(nicks) for ip, nicks in all_ips.items()}
            result["associated_hwids"] = {hwid: list(nicks) for hwid, nicks in all_hwids.items()}


            shared_hwid_nicks = set()
            for hwid, nicks in result["associated_hwids"].items():
                if len(nicks) > 1 and hwid != N_A:
                    shared_hwid_nicks.update(nicks)
            result["shared_hwid_nicknames"] = list(shared_hwid_nicks)

            user_id_match = re.search(r'/Players/Info/([0-9a-f-]+)"', html)
            if user_id_match:
                user_id = user_id_match.group(1)
                player_info = self.fetch_player_info(user_id)
                result["ban_counts"] = player_info["ban_counts"]
                result["ban_reasons"] = player_info["ban_reasons"]


                if result["ban_counts"] > 0:
                    if result["ban_counts"] >= 5:
                        result["status"] = "suspicious"
                    else:
                        if result["status"] not in ("suspicious", "banned"):
                            result["status"] = "banned"

        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking {url}: {e}")
        except Exception as e:
            logging.error(f"Exception checking {url}: {e}", exc_info=True)

        return result

    def fetch_player_info(self, user_id: str) -> Dict[str, Union[int, List[str]]]:
        info_result = {
            "ban_counts": 0,
            "ban_reasons": []
        }
        info_url = f"{self.BASE_ADMIN_URL}/Players/Info/{user_id}"
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

    def aggregate_player_info(
        self,
        partial_results_list: List[Dict[str, Any]]
    ) -> List[Dict[str, Union[str, List[str], bool, int]]]:
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
                    merged_dict["status"] = self._merge_statuses(
                        merged_dict["status"], result_j["status"]
                    )

                    for ip, nicks in result_j["associated_ips"].items():
                        if ip not in merged_dict["associated_ips"]:
                            merged_dict["associated_ips"][ip] = []
                        merged_dict["associated_ips"][ip].extend(
                            [nick for nick in nicks if nick not in merged_dict["associated_ips"][ip]])

                    for hwid, nicks in result_j["associated_hwids"].items():
                        if hwid not in merged_dict["associated_hwids"]:
                            merged_dict["associated_hwids"][hwid] = []
                        merged_dict["associated_hwids"][hwid].extend(
                            [nick for nick in nicks if nick not in merged_dict["associated_hwids"][hwid]])


            merged_dict["nicknames"] = list(merged_dict["nicknames"])
            merged_dict["ban_reasons"] = list(merged_dict["ban_reasons"])
            merged_dict["shared_hwid_nicknames"] = list(merged_dict["shared_hwid_nicknames"])

            merged_results.append(merged_dict)

        return merged_results

    def _merge_statuses(self, status_a: str, status_b: str) -> str:
        priority = {
            "suspicious": 4,
            "banned": 3,
            "unknown": 2,
            "clean": 1
        }
        val_a = priority.get(status_a, 2)
        val_b = priority.get(status_b, 2)
        return status_a if val_a > val_b else status_b