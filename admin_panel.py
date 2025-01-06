from typing import Dict, Union, List
import requests
from bs4 import BeautifulSoup
import re
import logging

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
)

class AdminPanel:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.ip_to_nicknames_map = {}
        self.hwid_to_nicknames_map = {}
        self.nickname_to_ban_counts = {}
        self.nickname_to_ban_reasons = {}

    def login(self) -> bool:
        initial_url = 'https://admin.deadspace14.net/Players'
        try:
            response = self.session.get(initial_url, allow_redirects=True)
            response.raise_for_status()
            logging.info(f"Successfully accessed initial URL: {initial_url}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error accessing admin site: {e}")
            return False

        if 'account.spacestation14.com' not in response.url:
            logging.warning("Did not get redirected to the SSO login page.")
            return False

        soup = BeautifulSoup(response.text, 'html.parser')
        token_input = soup.find('input', {'name': '__RequestVerificationToken'})
        if not token_input:
            logging.error("Could not find anti-forgery token on login page.")
            return False

        token = token_input.get('value')
        payload = {
            'Input.EmailOrUsername': self.username,
            'Input.Password': self.password,
            '__RequestVerificationToken': token
        }

        login_url = response.url
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': login_url,
            'Origin': 'https://account.spacestation14.com',
            'User-Agent': 'Mozilla/5.0 (compatible)'
        }

        try:
            response = self.session.post(login_url, data=payload, headers=headers, allow_redirects=True)
            response.raise_for_status()
            logging.info("Login request successful.")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error during login request: {e}")
            return False

        if 'admin.deadspace14.net/signin-oidc' in response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            form = soup.find('form')
            if not form:
                logging.error("Could not find the redirect form after login.")
                return False

            action_url = form.get('action')
            inputs = form.find_all('input')
            form_data = {inp.get('name'): inp.get('value', '') for inp in inputs}

            try:
                response = self.session.post(
                    action_url,
                    data=form_data,
                    headers={'Referer': response.url},
                    allow_redirects=True
                )
                response.raise_for_status()
                logging.info("Redirect form submission successful.")
            except requests.exceptions.RequestException as e:
                logging.error(f"Error submitting redirect form: {e}")
                return False

            if 'Logout' in response.text or 'Players' in response.text:
                logging.info("Successfully authenticated to admin.deadspace14.net!")
                return True
            else:
                logging.warning("The final redirect to admin.deadspace14.net failed.")
                return False
        else:
            logging.warning("Did not get the expected redirect form from SSO. Possibly wrong credentials.")
            return False

    def check_account_on_site(self, url: str) -> Dict[str, Union[str, List[str], None, bool, int]]:
        result: Dict[str, Union[str, List[str], None, bool, int]] = {
            "status": "unknown",
            "nicknames": [],
            "raw_html_snippet": "",
            "suspected_vpn": False,
            "ban_counts": 0,
            "ban_reasons": [],
            "shared_hwid_nicknames": []
        }

        local_ip_map = {}
        local_hwid_map = {}

        try:
            resp = self.session.get(url)
            resp.raise_for_status()
            html = resp.text
            result["raw_html_snippet"] = html[:500]
            soup = BeautifulSoup(html, 'html.parser')
            logging.debug(f"Successfully fetched and parsed URL: {url}")

            rows = soup.find_all("tr")
            found_denied = False
            found_accepted = False
            nicknames = set()

            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 6:
                    continue

                nickname_col = cols[0].get_text(strip=True)
                status_col = cols[5].get_text(strip=True)
                ip_col = cols[3].get_text(strip=True)
                hwid_col = cols[4].get_text(strip=True)

                if nickname_col:
                    nicknames.add(nickname_col)

                if ip_col:
                    local_ip_map.setdefault(ip_col, set()).add(nickname_col)
                if hwid_col:
                    local_hwid_map.setdefault(hwid_col, set()).add(nickname_col)

                if "Denied: Banned" in status_col:
                    found_denied = True
                elif "Accepted" in status_col:
                    found_accepted = True

            if found_denied:
                result["status"] = "banned"
            elif found_accepted:
                result["status"] = "clean"
            else:
                result["status"] = "unknown"

            result["nicknames"] = list(nicknames)

            for row in rows:
                cols = row.find_all("td")
                if len(cols) < 5:
                    continue
                ip_col = cols[3].get_text(strip=True)
                hwid_col = cols[4].get_text(strip=True)

                if ip_col in local_ip_map and len(local_ip_map[ip_col]) >= 5:
                    result["suspected_vpn"] = True
                if hwid_col in local_hwid_map and len(local_hwid_map[hwid_col]) >= 5:
                    result["suspected_vpn"] = True
                if result["suspected_vpn"]:
                    break

            for hwid, nicks in local_hwid_map.items():
                if len(nicks) > 1:
                    result["shared_hwid_nicknames"].extend(nicks)
            result["shared_hwid_nicknames"] = list(set(result["shared_hwid_nicknames"]))

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
                        result["status"] = "banned"

        except requests.exceptions.RequestException as e:
            logging.error(f"Error checking {url}: {e}")
        except Exception as e:
            logging.error(f"Exception checking {url}: {e}", exc_info=True)

        return result

    def fetch_player_info(self, user_id: str) -> dict:
        info_result = {
            "ban_counts": 0,
            "ban_reasons": []
        }

        info_url = f"https://admin.deadspace14.net/Players/Info/{user_id}"
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
            ban_rows = ban_table.find("tbody").find_all("tr", recursive=False)
            ban_reasons = []
            for row in ban_rows:
                cols = row.find_all("td", recursive=False)
                if len(cols) < 2:
                    continue
                reason_col = cols[1].get_text(strip=True)
                ban_reasons.append(reason_col)

            info_result["ban_counts"] = len(ban_reasons)
            info_result["ban_reasons"] = ban_reasons
            logging.debug(f"Found {info_result['ban_counts']} bans for user ID: {user_id}")

        return info_result

    def aggregate_player_info(self, partial_results_list: List[Dict]) -> List[Dict]:
        merged_results = []
        used = [False] * len(partial_results_list)

        for i, res_i in enumerate(partial_results_list):
            if used[i]:
                continue

            group_nicknames = set(res_i["nicknames"])
            merged_dict = {
                "status": res_i["status"],
                "nicknames": set(res_i["nicknames"]),
                "suspected_vpn": res_i["suspected_vpn"],
                "ban_counts": res_i["ban_counts"],
                "ban_reasons": set(res_i["ban_reasons"]),
                "shared_hwid_nicknames": set(res_i["shared_hwid_nicknames"]),
            }
            used[i] = True

            for j in range(i + 1, len(partial_results_list)):
                if used[j]:
                    continue
                res_j = partial_results_list[j]

                if group_nicknames.intersection(res_j["nicknames"]):
                    used[j] = True
                    merged_dict["nicknames"].update(res_j["nicknames"])
                    merged_dict["ban_reasons"].update(res_j["ban_reasons"])
                    merged_dict["shared_hwid_nicknames"].update(res_j["shared_hwid_nicknames"])
                    merged_dict["ban_counts"] += res_j["ban_counts"]
                    merged_dict["suspected_vpn"] = merged_dict["suspected_vpn"] or res_j["suspected_vpn"]
                    merged_dict["status"] = self._merge_statuses(merged_dict["status"], res_j["status"])
                    group_nicknames.update(res_j["nicknames"])

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
        if val_a > val_b:
            return status_a
        else:
            return status_b