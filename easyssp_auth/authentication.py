import base64
from datetime import UTC, datetime
import hashlib
import html
import json
import os
import re
import urllib.parse
import uuid

import urllib3


class AuthClient:
    """
    Class with methods for initial logging to the easySSP APIs and access token refreshing
    """

    BASE_URL = "https://www.easy-ssp.com"
    SUCCESS_STATUS_CODE = 200

    def __init__(self, username: str, password: str, client_id: str) -> None:
        self.client_id = client_id
        self.access_token = ""
        self.refresh_token = ""
        self._login(username, password)

    def get_access_token(self) -> str:
        if self._is_access_token_valid():
            return self.access_token
        self._refresh_token()
        return self.access_token

    def _refresh_token(self):
        try:
            provider = f"{self.BASE_URL}/realms/exxcellent"
            token_url = provider + "/protocol/openid-connect/token"

            http = urllib3.PoolManager()

            data = {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": self.refresh_token,
            }

            encoded_data = urllib.parse.urlencode(data)

            resp = http.request(
                "POST",
                token_url,
                body=encoded_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                redirect=False
            )
        except Exception as ex:
            raise AuthError("Failed to refresh access token.") from ex

        if resp.status == self.SUCCESS_STATUS_CODE:
            result = resp.json()
            self.access_token = result["access_token"]
            self.expiration = self._get_access_token_expiry_time()
            self.refresh_token = result["refresh_token"]
        else:
            raise AuthError(
                f"Refresh access token attempt failed: {resp.status} {resp.data.decode('utf-8')}")

    def _get_access_token_expiry_time(self):
        decoded_token_json = self._jwt_payload_decode(self.access_token)
        exp = decoded_token_json["exp"]
        exp_time = datetime.fromtimestamp(exp, tz=UTC)
        return exp_time

    def _is_access_token_valid(self) -> bool:
        return (self.expiration - datetime.now(UTC)).total_seconds() > 5 * 60  # expires less than 5 minutes from now

    def _b64_decode(self, data):
        data += "=" * (4 - len(data) % 4)
        return base64.b64decode(data).decode("utf-8")

    def _jwt_payload_decode(self, jwt):
        _, payload, _ = jwt.split(".")
        return json.loads(self._b64_decode(payload))

    def _login(self, username: str, password: str):
        try:
            provider = f"{self.BASE_URL}/realms/exxcellent"

            code_verifier = base64.urlsafe_b64encode(os.urandom(40)).decode("utf-8")
            code_verifier = re.sub("[^a-zA-Z0-9]+", "", code_verifier)

            code_challenge = hashlib.sha256(code_verifier.encode("utf-8")).digest()
            code_challenge = base64.urlsafe_b64encode(code_challenge).decode("utf-8")  # type: ignore[assignment]
            code_challenge = code_challenge.replace("=", "")  # type: ignore[arg-type]

            state = uuid.uuid4()
            http = urllib3.PoolManager()
            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "scope": "openid",
                "redirect_uri": self.BASE_URL,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }

            url_with_params = provider + "/protocol/openid-connect/auth?" + urllib.parse.urlencode(params)

            resp = http.request(
                "GET",
                url_with_params,
                redirect=False
            )

            cookie = resp.headers["Set-Cookie"]
            cookie = "; ".join(c.split(";")[0] for c in cookie.split(", "))

            page = resp.data.decode("utf-8")
            form_action = html.unescape(
                re.search('<form\\s+.*?\\s+action="(.*?)"', page, re.DOTALL).group(1))  # type: ignore[union-attr]

            form_data = {
                "username": username,
                "password": password,
            }

            encoded_data = urllib.parse.urlencode(form_data)

            resp = http.request(
                "POST",
                form_action,
                body=encoded_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": cookie,
                },
                redirect=False
            )

            redirect = resp.headers["Location"]
            assert redirect.startswith(self.BASE_URL)

            query = urllib.parse.urlparse(redirect).query
            redirect_params = urllib.parse.parse_qs(query)

            auth_code = redirect_params["code"][0]

            token_url = provider + "/protocol/openid-connect/token"

            data = {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "redirect_uri": self.BASE_URL,
                "code": auth_code,
                "code_verifier": code_verifier,
            }

            encoded_data = urllib.parse.urlencode(data)

            resp = http.request(
                "POST",
                token_url,
                body=encoded_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                redirect=False
            )
        except Exception as ex:
            raise AuthError("Failed to login.") from ex

        if resp.status == self.SUCCESS_STATUS_CODE:
            result = resp.json()
            self.access_token = result["access_token"]
            self.expiration = self._get_access_token_expiry_time()
            self.refresh_token = result["refresh_token"]
        else:
            raise AuthError(f"Login attempt failed: {resp.status} {resp.data.decode('utf-8')}")


class AuthError(Exception):
    """Exception raised for failed initial login or access token refreshing.

     Attributes:
         message -- explanation of the error
     """

    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)
