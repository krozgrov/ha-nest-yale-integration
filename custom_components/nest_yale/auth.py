import aiohttp
import asyncio
import urllib.parse
import logging
from .const import (
    API_TIMEOUT_SECONDS,
    TOKEN_URL,
    CLIENT_ID,
    CLIENT_ID_FT,
    USER_AGENT_STRING,
    PRODUCTION_HOSTNAME,
    API_AUTH_FAIL_RETRY_DELAY_SECONDS,
    parse_cookies,
)

_LOGGER = logging.getLogger(__name__)

class NestAuthenticator:
    """Handles authentication with Google for Nest integration."""

    def __init__(self, issue_token, api_key, cookies):
        self.issue_token = issue_token
        self.api_key = api_key
        if isinstance(cookies, str):
            self.cookies = parse_cookies(cookies)
        elif isinstance(cookies, dict):
            self.cookies = cookies
        else:
            _LOGGER.warning(f"Invalid cookies type: {type(cookies)}. Defaulting to empty dict.")
            self.cookies = {}
        self.access_token = None
        # also capture id_token from Google response
        self.id_token = None
        _LOGGER.debug("NestAuthenticator initialized with updated auth.py")

    @staticmethod
    def generate_token(ft=False):
        """Generate OAuth URL for user authorization."""
        data = {
            "access_type": "offline",
            "response_type": "code",
            "scope": "openid profile email https://www.googleapis.com/auth/nest-account",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "client_id": CLIENT_ID_FT if ft else CLIENT_ID
        }
        return f"https://accounts.google.com/o/oauth2/auth/oauthchooseaccount?{urllib.parse.urlencode(data)}"

    async def get_refresh_token(self, code, ft=False):
        """Exchange authorization code for a refresh token."""
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=API_TIMEOUT_SECONDS)) as session:
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT_STRING
            }
            data = {
                "code": code,
                "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                "client_id": CLIENT_ID_FT if ft else CLIENT_ID,
                "grant_type": "authorization_code"
            }
            try:
                async with session.post(TOKEN_URL, headers=headers, data=data) as response:
                    result = await response.json()
                    if "refresh_token" in result:
                        return result["refresh_token"]
                    else:
                        raise ValueError(f"Error retrieving refresh token: {result.get('error_description', result)}")
            except Exception as e:
                _LOGGER.error(f"Failed to get refresh token: {e}")
                return None

    async def authenticate(self, session=None):
        """Perform authentication and get an access token using Google OAuth."""
        _LOGGER.debug("Running updated authenticate method in auth.py")
        headers = {
            "Sec-Fetch-Mode": "cors",
            "User-Agent": USER_AGENT_STRING,
            "X-Requested-With": "XmlHttpRequest",
            "Referer": "https://accounts.google.com/o/oauth2/iframe"
        }

        # Validate or create session
        if session is None or not isinstance(session, aiohttp.ClientSession):
            _LOGGER.warning("Received invalid session, creating a new one")
            session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=API_TIMEOUT_SECONDS))
            own_session = True
        else:
            _LOGGER.debug("Using provided session")
            own_session = False

        try:
            for attempt in range(3):
                try:
                    # Step 1: Fetch Google access token
                    _LOGGER.debug(f"Attempting to fetch Google token with issue_token: {self.issue_token}")
                    _LOGGER.debug(f"Using cookies: {self.cookies}")
                    _LOGGER.debug("Sending GET request...")
                    async with session.get(
                        self.issue_token,
                        headers=headers,
                        cookies=self.cookies,
                        timeout=aiohttp.ClientTimeout(total=API_TIMEOUT_SECONDS)
                    ) as resp:
                        _LOGGER.debug(f"Response received: {resp.status}")
                        if resp.status != 200:
                            raise ValueError(f"HTTP error: {resp.status} - {await resp.text()}")
                        raw_response = await resp.text()
                        _LOGGER.debug(f"Raw Google response text: {raw_response}")
                        try:
                            _LOGGER.debug("Parsing JSON...")
                            google_data = await resp.json()
                        except ValueError as e:
                            _LOGGER.error(f"Failed to parse Google response as JSON: {e} - Raw response: {raw_response}")
                            raise ValueError(f"Google response not valid JSON: {raw_response}")
                        _LOGGER.debug(f"JSON parsed, google_data type: {type(google_data)}")
                        if google_data is None or not isinstance(google_data, dict):
                            _LOGGER.error(f"Invalid Google response (None or not a dict): {raw_response}")
                            raise ValueError(f"Google response is not a valid JSON dict: {raw_response}")
                        _LOGGER.debug(f"Google response: {google_data}")
                        google_token = google_data.get("access_token")
                        # capture Google's ID token for downstream structureId lookup
                        self.id_token = google_data.get("id_token")
                        if not google_token:
                            error_msg = google_data.get("error", "Unknown error")
                            error_detail = google_data.get("detail", "No details provided")
                            raise ValueError(f"No Google access token received: {error_msg} - {error_detail}")

                    # Step 2: Exchange for Nest JWT
                    nest_url = "https://nestauthproxyservice-pa.googleapis.com/v1/issue_jwt"
                    nest_headers = {
                        "Authorization": f"Bearer {google_token}",
                        "User-Agent": USER_AGENT_STRING,
                        "Referer": f"https://{PRODUCTION_HOSTNAME['api_hostname']}"
                    }
                    if self.api_key:
                        nest_headers["x-goog-api-key"] = self.api_key

                    nest_data = {
                        "embed_google_oauth_access_token": True,
                        "expire_after": "3600s",
                        "google_oauth_access_token": google_token,
                        "policy_id": "authproxy-oauth-policy"
                    }

                    _LOGGER.debug(f"Exchanging Google token for Nest JWT at {nest_url}")
                    async with session.post(
                        nest_url,
                        headers=nest_headers,
                        json=nest_data,
                        timeout=aiohttp.ClientTimeout(total=API_TIMEOUT_SECONDS)
                    ) as nest_resp:
                        _LOGGER.debug(f"Nest response received: {nest_resp.status}")
                        if nest_resp.status != 200:
                            raise ValueError(f"Nest HTTP error: {nest_resp.status} - {await nest_resp.text()}")
                        raw_nest_response = await nest_resp.text()
                        _LOGGER.debug(f"Raw Nest response text: {raw_nest_response}")
                        try:
                            result = await nest_resp.json()
                        except ValueError as e:
                            _LOGGER.error(f"Failed to parse Nest response as JSON: {e} - Raw response: {raw_nest_response}")
                            raise ValueError(f"Nest response not valid JSON: {raw_nest_response}")
                        if result is None or not isinstance(result, dict):
                            _LOGGER.error(f"Invalid Nest response (None or not a dict): {raw_nest_response}")
                            raise ValueError(f"Nest response is not a valid JSON dict: {raw_nest_response}")
                        _LOGGER.debug(f"Nest response: {result}")
                        self.access_token = result.get("jwt")
                        if not self.access_token:
                            raise ValueError("No Nest JWT received from nestauthproxyservice")

                    _LOGGER.debug("Authenticated successfully with JWT token")
                    return {
                        "access_token": self.access_token,
                        "id_token": self.id_token,
                        "userid": "unknown",
                        "urls": {"transport_url": f"https://{PRODUCTION_HOSTNAME['api_hostname']}"}
                    }

                except aiohttp.ClientError as e:
                    _LOGGER.error(f"Request error on attempt {attempt + 1}: {e}")
                    if attempt < 2:
                        _LOGGER.warning(f"Retrying in {API_AUTH_FAIL_RETRY_DELAY_SECONDS} seconds...")
                        await asyncio.sleep(API_AUTH_FAIL_RETRY_DELAY_SECONDS)
                    else:
                        return None
                except ValueError as e:
                    _LOGGER.error(f"Value error on attempt {attempt + 1}: {e}")
                    return None
                except Exception as e:
                    _LOGGER.error(f"Unexpected error on attempt {attempt + 1}: {type(e).__name__}: {e}")
                    return None

            _LOGGER.error("All authentication attempts failed")
            return None

        finally:
            if own_session:
                await session.close()
                _LOGGER.debug("Authenticator session closed")