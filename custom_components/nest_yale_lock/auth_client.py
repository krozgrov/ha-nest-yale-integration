import logging
import jwt
from .auth import NestAuthenticator
from .const import API_RETRY_DELAY_SECONDS

_LOGGER = logging.getLogger(__name__)

class NestAuthClient:
    def __init__(self, issue_token, api_key, cookies, session):
        self.authenticator = NestAuthenticator(issue_token, api_key, cookies)
        self.session = session
        self.access_token = None
        self.auth_data = {}
        self.transport_url = None
        self._user_id = None

    @property
    def user_id(self):
        return self._user_id

    async def authenticate(self):
        _LOGGER.debug("Authenticating with Nest API")
        try:
            self.auth_data = await self.authenticator.authenticate(self.session)
            _LOGGER.debug(f"Raw auth data received: {self.auth_data}")
            if not self.auth_data or "access_token" not in self.auth_data:
                raise ValueError("Invalid authentication data received")
            self.access_token = self.auth_data["access_token"]
            self.transport_url = self.auth_data.get("urls", {}).get("transport_url")
            id_token = self.auth_data.get("id_token")
            if id_token:
                decoded = jwt.decode(id_token, options={"verify_signature": False})
                self._user_id = decoded.get("sub", None)
                _LOGGER.info(f"Initial user_id from id_token: {self._user_id}")
            else:
                _LOGGER.warning("No id_token in auth_data, awaiting stream for user_id")
            _LOGGER.info(f"Authenticated with access_token: {self.access_token[:10]}..., user_id: {self._user_id}")
        except Exception as e:
            _LOGGER.error(f"Authentication failed: {e}", exc_info=True)
            raise

    async def ensure_authenticated(self):
        if not self.access_token:
            await self.authenticate()