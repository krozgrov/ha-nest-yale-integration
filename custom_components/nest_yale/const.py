import os
import certifi
from datetime import timedelta

# User-Agent string to mimic a real browser (from nest-endpoints.js and nest-connection.js)
USER_AGENT_STRING = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36"
)

# Nest API Hostnames (from nest-endpoints.js)
PRODUCTION_HOSTNAME = {
    "api_hostname": "home.nest.com",
    "camera_api_hostname": "webapi.camera.home.nest.com",
    "grpc_hostname": "grpc-web.production.nest.com",
    "cam_auth_cookie": "website_2",
}

FIELD_TEST_HOSTNAME = {
    "api_hostname": "home.ft.nest.com",
    "camera_api_hostname": "webapi.camera.home.ft.nest.com",
    "grpc_hostname": "grpc-web.ft.nest.com",
    "cam_auth_cookie": "website_ft",
}

# Default Fan and Hot Water Durations (from nest-connection.js)
DEFAULT_FAN_DURATION_MINUTES = 15
DEFAULT_HOT_WATER_DURATION_MINUTES = 30

# Timing and Retry Constants (from nest-connection.js)
API_AUTH_FAIL_RETRY_DELAY_SECONDS = 15
API_AUTH_FAIL_RETRY_LONG_DELAY_SECONDS = 60 * 60  # 1 hour
API_SUBSCRIBE_DELAY_SECONDS = 0.1
API_PUSH_DEBOUNCE_SECONDS = 2
API_PUSH_DEBOUNCE_MAXWAIT_SECONDS = 8
API_MERGE_PENDING_MAX_SECONDS = 8
API_MODE_CHANGE_DELAY_SECONDS = 7
API_SUBSCRIBE_TIMEOUT_SECONDS = 120
API_OBSERVE_TIMEOUT_SECONDS = 130
API_TIMEOUT_SECONDS = 40
API_RETRY_DELAY_SECONDS = 10
API_GOOGLE_REAUTH_MINUTES = 55
API_NEST_REAUTH_MINUTES = 20 * 24 * 60  # 20 days
API_HTTP2_PING_INTERVAL_SECONDS = 60

# REST API Endpoints (from nest-endpoints.js)
URL_NEST_AUTH = "https://{api_hostname}/session"
URL_NEST_VERIFY_PIN = "https://{api_hostname}/api/0.1/2fa/verify_pin"
ENDPOINT_PUT = "/v5/put"
ENDPOINT_SUBSCRIBE = "/v5/subscribe"

# Protobuf API Endpoints (from nest-endpoints.js)
URL_PROTOBUF = "https://{grpc_hostname}"
ENDPOINT_OBSERVE = "/nestlabs.gateway.v2.GatewayService/Observe"
ENDPOINT_UPDATE = "/nestlabs.gateway.v1.TraitBatchApi/BatchUpdateState"
ENDPOINT_SENDCOMMAND = "/nestlabs.gateway.v1.ResourceApi/SendCommand"

# Google OAuth2 Token URL (from nest-connection.js and second login.js)
TOKEN_URL = "https://oauth2.googleapis.com/token"

# Client IDs (from nest-connection.js and second login.js)
CLIENT_ID = "733249279899-1gpkq9duqmdp55a7e5lft1pr2smumdla.apps.googleusercontent.com"
CLIENT_ID_FT = "384529615266-57v6vaptkmhm64n9hn5dcmkr4at14p8j.apps.googleusercontent.com"

# Home Assistant Integration Constants
DOMAIN = "nest_yale"
PLATFORMS = ["lock"]
CONF_ISSUE_TOKEN = "issue_token"
CONF_API_KEY = "api_key"
CONF_COOKIES = "cookies"
UPDATE_INTERVAL_SECONDS = timedelta(seconds=30)  # Use timedelta for DataUpdateCoordinator

# SSL Certificate Path
SSL_VERIFY_PATH = certifi.where()

def parse_cookies(cookie_string):
    """Parses a cookie string into a dictionary."""
    cookies = {}
    for cookie in cookie_string.split(';'):
        if '=' in cookie:
            key, value = cookie.strip().split('=', 1)
            cookies[key] = value
    return cookies