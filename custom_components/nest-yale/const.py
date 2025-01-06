# Integration Domain
DOMAIN = "nest_yale"

# Supported Platforms
PLATFORMS = ["lock"]

# Configuration Keys
CONF_API_KEY = "api_key"
CONF_ISSUE_TOKEN = "issue_token"
CONF_COOKIES = "cookies"

# Default Values for Configuration
DEFAULT_NAME = "Nest Yale Lock"

# API Environment Modes
FIELD_TEST_MODE = False  # Set to True for field test environments

# Hostnames
PRODUCTION_HOSTNAME = {
    "api_hostname": "home.nest.com",
    "grpc_hostname": "grpc-web.production.nest.com",
    "cam_auth_cookie": "website_2",
}

FIELD_TEST_HOSTNAME = {
    "api_hostname": "home.ft.nest.com",
    "grpc_hostname": "grpc-web.ft.nest.com",
    "cam_auth_cookie": "website_ft",
}

# User-Agent String
USER_AGENT_STRING = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_0) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/77.0.3865.120 Safari/537.36"
)

# Endpoints
REST_ENDPOINTS = {
    "auth": "/session",
    "verify_pin": "/api/0.1/2fa/verify_pin",
    "put": "/v5/put",
    "subscribe": "/v5/subscribe",
}

PROTOBUF_ENDPOINTS = {
    "observe": "/nestlabs.gateway.v2.GatewayService/Observe",
    "update": "/nestlabs.gateway.v1.TraitBatchApi/BatchUpdateState",
    "send_command": "/nestlabs.gateway.v1.ResourceApi/SendCommand",
}

# Protobuf Schema
PROTOBUF_FOLDER = "custom_components/nest_yale/protobuf"  # Folder for .proto files
PROTOBUF_COMPILED_FOLDER = "custom_components/nest_yale/protobuf/compiled"  # Folder for compiled Protobuf files

# Device Types
DEVICE_TYPE_LOCK = "lock"

# API Request Settings
REQUEST_TIMEOUT = 10  # Timeout for API requests in seconds
RETRY_COUNT = 3  # Number of retries for failed requests
TOKEN_REFRESH_INTERVAL = 3600  # Interval to refresh tokens (in seconds)

# Response Handling
SUCCESS_STATUS_CODES = [200, 201]  # HTTP status codes indicating success

# Logging Configuration
LOGGING_LEVEL = "DEBUG"  # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)