# Integration Domain
DOMAIN = "nest_yale"

# Supported Platforms
PLATFORMS = ["lock"]  # Currently, only the lock platform is supported

# Configuration Keys
CONF_API_KEY = "api_key"
CONF_ISSUE_TOKEN = "issue_token"
CONF_COOKIES = "cookies"

# Default Values for Configuration
DEFAULT_NAME = "Nest Yale Lock"

# API Base URL
API_BASE_URL = "https://your-api-endpoint"  # Replace with the actual API base endpoint

# Authentication Defaults
ISSUE_TOKEN = "your_issue_token"  # Replace with the actual token during testing
API_KEY = "your_api_key"  # Replace with your API key during testing
COOKIES = {
    "__Secure-3PSID": "your_secure_cookie_value",  # Replace with your secure cookie
}

# API Endpoints
ENDPOINTS = {
    "lock_control": "control/lock",  # Endpoint for lock/unlock commands
    "device_status": "status/device",  # Endpoint for querying device status
    "auth_refresh": "auth/refresh",  # Endpoint for refreshing tokens
}

# Lock Platform Specific Constants
LOCK_DOMAIN = "lock"
LOCK_DEVICE_TYPE = "Nest Yale Lock"
LOCK_SUPPORTED_FEATURES = ["lock", "unlock"]

# Request Settings
REQUEST_TIMEOUT = 10  # Timeout for API requests in seconds
RETRY_COUNT = 3  # Number of retries for failed requests
TOKEN_REFRESH_INTERVAL = 3600  # Interval to refresh tokens (in seconds)

# Response Handling
SUCCESS_STATUS_CODES = [200, 201]  # HTTP status codes indicating success

# Logging Configuration
LOGGING_LEVEL = "DEBUG"  # Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)

# Protobuf Schema
PROTOBUF_FOLDER = "custom_components/nest_yale/protobuf"  # Folder for .proto files
PROTOBUF_COMPILED_FOLDER = "custom_components/nest_yale/protobuf/compiled"  # Folder for compiled Protobuf files

# Protobuf-Related Settings
LOCK_SCHEMA = "security.proto"  # Protobuf schema file for lock-related traits
COMMON_SCHEMA = "common.proto"  # Protobuf schema file for shared traits

# Device Types
DEVICE_TYPE_LOCK = "lock"  # Device type for Nest x Yale Lock