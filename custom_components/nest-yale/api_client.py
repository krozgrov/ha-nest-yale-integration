import aiohttp
from .const import (
    FIELD_TEST_MODE,
    PRODUCTION_HOSTNAME,
    FIELD_TEST_HOSTNAME,
    USER_AGENT_STRING,
    REST_ENDPOINTS,
    PROTOBUF_ENDPOINTS,
    REQUEST_TIMEOUT,
    SUCCESS_STATUS_CODES,
    RETRY_COUNT,
)


class APIClient:
    def __init__(self, session, issue_token, api_key, cookies, field_test_mode=FIELD_TEST_MODE):
        """Initialize the API client."""
        self.session = session
        self.issue_token = issue_token
        self.api_key = api_key
        self.cookies = cookies

        # Set environment mode (Field Test or Production)
        self.environment = FIELD_TEST_HOSTNAME if field_test_mode else PRODUCTION_HOSTNAME

        # Hostnames and Cookie Configuration
        self.api_hostname = self.environment["api_hostname"]
        self.grpc_hostname = self.environment["grpc_hostname"]
        self.cam_auth_cookie = self.environment["cam_auth_cookie"]

        # User-Agent
        self.user_agent = USER_AGENT_STRING

    async def send_request(self, method, endpoint, json=None, data=None, headers=None, retries=RETRY_COUNT):
        """Send a generic REST API request."""
        url = f"https://{self.api_hostname}{endpoint}"
        headers = headers or {}
        headers.update({"User-Agent": self.user_agent, "Authorization": f"Bearer {self.issue_token}"})
        try:
            for attempt in range(retries):
                async with self.session.request(
                    method, url, json=json, data=data, headers=headers, cookies=self.cookies, timeout=REQUEST_TIMEOUT
                ) as response:
                    if response.status in SUCCESS_STATUS_CODES:
                        return await response.json()
                    else:
                        if attempt < retries - 1:
                            continue
                        raise Exception(f"API request failed with status {response.status}: {await response.text()}")
        except Exception as e:
            raise Exception(f"Error in {method} request to {endpoint}: {str(e)}")

    async def send_protobuf_request(self, endpoint, protobuf_data):
        """Send a Protobuf API request."""
        url = f"https://{self.grpc_hostname}{endpoint}"
        headers = {
            "Authorization": f"Bearer {self.issue_token}",
            "Content-Type": "application/x-protobuf",
            "x-goog-api-key": self.api_key,
            "User-Agent": self.user_agent,
        }
        try:
            async with self.session.post(
                url, headers=headers, data=protobuf_data, cookies=self.cookies, timeout=REQUEST_TIMEOUT
            ) as response:
                if response.status not in SUCCESS_STATUS_CODES:
                    raise Exception(f"Protobuf request failed with status {response.status}: {await response.text()}")
                return await response.read()
        except Exception as e:
            raise Exception(f"Error in Protobuf request to {endpoint}: {str(e)}")

    async def authenticate(self):
        """Authenticate with the Nest API."""
        return await self.send_request("GET", REST_ENDPOINTS["auth"])

    async def verify_pin(self, pin):
        """Verify the 2FA pin."""
        json_data = {"pin": pin}
        return await self.send_request("POST", REST_ENDPOINTS["verify_pin"], json=json_data)

    async def observe_traits(self, resource_id):
        """Observe traits using Protobuf."""
        from .protobuf.compiled import ObserveTraits_pb2

        request = ObserveTraits_pb2.ObserveTraitsRequest()
        request.resource_id = resource_id
        serialized_request = request.SerializeToString()

        # Use Protobuf endpoint
        return await self.send_protobuf_request(PROTOBUF_ENDPOINTS["observe"], serialized_request)

    async def send_command(self, resource_id, command):
        """Send a command to a resource."""
        from .protobuf.compiled import ResourceCommand_pb2

        request = ResourceCommand_pb2.SendCommandRequest()
        request.resource_id = resource_id
        request.command.CopyFrom(command)  # Assuming `command` is already a Protobuf message
        serialized_request = request.SerializeToString()

        # Use Protobuf endpoint
        return await self.send_protobuf_request(PROTOBUF_ENDPOINTS["send_command"], serialized_request)

    async def get_devices(self):
        """Fetch devices using Protobuf."""
        from .protobuf.compiled import GetDevices_pb2

        request = GetDevices_pb2.GetDevicesRequest()
        serialized_request = request.SerializeToString()

        # Send request to discover devices
        response = await self.send_protobuf_request(PROTOBUF_ENDPOINTS["observe"], serialized_request)

        # Parse response
        devices_response = GetDevices_pb2.GetDevicesResponse()
        devices_response.ParseFromString(response)
        return devices_response.devices