from stix_shifter_utils.utils.error_mapper_base import ErrorMapperBase
from stix_shifter_utils.utils.error_response import ErrorCode
from stix_shifter_utils.utils import logger

# Keys are the Criminal IP body "status" values (errors usually arrive as HTTP 200 with the real status in the
# body), HTTP status codes for non-2xx responses, and the symbolic codes raised by api_client.py.
error_mapping = {
    # Bad request: "Missing Parameter", "Invalid Offset.", "Offset must not be over than 9900",
    # "Invalid filter combination."
    400: ErrorCode.TRANSMISSION_QUERY_PARSING_ERROR,
    401: ErrorCode.TRANSMISSION_AUTH_CREDENTIALS,
    # "check access failed": the x-api-key header is missing or empty
    403: ErrorCode.TRANSMISSION_AUTH_CREDENTIALS,
    # Unknown path: wrong host or API version
    404: ErrorCode.TRANSMISSION_INVALID_PARAMETER,
    # Request timed out
    408: ErrorCode.TRANSMISSION_CONNECT,
    # "Missing Parameter" (domain service)
    412: ErrorCode.TRANSMISSION_INVALID_PARAMETER,
    # "Unexpected Parameter"
    420: ErrorCode.TRANSMISSION_INVALID_PARAMETER,
    429: ErrorCode.TRANSMISSION_TOO_MANY_REQUESTS,
    # "internal server error" (when the API key was confirmed valid)
    500: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    502: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    503: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    504: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    # Cloudflare origin errors (520 unknown, 521 down, 522 connection timed out, 523 unreachable, 524 timeout)
    520: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    521: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    522: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    523: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    524: ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
    # Symbolic codes from api_client.CriminalIPResponseError
    'invalid_api_key': ErrorCode.TRANSMISSION_AUTH_CREDENTIALS,
    'results_limited': ErrorCode.TRANSMISSION_FORBIDDEN,
    # 403 "unable to call api at the same time" (per-key concurrency limit), still failing after retries
    'concurrent_limit': ErrorCode.TRANSMISSION_TOO_MANY_REQUESTS,
    'cloudflare_challenge': ErrorCode.TRANSMISSION_FORBIDDEN,
    'non_json_response': ErrorCode.TRANSMISSION_REMOTE_SYSTEM_IS_UNAVAILABLE,
}


class ErrorMapper:
    logger = logger.set_logger(__name__)
    DEFAULT_ERROR = ErrorCode.TRANSMISSION_MODULE_DEFAULT_ERROR

    @staticmethod
    def set_error_code(json_data, return_obj, connector=None):
        code = None
        try:
            code = json_data['code']
            if not isinstance(code, str) or code.isdigit():
                code = int(code)
        except Exception:
            pass

        error_code = error_mapping.get(code, ErrorMapper.DEFAULT_ERROR)

        if error_code == ErrorMapper.DEFAULT_ERROR:
            ErrorMapper.logger.error("failed to map: " + str(json_data))

        ErrorMapperBase.set_error_code(return_obj, error_code, connector=connector)
