import json

from stix_shifter_utils.stix_transmission.utils.RestApiClientAsync import RestApiClientAsync
from stix_shifter_utils.utils import logger


class CriminalIPResponseError(Exception):
    """A Criminal IP response that could not be used: transport problem, non-JSON body or a non-200 body status.

    ``code`` is either the body ``status`` returned by Criminal IP (400, 403, 404, 420, 500, ...), an HTTP status
    for non-2xx responses, or one of the symbolic codes below. ``error_mapper.py`` maps them to stix-shifter
    ErrorCodes. ``message`` never contains the API key or the raw response body of ``/v1/user/me``.
    """
    CLOUDFLARE_CHALLENGE = 'cloudflare_challenge'
    NON_JSON_RESPONSE = 'non_json_response'
    INVALID_API_KEY = 'invalid_api_key'
    RESULTS_LIMITED = 'results_limited'
    CONCURRENT_LIMIT = 'concurrent_limit'

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class APIClient:
    PING_ENDPOINT = 'v1/user/me'
    SEARCH_ENDPOINT = 'v2/banner/search'
    USER_AGENT = 'stix-shifter-criminalip/1.0'

    def __init__(self, connection, configuration):
        self.logger = logger.set_logger(__name__)
        auth = configuration.get('auth', {})
        headers = {
            'x-api-key': auth.get('api_key', ''),
            'Accept': 'application/json',
            'User-Agent': self.USER_AGENT,
        }
        self.client = RestApiClientAsync(connection.get('host'),
                                         connection.get('port'),
                                         headers,
                                         cert_verify=connection.get('selfSignedCert', None))
        self.timeout = connection.get('options', {}).get('timeout')

    async def ping_data_source(self):
        """POST /v1/user/me. An explicit empty body plus Content-Length: 0 is required, otherwise Cloudflare
        answers with an HTML challenge page. The response echoes the API key, so only the status is kept."""
        response = await self.client.call_api(self.PING_ENDPOINT, 'POST',
                                              headers={'Content-Length': '0'},
                                              data=b'', timeout=self.timeout)
        body = self._parse(response, is_ping=True)
        return {'status': body.get('status'), 'message': body.get('message')}

    async def search(self, query, offset):
        """GET /v2/banner/search for one page. Returns the parsed ``data`` object ({groups, count, result})."""
        response = await self.client.call_api(self.SEARCH_ENDPOINT, 'GET',
                                              urldata={'query': query, 'offset': int(offset)},
                                              timeout=self.timeout)
        body = self._parse(response)
        data = body.get('data')
        if not isinstance(data, dict):
            data = {}
        return data

    @staticmethod
    def _header(headers, name):
        if not headers:
            return None
        try:
            for key in headers:
                if key.lower() == name.lower():
                    return headers[key]
        except TypeError:
            return None
        return None

    def _parse(self, response, is_ping=False):
        code = response.code
        headers = response.headers
        raw = response.read()
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode('utf-8', errors='replace')
        raw = raw or ''

        content_type = (self._header(headers, 'Content-Type') or '').lower()
        if self._header(headers, 'cf-mitigated') or (code == 403 and 'html' in content_type):
            raise CriminalIPResponseError(
                CriminalIPResponseError.CLOUDFLARE_CHALLENGE,
                'Request was blocked by the Cloudflare challenge in front of the Criminal IP API '
                '(HTTP {})'.format(code))

        body = None
        if 'html' not in content_type:
            try:
                body = json.loads(raw)
            except ValueError:
                body = None
        if not isinstance(body, dict):
            if code == 429:
                raise CriminalIPResponseError(429, 'Criminal IP rate limit hit: Too Many Requests (HTTP 429)')
            if code >= 400:
                raise CriminalIPResponseError(code, 'Criminal IP returned HTTP {} with a non-JSON body'.format(code))
            raise CriminalIPResponseError(
                CriminalIPResponseError.NON_JSON_RESPONSE,
                'Criminal IP returned a non-JSON response (HTTP {}, content type "{}")'.format(code, content_type))

        status = body.get('status', code)
        try:
            status = int(status)
        except (TypeError, ValueError):
            status = code
        if status == 200 and 200 <= code < 300:
            return body

        message = str(body.get('message') or 'HTTP {}'.format(code))
        if status == 200:
            status = code
        if 'at the same time' in message.lower():
            # 403 "unable to call api at the same time": per-key concurrency limit. Transient, not an auth failure.
            raise CriminalIPResponseError(CriminalIPResponseError.CONCURRENT_LIMIT,
                                          'Criminal IP concurrency limit for this API key: {}'.format(message))
        if 'results are limited' in message.lower():
            # 403/420 "Results are limited": the query went past the plan's queryable range.
            raise CriminalIPResponseError(CriminalIPResponseError.RESULTS_LIMITED,
                                          'Criminal IP plan limit reached: {}'.format(message))
        if is_ping and status == 500:
            # A bad x-api-key returns {"status": 500, "message": "internal server error"} on /v1/user/me.
            raise CriminalIPResponseError(CriminalIPResponseError.INVALID_API_KEY,
                                          'Criminal IP rejected the API key ({})'.format(message))
        raise CriminalIPResponseError(status, 'Criminal IP returned status {}: {}'.format(status, message))
