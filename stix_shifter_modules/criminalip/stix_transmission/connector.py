import asyncio
import re
import time

from stix_shifter_utils.modules.base.stix_transmission.base_json_sync_connector import BaseJsonSyncConnector
from stix_shifter_utils.utils.error_response import ErrorResponder
from stix_shifter_utils.utils import logger
from .api_client import APIClient, CriminalIPResponseError
from ..stix_translation.post_filter import parse_search_id, record_matches

# Matches the filter names in a Criminal IP query string, e.g. "ip" and "port" in "ip: 8.8.8.0/24 port: 443".
FILTER_NAME_RE = re.compile(r'(?:^|\s)([A-Za-z_]+)\s*:')


class Connector(BaseJsonSyncConnector):
    # Banner search accepts offsets 0..9900 (at most 10,000 records per query).
    MAX_API_OFFSET = 9900
    DEFAULT_RESULT_LIMIT = 100
    DEFAULT_MAX_API_CALLS = 10
    # Criminal IP sends no rate-limit headers; keep successive page calls at or below about 2 per second.
    MIN_CALL_INTERVAL = 0.5
    # Retries after the per-key concurrency error ("unable to call api at the same time"), waiting
    # CONCURRENCY_BACKOFF * attempt seconds before each one.
    CONCURRENCY_RETRIES = 2
    CONCURRENCY_BACKOFF = 3

    def __init__(self, connection, configuration):
        self.api_client = APIClient(connection, configuration)
        self.logger = logger.set_logger(__name__)
        self.connector = __name__.split('.')[1]
        options = connection.get('options', {})
        self.result_limit = self._positive_int(options.get('result_limit'), self.DEFAULT_RESULT_LIMIT)
        self.max_api_calls = self._positive_int(options.get('max_api_calls'), self.DEFAULT_MAX_API_CALLS)
        self._last_call = None

    @staticmethod
    def _positive_int(value, default):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return default
        return value if value > 0 else default

    def _fill_error(self, return_obj, code, message):
        ErrorResponder.fill_error(return_obj, {'code': code, 'message': message}, ['message'],
                                  connector=self.connector)
        return return_obj

    def _fill_exception(self, return_obj, ex):
        if isinstance(ex, CriminalIPResponseError):
            return self._fill_error(return_obj, ex.code, ex.message)
        message = str(ex)
        code = 408 if 'timeout_error' in message else None
        self.logger.error('Criminal IP request failed: %s', message)
        return self._fill_error(return_obj, code, message)

    async def _with_concurrency_retry(self, func, *args):
        attempt = 0
        while True:
            try:
                return await func(*args)
            except CriminalIPResponseError as ex:
                if ex.code != CriminalIPResponseError.CONCURRENT_LIMIT or attempt >= self.CONCURRENCY_RETRIES:
                    raise
                attempt += 1
                self.logger.info('Criminal IP concurrency limit hit; retry %s of %s', attempt,
                                 self.CONCURRENCY_RETRIES)
                await asyncio.sleep(self.CONCURRENCY_BACKOFF * attempt)

    async def ping_connection(self):
        return_obj = {}
        try:
            await self._with_concurrency_retry(self.api_client.ping_data_source)
            return_obj['success'] = True
        except Exception as ex:
            self._fill_exception(return_obj, ex)
        return return_obj

    async def _throttle(self):
        if self._last_call is not None:
            wait = self.MIN_CALL_INTERVAL - (time.monotonic() - self._last_call)
            if wait > 0:
                await asyncio.sleep(wait)
        self._last_call = time.monotonic()

    async def _search_page(self, query, api_offset):
        await self._throttle()
        try:
            return await self._with_concurrency_retry(self.api_client.search, query, api_offset)
        except CriminalIPResponseError as ex:
            if ex.code == 500:
                # A bad API key also produces "internal server error" on search. Ask /v1/user/me once to
                # tell an authentication failure apart from a server-side error.
                try:
                    await self.api_client.ping_data_source()
                except CriminalIPResponseError as ping_ex:
                    if ping_ex.code in (CriminalIPResponseError.INVALID_API_KEY, 403):
                        raise ping_ex
                except Exception:
                    pass
            raise

    def _check_filters_recognised(self, query, data):
        """Criminal IP silently turns unknown filter names into keywords. Warn when that happens."""
        sent = {name.lower() for name in FILTER_NAME_RE.findall(query or '')}
        if not sent:
            return
        recognised = set()
        for group in data.get('groups') or []:
            for item in group.get('filters') or []:
                if item.get('key'):
                    recognised.add(str(item['key']).lower())
        missing = sent - recognised
        if missing:
            self.logger.warning('Criminal IP did not recognise filter(s) %s in query "%s"; they were treated as '
                                'keywords', sorted(missing), query)

    def _start_position(self, offset, post_filter, metadata):
        """Returns (api_offset, filtered_seen) to start scanning from.

        filtered_seen counts records that passed the post filter before api_offset, i.e. the stix offset of
        the next record. Without a post filter, the API offset is the stix offset."""
        if isinstance(metadata, dict):
            try:
                api_offset = int(metadata['api_offset'])
                filtered_seen = int(metadata['filtered_seen'])
                if 0 <= filtered_seen <= offset and api_offset >= 0:
                    return api_offset, filtered_seen
            except (KeyError, TypeError, ValueError):
                pass
            self.logger.debug('Ignoring unusable metadata: %s', metadata)
        if not post_filter:
            return offset, offset
        return 0, 0

    async def create_results_connection(self, search_id, offset, length, metadata=None):
        return_obj = {}
        try:
            offset = max(int(offset), 0)
            length = max(int(length), 0)
            query, post_filter = parse_search_id(search_id)
            end = min(offset + length, self.result_limit)
            api_offset, position = self._start_position(offset, post_filter, metadata)

            data = []
            calls = 0
            exhausted = False
            while position < end:
                if api_offset > self.MAX_API_OFFSET:
                    exhausted = True
                    break
                if calls >= self.max_api_calls:
                    self.logger.info('Stopped after max_api_calls (%s) Criminal IP calls', self.max_api_calls)
                    break
                page = await self._search_page(query, api_offset)
                calls += 1
                if calls == 1:
                    self._check_filters_recognised(query, page)
                records = page.get('result') or []
                if not records:
                    exhausted = True
                    break
                for record in records:
                    if position >= end:
                        break
                    api_offset += 1
                    if record_matches(record, post_filter):
                        if position >= offset:
                            data.append(record)
                        position += 1
                count = page.get('count')
                if isinstance(count, int) and api_offset >= count:
                    exhausted = True
                    break

            return_obj['success'] = True
            return_obj['data'] = data
            if not exhausted and position < self.result_limit and api_offset <= self.MAX_API_OFFSET:
                # More records may follow. The caller can pass this back to resume without rescanning.
                return_obj['metadata'] = {'api_offset': api_offset, 'filtered_seen': position}
        except Exception as ex:
            return_obj = {}
            self._fill_exception(return_obj, ex)
        return return_obj
