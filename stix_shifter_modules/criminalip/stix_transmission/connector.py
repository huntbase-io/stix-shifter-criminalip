import asyncio
import re
import time

from stix_shifter_utils.modules.base.stix_transmission.base_json_sync_connector import BaseJsonSyncConnector
from stix_shifter_utils.utils.error_response import ErrorResponder
from stix_shifter_utils.utils import logger
from .api_client import APIClient, CriminalIPResponseError
from ..stix_translation.post_filter import parse_search_id, record_matches, parse_lookup, LOOKUP_IP, \
    normalize_lookup_value

# Matches the filter names in a Criminal IP query string, e.g. "ip" and "port" in "ip: 8.8.8.0/24 port: 443".
# The translator always renders terms as 'name: value', so a colon inside a value (e.g. 'title: port:22') is not
# mistaken for a filter name.
FILTER_NAME_RE = re.compile(r'(?:^|\s)([A-Za-z_]+): ')


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
    # monotonic time of the last Criminal IP call made by any Connector in this process. stix-shifter creates a new
    # Connector for every results request, so per-instance state would not space calls across pages.
    _last_call = None

    def __init__(self, connection, configuration):
        self.api_client = APIClient(connection, configuration)
        self.logger = logger.set_logger(__name__)
        self.connector = __name__.split('.')[1]
        options = connection.get('options', {})
        self.result_limit = self._positive_int(options.get('result_limit'), self.DEFAULT_RESULT_LIMIT)
        self.max_api_calls = self._positive_int(options.get('max_api_calls'), self.DEFAULT_MAX_API_CALLS)

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
        last = Connector._last_call
        if last is not None:
            wait = self.MIN_CALL_INTERVAL - (time.monotonic() - last)
            if wait > 0:
                await asyncio.sleep(wait)
        Connector._last_call = time.monotonic()

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

    RECORD_TYPE_FIELD = 'criminalip_record_type'
    IP_CALLS_PER_VALUE = 2       # /v2/asset/ip/report + /v1/asset/ip/report/summary
    DOMAIN_CALLS_PER_VALUE = 2   # quick hash view (+ malicious view when the verdict is not "safe")

    async def _call(self, func, *args):
        await self._throttle()
        try:
            return await self._with_concurrency_retry(func, *args)
        except CriminalIPResponseError as ex:
            if ex.code == 500:
                # A bad API key also answers "internal server error"; tell it apart with one /v1/user/me call.
                try:
                    await self.api_client.ping_data_source()
                except CriminalIPResponseError as ping_ex:
                    if ping_ex.code in (CriminalIPResponseError.INVALID_API_KEY, 403, 401):
                        raise ping_ex
                except Exception:
                    pass
            raise

    async def _ip_lookup(self, ip):
        try:
            report = await self._call(self.api_client.ip_report, ip)
        except CriminalIPResponseError as ex:
            if ex.code == 400:   # "Invalid IP Address." (e.g. IPv6 or a malformed value)
                self.logger.warning('Criminal IP rejected IP %s: %s', ip, ex.message)
                return None, 1
            raise
        record = dict(report)
        record.pop('status', None)
        try:
            summary = dict(await self._call(self.api_client.ip_report_summary, ip))
            summary.pop('status', None)
            record['report_summary'] = summary
        except CriminalIPResponseError as ex:
            # The summary only adds the is_malicious verdict; keep the report when it is temporarily unavailable.
            if ex.code in (CriminalIPResponseError.INVALID_API_KEY, 401, 403):
                raise
            self.logger.warning('Criminal IP report summary for %s unavailable (%s); continuing without it',
                                ip, ex.message)
        record[self.RECORD_TYPE_FIELD] = 'ip_report'
        return record, 2

    async def _domain_lookup(self, domain):
        hash_view = await self._call(self.api_client.domain_quick, 'hash', domain)
        calls = 1
        malicious_view = {}
        if str(hash_view.get('result', '')).lower() != 'safe':
            malicious_view = await self._call(self.api_client.domain_quick, 'malicious', domain)
            calls += 1
        known = any(hash_view.get(k) for k in ('result', 'type')) or bool(malicious_view.get('type'))
        if not known:
            return None, calls     # "No Data" (or an empty verdict): Criminal IP knows nothing about this domain
        record = {self.RECORD_TYPE_FIELD: 'domain_quick', 'domain': domain, 'hash_view': hash_view,
                  'malicious_view': malicious_view}
        return record, calls

    async def _lookup_results(self, kind, values, offset, length, metadata):
        """Offset/length index the looked-up values (one record per value that Criminal IP knows)."""
        valid = []
        for value in values:
            normalized = normalize_lookup_value(kind, value)
            if normalized is None:
                self.logger.warning('Skipping invalid %s lookup value %r', kind, value)
            elif normalized not in valid:
                valid.append(normalized)
        values = valid
        start = offset
        if isinstance(metadata, dict) and isinstance(metadata.get('value_offset'), int) \
                and metadata['value_offset'] >= 0:
            start = metadata['value_offset']
        end = min(offset + length, self.result_limit, len(values))
        per_value = self.IP_CALLS_PER_VALUE if kind == LOOKUP_IP else self.DOMAIN_CALLS_PER_VALUE
        lookup = self._ip_lookup if kind == LOOKUP_IP else self._domain_lookup
        data = []
        calls = 0
        index = start
        while index < end:
            if calls + per_value > self.max_api_calls:
                self.logger.info('Stopped %s lookups after max_api_calls (%s); %s value(s) left', kind,
                                 self.max_api_calls, end - index)
                break
            record, used = await lookup(values[index])
            calls += used
            index += 1
            if record is not None:
                data.append(record)
        return_obj = {'success': True, 'data': data}
        if index < len(values) and index < self.result_limit:
            return_obj['metadata'] = {'value_offset': index}
        return return_obj

    async def create_results_connection(self, search_id, offset, length, metadata=None):
        return_obj = {}
        lookup = parse_lookup(search_id)
        if lookup is not None:
            try:
                return await self._lookup_results(lookup[0], lookup[1], max(int(offset), 0), max(int(length), 0),
                                                  metadata)
            except Exception as ex:
                return self._fill_exception({}, ex)
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
