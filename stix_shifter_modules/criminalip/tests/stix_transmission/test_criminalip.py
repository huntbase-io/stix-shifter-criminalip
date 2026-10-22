import asyncio
import copy
import json
import os
import unittest
from unittest.mock import patch

from tests.utils.async_utils import get_mock_response
from stix_shifter_modules.criminalip.stix_transmission.connector import Connector

SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sample_responses')
CALL_API = 'stix_shifter_utils.stix_transmission.utils.RestApiClientAsync.RestApiClientAsync.call_api'
JSON_HEADERS = {'Content-Type': 'application/json'}
FAKE_KEY = 'test-api-key-0123456789'

CONFIG = {'auth': {'api_key': FAKE_KEY}}


def connection(**options):
    opts = {'result_limit': 1000, 'timeout': 30, 'max_api_calls': 100}
    opts.update(options)
    return {'host': 'api.criminalip.io', 'port': 443, 'options': opts}


def load(name):
    with open(os.path.join(SAMPLES, name), 'r', encoding='utf-8') as f:
        return f.read()


def json_response(body, code=200):
    if not isinstance(body, str):
        body = json.dumps(body)
    return get_mock_response(code, body, 'byte', headers=JSON_HEADERS)


BASE_RECORD = json.loads(load('v2_banner_search_openssh_kr.json'))['data']['result'][0]


def make_records(start, n, product='OpenSSH'):
    records = []
    for i in range(start, start + n):
        record = copy.deepcopy(BASE_RECORD)
        record['ip_address'] = '10.0.{}.{}'.format(i // 256, i % 256)
        record['software'] = [{'product': product if i % 2 == 0 else 'Dropbear', 'version': '1.0'}]
        records.append(record)
    return records


def page(records, count):
    return json_response({
        'status': 200, 'message': 'success', 'timestamp': '2026-10-23 06:29:16',
        'data': {'groups': [{'keywords': [], 'filters': [{'key': 'port', 'value': '22', 'negate': False}]}],
                 'count': count, 'result': records}})


def paged_backend(total, page_size=10, product='OpenSSH'):
    """side_effect for call_api that serves `total` records, `page_size` per call, honouring the offset."""
    async def call_api(endpoint, method, headers=None, cookies=None, data=None, urldata=None, timeout=None):
        offset = urldata['offset']
        n = max(0, min(page_size, total - offset))
        return page(make_records(offset, n, product), total)
    return call_api


def run(coro):
    return asyncio.run(coro)


def offsets(mock):
    return [c.kwargs['urldata']['offset'] for c in mock.call_args_list]


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
class TestCriminalIPPing(unittest.TestCase):

    @patch(CALL_API)
    def test_ping_success(self, mock_api):
        mock_api.return_value = json_response(load('user_me.json'))
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertEqual(result, {'success': True})
        args, kwargs = mock_api.call_args
        self.assertEqual(args, ('v1/user/me', 'POST'))
        self.assertEqual(kwargs['headers'], {'Content-Length': '0'})
        self.assertEqual(kwargs['data'], b'')

    def test_api_key_header(self):
        connector = Connector(connection(), CONFIG)
        headers = connector.api_client.client.get_headers()
        self.assertEqual(headers['x-api-key'], FAKE_KEY)
        self.assertEqual(connector.api_client.client.get_server_ip(), 'api.criminalip.io:443')

    @patch(CALL_API)
    def test_ping_missing_key(self, mock_api):
        mock_api.return_value = json_response(load('missing_api_key.json'))
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'authentication_fail')
        self.assertIn('check access failed', result['error'])

    @patch(CALL_API)
    def test_ping_invalid_key(self, mock_api):
        mock_api.return_value = json_response(load('invalid_api_key.json'))
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'authentication_fail')
        self.assertIn('rejected the API key', result['error'])

    @patch(CALL_API)
    def test_ping_cloudflare_challenge(self, mock_api):
        mock_api.return_value = get_mock_response(
            403, '<!DOCTYPE html><html><head><title>Just a moment...</title></head></html>', 'byte',
            headers={'Content-Type': 'text/html; charset=UTF-8', 'cf-mitigated': 'challenge'})
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'forbidden')
        self.assertIn('Cloudflare', result['error'])
        self.assertNotIn('Just a moment', result['error'])

    @patch(CALL_API)
    def test_ping_html_server_error(self, mock_api):
        mock_api.return_value = get_mock_response(500, '<html><body>500 Internal Server Error</body></html>', 'byte',
                                                  headers={'Content-Type': 'text/html'})
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'service_unavailable')

    @patch(CALL_API)
    def test_ping_non_json_200(self, mock_api):
        mock_api.return_value = get_mock_response(200, 'not json', 'byte', headers={'Content-Type': 'text/plain'})
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'service_unavailable')

    @patch(CALL_API)
    def test_ping_connection_error(self, mock_api):
        mock_api.side_effect = Exception('client_connector_error: (Cannot connect to host api.criminalip.io:443)')
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'service_unavailable')

    @patch(CALL_API)
    def test_ping_timeout(self, mock_api):
        mock_api.side_effect = Exception('timeout_error (30 sec): ()')
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertEqual(result['code'], 'service_unavailable')

    @patch(CALL_API)
    def test_ping_never_leaks_key(self, mock_api):
        body = {'status': 500, 'message': 'internal server error', 'data': {'api_key': FAKE_KEY}}
        mock_api.return_value = json_response(body)
        result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertNotIn(FAKE_KEY, json.dumps(result))


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
class TestCriminalIPResults(unittest.TestCase):

    @patch(CALL_API)
    def test_fixture_page_returned_raw(self, mock_api):
        mock_api.return_value = json_response(load('v2_banner_search_openssh_kr.json'))
        query = 'product: OpenSSH port: 22 country: KR'
        result = run(Connector(connection(), CONFIG).create_results_connection(query, 0, 3))
        self.assertTrue(result['success'])
        expected = json.loads(load('v2_banner_search_openssh_kr.json'))['data']['result']
        self.assertEqual(result['data'], expected)
        args, kwargs = mock_api.call_args
        self.assertEqual(args, ('v2/banner/search', 'GET'))
        self.assertEqual(kwargs['urldata'], {'query': query, 'offset': 0})
        self.assertEqual(result['metadata'], {'api_offset': 3, 'filtered_seen': 3})

    @patch(CALL_API)
    def test_pages_until_length(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 25))
        self.assertEqual(len(result['data']), 25)
        self.assertEqual(offsets(mock_api), [0, 10, 20])
        self.assertEqual(result['data'][24]['ip_address'], '10.0.0.24')
        self.assertEqual(result['metadata'], {'api_offset': 25, 'filtered_seen': 25})

    @patch(CALL_API)
    def test_offset_maps_to_api_offset(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 35, 15))
        self.assertEqual(offsets(mock_api), [35, 45])
        self.assertEqual([r['ip_address'] for r in result['data']], ['10.0.0.{}'.format(i) for i in range(35, 50)])

    @patch(CALL_API)
    def test_string_offset_and_length(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', '10', '5'))
        self.assertEqual(offsets(mock_api), [10])
        self.assertEqual(len(result['data']), 5)

    @patch(CALL_API)
    def test_stops_at_count(self, mock_api):
        mock_api.side_effect = paged_backend(12)
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 100))
        self.assertEqual(len(result['data']), 12)
        self.assertEqual(offsets(mock_api), [0, 10])
        self.assertNotIn('metadata', result)

    @patch(CALL_API)
    def test_stops_on_empty_page(self, mock_api):
        mock_api.side_effect = [page(make_records(0, 10), 50), page([], 50)]
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 100))
        self.assertEqual(len(result['data']), 10)
        self.assertEqual(mock_api.call_count, 2)
        self.assertNotIn('metadata', result)

    @patch(CALL_API)
    def test_no_data_is_empty_result(self, mock_api):
        mock_api.return_value = json_response({'status': 200, 'message': 'No Data', 'data': {}})
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result, {'success': True, 'data': []})

    @patch(CALL_API)
    def test_unknown_filter_returns_empty(self, mock_api):
        mock_api.return_value = json_response(load('unknown_filter_becomes_keyword.json'))
        connector = Connector(connection(), CONFIG)
        with self.assertLogs(connector.logger, level='WARNING') as logs:
            result = run(connector.create_results_connection('bogusfilter: abc', 0, 10))
        self.assertEqual(result, {'success': True, 'data': []})
        self.assertIn('bogusfilter', ''.join(logs.output))

    @patch(CALL_API)
    def test_colon_inside_value_is_not_a_filter_name(self, mock_api):
        body = json.loads(load('v2_banner_search_openssh_kr.json'))
        body['data']['groups'] = [{'keywords': [], 'filters': [{'key': 'title', 'value': 'port:22', 'negate': False}]}]
        mock_api.return_value = json_response(body)
        connector = Connector(connection(), CONFIG)
        with patch.object(connector.logger, 'warning') as warning:
            run(connector.create_results_connection('title: port:22', 0, 5))
        warning.assert_not_called()

    @patch(CALL_API)
    def test_http_429_after_client_retries_is_too_many_requests(self, mock_api):
        mock_api.side_effect = Exception('Max retries exceeded. too_many_requests with max retry (1)')
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'too_many_requests')

    @patch(CALL_API)
    def test_result_limit_caps_calls(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        result = run(Connector(connection(result_limit=15), CONFIG).create_results_connection('port: 22', 0, 100))
        self.assertEqual(len(result['data']), 15)
        self.assertEqual(offsets(mock_api), [0, 10])
        self.assertNotIn('metadata', result)

    @patch(CALL_API)
    def test_offset_beyond_result_limit(self, mock_api):
        result = run(Connector(connection(result_limit=15), CONFIG).create_results_connection('port: 22', 15, 10))
        self.assertEqual(result, {'success': True, 'data': []})
        mock_api.assert_not_called()

    @patch(CALL_API)
    def test_max_api_calls(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        result = run(Connector(connection(max_api_calls=2), CONFIG).create_results_connection('port: 22', 0, 50))
        self.assertEqual(len(result['data']), 20)
        self.assertEqual(mock_api.call_count, 2)
        self.assertEqual(result['metadata'], {'api_offset': 20, 'filtered_seen': 20})

    def test_default_limits(self):
        connector = Connector({'host': 'api.criminalip.io', 'options': {}}, CONFIG)
        self.assertEqual((connector.result_limit, connector.max_api_calls), (100, 10))

    @patch(CALL_API)
    def test_never_exceeds_max_offset(self, mock_api):
        mock_api.side_effect = paged_backend(20000)
        connector = Connector(connection(result_limit=10000), CONFIG)
        result = run(connector.create_results_connection('port: 22', 9895, 50))
        self.assertEqual(offsets(mock_api), [9895])
        self.assertEqual(len(result['data']), 10)
        self.assertNotIn('metadata', result)
        mock_api.reset_mock()
        result = run(connector.create_results_connection('port: 22', 9901, 5))
        mock_api.assert_not_called()
        self.assertEqual(result['data'], [])

    @patch(CALL_API)
    def test_post_filter(self, mock_api):
        # Even indexes are OpenSSH, odd ones Dropbear; keep only OpenSSH records.
        mock_api.side_effect = paged_backend(1000)
        search_id = json.dumps({'query': 'product: OpenSSH',
                                'post_filter': {'terms': [{'field': 'software.product', 'value': 'OpenSSH'}]}})
        result = run(Connector(connection(), CONFIG).create_results_connection(search_id, 0, 7))
        self.assertEqual([r['ip_address'] for r in result['data']],
                         ['10.0.0.{}'.format(i) for i in range(0, 13, 2)])
        self.assertEqual(offsets(mock_api), [0, 10])
        self.assertEqual(result['metadata'], {'api_offset': 13, 'filtered_seen': 7})

    @patch(CALL_API)
    def test_post_filter_offset_scans_from_start(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        search_id = json.dumps({'query': 'product: OpenSSH',
                                'post_filter': {'terms': [{'field': 'software.product', 'value': 'OpenSSH'}]}})
        result = run(Connector(connection(), CONFIG).create_results_connection(search_id, 5, 3))
        self.assertEqual([r['ip_address'] for r in result['data']], ['10.0.0.10', '10.0.0.12', '10.0.0.14'])
        self.assertEqual(offsets(mock_api), [0, 10])
        self.assertEqual(result['metadata'], {'api_offset': 15, 'filtered_seen': 8})

    @patch(CALL_API)
    def test_post_filter_resume_from_metadata(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        search_id = json.dumps({'query': 'product: OpenSSH',
                                'post_filter': {'terms': [{'field': 'software.product', 'value': 'OpenSSH'}]}})
        metadata = {'api_offset': 15, 'filtered_seen': 8}
        result = run(Connector(connection(), CONFIG).create_results_connection(search_id, 8, 3, metadata))
        self.assertEqual(offsets(mock_api), [15])
        self.assertEqual([r['ip_address'] for r in result['data']], ['10.0.0.16', '10.0.0.18', '10.0.0.20'])
        self.assertEqual(result['metadata'], {'api_offset': 21, 'filtered_seen': 11})

    @patch(CALL_API)
    def test_post_filter_time_window(self, mock_api):
        records = make_records(0, 3)
        records[0]['scan_dtime'] = '2026-09-01 00:00:00'
        records[1]['scan_dtime'] = '2026-10-10 12:00:00'
        records[2]['scan_dtime'] = '2026-10-30 00:00:00'
        mock_api.return_value = page(records, 3)
        search_id = json.dumps({'query': 'port: 22 before: 2026-10-23',
                                'post_filter': {'start': '2026-10-01T00:00:00.000Z',
                                                'stop': '2026-10-22T00:00:00.000Z'}})
        result = run(Connector(connection(), CONFIG).create_results_connection(search_id, 0, 10))
        self.assertEqual([r['scan_dtime'] for r in result['data']], ['2026-10-10 12:00:00'])
        self.assertEqual(mock_api.call_args.kwargs['urldata']['query'], 'port: 22 before: 2026-10-23')

    @patch(CALL_API)
    def test_bad_metadata_is_ignored(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 5, {'foo': 1}))
        self.assertEqual(offsets(mock_api), [0])
        self.assertEqual(len(result['data']), 5)

    @patch(CALL_API)
    def test_http_400_missing_offset(self, mock_api):
        mock_api.return_value = json_response(load('banner_search_missing_offset_http400.json'), 400)
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'invalid_query')
        self.assertIn('Missing Parameter', result['error'])

    @patch(CALL_API)
    def test_invalid_filter_combination(self, mock_api):
        mock_api.return_value = json_response({'status': 400, 'message': 'Invalid filter combination.', 'data': {}})
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result['code'], 'invalid_query')

    @patch(CALL_API)
    def test_missing_key_on_search(self, mock_api):
        mock_api.return_value = json_response(load('missing_api_key.json'))
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result['code'], 'authentication_fail')

    @patch(CALL_API)
    def test_search_500_with_bad_key(self, mock_api):
        mock_api.side_effect = [json_response(load('invalid_api_key.json')),
                                json_response(load('invalid_api_key.json'))]
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result['code'], 'authentication_fail')
        self.assertEqual(mock_api.call_args_list[1].args, ('v1/user/me', 'POST'))

    @patch(CALL_API)
    def test_search_500_with_good_key(self, mock_api):
        mock_api.side_effect = [json_response(load('invalid_api_key.json')),
                                json_response(load('user_me.json'))]
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result['code'], 'service_unavailable')
        self.assertEqual(mock_api.call_count, 2)

    @patch(CALL_API)
    def test_results_limited(self, mock_api):
        mock_api.return_value = json_response({'status': 403, 'message': 'Results are limited', 'data': {}})
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result['code'], 'forbidden')

    @patch(CALL_API)
    def test_http_429(self, mock_api):
        mock_api.return_value = get_mock_response(429, 'Too Many Requests', 'byte',
                                                  headers={'Content-Type': 'text/plain'})
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertEqual(result['code'], 'too_many_requests')

    @patch(CALL_API)
    def test_error_mid_pagination(self, mock_api):
        mock_api.side_effect = [page(make_records(0, 10), 100),
                                get_mock_response(502, '<html>Bad gateway</html>', 'byte',
                                                  headers={'Content-Type': 'text/html'})]
        result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 20))
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'service_unavailable')
        self.assertNotIn('data', result)


CONCURRENCY_BODY = {'data': {}, 'message': 'unable to call api at the same time', 'status': 403}
SLEEP = 'stix_shifter_modules.criminalip.stix_transmission.connector.asyncio.sleep'


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
class TestCriminalIPConcurrencyLimit(unittest.TestCase):

    @patch(CALL_API)
    def test_search_retries_then_succeeds(self, mock_api):
        mock_api.side_effect = [json_response(CONCURRENCY_BODY), json_response(CONCURRENCY_BODY),
                                page(make_records(0, 5), 5)]
        with patch(SLEEP) as sleep:
            result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertTrue(result['success'])
        self.assertEqual(len(result['data']), 5)
        self.assertEqual(offsets(mock_api), [0, 0, 0])
        self.assertEqual([c.args[0] for c in sleep.call_args_list],
                         [Connector.CONCURRENCY_BACKOFF, Connector.CONCURRENCY_BACKOFF * 2])

    @patch(CALL_API)
    def test_search_gives_up_with_too_many_requests(self, mock_api):
        mock_api.return_value = json_response(CONCURRENCY_BODY)
        with patch(SLEEP):
            result = run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 10))
        self.assertFalse(result['success'])
        self.assertEqual(result['code'], 'too_many_requests')
        self.assertIn('at the same time', result['error'])
        self.assertEqual(mock_api.call_count, 1 + Connector.CONCURRENCY_RETRIES)

    @patch(CALL_API)
    def test_ping_retries_then_too_many_requests(self, mock_api):
        mock_api.return_value = json_response(CONCURRENCY_BODY)
        with patch(SLEEP):
            result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertEqual(result['code'], 'too_many_requests')
        self.assertEqual(mock_api.call_count, 1 + Connector.CONCURRENCY_RETRIES)

    @patch(CALL_API)
    def test_ping_retry_recovers(self, mock_api):
        mock_api.side_effect = [json_response(CONCURRENCY_BODY), json_response(load('user_me.json'))]
        with patch(SLEEP):
            result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertEqual(result, {'success': True})

    @patch(CALL_API)
    def test_missing_key_is_not_retried(self, mock_api):
        mock_api.return_value = json_response(load('missing_api_key.json'))
        with patch(SLEEP) as sleep:
            result = run(Connector(connection(), CONFIG).ping_connection())
        self.assertEqual(result['code'], 'authentication_fail')
        self.assertEqual(mock_api.call_count, 1)
        sleep.assert_not_called()


class TestCriminalIPThrottle(unittest.TestCase):

    def setUp(self):
        Connector._last_call = None

    @patch(CALL_API)
    def test_spacing_holds_across_connector_instances(self, mock_api):
        # stix-shifter builds a new Connector per results request; consecutive requests must still be spaced
        mock_api.side_effect = paged_backend(1000)
        with patch('stix_shifter_modules.criminalip.stix_transmission.connector.asyncio.sleep') as sleep:
            run(Connector(connection(), CONFIG).create_results_connection('port: 22', 0, 5))
            run(Connector(connection(), CONFIG).create_results_connection('port: 22', 5, 5))
        self.assertEqual(sleep.call_count, 1)

    @patch(CALL_API)
    def test_page_calls_are_spaced(self, mock_api):
        mock_api.side_effect = paged_backend(1000)
        connector = Connector(connection(), CONFIG)
        with patch('stix_shifter_modules.criminalip.stix_transmission.connector.asyncio.sleep') as sleep:
            run(connector.create_results_connection('port: 22', 0, 30))
        self.assertEqual(sleep.call_count, 2)
        for c in sleep.call_args_list:
            self.assertLessEqual(c.args[0], Connector.MIN_CALL_INTERVAL)
