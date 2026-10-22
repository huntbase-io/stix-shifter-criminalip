import json
import unittest
from unittest.mock import patch

from stix_shifter_modules.criminalip.entry_point import EntryPoint
from stix_shifter_modules.criminalip.stix_transmission.connector import Connector
from stix_shifter_modules.criminalip.tests.stix_transmission.test_criminalip import CALL_API, CONFIG, \
    connection, json_response, load, page, make_records, run

IP_REPORT = json.loads(load('v2_asset_ip_report_34.22.91.145_with_cves.json'))
IP_SUMMARY = json.loads(load('v1_asset_ip_report_summary_185.220.101.1.json'))
HASH_VIEW = json.loads(load('v1_domain_quick_hash_view_google.com.json'))
NO_DATA = json.loads(load('v1_domain_quick_malicious_view_google.com.json'))
INVALID_IP = json.loads(load('invalid_ip.json'))
MALICIOUS_HASH = {'status': 200, 'message': 'api success',
                  'data': {'call_count': 3, 'domain': 'bad.example', 'reg_dtime': '2026-01-01 00:00:00',
                           'result': 'malicious', 'type': 'phishing'}}
MALICIOUS_VIEW = {'status': 200, 'message': 'api success',
                  'data': {'call_count': 3, 'reg_dtime': '2026-01-01 00:00:00', 'type': 'phishing'}}
CONCURRENT = {'status': 403, 'message': 'unable to call api at the same time', 'data': {}}


def ip_backend(invalid=()):
    async def call_api(endpoint, method, headers=None, cookies=None, data=None, urldata=None, timeout=None):
        ip = urldata['ip']
        if ip in invalid:
            return json_response(INVALID_IP)
        if endpoint == 'v2/asset/ip/report':
            body = dict(IP_REPORT)
            body['ip'] = ip
            return json_response(body)
        if endpoint == 'v1/asset/ip/report/summary':
            return json_response(IP_SUMMARY)
        raise AssertionError('unexpected endpoint ' + endpoint)
    return call_api


def lookup_id(kind, values):
    return json.dumps({'lookup': kind, 'values': values})


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
@patch.object(Connector, 'CONCURRENCY_BACKOFF', 0)
class TestCriminalIPLookups(unittest.TestCase):

    @patch(CALL_API)
    def test_ip_lookup(self, mock_api):
        mock_api.side_effect = ip_backend()
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['34.22.91.145']), 0, 10))
        assert result['success'] is True
        assert len(result['data']) == 1
        record = result['data'][0]
        assert record['criminalip_record_type'] == 'ip_report'
        assert record['ip'] == '34.22.91.145'
        assert record['report_summary']['ip_scoring']['is_malicious'] is True
        assert 'status' not in record and 'status' not in record['report_summary']
        assert [c.args[0] for c in mock_api.call_args_list] == ['v2/asset/ip/report', 'v1/asset/ip/report/summary']
        assert 'metadata' not in result

    @patch(CALL_API)
    def test_ip_fan_out_capped_by_max_api_calls(self, mock_api):
        mock_api.side_effect = ip_backend()
        ips = ['10.0.0.{}'.format(i) for i in range(1, 11)]
        result = run(Connector(connection(max_api_calls=5), CONFIG).create_results_connection(
            lookup_id('ip', ips), 0, 10))
        assert len(result['data']) == 2          # 2 calls per IP -> 2 IPs within 5 calls
        assert mock_api.call_count == 4
        assert result['metadata'] == {'value_offset': 2}
        # resume
        mock_api.reset_mock()
        result = run(Connector(connection(max_api_calls=5), CONFIG).create_results_connection(
            lookup_id('ip', ips), 2, 8, result['metadata']))
        assert [r['ip'] for r in result['data']] == ['10.0.0.3', '10.0.0.4']

    @patch(CALL_API)
    def test_ip_offset_and_length_index_values(self, mock_api):
        mock_api.side_effect = ip_backend()
        ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3']
        result = run(Connector(connection(), CONFIG).create_results_connection(lookup_id('ip', ips), 1, 1))
        assert [r['ip'] for r in result['data']] == ['10.0.0.2']
        assert result['metadata'] == {'value_offset': 2}

    @patch(CALL_API)
    def test_invalid_ip_skipped(self, mock_api):
        mock_api.side_effect = ip_backend(invalid=('10.0.0.1',))
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['10.0.0.1', '10.0.0.2']), 0, 10))
        assert [r['ip'] for r in result['data']] == ['10.0.0.2']

    @patch(CALL_API)
    def test_ip_lookup_concurrency_retry(self, mock_api):
        responses = [json_response(CONCURRENT), json_response(IP_REPORT), json_response(IP_SUMMARY)]
        mock_api.side_effect = responses
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['34.22.91.145']), 0, 10))
        assert result['success'] is True and len(result['data']) == 1
        assert mock_api.call_count == 3

    @patch(CALL_API)
    def test_ip_lookup_bad_key(self, mock_api):
        bad = {'data': {}, 'message': 'internal server error', 'status': 500}
        mock_api.side_effect = [json_response(bad), json_response(bad)]
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['34.22.91.145']), 0, 10))
        assert result['success'] is False
        assert result['code'] == 'authentication_fail'

    @patch(CALL_API)
    def test_safe_domain_one_call(self, mock_api):
        mock_api.return_value = json_response(HASH_VIEW)
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('domain', ['google.com']), 0, 10))
        assert mock_api.call_count == 1
        assert mock_api.call_args.args[0] == 'v1/domain/quick/hash/view'
        assert mock_api.call_args.kwargs['urldata'] == {'domain': 'google.com'}
        record = result['data'][0]
        assert record['criminalip_record_type'] == 'domain_quick'
        assert record['hash_view']['result'] == 'safe'
        assert record['malicious_view'] == {}

    @patch(CALL_API)
    def test_malicious_domain_two_calls(self, mock_api):
        mock_api.side_effect = [json_response(MALICIOUS_HASH), json_response(MALICIOUS_VIEW)]
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('domain', ['bad.example']), 0, 10))
        endpoints = [c.args[0] for c in mock_api.call_args_list]
        assert endpoints == ['v1/domain/quick/hash/view', 'v1/domain/quick/malicious/view']
        assert result['data'][0]['malicious_view']['type'] == 'phishing'

    @patch(CALL_API)
    def test_unknown_domain_no_record(self, mock_api):
        mock_api.side_effect = [json_response(NO_DATA), json_response(NO_DATA)]
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('domain', ['nothing.example']), 0, 10))
        assert result == {'success': True, 'data': []}

    @patch(CALL_API)
    def test_never_scans_domains(self, mock_api):
        mock_api.side_effect = [json_response(MALICIOUS_HASH), json_response(MALICIOUS_VIEW)]
        run(Connector(connection(), CONFIG).create_results_connection(lookup_id('domain', ['bad.example']), 0, 10))
        for c in mock_api.call_args_list:
            assert 'scan' not in c.args[0]
            assert c.args[1] == 'GET'


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
class TestCriminalIPEndToEnd(unittest.TestCase):
    """translate -> results -> STIX, with mocked HTTP."""

    IDENTITY = {"type": "identity", "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff", "name": "criminalip",
                "identity_class": "system"}

    def stix(self, query, offset=0, length=10):
        entry_point = EntryPoint(connection(), CONFIG)
        return run(entry_point.create_results_stix_connection(query, offset, length, self.IDENTITY))

    @patch(CALL_API)
    def test_native_passthrough_query_end_to_end(self, mock_api):
        from stix_shifter.stix_translation import stix_translation
        native = 'product: OpenSSH port: 22 country: KR'
        queries = stix_translation.StixTranslation().translate('criminalip', 'query', '{}', native,
                                                               {'language': 'criminalip'})['queries']
        assert queries == [native]
        mock_api.return_value = page(make_records(0, 3), 3)
        bundle = self.stix(queries[0])
        assert mock_api.call_args.kwargs['urldata'] == {'query': native, 'offset': 0}
        observed = [o for o in bundle['objects'] if o['type'] == 'observed-data']
        assert len(observed) == 3
        assert observed[0]['objects']['0']['type'] == 'ipv4-addr'

    @patch(CALL_API)
    def test_ip_lookup_end_to_end(self, mock_api):
        mock_api.side_effect = ip_backend()
        bundle = self.stix(lookup_id('ip', ['34.22.91.145']))
        observed = [o for o in bundle['objects'] if o['type'] == 'observed-data']
        types = {obj['type'] for o in observed for obj in o['objects'].values()}
        assert {'ipv4-addr', 'autonomous-system', 'x-criminalip-ip', 'x-criminalip-vulnerability',
                'network-traffic', 'software', 'x-oca-geo'} <= types


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
class TestCriminalIPLookupResilience(unittest.TestCase):

    @patch(CALL_API)
    def test_summary_outage_keeps_report(self, mock_api):
        from tests.utils.async_utils import get_mock_response
        mock_api.side_effect = [json_response(IP_REPORT),
                                get_mock_response(522, '<html>origin timeout</html>', 'byte',
                                                  headers={'Content-Type': 'text/html'})]
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['34.22.91.145']), 0, 10))
        assert result['success'] is True
        assert 'report_summary' not in result['data'][0]

    @patch(CALL_API)
    def test_cloudflare_522_maps_to_service_unavailable(self, mock_api):
        from tests.utils.async_utils import get_mock_response
        mock_api.return_value = get_mock_response(522, '<html>origin timeout</html>', 'byte',
                                                  headers={'Content-Type': 'text/html'})
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['34.22.91.145']), 0, 10))
        assert result['success'] is False
        assert result['code'] == 'service_unavailable'

    @patch(CALL_API)
    def test_empty_verdict_domain_no_record(self, mock_api):
        empty = {'status': 200, 'message': 'api success', 'data': {'call_count': 0, 'domain': 'x.example'}}
        mock_api.side_effect = [json_response(empty), json_response(NO_DATA)]
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('domain', ['x.example']), 0, 10))
        assert result == {'success': True, 'data': []}


@patch.object(Connector, 'MIN_CALL_INTERVAL', 0)
class TestCriminalIPLookupInputSafety(unittest.TestCase):

    @patch(CALL_API)
    def test_invalid_values_never_sent(self, mock_api):
        mock_api.side_effect = ip_backend()
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('ip', ['8.8.8.0/24', '::1', 'x; rm', 42, ' 34.22.91.145 ', '34.22.91.145']), 0, 10))
        assert [r['ip'] for r in result['data']] == ['34.22.91.145']
        assert {c.kwargs['urldata']['ip'] for c in mock_api.call_args_list} == {'34.22.91.145'}

    @patch(CALL_API)
    def test_invalid_domains_never_sent(self, mock_api):
        mock_api.return_value = json_response(HASH_VIEW)
        result = run(Connector(connection(), CONFIG).create_results_connection(
            lookup_id('domain', ['bad domain.com', 'a/b.com', 'Google.COM']), 0, 10))
        assert mock_api.call_count == 1
        assert mock_api.call_args.kwargs['urldata'] == {'domain': 'google.com'}
        assert len(result['data']) == 1

    @patch(CALL_API)
    def test_lookups_use_the_shared_throttle(self, mock_api):
        mock_api.side_effect = ip_backend()
        with patch.object(Connector, '_throttle') as throttle:
            async def no_wait():
                return None
            throttle.side_effect = no_wait
            run(Connector(connection(), CONFIG).create_results_connection(lookup_id('ip', ['1.2.3.4']), 0, 10))
        assert throttle.call_count == 2
