"""Weekly smoke test of the Criminal IP connector against the live API.

Run from the root of a stix-shifter checkout that has the connector installed
(see .github/workflows/live-api-check.yml):

    CRIMINALIP_API_KEY=... PYTHONPATH="$PWD" python /path/to/live_api_check.py

Makes about 5 Criminal IP calls, one after the other (Criminal IP allows one
concurrent call per key):

  1. ping                                   /v1/user/me                    1 call
  2. execute an exact-IP lookup             IP report + summary            2 calls
  3. execute a banner search                /v2/banner/search, 1 page      1 call
  4. passthrough results (native query)     /v2/banner/search, 1 page      1 call

Never prints raw responses (the /v1/user/me body contains the API key) and
redacts the key from any error message. Exits 1 if any check fails.
"""
import ipaddress
import json
import os
import sys

from stix_shifter.stix_translation import stix_translation
from stix_shifter.stix_transmission import stix_transmission

MODULE = 'criminalip'
IDENTITY = {
    'type': 'identity',
    'id': 'identity--f431f809-377b-45e0-aa1c-6a4751cae5ff',
    'name': 'criminalip',
    'identity_class': 'system',
}
API_KEY = os.environ.get('CRIMINALIP_API_KEY', '')
CONNECTION = {
    'host': os.environ.get('CRIMINALIP_HOST', 'api.criminalip.io'),
    'port': int(os.environ.get('CRIMINALIP_PORT', '443')),
    'options': {'result_limit': 10, 'max_api_calls': 2, 'timeout': 60},
}
CONFIGURATION = {'auth': {'api_key': API_KEY}}

failures = []


def redact(value):
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return text.replace(API_KEY, '***') if API_KEY else text


def error(check, message):
    failures.append(check)
    print('::error title=Live API check: {}::{}'.format(check, redact(message).replace('\n', ' ')))


def describe_failure(result):
    """The error fields of a failed stix-shifter result, never its data."""
    return {k: result.get(k) for k in ('code', 'error', 'connector') if k in result}


def transmission():
    return stix_transmission.StixTransmission(MODULE, CONNECTION, CONFIGURATION)


def check_bundle(check, bundle, min_observed=1, ip_filter=None):
    """Assert a STIX results bundle holds valid-looking observed-data. Returns the observed-data list."""
    if not isinstance(bundle, dict) or bundle.get('type') != 'bundle':
        error(check, 'results translation did not return a STIX bundle: {}'.format(describe_failure(bundle or {})))
        return []
    objects = bundle.get('objects') or []
    if not any(o.get('type') == 'identity' and o.get('id') == IDENTITY['id'] for o in objects):
        error(check, 'bundle is missing the identity object')
    observed = [o for o in objects if o.get('type') == 'observed-data']
    if len(observed) < min_observed:
        error(check, 'expected at least {} observed-data object(s), got {}'.format(min_observed, len(observed)))
        return observed
    problems = set()
    ips = set()
    for od in observed:
        if not str(od.get('id', '')).startswith('observed-data--'):
            problems.add('observed-data without a valid id')
        if od.get('created_by_ref') != IDENTITY['id']:
            problems.add('observed-data with the wrong created_by_ref')
        for field in ('first_observed', 'last_observed'):
            if not od.get(field):
                problems.add('observed-data without {}'.format(field))
        if not isinstance(od.get('number_observed'), int) or od['number_observed'] < 1:
            problems.add('observed-data with a bad number_observed')
        objs = od.get('objects')
        if not isinstance(objs, dict) or not objs:
            problems.add('observed-data without objects')
            continue
        for sco in objs.values():
            if not isinstance(sco, dict) or not sco.get('type'):
                problems.add('observed-data with an untyped object')
            elif sco['type'] == 'ipv4-addr' and sco.get('value'):
                ips.add(sco['value'])
    for p in sorted(problems):
        error(check, p)
    if ip_filter is not None and not any(ip_filter(ip) for ip in ips):
        error(check, 'no ipv4-addr object matches the query')
    print('{}: {} observed-data object(s), {} distinct IPv4 address(es)'.format(check, len(observed), len(ips)))
    return observed


def execute(check, pattern, length):
    """What `main.py execute` does: translate, query, fetch results, translate results to STIX."""
    translation = stix_translation.StixTranslation()
    dsl = translation.translate(MODULE, 'query', '{}', pattern, CONNECTION['options'])
    queries = dsl.get('queries') if isinstance(dsl, dict) else None
    if not queries:
        error(check, 'query translation failed: {}'.format(describe_failure(dsl or {})))
        return None
    if len(queries) != 1:
        error(check, 'expected one translated query, got {}'.format(len(queries)))
        return None
    client = transmission()
    search = client.query(queries[0])
    if not search.get('success'):
        error(check, 'query failed: {}'.format(describe_failure(search)))
        return None
    results = client.results(search['search_id'], 0, length)
    if not results.get('success'):
        error(check, 'results failed: {}'.format(describe_failure(results)))
        return None
    data = results.get('data') or []
    print('{}: {} raw record(s)'.format(check, len(data)))
    return translation.translate(MODULE, 'results', json.dumps(IDENTITY), data, CONNECTION['options'])


def main():
    if not API_KEY:
        print('::error::CRIMINALIP_API_KEY is not set')
        return 1
    print('::add-mask::{}'.format(API_KEY))

    # 1. ping
    ping = transmission().ping()
    if ping.get('success'):
        print('ping: ok')
    else:
        error('ping', 'ping failed: {}'.format(describe_failure(ping)))
        # Nothing else can work without a valid key; do not spend more calls.
        return 1

    # 2. exact IP: answered by the IP report lookups
    bundle = execute('ip_lookup', "[ipv4-addr:value = '8.8.8.8']", 1)
    if bundle is not None:
        check_bundle('ip_lookup', bundle, ip_filter=lambda ip: ip == '8.8.8.8')

    # 3. banner search: one page (10 records) for a well-known /24
    net = ipaddress.ip_network('8.8.8.0/24')
    bundle = execute('banner_search', "[ipv4-addr:value ISSUBSET '8.8.8.0/24']", 10)
    if bundle is not None:
        check_bundle('banner_search', bundle, ip_filter=lambda ip: ipaddress.ip_address(ip) in net)

    # 4. passthrough: a native Criminal IP query sent unchanged to transmit results
    results = transmission().results('ip: 8.8.8.0/24 port: 443', 0, 5)
    if not results.get('success'):
        error('passthrough', 'results failed: {}'.format(describe_failure(results)))
    else:
        data = results.get('data') or []
        print('passthrough: {} raw record(s)'.format(len(data)))
        if not data:
            error('passthrough', 'no records returned')
        elif not all(isinstance(r, dict) and r.get('ip_address') for r in data):
            error('passthrough', 'records without ip_address')
        else:
            bundle = stix_translation.StixTranslation().translate(
                MODULE, 'results', json.dumps(IDENTITY), data, CONNECTION['options'])
            check_bundle('passthrough', bundle, ip_filter=lambda ip: ipaddress.ip_address(ip) in net)

    if failures:
        print('::error title=Live API check::{} check(s) failed: {}. The Criminal IP API may have changed.'.format(
            len(failures), ', '.join(sorted(set(failures)))))
        return 1
    print('All live checks passed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
