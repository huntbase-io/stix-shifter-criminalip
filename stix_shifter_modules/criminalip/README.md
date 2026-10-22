# Criminal IP Connector

**Table of Contents**

- [Criminal IP API Endpoints](#criminal-ip-api-endpoints)
- [How patterns are translated](#how-patterns-are-translated)
- [Pattern expression with STIX attributes - Single Observation](#single-observation)
- [Pattern expression with STIX attributes - Multiple Observations](#multiple-observations)
- [STIX Execute Query](#stix-execute-query)
- [Pagination and API credits](#pagination-and-api-credits)
- [Error handling](#error-handling)
- [Limitations](#limitations)
- [References](#references)

[Criminal IP](https://www.criminalip.io) is an internet-exposure and threat-intelligence search engine. This
synchronous connector runs STIX patterns against the Criminal IP **banner search** (`GET /v2/banner/search`).
Each returned banner (one service on one IP:port, as last seen by the Criminal IP scanners) becomes one STIX
`observed-data` object.

Supported STIX objects, properties and operators are listed in [criminalip_supported_stix.md](criminalip_supported_stix.md).

### Criminal IP API Endpoints

| Connector Method | Criminal IP API Endpoint | Method |
|--|--|--|
| Ping | `https://api.criminalip.io/v1/user/me` | POST (empty body) |
| Results | `https://api.criminalip.io/v2/banner/search?query=<query>&offset=<n>` | GET |

Authentication uses the `x-api-key` header. Ping uses `/v1/user/me` because it is cheap, authenticated and has no
threat-data side effects. Its response echoes the API key, so the connector never logs or returns that response.

### Connection and configuration

| Parameter | Default | Notes |
|--|--|--|
| `host` | `api.criminalip.io` | |
| `port` | `443` | |
| `options.result_limit` | `100` | Maximum records per query. Criminal IP itself stops at 10,000. |
| `options.max_api_calls` | `10` | Maximum banner-search calls for one `results` request. Each call returns 10 records and costs credits. |
| `options.timeout` | `30` | Seconds per HTTP call |
| `configuration.auth.api_key` | | Criminal IP API key |

### How patterns are translated

Criminal IP's query language is a list of `filter: value` terms. Several quirks of that language shape the
translator:

| Criminal IP behaviour (verified live) | What the translator does |
|--|--|
| Terms separated by a space are ANDed, and `NOT` negates one term. | `AND` becomes a space. `!=`, `NOT =` and `NOT IN` become `NOT filter: value`. |
| `OR` has the lowest precedence, so `a b OR c` means `(a AND b) OR c`, and there are no parentheses. | The pattern is rewritten into disjunctive normal form (an OR of AND-groups): `[a AND (b OR c)]` becomes `a b OR a c`. `IN (x, y)` is distributed the same way. At most 64 groups are allowed. |
| Values cannot contain spaces, and quoted values match nothing. | For a multi-word value, the longest word is sent (`software:name = 'Plesk Obsidian'` becomes `product: Obsidian`), and the full phrase is checked against each returned record on the client side. A negated multi-word value is checked only on the client side. The operator words `OR`, `AND` and `NOT` are never sent as a value, because the server would parse them as operators; a value made only of operator words is rejected. A colon inside a value is safe (`title: port:22` is read as one value). |
| Unknown filter names are silently treated as keywords. | Only documented filter names are emitted. Transmission checks `data.groups` and logs a warning if a filter was not recognised. |
| `after:` always returns 0 results, but `before:` works. | `START t'..' STOP t'..'` becomes `before: <STOP date + 1 day>` plus a client-side `scan_dtime` window [START, STOP]. |
| `ip:` accepts a single IPv4 address or a CIDR range. IPv6 is not supported. | `ipv4-addr:value = '1.2.3.0/24'` and `ISSUBSET '1.2.3.0/24'` both become `ip: 1.2.3.0/24`. An IPv6 value raises an error, and `ipv6-addr` is unmapped. |
| `service:` is the real filter name; `service_name:` is ignored. | `network-traffic:protocols[*]` becomes `service:`. |

Unmapped STIX properties and unsupported operators (`>`, `<`, `LIKE`, `MATCHES`, `ISSUPERSET`, `FOLLOWEDBY`) are
handled the usual stix-shifter way. When they are ORed with something mappable, they are dropped with a warning.
Otherwise translation fails with `mapping_error` or `invalid_parameter`.

When there is no `START`/`STOP` qualifier, **no default time window is applied**. Criminal IP holds scan data
collected over days and weeks, so the usual "last *N* minutes" default would always return nothing.

**Query format.** Each entry of `queries` is either:
- a plain Criminal IP query string, which can be pasted into the Criminal IP UI; or
- a JSON string of the form `{"query": "<criminal ip query>", "post_filter": {...}}`. This form is used when client-side checks
  are needed (a time window or a multi-word phrase).

AND-groups that need different client-side checks become separate queries. Each query is executed independently,
and the results are concatenated.

### Format for calling stix-shifter from the command line
```
python main.py `<translator_module>` `<query or result>` `<STIX identity object>` `<data>`
```

### Pattern expression with STIX attributes

#### Single Observation

##### STIX Translate query
```shell
python main.py translate criminalip query '{}' "[software:name = 'OpenSSH' AND network-traffic:dst_port = 22 AND x-oca-geo:country_iso_code = 'KR']"
```
##### STIX Translate query - output
```json
{
    "queries": [
        "country: KR port: 22 product: OpenSSH"
    ]
}
```

##### OR inside an observation, CIDR and IN
```shell
python main.py translate criminalip query '{}' "[ipv4-addr:value ISSUBSET '8.8.8.0/24' AND network-traffic:dst_port IN (80, 443)]"
```
```json
{
    "queries": [
        "ip: 8.8.8.0/24 port: 80 OR ip: 8.8.8.0/24 port: 443"
    ]
}
```

##### Multi-word values and time qualifiers
```shell
python main.py translate criminalip query '{}' "[software:name = 'Plesk Obsidian' AND network-traffic:dst_port = 8443] START t'2026-10-01T00:00:00Z' STOP t'2026-10-22T00:00:00Z'"
```
```json
{
    "queries": [
        "{\"post_filter\": {\"start\": \"2026-10-01T00:00:00Z\", \"stop\": \"2026-10-22T00:00:00Z\", \"terms\": [{\"field\": \"software.product\", \"negate\": false, \"value\": \"Plesk Obsidian\"}]}, \"query\": \"port: 8443 product: Obsidian before: 2026-10-23\"}"
    ]
}
```

#### Multiple Observations
```shell
python main.py translate criminalip query '{}' "[ipv4-addr:value = '1.1.1.1' AND network-traffic:dst_port = 53] OR [x509-certificate:subject = 'dns.google' AND network-traffic:protocols[*] = 'https']"
```
```json
{
    "queries": [
        "ip: 1.1.1.1 port: 53 OR service: https ssl_subject_common_name: dns.google"
    ]
}
```

### STIX Transmit ping
```shell
python main.py transmit criminalip '{"host":"api.criminalip.io","port":443}' '{"auth":{"api_key":"<API KEY>"}}' ping
```
```json
{
    "success": true
}
```

### STIX Transmit results
```shell
python main.py transmit criminalip '{"host":"api.criminalip.io","port":443}' '{"auth":{"api_key":"<API KEY>"}}' results "ip: 8.8.8.0/24" 0 2
```
The output contains the raw banner records (`ip_address`, `open_port_no`, `service_name`, `software`, `ssl_info`,
and so on). It also contains `metadata` (`{"api_offset": .., "filtered_seen": ..}`) when more records may follow.

### STIX Translate results
```shell
python main.py translate criminalip results '{"type":"identity","id":"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff","name":"criminalip","identity_class":"system"}' '<JSON array of banner records>'
```

### STIX Execute Query
```shell
python main.py execute criminalip criminalip '{"type":"identity","id":"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff","name":"criminalip","identity_class":"system"}' '{"host":"api.criminalip.io","port":443}' '{"auth":{"api_key":"<API KEY>"}}' "[ipv4-addr:value = '8.8.8.0/24' AND network-traffic:dst_port = 443]"
```
#### STIX Execute Query - output (trimmed)
```json
{
    "id": "observed-data--...",
    "type": "observed-data",
    "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
    "objects": {
        "0": {"type": "ipv4-addr", "value": "8.8.8.8"},
        "1": {"type": "network-traffic", "dst_ref": "0", "dst_port": 443, "protocols": ["tcp", "https"]},
        "2": {"type": "x-criminalip-banner", "ip_ref": "0", "as_name": "Google LLC", "cloud_provider": "Google",
              "socket_type": "TCP", "service_name": "HTTPS", "status_code": 200, "title": "Google Public DNS",
              "banner": "HTTP/2.0\nStatus: 200 OK\n...", "jarm": "29d3fd00029d29d00042d43d00041d8f924f5255cbc229bc55efa16391dad6",
              "has_cve": false, "ssl_expired": false, "latitude": 37.751, "longitude": -97.822},
        "3": {"type": "domain-name", "value": "dns.google", "resolves_to_refs": ["0"]},
        "4": {"type": "software", "name": "httpd"},
        "5": {"type": "x509-certificate", "subject": "CN=dns.google", "issuer": "C=US, O=Google Trust Services, CN=WR2",
              "serial_number": "119760305370515512493719377464821648688", "version": "3",
              "validity_not_before": "2026-09-18T20:02:29Z", "validity_not_after": "2026-12-11T20:02:28Z",
              "hashes": {"SHA-256": "94e2eeab5836c21ea772a00e89b7ddaa43203f581e639ae26a3353dc0b7d7c48"},
              "signature_algorithm": "SHA256-RSA"},
        "6": {"type": "x-oca-geo", "country_iso_code": "US"}
    },
    "first_observed": "2026-10-20T15:45:33.000Z",
    "last_observed": "2026-10-20T15:45:33.000Z",
    "number_observed": 1
}
```

### Results mapping

| Criminal IP field | STIX |
|--|--|
| `ip_address` | `ipv4-addr.value`, referenced from `network-traffic.dst_ref`, `domain-name.resolves_to_refs` and `x-criminalip-banner.ip_ref` |
| `open_port_no`, `socket_type`, `service_name` | `network-traffic.dst_port`, `network-traffic.protocols` (lower case; `["ipv4"]` when both are missing) |
| `hostname` (PTR) | `domain-name.value` |
| `software[]`, `operating_systems[]` (v1: `product`/`product_version`) | `software.name` / `software.version`; the literal `Unknown` is dropped |
| `ssl_info`, `ssl_*` | `x509-certificate` (subject/issuer DN, serial number, version, validity, SHA-256, signature algorithm) |
| `country`, `city` | `x-oca-geo.country_iso_code`, `x-oca-geo.city_name` |
| `scan_dtime` (UTC) | `first_observed`, `last_observed` |
| `as_name`, `org_name`, `cloud_source`, `title`, `status_code`, `banner`, `jarm`, `tags`, `tech_stacks`, `has_cve`, `ssl_expired`, `latitude`, `longitude` | `x-criminalip-banner` custom object |

`as_name` goes into the custom object, not into `autonomous-system`, because the STIX `autonomous-system`
object requires `number`, and banner search does not return the ASN number.

### Pagination and API credits

- Criminal IP returns **10 records per call**, and the `offset` parameter is a record index (at most 9900).
- Without client-side checks, stix-shifter's `offset` is used directly as the API offset.
- With client-side checks (a time window or a multi-word phrase), `offset`/`length` count *filtered* records.
  The `metadata` returned with each page lets the caller resume without scanning again from the start.
- A single `results` request makes at most `max_api_calls` search calls (10 by default), never reads past
  `result_limit`, and stops early on an empty page or once `count` is reached. Two kinds of extra call can happen on
  top of that: up to 2 retries of a page that hit the per-key concurrency limit, and one `/v1/user/me` call after a
  `status: 500` to tell a bad key apart from a server error.
- If a request stops at `max_api_calls` before `length` records were found, it returns fewer records plus
  `metadata`. Callers should pass `metadata` back with the next `offset`; without it, a query with client-side
  checks is scanned again from the start.
- Calls are spaced at least 0.5 s apart within one process, including across separate `results` requests.

### Error handling

Criminal IP usually reports errors with HTTP 200 and a `status` field in the body. The connector decides success from
`body.status`:

| Criminal IP | stix-shifter code |
|--|--|
| `status: 403` "check access failed" (missing key), `401` "invalid api key", or `500` from `/v1/user/me` (bad key) | `authentication_fail` |
| `status: 400` (bad query or offset) | `invalid_query` |
| `status: 404`/`412`/`420` | `invalid_parameter` |
| "Results are limited" (plan range exceeded), Cloudflare challenge (`cf-mitigated`) | `forbidden` |
| `status: 429`, or 403 "unable to call api at the same time" after retries | `too_many_requests` |
| `status: 500`/`502`/`503`/`504`, non-JSON (HTML) response | `service_unavailable` |

### Limitations

- Only banner search is queried. IP reports, domain scans and exploit search are not part of this connector.
- Filter matching is Criminal IP's own term matching, not strict STIX equality. For example, `as_name: Google`
  matches `Google LLC`.
- Equality only: there are no ranges, wildcards, `LIKE` or `MATCHES`.
- IPv4 only.
- There is no filter for `autonomous-system:number`, `software:vendor` or the certificate serial/validity, so these are
  unmapped.
- CVE IDs are not part of banner results (only the `has_cve` flag). `vulnerability:name` can be searched on, but it
  is not returned.
- Results from separate queries (for example, AND-groups with different client-side checks) may overlap.

### References
- [Criminal IP](https://www.criminalip.io)
- [Criminal IP search filters](https://www.criminalip.io/developer/api)
