# Criminal IP Connector

**Table of Contents**

- [Criminal IP API Endpoints](#criminal-ip-api-endpoints)
- [How patterns are translated](#how-patterns-are-translated)
- [IP and domain lookups](#ip-and-domain-lookups)
- [Criminal IP query passthrough](#criminal-ip-query-passthrough)
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
`observed-data` object. Patterns that only ask for exact IPv4 addresses or domain names are answered by the
Criminal IP **IP report** and **domain verdict** lookups instead (see [IP and domain lookups](#ip-and-domain-lookups)),
and native Criminal IP queries can be passed through unchanged (see
[Criminal IP query passthrough](#criminal-ip-query-passthrough)).

Supported STIX objects, properties and operators are listed in [criminalip_supported_stix.md](criminalip_supported_stix.md).

### Criminal IP API Endpoints

| Connector Method | Criminal IP API Endpoint | Method |
|--|--|--|
| Ping | `https://api.criminalip.io/v1/user/me` | POST (empty body) |
| Results (search) | `https://api.criminalip.io/v2/banner/search?query=<query>&offset=<n>` | GET |
| Results (IP lookup) | `https://api.criminalip.io/v2/asset/ip/report?ip=<ip>` and `/v1/asset/ip/report/summary?ip=<ip>` | GET |
| Results (domain lookup) | `https://api.criminalip.io/v1/domain/quick/hash/view?domain=<d>` (+ `/v1/domain/quick/malicious/view` when the verdict is not "safe") | GET |

Authentication uses the `x-api-key` header. Ping uses `/v1/user/me` because it is cheap, authenticated and has no
threat-data side effects. Its response echoes the API key, so the connector never logs or returns that response.

### Connection and configuration

| Parameter | Default | Notes |
|--|--|--|
| `host` | `api.criminalip.io` | |
| `port` | `443` | |
| `options.result_limit` | `100` | Maximum records per query. Criminal IP itself stops at 10,000. |
| `options.max_api_calls` | `10` | Maximum Criminal IP calls for one `results` request. A banner-search call returns 10 records; an IP lookup costs 2 calls per IP and a domain lookup 1–2 calls per domain. Every call costs credits. |
| `options.timeout` | `30` | Seconds per HTTP call |
| `configuration.auth.api_key` | | Criminal IP API key |

### How patterns are translated

Criminal IP's query language is a list of `filter: value` terms. Several quirks of that language shape the
translator:

| Criminal IP behaviour (verified live) | What the translator does |
|--|--|
| Terms separated by a space are ANDed, and `NOT` negates one term. | `AND` becomes a space. `!=`, `NOT =` and `NOT IN` become `NOT filter: value`. |
| `OR` has the lowest precedence, so `a b OR c` means `(a AND b) OR c`, and there are no parentheses. | The pattern is rewritten into disjunctive normal form (an OR of AND-groups): `[a AND (b OR c)]` becomes `a b OR a c`. `IN (x, y)` is distributed the same way. At most 64 groups are allowed. |
| Values cannot contain spaces, and quoted values match nothing. | For a multi-word value, the longest word is sent (`software:name = 'Plesk Obsidian'` becomes `product: Obsidian`), and the full phrase is checked against each returned record on the client side. A negated multi-word value is checked only on the client side. The same applies to values that the server's Lucene-style parser would read as syntax: the operator words `OR`/`AND`/`NOT` (parse error), `*` and `?` (wildcards, which would widen an exact match), brackets, `^`, `~`, `!`, `&&`/`\|\|` and a leading `+`, `-` or `/` (parse errors). Only the longest plain fragment is sent (`title = 'Obsidi*'` becomes `title: Obsidi`), and the exact value is checked on the client side. A backslash cannot be used as an escape because it triggers the Cloudflare WAF. When the field has no client-side check (for example `isp`), such a value is rejected. A colon inside a value is safe (`title: port:22` is read as one value). |
| Unknown filter names are silently treated as keywords. | Only documented filter names are emitted. Transmission checks `data.groups` and logs a warning if a filter was not recognised. |
| `after:` always returns 0 results, but `before:` works. | `START t'..' STOP t'..'` becomes `before: <STOP date + 1 day>` plus a client-side `scan_dtime` window [START, STOP]. |
| `ip:` accepts a single IPv4 address or a CIDR range. IPv6 is not supported. | `ipv4-addr:value = '1.2.3.0/24'` and `ISSUBSET '1.2.3.0/24'` both become `ip: 1.2.3.0/24`. An IPv6 value raises an error, and `ipv6-addr` is unmapped. |
| `service:` is the real filter name; `service_name:` is ignored. | `network-traffic:protocols[*]` becomes `service:`. |

Unmapped STIX properties and unsupported operators (`>`, `<`, `LIKE`, `MATCHES`, `ISSUPERSET`, `FOLLOWEDBY`) are
handled the usual stix-shifter way. When they are ORed with something mappable, they are dropped with a warning.
Otherwise translation fails with `mapping_error` or `invalid_parameter`.

When there is no `START`/`STOP` qualifier, **no default time window is applied**. Criminal IP holds scan data
collected over days and weeks, so the usual "last *N* minutes" default would always return nothing.

**Query format.** Each entry of `queries` is one of:
- a plain Criminal IP query string, which can be pasted into the Criminal IP UI;
- a JSON string `{"query": "<criminal ip query>", "post_filter": {"any": [...]}}`, used when client-side checks are
  needed (a time window or a multi-word phrase);
- a lookup envelope `{"lookup": "ip", "values": [...]}` or `{"lookup": "domain", "values": [...]}`.

A STIX pattern that goes to banner search always becomes **one** query, so results never overlap. When client-side
checks are needed, `post_filter.any` holds one group per OR-branch: the branch's time window and phrase checks, plus
the branch's server conditions that can be re-checked on a banner record (`ip` by CIDR, `port`, `service`,
`product`, `country`, `as_name`, `title` and so on). A record is kept when **any** group matches, so a record
returned because of one branch is never let through by another branch's checks. Conditions that cannot be
re-checked on a banner record (`cve_id`, `domain_from_banner`, `isp`, `malcode_md5`, ...) are left to the server.

### IP and domain lookups

When a pattern only asks for exact values joined by `OR` (between comparisons or observations), the connector
uses Criminal IP's lookup endpoints instead of banner search:

| Pattern | Query | Calls per value | Endpoints |
|--|--|--|--|
| `[ipv4-addr:value = '1.2.3.4']`, `[ipv4-addr:value IN ('1.2.3.4', '5.6.7.8')]` | `{"lookup": "ip", "values": [...]}` | 2 | `/v2/asset/ip/report` + `/v1/asset/ip/report/summary` |
| `[domain-name:value = 'example.com']`, `IN (...)` | `{"lookup": "domain", "values": [...]}` | 1 (2 if not "safe") | `/v1/domain/quick/hash/view` (+ `/malicious/view`) |

- A pattern with both IPs and domains (e.g. `[ipv4-addr:value = 'x'] OR [domain-name:value = 'y']`) yields one
  query of each kind.
- CIDR values, `!=`/`NOT`, `ISSUBSET`, and any other condition (e.g. `AND network-traffic:dst_port = 22`) keep using
  banner search.
- `START`/`STOP` qualifiers do not apply to lookups: they return Criminal IP's current knowledge of the value.
- **Domain scans are never started.** The quick views are synchronous database lookups; a domain Criminal IP has no
  data for produces no observation.
- `/v2/asset/ip/report` is called without `full=true`, so each section (ports, CVEs, categories) holds at most 20
  items. `full=true` returns 100–200 KB per popular IP and was left out on purpose.
- Fan-out is bounded by `max_api_calls`: with the default of 10, one `results` call looks up at most 5 IPs. The
  `metadata` returned (`{"value_offset": n}`) resumes with the next value. For lookups, `offset`/`length` count
  looked-up **values**, and one IP can produce several observations (one per open port plus a summary).
- If the report summary is temporarily unavailable (e.g. a Cloudflare 522), the IP report is still returned without
  the `is_malicious` verdict.

Lookup results map to STIX as follows:
- **IP summary observation**: `ipv4-addr`, `autonomous-system` with `number` and `name` (from `whois.as_no`; linked by
  `ipv4-addr.belongs_to_refs`), `x-oca-geo` (country, city, region), `domain-name` (PTR hostname),
  `x-criminalip-vulnerability` objects (one per CVE: `cve_id`, CVSS v3/v2 scores, app name/version, vendor,
  description), and `x-criminalip-ip` (`inbound_score`, `outbound_score`, `is_malicious`, `is_vpn`, `is_proxy`,
  `is_tor`, `is_hosting`, `is_cloud`, `is_mobile`, `is_darkweb`, `is_scanner`, `is_snort`, `is_anonymous_vpn`,
  `is_cdn`, `categories`, `ids_classifications`, `issues`, `abuse_record_count`, ...). `first_observed` is the report
  time.
- **One observation per open port** (`port.data[]`), shaped like a banner result: `ipv4-addr`, `network-traffic`,
  `software` (products and operating systems), `x509-certificate` when TLS details are present, `x-oca-geo`, and
  `x-criminalip-banner`. `first_observed` is the port's `confirmed_time`.
- **Domain observation**: `domain-name` and `x-criminalip-domain` (`verdict`, `domain_type`, `malicious_type`,
  `call_count`, `first_seen`).

CVEs use a custom object rather than STIX `vulnerability`, because `vulnerability` is a STIX Domain Object and
cannot be placed inside `observed-data` (other stix-shifter connectors do the same, e.g. `x-splunk-vulnerability`,
`x-ibm-finding`).

### Criminal IP query passthrough

Like QRadar's AQL passthrough, the connector accepts native Criminal IP banner search queries with the
`{"language": "criminalip"}` option. The query is returned unchanged (surrounding whitespace is stripped and runs of
whitespace outside double-quoted phrases are collapsed), transmission sends it to `/v2/banner/search`, and results
are translated to STIX as usual.

```shell
python main.py translate criminalip query '{}' "product: OpenSSH port: 22 country: KR" '{"language":"criminalip"}'
```
```json
{
    "queries": [
        "product: OpenSSH port: 22 country: KR"
    ]
}
```

```shell
python main.py transmit criminalip '{"host":"api.criminalip.io","port":443}' '{"auth":{"api_key":"<API KEY>"}}' results "product: OpenSSH port: 22 country: KR" 0 10
python main.py execute criminalip criminalip '<identity>' '{"host":"api.criminalip.io","port":443,"options":{"language":"criminalip"}}' '{"auth":{"api_key":"<API KEY>"}}' "product: OpenSSH port: 22 country: KR"
```

Translation makes no network calls. It rejects an empty query and logs a warning (the query is still returned) for:
- filter names that are not documented banner-search filters (Criminal IP silently turns them into keywords, e.g.
  `service_name:` instead of `service:`);
- `after:`, which always returns 0 results;
- quoted filter values such as `title: "Plesk Obsidian"`, which match nothing (quotes only work for keyword phrases).

A Criminal IP query never starts with `{`. A passthrough query that does is accepted only if it is one of the
connector's JSON envelopes, otherwise translation fails with `mapping_error`, so it can never be misread. This also
gives a native form for lookups:

```shell
python main.py translate criminalip query '{}' '{"lookup": "ip", "values": ["185.220.101.1"]}' '{"language":"criminalip"}'
```

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
        "{\"post_filter\": {\"any\": [{\"start\": \"2026-10-01T00:00:00Z\", \"stop\": \"2026-10-22T00:00:00Z\", \"terms\": [{\"field\": \"open_port_no\", \"match\": \"equals\", \"negate\": false, \"value\": \"8443\"}, {\"field\": \"software.product\", \"match\": \"contains\", \"negate\": false, \"value\": \"Plesk Obsidian\"}]}]}, \"query\": \"port: 8443 product: Obsidian before: 2026-10-23\"}"
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

For banner results, `as_name` goes into the custom object, not into `autonomous-system`, because the STIX
`autonomous-system` object requires `number`, and banner search does not return the ASN number. IP lookups do return
it, so their observations contain a proper `autonomous-system` object.

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

- Domain scans and exploit search are not part of this connector. Domain lookups use the quick verdict views only.
- Filter matching is Criminal IP's own term matching, not strict STIX equality. For example, `as_name: Google`
  matches `Google LLC`.
- Equality only: there are no ranges, wildcards, `LIKE` or `MATCHES`.
- IPv4 only.
- There is no banner-search filter for `autonomous-system:number` (`as_no:`, `asn:` and `as_number:` were tested live and
  are all treated as keywords), `software:vendor` or the certificate serial/validity, so these are unmapped.
- CVE IDs are not part of banner results (only the `has_cve` flag); they are returned by IP lookups. In banner search,
  `vulnerability:name` can be searched on, but the CVE is not returned.
- Client-side re-checks use simple matching (case-insensitive substring, exact for ports/codes, CIDR for IPs), which can
  be stricter than Criminal IP's own term matching in rare cases.
- An IP lookup and a domain lookup from the same pattern are separate queries and may describe the same host.

### References
- [Criminal IP](https://www.criminalip.io)
- [Criminal IP search filters](https://www.criminalip.io/developer/api)
