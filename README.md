# stix-shifter Criminal IP connector

A [stix-shifter](https://github.com/opencybersecurityalliance/stix-shifter) connector for the
[Criminal IP](https://www.criminalip.io) threat-intelligence API, maintained by [Huntbase](https://huntbase.io).
It translates STIX patterns into Criminal IP **banner search** queries (`/v2/banner/search`), or into IP report /
domain verdict lookups for exact IPs and domains, and turns the results (IP, ASN, port, service, software, TLS
certificate, CVEs, threat scores, geo and so on) into STIX `observed-data`. Native Criminal IP queries can be passed
through as well.

The connector lives in `stix_shifter_modules/criminalip/` and follows the stix-shifter module layout exactly, so
it can be copied into a stix-shifter tree unchanged (for example, for an upstream pull request).

```
stix_shifter_modules/criminalip/
├── configuration/          config.json, lang_en.json
├── stix_translation/       query_constructor.py, query_translator.py, results_translator.py, post_filter.py
│   └── json/               from_stix_map.json, to_stix_map.json, operators.json
├── stix_transmission/      api_client.py, connector.py, error_mapper.py
├── tests/                  unit tests (translation + mocked transmission)
├── entry_point.py
├── README.md               connector documentation (translation rules, examples, limitations)
└── criminalip_supported_stix.md
```

For the full connector documentation (mapping rules, query quirks, pagination, error codes and limitations),
see [stix_shifter_modules/criminalip/README.md](stix_shifter_modules/criminalip/README.md).

## Install the released wheel

Each `v*` tag publishes `stix_shifter_modules_criminalip-<version>-py3-none-any.whl` (plus `SHA256SUMS`) as a
[GitHub release](https://github.com/huntbase-io/stix-shifter-criminalip/releases) asset. It installs the module at
`stix_shifter_modules/criminalip` next to an installed stix-shifter (tested with stix-shifter 8.1.2 from PyPI):

```bash
pip install "stix-shifter==8.1.2" "stix-shifter-utils==8.1.2" \
  https://github.com/huntbase-io/stix-shifter-criminalip/releases/download/v1.0.0/stix_shifter_modules_criminalip-1.0.0-py3-none-any.whl
stix-shifter translate criminalip query '{}' "[ipv4-addr:value = '8.8.8.0/24' AND network-traffic:dst_port = 443]"
```

With uv, reference the asset in `[tool.uv.sources]` (uv.lock then records its sha256):

```toml
[project]
dependencies = ["stix-shifter-modules-criminalip==1.0.0"]

[tool.uv.sources]
stix-shifter-modules-criminalip = { url = "https://github.com/huntbase-io/stix-shifter-criminalip/releases/download/v1.0.0/stix_shifter_modules_criminalip-1.0.0-py3-none-any.whl" }
```

## Install into a stix-shifter checkout

```bash
# upstream; Huntbase uses its fork: git clone -b develop https://github.com/huntbase-io/stix-shifter.git
git clone https://github.com/opencybersecurityalliance/stix-shifter.git
cd stix-shifter
python3 -m venv .venv && . .venv/bin/activate
python generate_requirements.py && pip install -r requirements-dev.txt

# link (development) or copy (packaging / upstream PR) the module into the checkout
/path/to/stix-shifter-criminalip/scripts/install_into_stix_shifter.sh .          # symlink
/path/to/stix-shifter-criminalip/scripts/install_into_stix_shifter.sh --copy .   # copy
```

The connector has no extra Python dependencies beyond stix-shifter's own.

To package it as a wheel the way stix-shifter does (run inside the stix-shifter checkout, after a `--copy` install):

```bash
MODE='criminalip' VERSION='1.0.0' python -m build_tools.run_build
```

## Use

Keep the key out of files and shell history. For example, export it from a `.env` file that git ignores:

```bash
set -a; . ./.env; set +a          # defines API_KEY
CONN='{"host":"api.criminalip.io","port":443,"options":{"result_limit":100,"max_api_calls":10}}'
AUTH="{\"auth\":{\"api_key\":\"$API_KEY\"}}"
IDENTITY='{"type":"identity","id":"identity--f431f809-377b-45e0-aa1c-6a4751cae5ff","name":"criminalip","identity_class":"system"}'
```

Translate a STIX pattern into Criminal IP queries (no API call):

```bash
python main.py translate criminalip query '{}' \
  "[software:name = 'OpenSSH' AND network-traffic:dst_port = 22 AND x-oca-geo:country_iso_code = 'KR']"
# {"queries": ["country: KR port: 22 product: OpenSSH"]}

python main.py translate criminalip query '{}' "[ipv4-addr:value ISSUBSET '8.8.8.0/24' AND network-traffic:dst_port IN (80, 443)]"
# {"queries": ["ip: 8.8.8.0/24 port: 80 OR ip: 8.8.8.0/24 port: 443"]}
```

Transmit (ping, then fetch raw results for a query at offset 0, length 10):

```bash
python main.py transmit criminalip "$CONN" "$AUTH" ping
python main.py transmit criminalip "$CONN" "$AUTH" results "ip: 8.8.8.0/24" 0 10
```

Execute (translate, query, and convert the results into a STIX bundle):

```bash
python main.py execute criminalip criminalip "$IDENTITY" "$CONN" "$AUTH" \
  "[ipv4-addr:value = '8.8.8.0/24' AND network-traffic:dst_port = 443]" -r 10
```

Exact IPv4 addresses and domain names are answered by Criminal IP's lookup endpoints (IP report with ASN, scores,
open ports and CVEs; domain verdicts) instead of banner search. Domain scans are never started:

```bash
python main.py translate criminalip query '{}' "[ipv4-addr:value IN ('185.220.101.1', '34.22.91.145')]"
# {"queries": ["{\"lookup\": \"ip\", \"values\": [\"185.220.101.1\", \"34.22.91.145\"]}"]}
python main.py execute criminalip criminalip "$IDENTITY" "$CONN" "$AUTH" "[domain-name:value = 'google.com']"
```

### Criminal IP query passthrough

Native Criminal IP banner search queries can be passed through unchanged with the `{"language": "criminalip"}`
option (like QRadar's AQL passthrough). Translation only warns about unknown filter names, `after:` and quoted filter
values, which Criminal IP silently answers with nothing:

```bash
python main.py translate criminalip query '{}' "product: OpenSSH port: 22 country: KR" '{"language":"criminalip"}'
# {"queries": ["product: OpenSSH port: 22 country: KR"]}
python main.py transmit criminalip "$CONN" "$AUTH" results "product: OpenSSH port: 22 country: KR" 0 10
python main.py execute criminalip criminalip "$IDENTITY" \
  '{"host":"api.criminalip.io","port":443,"options":{"language":"criminalip"}}' "$AUTH" "product: OpenSSH port: 22 country: KR"
```

### Translate raw results

Translate raw Criminal IP banner records into STIX (no API call):

```bash
python main.py translate criminalip results "$IDENTITY" "$(jq -c '.data.result' banner_search_response.json)"
```

### Connection options

| Option | Default | Meaning |
|--|--|--|
| `host` / `port` | `api.criminalip.io` / `443` | API endpoint |
| `options.result_limit` | `100` | Maximum records returned per query (Criminal IP stops at 10,000) |
| `options.max_api_calls` | `10` | Maximum Criminal IP calls for one results request (banner search: 10 records per call; IP lookup: 2 calls per IP; domain lookup: 1–2 calls per domain). Every call costs credits. |
| `options.timeout` | `30` | Seconds per HTTP call |

## Develop and test

```bash
cd /path/to/stix-shifter            # with the module installed as above
python -m pytest stix_shifter_modules/criminalip -q
python -m pytest tests/utils -q     # stix-shifter config/lang validation across all modules (needs a --copy install)
flake8 stix_shifter_modules/criminalip --max-line-length=127
python map_validator/validate_mapping.py stix_shifter_modules/criminalip/stix_translation/json/to_stix_map.json
```

`tests/utils` walks `stix_shifter_modules/` without following symlinks, so it silently skips the module after a
symlink install. Run it after a `--copy` install.

The unit tests use trimmed real Criminal IP responses (`tests/*/sample_responses/`) and make no network calls.

CI (`.github/workflows/ci.yml`) runs these steps on every push and pull request against Huntbase's stix-shifter fork
(`develop`, Python 3.12) after a `--copy` install. flake8 complexity warnings (C901) are reported but do not fail the
build; mapping-validator errors do. Pushing a `v<version>` tag runs `.github/workflows/release.yml`: the same tests, a wheel
build with stix-shifter's `build_tools`, a smoke test of the wheel against stix-shifter 8.1.2 from PyPI, and a GitHub
release with the wheel and `SHA256SUMS`. A weekly workflow (`.github/workflows/live-api-check.yml`) also runs a ping, an IP
lookup, a banner search and a passthrough query against the live API; it needs the `CRIMINALIP_API_KEY` repository
secret and skips itself when the secret is not set.

## License

Apache License 2.0. See [LICENSE](LICENSE).
