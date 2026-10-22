"""Search id format and client-side filtering, shared by translation (which writes them) and transmission
(which reads them).

Search id ("query") formats handed from translation to transmission
-------------------------------------------------------------------
1. A plain Criminal IP banner search query, e.g. ``ip: 8.8.8.0/24 port: 443``. A Criminal IP query never starts
   with ``{``, so any string that does is one of the JSON envelopes below.
2. ``{"query": "<banner search query>", "post_filter": {...}}``: banner search plus client-side checks.
3. ``{"lookup": "ip", "values": ["1.2.3.4", ...]}``: per-IP lookups (``/v2/asset/ip/report`` plus
   ``/v1/asset/ip/report/summary``) for patterns that only ask for exact IPv4 addresses.
4. ``{"lookup": "domain", "values": ["example.com", ...]}``: per-domain lookups
   (``/v1/domain/quick/hash/view``, plus ``/v1/domain/quick/malicious/view`` when the verdict is not "safe").
   Domain scans are never started.

Why client-side checks exist
----------------------------
* ``after:`` is broken server-side, so a pattern's START bound is enforced here against ``scan_dtime``
  (``before:`` is still sent to the API to narrow the search).
* Filter values cannot contain spaces. For ``'Apache httpd'`` the translator sends the longest single token
  (``product: Apache``) and asks for the full phrase to be checked here.

post_filter format::

    {"any": [                          # the record is kept when ANY group matches (OR of AND-groups)
        {"start": "2026-10-01T00:00:00Z",   # optional, inclusive lower bound on scan_dtime (UTC)
         "stop":  "2026-10-22T00:00:00Z",   # optional, inclusive upper bound on scan_dtime (UTC)
         "terms": [{"field": "software.product", "value": "Apache httpd", "negate": false,
                    "match": "contains"}]}   # every term must hold (AND); match: contains | equals | cidr
    ]}

Every group mirrors one OR-branch of the server query. It holds that branch's client-only checks plus the
branch's server-side conditions that can be re-checked on a banner record (for example ``port`` or ``ip``),
so that a record matched by one branch cannot slip through another branch's checks. Server conditions with no
corresponding result field (``cve_id``, ``domain_from_banner``, ...) are trusted to the server.

The legacy single-group form ``{"start", "stop", "terms"}`` is still accepted.
"""
import ipaddress
import json
from datetime import datetime, timezone

# CIP filter name -> (banner result field, match mode). "a.b" means: field "a" is a list of objects; compare
# their "b" member. A plain list field compares its items. Used both for multi-word phrase checks and for
# re-checking server-side conditions of an OR-branch.
FILTER_RESULT_FIELDS = {
    "ip": ("ip_address", "cidr"),
    "port": ("open_port_no", "equals"),
    "status_code": ("status_code", "equals"),
    "country": ("country", "equals"),
    "ssl_expired": ("ssl_expired", "equals"),
    "service": ("service_name", "contains"),
    "product": ("software.product", "contains"),
    "product_version": ("software.version", "contains"),
    "as_name": ("as_name", "contains"),
    "org": ("org_name", "contains"),
    "city": ("city", "contains"),
    "title": ("title", "contains"),
    "tag": ("tags", "contains"),
    "tech_stack": ("tech_stacks", "contains"),
    "cloud_provider": ("cloud_source", "contains"),
    "hostname": ("hostname", "contains"),
    "jarm": ("jarm", "equals"),
    "ssl_issuer_organization": ("ssl_issuer_organization", "contains"),
    "ssl_subject_organization": ("ssl_subject_organization", "contains"),
    "ssl_subject_common_name": ("ssl_subject_common_name", "contains"),
    "ssl_subject_country": ("ssl_subject_country", "equals"),
}

LOOKUP_IP = "ip"
LOOKUP_DOMAIN = "domain"
LOOKUP_TYPES = (LOOKUP_IP, LOOKUP_DOMAIN)


def build_search_id(query, post_filter=None):
    if not post_filter:
        return query
    return json.dumps({"query": query, "post_filter": post_filter}, sort_keys=True)


def build_lookup_id(lookup, values):
    return json.dumps({"lookup": lookup, "values": list(values)}, sort_keys=True)


def _load(search_id):
    if isinstance(search_id, dict):
        return search_id
    text = (search_id or "").strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError:
            return None
        if isinstance(obj, dict):
            return obj
    return None


def parse_lookup(search_id):
    """Returns (lookup_type, [values]) for a lookup envelope, else None."""
    obj = _load(search_id)
    if obj and obj.get("lookup") in LOOKUP_TYPES and isinstance(obj.get("values"), list):
        return obj["lookup"], [str(v).strip() for v in obj["values"] if str(v).strip()]
    return None


def parse_search_id(search_id):
    """Returns (criminal_ip_query_string, post_filter_dict_or_None) for banner search ids."""
    obj = _load(search_id)
    if obj is not None and "query" in obj:
        return obj["query"], obj.get("post_filter") or None
    if isinstance(search_id, dict):
        return search_id.get("query", ""), None
    return (search_id or "").strip(), None


def validate_envelope(text):
    """Raises ValueError unless ``text`` is a well-formed JSON envelope (used for native-query passthrough)."""
    obj = _load(text)
    if obj is None:
        raise ValueError("a query starting with '{' must be a JSON envelope: {\"query\": ...} or "
                         "{\"lookup\": \"ip\"|\"domain\", \"values\": [...]}")
    if "lookup" in obj:
        lookup = parse_lookup(obj)
        if lookup is None or not lookup[1]:
            raise ValueError("lookup envelope needs \"lookup\": \"ip\" or \"domain\" and a non-empty \"values\" list")
        return obj
    if not isinstance(obj.get("query"), str) or not obj["query"].strip():
        raise ValueError("JSON envelope needs a non-empty \"query\" string")
    if obj.get("post_filter") is not None and not isinstance(obj["post_filter"], dict):
        raise ValueError("\"post_filter\" must be an object")
    return obj


def _parse_time(value):
    if not value:
        return None
    value = str(value).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _field_values(record, path):
    if "." in path:
        head, member = path.split(".", 1)
        items = record.get(head) or []
        if isinstance(items, dict):
            items = [items]
        return [str(i.get(member)) for i in items if isinstance(i, dict) and i.get(member) not in (None, "")]
    value = record.get(path)
    if value in (None, ""):
        return []
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def _in_network(value, network):
    try:
        return ipaddress.ip_address(value) in ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False


def term_matches(record, term):
    needle = str(term.get("value", "")).lower()
    mode = term.get("match", "contains")
    values = _field_values(record, term["field"])
    if mode == "cidr":
        found = any(_in_network(v, term.get("value", "")) for v in values)
    elif mode == "equals":
        found = any(needle == v.lower() for v in values)
    else:
        found = any(needle in v.lower() for v in values)
    return not found if term.get("negate") else found


def _group_matches(record, group):
    start = _parse_time(group.get("start"))
    stop = _parse_time(group.get("stop"))
    if start or stop:
        seen = _parse_time(record.get("scan_dtime"))
        if seen is None:
            return False
        if start and seen < start:
            return False
        if stop and seen > stop:
            return False
    return all(term_matches(record, t) for t in group.get("terms", []))


def record_matches(record, post_filter):
    if not post_filter:
        return True
    groups = post_filter.get("any")
    if isinstance(groups, list):
        return any(_group_matches(record, g) for g in groups)
    return _group_matches(record, post_filter)
