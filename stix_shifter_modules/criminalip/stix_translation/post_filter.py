"""Client-side filtering shared by translation (which writes the spec) and transmission (which applies it).

Criminal IP's banner search cannot express everything a STIX pattern can:

* ``after:`` is broken server-side, so a pattern's START bound is enforced here against ``scan_dtime``
  (``before:`` is still sent to the API to narrow the search).
* Filter values cannot contain spaces. For a value such as ``'Apache httpd'`` the translator sends the
  longest single token (``product: Apache``) and asks for the full phrase to be checked here.

Search id format (the "query" handed from translation to transmission):

* a plain Criminal IP query string, e.g. ``ip: 8.8.8.0/24 port: 443`` -> no client-side filtering, or
* a JSON object string ``{"query": "<criminal ip query>", "post_filter": {...}}`` where ``post_filter`` is::

      {
        "start": "2026-10-01T00:00:00.000Z",   # optional, inclusive lower bound on scan_dtime (UTC)
        "stop":  "2026-10-22T00:00:00.000Z",   # optional, inclusive upper bound on scan_dtime (UTC)
        "terms": [                              # optional, every term must hold (AND)
            {"field": "software.product", "value": "Apache httpd", "negate": false}
        ]
      }
"""
import json
from datetime import datetime, timezone

# CIP filter name -> path of the banner result field used to verify a multi-word value client side.
# "a.b" means: field "a" is a list of objects, compare their "b" member. A plain list field compares items.
FILTER_RESULT_FIELDS = {
    "product": "software.product",
    "product_version": "software.version",
    "as_name": "as_name",
    "org": "org_name",
    "city": "city",
    "title": "title",
    "tag": "tags",
    "tech_stack": "tech_stacks",
    "cloud_provider": "cloud_source",
    "hostname": "hostname",
    "ssl_issuer_organization": "ssl_issuer_organization",
    "ssl_subject_organization": "ssl_subject_organization",
    "ssl_subject_common_name": "ssl_subject_common_name",
    "service": "service_name",
}


def build_search_id(query, post_filter=None):
    if not post_filter:
        return query
    return json.dumps({"query": query, "post_filter": post_filter}, sort_keys=True)


def parse_search_id(search_id):
    """Returns (criminal_ip_query_string, post_filter_dict_or_None)."""
    if isinstance(search_id, dict):
        return search_id.get("query", ""), search_id.get("post_filter") or None
    text = (search_id or "").strip()
    if text.startswith("{"):
        try:
            obj = json.loads(text)
        except ValueError:
            return text, None
        if isinstance(obj, dict) and "query" in obj:
            return obj["query"], obj.get("post_filter") or None
    return text, None


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
    if isinstance(value, list):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def term_matches(record, term):
    needle = str(term.get("value", "")).lower()
    found = any(needle in v.lower() for v in _field_values(record, term["field"]))
    return not found if term.get("negate") else found


def record_matches(record, post_filter):
    if not post_filter:
        return True
    start = _parse_time(post_filter.get("start"))
    stop = _parse_time(post_filter.get("stop"))
    if start or stop:
        seen = _parse_time(record.get("scan_dtime"))
        if seen is None:
            return False
        if start and seen < start:
            return False
        if stop and seen > stop:
            return False
    return all(term_matches(record, t) for t in post_filter.get("terms", []))
