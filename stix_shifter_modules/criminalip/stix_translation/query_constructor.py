"""STIX pattern -> Criminal IP queries.

Criminal IP banner search query language facts (all verified live):

* ``filter: value`` terms separated by spaces are ANDed; ``NOT`` before a term negates it.
* ``OR`` has the LOWEST precedence and splits the query into AND-groups, i.e. the server reads
  ``a b OR c`` as ``(a AND b) OR c``. There are no parentheses. The translator therefore converts every
  pattern to disjunctive normal form (DNF) and emits ``group1 OR group2 ...``.
* Values cannot contain spaces, and quoted values match nothing. Multi-word values are sent as their longest
  single token, and the full phrase is verified client side (see post_filter.py).
* ``after:`` is broken (always 0 results); ``before:`` works. START/STOP qualifiers become ``before:`` plus a
  client-side ``scan_dtime`` window.

Output contract with stix_transmission (formats are documented in post_filter.py):

``translate_pattern`` returns a LIST of queries; each is executed independently by transmission.

* Patterns that only ask for exact IPv4 addresses (``=`` / ``IN``, joined by OR) become ONE lookup envelope
  ``{"lookup": "ip", "values": [...]}``; patterns that only ask for exact domain names become
  ``{"lookup": "domain", "values": [...]}``. A pattern mixing both yields one of each.
* Every other pattern becomes exactly ONE banner search query: a plain Criminal IP query string, or
  ``{"query": ..., "post_filter": {"any": [...]}}`` when client-side checks are needed. The post filter has one
  group per OR-branch, so results never overlap.
"""
import ipaddress
import json
import logging
import re
from datetime import datetime, timedelta

from stix_shifter_utils.stix_translation.src.patterns.pattern_objects import ObservationExpression, \
    ComparisonExpression, ComparisonComparators, Pattern, CombinedComparisonExpression, \
    CombinedObservationExpression, StartStopQualifier, Qualifier, SetValue, ComparisonExpressionOperators
from stix_shifter_utils.stix_translation.src.patterns.errors import SearchFeatureNotSupportedError
from stix_shifter_utils.stix_translation.src.utils.exceptions import DataMappingException

from .post_filter import FILTER_RESULT_FIELDS, build_search_id, build_lookup_id, LOOKUP_IP, LOOKUP_DOMAIN, \
    normalize_lookup_value

logger = logging.getLogger(__name__)

# Upper bound on OR-groups in one translated pattern; DNF can grow exponentially and every group makes the
# query string longer. Patterns above this are rejected instead of silently truncated.
MAX_DNF_GROUPS = 64

TIME_FILTER = "before"
IP_FILTER = "ip"
SERVICE_FILTER = "service"
TRANSPORT_PROTOCOLS = {"tcp", "udp"}
UPPERCASE_FILTERS = {"country", "ssl_subject_country"}
BOOLEAN_FILTERS = {"ssl_expired"}
INTEGER_FILTERS = {"port", "status_code"}
DN_ATTRIBUTE_FILTERS = {
    "ssl_subject_common_name": {"CN": "ssl_subject_common_name", "O": "ssl_subject_organization",
                                "C": "ssl_subject_country"},
    "ssl_issuer_organization": {"O": "ssl_issuer_organization"},
}
# Filter values reach a Lucene-style query parser on the Criminal IP side (verified live):
# * 'title: OR' fails with "parse_exception: Encountered <OR>"; AND/NOT are operators too;
# * 'title: Obsidi*' is a wildcard search (39k hits), so '*' and '?' widen an equality match;
# * 'title: a(b' fails with a parse_exception; a backslash escape trips the Cloudflare WAF (HTTP 403 challenge).
# A colon inside a value is fine ('title: port:22' parses as one value). So a value is only sent as-is when it is
# a single token without these characters. Otherwise the longest safe fragment is sent and the full value is
# checked client side (post_filter), or the pattern is rejected when that is not possible.
QUERY_OPERATOR_WORDS = {"OR", "AND", "NOT"}
UNSAFE_VALUE_SPLIT = re.compile(r'[\s(){}\[\]^"~*?\\!]+|&&|\|\|')
UNSAFE_TOKEN_PREFIX = "+-/"


def _is_safe_token(token):
    if token == "" or token.upper() in QUERY_OPERATOR_WORDS or token[0] in UNSAFE_TOKEN_PREFIX:
        return False
    return UNSAFE_VALUE_SPLIT.search(token) is None


def _safe_fragments(value):
    fragments = (f.lstrip(UNSAFE_TOKEN_PREFIX) for f in UNSAFE_VALUE_SPLIT.split(value))
    return [f for f in fragments if _is_safe_token(f)]


SUPPORTED_COMPARATORS = {ComparisonComparators.Equal, ComparisonComparators.NotEqual, ComparisonComparators.In,
                         ComparisonComparators.IsSubSet}


# ---------------------------------------------------------------- boolean tree helpers
# A "term" is a hashable tuple:
#   ("s", filter, value, negate)  -> sent to Criminal IP
#   ("p", result_field, value, negate) -> checked client side (post filter)
#   ("t", start_iso, stop_iso)       -> time window (client side + "before:" server side)
# A DNF is a list of frozensets of terms (OR of ANDs).

def _dnf_and(left, right):
    result = []
    for a in left:
        for b in right:
            result.append(a | b)
            if len(result) > MAX_DNF_GROUPS:
                raise SearchFeatureNotSupportedError(
                    "pattern expands to more than {} OR-groups; simplify the pattern".format(MAX_DNF_GROUPS))
    return result


def _dnf_or(left, right):
    result = list(left)
    for group in right:
        if group not in result:
            result.append(group)
    if len(result) > MAX_DNF_GROUPS:
        raise SearchFeatureNotSupportedError(
            "pattern expands to more than {} OR-groups; simplify the pattern".format(MAX_DNF_GROUPS))
    return result


def _term(kind, field, value, negate=False):
    return [frozenset([(kind, field, value, negate)])]


class QueryStringPatternTranslator:

    def __init__(self, pattern: Pattern, data_model_mapper):
        self.dmm = data_model_mapper
        self.comparator_lookup = self.dmm.map_comparator()
        self.pattern = pattern
        self.dnf = self._parse(pattern)

    # ------------------------------------------------------------ value formatting
    @staticmethod
    def _clean_value(field, value):
        if isinstance(value, bool):
            value = "true" if value else "false"
        value = str(value).strip()
        if value == "":
            raise DataMappingException("empty value for Criminal IP filter '{}'".format(field))
        if '"' in value:
            raise SearchFeatureNotSupportedError(
                "double quotes are not supported in Criminal IP filter values ({}: {})".format(field, value))
        if field in UPPERCASE_FILTERS:
            value = value.upper()
        if field in BOOLEAN_FILTERS:
            if value.lower() not in ("true", "false"):
                raise DataMappingException("'{}' expects true or false, got '{}'".format(field, value))
            value = value.lower()
        if field in INTEGER_FILTERS:
            try:
                value = str(int(value))
            except ValueError:
                raise DataMappingException("'{}' expects an integer, got '{}'".format(field, value))
        return value

    @staticmethod
    def _validate_ip(value, comparator):
        try:
            if "/" in value:
                net = ipaddress.ip_network(value, strict=False)
                if net.version != 4:
                    raise ValueError()
                return str(net)
            addr = ipaddress.ip_address(value)
            if addr.version != 4:
                raise ValueError()
            if comparator == ComparisonComparators.IsSubSet:
                return "{}/32".format(addr)
            return str(addr)
        except ValueError:
            raise DataMappingException(
                "Criminal IP only supports IPv4 addresses and CIDR ranges, got '{}'".format(value))

    @staticmethod
    def _parse_dn(value):
        """'C=US, O=Google Trust Services, CN=WR2' -> {'C': 'US', 'O': 'Google Trust Services', 'CN': 'WR2'}"""
        if "=" not in value:
            return None
        attributes = {}
        for part in re.split(r"\s*[,/]\s*(?=[A-Za-z]+\s*=)", value.strip().strip("/")):
            if "=" in part:
                key, _, val = part.partition("=")
                if val.strip():
                    attributes[key.strip().upper()] = val.strip()
        return attributes

    def _value_tree(self, field, value, negate):
        """DNF for a single 'field = value' (negated when negate is True)."""
        if _is_safe_token(value):
            return _term("s", field, value, negate)
        result_field = FILTER_RESULT_FIELDS.get(field, (None,))[0]
        if not result_field:
            raise SearchFeatureNotSupportedError(
                "Criminal IP cannot search '{}' for a value with spaces, operator words (OR/AND/NOT) or query "
                "syntax characters, and the value cannot be verified client side: '{}'".format(field, value))
        phrase = " ".join(value.split())
        if negate:
            # 'NOT field: token' would also drop unrelated records, so only the client side check is used.
            return _term("p", result_field, phrase, True)
        fragments = _safe_fragments(phrase)
        if not fragments:
            raise SearchFeatureNotSupportedError(
                "'{}' has no part that Criminal IP can search on (only operator words or query syntax)".format(value))
        token = max(fragments, key=len)
        return [frozenset([("s", field, token, False), ("p", result_field, phrase, False)])]

    def _field_tree(self, field, raw_value, comparator, negate):
        if field == SERVICE_FILTER and str(raw_value).strip().lower() in TRANSPORT_PROTOCOLS:
            # 'service:' holds application protocols (ssh, http, ...); 'tcp'/'udp' would match nothing there.
            # There is no transport filter, so it is checked client side against the record's socket_type.
            return _term("p", "socket_type", str(raw_value).strip().lower(), negate)
        if field == IP_FILTER:
            return _term("s", field, self._validate_ip(str(raw_value).strip(), comparator), negate)
        if comparator == ComparisonComparators.IsSubSet:
            raise SearchFeatureNotSupportedError("ISSUBSET is only supported for IPv4 address fields")

        value = self._clean_value(field, raw_value)
        if field in DN_ATTRIBUTE_FILTERS:
            attributes = self._parse_dn(value)
            if attributes is not None:
                parts = [(cip, attributes[attr]) for attr, cip in DN_ATTRIBUTE_FILTERS[field].items()
                         if attr in attributes]
                if not parts:
                    raise DataMappingException(
                        "no supported attribute ({}) in distinguished name '{}'".format(
                            ", ".join(DN_ATTRIBUTE_FILTERS[field].keys()), value))
                trees = [self._value_tree(cip, self._clean_value(cip, v), negate) for cip, v in parts]
                tree = trees[0]
                for other in trees[1:]:
                    # NOT (a AND b) == NOT a OR NOT b
                    tree = _dnf_or(tree, other) if negate else _dnf_and(tree, other)
                return tree
        return self._value_tree(field, value, negate)

    # ------------------------------------------------------------ pattern walking
    def _comparison(self, expression: ComparisonExpression):
        stix_object, stix_field = expression.object_path.split(':', 1)
        mapped_fields = self.dmm.map_field(stix_object, stix_field)
        if not mapped_fields:  # stripped earlier by stix-shifter; defensive only
            raise DataMappingException("Unable to map {}".format(expression.object_path))
        comparator = expression.comparator
        if comparator not in SUPPORTED_COMPARATORS:
            raise SearchFeatureNotSupportedError(
                "comparison operator {} is not supported by Criminal IP".format(comparator.name))

        negate = (comparator == ComparisonComparators.NotEqual) != bool(expression.negated)
        if isinstance(expression.value, SetValue):
            values = list(expression.value.element_iterator())
        else:
            values = [expression.value]

        tree = None
        for value in values:
            for field in mapped_fields:
                sub = self._field_tree(field, value, comparator, negate)
                if tree is None:
                    tree = sub
                elif negate:
                    tree = _dnf_and(tree, sub)   # NOT (a OR b) == NOT a AND NOT b
                else:
                    tree = _dnf_or(tree, sub)
        return tree

    def _parse(self, expression):
        if isinstance(expression, Pattern):
            return self._parse(expression.expression)
        if isinstance(expression, ComparisonExpression):
            return self._comparison(expression)
        if isinstance(expression, CombinedComparisonExpression):
            left = self._parse(expression.expr1)
            right = self._parse(expression.expr2)
            if expression.operator == ComparisonExpressionOperators.And:
                return _dnf_and(left, right)
            return _dnf_or(left, right)
        if isinstance(expression, ObservationExpression):
            return self._parse(expression.comparison_expression)
        if isinstance(expression, CombinedObservationExpression):
            # Observation AND / OR both become a union of results (stix-shifter convention); FOLLOWEDBY has no
            # Criminal IP equivalent.
            if str(expression.operator) not in self.comparator_lookup:
                raise SearchFeatureNotSupportedError(
                    "observation operator {} is not supported".format(expression.operator.name))
            return _dnf_or(self._parse(expression.expr1), self._parse(expression.expr2))
        if isinstance(expression, StartStopQualifier):
            inner = self._parse(expression.observation_expression)
            window = frozenset([("t", expression.start_iso, expression.stop_iso, False)])
            return [group | window for group in inner]
        if isinstance(expression, Qualifier):
            logger.warning("Qualifier %s is not supported by Criminal IP and is ignored", expression.qualifier)
            return self._parse(expression.observation_expression)
        raise RuntimeError("Unknown Recursion Case for expression={}, type(expression)={}".format(
            expression, type(expression)))


# ---------------------------------------------------------------- query rendering
def _render_term(term):
    _, field, value, negate = term
    return "{}{}: {}".format("NOT " if negate else "", field, value)


def _before_date(stop_iso):
    """``before:`` takes a date; use the day after STOP so STOP's own day is included (exact cut is client side)."""
    stop = datetime.strptime(stop_iso[:10], "%Y-%m-%d")
    return (stop + timedelta(days=1)).strftime("%Y-%m-%d")


def _client_checks(server, posts):
    """Client-side re-check of one OR-branch: re-checkable server terms plus phrase checks."""
    checks = []
    phrase_fields = {field for _, field, _, negate in posts if not negate}
    for _, field, value, negate in server:
        if field in FILTER_RESULT_FIELDS and FILTER_RESULT_FIELDS[field][0] not in phrase_fields:
            result_field, mode = FILTER_RESULT_FIELDS[field]
            checks.append({"field": result_field, "value": value, "negate": negate, "match": mode})
    for _, field, value, negate in posts:
        checks.append({"field": field, "value": value, "negate": negate, "match": "contains"})
    return checks


def _render_queries(dnf):
    """Renders the DNF as ONE banner search query (plus one client-side check group per OR-branch if needed)."""
    rendered_groups = []
    client_groups = []
    needs_client = False
    for group in dnf:
        server = sorted((t for t in group if t[0] == "s"), key=lambda t: (t[1] != IP_FILTER, t[1], t[2], t[3]))
        posts = sorted(t for t in group if t[0] == "p")
        windows = [t for t in group if t[0] == "t"]
        if not server:
            raise SearchFeatureNotSupportedError(
                "every OR-branch of the pattern needs at least one condition Criminal IP can search on")
        client_group = {}
        if windows:
            # Several windows in one group (nested qualifiers) -> use their intersection.
            client_group["start"] = max(w[1] for w in windows)
            client_group["stop"] = min(w[2] for w in windows)
        if posts or windows:
            needs_client = True
        checks = _client_checks(server, posts)
        if checks:
            client_group["terms"] = checks
        group_terms = [_render_term(t) for t in server]
        if windows:
            group_terms.append("{}: {}".format(TIME_FILTER, _before_date(client_group["stop"])))
        rendered = " ".join(group_terms)
        if rendered not in rendered_groups:
            rendered_groups.append(rendered)
        if client_group not in client_groups:
            client_groups.append(client_group)

    query = " OR ".join(rendered_groups)
    if not needs_client:
        return [query]
    return [build_search_id(query, {"any": client_groups})]


# ---------------------------------------------------------------- lookup detection
LOOKUP_PATHS = {"ipv4-addr:value": LOOKUP_IP, "domain-name:value": LOOKUP_DOMAIN}


class _NotALookup(Exception):
    pass


def _lookup_comparison(expression, found):
    lookup = LOOKUP_PATHS.get(expression.object_path)
    if lookup is None or expression.negated or \
            expression.comparator not in (ComparisonComparators.Equal, ComparisonComparators.In):
        raise _NotALookup()
    if isinstance(expression.value, SetValue):
        values = list(expression.value.element_iterator())
    else:
        values = [expression.value]
    for raw in values:
        value = normalize_lookup_value(lookup, str(raw))
        if value is None:
            raise _NotALookup()   # CIDR or invalid -> banner search (which validates and reports errors)
        if value not in found[lookup]:
            found[lookup].append(value)


def _collect_lookups(expression, found):
    if isinstance(expression, Pattern):
        _collect_lookups(expression.expression, found)
    elif isinstance(expression, Qualifier):
        # Lookups return Criminal IP's current verdict for the value; time qualifiers do not apply to them.
        _collect_lookups(expression.observation_expression, found)
    elif isinstance(expression, CombinedObservationExpression):
        if expression.operator.name not in ("And", "Or"):
            raise _NotALookup()
        _collect_lookups(expression.expr1, found)
        _collect_lookups(expression.expr2, found)
    elif isinstance(expression, ObservationExpression):
        _collect_lookups(expression.comparison_expression, found)
    elif isinstance(expression, CombinedComparisonExpression):
        if expression.operator != ComparisonExpressionOperators.Or:
            raise _NotALookup()
        _collect_lookups(expression.expr1, found)
        _collect_lookups(expression.expr2, found)
    elif isinstance(expression, ComparisonExpression):
        _lookup_comparison(expression, found)
    else:
        raise _NotALookup()


def lookup_queries(pattern):
    """Returns lookup envelopes when the pattern only asks for exact IPv4 addresses and/or domain names
    (joined by OR), else None."""
    found = {LOOKUP_IP: [], LOOKUP_DOMAIN: []}
    try:
        _collect_lookups(pattern, found)
    except _NotALookup:
        return None
    queries = [build_lookup_id(kind, found[kind]) for kind in (LOOKUP_IP, LOOKUP_DOMAIN) if found[kind]]
    return queries or None


def translate_pattern(pattern: Pattern, data_model_mapping, options):
    # No default time window is applied when the pattern has no START/STOP qualifier: Criminal IP data is
    # internet-scan data collected over days/weeks, so stix-shifter's "last N minutes" default would always
    # return nothing. The result limit is enforced by transmission (offset/length/result_limit).
    queries = lookup_queries(pattern)
    if not queries:
        queries = _render_queries(QueryStringPatternTranslator(pattern, data_model_mapping).dnf)
    logger.debug("Criminal IP queries: %s", json.dumps(queries))
    return queries
