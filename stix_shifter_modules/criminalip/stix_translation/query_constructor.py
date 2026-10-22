"""STIX pattern -> Criminal IP banner search query (GET /v2/banner/search ``query`` parameter).

Criminal IP query language facts (all verified live):

* ``filter: value`` terms separated by spaces are ANDed; ``NOT`` before a term negates it.
* ``OR`` has the LOWEST precedence and splits the query into AND-groups, i.e. the server reads
  ``a b OR c`` as ``(a AND b) OR c``. There are no parentheses. The translator therefore converts every
  pattern to disjunctive normal form (DNF) and emits ``group1 OR group2 ...``.
* Values cannot contain spaces, and quoted values match nothing. Multi-word values are sent as their longest
  single token, and the full phrase is verified client side (see post_filter.py).
* ``after:`` is broken (always 0 results); ``before:`` works. START/STOP qualifiers become ``before:`` plus a
  client-side ``scan_dtime`` window.

Output contract with stix_transmission:

``translate_pattern`` returns a LIST of queries. Each one is executed independently by transmission and the
results are concatenated. Each list item is either

* a plain Criminal IP query string (no client-side filtering needed), or
* a JSON object string ``{"query": "<criminal ip query>", "post_filter": {...}}``. Transmission must apply
  ``post_filter.record_matches`` to every returned record (see post_filter.py for the format).

All AND-groups that share the same client-side requirements (time window + phrase checks) are merged into a
single query, so a typical pattern yields exactly one query.
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

from .post_filter import FILTER_RESULT_FIELDS, build_search_id

logger = logging.getLogger(__name__)

# Upper bound on OR-groups in one translated pattern; DNF can grow exponentially and every group makes the
# query string longer. Patterns above this are rejected instead of silently truncated.
MAX_DNF_GROUPS = 64

TIME_FILTER = "before"
IP_FILTER = "ip"
UPPERCASE_FILTERS = {"country", "ssl_subject_country"}
BOOLEAN_FILTERS = {"ssl_expired"}
INTEGER_FILTERS = {"port", "status_code"}
DN_ATTRIBUTE_FILTERS = {
    "ssl_subject_common_name": {"CN": "ssl_subject_common_name", "O": "ssl_subject_organization",
                                "C": "ssl_subject_country"},
    "ssl_issuer_organization": {"O": "ssl_issuer_organization"},
}
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
        if " " not in value and "\t" not in value:
            return _term("s", field, value, negate)
        result_field = FILTER_RESULT_FIELDS.get(field)
        if not result_field:
            raise SearchFeatureNotSupportedError(
                "Criminal IP filter values cannot contain spaces and '{}' cannot be verified client side: '{}'"
                .format(field, value))
        phrase = " ".join(value.split())
        if negate:
            # 'NOT field: token' would also drop unrelated records, so only the client side check is used.
            return _term("p", result_field, phrase, True)
        token = max(phrase.split(" "), key=len)
        return [frozenset([("s", field, token, False), ("p", result_field, phrase, False)])]

    def _field_tree(self, field, raw_value, comparator, negate):
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


def _render_queries(dnf):
    buckets = {}   # signature -> list of server-side group strings
    order = []
    for group in dnf:
        server = sorted((t for t in group if t[0] == "s"), key=lambda t: (t[1] != IP_FILTER, t[1], t[2], t[3]))
        posts = tuple(sorted(t for t in group if t[0] == "p"))
        windows = [t for t in group if t[0] == "t"]
        if not server:
            raise SearchFeatureNotSupportedError(
                "every OR-branch of the pattern needs at least one condition Criminal IP can search on")
        start = stop = None
        if windows:
            # Several windows in one group (nested qualifiers) -> use their intersection.
            start = max(w[1] for w in windows)
            stop = min(w[2] for w in windows)
        group_terms = [_render_term(t) for t in server]
        if stop:
            group_terms.append("{}: {}".format(TIME_FILTER, _before_date(stop)))
        signature = (start, stop, posts)
        if signature not in buckets:
            buckets[signature] = []
            order.append(signature)
        rendered = " ".join(group_terms)
        if rendered not in buckets[signature]:
            buckets[signature].append(rendered)

    queries = []
    for signature in order:
        start, stop, posts = signature
        query = " OR ".join(buckets[signature])
        post_filter = {}
        if start:
            post_filter["start"] = start
        if stop:
            post_filter["stop"] = stop
        if posts:
            post_filter["terms"] = [{"field": f, "value": v, "negate": n} for _, f, v, n in posts]
        queries.append(build_search_id(query, post_filter))
    return queries


def translate_pattern(pattern: Pattern, data_model_mapping, options):
    # No default time window is applied when the pattern has no START/STOP qualifier: Criminal IP data is
    # internet-scan data collected over days/weeks, so stix-shifter's "last N minutes" default would always
    # return nothing. The result limit is enforced by transmission (offset/length/result_limit).
    translator = QueryStringPatternTranslator(pattern, data_model_mapping)
    queries = _render_queries(translator.dnf)
    logger.debug("Criminal IP queries: %s", json.dumps(queries))
    return queries
