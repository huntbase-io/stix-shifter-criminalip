"""Native Criminal IP query passthrough (``{"language": "criminalip"}``), modelled on QRadar's AQL passthrough.

    python main.py translate criminalip query '{}' "product: OpenSSH port: 22 country: KR" '{"language":"criminalip"}'
    -> {"queries": ["product: OpenSSH port: 22 country: KR"]}

The query is returned as-is (only surrounding whitespace is stripped and runs of whitespace outside double-quoted
phrases are collapsed), so transmission sends it unchanged to ``/v2/banner/search``. Nothing is sent over the
network during translation; the checks below only log warnings for constructs that are known to silently return
nothing.

A Criminal IP query never starts with ``{``. A passthrough query that does is treated as one of the connector's
JSON envelopes (see post_filter.py), e.g. ``{"lookup": "ip", "values": ["1.2.3.4"]}`` for IP lookups, and is
rejected unless it is a well-formed envelope, so that it can never be misread.
"""
import re

from stix_shifter_utils.modules.base.stix_translation.base_query_translator import BaseQueryTranslator
from stix_shifter_utils.stix_translation.src.utils.exceptions import DataMappingException
from stix_shifter_utils.utils import logger as utils_logger

from .post_filter import validate_envelope

LANGUAGE = "criminalip"

# Banner search filters documented in the Criminal IP API (see docs/api-reference.md). Any other "name:" is
# silently turned into two keywords by the server and usually matches nothing.
KNOWN_FILTERS = {
    "ip", "port", "service", "product", "product_version", "country", "city", "as_name", "isp", "org",
    "cloud_provider", "hostname", "domain_from_banner", "title", "html_meta_author", "html_meta_description",
    "html_meta_keywords", "html_meta_title", "status_code", "tech_stack", "tag", "favicon", "jarm", "ssl_expired",
    "ssl_issuer_organization", "ssl_subject_common_name", "ssl_subject_country", "ssl_subject_organization",
    "cve_id", "malcode_md5", "snort_classification", "snort_rule", "scanner_port", "scanner_raw", "prefix",
    "after", "before",
}

FILTER_RE = re.compile(r'(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)\s*:')
QUOTED_FILTER_VALUE_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"[^"]*"')
QUOTED_RE = re.compile(r'"[^"]*"')

logger = utils_logger.set_logger(__name__)


def normalize_query(query):
    """Strips the query and collapses whitespace runs outside double-quoted phrases."""
    text = (query or "").strip()
    parts = []
    last = 0
    for match in QUOTED_RE.finditer(text):
        parts.append(re.sub(r"\s+", " ", text[last:match.start()]))
        parts.append(match.group(0))
        last = match.end()
    parts.append(re.sub(r"\s+", " ", text[last:]))
    return "".join(parts)


def query_warnings(query):
    """Returns human-readable warnings for constructs that make Criminal IP return wrong or empty results."""
    warnings = []
    unquoted = QUOTED_RE.sub(" ", query)
    names = [m.group(1) for m in FILTER_RE.finditer(unquoted)]
    unknown = sorted({n for n in names if n.lower() not in KNOWN_FILTERS})
    if unknown:
        warnings.append("unknown filter name(s) {}: Criminal IP silently treats them as keywords (did you mean "
                        "'service' instead of 'service_name'?)".format(unknown))
    if "after" in (n.lower() for n in names):
        warnings.append("'after:' always returns 0 results on Criminal IP; use 'before:' and filter on scan_dtime")
    quoted = sorted({m.group(1) for m in QUOTED_FILTER_VALUE_RE.finditer(query)})
    if quoted:
        warnings.append("quoted filter value(s) for {} match nothing on Criminal IP; filter values cannot contain "
                        "spaces (quotes only work for keyword phrases)".format(quoted))
    return warnings


class CriminalIPQueryTranslator(BaseQueryTranslator):

    def fetch_mapping(self, basepath, dialect, options):
        return {}

    def fetch_operators(self, basepath, dialect, options):
        return {}

    def get_language(self):
        return LANGUAGE

    def parse_query(self, data):
        # Native queries carry no STIX time qualifiers.
        return {"start_time": None, "end_time": None}

    def transform_query(self, data):
        query = normalize_query(data)
        if not query:
            raise DataMappingException("empty Criminal IP query")
        if query.startswith("{"):
            try:
                validate_envelope(query)
            except ValueError as ex:
                raise DataMappingException(str(ex))
        else:
            for warning in query_warnings(query):
                logger.warning("Criminal IP query %r: %s", query, warning)
        return {"queries": [query], "unmapped_attributes": []}
