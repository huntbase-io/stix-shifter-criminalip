import json
import logging
import unittest

from stix_shifter.stix_translation import stix_translation
from stix_shifter_modules.criminalip.stix_translation.criminalip_query_translator import normalize_query, \
    query_warnings

translation = stix_translation.StixTranslation()
NATIVE = {"language": "criminalip"}


def translate(query, options=None):
    return translation.translate("criminalip", "query", "{}", query, options or dict(NATIVE))


class TestCriminalIPPassthrough(unittest.TestCase):

    def test_passthrough_unchanged(self):
        assert translate("product: OpenSSH port: 22 country: KR") == \
            {"queries": ["product: OpenSSH port: 22 country: KR"]}

    def test_keyword_phrase_and_or_kept(self):
        query = '"default password" port: 8080 OR port: 8443 NOT country: US'
        assert translate(query)["queries"] == [query]

    def test_whitespace_normalised_outside_quotes(self):
        assert translate("  product: OpenSSH \n\t port: 22  ")["queries"] == ["product: OpenSSH port: 22"]
        assert normalize_query('"two  spaces"   port: 1') == '"two  spaces" port: 1'

    def test_empty_query_rejected(self):
        for query in ("", "   "):
            result = translate(query)
            assert result["success"] is False
            assert "empty" in result["error"]

    def test_warnings(self):
        assert query_warnings("product: OpenSSH port: 22") == []
        warnings = query_warnings('service_name: ssh title: "Plesk Obsidian" after: 2026-01-01')
        assert any("service_name" in w for w in warnings)
        assert any("after:" in w for w in warnings)
        assert any("quoted filter value" in w and "title" in w for w in warnings)
        # a colon inside a quoted keyword phrase is not a filter
        assert query_warnings('"Server: nginx" port: 80') == []

    def test_warnings_are_logged_not_fatal(self):
        logger = logging.getLogger("stix_shifter_modules.criminalip.stix_translation.criminalip_query_translator")
        with self.assertLogs(logger, level="WARNING") as captured:
            result = translate("bogusfilter: abc")
        assert result["queries"] == ["bogusfilter: abc"]
        assert any("bogusfilter" in line for line in captured.output)

    def test_json_envelopes(self):
        lookup = '{"lookup": "ip", "values": ["8.8.8.8"]}'
        assert translate(lookup)["queries"] == [lookup]
        envelope = json.dumps({"query": "product: Plesk", "post_filter": {"any": [{"terms": []}]}})
        assert translate(envelope)["queries"] == [envelope]
        for bad in ('{bad', '{"lookup": "url", "values": ["x"]}', '{"lookup": "ip", "values": []}', '{"foo": 1}',
                    '{"query": ""}'):
            result = translate(bad)
            assert result["success"] is False, bad

    def test_stix_is_still_default(self):
        assert translation.translate("criminalip", "query", "{}", "[network-traffic:dst_port = 22]", {}) == \
            {"queries": ["port: 22"]}
        assert translation.translate("criminalip", "query", "{}", "[network-traffic:dst_port = 22]",
                                     {"language": "stix"})["queries"] == ["port: 22"]

    def test_dialects_listing(self):
        dialects = translation.translate("criminalip", "dialects", None, None)
        assert dialects["criminalip"]["language"] == "criminalip"
        assert dialects["default"]["language"] == "stix"
