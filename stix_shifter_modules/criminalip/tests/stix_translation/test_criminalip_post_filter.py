import json
import unittest

from stix_shifter_modules.criminalip.stix_translation.post_filter import parse_search_id, record_matches, \
    build_search_id

RECORD = {"ip_address": "34.141.81.106", "scan_dtime": "2026-10-22 07:40:15", "as_name": "Google LLC",
          "software": [{"product": "Plesk Obsidian", "version": "18.0.81"}], "tags": ["DSM", "DevOps"]}


class TestPostFilter(unittest.TestCase):

    def test_plain_query_round_trip(self):
        assert build_search_id("port: 22") == "port: 22"
        assert parse_search_id("port: 22") == ("port: 22", None)

    def test_json_query_round_trip(self):
        sid = build_search_id("product: Plesk", {"terms": [{"field": "software.product", "value": "Plesk Obsidian",
                                                            "negate": False}]})
        query, pf = parse_search_id(sid)
        assert query == "product: Plesk"
        assert pf["terms"][0]["value"] == "Plesk Obsidian"
        assert parse_search_id(json.loads(sid))[0] == "product: Plesk"

    def test_malformed_json_is_treated_as_query(self):
        assert parse_search_id("{not json") == ("{not json", None)

    def test_phrase_terms(self):
        assert record_matches(RECORD, {"terms": [{"field": "software.product", "value": "plesk obsidian"}]})
        assert not record_matches(RECORD, {"terms": [{"field": "software.product", "value": "Apache httpd"}]})
        assert record_matches(RECORD, {"terms": [{"field": "as_name", "value": "Amazon", "negate": True}]})
        assert not record_matches(RECORD, {"terms": [{"field": "as_name", "value": "Google LLC", "negate": True}]})
        assert record_matches(RECORD, {"terms": [{"field": "tags", "value": "devops"}]})
        assert not record_matches(RECORD, {"terms": [{"field": "title", "value": "x"}]})

    def test_time_window(self):
        assert record_matches(RECORD, {"start": "2026-10-22T00:00:00Z", "stop": "2026-10-23T00:00:00.000Z"})
        assert not record_matches(RECORD, {"start": "2026-10-22T08:00:00Z"})
        assert not record_matches(RECORD, {"stop": "2026-10-22T07:40:14Z"})
        assert not record_matches(RECORD, {"stop": "2026-10-22T07:40:15Z"})   # STOP is exclusive
        assert record_matches(RECORD, {"stop": "2026-10-22T07:40:16Z"})
        assert record_matches(RECORD, {"start": "2026-10-22T07:40:15Z"})      # START is inclusive
        assert not record_matches({"ip_address": "1.1.1.1"}, {"start": "2026-10-22T00:00:00Z"})

    def test_no_filter(self):
        assert record_matches(RECORD, None)


class TestPostFilterGroups(unittest.TestCase):

    def test_any_group(self):
        from stix_shifter_modules.criminalip.stix_translation.post_filter import record_matches as matches
        pf = {"any": [{"terms": [{"field": "software.product", "value": "Apache httpd"}]},
                      {"terms": [{"field": "open_port_no", "value": "8443", "match": "equals"}]}]}
        assert matches({"open_port_no": 8443}, pf)
        assert matches({"open_port_no": 80, "software": [{"product": "Apache httpd"}]}, pf)
        assert not matches({"open_port_no": 80, "software": [{"product": "nginx"}]}, pf)
        assert not matches({"open_port_no": 84430}, pf)
        assert not matches({}, {"any": []})

    def test_cidr_and_bool(self):
        from stix_shifter_modules.criminalip.stix_translation.post_filter import term_matches
        assert term_matches({"ip_address": "8.8.8.8"}, {"field": "ip_address", "value": "8.8.8.0/24", "match": "cidr"})
        assert not term_matches({"ip_address": "8.8.9.8"},
                                {"field": "ip_address", "value": "8.8.8.0/24", "match": "cidr"})
        assert term_matches({"ssl_expired": False}, {"field": "ssl_expired", "value": "false", "match": "equals"})

    def test_lookup_ids(self):
        from stix_shifter_modules.criminalip.stix_translation.post_filter import build_lookup_id, parse_lookup, \
            validate_envelope
        sid = build_lookup_id("ip", ["1.2.3.4"])
        assert parse_lookup(sid) == ("ip", ["1.2.3.4"])
        assert parse_lookup("ip: 1.2.3.4") is None
        assert parse_lookup('{"lookup": "url", "values": ["x"]}') is None
        assert parse_search_id(sid)[1] is None
        validate_envelope(sid)
        with self.assertRaises(ValueError):
            validate_envelope('{"lookup": "ip", "values": []}')
