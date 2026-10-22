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
        assert record_matches(RECORD, {"stop": "2026-10-22T07:40:15Z"})
        assert not record_matches({"ip_address": "1.1.1.1"}, {"start": "2026-10-22T00:00:00Z"})

    def test_no_filter(self):
        assert record_matches(RECORD, None)
