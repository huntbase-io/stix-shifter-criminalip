import json
import os
import unittest

from stix_shifter.stix_translation import stix_translation
from stix_shifter_modules.criminalip.entry_point import EntryPoint
from stix_shifter_modules.criminalip.stix_translation.results_translator import normalize_record, to_iso
from stix_shifter_utils.stix_translation.src.utils.transformer_utils import get_module_transformers
from stix_shifter_utils.stix_translation.src.json_to_stix import json_to_stix_translator

MODULE = "criminalip"
SAMPLES = os.path.join(os.path.dirname(__file__), "sample_responses")
DATA_SOURCE = {"type": "identity", "id": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
               "name": "criminalip", "identity_class": "events"}
translation = stix_translation.StixTranslation()


def load_results(name):
    with open(os.path.join(SAMPLES, name)) as f:
        return json.load(f)["data"]["result"]


def to_bundle(records, options=None):
    return translation.translate(MODULE, 'results', json.dumps(DATA_SOURCE), json.dumps(records), options or {})


def objects_by_type(observed):
    by_type = {}
    for obj in observed["objects"].values():
        by_type.setdefault(obj["type"], []).append(obj)
    return by_type


class TestCriminalIPJsonToStix(unittest.TestCase):

    def test_bundle_shape(self):
        records = load_results("v2_banner_search_ip_cidr_8.8.8.0-24.json")
        bundle = to_bundle(records)
        assert bundle["type"] == "bundle"
        assert bundle["objects"][0]["type"] == "identity"
        observed = [o for o in bundle["objects"] if o["type"] == "observed-data"]
        assert len(observed) == len(records)
        for o in observed:
            assert o["number_observed"] == 1
            assert o["created_by_ref"] == DATA_SOURCE["id"]

    def test_https_record_with_certificate(self):
        record = [r for r in load_results("v2_banner_search_ip_cidr_8.8.8.0-24.json") if r["open_port_no"] == 443][0]
        observed = to_bundle([record])["objects"][1]
        assert observed["first_observed"] == "2026-10-20T15:45:33.000Z"
        assert observed["last_observed"] == "2026-10-20T15:45:33.000Z"
        objs = objects_by_type(observed)
        ip = objs["ipv4-addr"][0]
        assert ip["value"] == "8.8.8.8"
        nt = objs["network-traffic"][0]
        assert nt["dst_port"] == 443
        assert nt["protocols"] == ["tcp", "https"]
        assert observed["objects"][nt["dst_ref"]]["value"] == "8.8.8.8"
        domain = objs["domain-name"][0]
        assert domain["value"] == "dns.google"
        assert observed["objects"][domain["resolves_to_refs"][0]]["value"] == "8.8.8.8"
        # autonomous-system requires "number", which banner search does not return -> custom property instead
        assert "autonomous-system" not in objs
        assert "belongs_to_refs" not in ip
        cert = objs["x509-certificate"][0]
        assert cert["subject"] == "CN=dns.google"
        assert cert["issuer"] == "C=US, O=Google Trust Services, CN=WR2"
        assert cert["serial_number"] == "119760305370515512493719377464821648688"
        assert cert["validity_not_after"] == "2026-12-11T20:02:28Z"
        assert len(cert["hashes"]["SHA-256"]) == 64
        geo = objs["x-oca-geo"][0]
        assert geo["country_iso_code"] == "US"
        banner = objs["x-criminalip-banner"][0]
        assert banner["title"] == "Google Public DNS"
        assert banner["status_code"] == 200
        assert banner["ssl_expired"] is False
        assert banner["cloud_provider"] == "Google"
        assert banner["as_name"] == "Google LLC"
        assert observed["objects"][banner["ip_ref"]]["value"] == "8.8.8.8"

    def test_software_and_operating_system(self):
        record = load_results("v2_banner_search_openssh_kr.json")[0]
        observed = to_bundle([record])["objects"][1]
        software = {(s["name"], s.get("version")) for s in objects_by_type(observed)["software"]}
        assert software == {("OpenSSH", "10.2p1"), ("Ubuntu Linux", "2")}
        objs = objects_by_type(observed)
        assert "x509-certificate" not in objs
        assert objs["network-traffic"][0]["protocols"] == ["tcp", "ssh"]
        assert objs["x-oca-geo"][0] == {"type": "x-oca-geo", "country_iso_code": "KR", "city_name": "Seoul"}

    def test_unknown_version_dropped(self):
        record = [r for r in load_results("v2_banner_search_ip_cidr_8.8.8.0-24.json") if r["open_port_no"] == 80][0]
        objs = objects_by_type(to_bundle([record])["objects"][1])
        assert objs["software"] == [{"type": "software", "name": "httpd"}]

    def test_v1_record_shape(self):
        record = load_results("v1_banner_search_openssh_kr.json")[0]
        norm = normalize_record(record)
        assert norm["software"][0]["name"] == record["product"]

    def test_empty_values_not_emitted(self):
        norm = normalize_record({"ip_address": "1.2.3.4", "open_port_no": 22, "hostname": "", "as_name": None,
                                 "socket_type": "TCP", "service_name": None, "ssl_info": "", "title": None,
                                 "tags": [], "scan_dtime": "2026-10-22 07:20:04"})
        assert norm == {"ip_address": "1.2.3.4", "open_port_no": 22, "protocols": ["tcp"],
                        "observed_time": "2026-10-22T07:20:04.000Z", "banner_info": {"socket_type": "TCP"}}

    def test_to_iso(self):
        assert to_iso("2026-10-22 07:20:04") == "2026-10-22T07:20:04.000Z"
        assert to_iso("") is None
        assert to_iso("garbage") is None

    def test_stix_2_1(self):
        records = load_results("v2_banner_search_ip_cidr_8.8.8.0-24.json")
        bundle = to_bundle(records, {"stix_2.1": True})
        types = {o["type"] for o in bundle["objects"]}
        assert {"identity", "observed-data", "ipv4-addr", "network-traffic", "domain-name"} <= types

    def test_entry_point_uses_module_results_translator(self):
        translator = EntryPoint().get_results_translator()
        assert type(translator).__name__ == "ResultsTranslator"
        transformers = get_module_transformers(MODULE)
        result = json_to_stix_translator.convert_to_stix(
            DATA_SOURCE, translator.map_data, [normalize_record(load_results("v2_banner_search_openssh_kr.json")[0])],
            transformers, {})
        assert result["objects"][1]["objects"]["0"]["type"] == "ipv4-addr"

    def test_mutilated_records_give_valid_network_traffic(self):
        # STIX 2.0: network-traffic needs protocols and a src_ref/dst_ref; values must have the right type
        base = load_results("v2_banner_search_openssh_kr.json")[0]
        variants = []
        for key in ("ip_address", "socket_type", "service_name", "open_port_no", "hostname"):
            for bad in (None, "", [], {"x": 1}, 12345):
                record = dict(base)
                record[key] = bad
                variants.append(record)
        record = dict(base)
        record.pop("socket_type")
        record.pop("service_name")
        variants.append(record)
        for record in variants:
            bundle = to_bundle([record])
            assert "objects" in bundle, (record, bundle)
            for observed in bundle["objects"][1:]:
                by_type = objects_by_type(observed)
                for nt in by_type.get("network-traffic", []):
                    assert nt.get("protocols"), (record, nt)
                    assert observed["objects"][nt["dst_ref"]]["type"] == "ipv4-addr", (record, nt)
                for domain in by_type.get("domain-name", []):
                    assert isinstance(domain["value"], str), (record, domain)
                for ip in by_type.get("ipv4-addr", []):
                    assert isinstance(ip["value"], str), (record, ip)

    def test_port_without_socket_type_defaults_protocol(self):
        record = dict(load_results("v2_banner_search_openssh_kr.json")[0])
        record.pop("socket_type")
        record.pop("service_name")
        nt = objects_by_type(to_bundle([record])["objects"][1])["network-traffic"][0]
        assert nt["protocols"] == ["ipv4"]
        assert nt["dst_port"] == 22

    def test_v1_product_of_wrong_type_does_not_crash(self):
        record = dict(load_results("v1_banner_search_openssh_kr.json")[0])
        record["product"] = {"x": 1}
        assert "objects" in to_bundle([record])
