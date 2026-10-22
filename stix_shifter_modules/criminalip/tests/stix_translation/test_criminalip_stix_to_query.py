import json
import unittest

from stix_shifter.stix_translation import stix_translation
from stix_shifter_modules.criminalip.stix_translation.post_filter import parse_search_id

translation = stix_translation.StixTranslation()
MODULE = "criminalip"


def translate(pattern, options=None):
    return translation.translate(MODULE, 'query', '{}', pattern, options or {})


def queries(pattern):
    result = translate(pattern)
    assert 'queries' in result, result
    return result['queries']


class TestCriminalIPStixToQuery(unittest.TestCase):

    def test_ipv4_single(self):
        assert queries("[ipv4-addr:value = '8.8.8.8']") == ["ip: 8.8.8.8"]

    def test_ipv4_cidr_equal_and_issubset(self):
        assert queries("[ipv4-addr:value = '8.8.8.0/24']") == ["ip: 8.8.8.0/24"]
        assert queries("[ipv4-addr:value ISSUBSET '8.8.8.0/24']") == ["ip: 8.8.8.0/24"]
        assert queries("[ipv4-addr:value ISSUBSET '8.8.8.8']") == ["ip: 8.8.8.8/32"]

    def test_network_traffic_dst_ref(self):
        assert queries("[network-traffic:dst_ref.value = '1.2.3.4']") == ["ip: 1.2.3.4"]

    def test_ipv4_rejects_ipv6_value(self):
        result = translate("[ipv4-addr:value = 'fe80::1']")
        assert result['success'] is False
        assert result['code'] == 'mapping_error'
        assert 'IPv4' in result['error']

    def test_ipv6_is_unmapped(self):
        result = translate("[ipv6-addr:value = '::1']")
        assert result['success'] is False
        assert result['code'] == 'mapping_error'
        assert 'ipv6-addr:value' in result['error']

    def test_unmapped_attribute_dropped_in_or(self):
        result = translate("[ipv6-addr:value = '::1' OR ipv4-addr:value = '1.2.3.4']")
        assert result['queries'] == ["ip: 1.2.3.4"]

    def test_unmapped_attribute_in_and_fails(self):
        result = translate("[software:vendor = 'OpenBSD' AND software:name = 'OpenSSH']")
        assert result['success'] is False
        assert result['code'] == 'mapping_error'

    def test_unsupported_operator(self):
        result = translate("[network-traffic:dst_port > 22]")
        assert result['success'] is False
        assert 'GreaterThan' in result['error']
        result = translate("[software:name LIKE 'Open%']")
        assert result['success'] is False

    def test_and_is_implicit(self):
        assert queries("[software:name = 'OpenSSH' AND network-traffic:dst_port = 22 AND "
                       "x-oca-geo:country_iso_code = 'kr']") == ["country: KR port: 22 product: OpenSSH"]

    def test_in_operator_distributes(self):
        assert queries("[ipv4-addr:value = '8.8.8.0/24' AND network-traffic:dst_port IN (80, 443)]") == \
            ["ip: 8.8.8.0/24 port: 80 OR ip: 8.8.8.0/24 port: 443"]

    def test_or_inside_and_becomes_dnf(self):
        q = queries("[software:name = 'OpenSSH' AND (network-traffic:dst_port = 22 OR "
                    "network-traffic:dst_port = 2222)]")[0]
        groups = sorted(q.split(" OR "))
        assert groups == ["port: 22 product: OpenSSH", "port: 2222 product: OpenSSH"]

    def test_observation_or_and_and(self):
        for op in ("OR", "AND"):
            q = queries("[ipv4-addr:value = '1.2.3.4'] {} [network-traffic:dst_port = 3389]".format(op))[0]
            assert sorted(q.split(" OR ")) == ["ip: 1.2.3.4", "port: 3389"]

    def test_followedby_not_supported(self):
        result = translate("[ipv4-addr:value = '1.2.3.4'] FOLLOWEDBY [ipv4-addr:value = '1.2.3.5']")
        assert result['success'] is False

    def test_not_equal_and_not(self):
        assert queries("[x-oca-geo:country_iso_code != 'us']") == \
            ["NOT country: US"]
        assert queries("[network-traffic:dst_port = 22 AND NOT x-oca-geo:country_iso_code = 'US']") == \
            ["NOT country: US port: 22"]

    def test_negated_in_uses_de_morgan(self):
        assert queries("[network-traffic:dst_port = 22 AND x-oca-geo:country_iso_code NOT IN ('US', 'CN')]") == \
            ["NOT country: CN NOT country: US port: 22"]

    def test_domain_maps_to_hostname_or_banner_domain(self):
        assert queries("[domain-name:value = 'dns.google']") == \
            ["hostname: dns.google OR domain_from_banner: dns.google"]
        assert queries("[network-traffic:dst_port = 53 AND domain-name:value != 'dns.google']") == \
            ["NOT domain_from_banner: dns.google NOT hostname: dns.google port: 53"]

    def test_protocols_map_to_service(self):
        assert queries("[network-traffic:protocols[*] = 'ssh' AND x-oca-geo:country_iso_code = 'KR']") == \
            ["country: KR service: ssh"]

    def test_cve(self):
        assert queries("[vulnerability:name = 'CVE-2023-38408']") == ["cve_id: CVE-2023-38408"]

    def test_md5(self):
        assert queries("[file:hashes.MD5 = 'd41d8cd98f00b204e9800998ecf8427e']") == \
            ["malcode_md5: d41d8cd98f00b204e9800998ecf8427e"]

    def test_x509_subject_dn_and_cn(self):
        assert queries("[x509-certificate:subject = 'dns.google']") == ["ssl_subject_common_name: dns.google"]
        assert queries("[x509-certificate:subject = 'C=KR, O=Acme, CN=www.acme.kr']") == \
            ["ssl_subject_common_name: www.acme.kr ssl_subject_country: KR ssl_subject_organization: Acme"]

    def test_x509_issuer_dn_with_spaces_uses_post_filter(self):
        q = queries("[x509-certificate:issuer = 'C=US, O=Google Trust Services, CN=WR2']")
        query, post = parse_search_id(q[0])
        assert query == "ssl_issuer_organization: Services"
        assert post == {"terms": [{"field": "ssl_issuer_organization", "value": "Google Trust Services",
                                   "negate": False}]}

    def test_x509_issuer_without_org_fails(self):
        result = translate("[x509-certificate:issuer = 'CN=WR2']")
        assert result['success'] is False

    def test_multi_word_value_token_and_post_filter(self):
        q = queries("[software:name = 'Plesk Obsidian' AND network-traffic:dst_port = 8443]")
        assert len(q) == 1
        query, post = parse_search_id(q[0])
        assert query == "port: 8443 product: Obsidian"
        assert post["terms"] == [{"field": "software.product", "value": "Plesk Obsidian", "negate": False}]

    def test_negated_multi_word_value_is_client_side_only(self):
        q = queries("[network-traffic:dst_port = 443 AND autonomous-system:name != 'Google LLC']")
        query, post = parse_search_id(q[0])
        assert query == "port: 443"
        assert post["terms"] == [{"field": "as_name", "value": "Google LLC", "negate": True}]

    def test_only_client_side_conditions_rejected(self):
        result = translate("[software:name != 'Apache httpd']")
        assert result['success'] is False
        assert result['code'] == 'invalid_parameter'

    def test_multi_word_value_without_result_field_rejected(self):
        result = translate("[x-criminalip-banner:isp = 'Korea Telecom']")
        assert result['success'] is False

    def test_groups_with_different_post_filters_are_split(self):
        q = queries("[x-criminalip-banner:tags[*] = 'Data Leak' OR software:name = 'nginx']")
        assert len(q) == 2
        assert "product: nginx" in q
        other = [parse_search_id(x) for x in q if x != "product: nginx"][0]
        assert other[0] == "tag: Data"
        assert other[1]["terms"][0]["value"] == "Data Leak"

    def test_start_stop_qualifier(self):
        q = queries("[network-traffic:dst_port = 22] START t'2026-10-01T00:00:00Z' STOP t'2026-10-22T10:00:00Z'")
        query, post = parse_search_id(q[0])
        assert query == "port: 22 before: 2026-10-23"
        assert post == {"start": "2026-10-01T00:00:00Z", "stop": "2026-10-22T10:00:00Z"}

    def test_no_default_time_window(self):
        assert queries("[network-traffic:dst_port = 22]") == ["port: 22"]

    def test_mixed_qualifiers_split_queries(self):
        q = queries("[network-traffic:dst_port = 22] START t'2026-10-01T00:00:00Z' STOP t'2026-10-02T00:00:00Z' "
                    "OR [network-traffic:dst_port = 23]")
        assert len(q) == 2
        assert "port: 23" in q

    def test_value_validation(self):
        assert translate("[x-criminalip-banner:status_code = 'abc']")['success'] is False
        assert queries("[x-criminalip-banner:status_code = 200]") == ["status_code: 200"]
        assert queries("[x-criminalip-banner:ssl_expired = 'TRUE']") == ["ssl_expired: true"]
        assert translate("[x-criminalip-banner:title = 'a\"b']")['success'] is False

    def test_issubset_only_for_ip(self):
        result = translate("[software:name ISSUBSET 'OpenSSH']")
        assert result['success'] is False

    def test_dnf_explosion_is_bounded(self):
        ports = ", ".join(str(p) for p in range(1, 10))
        pattern = "[network-traffic:dst_port IN ({p}) AND x-criminalip-banner:status_code IN ({p})]".format(p=ports)
        result = translate(pattern)
        assert result['success'] is False
        assert 'OR-groups' in result['error']

    def test_validate_pattern_option(self):
        result = translate("[ipv4-addr:value = '1.2.3.4']", {"validate_pattern": True})
        assert result['queries'] == ["ip: 1.2.3.4"]

    def test_output_is_json_or_plain(self):
        for q in queries("[software:name = 'Apache httpd'] OR [ipv4-addr:value = '1.1.1.1']"):
            if q.startswith("{"):
                assert set(json.loads(q).keys()) == {"query", "post_filter"}

    def test_operator_word_never_sent_as_token(self):
        # 'x OR y' must not become 'title: OR' (the server would split the query at OR)
        query, post = parse_search_id(queries("[x-criminalip-banner:title = 'x OR y']")[0])
        assert query == "title: x"
        assert post["terms"][0]["value"] == "x OR y"
        query, _ = parse_search_id(queries("[x-criminalip-banner:title = 'a NOT bb or ccc']")[0])
        assert query == "title: ccc"

    def test_operator_word_value_rejected(self):
        for value in ("OR", "not", "AND", "OR AND"):
            result = translate("[x-criminalip-banner:title = '{}']".format(value))
            assert result['success'] is False, value
            assert result['code'] == 'invalid_parameter'

    def test_colon_in_value_stays_a_value(self):
        # verified live: 'title: port:22' parses as filter title with value 'port:22'
        assert queries("[x-criminalip-banner:title = 'port:22']") == ["title: port:22"]

    def test_other_whitespace_uses_phrase_path(self):
        query, post = parse_search_id(queries("[x-criminalip-banner:title = 'Plesk\tObsidian']")[0])
        assert query == "title: Obsidian"
        assert post["terms"][0]["value"] == "Plesk Obsidian"
