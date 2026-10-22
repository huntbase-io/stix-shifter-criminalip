"""Results translator: normalises Criminal IP banner search records, then maps them with to_stix_map.json.

Transmission returns the raw ``data.result`` items of ``/v2/banner/search``. Some of their content does not fit
the declarative to-STIX mapping, so each record is reshaped first:

* ``socket_type`` + ``service_name``  -> ``protocols`` list (``["tcp", "ssh"]``)
* ``software[]`` + ``operating_systems[]`` (v2) or ``product``/``product_version`` (v1) -> ``software`` list,
  dropping the literal ``"Unknown"``
* ``ssl_*`` fields and the raw ``ssl_info`` certificate text -> ``certificate`` dict (subject/issuer DN, serial,
  validity, SHA-256 fingerprint)
* ``scan_dtime`` (naive ``YYYY-MM-DD HH:MM:SS``, UTC) -> ISO-8601 ``observed_time``
"""
import json
import re
from datetime import datetime

from stix_shifter_utils.stix_translation.src.json_to_stix.json_to_stix import JSONToStix

from .post_filter import normalize_lookup_value, LOOKUP_IP, LOOKUP_DOMAIN

UNKNOWN_VALUES = {"", "unknown", "none", "null", "n/a"}

# fields copied unchanged into the custom x-criminalip-banner object
BANNER_FIELDS = ["as_name", "latitude", "longitude", "org_name", "cloud_source", "socket_type", "service_name",
                 "status_code", "title", "banner", "jarm", "has_cve", "tags", "tech_stacks", "ssl_expired"]


def _present(value):
    if value is None:
        return False
    if isinstance(value, str) and value.strip().lower() in UNKNOWN_VALUES:
        return False
    if isinstance(value, (list, dict)) and not value:
        return False
    return True


def _scalar(value):
    """True for a present string/number value (not a list, dict or bool)."""
    return _present(value) and isinstance(value, (str, int, float)) and not isinstance(value, bool)


def to_iso(naive):
    """'2026-10-22 07:20:04' -> '2026-10-22T07:20:04.000Z' (Criminal IP timestamps are UTC without a zone)."""
    if not _present(naive):
        return None
    text = str(naive).strip().replace("T", " ").rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        except ValueError:
            continue
    return None


def _ssl_info_value(ssl_info, label):
    match = re.search(r"^\s*{}:[ \t]*(.+?)\s*$".format(re.escape(label)), ssl_info, re.MULTILINE)
    return match.group(1) if match else None


def _ssl_info_block_value(ssl_info, block, label):
    match = re.search(r"^{}:\s*\n((?:[ \t]+.*\n?)+)".format(re.escape(block)), ssl_info, re.MULTILINE)
    if not match:
        return None
    return _ssl_info_value(match.group(1), label)


def parse_certificate(record):
    """Builds the certificate dict from the flat ssl_* fields and the raw ssl_info text."""
    ssl_info = record.get("ssl_info") or ""
    if not isinstance(ssl_info, str):
        ssl_info = ""
    cert = {}
    subject_dn = _ssl_info_value(ssl_info, "Subject Dn")
    issuer_dn = _ssl_info_value(ssl_info, "Issuer Dn")
    if not subject_dn and _present(record.get("ssl_subject_common_name")):
        parts = []
        if _present(record.get("ssl_subject_country")):
            parts.append("C=" + str(record["ssl_subject_country"]))
        if _present(record.get("ssl_subject_organization")):
            parts.append("O=" + str(record["ssl_subject_organization"]))
        parts.append("CN=" + str(record["ssl_subject_common_name"]))
        subject_dn = ", ".join(parts)
    if not issuer_dn and _present(record.get("ssl_issuer_organization")):
        issuer_dn = "O=" + str(record["ssl_issuer_organization"])
    if subject_dn:
        cert["subject"] = subject_dn
    if issuer_dn:
        cert["issuer"] = issuer_dn
    serial = _ssl_info_value(ssl_info, "Serial Number")
    if serial:
        cert["serial_number"] = serial
    version = _ssl_info_value(ssl_info, "Version")
    if version:
        cert["version"] = version
    not_before = _ssl_info_block_value(ssl_info, "Validity", "Start")
    not_after = _ssl_info_block_value(ssl_info, "Validity", "End")
    if not_before and re.match(r"^\d{4}-\d{2}-\d{2}T", not_before):
        cert["validity_not_before"] = not_before
    if not_after and re.match(r"^\d{4}-\d{2}-\d{2}T", not_after):
        cert["validity_not_after"] = not_after
    fingerprint = _ssl_info_value(ssl_info, "Fingerprint Sha256")
    if fingerprint and re.match(r"^[0-9a-fA-F]{64}$", fingerprint):
        cert["sha256"] = fingerprint.lower()
    signature = _ssl_info_block_value(ssl_info, "Signature Algorithm", "Name")
    if signature:
        cert["signature_algorithm"] = signature
    return cert


def _software_list(record):
    items = []
    entries = []
    for key in ("software", "operating_systems"):
        value = record.get(key)
        if isinstance(value, list):
            entries.extend(v for v in value if isinstance(v, dict))
    if not entries and _present(record.get("product")):    # v1 record shape
        entries.append({"product": record.get("product"), "version": record.get("product_version")})
    seen = set()
    for entry in entries:
        name = entry.get("product")
        if not _scalar(name):
            continue
        version = entry.get("version") if _scalar(entry.get("version")) else None
        if (name, version) in seen:
            continue
        seen.add((name, version))
        item = {"name": str(name)}
        if version is not None:
            item["version"] = str(version)
        items.append(item)
    return items


def normalize_record(record):
    if not isinstance(record, dict):
        return record
    out = {}
    ip = record.get("ip_address")
    if isinstance(ip, str) and _present(ip):
        out["ip_address"] = ip.strip()
        # network-traffic needs dst_ref (the IP) and, in STIX 2.0, protocols, so it is only built with an IP.
        protocols = []
        for key in ("socket_type", "service_name"):
            if _scalar(record.get(key)):
                proto = str(record[key]).strip().lower()
                if proto not in protocols:
                    protocols.append(proto)
        port = record.get("open_port_no")
        if _scalar(port) and str(port).strip().isdigit():
            out["open_port_no"] = int(str(port).strip())
            if not protocols:
                protocols = ["ipv4"]   # Criminal IP is IPv4 only; the transport protocol is unknown
        if protocols:
            out["protocols"] = protocols
        if _scalar(record.get("hostname")):
            # domain-name.resolves_to_refs points at the IP, so the hostname is only kept with an IP.
            out["hostname"] = str(record["hostname"])
    software = _software_list(record)
    if software:
        out["software"] = software
    cert = parse_certificate(record)
    if cert:
        out["certificate"] = cert
    geo = {}
    if _present(record.get("country")):
        geo["country_iso_code"] = str(record["country"]).upper()
    if _present(record.get("city")):
        geo["city_name"] = record["city"]
    if geo:
        out["geo"] = geo
    observed = to_iso(record.get("scan_dtime"))
    if observed:
        out["observed_time"] = observed
    banner = {}
    for key in BANNER_FIELDS:
        value = record.get(key)
        if key in ("has_cve", "ssl_expired"):
            if isinstance(value, bool):
                banner[key] = value
            continue
        if _present(value):
            banner[key] = value
    if banner:
        out["banner_info"] = banner
    return out


# ---------------------------------------------------------------- IP and domain lookups
RECORD_TYPE_FIELD = "criminalip_record_type"
IP_ISSUE_FLAGS = ["is_vpn", "is_cloud", "is_tor", "is_proxy", "is_hosting", "is_mobile", "is_darkweb",
                  "is_scanner", "is_snort", "is_anonymous_vpn"]
MAX_DESCRIPTION = 500


def _dict(value):
    return value if isinstance(value, dict) else {}


def _path(obj, *keys):
    """Nested dict lookup that tolerates missing or mistyped levels."""
    for key in keys:
        obj = _dict(obj).get(key)
    return obj


def _section(report, name):
    section = _dict(report).get(name)
    if isinstance(section, dict) and isinstance(section.get("data"), list):
        return [d for d in section["data"] if isinstance(d, dict)]
    return []


def _unique(values):
    out = []
    for value in values:
        if _scalar(value) and value not in out:
            out.append(value)
    return out


def _float(value):
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _count(value):
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _ip_info(report, summary):
    info = {}
    score = _dict(report.get("score"))
    scoring = _dict(summary.get("ip_scoring"))
    for key in ("inbound", "outbound"):
        value = score.get(key) if _scalar(score.get(key)) else scoring.get(key)
        if _scalar(value):
            info[key + "_score"] = str(value)
    if isinstance(scoring.get("is_malicious"), bool):
        info["is_malicious"] = scoring["is_malicious"]
    issues = _dict(report.get("issues"))
    for flag in IP_ISSUE_FLAGS:
        if isinstance(issues.get(flag), bool):
            info[flag] = issues[flag]
    categories = _unique(c.get("type") for c in _section(report, "ip_category"))
    if categories:
        info["categories"] = categories
    ids = _unique(i.get("classification") for i in _section(report, "ids"))
    if ids:
        info["ids_classifications"] = ids
    summary_issues = summary.get("issue")
    if isinstance(summary_issues, list) and _unique(summary_issues):
        info["issues"] = _unique(summary_issues)
    tags = summary.get("tags")
    if isinstance(tags, list) and _unique(tags):
        info["tags"] = _unique(tags)
    for src, dst in (("abuse_record", "abuse_record_count"), ("open_ports", "open_port_count"),
                     ("vulnerabilities", "vulnerability_count")):
        count = _count(_path(summary, "summary", "security", src))
        if count is not None:
            info[dst] = count
    cdn = _path(summary, "summary", "detection", "cdn_ip")
    if isinstance(cdn, bool):
        info["is_cdn"] = cdn
    whois = (_section(report, "whois") or [{}])[0]
    if _scalar(whois.get("org_name")):
        info["org_name"] = str(whois["org_name"])
    representative = _path(summary, "summary", "connection", "representative_domain")
    if _scalar(representative):
        info["representative_domain"] = str(representative)
    return info


def _vulnerabilities(report):
    vulns = []
    for v in _section(report, "vulnerability"):
        if not isinstance(v.get("cve_id"), str) or not _present(v.get("cve_id")):
            continue
        item = {"cve_id": v["cve_id"].strip()}
        for key in ("cvssv3_score", "cvssv2_score"):
            score = _float(v.get(key))
            if score:
                item[key] = score
        for key in ("app_name", "app_version", "vendor"):
            if _scalar(v.get(key)):
                item[key] = str(v[key])
        if _scalar(v.get("cve_description")):
            item["description"] = str(v["cve_description"])[:MAX_DESCRIPTION]
        vulns.append(item)
    return vulns


def expand_ip_report(report):
    """One /v2/asset/ip/report (+ report/summary) -> an IP observation plus one observation per open port.
    A report without a valid IPv4 address is skipped (every object hangs off the ipv4-addr)."""
    ip = normalize_lookup_value(LOOKUP_IP, report.get("ip"))
    if ip is None:
        return []
    summary = _dict(report.get("report_summary"))
    whois = (_section(report, "whois") or [{}])[0]
    country = whois.get("org_country_code")
    if not _scalar(country):
        country = _path(summary, "summary", "connection", "country")
    country = str(country).upper() if _scalar(country) else None
    out = {"ip_address": ip}
    as_no = _count(whois.get("as_no"))
    if as_no:
        asn = {"number": as_no, "link": True}
        if _scalar(whois.get("as_name")):
            asn["name"] = str(whois["as_name"])
        out["asn"] = asn
    geo = {}
    if country:
        geo["country_iso_code"] = country
    for src, dst in (("city", "city_name"), ("region", "region_name")):
        if _scalar(whois.get(src)):
            geo[dst] = str(whois[src])
    if geo:
        out["geo"] = geo
    hostnames = _section(report, "hostname")
    if hostnames and isinstance(hostnames[0].get("domain_name_full"), str) and \
            _present(hostnames[0]["domain_name_full"]):
        out["hostname"] = hostnames[0]["domain_name_full"].strip()
    vulns = _vulnerabilities(report)
    if vulns:
        out["vulnerabilities"] = vulns
    info = _ip_info(report, summary)
    if info:
        info["ip_ref"] = True
        out["ip_info"] = info
    observed = to_iso(report.get("timestamp")) if _scalar(report.get("timestamp")) else None
    if observed:
        out["observed_time"] = observed
    records = [out]

    for port in _section(report, "port"):
        banner_like = {
            "ip_address": ip,
            "open_port_no": port.get("open_port_no"),
            "socket_type": port.get("socket"),
            "service_name": port.get("protocol"),
            "software": port.get("software"),
            "operating_systems": port.get("operating_systems"),
            "banner": port.get("banner"),
            "tags": port.get("tags"),
            "jarm": port.get("jarm_hash"),
            "ssl_info": port.get("ssl_info_raw"),
            "scan_dtime": port.get("confirmed_time"),
            "as_name": whois.get("as_name"),
            "country": country,
            "city": whois.get("city"),
        }
        if isinstance(port.get("is_vulnerability"), bool):
            banner_like["has_cve"] = port["is_vulnerability"]
        normalized = normalize_record(banner_like)
        if normalized.get("open_port_no") is not None:   # a port observation without a port adds nothing
            records.append(normalized)
    return records


def expand_domain_lookup(record):
    """/v1/domain/quick/{hash,malicious}/view results -> one domain observation (skipped without a valid domain)."""
    hash_view = _dict(record.get("hash_view"))
    malicious_view = _dict(record.get("malicious_view"))
    domain = normalize_lookup_value(LOOKUP_DOMAIN, record.get("domain")) or \
        normalize_lookup_value(LOOKUP_DOMAIN, hash_view.get("domain"))
    if domain is None:
        return []
    out = {"domain_name": domain}
    info = {}
    for key, view, src in (("verdict", hash_view, "result"), ("domain_type", hash_view, "type"),
                           ("malicious_type", malicious_view, "type")):
        if _scalar(view.get(src)):
            info[key] = str(view[src])
    call_count = _count(hash_view.get("call_count"))
    if call_count is None:
        call_count = _count(malicious_view.get("call_count"))
    if call_count is not None:
        info["call_count"] = call_count
    reg = hash_view.get("reg_dtime") if _scalar(hash_view.get("reg_dtime")) else malicious_view.get("reg_dtime")
    registered = to_iso(reg) if _scalar(reg) else None
    if registered:
        info["first_seen"] = registered
    if info:
        info["domain_ref"] = True
        out["domain_info"] = info
    return [out]


def expand_record(record):
    """Any record returned by transmission -> list of normalized records (one per observed-data)."""
    if not isinstance(record, dict):
        return []
    record_type = record.get(RECORD_TYPE_FIELD)
    if record_type == "ip_report" or (record_type is None and "ip" in record and "issues" in record
                                      and "ip_address" not in record):
        return expand_ip_report(record)
    if record_type == "domain_quick":
        return expand_domain_lookup(record)
    return [normalize_record(record)]


class ResultsTranslator(JSONToStix):

    def translate_results(self, data_source, data):
        if isinstance(data_source, str):
            data_source = json.loads(data_source)
        records = json.loads(data) if isinstance(data, str) else data
        if isinstance(records, dict):
            records = [records]
        normalized = [n for r in (records or []) for n in expand_record(r)]
        # A record with nothing mappable would become an observed-data with no objects, which is invalid STIX.
        normalized = [r for r in normalized if not isinstance(r, dict) or set(r) - {"observed_time"}]
        return super().translate_results(data_source, normalized)
