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


def _section(report, name):
    section = report.get(name)
    if isinstance(section, dict) and isinstance(section.get("data"), list):
        return [d for d in section["data"] if isinstance(d, dict)]
    return []


def _unique(values):
    out = []
    for value in values:
        if _present(value) and value not in out:
            out.append(value)
    return out


def _float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _ip_info(report, summary):
    info = {}
    score = report.get("score") or {}
    scoring = summary.get("ip_scoring") or {}
    for key in ("inbound", "outbound"):
        value = score.get(key) or scoring.get(key)
        if _present(value):
            info[key + "_score"] = value
    if isinstance(scoring.get("is_malicious"), bool):
        info["is_malicious"] = scoring["is_malicious"]
    issues = report.get("issues") or {}
    for flag in IP_ISSUE_FLAGS:
        if isinstance(issues.get(flag), bool):
            info[flag] = issues[flag]
    categories = _unique(c.get("type") for c in _section(report, "ip_category"))
    if categories:
        info["categories"] = categories
    ids = _unique(i.get("classification") for i in _section(report, "ids"))
    if ids:
        info["ids_classifications"] = ids
    if _present(summary.get("issue")):
        info["issues"] = summary["issue"]
    if _present(summary.get("tags")):
        info["tags"] = summary["tags"]
    security = (summary.get("summary") or {}).get("security") or {}
    for src, dst in (("abuse_record", "abuse_record_count"), ("open_ports", "open_port_count"),
                     ("vulnerabilities", "vulnerability_count")):
        if isinstance(security.get(src), int):
            info[dst] = security[src]
    detection = (summary.get("summary") or {}).get("detection") or {}
    if isinstance(detection.get("cdn_ip"), bool):
        info["is_cdn"] = detection["cdn_ip"]
    whois = (_section(report, "whois") or [{}])[0]
    if _present(whois.get("org_name")):
        info["org_name"] = whois["org_name"]
    if _present(summary.get("summary", {}).get("connection", {}).get("representative_domain")):
        info["representative_domain"] = summary["summary"]["connection"]["representative_domain"]
    return info


def _vulnerabilities(report):
    vulns = []
    for v in _section(report, "vulnerability"):
        if not _present(v.get("cve_id")):
            continue
        item = {"cve_id": v["cve_id"]}
        for key in ("cvssv3_score", "cvssv2_score"):
            score = _float(v.get(key))
            if score:
                item[key] = score
        for key in ("app_name", "app_version", "vendor"):
            if _present(v.get(key)):
                item[key] = str(v[key])
        if _present(v.get("cve_description")):
            item["description"] = str(v["cve_description"])[:MAX_DESCRIPTION]
        vulns.append(item)
    return vulns


def expand_ip_report(report):
    """One /v2/asset/ip/report (+ report/summary) -> an IP observation plus one observation per open port."""
    ip = report.get("ip")
    summary = report.get("report_summary") or {}
    whois = (_section(report, "whois") or [{}])[0]
    country = whois.get("org_country_code") or (summary.get("summary") or {}).get("connection", {}).get("country")
    out = {"ip_address": ip}
    asn = {}
    if isinstance(whois.get("as_no"), int) and whois["as_no"] > 0:
        asn["number"] = whois["as_no"]
        if _present(whois.get("as_name")):
            asn["name"] = whois["as_name"]
        asn["link"] = True
        out["asn"] = asn
    geo = {}
    if _present(country):
        geo["country_iso_code"] = str(country).upper()
    if _present(whois.get("city")):
        geo["city_name"] = whois["city"]
    if _present(whois.get("region")):
        geo["region_name"] = whois["region"]
    if geo:
        out["geo"] = geo
    hostnames = _section(report, "hostname")
    if hostnames and _present(hostnames[0].get("domain_name_full")):
        out["hostname"] = hostnames[0]["domain_name_full"]
    vulns = _vulnerabilities(report)
    if vulns:
        out["vulnerabilities"] = vulns
    info = _ip_info(report, summary)
    if info:
        info["ip_ref"] = True
        out["ip_info"] = info
    observed = to_iso(report.get("timestamp"))
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
        if not _present(banner_like["open_port_no"]):
            continue
        records.append(normalize_record(banner_like))
    return records


def expand_domain_lookup(record):
    """/v1/domain/quick/{hash,malicious}/view results -> one domain observation."""
    hash_view = record.get("hash_view") or {}
    malicious_view = record.get("malicious_view") or {}
    domain = record.get("domain") or hash_view.get("domain")
    out = {"domain_name": domain}
    info = {}
    if _present(hash_view.get("result")):
        info["verdict"] = hash_view["result"]
    if _present(hash_view.get("type")):
        info["domain_type"] = hash_view["type"]
    if _present(malicious_view.get("type")):
        info["malicious_type"] = malicious_view["type"]
    call_count = hash_view.get("call_count", malicious_view.get("call_count"))
    if isinstance(call_count, int):
        info["call_count"] = call_count
    registered = to_iso(hash_view.get("reg_dtime") or malicious_view.get("reg_dtime"))
    if registered:
        info["first_seen"] = registered
    if info:
        info["domain_ref"] = True
        out["domain_info"] = info
    return [out]


def expand_record(record):
    """Any record returned by transmission -> list of normalized records (one per observed-data)."""
    if not isinstance(record, dict):
        return [record]
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
