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


class ResultsTranslator(JSONToStix):

    def translate_results(self, data_source, data):
        if isinstance(data_source, str):
            data_source = json.loads(data_source)
        records = json.loads(data) if isinstance(data, str) else data
        if isinstance(records, dict):
            records = [records]
        normalized = [normalize_record(r) for r in (records or [])]
        return super().translate_results(data_source, normalized)
