##### Updated on 10/22/26
## Criminal IP
### Results STIX Domain Objects
* Identity
* Observed Data
<br>
### Supported query languages
| Language option | Query |
|--|--|
| `stix` (default) | STIX pattern, translated as below |
| `criminalip` | Native Criminal IP banner search query, passed through unchanged |
<br>
### Supported STIX Operators
*Comparison AND/OR operators are inside the observation while observation AND/OR operators are between observations (square brackets).*

| STIX Operator | Data Source Operator |
|--|--|
| AND (Comparison) | (space, implicit AND) |
| OR (Comparison) | OR (query rewritten to OR-of-AND groups) |
| = | filter: value |
| != | NOT filter: value |
| IN | filter: a OR filter: b |
| ISSUBSET | ip: a.b.c.d/nn |
| AND (Observation) | OR |
| OR (Observation) | OR |
| <br> | |
### Searchable STIX objects and properties
*Patterns made only of exact `ipv4-addr:value` and/or `domain-name:value` comparisons (`=`/`IN`, joined by OR) use the IP report / domain verdict lookups instead of banner search.*

| STIX Object and Property | Mapped Data Source Fields |
|--|--|
| **ipv4-addr**:value | ip |
| **network-traffic**:dst_port | port |
| **network-traffic**:protocols[*] | service |
| **network-traffic**:dst_ref.value | ip |
| **domain-name**:value | hostname, domain_from_banner |
| **x509-certificate**:subject | ssl_subject_common_name |
| **x509-certificate**:issuer | ssl_issuer_organization |
| **software**:name | product |
| **software**:version | product_version |
| **autonomous-system**:name | as_name |
| **x-oca-geo**:country_iso_code | country |
| **x-oca-geo**:city_name | city |
| **vulnerability**:name | cve_id |
| **file**:hashes.MD5 | malcode_md5 |
| **file**:hashes.'MD5' | malcode_md5 |
| **x-criminalip-banner**:country | country |
| **x-criminalip-banner**:city | city |
| **x-criminalip-banner**:org_name | org |
| **x-criminalip-banner**:isp | isp |
| **x-criminalip-banner**:cloud_provider | cloud_provider |
| **x-criminalip-banner**:title | title |
| **x-criminalip-banner**:status_code | status_code |
| **x-criminalip-banner**:jarm | jarm |
| **x-criminalip-banner**:favicon | favicon |
| **x-criminalip-banner**:tags[*] | tag |
| **x-criminalip-banner**:tech_stacks[*] | tech_stack |
| **x-criminalip-banner**:ssl_expired | ssl_expired |
| **x-criminalip-banner**:cve_id | cve_id |
| **x-criminalip-banner**:snort_classification | snort_classification |
| **x-criminalip-banner**:snort_rule | snort_rule |
| **x-criminalip-banner**:html_meta_title | html_meta_title |
| **x-criminalip-banner**:html_meta_author | html_meta_author |
| **x-criminalip-banner**:html_meta_description | html_meta_description |
| **x-criminalip-banner**:html_meta_keywords | html_meta_keywords |
| **x-criminalip-banner**:prefix | prefix |
| <br> | |
### Supported STIX Objects and Properties for Query Results
| STIX Object | STIX Property | Data Source Field |
|--|--|--|
| autonomous-system | name | IP report: whois.as_name |
| autonomous-system | number | IP report: whois.as_no |
| domain-name | resolves_to_refs | hostname (IP report: hostname.domain_name_full) |
| domain-name | value | domain lookup: domain |
| domain-name | value | hostname (IP report: hostname.domain_name_full) |
| observed-data | first_observed | scan_dtime (IP report: timestamp / port.confirmed_time) |
| ipv4-addr | belongs_to_refs | IP report: whois.as_no |
| ipv4-addr | value | ip_address |
| observed-data | last_observed | scan_dtime (IP report: timestamp / port.confirmed_time) |
| network-traffic | dst_port | open_port_no |
| network-traffic | dst_ref | ip_address |
| network-traffic | protocols | socket_type, service_name (IP report: port.socket, port.protocol) |
| software | name | software[].product, operating_systems[].product |
| software | version | software[].version, operating_systems[].version |
| x-criminalip-banner | as_name | as_name |
| x-criminalip-banner | banner | banner |
| x-criminalip-banner | cloud_provider | cloud_source |
| x-criminalip-banner | has_cve | has_cve |
| x-criminalip-banner | ip_ref | ip_address |
| x-criminalip-banner | jarm | jarm |
| x-criminalip-banner | latitude | latitude |
| x-criminalip-banner | longitude | longitude |
| x-criminalip-banner | org_name | org_name |
| x-criminalip-banner | service_name | service_name |
| x-criminalip-banner | socket_type | socket_type |
| x-criminalip-banner | ssl_expired | ssl_expired |
| x-criminalip-banner | status_code | status_code |
| x-criminalip-banner | tags | tags |
| x-criminalip-banner | tech_stacks | tech_stacks |
| x-criminalip-banner | title | title |
| x-criminalip-domain | call_count | call_count |
| x-criminalip-domain | domain_ref | domain lookup: domain |
| x-criminalip-domain | domain_type | quick/hash/view type |
| x-criminalip-domain | first_seen | reg_dtime |
| x-criminalip-domain | malicious_type | quick/malicious/view type |
| x-criminalip-domain | verdict | quick/hash/view result |
| x-criminalip-ip | abuse_record_count | IP report / report summary: abuse_record_count |
| x-criminalip-ip | categories | IP report / report summary: categories |
| x-criminalip-ip | ids_classifications | IP report / report summary: ids_classifications |
| x-criminalip-ip | inbound_score | IP report / report summary: inbound_score |
| x-criminalip-ip | ip_ref | IP report / report summary: ip_ref |
| x-criminalip-ip | is_anonymous_vpn | IP report / report summary: is_anonymous_vpn |
| x-criminalip-ip | is_cdn | IP report / report summary: is_cdn |
| x-criminalip-ip | is_cloud | IP report / report summary: is_cloud |
| x-criminalip-ip | is_darkweb | IP report / report summary: is_darkweb |
| x-criminalip-ip | is_hosting | IP report / report summary: is_hosting |
| x-criminalip-ip | is_malicious | IP report / report summary: is_malicious |
| x-criminalip-ip | is_mobile | IP report / report summary: is_mobile |
| x-criminalip-ip | is_proxy | IP report / report summary: is_proxy |
| x-criminalip-ip | is_scanner | IP report / report summary: is_scanner |
| x-criminalip-ip | is_snort | IP report / report summary: is_snort |
| x-criminalip-ip | is_tor | IP report / report summary: is_tor |
| x-criminalip-ip | is_vpn | IP report / report summary: is_vpn |
| x-criminalip-ip | issues | IP report / report summary: issues |
| x-criminalip-ip | open_port_count | IP report / report summary: open_port_count |
| x-criminalip-ip | org_name | IP report / report summary: org_name |
| x-criminalip-ip | outbound_score | IP report / report summary: outbound_score |
| x-criminalip-ip | representative_domain | IP report / report summary: representative_domain |
| x-criminalip-ip | tags | IP report / report summary: tags |
| x-criminalip-ip | vulnerability_count | IP report / report summary: vulnerability_count |
| x-criminalip-vulnerability | app_name | IP report: vulnerability.data[].app_name |
| x-criminalip-vulnerability | app_version | IP report: vulnerability.data[].app_version |
| x-criminalip-vulnerability | cve_id | IP report: vulnerability.data[].cve_id |
| x-criminalip-vulnerability | cvssv2_score | IP report: vulnerability.data[].cvssv2_score |
| x-criminalip-vulnerability | cvssv3_score | IP report: vulnerability.data[].cvssv3_score |
| x-criminalip-vulnerability | description | IP report: vulnerability.data[].description |
| x-criminalip-vulnerability | vendor | IP report: vulnerability.data[].vendor |
| x-oca-geo | city_name | city (IP report: whois.city) |
| x-oca-geo | country_iso_code | country (IP report: whois.org_country_code) |
| x-oca-geo | region_name | IP report: whois.region |
| x509-certificate | hashes.SHA-256 | ssl_info (Fingerprint Sha256) |
| x509-certificate | issuer | ssl_info (Issuer Dn) / ssl_issuer_organization |
| x509-certificate | serial_number | ssl_info (Serial Number) |
| x509-certificate | signature_algorithm | ssl_info (Signature Algorithm) |
| x509-certificate | subject | ssl_info (Subject Dn) / ssl_subject_* |
| x509-certificate | validity_not_after | ssl_info (Validity End) |
| x509-certificate | validity_not_before | ssl_info (Validity Start) |
| x509-certificate | version | ssl_info (Version) |
| <br> | | |
