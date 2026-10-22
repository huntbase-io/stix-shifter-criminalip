##### Updated on 10/22/26
## Criminal IP
### Results STIX Domain Objects
* Identity
* Observed Data
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
| domain-name | resolves_to_refs | hostname |
| domain-name | value | hostname |
| observed-data | first_observed | scan_dtime |
| ipv4-addr | value | ip_address |
| observed-data | last_observed | scan_dtime |
| network-traffic | dst_port | open_port_no |
| network-traffic | dst_ref | ip_address |
| network-traffic | protocols | socket_type, service_name |
| software | name | software[].product, operating_systems[].product |
| software | version | software[].version, operating_systems[].version |
| x-criminalip-banner | banner | banner |
| x-criminalip-banner | cloud_provider | cloud_source |
| x-criminalip-banner | has_cve | has_cve |
| x-criminalip-banner | ip_ref | ip_address |
| x-criminalip-banner | as_name | as_name |
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
| x-oca-geo | city_name | city |
| x-oca-geo | country_iso_code | country |
| x509-certificate | hashes.SHA-256 | ssl_info (Fingerprint Sha256) |
| x509-certificate | issuer | ssl_info (Issuer Dn) / ssl_issuer_organization |
| x509-certificate | serial_number | ssl_info (Serial Number) |
| x509-certificate | signature_algorithm | ssl_info (Signature Algorithm) |
| x509-certificate | subject | ssl_info (Subject Dn) / ssl_subject_* |
| x509-certificate | validity_not_after | ssl_info (Validity End) |
| x509-certificate | validity_not_before | ssl_info (Validity Start) |
| x509-certificate | version | ssl_info (Version) |
| <br> | | |
