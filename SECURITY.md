# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
[private vulnerability reporting](https://github.com/huntbase-io/stix-shifter-criminalip/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab). Do not open a
public issue or pull request for a suspected vulnerability.

Include the connector version (or commit), the stix-shifter version, the
command or STIX pattern you ran, and steps to reproduce. We will acknowledge
your report within 5 working days, keep you updated while we look into it,
and credit you in the advisory unless you prefer otherwise.

Security fixes are made on the latest release only.

## Scope

The connector translates STIX patterns into Criminal IP queries, calls the
Criminal IP API with the key you configure, and turns the results into STIX
`observed-data`. In scope are issues in the connector itself, for example:

- the API key leaking into translated queries, results, logs or error
  messages;
- the connector sending the key or a request to a host other than the one in
  the connection configuration;
- a STIX pattern or value injecting query syntax or operators that change the
  Criminal IP query beyond what the pattern says;
- result data from the API producing STIX output that could mislead or attack
  a consumer, beyond reporting what the API returned;
- vulnerabilities in the published wheel or the install script.

Issues in stix-shifter itself should be reported to the
[stix-shifter project](https://github.com/opencybersecurityalliance/stix-shifter).
Vulnerabilities in the Criminal IP API or service should be reported to AI
Spera, which runs Criminal IP.

## Using the connector safely

**Treat the API key as a credential.** Pass it from a secret store or an
environment variable rather than typing it into shared shell history.

**Mind the credit budget.** Every Criminal IP call costs credits.
`options.max_api_calls` and `options.result_limit` cap how much one request
can spend; raise them only when you mean to.
