# Security Policy

If you discover a security vulnerability, please report it responsibly.

- Do **not** open a public issue.
- Instead, contact the maintainer privately.
- You may also use [GitHub Security Advisories](https://github.com/taiyaky/verikloak/security/advisories) to submit a report.

We will investigate and address vulnerabilities as a priority.

## Known limitations

### DNS rebinding (SSRF checks)

The SSRF protections in `Discovery` (redirect targets) and `JwksCache`
(`jwks_uri`) resolve the target hostname and reject private/internal
addresses **at validation time**. The HTTP client resolves the hostname
again when it connects, so an attacker who controls DNS for the target
host and serves short-TTL records can pass validation with a public
address and have the connection resolve to a private one (DNS rebinding).

Mitigations:

- Point `discovery_url` only at identity providers you trust; the redirect
  and `jwks_uri` values are the attacker-controlled inputs these checks
  defend against, and both originate from that endpoint.
- Run workloads with egress network policies that block traffic to
  internal ranges, which closes the gap independently of DNS.