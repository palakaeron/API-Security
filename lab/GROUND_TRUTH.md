# Controlled Lab Ground Truth

All records, identifiers, email addresses, account references, and tokens in this laboratory are synthetic. This document is the ground truth for detector-accuracy tests in later milestones.

| Scenario | Vulnerable path | Expected vulnerable behavior | Secured counterpart | Expected secured behavior |
|---|---|---|---|---|
| BOLA: user object | `GET /vuln/users/bob` as Alice | Returns Bob's object | `GET /secure/users/bob` as Alice | 403 |
| Broken function authorization | `GET /vuln/admin/audit` as Alice | Returns admin data | `GET /secure/admin/audit` as Alice | 403 |
| Broken property authorization | `GET/PATCH /vuln/profiles/bob` as Alice | Reads/writes Bob's sensitive properties and role | `GET/PATCH /secure/profiles/bob` as Alice | 403 |
| Sensitive payments | `GET /vuln/payments/bob` as Alice | Returns Bob's synthetic payment data | `GET /secure/payments/bob` as Alice | 403 |
| Order BOLA / business flow | `GET /vuln/orders/ord-bob-001` as Alice | Returns Bob's order | `GET /secure/orders/ord-bob-001` as Alice | 403 |
| Weak JWT controls | `POST /vuln/auth/token` | HS256 with a known synthetic lab secret and 10-year expiry | `POST /secure/auth/token` | environment-supplied secret, 15-min expiry, issuer/audience required |
| Zombie inventory | `GET /v1/users/alice` | Deprecated endpoint remains reachable | N/A | Must be reported as live deprecated inventory |
| Shadow inventory | `GET /internal/diagnostics` | Reachable but excluded from `public-api.yaml` | N/A | Must be reported as undocumented inventory |
| GraphQL introspection | `POST /vuln/graphql` with `{ __schema { queryType { name } } }` | Returns introspection data | `POST /secure/graphql` | 403 |

The secure routes are expected negatives for detector precision/recall. `scripts/run_lab.ps1` starts each API domain as a separate localhost process (ports 8101–8107). Later detector tests must target only these loopback URLs and must pass the shared target-allowlist check before sending traffic.
