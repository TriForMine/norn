# Risk Scoring

Norn scores runtime risk from vulnerability severity plus runtime context.

## MVP Rules

- Critical CVE on a publicly exposed service becomes Critical runtime risk.
- High CVE on a publicly exposed service becomes High runtime risk.
- Critical CVE on an internal-only or localhost service becomes High runtime risk.
- Medium and Low CVEs on internal services remain Medium or Low.
- Unknown exposure is retained and marked for review.
- Privileged containers increase risk by one level.
- Containers mounting `/var/run/docker.sock` increase risk by one level.
- Fix availability affects recommended action text.

## Examples

| Finding | Runtime context | Result |
| --- | --- | --- |
| Critical CVE | `0.0.0.0:443` | Critical |
| Critical CVE | container network only | High |
| High CVE | localhost service | Medium |
| High CVE | privileged container | one level higher |
| Medium CVE | unknown exposure | Medium, marked unknown |

## Limitations

Norn does not yet include EPSS, CISA KEV, exploit maturity, asset criticality, compensating controls, or service ownership. The model leaves room for those fields in future releases.
