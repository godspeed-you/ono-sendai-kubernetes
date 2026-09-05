# Security Policy

This repository specifies the Kubernetes provider for
[Ono-Sendai](https://github.com/godspeed-you/ono-sendai). **There is no implementation yet**, so
there is no released code here to have a vulnerability in. This policy exists so that the
reporting path is established before it is needed, and it covers the specification itself: a
requirement that mandates unsafe behaviour is a security defect worth reporting.

## Reporting a vulnerability

**Report privately.** Use [GitHub's private vulnerability
reporting](https://github.com/godspeed-you/ono-sendai-kubernetes/security/advisories/new) on this
repository — *Security → Report a vulnerability*.

If the issue is in Ono-Sendai core rather than in this provider — the shell, the pipeline, the
KUANG/11 host or the generic provider contract — report it on the
[core repository](https://github.com/godspeed-you/ono-sendai/security/advisories/new) instead. If
you are unsure which side owns it, report it on either and say so; it will be routed.

There is no published security email address. If private reporting is unavailable to you, open a
public issue describing **the impact and affected component only** — no reproduction, no working
exploit, no proof-of-concept input — and say that you have details to share privately.

A public issue is the wrong place for an unpatched exploitable vulnerability. The tracker is
world-readable and indexed.

### What to expect

The response times of the [core security
policy](https://github.com/godspeed-you/ono-sendai/blob/main/SECURITY.md) apply to this repository
as well: acknowledgement within 7 days, first assessment within 14, and a fix or a stated plan
with a date within 90 days of the assessment. The project is developed by a small number of
people; these are the times it commits to. If a deadline is going to be missed you will be told
before it passes, with the reason.

## Supported versions

| Version | Supported |
|---|---|
| — | there is no release of this provider yet |

This table is filled in when the first version ships. It is left empty rather than implying a
maintenance commitment that does not exist.

## Why this provider is security-sensitive

A Kubernetes provider is not an ordinary integration. When implemented it will hold or broker
cluster credentials, reach production control planes, and act with whatever authority the
operator's kubeconfig carries. The specification therefore makes several properties normative
rather than advisory, and a change that weakens one of them is a security change:

- **Credentials never become values.** Tokens, private keys and client certificate material must
  not appear in typed values, logs, crash diagnostics, history, provider manifests or serialized
  session state (§8.1). Credential bytes pass through the host's credential broker.
- **TLS validation is on by default.** Insecure modes require explicit configuration, must be
  visible in provider diagnostics, and should be prominent in destructive-change contexts (§8.4).
- **Exec credential plugins run only under an explicit KUANG/11 process capability** (§8.2), and a
  non-interactive context must not fake interactive stdin.
- **Secret payloads are redacted by default.** `Secret` objects participate in identity,
  relationships and navigation; their `data` does not appear in ordinary inspection (§22).
- **The API server remains the authorization authority.** Ono does not substitute its own RBAC
  evaluator, and a preflight check is advisory rather than a guarantee (§21.1, §21.2).
- **Denied is not empty.** A `403` maps to an explicit denied state, distinguishable from absence,
  so that a permission boundary is never read as "there is nothing there" (§21.4, and §4 invariant 13).
- **Impersonation is never confusable with the credential identity** (§8.5).
- **Reads do not mutate.** Discovery, rendering, relationship resolution and inspection are
  side-effect free (§21.2, and invariant 9 of the generic provider contract).

Reports that a specification requirement mandates or permits unsafe behaviour are in scope, as are
reports that a requirement above is contradicted elsewhere in the document.

## Threat model

The provider inherits the Ono-Sendai threat model in
`docs/specs/ono_sendai_shell_spec_v0.4.1_hardening_trust_release_integrity.md` and the KUANG/11
sandbox, capability and audit model in the core repository. This repository does not define a
competing one.
