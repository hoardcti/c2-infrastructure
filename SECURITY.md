# Security Policy

hoardCTI produces threat intelligence that other organisations depend on for
their own defence. A vulnerability here can propagate into every downstream
consumer, so we treat reports seriously and respond quickly.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report privately through GitHub's [private vulnerability reporting][pvr] —
the **Security** tab of this repository, then **Report a vulnerability**. This
keeps the report confidential until a fix is available and gives us a private
fork to develop the fix in.

[pvr]: https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability

If you cannot use that route, email **<!-- TEMPLATE: security contact -->
security@hoardcti.com** and, if possible, encrypt with our published PGP key.

Please include:

- What the issue is and why you believe it is a security problem
- Steps to reproduce, or a proof of concept
- Affected version, commit, or deployment
- Any impact you have already assessed (data exposure, privilege escalation,
  feed poisoning, denial of service)

## What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | 3 working days |
| Initial assessment and severity triage | 10 working days |
| Fix or documented mitigation for high/critical issues | 90 days |
| Public advisory | Coordinated with you, normally at fix release |

We will keep you updated as the assessment progresses, credit you in the
advisory unless you prefer otherwise, and let you know if we determine the
report is not a vulnerability.

## Scope

In scope: source code in this repository, its build and release pipeline, its
GitHub Actions workflows, and the integrity of any intelligence data it
produces or distributes.

Out of scope: findings against third-party services we merely link to, reports
generated solely by automated scanners with no demonstrated impact, social
engineering of maintainers, and denial of service achieved through unrealistic
traffic volumes.

## Safe harbour

We will not pursue or support legal action against researchers who act in good
faith, make a genuine effort to avoid privacy violations and service
disruption, and give us reasonable time to remediate before disclosing.

## Handling credentials

If you find a credential committed to this repository, treat it as live:
report it privately as above rather than opening a pull request that removes
it, since the removal commit advertises what to look for in the history. Any
credential that reaches a repository must be **rotated**, not just deleted.

## Supported versions

<!-- TEMPLATE: replace with this project's actual support window. -->

| Version | Supported |
| --- | --- |
| Latest release | :white_check_mark: |
| Older releases | :x: |
