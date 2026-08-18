# Security Policy

## Purpose & scope

This repository is an **academic proof-of-concept** for detecting Golden Ticket and
SIDHistory abuse in Active Directory. It contains **detection** content (KQL analytics
rules, memory-forensics tooling, infrastructure-as-code) and controlled attack-simulation
scripts intended **only** for use in an isolated, authorized lab you own.

## Responsible use

- Run the attack-simulation scripts **only** against a lab domain you control.
- Never target production systems or systems you are not explicitly authorized to test.
- The simulation scripts demonstrate known techniques for **defensive research and
  education**; they are not a toolkit for unauthorized access.

## Reporting an issue

If you find a security problem in the detection logic or tooling, please open a private
report via the repository's **Security → Report a vulnerability** tab, or contact the
author. Please do not open a public issue for anything sensitive.

## Secrets & configuration

- No subscription IDs, tenant IDs, resource IDs, connection strings, or SAS tokens are
  committed. Deployment values are parameters/placeholders.
- Use **Managed Identity** for storage and queue access; do not hardcode keys.
