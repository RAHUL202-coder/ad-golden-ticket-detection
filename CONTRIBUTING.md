# Contributing

Thanks for your interest in this project. It is an academic capstone research
framework, and contributions that improve the detection logic, documentation, or
reproducibility are welcome.

## How to contribute

1. **Open an issue** describing the change or problem before large edits.
2. **Fork** the repository and create a feature branch.
3. Keep changes focused and well-described.
4. **Do not commit secrets** — subscription/tenant/resource IDs, connection strings,
   SAS tokens, or private keys. Use parameters and Managed Identity.
5. Open a **pull request** referencing the issue.

## Areas that welcome contributions

- New or tuned **KQL** detection rules (with false-positive analysis)
- Improvements to the **memory-forensics** worker
- **Bicep** module refinements
- Documentation and reproducibility fixes

## Style

- KQL: readable, commented, with a short rationale for thresholds.
- PowerShell / Python: clear naming, no hardcoded environment values.
- Match the existing structure of the repository.
