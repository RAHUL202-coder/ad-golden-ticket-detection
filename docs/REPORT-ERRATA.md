# Report Errata — corrections to align the written report with the deployed system

These are factual mismatches found between the report and the live deployment (sub `824f770b`),
verified 2026-08. Fix each in the report/abstract before final submission.

| # | Where in report | Currently says (WRONG) | Correct it to | Why |
|---|-----------------|------------------------|---------------|-----|
| 1 | Memory forensics / methodology | Kerberos tickets extracted with **Volatility** | **pypykatz** (`pypykatz lsa minidump -k`) extracts the tickets; Volatility 3 is only used for supporting scans (mutantscan/pslist/cmdline) | Volatility 3 has **no** Kerberos-ticket plugin — it cannot do this on modern Windows. This is verified: analysisSource = `VolatilityWorker-v2-pypykatz`. |
| 2 | Abstract / Results | Detection accuracy **87.2% / 90% / 100%** | Remove. Replace with **measured benchmark figures** (see `benchmark-results.md`) or, if not run, **"per-case functional validation"** | No labelled precision/recall benchmark was ever run; these numbers were unmeasured. |
| 3 | Analytics rules section | **16 rules = 3 NRT + 13 Scheduled** | **16 Scheduled rules (+ 1 built-in Fusion); 0 NRT** on this subscription | Verified live: no NRT rules deployed on `824f770b`. |
| 4 | Detection-time / response | **Event-triggered LSASS capture (~5 sec)** | Either remove, or update **only after** the response playbook is wired. Current reality: LSASS capture is a **scheduled task (4h)** or manual trigger | The Logic App auto-capture was never wired (needs interactive OAuth). |
| 5 | Response automation | **"Logic App runs → Arc Run Command LsassCapture → Succeeded"** | Mark as **future work**, or update after wiring (Phase 2 of the continuation plan) | Verified: the Logic App has **never** auto-invoked (0 runs). |
| 6 | Architecture / data-flow diagram | SIDHistory flows **through the Azure Function**; Volatility results → **SecurityEvent** | SIDHistory posts **directly** to `SIDHistoryInventory_CL` via HTTP Data Collector API (no Function in that path); Volatility results → **`VolatilityAnalysis_CL`** | Verified from live function bindings + table schema. Use the corrected `architecture-diagram.html`. |
| 7 | Detection-time table | "2 min" as the headline | Use **measured range: log-based Golden Ticket ~4–10 min; memory analysis ~1 min to a CRITICAL result** (incident within the PT5M cycle) | Real measured values from live runs (incidents #214/#265 GT; #264/#312 memory). |

## Notes for the viva
- Item **1** is the highest-risk contradiction — an examiner who knows Volatility can ask "which plugin extracts the ticket?" There is no honest answer except pypykatz. Fix it first.
- Items **2, 4, 5** are honesty items — reframing them as measured/future-work is stronger than leaving inflated claims.
- Present the pypykatz finding as a **contribution**, not an embarrassment: "off-the-shelf Volatility cannot extract Kerberos tickets on modern Windows; I identified this and used pypykatz" is a genuine research result. See `pypykatz-contribution.md`.
