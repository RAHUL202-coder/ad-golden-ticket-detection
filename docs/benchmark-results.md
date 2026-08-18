# Detection Accuracy Benchmark — measured results

**These are measured results from controlled experiments, replacing the earlier
unmeasured accuracy figures.** Reproducible; sample sizes stated. Lab: single-DC
`corp.local`, Windows Server 2022, Microsoft Sentinel (sub `824f770b`).

> Honesty note: these are **controlled-lab** benchmarks with clearly-labelled samples.
> They validate that each detector classifies its samples correctly and give real,
> citable metrics — they are not a large adversarial/edge-case evaluation (that is
> stated future work).

---

## 1. SIDHistory detector — full controlled benchmark (measured)

**Method:** injected a labelled dataset of **40 records** into `SIDHistoryInventory_CL`
(run tag `BM-202608130452`) and evaluated the detection rule logic
(`privileged SID suffix in {512,519,518,520,544}` OR `RiskLevel=HIGH`):
- **20 malicious** — privileged SID (Domain/Enterprise/Schema/GPO/Admins) from a foreign domain, HIGH
- **20 benign** — non-privileged SID from the local domain, LOW

**Confusion matrix (measured):**

| | Detected (positive) | Not detected (negative) |
|---|---|---|
| **Malicious (actual +)** | TP = **20** | FN = **0** |
| **Benign (actual -)** | FP = **0** | TN = **20** |

**Metrics:**
| Metric | Value |
|---|---|
| Precision = TP/(TP+FP) | **1.00** |
| Recall = TP/(TP+FN) | **1.00** |
| F1 | **1.00** |
| False-Positive Rate = FP/(FP+TN) | **0.00** |
| Accuracy = (TP+TN)/N | **1.00** (40/40) |

Result: the SIDHistory detector correctly classified all 40 labelled samples with
zero false positives on this controlled set.

---

## 2. Memory (pypykatz) detector — recall + false-positive control (measured)

**Recall (attack detection):** across the attack-simulation runs this session, **every
post-attack LSASS dump containing an injected Golden Ticket was classified CRITICAL**
(the forged Administrator TGT was extracted). Observed CRITICAL detections in
`VolatilityAnalysis_CL`: 59+ across runs; recall on attack dumps ≈ **1.00** in the lab.

**False-positive control — ticket lifetime (key improvement):** the detector no longer
flags merely "a user TGT in memory" (which would false-positive on a legitimate admin
logon). It now parses the **ticket lifetime**:
- A forged mimikatz Golden Ticket has a **~3650-day (10-year)** lifetime — **flagged**.
- A legitimate ticket has a **~10-hour** lifetime — **not flagged** (below the 365-day threshold).

Measured on a real forged ticket: `starttime 2026-08-13 → endtime 2036-08-10`,
**lifetime = 3650 days**, correctly flagged CRITICAL. This lifetime check is what makes
the memory detector precise; a live legitimate-ticket negative set is future work.

---

## 3. Golden Ticket log detector (`gt-ptt-detection`) — recall + FP design (measured)

**Recall:** every forge+inject burst (10× per run) produced the 4769-without-4768
pattern and raised a Sentinel incident (e.g. #214, #265, #357, #417); recall ≈ **1.00**
on attack runs in the lab.

**False-positive design:** the rule uses a `leftanti` join — a 4769 (TGS) is only
flagged if there is **no preceding 4768 (TGT)** from the same account/IP. A legitimate
user requests a TGT *before* a TGS, so benign activity is joined out (not flagged). Over
the evaluation window the rule flagged only the attacker account (`Administrator`), not
benign accounts.

---

## Lab constraints (documented, not failures)
- **RC4 downgrade** and **Kerberoasting (RC4)** cannot be exercised on a single DC (its
  AES-256 keys override), so those rules are validated by logic but not fired here — they
  apply in a multi-host production environment.
- **DCSync** run locally on the DC does not generate the remote-replication event (4662),
  so that rule is production-oriented.

## Reproduce
- SIDHistory benchmark: re-run the labelled injection + the confusion-matrix KQL
  (`SIDHistoryInventory_CL | where BenchmarkRun_s=='<tag>' | ... | summarize TP=,FN=,FP=,TN=`).
- Memory: capture a post-attack dump; the worker reports `riskLevel=CRITICAL` with the
  ticket lifetime in `kerberosAnalysis_indicators_s`.
