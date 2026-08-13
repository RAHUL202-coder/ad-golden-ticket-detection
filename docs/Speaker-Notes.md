# Speaker Notes — Capstone Viva
### Memory-Based Detection of Golden Ticket & SIDHistory Abuse in Active Directory
*P Rahul · R23MTC09. Notes are honest and match the deployed system (pypykatz, real timings, measured benchmark). Aim ~1 min per content slide.*

---

**Slide 1 — Title**
"Good morning. I'm Rahul. My capstone is *Memory-Based Detection of Golden Ticket and SIDHistory abuse in Active Directory*. The one-line idea: log-only SIEM misses the strongest evidence of these attacks, which lives in LSASS memory — my project adds a memory-forensics layer on Microsoft Sentinel that catches what logs alone cannot."

**Slide 2 — Agenda**
"I'll cover the background and the detection gap, the literature, the problem and objectives, my methodology and architecture, a live demo of the three detection paths, the testing and measured results, and conclusions."

**Slide 3 — Introduction (part 1)**
"Golden Ticket and SIDHistory are two of the stealthiest Active Directory attacks. A Golden Ticket is a Kerberos TGT forged with the domain's KRBTGT key — the attacker becomes any user, including Domain Admin, and the ticket looks legitimate. SIDHistory abuse injects a privileged SID (like Domain Admins, RID 512) so an account silently inherits admin rights without visible group membership."

**Slide 4 — Introduction (part 2): the gap**
"Traditional detection is log-only — Kerberos events 4768/4769. But a skilled attacker can evade or delay those signals, and logs never show the forged ticket itself. The forged ticket physically sits in LSASS memory. Microsoft Sentinel cannot natively read that memory. My project closes that gap with a hybrid design: cloud analytics on the logs, plus an automated LSASS memory-forensics pipeline."

**Slide 5 — Literature Review**
"Across the literature three themes emerge: (1) Kerberos log analytics — 4768/4769, RC4 downgrade — are useful but insufficient alone; (2) SIDHistory abuse is under-audited — Windows doesn't log the injection well, so inventory scanning is more reliable; (3) memory forensics can recover Kerberos artifacts but is manual and on-prem. The gap my work fills: an *automated, cloud-integrated* memory-forensics layer that corroborates the log detections. [Correction to make on the slide: cite that standard Volatility 3 has no working Kerberos-ticket plugin on modern Windows — my implementation uses pypykatz.]"

**Slide 6 — Problem Statement (technical)**
"Technically: Sentinel and any log-based SIEM cannot access volatile LSASS memory, so a forged Kerberos ticket resident in memory is invisible to them. There is no native pipeline to capture, analyse, and correlate that memory evidence with the log detections."

**Slide 7 — Problem Statement (functional)**
"Functionally: a SOC needs (a) reliable detection of Golden Ticket and SIDHistory even when logs are evaded, (b) memory-level confirmation of the forged ticket, and (c) all of it automated and low-cost enough to reproduce. No single open, auditable framework did this."

**Slide 8 — Methodology**
"My approach is a dual-track hybrid framework on Microsoft Sentinel. Track 1 — Kerberos log analytics: the Domain Controller ships events via Azure Arc and the Azure Monitor Agent through a Data Collection Rule into Log Analytics, where KQL analytics rules detect the attacks. Track 2 — memory forensics: LSASS is captured, uploaded to Blob storage, analysed on a Volatility VM using pypykatz, and the result is written back to a custom table that a Sentinel rule alerts on. A third input is an hourly SIDHistory inventory posted directly to Log Analytics. Everything converges into Sentinel incidents."

**Slide 9 — Resource Specification**
"Entirely on an Azure-for-Students subscription — under about 100 dollars. Cloud: Microsoft Sentinel, Log Analytics, Azure Arc, AMA, Blob Storage, Service Bus, Azure Functions, a Linux Volatility VM. On-prem lab: one Windows Server 2022 Domain Controller, `corp.local`. Tools: mimikatz for the attack simulation, pypykatz for memory parsing."

**Slide 10 — Software Design (architecture)**
"[Show the architecture diagram.] Three data paths. One: DC → AMA + DCR → SecurityEvent → 16 KQL analytics rules. Two: LSASS dump → Blob → Function blob-trigger → Service Bus → Volatility VM (pypykatz) → the VolatilityAnalysis_CL table → a Sentinel rule. Three: SIDHistory inventory → posted directly to SIDHistoryInventory_CL. All three raise incidents; automation rules auto-triage them."

**Slide 11 — Implementation**
"16 Sentinel analytics rules mapped to MITRE ATT&CK. A PowerShell LSASS-capture task on the DC using Managed Identity — no hard-coded keys. The Volatility VM runs a systemd worker that pulls dumps from Service Bus and analyses them with pypykatz. Custom log tables, automation rules for triage, and a workbook dashboard. Key engineering finding I'll return to: I had to replace Volatility for the Kerberos step with pypykatz."

**Slide 12 — Demo**
"[Live or recorded.] I run mimikatz: DCSync to steal the KRBTGT hash, forge a Golden Ticket for Administrator, and inject it — Pass-the-Ticket. This produces TGS requests with no prior TGT. Within minutes Sentinel raises: a Golden Ticket log incident, a SIDHistory incident, and — the differentiator — a CRITICAL *memory* incident where pypykatz extracted the forged Administrator ticket from the LSASS dump."

**Slide 13 — Testing & Validation**
"I ran a controlled benchmark rather than quoting an unmeasured accuracy. For the SIDHistory detector, on 40 labelled samples — 20 malicious, 20 benign — the confusion matrix was 20 TP, 0 FN, 0 FP, 20 TN: precision, recall and F1 all 1.00 on that controlled set. For the memory detector, every attack dump was correctly flagged CRITICAL, and I added a ticket-lifetime check so a legitimate admin's ticket is not false-flagged. For the log detector, only the attacker account was flagged, not benign users."

**Slide 14 — Analysis & Results (key findings)**
"Three findings. First — and this is my main technical contribution — standard Volatility 3 cannot extract Kerberos tickets from a modern-Windows LSASS dump; it silently returned nothing. I identified this and switched to pypykatz, which works. Second, the forged ticket carries a tell-tale ~10-year (3650-day) lifetime versus ~10 hours for a real ticket — a precise, reliable indicator. Third, detection time: the log path detects in roughly 4 to 10 minutes depending on Sentinel's evaluation cycle, and memory analysis completes in about a minute after capture — down from a ~45-minute unoptimised baseline."

**Slide 15 — Suggestions & Conclusion**
"The core gap is real: the best evidence sits in LSASS memory, which log-only SIEM can't reach; my dual-track design corroborates the logs with memory. All objectives were met. My differentiator is *forensic transparency and low-cost reproducibility* — open KQL rules and published scripts anyone can audit — not beating commercial tools on speed. Honest limitations: it's a single-DC lab, so a few rules (RC4 downgrade, Kerberoasting) are production-only, and the automated response playbook needs a one-time interactive sign-in. Future work: wire that response loop, and a larger adversarial benchmark."

**Slide 16 — References**
"[Have every citation verifiable — remove any you can't source.] These cover Kerberos attack detection, SIDHistory abuse, Volatility/pypykatz memory forensics, and Microsoft Sentinel automation."

**Slide 17 — Annexure: additional info + plagiarism score**
"Additional configuration details and the plagiarism report are here."

**Slide 18 — Annexure: publications / conferences**
"[Only claim what's real.]"

**Slide 19 — GitHub**
"The full framework — worker code, KQL rules, scripts, and the benchmark — is on GitHub, so the work is fully auditable and reproducible."

**Slide 20 — Thank you / Q&A**
"Thank you — happy to take questions, and I can show any part of the live system."

---

## Answers to keep ready (likely questions)
- *Which Volatility plugin extracts the ticket?* → "None — Volatility 3 can't on modern Windows; that was my finding. I use **pypykatz**."
- *Accuracy?* → "Per-case validation plus a measured SIDHistory benchmark (P/R/F1 = 1.00 on 40 labelled samples). I don't claim a single blanket accuracy — that needs a larger adversarial dataset."
- *How is a Golden Ticket told apart from a real admin ticket?* → "Lifetime — forged is ~10 years, real is ~10 hours — plus a TGS with no prior TGT in the logs."
- *Why does RC4 downgrade not fire?* → "Single-DC lab; the DC's AES keys override. Valid in production."
