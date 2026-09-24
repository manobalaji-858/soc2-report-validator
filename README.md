---
title: SOC 2 Trust Services Evaluator
emoji: 🛡️
colorFrom: teal
colorTo: blue
sdk: streamlit
app_file: app.py
pinned: false
license: mit
short_description: Scope AICPA Trust Services Criteria and validate a vendor's SOC 2 posture
---

# SOC 2 Trust Services Evaluator

A vendor risk-assessment tool built around the **AICPA Trust Services Criteria**.
It scopes the TSC categories a vendor must satisfy from an inherent-risk
questionnaire, then validates the vendor's **SOC 2 / SOC 3 report** against that
scope and scores residual risk.

**Designed by:** Manobalaji Ganapathi — GRC & security automation.  
**Status:** in development.

## What it does (Version 1)

0. **Overview** — what the tool checks, then **Start**.
1. **Vendor Scope for Access and Data** — vendor profile (legal entity, HQ,
   service, business unit, owner, contract dates and value), data shared,
   record volume, processing regions, access, criticality, claimed
   certifications, sub-processors and **Right to Audit**.
2. **Inherent Risk Questionnaire** — uptime dependence, customer-facing,
   processing reliance, credentials, code in our environment, physical access,
   AI/ML training on our data, cross-border transfers, fourth parties and
   applicable regulations. **Tier-escalation rules** can raise (never lower) the
   tier, e.g. >100k sensitive records or privileged access + credentials → Tier 1.
3. **Auto-scoped TSC** — Security always; Availability, Confidentiality,
   Processing Integrity and Privacy added from the answers (privacy laws and
   SOX also trigger scope), each with the reason shown.
4. **Control Questionnaire** — up to 48 controls in 10 domains (Governance,
   Identity & Access, Data Protection, Security Ops, Change, Incident Response,
   Sub-processors, Resilience, Privacy, Processing Integrity), shown only for
   categories in scope, each mapped to a TSC criterion; critical controls flagged.
   Question bank lives in `questionnaire.py`.
5. **Evidence** — upload a SOC 2 / SOC 3 (or load the sample) for AI extraction
   with a rule-based fallback, or proceed on the questionnaire alone.
6. **Dashboard** — criteria coverage, residual-risk gauge, vendor profile,
   questionnaire domain scores, maturity breakdown, findings by severity mapped
   to TSC, a recommendation and a downloadable JSON + Markdown report.

### Contract review & control mapping (ISO 27001 ↔ SOC 2)

On the Evidence step, an **agreements checklist** (DPA, MSA, SOW) lets you
upload each agreement or load a synthetic sample. `contracts.py` checks 25
clauses — GDPR Art. 28(3) processor terms, transfer mechanism, right to audit,
security schedule, breach notice (≤ 72h), liability, insurance, exit, SLAs,
screening, locations — with **transparent keyword rules, not AI**: contract
text never leaves the app and every result quotes the sentence it matched.

The dashboard then scores **18 unified controls**, each mapped to
**ISO/IEC 27001:2022 Annex A** and the **AICPA TSC**, from every source of
evidence at once — contract clauses, questionnaire answers, intake answers and
the SOC 2 report. Control status = average of assessed sources
(Met ≥ 0.8 · Partial ≥ 0.4 · Gap). Filter by framework and status, and export
the matrix as CSV. Contract gaps and contradictions (e.g. "right to audit"
answered Yes but absent from the MSA; 72h breach notice claimed but the DPA
says 96h) become findings. Contract assurance is shown separately and does not
change the residual score.

### Guided tour & simulate

On the Overview, **See it in action** offers three synthetic vendors — one per
tier — defined in `demo.py`:

| Vendor | Tier | What it demonstrates |
|---|---|---|
| NimbusCRM Cloud | 2 | Type II missing Privacy, CUECs, carve-out, right to audit |
| PayBridge Financial | 1 | Enhanced Due Diligence, qualified + stale SOC 2, critical controls missing → Critical |
| Santoso Hardware Supply | 3 | Lite questionnaire, no SOC 2, proportionate → Low |

**▶ Guided tour** pre-fills every step and adds a narration panel (6 stops)
explaining what to look at and why the numbers come out as they do.
**⚡ Simulate** jumps straight to the dashboard. Tour data is fixed (no AI call),
so results are repeatable; dates are relative to today.

### Vendor tiers

Inherent score = 0.45 × data sensitivity + 0.35 × access + 0.20 × criticality.

| Tier | Criteria | Also raised here by | Questionnaire | Review |
|---|---|---|---|---|
| 1 (high) | Inherent ≥ 65 | >100k sensitive records; privileged access + credentials | **Full + Enhanced Due Diligence** (exit plan, audit access, 24x7 SOC, insurance, financial stability…) and Resilience always | 3 months |
| 2 (moderate) | 40 – 64 | code in our environment; AI training on our data; PHI/financial data cross-border; business-critical + customer-facing | **Standard** — every question in the in-scope domains | 6 months |
| 3 (low) | < 40 | — | **Lite** — critical controls + key basics | 12 months |

Escalation rules only ever raise a tier. The same table is shown in the app
as a banner on the Inherent Risk step, with the current vendor
highlighted.

### How evidence is weighed

The SOC 2 is the primary evidence. The self-attested questionnaire:

- **stands in at 60% weight** when no SOC 2 exists (maturity = 0.6 × score);
- **softens a coverage gap** from −12 to −6 when the matching domain scores
  ≥ 75% (e.g. Privacy domain for an uncovered Privacy category);
- **penalises critical controls the vendor says are missing** (−5 each, max −15),
  each raised as a High finding.

Findings also cover cross-border transfers without SCCs/adequacy, claimed but
unevidenced certifications, contract expiry / renewal windows, missing
relationship owners, and cases where the questionnaire confirms an audit
exception.

### Right to Audit logic (TSC CC9.2 — vendor and business partner risk)

A contractual right to audit lets you test what the SOC 2 doesn't cover. When
the report leaves assurance gaps (uncovered categories, not Type II, stale
period, carved-out sub-processors):

- **Yes** → report quality +5, a Low finding naming what to audit, and the
  recommendation tells you to exercise the right on those gaps.
- **No** → report quality −5 (also applied to any Tier 1 vendor), a finding that
  the SOC 2 is the only assurance (High for Tier 1, else Medium), and for
  High/Critical residual risk the recommendation makes the clause a contract
  condition.

## AI extraction (optional but recommended)

Add keys in **Streamlit Cloud → app Settings → Secrets** (or a gitignored
`.streamlit/secrets.toml` locally):

```toml
GROQ_API_KEY = "gsk_..."   # optional, tried first (free tier)
HF_TOKEN = "hf_..."        # Hugging Face Inference Providers
# MODEL = "meta-llama/Llama-3.1-8B-Instruct"   # optional override
```

If no key is set, or every provider fails, the app falls back to a rule-based
extractor and shows why on screen (e.g. revoked key, credits exhausted).

## Notes

Demo on **synthetic data**. Use the sample or non-confidential reports only —
real SOC 2 reports are typically confidential and NDA-bound. Not affiliated with
the AICPA. Not audit advice.
