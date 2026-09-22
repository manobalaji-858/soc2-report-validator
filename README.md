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

**Author:** Manobalaji Ganapathi — GRC & security automation.

## What it does

1. **Vendor & intake** — service category, data shared, access level, criticality.
2. **Inherent Risk Questionnaire (IRQ)** — refines the inherent tier and TSC scope.
3. **Auto-scoped TSC** — Security (Common Criteria) is always required; Availability,
   Confidentiality, Processing Integrity and Privacy are added conditionally from
   the answers.
4. **Report validation** — upload a SOC 2 / SOC 3 (or load the built-in sample);
   the app extracts report type, period, TSC categories covered, auditor opinion,
   exceptions, CUECs and subservice method.
5. **Results** — required-vs-covered coverage, residual score, findings
   (Type I vs II, stale period / bridge letter, CUECs, carve-out sub-processors),
   a recommendation, and a downloadable JSON + Markdown report.

## AI extraction (optional but recommended)

Report extraction uses a Hugging Face-hosted model. To enable it:

1. Get a free access token at **huggingface.co → Settings → Access Tokens**.
2. In this Space: **Settings → Variables and secrets → New secret**,
   name `HF_TOKEN`, paste the token.

If no token is set, or the model is unavailable, the app automatically falls
back to a rule-based extractor, so it always runs. The model is set by `MODEL`
in `app.py` (default `meta-llama/Llama-3.1-8B-Instruct`) and can be swapped for
any chat model served on HF Inference.

## Notes

Demo on **synthetic data**. Use the sample or non-confidential reports only —
real SOC 2 reports are typically confidential and NDA-bound. Not affiliated with
the AICPA. Not audit advice.
