"""
Synthetic demo vendors for the guided tour and "Simulate" mode.

One per tier so the tour shows how scope, questionnaire depth, evidence and
findings change. Dates are relative to today so the demo never goes stale.
"""

import datetime as dt

from questionnaire import SAMPLE_ANSWERS

SCENARIOS = {
    "nimbus": {
        "label": "NimbusCRM Cloud",
        "tagline": "Tier 2 · CRM SaaS · clean SOC 2 Type II that misses Privacy",
        "shows": "a coverage gap, CUECs, a carved-out sub-processor, DPA / "
                 "MSA / SOW clause review and the ISO 27001 ↔ SOC 2 control "
                 "matrix",
        "evidence": "sample",
    },
    "paybridge": {
        "label": "PayBridge Financial",
        "tagline": "Tier 1 · payment processor · stale, qualified SOC 2, no "
                   "right to audit",
        "shows": "a Tier 1 score, Enhanced Due Diligence, a qualified opinion, "
                 "a bridge-letter gap, critical controls missing and a "
                 "Critical residual",
        "evidence": "paybridge",
    },
    "santoso": {
        "label": "Santoso Hardware Supply",
        "tagline": "Tier 3 · hardware supplier · no SOC 2, no data access",
        "shows": "the Lite questionnaire and a proportionate, self-attested "
                 "assessment with Low residual risk",
        "evidence": "none",
    },
}


def _days(today, n):
    return today + dt.timedelta(days=n)


def answers(key):
    if key == "nimbus":
        return dict(SAMPLE_ANSWERS)
    if key == "paybridge":
        ans = dict(SAMPLE_ANSWERS)
        ans.update({"iam4": "No", "edd2": "No", "bcp2": "Partial",
                    "pin3": "No", "ops4": "No", "inc3": "Partial",
                    "tpr3": "No", "edd1": "No"})
        return ans
    # santoso: small supplier, mostly fine, self-attested
    ans = {k: "Yes" for k in SAMPLE_ANSWERS}
    ans.update({"gov3": "Partial", "tpr1": "No", "dat5": "N/A",
                "ops2": "Partial"})
    return ans


def vendor(key, today):
    """The wizard's answer dict for a scenario (without derived fields)."""
    if key == "nimbus":
        return {
            "vendor": "NimbusCRM Cloud", "legal_name": "NimbusCRM Cloud, Inc.",
            "website": "nimbuscrm.io", "hq": "Ireland",
            "category": "Marketing / CRM", "spend": "$50k – $250k",
            "description": "CRM platform for the global sales pipeline.",
            "bu": "Sales & Marketing", "owner": "Head of Sales Ops",
            "contract_start": _days(today, -540),
            "contract_end": _days(today, 75),
            "data": ["Customer PII"], "volume": "10k – 100k records",
            "regions": ["EU / EEA", "United States"],
            "access": "Reads our production data", "crit": "Moderate",
            "certs": ["SOC 2 Type II", "ISO 27001"],
            "subprocessors": "AWS, Twilio", "rta": "Yes",
            "irq_store": True, "irq_uptime": True,
            "irq_customer_facing": False, "irq_processing": False,
            "irq_creds": False, "irq_code": False, "irq_physical": False,
            "irq_ai": False, "irq_crossborder": True, "irq_fourth": True,
            "regulations": ["GDPR"],
        }
    if key == "paybridge":
        return {
            "vendor": "PayBridge Financial",
            "legal_name": "PayBridge Financial Services LLC",
            "website": "paybridge.co", "hq": "United States",
            "category": "Payment processor", "spend": "> $250k",
            "description": "Processes outbound vendor and payroll payments.",
            "bu": "Finance", "owner": "",
            "contract_start": _days(today, -900),
            "contract_end": _days(today, 40),
            "data": ["Financial / cardholder"],
            "volume": "100k – 1M records", "regions": ["United States"],
            "access": "Read-write to core systems", "crit": "Business-critical",
            "certs": ["SOC 2 Type II", "PCI DSS"],
            "subprocessors": "Stripe, AWS", "rta": "No",
            "irq_store": True, "irq_uptime": True,
            "irq_customer_facing": False, "irq_processing": True,
            "irq_creds": True, "irq_code": False, "irq_physical": False,
            "irq_ai": False, "irq_crossborder": False, "irq_fourth": True,
            "regulations": ["PCI DSS", "SOX"],
        }
    return {
        "vendor": "Santoso Hardware Supply",
        "legal_name": "PT Santoso Hardware Supply", "website":
        "santosohardware.co.id", "hq": "Indonesia",
        "category": "Hardware & equipment", "spend": "< $10k",
        "description": "Office hardware and peripherals. No system or data "
                       "access.",
        "bu": "Procurement", "owner": "Procurement Lead",
        "contract_start": _days(today, -300),
        "contract_end": _days(today, 400),
        "data": ["None"], "volume": "< 10k records", "regions": ["Other"],
        "access": "No access to our systems or data", "crit": "Moderate",
        "certs": [], "subprocessors": "", "rta": "No",
        "irq_store": False, "irq_uptime": False, "irq_customer_facing": False,
        "irq_processing": False, "irq_creds": False, "irq_code": False,
        "irq_physical": True, "irq_ai": False, "irq_crossborder": False,
        "irq_fourth": False, "regulations": [],
    }


def paybridge_report(today):
    """Extracted attributes of PayBridge's (synthetic) SOC 2."""
    return {
        "report_type": "SOC 2 Type II",
        "period_start": _days(today, -815).isoformat(),
        "period_end": _days(today, -450).isoformat(),
        "tsc_categories": ["Security", "Confidentiality",
                           "Processing Integrity"],
        "auditor_opinion": "Qualified",
        "exceptions_noted": True,
        "exceptions_summary": "Change approvals missing for 4 of 40 sampled "
                              "production releases (CC8.1).",
        "cuecs_present": True,
        "cuecs_summary": "Customers must restrict and review API key access.",
        "subservice_method": "Inclusive",
    }


# What to look at on each wizard step during the tour.
TOUR = {
    1: ("Vendor Scope for Access and Data",
        "Every field is pre-filled for <b>{vendor}</b>. Watch the <b>Live "
        "inherent risk</b> donut: it is 0.45 × data sensitivity + 0.35 × "
        "access + 0.20 × criticality = <b>{inherent}</b>. Right to Audit is "
        "<b>{rta}</b> — remember it; it changes the maturity score later. "
        "Try changing the access level and see the donut move."),
    2: ("Inherent Risk Questionnaire",
        "These answers don't change the score — they can only <b>raise the "
        "tier</b> and <b>widen the TSC scope</b>. {escalation} Scroll to the "
        "tier banner at the bottom: {vendor} is highlighted as <b>{tier}</b>."),
    3: ("Auto-scoped Trust Services Criteria",
        "Security (the Common Criteria) is always required. Each other "
        "category shows <i>why</i> it was added. For {vendor} that's "
        "<b>{required}</b> — <b>{n_criteria}</b> criteria the SOC 2 has to "
        "cover."),
    4: ("Control Questionnaire",
        "Depth follows the tier: <b>{depth}</b> — {n_questions} questions. "
        "Answers are pre-filled. Controls marked <b>Critical</b> and "
        "answered No become High findings; watch <b>Live control "
        "maturity</b> on the right."),
    5: ("Evidence & contracts",
        "{evidence_note} {contracts_note} The tour uses fixed synthetic data "
        "(no AI call) so the result is repeatable."),
    6: ("Dashboard",
        "Read it top-down: <b>Residual Risk</b> (the answer) → <b>Maturity "
        "breakdown</b> (why) → <b>TSC Coverage</b> (what the report misses) "
        "→ <b>Control mapping</b> (every control scored against ISO 27001 "
        "and SOC 2 from all evidence) → <b>Findings</b> (what to do). Open "
        "<i>How to read this dashboard</i> for every formula. This scenario "
        "shows {shows}."),
}
