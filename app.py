"""
SOC 2 Trust Services Evaluator
------------------------------
A vendor risk-assessment tool built around the AICPA Trust Services Criteria.

Flow:
  1. Vendor + intake (access, data, business context)
  2. Inherent Risk Questionnaire (IRQ)
  3. Auto-scope the TSC categories/criteria that must be satisfied
  4. Upload (or load a sample) SOC 2 / SOC 3 report -> AI extraction with a
     rule-based fallback
  5. Evaluate risk posture, show required-vs-covered, residual score, download

Author: Manobalaji Ganapathi  |  GRC & security automation
Demo on synthetic data. Not affiliated with the AICPA. Not audit advice.
"""

import os
import re
import json
import datetime as dt

import streamlit as st

# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------
# Swap MODEL for any chat model served on HF Inference. If it is gated or
# unavailable, the app automatically falls back to rule-based extraction.
MODEL = "meta-llama/Llama-3.1-8B-Instruct"
HF_TOKEN = os.environ.get("HF_TOKEN")  # set as a Space secret
TODAY = dt.date.today()

st.set_page_config(page_title="SOC 2 Trust Services Evaluator",
                   page_icon="🛡️", layout="centered")

# ----------------------------------------------------------------------
# Trust Services Criteria catalogue (AICPA TSC 2017, rev.)
# ----------------------------------------------------------------------
COMMON_CRITERIA = {
    "CC1": "Control Environment",
    "CC2": "Communication & Information",
    "CC3": "Risk Assessment",
    "CC4": "Monitoring Activities",
    "CC5": "Control Activities",
    "CC6": "Logical & Physical Access Controls",
    "CC7": "System Operations",
    "CC8": "Change Management",
    "CC9": "Risk Mitigation",
}
CATEGORY_CRITERIA = {
    "Availability": {
        "A1.1": "Capacity & performance management",
        "A1.2": "Environmental protections, backup & recovery infrastructure",
        "A1.3": "Recovery plan testing",
    },
    "Confidentiality": {
        "C1.1": "Identify & maintain confidential information",
        "C1.2": "Dispose of confidential information",
    },
    "Processing Integrity": {
        "PI1.1": "Definitions of processing specifications",
        "PI1.2": "Completeness & accuracy of inputs",
        "PI1.3": "Completeness & accuracy of processing",
        "PI1.4": "Accuracy & timeliness of outputs",
        "PI1.5": "Storage integrity",
    },
    "Privacy": {
        "P1": "Notice & communication of privacy commitments",
        "P2": "Choice & consent",
        "P3": "Collection",
        "P4": "Use, retention & disposal",
        "P5": "Access",
        "P6": "Disclosure & notification",
        "P7": "Quality",
        "P8": "Monitoring & enforcement",
    },
}
ALL_CATEGORIES = ["Security", "Availability", "Confidentiality",
                  "Processing Integrity", "Privacy"]

# ----------------------------------------------------------------------
# Scoring maps
# ----------------------------------------------------------------------
DATA_SENS = {
    "None": 5, "Internal business data": 25, "Confidential / proprietary": 55,
    "Customer PII": 60, "Employee PII": 60, "Authentication / credentials": 75,
    "Financial / cardholder": 80, "Health / PHI": 90,
}
ACCESS_SCORE = {
    "No access to our systems or data": 10,
    "Reads our production data": 35,
    "Read-write to core systems": 65,
    "Admin / privileged access": 90,
}
CRIT_SCORE = {"Low": 10, "Moderate": 40, "Business-critical": 75}

# ----------------------------------------------------------------------
# Synthetic sample SOC 2 (for the "Load sample" button)
# ----------------------------------------------------------------------
SAMPLE_SOC2 = """INDEPENDENT SERVICE AUDITOR'S REPORT

Report of NimbusCRM Cloud, Inc. relevant to Security, Availability and
Confidentiality throughout the period October 1, 2025 to March 31, 2026
(SOC 2 Type 2).

Scope. We have examined NimbusCRM Cloud's description of its CRM platform
system and the suitability of the design and operating effectiveness of
controls to meet the criteria for the Security, Availability and
Confidentiality categories set forth in TSP section 100, Trust Services
Criteria.

Opinion. In our opinion, in all material respects, the controls were suitably
designed and operated effectively throughout the specified period (unqualified
opinion), based on the applicable trust services criteria.

Exceptions. One exception was noted: for two of twenty-five sampled
terminations, access was not revoked within the one business day required by
policy (relates to CC6). Management remediated the control in Q1 2026.

Subservice organizations. NimbusCRM Cloud uses AWS as a subservice
organization and applies the carve-out method. Complementary User Entity
Controls (CUECs) are described in Section 5 and are the responsibility of
user entities, including enforcement of MFA and timely user access reviews.

Privacy and Processing Integrity categories were not in scope for this
examination.
"""

# ----------------------------------------------------------------------
# Extraction: AI first, rule-based fallback
# ----------------------------------------------------------------------
EXTRACT_PROMPT = """You are a SOC 2 analyst. Read the report text and return ONLY a JSON object, no prose, with these keys:
report_type: one of "SOC 2 Type II","SOC 2 Type I","SOC 3","Unknown"
period_start: YYYY-MM-DD or null
period_end: YYYY-MM-DD or null
tsc_categories: array from ["Security","Availability","Confidentiality","Processing Integrity","Privacy"]
auditor_opinion: one of "Unqualified","Qualified","Adverse","Disclaimer","Unknown"
exceptions_noted: true or false
exceptions_summary: short string or null
cuecs_present: true or false
cuecs_summary: short string or null
subservice_method: one of "Carve-out","Inclusive","Unknown"

REPORT TEXT:
"""


def _month_to_num(m):
    months = ["jan", "feb", "mar", "apr", "may", "jun",
              "jul", "aug", "sep", "oct", "nov", "dec"]
    m = m.lower()[:3]
    return months.index(m) + 1 if m in months else None


def _find_dates(text):
    """Best-effort period extraction, e.g. 'October 1, 2025 to March 31, 2026'."""
    pat = r"([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})"
    found = re.findall(pat, text)
    dates = []
    for mon, day, yr in found:
        n = _month_to_num(mon)
        if n:
            try:
                dates.append(dt.date(int(yr), n, int(day)))
            except ValueError:
                pass
    if len(dates) >= 2:
        return min(dates).isoformat(), max(dates).isoformat()
    if len(dates) == 1:
        return None, dates[0].isoformat()
    return None, None


def rule_extract(text):
    # normalise whitespace so line breaks don't split key phrases
    t = re.sub(r"\s+", " ", text.lower())
    if "soc 3" in t or "soc3" in t:
        rtype = "SOC 3"
    elif "type 2" in t or "type ii" in t:
        rtype = "SOC 2 Type II"
    elif "type 1" in t or "type i" in t:
        rtype = "SOC 2 Type I"
    else:
        rtype = "Unknown"

    # categories explicitly marked out of scope should not count as covered
    excluded = set()
    for m in re.finditer(
            r"([\w ,]+?)\s+(?:categories?\s+)?(?:were|was|are|is)\s+not\s+in\s+scope", t):
        seg = m.group(1)
        for c in ["availability", "confidentiality", "processing integrity",
                  "privacy", "security"]:
            if c in seg:
                excluded.add(c)

    cats = []
    if ("security" in t or "common criteria" in t) and "security" not in excluded:
        cats.append("Security")
    for c in ["Availability", "Confidentiality", "Processing Integrity", "Privacy"]:
        if c.lower() in t and c.lower() not in excluded:
            cats.append(c)

    if "unqualified" in t or "in all material respects" in t:
        opinion = "Unqualified"
    elif "adverse" in t:
        opinion = "Adverse"
    elif "disclaimer" in t:
        opinion = "Disclaimer"
    elif "qualified" in t:
        opinion = "Qualified"
    else:
        opinion = "Unknown"

    exc = ("exception" in t) or ("deviation" in t)
    cuec = "complementary user entity control" in t  # matches singular/plural
    if "carve-out" in t or "carve out" in t:
        sub = "Carve-out"
    elif "inclusive method" in t:
        sub = "Inclusive"
    else:
        sub = "Unknown"

    ps, pe = _find_dates(text)
    return {
        "report_type": rtype, "period_start": ps, "period_end": pe,
        "tsc_categories": cats or ["Security"], "auditor_opinion": opinion,
        "exceptions_noted": exc, "exceptions_summary": None,
        "cuecs_present": cuec, "cuecs_summary": None,
        "subservice_method": sub, "_method": "rule-based",
    }


def ai_extract(text):
    """Call an HF-hosted model; raise on any failure so caller can fall back."""
    from huggingface_hub import InferenceClient
    client = InferenceClient(provider="hf-inference", api_key=HF_TOKEN)
    resp = client.chat.completions.create(
        model=MODEL,
        messages=[{"role": "user", "content": EXTRACT_PROMPT + text[:6000]}],
        max_tokens=600, temperature=0.1,
    )
    raw = resp.choices[0].message.content.strip()
    raw = re.sub(r"^```(json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
    start, end = raw.find("{"), raw.rfind("}")
    data = json.loads(raw[start:end + 1])
    data.setdefault("tsc_categories", ["Security"])
    data["_method"] = "AI (" + MODEL.split("/")[-1] + ")"
    return data


def extract(text):
    if HF_TOKEN:
        try:
            return ai_extract(text)
        except Exception as e:  # noqa: BLE001 - demo resilience
            res = rule_extract(text)
            res["_method"] = "rule-based (AI unavailable: %s)" % type(e).__name__
            return res
    return rule_extract(text)


def read_pdf(uploaded):
    from pypdf import PdfReader
    reader = PdfReader(uploaded)
    return "\n".join((p.extract_text() or "") for p in reader.pages)


# ----------------------------------------------------------------------
# GRC engines
# ----------------------------------------------------------------------
def compute_inherent(a):
    sens = max([DATA_SENS.get(d, 5) for d in a["data"]] or [5])
    acc = ACCESS_SCORE[a["access"]]
    crit = CRIT_SCORE[a["crit"]]
    inh = round(0.45 * sens + 0.35 * acc + 0.20 * crit)
    tier = 1 if inh >= 65 else 2 if inh >= 40 else 3
    return inh, tier


def scope_tsc(a):
    """Return the TSC categories that must be satisfied for this engagement."""
    cats = ["Security"]  # Common Criteria always in scope
    pii = any(d in a["data"] for d in
              ["Customer PII", "Employee PII", "Health / PHI"])
    if pii:
        cats.append("Privacy")
    if "Confidential / proprietary" in a["data"] or pii \
            or a["data"] not in ([], ["None"]):
        if "Confidentiality" not in cats:
            cats.append("Confidentiality")
    if a["crit"] == "Business-critical" or a["irq_uptime"]:
        cats.append("Availability")
    if a["irq_processing"]:
        cats.append("Processing Integrity")
    # keep canonical order
    return [c for c in ALL_CATEGORIES if c in cats]


def report_maturity(required, ext):
    """Translate report quality into a control-maturity proxy (0-100)."""
    rtype = ext["report_type"]
    if rtype in ("SOC 2 Type I", "SOC 3", "Unknown"):
        m = 35  # design-only or summary: weak validation
    else:
        m = 85  # Type II baseline
    op = ext["auditor_opinion"]
    if op == "Qualified":
        m -= 20
    elif op in ("Adverse", "Disclaimer"):
        m -= 45
    if ext["exceptions_noted"]:
        m -= 10
    # period currency (needs bridge letter if end > ~12 months ago)
    stale = False
    if ext.get("period_end"):
        try:
            end = dt.date.fromisoformat(ext["period_end"])
            if (TODAY - end).days > 365:
                stale, m = True, m - 15
        except ValueError:
            pass
    # coverage of required categories
    covered = set(ext.get("tsc_categories", []))
    missing = [c for c in required if c not in covered]
    m -= 12 * len(missing)
    if ext["cuecs_present"]:
        m -= 5
    return max(0, min(100, m)), missing, stale


def compute_residual(inherent, maturity):
    res = max(0, min(100, round(inherent * (1 - 0.70 * (maturity / 100)))))
    band = ("Low" if res <= 20 else "Medium" if res <= 40
            else "High" if res <= 65 else "Critical")
    return res, band


BAND_COLOR = {"Low": "#43B583", "Medium": "#E0B341",
              "High": "#E5824A", "Critical": "#E1515F"}
TIER_LABEL = {1: "Tier 1 (high)", 2: "Tier 2 (moderate)", 3: "Tier 3 (low)"}


# ----------------------------------------------------------------------
# UI helpers
# ----------------------------------------------------------------------
st.markdown("""
<style>
.block-container{max-width:820px}
.small{color:#8A97AD;font-size:0.86rem}
.pill{display:inline-block;padding:3px 10px;border-radius:999px;font-size:0.8rem;
  font-family:monospace;border:1px solid #24314A;margin:2px 4px 2px 0}
.crit-ok{color:#43B583;border-color:#255c45;background:#122a22}
.crit-gap{color:#E1515F;border-color:#5c2730;background:#2c1519}
hr{border-color:#24314A}
</style>
""", unsafe_allow_html=True)

if "step" not in st.session_state:
    st.session_state.step = 1
if "a" not in st.session_state:
    st.session_state.a = {}


def goto(n):
    st.session_state.step = n
    st.rerun()


# ----------------------------------------------------------------------
# Header
# ----------------------------------------------------------------------
st.title("🛡️ SOC 2 Trust Services Evaluator")
st.markdown(
    "<span class='small'>Scope the AICPA Trust Services Criteria for a vendor "
    "from an inherent-risk questionnaire, then validate their risk posture "
    "against a SOC 2 report. A working demo by <b>Manobalaji Ganapathi</b> "
    "&middot; GRC &amp; security automation.</span>",
    unsafe_allow_html=True)
st.markdown(
    "<span class='small'>⚠️ Demo on <b>synthetic data</b>. Use sample or "
    "non-confidential reports only. Not affiliated with the AICPA; not audit "
    "advice.</span>", unsafe_allow_html=True)
st.progress(st.session_state.step / 5.0,
            text="Step %d of 5" % st.session_state.step)
st.divider()

a = st.session_state.a

# ----------------------------------------------------------------------
# STEP 1 — Vendor & intake
# ----------------------------------------------------------------------
if st.session_state.step == 1:
    st.subheader("1 · Vendor & intake")
    a["vendor"] = st.text_input("Vendor name", a.get("vendor", ""),
                                placeholder="e.g. NimbusCRM Cloud")
    a["category"] = st.selectbox(
        "Service category",
        ["SaaS application", "Cloud infrastructure", "Payment processor",
         "Data analytics", "Marketing / CRM", "Managed IT service",
         "HR / payroll", "Open-source dependency"],
        index=["SaaS application", "Cloud infrastructure", "Payment processor",
               "Data analytics", "Marketing / CRM", "Managed IT service",
               "HR / payroll", "Open-source dependency"].index(
                   a.get("category", "SaaS application")))
    a["data"] = st.multiselect(
        "What data will we share with this vendor?",
        list(DATA_SENS.keys()), a.get("data", ["Customer PII"]))
    a["access"] = st.selectbox(
        "What access will the vendor have?", list(ACCESS_SCORE.keys()),
        index=list(ACCESS_SCORE.keys()).index(
            a.get("access", "Reads our production data")))
    a["crit"] = st.selectbox(
        "Business criticality", list(CRIT_SCORE.keys()),
        index=list(CRIT_SCORE.keys()).index(a.get("crit", "Moderate")))
    st.caption("Answers here drive which Trust Services Criteria apply.")
    if st.button("Next → Risk questionnaire", type="primary",
                 disabled=not a.get("vendor")):
        goto(2)

# ----------------------------------------------------------------------
# STEP 2 — IRQ
# ----------------------------------------------------------------------
elif st.session_state.step == 2:
    st.subheader("2 · Inherent Risk Questionnaire")
    st.caption("These refine the inherent tier and the TSC scope.")
    a["irq_store"] = st.checkbox(
        "The vendor will store or process our data",
        a.get("irq_store", True))
    a["irq_uptime"] = st.checkbox(
        "The vendor is part of a real-time or business-critical workflow "
        "(we depend on their uptime)", a.get("irq_uptime", False))
    a["irq_processing"] = st.checkbox(
        "The vendor performs transaction processing or calculations we rely "
        "on for accuracy", a.get("irq_processing", False))
    a["irq_crossborder"] = st.checkbox(
        "Data will be transferred across borders", a.get("irq_crossborder", False))
    a["irq_creds"] = st.checkbox(
        "The vendor integrates with authentication or holds credentials",
        a.get("irq_creds", False))
    c1, c2 = st.columns(2)
    if c1.button("← Back"):
        goto(1)
    if c2.button("Next → Scope criteria", type="primary"):
        goto(3)

# ----------------------------------------------------------------------
# STEP 3 — Auto-scoped TSC
# ----------------------------------------------------------------------
elif st.session_state.step == 3:
    st.subheader("3 · Applicable Trust Services Criteria")
    inh, tier = compute_inherent(a)
    required = scope_tsc(a)
    a["inherent"], a["tier"], a["required"] = inh, tier, required

    c1, c2 = st.columns(2)
    c1.metric("Inherent risk score", "%d / 100" % inh)
    c2.metric("Inherent tier", TIER_LABEL[tier])

    st.markdown("**Categories in scope for %s:**" % (a.get("vendor") or "vendor"))
    st.markdown(" ".join(
        "<span class='pill crit-ok'>%s</span>" % c for c in required),
        unsafe_allow_html=True)

    with st.expander("See the specific criteria that must be satisfied"):
        st.markdown("**Security — Common Criteria (always in scope)**")
        for k, v in COMMON_CRITERIA.items():
            st.markdown("- `%s` %s" % (k, v))
        for cat in required:
            if cat in CATEGORY_CRITERIA:
                st.markdown("**%s**" % cat)
                for k, v in CATEGORY_CRITERIA[cat].items():
                    st.markdown("- `%s` %s" % (k, v))

    st.info("Security is always required as the Common Criteria. Confidentiality, "
            "Privacy, Availability and Processing Integrity were added based on "
            "your intake and questionnaire answers.")
    c1, c2 = st.columns(2)
    if c1.button("← Back"):
        goto(2)
    if c2.button("Next → Add SOC 2 report", type="primary"):
        goto(4)

# ----------------------------------------------------------------------
# STEP 4 — Evidence
# ----------------------------------------------------------------------
elif st.session_state.step == 4:
    st.subheader("4 · Validate with a SOC 2 report")
    st.caption("Upload the vendor's SOC 2 / SOC 3 report, or load the sample.")
    if not HF_TOKEN:
        st.warning("No HF_TOKEN secret set — using the rule-based extractor. "
                   "Add an HF_TOKEN Space secret to enable AI extraction.")

    up = st.file_uploader("SOC 2 / SOC 3 report (PDF)", type=["pdf"])
    use_sample = st.button("↧ Load sample synthetic report instead")

    text = None
    if use_sample:
        text = SAMPLE_SOC2
        st.session_state.a["evidence_name"] = "Sample synthetic SOC 2 (NimbusCRM)"
    elif up is not None:
        try:
            text = read_pdf(up)
            st.session_state.a["evidence_name"] = up.name
        except Exception as e:  # noqa: BLE001
            st.error("Could not read that PDF: %s" % e)

    if text:
        with st.spinner("Extracting report attributes..."):
            a["extracted"] = extract(text)
        st.success("Extracted using: %s" % a["extracted"]["_method"])
        st.json({k: v for k, v in a["extracted"].items()
                 if not k.startswith("_")})
        if st.button("Next → Results", type="primary"):
            goto(5)

    if st.button("← Back"):
        goto(3)

# ----------------------------------------------------------------------
# STEP 5 — Results
# ----------------------------------------------------------------------
elif st.session_state.step == 5:
    st.subheader("5 · Risk posture — %s" % a.get("vendor", "vendor"))
    required = a["required"]
    ext = a["extracted"]
    maturity, missing, stale = report_maturity(required, ext)
    residual, band = compute_residual(a["inherent"], maturity)
    a["residual"], a["band"], a["maturity"] = residual, band, maturity

    c1, c2, c3 = st.columns(3)
    c1.metric("Inherent", "%d" % a["inherent"], TIER_LABEL[a["tier"]])
    c2.metric("Report quality", "%d / 100" % maturity, ext["report_type"])
    c3.metric("Residual risk", "%d · %s" % (residual, band))
    st.markdown(
        "<div style='height:8px;border-radius:5px;background:%s;"
        "width:%d%%'></div>" % (BAND_COLOR[band], residual),
        unsafe_allow_html=True)

    st.markdown("### Required categories vs. report coverage")
    covered = set(ext.get("tsc_categories", []))
    for cat in required:
        ok = cat in covered
        st.markdown(
            "<span class='pill %s'>%s %s</span>" %
            ("crit-ok" if ok else "crit-gap", "✓" if ok else "✗", cat),
            unsafe_allow_html=True)
    if missing:
        st.error("Coverage gap: the report does not cover %s, which your "
                 "engagement requires. Request an updated report with these "
                 "categories in scope, or add compensating evidence."
                 % ", ".join(missing))
    else:
        st.success("The report covers every required category.")

    st.markdown("### Findings")
    findings = []
    if ext["report_type"] != "SOC 2 Type II":
        findings.append("Report is **%s**, not SOC 2 Type II — operating "
                        "effectiveness over time is not evidenced." % ext["report_type"])
    if ext["auditor_opinion"] in ("Qualified", "Adverse", "Disclaimer"):
        findings.append("Auditor opinion is **%s** — investigate the basis."
                        % ext["auditor_opinion"])
    if ext["exceptions_noted"]:
        findings.append("**Exceptions were noted.** Review each and its "
                        "remediation status." + (
                            " " + ext["exceptions_summary"]
                            if ext.get("exceptions_summary") else ""))
    if stale:
        findings.append("Report period ended more than 12 months ago — "
                        "request a **bridge letter** to cover the gap to today.")
    if ext["cuecs_present"]:
        findings.append("**Complementary User Entity Controls** apply — these "
                        "are controls *you* must operate. Confirm you perform "
                        "them or the assurance does not hold.")
    if ext.get("subservice_method") == "Carve-out":
        findings.append("Subservice organisations are **carved out** — their "
                        "controls are excluded; assess the sub-processor "
                        "separately (nth-party risk).")
    if not findings:
        findings.append("No structural issues detected in the report metadata.")
    for f in findings:
        st.markdown("- " + f)

    st.markdown("### Recommendation")
    rec = {
        "Low": "Approve with standard onboarding and annual review.",
        "Medium": "Approve with conditions. Track the findings above and "
                  "reassess at renewal.",
        "High": "Conditional. Remediate coverage gaps and findings before "
                "onboarding; reassess within six months.",
        "Critical": "Do not onboard until critical gaps are resolved. Escalate "
                    "to the risk committee.",
    }[band]
    st.markdown("> " + rec)

    # ---- Downloadable report ----
    report = {
        "generated": TODAY.isoformat(),
        "vendor": a.get("vendor"),
        "service_category": a.get("category"),
        "intake": {"data_shared": a.get("data"), "access": a.get("access"),
                   "business_criticality": a.get("crit")},
        "inherent_score": a["inherent"], "inherent_tier": TIER_LABEL[a["tier"]],
        "required_tsc_categories": required,
        "evidence": a.get("evidence_name"),
        "report_extracted": {k: v for k, v in ext.items()
                             if not k.startswith("_")},
        "extraction_method": ext.get("_method"),
        "report_quality_score": maturity,
        "coverage_gaps": missing,
        "residual_score": residual, "residual_band": band,
        "findings": [re.sub(r"\*\*|`", "", f) for f in findings],
        "recommendation": rec,
        "disclaimer": "Demo on synthetic data. Not audit advice.",
    }
    md = ["# SOC 2 Trust Services Evaluation",
          "**Vendor:** %s  " % a.get("vendor"),
          "**Generated:** %s  " % TODAY.isoformat(),
          "**Inherent:** %d (%s)  " % (a["inherent"], TIER_LABEL[a["tier"]]),
          "**Report:** %s · quality %d/100 · %s  "
          % (ext["report_type"], maturity, ext["auditor_opinion"]),
          "**Residual:** %d (%s)  " % (residual, band),
          "**Required TSC:** %s  " % ", ".join(required),
          "**Coverage gaps:** %s  " % (", ".join(missing) or "none"),
          "", "## Findings"] + ["- " + re.sub(r"\*\*|`", "", f) for f in findings] \
        + ["", "## Recommendation", rec,
           "", "_Demo on synthetic data. Not audit advice._"]
    md = "\n".join(md)

    c1, c2 = st.columns(2)
    c1.download_button("⬇ Download JSON", json.dumps(report, indent=2),
                       file_name="soc2_eval_%s.json" %
                       (a.get("vendor") or "vendor").replace(" ", "_"),
                       mime="application/json")
    c2.download_button("⬇ Download report (Markdown)", md,
                       file_name="soc2_eval_%s.md" %
                       (a.get("vendor") or "vendor").replace(" ", "_"),
                       mime="text/markdown")

    st.divider()
    c1, c2 = st.columns(2)
    if c1.button("← Back"):
        goto(4)
    if c2.button("Start a new assessment"):
        st.session_state.a = {}
        goto(1)
