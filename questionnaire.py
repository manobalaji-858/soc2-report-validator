"""
Vendor control questionnaire, mapped to the AICPA Trust Services Criteria.

Each domain is shown when its `show_if` category is in scope, and can
compensate (self-attested) for a SOC 2 that doesn't cover its `covers`
category. Questions are (id, text, TSC reference, critical).
"""

ANSWERS = ["Yes", "Partial", "No", "N/A"]
SCORE = {"Yes": 1.0, "Partial": 0.5, "No": 0.0}
# Self-attested answers count for less than independently audited evidence.
SELF_ATTESTED_WEIGHT = 0.60
# A questionnaire domain at or above this score softens a SOC 2 coverage gap.
COMPENSATING_THRESHOLD = 75

DOMAINS = [
    {"key": "gov", "name": "Governance & Risk", "tsc": "CC1–CC3",
     "show_if": "Security", "covers": None, "questions": [
         ("gov1", "Documented information security policy, approved by "
                  "leadership and reviewed at least annually", "CC1.1 / CC5.3", False),
         ("gov2", "Formal risk assessment performed at least annually, with a "
                  "maintained risk register", "CC3.1 / CC3.2", False),
         ("gov3", "Security awareness training for all staff at hire and "
                  "annually", "CC1.4 / CC2.2", False),
         ("gov4", "Background checks for personnel with access to customer "
                  "data", "CC1.4", False),
         ("gov5", "Named security leader (CISO or equivalent) accountable for "
                  "the programme", "CC1.3", False),
     ]},
    {"key": "iam", "name": "Identity & Access", "tsc": "CC6.1–CC6.3",
     "show_if": "Security", "covers": None, "questions": [
         ("iam1", "MFA enforced for all workforce and administrative access",
          "CC6.1", True),
         ("iam2", "Single sign-on through a centralised identity provider",
          "CC6.1", False),
         ("iam3", "Least-privilege, role-based access with periodic access "
                  "reviews (at least quarterly for privileged roles)",
          "CC6.2 / CC6.3", False),
         ("iam4", "Privileged access is brokered, time-bound and logged",
          "CC6.1 / CC6.3", True),
         ("iam5", "Access revoked within 24 hours of termination", "CC6.2",
          False),
     ]},
    {"key": "dat", "name": "Data Protection", "tsc": "CC6.1 / CC6.7 / C1",
     "show_if": "Security", "covers": "Confidentiality", "questions": [
         ("dat1", "Customer data encrypted at rest (AES-256 or equivalent)",
          "CC6.1 / C1.1", True),
         ("dat2", "Data encrypted in transit with TLS 1.2 or higher", "CC6.7",
          True),
         ("dat3", "Encryption keys managed in a KMS / HSM with rotation",
          "CC6.1", False),
         ("dat4", "Data classification scheme drives handling rules", "C1.1",
          False),
         ("dat5", "Secure deletion of our data at contract end, with a "
                  "certificate of destruction", "C1.2", False),
         ("dat6", "Our data is logically segregated from other customers' "
                  "data", "CC6.1", False),
     ]},
    {"key": "ops", "name": "Security Operations", "tsc": "CC7.1–CC7.2",
     "show_if": "Security", "covers": None, "questions": [
         ("ops1", "Centralised logging with alerting (SIEM) and at least "
                  "12-month retention", "CC7.2", False),
         ("ops2", "Vulnerability scanning at least monthly, with remediation "
                  "SLAs", "CC7.1", False),
         ("ops3", "Independent penetration test within the last 12 months",
          "CC4.1 / CC7.1", True),
         ("ops4", "Critical patches applied within 14 days", "CC7.1", False),
         ("ops5", "Endpoint malware protection / EDR on servers and laptops",
          "CC6.8", False),
     ]},
    {"key": "chg", "name": "Change & Development", "tsc": "CC8.1",
     "show_if": "Security", "covers": None, "questions": [
         ("chg1", "Changes are peer-reviewed, tested and approved before "
                  "production", "CC8.1", False),
         ("chg2", "Separate development, test and production environments",
          "CC8.1", False),
         ("chg3", "Secure SDLC with code scanning (SAST / dependency scanning)",
          "CC8.1", False),
         ("chg4", "Production customer data is not used in non-production "
                  "environments", "CC8.1 / C1.1", False),
     ]},
    {"key": "inc", "name": "Incident Response", "tsc": "CC7.3–CC7.5",
     "show_if": "Security", "covers": None, "questions": [
         ("inc1", "Documented incident response plan with defined roles",
          "CC7.3", True),
         ("inc2", "Contractual breach notification to us within 72 hours",
          "CC7.4 / P6", True),
         ("inc3", "Incident response plan tested at least annually", "CC7.5",
          False),
         ("inc4", "No material security breach in the last 24 months", "CC7.4",
          False),
     ]},
    {"key": "tpr", "name": "Sub-processors & Fourth Parties", "tsc": "CC9.2",
     "show_if": "Security", "covers": None, "questions": [
         ("tpr1", "Maintains a current list of sub-processors and shares it "
                  "with customers", "CC9.2", False),
         ("tpr2", "Security requirements are flowed down to sub-processors "
                  "contractually", "CC9.2", False),
         ("tpr3", "Sub-processors are assessed before onboarding and at least "
                  "annually", "CC9.2", False),
         ("tpr4", "We are notified before new sub-processors are added",
          "CC9.2 / P6", False),
     ]},
    {"key": "bcp", "name": "Resilience & Availability", "tsc": "A1.1–A1.3",
     "show_if": "Availability", "covers": "Availability", "questions": [
         ("bcp1", "Business continuity and disaster recovery plans are "
                  "documented", "A1.2", False),
         ("bcp2", "DR tested within the last 12 months against defined "
                  "RTO / RPO", "A1.3", True),
         ("bcp3", "Backups are encrypted, stored off-site and restore-tested",
          "A1.2", False),
         ("bcp4", "Contractual uptime SLA (e.g. 99.9%) with service credits",
          "A1.1", False),
         ("bcp5", "Capacity monitoring and redundancy across availability "
                  "zones", "A1.1", False),
     ]},
    {"key": "prv", "name": "Privacy", "tsc": "P1–P8", "show_if": "Privacy",
     "covers": "Privacy", "questions": [
         ("prv1", "Data Processing Agreement (DPA) signed or offered",
          "P6 / CC9.2", True),
         ("prv2", "Personal data processed only on our documented "
                  "instructions", "P3 / P4", False),
         ("prv3", "Supports data subject rights (access, correction, "
                  "deletion) within statutory deadlines", "P5", False),
         ("prv4", "Defined retention schedule; personal data deleted when no "
                  "longer needed", "P4", False),
         ("prv5", "Lawful transfer mechanism for cross-border transfers "
                  "(SCCs, adequacy, DPDP-permitted country)", "P6", False),
         ("prv6", "Privacy impact assessments for new or changed processing",
          "P1 / P8", False),
     ]},
    {"key": "edd", "name": "Enhanced Due Diligence", "tsc": "CC9.1 / CC9.2",
     "show_if": "Security", "covers": None, "min_tier": 1, "questions": [
         ("edd1", "Accepts on-site or remote audits by us or our appointed "
                  "auditor", "CC9.2", False),
         ("edd2", "Documented exit plan: our data returned in a usable format "
                  "and deleted at termination", "CC9.2 / C1.2", True),
         ("edd3", "24x7 security monitoring (SOC) with defined escalation to "
                  "us", "CC7.2 / CC7.3", False),
         ("edd4", "Cyber insurance cover appropriate to the contract value",
          "CC9.1", False),
         ("edd5", "Financial stability evidenced (audited financials or "
                  "credit rating)", "CC9.2", False),
         ("edd6", "No key-person or single-site dependency for delivering the "
                  "service", "A1.2 / CC9.1", False),
         ("edd7", "Annual red-team or adversary-simulation exercise",
          "CC4.1", False),
         ("edd8", "Bridge letters provided to cover gaps between SOC 2 "
                  "periods", "CC4.1", False),
     ]},
    {"key": "pin", "name": "Processing Integrity", "tsc": "PI1.1–PI1.5",
     "show_if": "Processing Integrity", "covers": "Processing Integrity",
     "questions": [
         ("pin1", "Processing specifications and definitions are documented",
          "PI1.1", False),
         ("pin2", "Inputs are validated for completeness and accuracy",
          "PI1.2", True),
         ("pin3", "Automated reconciliation and error handling during "
                  "processing", "PI1.3", False),
         ("pin4", "Outputs are reviewed for accuracy and delivered on time",
          "PI1.4", False),
     ]},
]

# Illustrative answers for the synthetic NimbusCRM vendor ("Load sample").
SAMPLE_ANSWERS = {
    "gov1": "Yes", "gov2": "Yes", "gov3": "Yes", "gov4": "Partial",
    "gov5": "Yes",
    "iam1": "Yes", "iam2": "Yes", "iam3": "Partial", "iam4": "Yes",
    "iam5": "Partial",
    "dat1": "Yes", "dat2": "Yes", "dat3": "Yes", "dat4": "Partial",
    "dat5": "No", "dat6": "Yes",
    "ops1": "Yes", "ops2": "Yes", "ops3": "Yes", "ops4": "Partial",
    "ops5": "Yes",
    "chg1": "Yes", "chg2": "Yes", "chg3": "Partial", "chg4": "Yes",
    "inc1": "Yes", "inc2": "Partial", "inc3": "Yes", "inc4": "Yes",
    "tpr1": "Yes", "tpr2": "Partial", "tpr3": "No", "tpr4": "Yes",
    "bcp1": "Yes", "bcp2": "Yes", "bcp3": "Yes", "bcp4": "Yes", "bcp5": "Yes",
    "prv1": "Yes", "prv2": "Yes", "prv3": "Partial", "prv4": "Partial",
    "prv5": "No", "prv6": "No",
    "pin1": "Yes", "pin2": "Yes", "pin3": "Partial", "pin4": "Yes",
    "edd1": "Partial", "edd2": "Yes", "edd3": "Yes", "edd4": "Yes",
    "edd5": "Partial", "edd6": "Yes", "edd7": "No", "edd8": "Yes",
}

# Questionnaire depth by tier (proportionate due diligence):
#   Tier 3 — Lite: core questions only (every critical control + key basics)
#   Tier 2 — Standard: every question in the in-scope domains
#   Tier 1 — Full: Standard + Enhanced Due Diligence, and Resilience is asked
#            even when Availability isn't in scope (concentration / exit risk)
CORE = {"gov1", "gov3", "iam1", "iam4", "iam5", "dat1", "dat2", "dat5",
        "ops2", "ops3", "inc1", "inc2", "tpr1", "bcp1", "bcp2", "bcp3",
        "prv1", "prv3", "prv5", "pin2"}
TIER_DEPTH = {1: "Full + Enhanced Due Diligence", 2: "Standard", 3: "Lite"}


def domains_for(required, tier):
    """Domains (with questions filtered) to ask for this scope and tier."""
    out = []
    for d in DOMAINS:
        if d.get("min_tier") and tier > d["min_tier"]:
            continue
        in_scope = d["show_if"] in required or (tier == 1 and d["key"] == "bcp")
        if not in_scope:
            continue
        qs = d["questions"]
        if tier == 3:
            qs = [q for q in qs if q[0] in CORE]
        if qs:
            out.append(dict(d, questions=qs))
    return out


def domains_in_scope(required):
    return domains_for(required, 2)


def score(answers, domains):
    """Per-domain % and overall %, plus critical controls answered No.

    N/A is excluded; an unanswered question counts as No.
    """
    per, total_pts, total_n, critical = {}, 0.0, 0, []
    for d in domains:
        pts, n = 0.0, 0
        for qid, text, ref, crit in d["questions"]:
            ans = answers.get(qid)
            if ans == "N/A":
                continue
            n += 1
            pts += SCORE.get(ans, 0.0)
            if crit and ans in (None, "No"):
                critical.append((d["name"], text, ref, ans or "Unanswered"))
        per[d["key"]] = round(100 * pts / n) if n else None
        total_pts += pts
        total_n += n
    overall = round(100 * total_pts / total_n) if total_n else 0
    return per, overall, critical


def answered(answers, domains):
    qs = [q[0] for d in domains for q in d["questions"]]
    return sum(1 for q in qs if answers.get(q)), len(qs)
