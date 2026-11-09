> **LEGAL DISCLAIMER**: LEGAL DISCLAIMER: This tool provides technical readiness indicators and gap analysis only. It does NOT constitute legal advice or certify legal compliance with Sri Lanka's Personal Data Protection Act, No. 9 of 2022 (PDPA). Organizations must verify all legal references against the official Act (dpa.gov.lk) and consult qualified legal counsel.

> **DEFENSIVE NOTICE**: Defensive use only. Use this tool only on websites, endpoints, or local projects that you own or have explicit written authorization to audit.

# Sri Lanka PDPA Technical Readiness Gap Analysis Report

## Executive Summary
- **Target**: URL=http://127.0.0.1:8991, Project=C:\Users\DELL\Desktop\pdpa-audit-mcp\tests\fixtures\sample_project\good
- **Timestamp**: 2026-11-09T14:45:54.105354+00:00
- **Overall Readiness Score**: 100.0% (Mostly Ready | Coverage: 95.8% [weight: 95.0%] | 1 rules require human review)
- **Audit Execution Status**: OK *(Assessed: 23/24, Needs review: 1, Not applicable: 3, Not assessed: 0)*

### Category Breakdown
| Category | Score | Passed | Failed | Needs Review | Not Applicable | Not Evaluated |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Transparency / Privacy Notice | 100.0% | 5 | 0 | 0 | 0 | 0 |
| Data Subject Rights | 100.0% | 7 | 0 | 0 | 0 | 0 |
| Data Protection Officer | 100.0% | 1 | 0 | 0 | 0 | 0 |
| Consent | 100.0% | 2 | 0 | 0 | 1 | 0 |
| Security Safeguards | 100.0% | 4 | 0 | 0 | 1 | 0 |
| Cross-Border Transfers | Insufficient data | 0 | 0 | 0 | 1 | 0 |
| Data Minimisation | 100.0% | 1 | 0 | 0 | 0 | 0 |
| Breach Readiness | 100.0% | 3 | 0 | 0 | 0 | 0 |
| Children's Data | Insufficient data | 0 | 0 | 1 | 0 | 0 |

## High-Priority Gaps
No technical failures detected in this severity tier.

## Medium-Priority Gaps
No technical failures detected in this severity tier.

## Low-Priority Gaps
No technical failures detected in this severity tier.

## Needs Manual Review
### 1. Age Verification or Notice for Processing Minors' Data (`children_age_gate_notice`) - Category: Children's Data
- **Status**: needs_review (Confidence: low)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Assess whether the digital service processes minors' data; implement age gating and parental authorization where required.
- **Observation**: `Manual review required: cannot be audited purely statically.`

## Not Applicable
### 1. Consent Prior to Non-Essential Cookies and Trackers (`consent_before_tracking`) - Category: Consent
- **Status**: not_applicable
- **Reason**: `No pre-consent third-party tracking scripts detected in initial HTML.`

### 2. Secure, HttpOnly, and SameSite Flags on Cookies (`security_secure_cookie_flags`) - Category: Security Safeguards
- **Status**: not_applicable
- **Reason**: `No cookies set on initial page response.`

### 3. Cross-Border Transfers and International Processors Disclosed (`transfer_cross_border_disclosed`) - Category: Cross-Border Transfers
- **Status**: not_applicable
- **Reason**: `No external third-party domains detected in HTML markup. | No third-party analytics or tracking SDKs detected in...`

## Not Evaluated
All technical rules were evaluated.

## Out of Scope
The following aspects cannot be validated via automated static scanning:
- Client-side JavaScript rendering not visible in initial static HTML responses.
- Internal organizational data retention schedules and physical server purge routines.
- Formal appointment and legal qualifications of the Data Protection Officer.
- Third-party processing contracts, cloud vendor agreements, and adequacy documentation.
- Physical premises security, employee background checks, and organizational governance.

*Note: Rule weights and severities are heuristic technical indicators and do not reflect legal priority or liability under Sri Lanka PDPA No. 9 of 2022.*

> **LEGAL DISCLAIMER**: LEGAL DISCLAIMER: This tool provides technical readiness indicators and gap analysis only. It does NOT constitute legal advice or certify legal compliance with Sri Lanka's Personal Data Protection Act, No. 9 of 2022 (PDPA). Organizations must verify all legal references against the official Act (dpa.gov.lk) and consult qualified legal counsel.