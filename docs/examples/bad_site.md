> **LEGAL DISCLAIMER**: LEGAL DISCLAIMER: This tool provides technical readiness indicators and gap analysis only. It does NOT constitute legal advice or certify legal compliance with Sri Lanka's Personal Data Protection Act, No. 9 of 2022 (PDPA). Organizations must verify all legal references against the official Act (dpa.gov.lk) and consult qualified legal counsel.

> **DEFENSIVE NOTICE**: Defensive use only. Use this tool only on websites, endpoints, or local projects that you own or have explicit written authorization to audit.

# Sri Lanka PDPA Technical Readiness Gap Analysis Report

## Executive Summary
- **Target**: URL=http://127.0.0.1:8992, Project=C:\Users\DELL\Desktop\pdpa-audit-mcp\tests\fixtures\sample_project\bad
- **Timestamp**: 2026-11-09T14:45:55.491778+00:00
- **Overall Readiness Score**: 0.0% (Not Ready | Coverage: 76.9% [weight: 76.9%] | 6 rules require human review)
- **Audit Execution Status**: OK *(Assessed: 20/26, Needs review: 6, Not applicable: 1, Not assessed: 0)*

### Category Breakdown
| Category | Score | Passed | Failed | Needs Review | Not Applicable | Not Evaluated |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Transparency / Privacy Notice | 0.0% | 0 | 5 | 0 | 0 | 0 |
| Data Subject Rights | 0.0% | 0 | 6 | 1 | 0 | 0 |
| Data Protection Officer | 0.0% | 0 | 1 | 0 | 0 | 0 |
| Consent | 0.0% | 0 | 2 | 1 | 0 | 0 |
| Security Safeguards | 0.0% | 0 | 4 | 0 | 1 | 0 |
| Cross-Border Transfers | 0.0% | 0 | 1 | 0 | 0 | 0 |
| Data Minimisation | 0.0% | 0 | 1 | 0 | 0 | 0 |
| Breach Readiness | Insufficient data | 0 | 0 | 3 | 0 | 0 |
| Children's Data | Insufficient data | 0 | 0 | 1 | 0 | 0 |

## High-Priority Gaps
### 1. Explicit Purpose of Processing Specified (`transparency_purpose`) [HIGH]
- **Category**: Transparency / Privacy Notice
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Explicit Purpose of Processing Specified
- **Remediation Recommendation**: State explicitly why each category of personal data is collected and ensure processing is limited to those stated purposes.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 2. Privacy Contact Information Published (`transparency_contact`) [HIGH]
- **Category**: Transparency / Privacy Notice
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Privacy Contact Information Published
- **Remediation Recommendation**: Provide a dedicated contact method (email, postal address, or support webform) for data privacy inquiries.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 3. Right to Access Personal Data (`rights_access`) [HIGH]
- **Category**: Data Subject Rights
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Right to Access Personal Data
- **Remediation Recommendation**: Explain how users can request a copy of the personal data held about them.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 4. Right to Rectification / Correction (`rights_correction`) [HIGH]
- **Category**: Data Subject Rights
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Right to Rectification / Correction
- **Remediation Recommendation**: Detail the procedure for individuals to submit correction or rectification requests.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 5. Right to Erasure / Deletion (`rights_erasure`) [HIGH]
- **Category**: Data Subject Rights
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Right to Erasure / Deletion
- **Remediation Recommendation**: Clarify the grounds and mechanism for requesting deletion/erasure of personal data.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 6. Right to Withdraw Consent (`rights_withdraw_consent`) [HIGH]
- **Category**: Data Subject Rights
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Right to Withdraw Consent
- **Remediation Recommendation**: State that consent may be withdrawn at any time and specify how to execute withdrawal.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 7. Special Categories / Sensitive Personal Data Justification (`minimisation_sensitive_fields`) [HIGH]
- **Category**: Data Minimisation
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Special Categories / Sensitive Personal Data Justification
- **Remediation Recommendation**: Assess whether collecting special category data (e.g. NIC, health, biometric) is strictly justified under applicable legal grounds.
- **Matched Terms**: nic
- **Evidence**: `Forms collect sensitive data fields: ['nic']` (sources: forms(url), forms(project))

### 8. HTTPS Encryption Enforced (`security_https_enforced`) [HIGH]
- **Category**: Security Safeguards
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: HTTPS Encryption Enforced
- **Remediation Recommendation**: Enforce HTTPS across all form action endpoints with TLS.
- **Evidence**: `Form submits over insecure HTTP endpoint: http://insecure.example.com/submit | local http server` (sources: forms(project), forms(url))

### 9. No Personal Data in Query Parameters (`security_no_pii_in_urls`) [HIGH]
- **Category**: Security Safeguards
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: No Personal Data in Query Parameters
- **Remediation Recommendation**: Use POST requests with encrypted request bodies for personal data submissions.
- **Matched Terms**: email, nic
- **Evidence**: `GET form transmits personal fields in query strings: ['email', 'nic'] | No GET forms submitting personal data detected.` (sources: forms(project), forms(url))

### 10. Consent Not Pre-Ticked (Opt-In by Default) (`consent_not_preticked`) [HIGH]
- **Category**: Consent
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: Consent Not Pre-Ticked (Opt-In by Default)
- **Remediation Recommendation**: Ensure consent checkboxes are unchecked by default for affirmative opt-in.
- **Matched Terms**: marketing_consent
- **Evidence**: `Pre-checked consent checkboxes detected: ['marketing_consent'] | Consent and marketing checkboxes are unchecked by...` (sources: forms(project), forms(url))

### 11. No Personal Data in Application Logs (`no_pii_in_logs`) [HIGH]
- **Category**: Security Safeguards
- **Status**: failed
- **Severity**: high
- **PDPA Section**: legal reference: to be verified
- **Description**: No Personal Data in Application Logs
- **Remediation Recommendation**: Refactor logging calls to remove personal data fields and log references only (file and line numbers).
- **Matched Terms**: email, nic, phone
- **Evidence**: `Logging calls referencing personal data detected at: app.js:6, app.js:6, app.js:7` (sources: project_scan)

## Medium-Priority Gaps
### 1. Categories of Personal Data Stated (`transparency_categories`) [MEDIUM]
- **Category**: Transparency / Privacy Notice
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Categories of Personal Data Stated
- **Remediation Recommendation**: Provide a clear breakdown of personal data types (e.g. name, contact details, payment information, IP addresses) collected from data subjects.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 2. Data Retention Period Disclosed (`transparency_retention`) [MEDIUM]
- **Category**: Transparency / Privacy Notice
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Data Retention Period Disclosed
- **Remediation Recommendation**: Define and publish concrete retention schedules or explicit criteria determining how long personal data is kept.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 3. Third-Party Data Sharing and Recipients Disclosed (`transparency_recipients`) [MEDIUM]
- **Category**: Transparency / Privacy Notice
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Third-Party Data Sharing and Recipients Disclosed
- **Remediation Recommendation**: List all categories of third-party processors, cloud service providers, and analytics partners receiving personal data.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 4. Right to Object to Processing (`rights_objection`) [MEDIUM]
- **Category**: Data Subject Rights
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Right to Object to Processing
- **Remediation Recommendation**: Provide users with a straightforward way to object to processing, especially for commercial marketing.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 5. Procedure for Exercising Data Subject Rights (`rights_request_procedure`) [MEDIUM]
- **Category**: Data Subject Rights
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Procedure for Exercising Data Subject Rights
- **Remediation Recommendation**: Include a designated email or self-service portal link for exercising data protection rights.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 6. DPO or Privacy Lead Details Published (`dpo_contact_published`) [MEDIUM]
- **Category**: Data Protection Officer
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: DPO or Privacy Lead Details Published
- **Remediation Recommendation**: Publish the contact details or designated inbox for the organization's Data Protection Officer or privacy coordinator.
- **Evidence**: `No indicators matching this requirement were detected in the policy text.` (sources: privacy_policy)

### 7. Withdrawal of Consent As Easy As Giving (`consent_easy_withdrawal`) [MEDIUM]
- **Category**: Consent
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Withdrawal of Consent As Easy As Giving
- **Remediation Recommendation**: Provide an equally prominent 'Reject All' or 'Decline' button on the cookie banner.
- **Evidence**: `Consent banner detected with accept option but missing an explicit reject option.` (sources: cookie_consent)

### 8. Cross-Border Transfers and International Processors Disclosed (`transfer_cross_border_disclosed`) [MEDIUM]
- **Category**: Cross-Border Transfers
- **Status**: failed
- **Severity**: medium
- **PDPA Section**: legal reference: to be verified
- **Description**: Cross-Border Transfers and International Processors Disclosed
- **Remediation Recommendation**: Update privacy policy to disclose third-party data processors, hosting providers, and whether personal data is processed outside Sri Lanka.
- **Matched Terms**: cdnjs.cloudflare.com, connect.facebook.net, fonts.googleapis.com, insecure-store.lk, www.google-analytics.com
- **Evidence**: `Page loads 5 external domains (cdnjs.cloudflare.com, connect.facebook.net, fonts.googleapis.com,...` (sources: transfers, project_scan)

## Low-Priority Gaps
### 1. Password Fields Permit Proper Password Manager Autocomplete (`security_password_autocomplete`) [LOW]
- **Category**: Security Safeguards
- **Status**: failed
- **Severity**: low
- **PDPA Section**: legal reference: to be verified
- **Description**: Password Fields Permit Proper Password Manager Autocomplete
- **Remediation Recommendation**: Set autocomplete='current-password' or 'new-password' on inputs.
- **Matched Terms**: password
- **Evidence**: `Password field missing standard autocomplete attribute or set to 'off'. | No password fields detected in audited forms.` (sources: forms(project), forms(url))

## Needs Manual Review
### 1. Consent Prior to Non-Essential Cookies and Trackers (`consent_before_tracking`) - Category: Consent
- **Status**: needs_review (Confidence: medium)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Cannot verify trackers are blocked before consent from static HTML. Verify client-side.
- **Matched Terms**: Meta (Facebook) Pixel, Google Analytics
- **Observation**: `Found consent banner (<div id='cookie-banner' class='cookie-popup'>) and trackers ['Meta (Facebook) Pixel', 'Google...`

### 2. Code-Level Data Erasure Mechanism (`erasure_mechanism_in_code`) - Category: Data Subject Rights
- **Status**: needs_review (Confidence: medium)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Implement explicit personal data erasure/purge procedures and automated retention policies to support data subject deletion rights.
- **Matched Terms**: SQL
- **Observation**: `Models with personal data identified (1), but no automated deletion or retention methods detected in codebase.`

### 3. Documented Incident and Personal Data Breach Response Plan (`breach_response_plan_documented`) - Category: Breach Readiness
- **Status**: needs_review (Confidence: low)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Establish an incident response procedure for personal data breaches. Note that policies may be maintained outside code repositories.
- **Observation**: `Incident response plan documentation not found in repository.`

### 4. Designated Breach Notification and Escalation Contact (`breach_notification_contact`) - Category: Breach Readiness
- **Status**: needs_review (Confidence: low)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Publish a designated security contact email or RFC 9116 security.txt file to streamline vulnerability and breach reporting.
- **Observation**: `Dedicated security contact or security.txt not found in repository.`

### 5. Defined Breach Escalation and Record-Keeping Timelines (`breach_internal_escalation`) - Category: Breach Readiness
- **Status**: needs_review (Confidence: low)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Define internal escalation timelines and establish a breach register documenting severity, root causes, and remediation measures.
- **Observation**: `Internal breach escalation timelines not found in repository.`

### 6. Age Verification or Notice for Processing Minors' Data (`children_age_gate_notice`) - Category: Children's Data
- **Status**: needs_review (Confidence: low)
- **PDPA Section**: legal reference: to be verified
- **Remediation Recommendation**: Assess whether the digital service processes minors' data; implement age gating and parental authorization where required.
- **Observation**: `Manual review required: cannot be audited purely statically.`

## Not Applicable
### 1. Secure, HttpOnly, and SameSite Flags on Cookies (`security_secure_cookie_flags`) - Category: Security Safeguards
- **Status**: not_applicable
- **Reason**: `No cookies set on initial page response.`

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