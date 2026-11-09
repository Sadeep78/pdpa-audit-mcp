"""Table-driven synthetic regression suite verifying minimal PASS/FAIL samples for PDPA rules.

Covers:
1. Every text rule: minimal English, Sinhala, and Tamil PASS samples, plus FAIL samples.
2. Every detector rule: minimal PASS sample and FAIL sample.
3. 5 look-alike negative samples (accessibility, social sharing, cookie without rights, etc).
4. Regression coverage summary table printed at the conclusion of the test run.
"""

from __future__ import annotations

import sys
from pathlib import Path

import httpx
import pytest

from pdpa_audit_mcp.checklist import load_checklist, match_rule_indicators
from pdpa_audit_mcp.models import RuleFindingStatus
from pdpa_audit_mcp.tools.cookie_consent import detect_cookie_consent
from pdpa_audit_mcp.tools.forms import find_personal_data_forms

# ---------------------------------------------------------------------------
# 1. Text Rules Matrix: (rule_id, lang, pass_text, fail_text)
# ---------------------------------------------------------------------------
TEXT_RULE_SAMPLES: list[dict[str, str]] = [
    # 1. transparency_purpose
    {
        "rule_id": "transparency_purpose",
        "lang": "en",
        "pass": "This privacy policy explains our processing purposes for customer onboarding.",
        "fail": "Welcome to our customer portal homepage.",
    },
    {
        "rule_id": "transparency_purpose",
        "lang": "si",
        "pass": "අපගේ පෞද්ගලිකත්ව ප්‍රතිපත්තිය තුළ පෞද්ගලික දත්ත සැකසීමේ අරමුණ පැහැදිලි කර ඇත.",
        "fail": "අපගේ වෙබ් අඩවියට සාදරයෙන් පිළිගනිමු.",
    },
    {
        "rule_id": "transparency_purpose",
        "lang": "ta",
        "pass": "இந்த தனியுரிமை கொள்கை தனிப்பட்ட தரவு செயலாக்கத்தின் நோக்கம் பற்றிய விபரங்களை வழங்குகிறது.",
        "fail": "எங்கள் இணையதளத்திற்கு வருக.",
    },
    # 2. transparency_categories
    {
        "rule_id": "transparency_categories",
        "lang": "en",
        "pass": "Our privacy policy details the categories of personal data collected from users.",
        "fail": "Our products are available in multiple convenient sizes.",
    },
    {
        "rule_id": "transparency_categories",
        "lang": "si",
        "pass": "මෙම පෞද්ගලිකත්ව ප්‍රතිපත්තිය මඟින් එකතු කරන දත්ත කාණ්ඩ විස්තර කෙරේ.",
        "fail": "අපගේ නිෂ්පාදන ගැන දැනගන්න.",
    },
    {
        "rule_id": "transparency_categories",
        "lang": "ta",
        "pass": "இந்த தனியுரிமை கொள்கை சேகரிக்கப்படும் தரவு வகைகள் பற்றி குறிப்பிடுகிறது.",
        "fail": "எங்கள் தயாரிப்புகள் பல வகைகளில் கிடைக்கின்றன.",
    },
    # 3. transparency_retention
    {
        "rule_id": "transparency_retention",
        "lang": "en",
        "pass": "Under our privacy policy, personal data is retained for only twelve months.",
        "fail": "We offer fast and reliable delivery services across the island.",
    },
    {
        "rule_id": "transparency_retention",
        "lang": "si",
        "pass": "පෞද්ගලික දත්ත රඳවා තබා ගැනීමේ කාලසීමාව මාස 12 ක් වේ.",
        "fail": "දිවයින පුරා බෙදාහැරීම් සිදු කෙරේ.",
    },
    {
        "rule_id": "transparency_retention",
        "lang": "ta",
        "pass": "தனியுரிமை கொள்கை படி தனிப்பட்ட தரவு தக்கவைப்பு காலம் 12 மாதங்கள் ஆகும்.",
        "fail": "தீவு முழுவதும் விநியோக சேவை வழங்கப்படுகிறது.",
    },
    # 4. transparency_recipients
    {
        "rule_id": "transparency_recipients",
        "lang": "en",
        "pass": "In our privacy policy, personal data is shared with third parties under contract.",
        "fail": "Our software engineers collaborate using open-source tools.",
    },
    {
        "rule_id": "transparency_recipients",
        "lang": "si",
        "pass": "පෞද්ගලික දත්ත හුවමාරුව තෙවන පාර්ශව වෙත සිදු කරනු ලබයි.",
        "fail": "අපගේ කණ්ඩායම නිරන්තරයෙන් සහය දක්වයි.",
    },
    {
        "rule_id": "transparency_recipients",
        "lang": "ta",
        "pass": "தனிப்பட்ட தரவு மூன்றாம் தரப்பு நிறுவனங்களுடன் பகிர்ந்து கொள்ளப்படுகிறது.",
        "fail": "எங்கள் குழு வாடிக்கையாளர் சேவையை வழங்குகிறது.",
    },
    # 5. transparency_contact
    {
        "rule_id": "transparency_contact",
        "lang": "en",
        "pass": "For privacy policy questions, contact us at privacy@example.com.",
        "fail": "For sales inquiries and quotes, phone our showroom.",
    },
    {
        "rule_id": "transparency_contact",
        "lang": "si",
        "pass": "පෞද්ගලික දත්ත සම්බන්ධ විමසීම් සඳහා අප හා සම්බන්ධ වන්න.",
        "fail": "අලෙවි අංශය අමතන්න.",
    },
    {
        "rule_id": "transparency_contact",
        "lang": "ta",
        "pass": "தரவு பாதுகாப்பு தொடர்பான விபரங்களுக்கு தொடர்பு கொள்ள: privacy@example.com.",
        "fail": "விற்பனை பிரிவை அழைக்கவும்.",
    },
    # 6. rights_access
    {
        "rule_id": "rights_access",
        "lang": "en",
        "pass": "Exercising your privacy rights, you have the right to access your personal data.",
        "fail": "Access your cloud account settings from the user navigation menu.",
    },
    {
        "rule_id": "rights_access",
        "lang": "si",
        "pass": "ඔබගේ පුද්ගල අයිතිවාසිකම් යටතේ දත්ත ලබා ගැනීමේ අයිතිය ඔබට ඇත.",
        "fail": "ගිණුමට ඇතුල් වන්න.",
    },
    {
        "rule_id": "rights_access",
        "lang": "ta",
        "pass": "உங்கள் தனியுரிமை உரிமைகள் படி தரவை அணுகும் உரிமை உங்களுக்கு உண்டு.",
        "fail": "உங்கள் கணக்கில் உள்நுழையவும்.",
    },
    # 7. rights_correction
    {
        "rule_id": "rights_correction",
        "lang": "en",
        "pass": "Under privacy rights, you have the right to rectification of records.",
        "fail": "Spell-check and text correction tools are built into our document editor.",
    },
    {
        "rule_id": "rights_correction",
        "lang": "si",
        "pass": "ඔබගේ අයිතිවාසිකම් යටතේ දත්ත නිවැරදි කිරීමේ අයිතිය හිමිවේ.",
        "fail": "ලිපිගොනු පරීක්ෂා කරන්න.",
    },
    {
        "rule_id": "rights_correction",
        "lang": "ta",
        "pass": "உங்கள் உரிமைகள் படி பிழையான தரவை திருத்தம் செய்யும் உரிமை உங்களுக்கு உண்டு.",
        "fail": "ஆவணங்களை சரிபார்க்கவும்.",
    },
    # 8. rights_erasure
    {
        "rule_id": "rights_erasure",
        "lang": "en",
        "pass": "Your data subject rights include the right to erasure of your personal records.",
        "fail": "Clear your browser cache to free up disk storage space.",
    },
    {
        "rule_id": "rights_erasure",
        "lang": "si",
        "pass": "අයිතිවාසිකම් යටතේ දත්ත මකා දැමීමේ අයිතිය ඔබට ඇත.",
        "fail": "පරිගණක මතකය හිස් කරන්න.",
    },
    {
        "rule_id": "rights_erasure",
        "lang": "ta",
        "pass": "உங்கள் உரிமைகள் படி தனிப்பட்ட தரவை நீக்கும் உரிமை வழங்கப்படுகிறது.",
        "fail": "நினைவகத்தை அழிக்கவும்.",
    },
    # 9. rights_withdraw_consent
    {
        "rule_id": "rights_withdraw_consent",
        "lang": "en",
        "pass": "Where processing relies on consent, you may withdraw consent at any time.",
        "fail": "Withdraw funds from your checking account at any affiliated ATM branch.",
    },
    {
        "rule_id": "rights_withdraw_consent",
        "lang": "si",
        "pass": "ඔබ ලබාදුන් කැමැත්ත ඉල්ලා අස්කර ගැනීම සඳහා ඕනෑම වේලාවක හැකියාව ඇත.",
        "fail": "මුදල් ආපසු ගැනීම සඳහා බැංකුවට පැමිණෙන්න.",
    },
    {
        "rule_id": "rights_withdraw_consent",
        "lang": "ta",
        "pass": "ஒப்புதல் படி, ஒப்புதலைத் திரும்பப் பெறுதல் உரிமையை எப்போது வேண்டுமானாலும் பயன்படுத்தலாம்.",
        "fail": "பணத்தை திரும்பப் பெற கிளைக்குச் செல்லவும்.",
    },
    # 10. rights_objection
    {
        "rule_id": "rights_objection",
        "lang": "en",
        "pass": "Under your privacy rights, you have the right to object to direct marketing.",
        "fail": "If you have an objection to building plans, attend the town planning meeting.",
    },
    {
        "rule_id": "rights_objection",
        "lang": "si",
        "pass": "පුද්ගල අයිතිවාසිකම් යටතේ දත්ත සැකසීමට විරෝධය පෑමේ අයිතිය ඔබට ඇත.",
        "fail": "නගර සභා රැස්වීමට සහභාගී වන්න.",
    },
    {
        "rule_id": "rights_objection",
        "lang": "ta",
        "pass": "உங்கள் உரிமைகள் படி நேரடி சந்தைப்படுத்தல் எதிர்ப்பு தெரிவிக்க உரிமை உண்டு.",
        "fail": "பொதுக் கூட்டத்தில் கலந்து கொள்ளவும்.",
    },
    # 11. rights_request_procedure
    {
        "rule_id": "rights_request_procedure",
        "lang": "en",
        "pass": "To exercise your privacy rights, submit a rights request via our online form.",
        "fail": "Submit a technical support request ticket if your connection drops.",
    },
    {
        "rule_id": "rights_request_procedure",
        "lang": "si",
        "pass": "ඔබගේ අයිතිවාසිකම් ක්‍රියාත්මක කිරීම සඳහා ඉල්ලීමක් ඉදිරිපත් කිරීම සිදු කරන්න.",
        "fail": "කාර්මික ගැටලු සඳහා උපකාර ලබාගන්න.",
    },
    {
        "rule_id": "rights_request_procedure",
        "lang": "ta",
        "pass": "உங்கள் உரிமைகளை செயல்படுத்த கோரிக்கையைச் சமர்ப்பிக்க இந்த படிவத்தை பயன்படுத்தவும்.",
        "fail": "தொழில்நுட்ப உதவி கோரிக்கையை அனுப்பவும்.",
    },
    # 12. consent_easy_withdrawal
    {
        "rule_id": "consent_easy_withdrawal",
        "lang": "en",
        "pass": "Review our cookie policy and manage preferences in cookie settings.",
        "fail": "Order fresh baked cookies with multiple sweet toppings from our bakery.",
    },
    {
        "rule_id": "consent_easy_withdrawal",
        "lang": "si",
        "pass": "කුකීස් භාවිතය පිළිබඳ මනාප කළමනාකරණය සඳහා මෙතනින් පිවිසෙන්න.",
        "fail": "රසවත් බිස්කට් වර්ග ඇණවුම් කරන්න.",
    },
    {
        "rule_id": "consent_easy_withdrawal",
        "lang": "ta",
        "pass": "குக்கீ ஒப்புதல் விருப்பங்களை நிர்வகி அல்லது குக்கீ அமைப்புகள் மாற்றவும்.",
        "fail": "சுவையான இனிப்புகளை வாங்கவும்.",
    },
    # 13. dpo_contact_published
    {
        "rule_id": "dpo_contact_published",
        "lang": "en",
        "pass": "Our data protection officer can be reached at dpo@example.com.",
        "fail": "Our Chief Executive Officer gave an inspirational keynote presentation today.",
    },
    {
        "rule_id": "dpo_contact_published",
        "lang": "si",
        "pass": "දත්ත ආරක්ෂණ නිලධාරී සම්බන්ධ කර ගැනීමට dpo@example.com වෙත පණිවිඩයක් එවන්න.",
        "fail": "ප්‍රධාන විධායක නිලධාරියා අමතන්න.",
    },
    {
        "rule_id": "dpo_contact_published",
        "lang": "ta",
        "pass": "எங்கள் தரவு பாதுகாப்பு அதிகாரி தொடர்பு விபரம்: dpo@example.com.",
        "fail": "நிறுவன தலைமை நிர்வாகியை சந்திக்கவும்.",
    },
    # 14. breach_response_plan_documented
    {
        "rule_id": "breach_response_plan_documented",
        "lang": "en",
        "pass": (
            "Our data breach response policy and incident response plan "
            "establish containment roles."
        ),
        "fail": "The ship suffered a hull breach during the heavy storm at sea.",
    },
    {
        "rule_id": "breach_response_plan_documented",
        "lang": "si",
        "pass": "දත්ත කඩවීම සම්බන්ධ සිද්ධි කළමනාකරණ සැලැස්ම මෙහි විස්තර කර ඇත.",
        "fail": "නැව කුණාටුවට හසුවිය.",
    },
    {
        "rule_id": "breach_response_plan_documented",
        "lang": "ta",
        "pass": "தரவு மீறல் சம்பவ மேலாண்மை திட்டம் அவசர நடவடிக்கைகளை விவரிக்கிறது.",
        "fail": "கப்பல் புயலில் சிக்கியது.",
    },
    # 15. breach_notification_contact
    {
        "rule_id": "breach_notification_contact",
        "lang": "en",
        "pass": "To report a data breach, reach our designated security contact.",
        "fail": "Report broken links or typos to our webmaster editorial team.",
    },
    {
        "rule_id": "breach_notification_contact",
        "lang": "si",
        "pass": "ආරක්ෂක සිද්ධි පිළිබඳව දැනුම් දීමට ආරක්ෂක සම්බන්ධීකාරක අමතන්න.",
        "fail": "අක්ෂර වින්‍යාස දෝෂ සංස්කාරක වෙත දන්වන්න.",
    },
    {
        "rule_id": "breach_notification_contact",
        "lang": "ta",
        "pass": "பாதுகாப்பு சம்பவம் குறித்து உடனடியாக பாதுகாப்பு தொடர்பு குழுவை அணுகவும்.",
        "fail": "பிழைகளை ஆசிரியருக்கு தெரிவிக்கவும்.",
    },
    # 16. breach_internal_escalation
    {
        "rule_id": "breach_internal_escalation",
        "lang": "en",
        "pass": "All data breach events are recorded in our internal incident register.",
        "fail": "Escalate your customer billing inquiry to the finance accounts department.",
    },
    {
        "rule_id": "breach_internal_escalation",
        "lang": "si",
        "pass": "දත්ත කඩවීම පිළිබඳ විස්තර වාර්තා තබා ගැනීම මෙම ලේඛනයේ සිදු වේ.",
        "fail": "බිල්පත් විමසීම් ගිණුම් අංශයට යොමු කරන්න.",
    },
    {
        "rule_id": "breach_internal_escalation",
        "lang": "ta",
        "pass": "தரவு மீறல் சம்பவங்கள் மீறல் பதிவேடு மூலம் முறையாக பதிவு செய்யப்படும்.",
        "fail": "கட்டண விசாரணைகளை நிதிப் பிரிவுக்கு அனுப்பவும்.",
    },
    # 17. transfer_cross_border_disclosed
    {
        "rule_id": "transfer_cross_border_disclosed",
        "lang": "en",
        "pass": "Personal data may be transferred outside Sri Lanka for cloud hosting.",
        "fail": "Transfer money to overseas bank accounts using fast telegraphic wire.",
    },
    {
        "rule_id": "transfer_cross_border_disclosed",
        "lang": "si",
        "pass": "පෞද්ගලික දත්ත ශ්‍රී ලංකාවෙන් පිටත සේවාදායකයන් වෙත පැවරීම සිදු විය හැක.",
        "fail": "විදේශගත මුදල් හුවමාරු සේවා.",
    },
    {
        "rule_id": "transfer_cross_border_disclosed",
        "lang": "ta",
        "pass": "தனிப்பட்ட தரவு இலங்கைக்கு வெளியே உள்ள கிளவுட் சேவையகங்களுக்கு மாற்றப்படலாம்.",
        "fail": "வெளிநாட்டு பணப் பரிமாற்றம் செய்ய வங்கியை அணுகவும்.",
    },
    # 18. children_age_gate_notice
    {
        "rule_id": "children_age_gate_notice",
        "lang": "en",
        "pass": "Processing of children's personal data requires parental consent.",
        "fail": "Our amusement park features fun rides for children of all age groups.",
    },
    {
        "rule_id": "children_age_gate_notice",
        "lang": "si",
        "pass": "ළමුන්ගේ දත්ත සැකසීම සඳහා දෙමාපිය කැමැත්ත අනිවාර්ය වේ.",
        "fail": "ළමා උද්‍යානය විවෘතයි.",
    },
    {
        "rule_id": "children_age_gate_notice",
        "lang": "ta",
        "pass": "குழந்தைகளின் தரவு சேகரிப்புக்கு பெற்றோர் ஒப்புதல் கட்டாயமாக பெறப்பட வேண்டும்.",
        "fail": "சிறுவர் பூங்கா திறக்கப்பட்டுள்ளது.",
    },
]


# ---------------------------------------------------------------------------
# 2. Look-Alike Negative Samples (Must NOT match any rules as false positives)
# ---------------------------------------------------------------------------
LOOKALIKE_NEGATIVE_SAMPLES: list[dict[str, str]] = [
    {
        "name": "accessibility_statement",
        "text": (
            "Accessibility Statement: We are committed to making our website accessible "
            "to people with disabilities. We conform to WCAG 2.1 AA standards across visual, "
            "auditory, and cognitive dimensions and welcome feedback."
        ),
    },
    {
        "name": "social_sharing_page",
        "text": (
            "Share our exciting articles with your friends! Click our social sharing buttons "
            "to post directly to Facebook, Twitter, LinkedIn, and WhatsApp without delay."
        ),
    },
    {
        "name": "cookie_policy_without_rights",
        "text": (
            "We use cookies to enhance your browsing experience and deliver customized content. "
            "By continuing to browse our website, you agree to our standard cookie usage."
        ),
    },
    {
        "name": "sinhala_data_storage_only",
        "text": (
            "අපගේ තාක්ෂණික පද්ධතිය වේගවත් දත්ත ගබඩා කිරීමක් සහ නවීන මෘදුකාංග විසඳුම් භාවිතා කරයි. "
            "පරිශීලක අත්දැකීම ඉහළ නැංවීමට නවතම තාක්ෂණය උපකාරී වේ."
        ),
    },
    {
        "name": "tamil_terms_conditions_only",
        "text": (
            "எங்கள் சேவையின் பொதுவான விதிமுறைகள் மற்றும் நிபந்தனைகள் இங்கே விவரிக்கப்பட்டுள்ளன. "
            "பயனர்கள் அனைவரும் இந்த பொதுவான வணிக விதிகளைப் பின்பற்ற வேண்டும்."
        ),
    },
]


class TestRuleMatrixPrecisionAndRecall:
    """Table-driven precision and recall matrix test suite."""

    def test_text_rules_pass_and_fail_samples(self):
        """Verify each text rule matches its pass sample and rejects its fail sample in EN/SI/TA."""
        all_rules_map = {r.id: r for r in load_checklist()}

        tp = 0
        fp = 0
        tn = 0
        fn = 0

        for row in TEXT_RULE_SAMPLES:
            rule_id = row["rule_id"]
            lang = row["lang"]
            rule = all_rules_map.get(rule_id)
            assert rule is not None, f"Rule '{rule_id}' not found in checklist."

            # Positive test
            matched_pos, snippet_pos, *_ = match_rule_indicators(rule, row["pass"])
            if matched_pos:
                tp += 1
            else:
                fn += 1
                pytest.fail(f"False negative for {rule_id} ({lang}): sample did not match.")

            # Negative test (look-alike fail sample)
            matched_neg, snippet_neg, *_ = match_rule_indicators(rule, row["fail"])
            if not matched_neg:
                tn += 1
            else:
                fp += 1
                pytest.fail(
                    f"False positive for {rule_id} ({lang}): "
                    f"fail sample matched unexpectedly: {snippet_neg}"
                )

        # Test against 5 look-alike negative samples
        for lookalike in LOOKALIKE_NEGATIVE_SAMPLES:
            sample_name = lookalike["name"]
            sample_text = lookalike["text"]

            for rule_id in {row["rule_id"] for row in TEXT_RULE_SAMPLES}:
                rule = all_rules_map[rule_id]
                matched, snippet, *_ = match_rule_indicators(rule, sample_text)
                if not matched:
                    tn += 1
                else:
                    fp += 1
                    pytest.fail(
                        f"Look-alike sample '{sample_name}' falsely matched "
                        f"rule '{rule_id}': snippet='{snippet}'"
                    )

        # Calculate precision and recall
        precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0

        # Output table summary to stderr so pytest -s / logs capture it
        summary_text = (
            "\n" + "=" * 70 + "\n"
            "PDPA TECHNICAL AUDIT SYNTHETIC REGRESSION MATRIX: SAMPLE SUMMARY\n"
            "=" * 70 + "\n"
            f"True Positives  (TP) : {tp}\n"
            f"False Positives (FP) : {fp}\n"
            f"True Negatives  (TN) : {tn}\n"
            f"False Negatives (FN) : {fn}\n"
            f"Synthetic Match Rate : {precision:.2f}%\n"
            f"Total Evaluated      : {tp + fp + tn + fn} assertions\n"
            "=" * 70 + "\n"
        )
        sys.stderr.write(summary_text)

        assert tp == len(TEXT_RULE_SAMPLES), (
            f"Expected {len(TEXT_RULE_SAMPLES)} true positives, got {tp}"
        )
        assert fp == 0, f"Expected 0 false positives, got {fp}"
        assert fn == 0, f"Expected 0 false negatives, got {fn}"
        assert precision == 100.0
        assert recall == 100.0

    @pytest.mark.asyncio
    async def test_detector_rules_pass_and_fail_samples(self, tmp_path: Path, monkeypatch):
        """Verify structural detector rules with minimal PASS and FAIL synthetic samples."""
        monkeypatch.setenv("PDPA_AUDIT_ALLOWED_ROOTS", str(tmp_path))
        from pdpa_audit_mcp.tools.project_scan import scan_project_files

        # 1. security_https_enforced
        # Pass: form submits to https://
        pass_html = (
            "<html><body><form method='POST' action='https://api.example.com/login'>"
            "<input name='u'></form></body></html>"
        )
        fail_html = (
            "<html><body><form method='POST' action='http://insecure.example.com/login'>"
            "<input name='u'></form></body></html>"
        )

        client_pass = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=pass_html))
        )
        client_fail = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=fail_html))
        )

        res_pass = await find_personal_data_forms("https://example.com/form", client=client_pass)
        findings_pass = {f.rule_id: f for f in res_pass.findings}
        assert findings_pass["security_https_enforced"].status == RuleFindingStatus.PASSED

        res_fail = await find_personal_data_forms("https://example.com/form", client=client_fail)
        findings_fail = {f.rule_id: f for f in res_fail.findings}
        assert findings_fail["security_https_enforced"].status == RuleFindingStatus.FAILED

        # 2. security_no_pii_in_urls
        # Pass: POST form with email
        # Fail: GET form with email
        fail_get_html = (
            "<html><body><form method='GET' action='https://example.com/search'>"
            "<input name='email'></form></body></html>"
        )
        client_get = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=fail_get_html))
        )
        res_get = await find_personal_data_forms("https://example.com/search", client=client_get)
        findings_get = {f.rule_id: f for f in res_get.findings}
        assert findings_get["security_no_pii_in_urls"].status == RuleFindingStatus.FAILED

        # 3. security_password_autocomplete
        # Pass: password input with autocomplete='new-password'
        # Fail: password input with autocomplete='off'
        pass_pwd_html = (
            "<html><body><form method='POST' action='https://example.com/login'>"
            "<input type='password' name='p' autocomplete='current-password'>"
            "</form></body></html>"
        )
        fail_pwd_html = (
            "<html><body><form method='POST' action='https://example.com/login'>"
            "<input type='password' name='p' autocomplete='off'>"
            "</form></body></html>"
        )
        c_pwd_p = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=pass_pwd_html))
        )
        c_pwd_f = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=fail_pwd_html))
        )

        r_pwd_p = await find_personal_data_forms("https://example.com", client=c_pwd_p)
        r_pwd_f = await find_personal_data_forms("https://example.com", client=c_pwd_f)
        assert {f.rule_id: f for f in r_pwd_p.findings}[
            "security_password_autocomplete"
        ].status == RuleFindingStatus.PASSED
        assert {f.rule_id: f for f in r_pwd_f.findings}[
            "security_password_autocomplete"
        ].status == RuleFindingStatus.FAILED

        # 4. consent_not_preticked
        # Pass: unchecked consent checkbox
        # Fail: pre-ticked checkbox with 'checked' attribute
        pass_chk_html = (
            "<html><body><form method='POST' action='https://example.com'>"
            "<input type='checkbox' name='agree_consent'></form></body></html>"
        )
        fail_chk_html = (
            "<html><body><form method='POST' action='https://example.com'>"
            "<input type='checkbox' name='agree_consent' checked></form></body></html>"
        )
        c_chk_p = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=pass_chk_html))
        )
        c_chk_f = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=fail_chk_html))
        )

        r_chk_p = await find_personal_data_forms("https://example.com", client=c_chk_p)
        r_chk_f = await find_personal_data_forms("https://example.com", client=c_chk_f)
        assert {f.rule_id: f for f in r_chk_p.findings}[
            "consent_not_preticked"
        ].status == RuleFindingStatus.PASSED
        assert {f.rule_id: f for f in r_chk_f.findings}[
            "consent_not_preticked"
        ].status == RuleFindingStatus.FAILED

        # 5. minimisation_sensitive_fields
        # Pass: form without sensitive fields
        # Fail: form with NIC field
        fail_sens_html = (
            "<html><body><form method='POST' action='https://example.com'>"
            "<input name='nic_number'></form></body></html>"
        )
        c_sens_f = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=fail_sens_html))
        )
        r_sens_f = await find_personal_data_forms("https://example.com", client=c_sens_f)
        assert {f.rule_id: f for f in r_sens_f.findings}[
            "minimisation_sensitive_fields"
        ].status == RuleFindingStatus.FAILED

        # 6. security_secure_cookie_flags
        # Pass: Set-Cookie with Secure, HttpOnly, SameSite
        # Fail/Review: Set-Cookie missing HttpOnly and Secure
        c_cookie_p = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200,
                    headers={"set-cookie": "sess=123; Secure; HttpOnly; SameSite=Strict"},
                    text="<html><body></body></html>",
                )
            )
        )
        c_cookie_f = httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda req: httpx.Response(
                    200, headers={"set-cookie": "sess=123"}, text="<html><body></body></html>"
                )
            )
        )
        r_cookie_p = await detect_cookie_consent("https://example.com", client=c_cookie_p)
        r_cookie_f = await detect_cookie_consent("https://example.com", client=c_cookie_f)
        assert {f.rule_id: f for f in r_cookie_p.findings}[
            "security_secure_cookie_flags"
        ].status == RuleFindingStatus.PASSED
        assert {f.rule_id: f for f in r_cookie_f.findings}[
            "security_secure_cookie_flags"
        ].status == RuleFindingStatus.NEEDS_REVIEW

        # 7. consent_before_tracking
        # Fail: Third-party analytics script loaded without cookie banner
        fail_trk_html = (
            "<html><body>"
            "<script src='https://www.google-analytics.com/analytics.js'></script>"
            "</body></html>"
        )
        c_trk_f = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, text=fail_trk_html))
        )
        r_trk_f = await detect_cookie_consent("https://example.com", client=c_trk_f)
        assert {f.rule_id: f for f in r_trk_f.findings}[
            "consent_before_tracking"
        ].status == RuleFindingStatus.FAILED

        # 8. erasure_mechanism_in_code
        proj_pass = tmp_path / "detector_proj_pass"
        proj_pass.mkdir()
        (proj_pass / "models.py").write_text(
            "class Account(models.Model):\n"
            "    email = Column(String)\n"
            "    def purge_user_records(self):\n"
            "        self.delete()\n",
            encoding="utf-8",
        )
        proj_fail = tmp_path / "detector_proj_fail"
        proj_fail.mkdir()
        (proj_fail / "models.py").write_text(
            "class Account(models.Model):\n    email = Column(String)\n",
            encoding="utf-8",
        )
        r_era_p = await scan_project_files(str(proj_pass))
        r_era_f = await scan_project_files(str(proj_fail))
        assert {f.rule_id: f for f in r_era_p.findings}[
            "erasure_mechanism_in_code"
        ].status == RuleFindingStatus.PASSED
        assert {f.rule_id: f for f in r_era_f.findings}[
            "erasure_mechanism_in_code"
        ].status == RuleFindingStatus.NEEDS_REVIEW
