"""Unit tests for PDPA checklist loading, validation, and indicator matching."""

import pytest

from pdpa_audit_mcp.checklist import (
    KNOWN_DETECTORS,
    get_checklist_path,
    get_rule_by_id,
    get_rules_by_category,
    get_rules_by_check_type,
    load_checklist,
    match_rule_indicators,
)
from pdpa_audit_mcp.models import CheckTypeEnum, SeverityEnum


class TestChecklistLoading:
    """Test checklist parsing, structure, and legal reference rules."""

    def test_checklist_file_exists(self):
        path = get_checklist_path()
        assert path.exists()
        assert path.is_file()

    def test_loads_rules_successfully(self):
        rules = load_checklist()
        assert len(rules) >= 15

    def test_every_rule_has_required_fields(self):
        rules = load_checklist()
        for rule in rules:
            assert rule.id, "Rule ID must not be empty"
            assert rule.category, f"Rule '{rule.id}' must have a category"
            assert rule.title, f"Rule '{rule.id}' must have a title"
            assert rule.description, f"Rule '{rule.id}' must have a description"
            assert rule.recommendation, f"Rule '{rule.id}' must have a recommendation"
            assert rule.severity in (SeverityEnum.HIGH, SeverityEnum.MEDIUM, SeverityEnum.LOW)
            assert rule.weight >= 1
            assert rule.check_type in list(CheckTypeEnum)

            if rule.detector is not None:
                assert rule.detector in KNOWN_DETECTORS
                assert len(rule.all_of) == 0, (
                    f"Structural rule '{rule.id}' must not have all_of keywords"
                )
            else:
                assert len(rule.all_of) >= 1, (
                    f"Text rule '{rule.id}' must have all_of indicator groups"
                )

            # Unverified rules must display pending note
            if not rule.legal_ref_verified:
                assert rule.display_legal_ref == "legal reference: to be verified"

    def test_rule_ids_are_unique(self):
        rules = load_checklist()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs detected: {ids}"

    def test_manual_check_types_only_for_truly_non_automatable(self):
        manual_rules = get_rules_by_check_type(CheckTypeEnum.MANUAL)
        manual_ids = {r.id for r in manual_rules}
        # children_age_gate_notice is the only manual review item
        assert manual_ids == {"children_age_gate_notice"}
        # consent_not_preticked was re-classified to forms
        forms_rules = get_rules_by_check_type(CheckTypeEnum.FORMS)
        assert any(r.id == "consent_not_preticked" for r in forms_rules)

    def test_get_rules_by_category(self):
        transparency_rules = get_rules_by_category("Transparency")
        assert len(transparency_rules) >= 4
        for r in transparency_rules:
            assert "transparency" in r.category.lower()

    def test_verified_legal_ref_requires_source_url(self, tmp_path):
        bad_yaml = tmp_path / "bad_verified.yaml"
        bad_yaml.write_text(
            """
rules:
  - id: "verified_without_url"
    category: "Security"
    title: "Verified Without URL"
    description: "Testing rule validation"
    severity: "high"
    weight: 2
    check_type: "privacy_policy"
    all_of: [["https"]]
    recommendation: "Fix"
    legal_ref: "Part II Section 8"
    legal_ref_verified: true
    source_url: null
"""
        )
        with pytest.raises(ValueError, match="legal_ref_verified=True but missing source_url"):
            load_checklist(bad_yaml)

    def test_verified_legal_ref_with_source_url_accepted(self, tmp_path):
        good_yaml = tmp_path / "good_verified.yaml"
        good_yaml.write_text(
            """
rules:
  - id: "verified_with_url"
    category: "Security Safeguards"
    title: "Verified With URL"
    description: "Testing rule validation"
    severity: "high"
    weight: 2
    check_type: "privacy_policy"
    all_of: [["https"]]
    recommendation: "Fix"
    legal_ref: "Section 8"
    legal_ref_verified: true
    source_url: "https://dpa.gov.lk/act"
"""
        )
        rules = load_checklist(good_yaml)
        assert len(rules) == 1
        assert rules[0].legal_ref == "Section 8"
        assert rules[0].display_legal_ref == "Section 8"

    def test_unknown_detector_rejected(self, tmp_path):
        bad_yaml = tmp_path / "unknown_detector.yaml"
        bad_yaml.write_text(
            """
rules:
  - id: "bad_detector"
    category: "Security"
    title: "Bad Detector Rule"
    description: "Testing unknown detector rejection"
    severity: "high"
    weight: 2
    check_type: "forms"
    detector: "non_existent_detector_id"
    recommendation: "Fix"
    legal_ref: "TODO_VERIFY"
"""
        )
        with pytest.raises(ValueError, match="unknown detector"):
            load_checklist(bad_yaml)

    def test_detector_rule_with_all_of_rejected(self, tmp_path):
        bad_yaml = tmp_path / "detector_with_all_of.yaml"
        bad_yaml.write_text(
            """
rules:
  - id: "detector_with_keywords"
    category: "Security"
    title: "Detector with all_of"
    description: "Testing invalid combination"
    severity: "high"
    weight: 2
    check_type: "forms"
    detector: "security_https_enforced"
    all_of: [["https"]]
    recommendation: "Fix"
    legal_ref: "TODO_VERIFY"
"""
        )
        with pytest.raises(ValueError, match="must NOT carry all_of keywords"):
            load_checklist(bad_yaml)


class TestIndicatorMatching:
    """Tests for indicator group matching, word boundaries, and 600-char sliding window."""

    def test_page_with_only_data_does_not_pass_any_rule(self):
        rules = load_checklist()
        page_text = "data"
        for rule in rules:
            matched, snippet, *_ = match_rule_indicators(rule, page_text)
            assert matched is False, f"Rule '{rule.id}' unexpectedly passed page with only 'data'!"

    def test_rule_passes_when_all_groups_match_in_one_paragraph(self):
        rule = get_rule_by_id("transparency_recipients")
        assert rule is not None
        page = (
            "In our privacy policy, we disclose when personal data is shared with "
            "third parties or cloud service providers."
        )
        matched, snippet, terms = match_rule_indicators(rule, page)
        assert matched is True
        assert snippet
        assert len(terms) > 0

    def test_accessibility_statement_does_not_pass_rights_access(self):
        rule = get_rule_by_id("rights_access")
        assert rule is not None
        page = (
            "This is our accessibility statement. Please contact us for any accessibility issues."
        )
        matched, snippet, *_ = match_rule_indicators(rule, page)
        assert matched is False, "Accessibility statement must not pass rights_access"

    def test_terms_separated_by_3000_chars_do_not_pass(self):
        rule = get_rule_by_id("transparency_recipients")
        assert rule is not None
        page = (
            "This is our privacy policy where we explain our general standards.\n\n"
            + ("Some unrelated content filler text for the page. " * 100)
            + "\n\nWe also work with various third parties."
        )
        matched, snippet, *_ = match_rule_indicators(rule, page)
        assert matched is False, "Terms 3000 characters apart must not pass"

    def test_sinhala_and_tamil_matching(self):
        rule = get_rule_by_id("transparency_purpose")
        assert rule is not None
        # Sinhala matching with zero-width characters in text
        sinhala_page = "මෙය අපගේ පෞද්ගලික දත්ත\u200c ප්‍රතිපත්තියයි. දත්ත සැකසීමේ අරමුණ මෙහි දැක්වේ."
        matched, snippet, *_ = match_rule_indicators(rule, sinhala_page)
        assert matched is True

        # Tamil matching
        tamil_page = "இது எமது தனிப்பட்ட தரவு கொள்கை. செயலாக்கத்தின் நோக்கம் இங்கே குறிப்பிடப்பட்டுள்ளது."
        matched_tamil, snippet_tamil, *_ = match_rule_indicators(rule, tamil_page)
        assert matched_tamil is True

    def test_natural_tamil_phrasing_in_rights_request(self):
        rule = get_rule_by_id("rights_request_procedure")
        assert rule is not None
        page = "எங்கள் பயனர்கள் உரிமைகளைப் பயன்படுத்த மற்றும் கோரிக்கையைச் சமர்ப்பிக்க வழிமுறைகள்."
        matched, snippet, *_ = match_rule_indicators(rule, page)
        assert matched is True
