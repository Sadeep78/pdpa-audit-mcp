"""Unit tests for readiness scoring with hand-calculated expected values."""

from pdpa_audit_mcp.models import (
    ChecklistRule,
    CheckTypeEnum,
    Finding,
    ReadinessLabel,
    RuleFindingStatus,
    SeverityEnum,
)
from pdpa_audit_mcp.scoring import calculate_readiness_score, determine_readiness_label


def _create_mock_rule(
    rule_id: str,
    category: str,
    weight: int,
    severity: SeverityEnum = SeverityEnum.HIGH,
) -> ChecklistRule:
    return ChecklistRule(
        id=rule_id,
        category=category,
        title=f"Rule {rule_id}",
        description="Test rule description",
        severity=severity,
        weight=weight,
        check_type=CheckTypeEnum.PRIVACY_POLICY,
        all_of=[["test"]],
        recommendation="Test recommendation",
        legal_ref="TODO_VERIFY",
    )


def _create_mock_finding(
    rule_id: str,
    category: str,
    status: RuleFindingStatus,
    severity: SeverityEnum = SeverityEnum.HIGH,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=category,
        title=f"Rule {rule_id}",
        severity=severity,
        status=status,
        evidence="Sample evidence",
        recommendation="Sample recommendation",
        legal_ref="TODO_VERIFY",
        check_type=CheckTypeEnum.PRIVACY_POLICY,
    )


class TestReadinessThresholds:
    """Tests for threshold classification."""

    def test_labels(self):
        assert determine_readiness_label(None) == ReadinessLabel.INSUFFICIENT_DATA
        assert determine_readiness_label(0.0) == ReadinessLabel.NOT_READY
        assert determine_readiness_label(49.9) == ReadinessLabel.NOT_READY
        assert determine_readiness_label(50.0) == ReadinessLabel.PARTIALLY_READY
        assert determine_readiness_label(79.9) == ReadinessLabel.PARTIALLY_READY
        assert determine_readiness_label(80.0) == ReadinessLabel.MOSTLY_READY
        assert determine_readiness_label(100.0) == ReadinessLabel.MOSTLY_READY


class TestScoringCalculations:
    """Tests for score calculation with explicit hand-calculated formulas in comments."""

    def test_single_category_mixed_results(self):
        """HAND CALCULATION:
        Category: 'Transparency'
        - Rule 1 (weight 3): PASSED       -> earned: 3, scored: 3
        - Rule 2 (weight 2): FAILED       -> earned: 0, scored: 2
        - Rule 3 (weight 3): NEEDS_REVIEW -> excluded from scored weight
        - Rule 4 (weight 1): PASSED       -> earned: 1, scored: 1

        Total earned weight = 3 + 0 + 1 = 4
        Total scored weight = 3 + 2 + 1 = 6
        Category Score = (4 / 6) * 100 = 66.666... -> rounded to 66.7%
        Overall Score  = (4 / 6) * 100 = 66.7%
        Label = 'Partially Ready' (50.0 <= 66.7 < 80.0)
        Excluded needs_review count = 1
        """
        rules = {
            "r1": _create_mock_rule("r1", "Transparency", weight=3),
            "r2": _create_mock_rule("r2", "Transparency", weight=2),
            "r3": _create_mock_rule("r3", "Transparency", weight=3),
            "r4": _create_mock_rule("r4", "Transparency", weight=1),
        }
        findings = [
            _create_mock_finding("r1", "Transparency", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Transparency", RuleFindingStatus.FAILED),
            _create_mock_finding("r3", "Transparency", RuleFindingStatus.NEEDS_REVIEW),
            _create_mock_finding("r4", "Transparency", RuleFindingStatus.PASSED),
        ]

        summary = calculate_readiness_score(findings, rules)

        assert summary.overall_score == 66.7
        assert summary.readiness_label == ReadinessLabel.PARTIALLY_READY
        assert summary.total_passed == 2
        assert summary.total_failed == 1
        assert summary.total_needs_review == 1
        assert summary.excluded_needs_review_count == 1

        cat = summary.category_scores[0]
        assert cat.category == "Transparency"
        assert cat.score == 66.7
        assert cat.weight_earned == 4
        assert cat.weight_total == 6

    def test_multiple_categories_weighted_average(self):
        """HAND CALCULATION:
        Category 1: 'Transparency'
        - r1 (weight 3): PASSED -> earned 3, scored 3
        - r2 (weight 2): PASSED -> earned 2, scored 2
        Cat 1 earned = 5, scored = 5. Cat 1 Score = (5/5)*100 = 100.0%

        Category 2: 'Consent'
        - r3 (weight 3): FAILED -> earned 0, scored 3
        - r4 (weight 2): PASSED -> earned 2, scored 2
        Cat 2 earned = 2, scored = 5. Cat 2 Score = (2/5)*100 = 40.0%

        Category 3: 'Breach Readiness'
        - r5 (weight 2): NEEDS_REVIEW -> excluded
        Cat 3 earned = 0, scored = 0. Cat 3 Score = None (zero scored weight)

        Across all scored categories:
        Total earned weight = 5 + 2 = 7
        Total scored weight = 5 + 5 = 10
        Overall Score = (7 / 10) * 100 = 70.0%
        Label = 'Partially Ready' (50 <= 70.0 < 80)
        Excluded needs_review count = 1
        """
        rules = {
            "r1": _create_mock_rule("r1", "Transparency", weight=3),
            "r2": _create_mock_rule("r2", "Transparency", weight=2),
            "r3": _create_mock_rule("r3", "Consent", weight=3),
            "r4": _create_mock_rule("r4", "Consent", weight=2),
            "r5": _create_mock_rule("r5", "Breach Readiness", weight=2),
        }
        findings = [
            _create_mock_finding("r1", "Transparency", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Transparency", RuleFindingStatus.PASSED),
            _create_mock_finding("r3", "Consent", RuleFindingStatus.FAILED),
            _create_mock_finding("r4", "Consent", RuleFindingStatus.PASSED),
            _create_mock_finding("r5", "Breach Readiness", RuleFindingStatus.NEEDS_REVIEW),
        ]

        summary = calculate_readiness_score(findings, rules)

        assert summary.overall_score == 70.0
        assert summary.readiness_label == ReadinessLabel.PARTIALLY_READY
        assert summary.total_passed == 3
        assert summary.total_failed == 1
        assert summary.total_needs_review == 1

        cats = {c.category: c for c in summary.category_scores}
        assert cats["Transparency"].score == 100.0
        assert cats["Consent"].score == 40.0
        assert cats["Breach Readiness"].score is None
        assert cats["Breach Readiness"].needs_review_count == 1

    def test_mostly_ready_threshold(self):
        """HAND CALCULATION:
        - r1 (weight 4): PASSED -> earned 4, scored 4
        - r2 (weight 1): FAILED -> earned 0, scored 1

        Total earned = 4, Total scored = 5
        Overall Score = (4 / 5) * 100 = 80.0%
        Label = 'Mostly Ready' (>= 80.0)
        """
        rules = {
            "r1": _create_mock_rule("r1", "Security", weight=4),
            "r2": _create_mock_rule("r2", "Security", weight=1),
        }
        findings = [
            _create_mock_finding("r1", "Security", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Security", RuleFindingStatus.FAILED),
        ]
        summary = calculate_readiness_score(findings, rules)
        assert summary.overall_score == 80.0
        assert summary.readiness_label == ReadinessLabel.MOSTLY_READY

    def test_not_ready_threshold(self):
        """HAND CALCULATION:
        - r1 (weight 1): PASSED -> earned 1, scored 1
        - r2 (weight 3): FAILED -> earned 0, scored 3

        Total earned = 1, Total scored = 4
        Overall Score = (1 / 4) * 100 = 25.0%
        Label = 'Not Ready' (< 50.0)
        """
        rules = {
            "r1": _create_mock_rule("r1", "Rights", weight=1),
            "r2": _create_mock_rule("r2", "Rights", weight=3),
        }
        findings = [
            _create_mock_finding("r1", "Rights", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Rights", RuleFindingStatus.FAILED),
        ]
        summary = calculate_readiness_score(findings, rules)
        assert summary.overall_score == 25.0
        assert summary.readiness_label == ReadinessLabel.NOT_READY

    def test_zero_scored_weight_gives_none_and_insufficient_data(self):
        """HAND CALCULATION:
        - r1 (weight 3): NEEDS_REVIEW  -> excluded
        - r2 (weight 2): NOT_EVALUATED -> excluded

        Total scored weight = 0
        Overall Score = None (never 0 or 100)
        Category Score = None
        Label = 'Insufficient data'
        total_needs_review = 1, total_not_evaluated = 1
        """
        rules = {
            "r1": _create_mock_rule("r1", "Manual Checks", weight=3),
            "r2": _create_mock_rule("r2", "Manual Checks", weight=2),
        }
        findings = [
            _create_mock_finding("r1", "Manual Checks", RuleFindingStatus.NEEDS_REVIEW),
            _create_mock_finding("r2", "Manual Checks", RuleFindingStatus.NOT_EVALUATED),
        ]
        summary = calculate_readiness_score(findings, rules)
        assert summary.overall_score is None
        assert summary.readiness_label == ReadinessLabel.INSUFFICIENT_DATA
        assert summary.total_needs_review == 1
        assert summary.total_not_evaluated == 1
        assert summary.category_scores[0].score is None

    def test_coverage_metrics_calculation(self):
        """Verify rule coverage and weight coverage calculations."""
        rules = {
            "r1": _create_mock_rule("r1", "Sec", weight=3),
            "r2": _create_mock_rule("r2", "Sec", weight=2),
            "r3": _create_mock_rule("r3", "Sec", weight=5),
            "r4": _create_mock_rule("r4", "Sec", weight=2),
        }
        findings = [
            _create_mock_finding("r1", "Sec", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Sec", RuleFindingStatus.FAILED),
            _create_mock_finding("r3", "Sec", RuleFindingStatus.NEEDS_REVIEW),
            _create_mock_finding("r4", "Sec", RuleFindingStatus.NOT_EVALUATED),
        ]
        summary = calculate_readiness_score(findings, rules)

        # Assessed = r1 (passed) + r2 (failed) = 2
        # Applicable = r1 + r2 + r3 (needs_review) = 3 (not_evaluated is excluded from applicable)
        assert summary.assessed_rules == 2
        assert summary.applicable_rules == 3
        # Coverage = 2 / 3 * 100 = 66.7%
        assert summary.coverage == 66.7

        # Scored weight = 3 + 2 = 5
        # Applicable weight = 5 + 5 (needs_review) = 10
        # Weight coverage = 5 / 10 * 100 = 50.0%
        assert summary.weight_coverage == 50.0

        # Score = (3 / 5) * 100 = 60.0% (Partially Ready)
        # Because weight_coverage (50.0%) < 60.0%, label has (partial assessment)
        assert summary.readiness_label == "Partially Ready (partial assessment)"

    def test_partial_assessment_when_weight_coverage_under_60(self):
        """When weight coverage < 60%, readiness label appends '(partial assessment)'."""
        rules = {
            "r1": _create_mock_rule("r1", "Sec", weight=1),
            "r2": _create_mock_rule("r2", "Sec", weight=4),
        }
        findings = [
            _create_mock_finding("r1", "Sec", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Sec", RuleFindingStatus.NEEDS_REVIEW),
        ]
        summary = calculate_readiness_score(findings, rules)
        assert summary.overall_score == 100.0
        assert summary.weight_coverage == 20.0
        assert summary.readiness_label == "Mostly Ready (partial assessment)"

    def test_normal_label_when_weight_coverage_60_or_above(self):
        """When weight coverage >= 60%, readiness label does NOT append '(partial assessment)'."""
        rules = {
            "r1": _create_mock_rule("r1", "Sec", weight=4),
            "r2": _create_mock_rule("r2", "Sec", weight=1),
        }
        findings = [
            _create_mock_finding("r1", "Sec", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Sec", RuleFindingStatus.NEEDS_REVIEW),
        ]
        summary = calculate_readiness_score(findings, rules)
        assert summary.overall_score == 100.0
        assert summary.weight_coverage == 80.0
        assert summary.readiness_label == "Mostly Ready"

    def test_not_applicable_excluded_from_denominator_and_coverage(self):
        """HAND CALCULATION:
        - r1 (weight 3): PASSED -> earned: 3, scored: 3
        - r2 (weight 2): FAILED -> earned: 0, scored: 2
        - r3 (weight 4): NOT_APPLICABLE -> excluded from scored weight, denominator, and coverage
        - r4 (weight 1): NEEDS_REVIEW -> excluded from scored weight, included in applicable rules

        Earned weight = 3
        Scored weight = 3 + 2 = 5
        Overall Score = (3 / 5) * 100 = 60.0%
        Total passed = 1, failed = 1, needs_review = 1, not_applicable = 1
        Assessed rules = 1 + 1 = 2 (not_applicable excluded)
        Applicable rules = 1 + 1 + 1 = 3 (not_applicable excluded)
        Rule coverage = (2 / 3) * 100 = 66.7%
        Scored weight = 5
        Applicable weight = 5 + 1 = 6 (not_applicable excluded)
        Weight coverage = (5 / 6) * 100 = 83.3%
        Readiness label = 'Partially Ready' (>= 60% weight coverage, no partial assessment note)
        """
        rules = {
            "r1": _create_mock_rule("r1", "Sec", weight=3),
            "r2": _create_mock_rule("r2", "Sec", weight=2),
            "r3": _create_mock_rule("r3", "Sec", weight=4),
            "r4": _create_mock_rule("r4", "Sec", weight=1),
        }
        findings = [
            _create_mock_finding("r1", "Sec", RuleFindingStatus.PASSED),
            _create_mock_finding("r2", "Sec", RuleFindingStatus.FAILED),
            _create_mock_finding("r3", "Sec", RuleFindingStatus.NOT_APPLICABLE),
            _create_mock_finding("r4", "Sec", RuleFindingStatus.NEEDS_REVIEW),
        ]
        summary = calculate_readiness_score(findings, rules)
        assert summary.overall_score == 60.0
        assert summary.total_passed == 1
        assert summary.total_failed == 1
        assert summary.total_needs_review == 1
        assert summary.total_not_applicable == 1
        assert summary.assessed_rules == 2
        assert summary.applicable_rules == 3
        assert summary.coverage == 66.7
        assert summary.weight_coverage == 83.3
        assert summary.readiness_label == "Partially Ready"

        cat = summary.category_scores[0]
        assert cat.not_applicable_count == 1
        assert cat.score == 60.0
