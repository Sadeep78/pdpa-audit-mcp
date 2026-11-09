"""Readiness scoring calculation for Sri Lanka PDPA gap analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pdpa_audit_mcp.checklist import load_checklist
from pdpa_audit_mcp.models import (
    AuditSummary,
    CategoryScore,
    ReadinessLabel,
    RuleFindingStatus,
)

if TYPE_CHECKING:
    from pdpa_audit_mcp.models import ChecklistRule, Finding


def determine_readiness_label(score: float | None) -> ReadinessLabel:
    """Classify readiness score into predefined thresholds:

    - None: Insufficient data
    - < 50: Not Ready
    - 50 - 79: Partially Ready
    - >= 80: Mostly Ready
    """
    if score is None:
        return ReadinessLabel.INSUFFICIENT_DATA
    if score < 50.0:
        return ReadinessLabel.NOT_READY
    if score < 80.0:
        return ReadinessLabel.PARTIALLY_READY
    return ReadinessLabel.MOSTLY_READY


def calculate_readiness_score(
    findings: list[Finding],
    rules_map: dict[str, ChecklistRule] | None = None,
) -> AuditSummary:
    """Calculate category scores and overall readiness score from audit findings.

    Rules:
    - passed: earns full rule weight
    - failed: earns 0 weight
    - needs_review & not_evaluated: excluded from scoring denominator, counted separately
    - not_applicable: excluded from scoring denominator and coverage numerator
    - If scored weight is zero: score is None, label is 'Insufficient data'
    - Category score = (earned weight / scored weight) * 100
    - Overall score = (total earned weight / total scored weight) * 100
    """
    if rules_map is None:
        all_rules = load_checklist()
        rules_map = {r.id: r for r in all_rules}

    # Group findings and weights by category
    categories_data: dict[str, dict[str, int]] = {}

    total_passed = 0
    total_failed = 0
    total_needs_review = 0
    total_not_applicable = 0
    total_not_evaluated = 0
    sum_needs_review_weight = 0

    for finding in findings:
        cat = finding.category
        if cat not in categories_data:
            categories_data[cat] = {
                "passed_count": 0,
                "failed_count": 0,
                "needs_review_count": 0,
                "not_applicable_count": 0,
                "not_evaluated_count": 0,
                "weight_earned": 0,
                "weight_total": 0,
            }

        rule = rules_map.get(finding.rule_id)
        weight = rule.weight if rule is not None else 1

        if finding.status == RuleFindingStatus.PASSED:
            categories_data[cat]["passed_count"] += 1
            categories_data[cat]["weight_earned"] += weight
            categories_data[cat]["weight_total"] += weight
            total_passed += 1
        elif finding.status == RuleFindingStatus.FAILED:
            categories_data[cat]["failed_count"] += 1
            categories_data[cat]["weight_total"] += weight
            total_failed += 1
        elif finding.status == RuleFindingStatus.NEEDS_REVIEW:
            categories_data[cat]["needs_review_count"] += 1
            total_needs_review += 1
            sum_needs_review_weight += weight
        elif finding.status == RuleFindingStatus.NOT_APPLICABLE:
            categories_data[cat]["not_applicable_count"] += 1
            total_not_applicable += 1
        elif finding.status == RuleFindingStatus.NOT_EVALUATED:
            categories_data[cat]["not_evaluated_count"] += 1
            total_not_evaluated += 1

    category_scores: list[CategoryScore] = []
    sum_earned_weight = 0
    sum_scored_weight = 0

    for cat_name, data in categories_data.items():
        w_earned = data["weight_earned"]
        w_total = data["weight_total"]

        cat_score = round((w_earned / w_total) * 100.0, 1) if w_total > 0 else None

        category_scores.append(
            CategoryScore(
                category=cat_name,
                score=cat_score,
                passed_count=data["passed_count"],
                failed_count=data["failed_count"],
                needs_review_count=data["needs_review_count"],
                not_applicable_count=data["not_applicable_count"],
                not_evaluated_count=data["not_evaluated_count"],
                weight_earned=w_earned,
                weight_total=w_total,
            )
        )

        sum_earned_weight += w_earned
        sum_scored_weight += w_total

    assessed_rules = total_passed + total_failed
    applicable_rules = total_passed + total_failed + total_needs_review
    coverage = (
        round((assessed_rules / applicable_rules) * 100.0, 1) if applicable_rules > 0 else None
    )

    sum_applicable_weight = sum_scored_weight + sum_needs_review_weight
    weight_coverage = (
        round((sum_scored_weight / sum_applicable_weight) * 100.0, 1)
        if sum_applicable_weight > 0
        else None
    )

    if sum_scored_weight > 0:
        overall_score: float | None = round((sum_earned_weight / sum_scored_weight) * 100.0, 1)
        base_label = determine_readiness_label(overall_score).value
        if weight_coverage is not None and weight_coverage < 60.0:
            readiness_label = f"{base_label} (partial assessment)"
        else:
            readiness_label = base_label
    else:
        overall_score = None
        readiness_label = ReadinessLabel.INSUFFICIENT_DATA.value

    return AuditSummary(
        overall_score=overall_score,
        readiness_label=readiness_label,
        category_scores=category_scores,
        total_passed=total_passed,
        total_failed=total_failed,
        total_needs_review=total_needs_review,
        total_not_applicable=total_not_applicable,
        total_not_evaluated=total_not_evaluated,
        excluded_needs_review_count=total_needs_review,
        coverage=coverage,
        weight_coverage=weight_coverage,
        applicable_rules=applicable_rules,
        assessed_rules=assessed_rules,
    )
