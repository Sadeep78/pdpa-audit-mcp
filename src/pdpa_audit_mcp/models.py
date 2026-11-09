"""Pydantic v2 data models for pdpa-audit-mcp."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pdpa_audit_mcp.config import LEGAL_DISCLAIMER, LEGAL_REF_PENDING


class SeverityEnum(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RuleFindingStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"
    NOT_APPLICABLE = "not_applicable"
    NOT_EVALUATED = "not_evaluated"


class CheckTypeEnum(StrEnum):
    PRIVACY_POLICY = "privacy_policy"
    COOKIE_CONSENT = "cookie_consent"
    FORMS = "forms"
    PROJECT = "project"
    BREACH = "breach"
    TRANSFER = "transfer"
    MANUAL = "manual"


class ReadinessLabel(StrEnum):
    NOT_READY = "Not Ready"
    PARTIALLY_READY = "Partially Ready"
    MOSTLY_READY = "Mostly Ready"
    INSUFFICIENT_DATA = "Insufficient data"


class ConfidenceEnum(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


KNOWN_DETECTORS: set[str] = {
    "security_https_enforced",
    "security_no_pii_in_urls",
    "security_password_autocomplete",
    "consent_not_preticked",
    "minimisation_sensitive_fields",
    "security_secure_cookie_flags",
    "consent_before_tracking",
    "erasure_mechanism_in_code",
    "no_pii_in_logs",
}


class ChecklistRule(BaseModel):
    """Schema for a single rule defined in the checklist YAML."""

    model_config = ConfigDict(extra="ignore")

    id: str
    category: str
    title: str
    description: str
    severity: SeverityEnum
    weight: int = Field(default=1, ge=1)
    check_type: CheckTypeEnum
    detector: str | None = None
    indicators: list[str] = Field(default_factory=list)
    all_of: list[list[str]] = Field(default_factory=list)
    recommendation: str
    legal_ref: str = "TODO_VERIFY"
    legal_ref_verified: bool = False
    source_url: str | None = None

    @model_validator(mode="after")
    def validate_verified_source_and_detector(self) -> ChecklistRule:
        if self.legal_ref_verified and not (self.source_url and self.source_url.strip()):
            raise ValueError(
                f"Rule '{self.id}' has legal_ref_verified=True but missing non-empty source_url."
            )
        if self.detector is not None:
            if self.detector not in KNOWN_DETECTORS:
                raise ValueError(
                    f"Rule '{self.id}' has unknown detector '{self.detector}'. "
                    f"Must be one of: {sorted(KNOWN_DETECTORS)}"
                )
            if self.all_of:
                raise ValueError(
                    f"Structural rule '{self.id}' specifies detector '{self.detector}' "
                    "and must NOT carry all_of keywords."
                )
        else:
            if not self.all_of:
                raise ValueError(
                    f"Text rule '{self.id}' requires non-empty all_of indicator groups."
                )
        return self

    @property
    def display_legal_ref(self) -> str:
        if not self.legal_ref_verified:
            return LEGAL_REF_PENDING
        return self.legal_ref


class Finding(BaseModel):
    """An individual finding from an audit rule check."""

    model_config = ConfigDict(extra="ignore")

    rule_id: str
    category: str
    title: str
    severity: SeverityEnum
    status: RuleFindingStatus
    evidence: str = Field(
        default="",
        max_length=150,
        description="Sanitized evidence snippet (max 120 chars, no personal data).",
    )
    recommendation: str
    confidence: ConfidenceEnum = ConfidenceEnum.HIGH
    legal_ref: str = "TODO_VERIFY"
    legal_ref_verified: bool = False
    source_url: str | None = None
    check_type: CheckTypeEnum | str = CheckTypeEnum.MANUAL
    sources: list[str] = Field(default_factory=list)
    matched_terms: list[str] = Field(
        default_factory=list,
        description="Matched indicator terms or field/tracker names (up to 5).",
    )
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def display_legal_ref(self) -> str:
        if not self.legal_ref_verified:
            return LEGAL_REF_PENDING
        return self.legal_ref


class CategoryScore(BaseModel):
    """Score summary for an individual audit category."""

    category: str
    score: float | None = Field(default=None, ge=0.0, le=100.0)
    passed_count: int = 0
    failed_count: int = 0
    needs_review_count: int = 0
    not_applicable_count: int = 0
    not_evaluated_count: int = 0
    weight_earned: int = 0
    weight_total: int = 0


class AuditSummary(BaseModel):
    """Overall scoring summary and compliance indicators."""

    overall_score: float | None = Field(default=None, ge=0.0, le=100.0)
    readiness_label: str
    category_scores: list[CategoryScore] = Field(default_factory=list)
    total_passed: int = 0
    total_failed: int = 0
    total_needs_review: int = 0
    total_not_applicable: int = 0
    total_not_evaluated: int = 0
    excluded_needs_review_count: int = 0
    coverage: float | None = Field(default=None, ge=0.0, le=100.0)
    weight_coverage: float | None = Field(default=None, ge=0.0, le=100.0)
    applicable_rules: int = 0
    assessed_rules: int = 0


class Report(BaseModel):
    """Comprehensive gap analysis report."""

    status: Literal["ok", "error"] = "ok"
    target: str
    timestamp: str
    summary: AuditSummary
    findings: list[Finding] = Field(default_factory=list)
    needs_human_review: list[Finding] = Field(default_factory=list)
    not_applicable: list[Finding] = Field(default_factory=list)
    not_assessed: list[Finding] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    disclaimer: str = LEGAL_DISCLAIMER
    error_message: str | None = None
    untrusted_content_notice: str = (
        "Evidence snippets are extracted from untrusted third-party targets "
        "and have been sanitized."
    )


class ToolResult(BaseModel):
    """Standardized wrapper for all MCP and API tool responses."""

    status: Literal["ok", "error"] = "ok"
    tool_name: str
    findings: list[Finding] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    disclaimer: str = LEGAL_DISCLAIMER
