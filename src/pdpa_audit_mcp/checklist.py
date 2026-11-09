"""Checklist loader, validator, and indicator matching for Sri Lanka PDPA readiness audit rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import yaml

from pdpa_audit_mcp.models import KNOWN_DETECTORS, ChecklistRule
from pdpa_audit_mcp.safety import (
    extract_centered_snippet,
    normalize_text,
)

if TYPE_CHECKING:
    from pdpa_audit_mcp.models import CheckTypeEnum


def get_checklist_path() -> Path:
    """Return the absolute path to the bundled pdpa_checklist.yaml file."""
    return Path(__file__).parent / "data" / "pdpa_checklist.yaml"


def load_checklist(custom_path: Path | str | None = None) -> list[ChecklistRule]:
    """Load and validate audit rules from the YAML checklist.

    - Accepts legal_ref == 'TODO_VERIFY' OR a non-empty string.
    - If legal_ref_verified is True, a non-empty source_url is required.
    - If detector is present, it must be in KNOWN_DETECTORS and all_of must be empty.
    - If detector is absent, all_of must be non-empty.
    """
    path = Path(custom_path) if custom_path else get_checklist_path()
    if not path.exists():
        raise FileNotFoundError(f"Checklist file not found at: {path}")

    content = path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError("Invalid checklist YAML format: root object must contain 'rules' key.")

    rules_raw = data["rules"]
    if not isinstance(rules_raw, list) or len(rules_raw) == 0:
        raise ValueError("Checklist 'rules' must be a non-empty list.")

    rules: list[ChecklistRule] = []
    seen_ids: set[str] = set()

    for idx, rule_dict in enumerate(rules_raw):
        if not isinstance(rule_dict, dict):
            raise ValueError(f"Rule at index {idx} is not a valid dictionary.")

        legal_ref = rule_dict.get("legal_ref", "")
        if not isinstance(legal_ref, str) or not legal_ref.strip():
            raise ValueError(f"Rule '{rule_dict.get('id', idx)}' must have a non-empty legal_ref.")

        verified = rule_dict.get("legal_ref_verified", False)
        source_url = rule_dict.get("source_url")
        if verified and (not source_url or not str(source_url).strip()):
            raise ValueError(
                f"Rule '{rule_dict.get('id', idx)}' has legal_ref_verified=True but "
                "missing source_url."
            )

        detector = rule_dict.get("detector")
        if detector is not None:
            if detector not in KNOWN_DETECTORS:
                raise ValueError(
                    f"Rule '{rule_dict.get('id', idx)}' has unknown detector '{detector}'"
                )

        rule = ChecklistRule.model_validate(rule_dict)

        if rule.id in seen_ids:
            raise ValueError(f"Duplicate rule id found: '{rule.id}'")
        seen_ids.add(rule.id)

        rules.append(rule)

    return rules


def get_rules_by_category(category: str | None = None) -> list[ChecklistRule]:
    """Return rules optionally filtered by category name (case-insensitive substring)."""
    rules = load_checklist()
    if not category:
        return rules
    cat_lower = category.lower().strip()
    return [r for r in rules if cat_lower in r.category.lower()]


def get_rules_by_check_type(check_type: CheckTypeEnum | str) -> list[ChecklistRule]:
    """Return rules filtered by check_type (e.g. privacy_policy, cookie_consent, forms)."""
    type_str = str(check_type.value if hasattr(check_type, "value") else check_type)
    rules = load_checklist()
    return [r for r in rules if r.check_type == type_str]


def get_rule_by_id(rule_id: str) -> ChecklistRule | None:
    """Return a single rule by its ID, or None if not found."""
    rules = load_checklist()
    for r in rules:
        if r.id == rule_id:
            return r
    return None


def _find_term_occurrences(term: str, target: str) -> list[tuple[int, int, str]]:
    """Find occurrences of term in normalized target.

    Latin-script terms match on word boundaries (\b).
    Sinhala/Tamil terms use normalized substring matching.
    """
    norm_term = normalize_text(term)
    if not norm_term:
        return []

    has_latin = bool(re.search(r"[a-zA-Z]", norm_term))
    occurrences: list[tuple[int, int, str]] = []

    if has_latin:
        pattern = re.compile(r"\b" + re.escape(norm_term) + r"\b")
        for match in pattern.finditer(target):
            occurrences.append((match.start(), match.end(), norm_term))
    else:
        start = 0
        while True:
            idx = target.find(norm_term, start)
            if idx == -1:
                break
            occurrences.append((idx, idx + len(norm_term), norm_term))
            start = idx + 1

    return occurrences


def _check_groups_in_text(
    groups: list[list[str]], target: str
) -> tuple[bool, list[tuple[int, int, str]]]:
    """Check if every group has at least one occurrence in target."""
    group_matches: list[tuple[int, int, str]] = []
    for group in groups:
        found = False
        for term in group:
            occs = _find_term_occurrences(term, target)
            if occs:
                group_matches.append(occs[0])
                found = True
                break
        if not found:
            return False, []
    return True, group_matches


class MatchResult(NamedTuple):
    """Result of indicator matching for a checklist rule."""

    matched: bool
    snippet: str
    matched_terms: list[str] = []


def match_rule_indicators(rule: ChecklistRule, text: str) -> MatchResult:
    """Match a rule against text using indicator groups (`all_of`).

    Every group in `rule.all_of` must match at least one term.
    Latin terms match on word boundaries (\b); Sinhala/Tamil use normalized substring.
    All groups must match within the same text block or within a 600-character sliding window.
    Returns: MatchResult(is_match, evidence_snippet, matched_terms)
    """
    if not text or rule.detector is not None or not rule.all_of:
        return MatchResult(False, "", [])

    # Strategy 1: Check if all groups match within the same text block (e.g. paragraph)
    blocks = [b.strip() for b in re.split(r"\n\s*\n|\r\n\s*\r\n", text) if b.strip()]
    for block in blocks:
        norm_block = normalize_text(block)
        matched, matches = _check_groups_in_text(rule.all_of, norm_block)
        if matched:
            first_start = min(m[0] for m in matches)
            last_end = max(m[1] for m in matches)
            if last_end - first_start <= 600:
                matched_terms = list(dict.fromkeys(m[2] for m in matches))[:5]
                return MatchResult(
                    True,
                    extract_centered_snippet(norm_block, first_start, last_end, target_len=120),
                    matched_terms,
                )

    # Strategy 2: 600-character sliding window across full normalized page
    norm_page = normalize_text(text)
    group_occurrences: list[list[tuple[int, int, str]]] = []
    for group in rule.all_of:
        group_occs: list[tuple[int, int, str]] = []
        for term in group:
            group_occs.extend(_find_term_occurrences(term, norm_page))
        if not group_occs:
            return MatchResult(False, "", [])
        group_occurrences.append(group_occs)

    # Flatten occurrences with group index and sort by start position
    all_events: list[tuple[int, int, int, str]] = []
    for g_idx, occs in enumerate(group_occurrences):
        for s, e, t in occs:
            all_events.append((s, e, g_idx, t))
    all_events.sort(key=lambda x: x[0])

    num_groups = len(rule.all_of)
    group_counts: dict[int, int] = {}
    left = 0

    for right in range(len(all_events)):
        r_g = all_events[right][2]
        group_counts[r_g] = group_counts.get(r_g, 0) + 1

        while len(group_counts) == num_groups:
            span_start = all_events[left][0]
            span_end = max(all_events[i][1] for i in range(left, right + 1))
            if span_end - span_start <= 600:
                matched_terms = list(
                    dict.fromkeys(all_events[i][3] for i in range(left, right + 1))
                )[:5]
                return MatchResult(
                    True,
                    extract_centered_snippet(norm_page, span_start, span_end, target_len=120),
                    matched_terms,
                )

            l_g = all_events[left][2]
            group_counts[l_g] -= 1
            if group_counts[l_g] == 0:
                del group_counts[l_g]
            left += 1

    return MatchResult(False, "", [])
