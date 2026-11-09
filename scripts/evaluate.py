"""CLI evaluation sheet generator for pdpa-audit-mcp.

Usage:
    python scripts/evaluate.py --url URL [--project PATH] --confirm-authorised
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from pdpa_audit_mcp.report import run_full_audit


def parse_args(args: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an evaluation and labeling sheet for Sri Lanka PDPA readiness audit."
    )
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="Target website URL to audit.",
    )
    parser.add_argument(
        "--project",
        type=str,
        default=None,
        help="Optional local project directory path to audit.",
    )
    parser.add_argument(
        "--confirm-authorised",
        action="store_true",
        default=False,
        help="Affirmative confirmation that you own or are authorised to audit this target.",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="docs/evaluation_sheet.md",
        help="Output path for the evaluation labeling sheet (default: docs/evaluation_sheet.md).",
    )
    return parser.parse_args(args)


async def generate_evaluation_sheet(
    url: str | None,
    project_path: str | None,
    out_path: str | Path,
) -> None:
    target_label = url or project_path or "unspecified"
    inspect_url = url or ""

    report = await run_full_audit(url=url, project_path=project_path)

    lines: list[str] = [
        "# Real-World PDPA Audit Evaluation & Labeling Sheet",
        "",
        f"- **Audited Target**: `{target_label}`",
        f"- **Total Rules Assessed**: {len(report.findings)}",
        "- **Instructions**: Fill out the right-most three columns during manual verification.",
        (
            "  See `docs/EVALUATION.md` for definitions of verdicts "
            "(`correct`, `false pass`, `false fail`, `n/a`)."
        ),
        "",
        (
            "| Target | Rule ID | Tool Status | Matched Terms | Evidence Snippet | URL to inspect "
            "| Requirement actually met? (yes/no) "
            "| Human verdict (correct / false pass / false fail / n/a) "
            "| Notes |"
        ),
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for f in report.findings:
        terms_str = ", ".join(f.matched_terms) if f.matched_terms else "-"
        ev_str = f.evidence.replace("|", "\\|").replace("\n", " ").strip() if f.evidence else "-"
        row = (
            f"| `{target_label}` | `{f.rule_id}` | {f.status.value} | {terms_str} | "
            f"{ev_str} | {inspect_url} | | | |"
        )
        lines.append(row)

    lines.append("")
    out_file = Path(out_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(lines), encoding="utf-8")
    print(f"Evaluation sheet written successfully to: {out_file}")


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)

    if not args.confirm_authorised:
        sys.stderr.write("Error: only audit sites/projects you own or are authorised to audit\n")
        sys.exit(1)

    if not args.url and not args.project:
        sys.stderr.write("Error: At least one of --url or --project must be specified.\n")
        sys.exit(1)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures

        with concurrent.futures.ThreadPoolExecutor() as pool:
            pool.submit(
                asyncio.run, generate_evaluation_sheet(args.url, args.project, args.out)
            ).result()
    else:
        asyncio.run(generate_evaluation_sheet(args.url, args.project, args.out))


if __name__ == "__main__":
    main()
