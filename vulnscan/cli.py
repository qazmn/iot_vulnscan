from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from .lua_scanner import Decompiler, LuaScanner
from .report import Report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IoT firmware vulnerability scanner (Lua-focused)."
    )
    parser.add_argument(
        "firmware_dir",
        type=Path,
        help="Path to unpacked firmware root directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Write report to this file (defaults to stdout)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text"],
        default="text",
        help="Output format",
    )
    parser.add_argument(
        "--keep-decompiled",
        action="store_true",
        help="Keep decompiled Lua files under .vulnscan_decompiled",
    )
    parser.add_argument(
        "--decompiler",
        action="append",
        default=[],
        help=(
            "Custom decompiler command template. Use {input} and {output} placeholders. "
            "Example: --decompiler 'luadec -o {output} {input}'"
        ),
    )
    return parser


def build_decompilers(overrides: List[str]) -> List[Decompiler]:
    decompilers = []
    for index, command in enumerate(overrides, start=1):
        decompilers.append(Decompiler(f"custom-{index}", command))
    return decompilers


def render_text(report: Report) -> str:
    lines = [
        f"Findings: {len(report.findings)}",
        f"Warnings: {len(report.warnings)}",
        "",
    ]
    if report.warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in report.warnings)
        lines.append("")
    if report.findings:
        lines.append("Findings:")
        for finding in report.findings:
            lines.append(
                f"- [{finding.severity}] {finding.rule_id} {finding.file_path}:{finding.line}"
            )
            lines.append(f"  {finding.message}")
            lines.append(f"  {finding.code}")
    return "\n".join(lines)


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.firmware_dir.exists():
        parser.error(f"Firmware directory does not exist: {args.firmware_dir}")

    report = Report()
    decompilers = build_decompilers(args.decompiler)
    scanner = LuaScanner(
        decompilers=decompilers or None,
        keep_decompiled=args.keep_decompiled,
    )
    scanner.scan_firmware(args.firmware_dir, report)

    if args.format == "json":
        output = json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    else:
        output = render_text(report)

    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
