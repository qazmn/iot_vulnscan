from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Iterable, List


@dataclass
class Finding:
    file_path: str
    line: int
    rule_id: str
    severity: str
    message: str
    code: str


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def add_findings(self, items: Iterable[Finding]) -> None:
        self.findings.extend(items)

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_findings": len(self.findings),
                "total_warnings": len(self.warnings),
            },
            "findings": [asdict(item) for item in self.findings],
            "warnings": list(self.warnings),
        }
