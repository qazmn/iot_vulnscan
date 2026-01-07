from __future__ import annotations

import os
import re
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set, Tuple

from .report import Finding, Report


@dataclass(frozen=True)
class Decompiler:
    name: str
    command: str


TAINT_SOURCES = [
    r"luci\.http\.formvalue",
    r"luci\.http\.formvalues",
    r"luci\.http\.getenv",
    r"luci\.http\.content",
    r"luci\.sys\.exec",
    r"luci\.sys\.call",
    r"uhttpd\.formvalue",
    r"ngx\.req\.get_uri_args",
    r"ngx\.req\.get_post_args",
    r"ngx\.var\.[A-Za-z_][A-Za-z0-9_]*",
    r"cgi\.getParam",
    r"http\.formvalue",
]

COMMAND_SINKS = [
    "os.execute",
    "os.popen",
    "io.popen",
    "luci.sys.exec",
    "luci.sys.call",
    "nixio.exec",
    "nixio.execp",
    "posix.exec",
    "sys.exec",
    "sys.call",
]

FILE_SINKS = [
    "io.open",
    "os.remove",
    "os.rename",
    "lfs.chdir",
    "nixio.chdir",
    "nixio.open",
]

EVAL_SINKS = [
    "loadstring",
    "load",
    "dofile",
    "loadfile",
    "require",
]

XSS_SINKS = [
    "luci.http.write",
    "luci.http.write_json",
    "ngx.say",
    "ngx.print",
]

DEFAULT_DECOMPILERS = [
    Decompiler("luadec", "luadec -o {output} {input}"),
    Decompiler("luadec-stdout", "luadec {input} > {output}"),
    Decompiler("unluac", "unluac {input} > {output}"),
]


class LuaScanner:
    def __init__(
        self,
        decompilers: Optional[Sequence[Decompiler]] = None,
        keep_decompiled: bool = False,
    ) -> None:
        self.decompilers = list(decompilers or DEFAULT_DECOMPILERS)
        self.keep_decompiled = keep_decompiled

    def scan_firmware(self, root: Path, report: Report) -> None:
        lua_files, bytecode_files = self._collect_files(root)
        decompiled_dir = root / ".vulnscan_decompiled"
        if bytecode_files:
            decompiled_dir.mkdir(exist_ok=True)

        for file_path in bytecode_files:
            decompiled_path = self._decompile_file(file_path, decompiled_dir, report)
            if decompiled_path:
                lua_files.append(decompiled_path)

        for lua_file in lua_files:
            report.add_findings(self.scan_lua_file(lua_file))

        if decompiled_dir.exists() and not self.keep_decompiled:
            for item in decompiled_dir.glob("*"):
                item.unlink(missing_ok=True)
            decompiled_dir.rmdir()

    def scan_lua_file(self, path: Path) -> List[Finding]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        lines = text.splitlines()
        tainted: Set[str] = set()
        findings: List[Finding] = []

        for line_no, raw_line in enumerate(lines, start=1):
            line = self._strip_comment(raw_line)
            if not line.strip():
                continue
            assigned = self._parse_assignment(line)
            if assigned:
                var_name, expr = assigned
                if self._contains_source(expr) or self._contains_tainted(expr, tainted):
                    tainted.add(var_name)
            self._append_sink_findings(
                findings, path, line_no, line, tainted
            )
        return findings

    def _collect_files(self, root: Path) -> Tuple[List[Path], List[Path]]:
        lua_files: List[Path] = []
        bytecode_files: List[Path] = []
        for current, _, files in os.walk(root):
            for filename in files:
                path = Path(current) / filename
                ext = path.suffix.lower()
                if ext == ".lua":
                    lua_files.append(path)
                elif ext in {".luac", ".lc", ".luajit"}:
                    bytecode_files.append(path)
        return lua_files, bytecode_files

    def _decompile_file(self, path: Path, output_dir: Path, report: Report) -> Optional[Path]:
        output_path = output_dir / f"{path.stem}.lua"
        for decompiler in self.decompilers:
            command = decompiler.command.format(
                input=shlex.quote(str(path)),
                output=shlex.quote(str(output_path)),
            )
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except OSError as exc:
                report.add_warning(
                    f"Failed to run {decompiler.name} on {path}: {exc}"
                )
                continue
            if result.returncode == 0 and output_path.exists():
                return output_path
            if result.returncode == 0 and result.stdout:
                output_path.write_text(result.stdout, encoding="utf-8")
                return output_path
            report.add_warning(
                f"Decompiler {decompiler.name} failed for {path}: {result.stderr.strip()}"
            )
        report.add_warning(f"No decompiler succeeded for {path}")
        return None

    def _strip_comment(self, line: str) -> str:
        if "--" not in line:
            return line
        parts = line.split("--", 1)
        return parts[0]

    def _parse_assignment(self, line: str) -> Optional[Tuple[str, str]]:
        match = re.match(r"\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)", line)
        if not match:
            return None
        var_name = match.group(1)
        expr = match.group(2)
        return var_name, expr

    def _contains_source(self, expr: str) -> bool:
        for source in TAINT_SOURCES:
            if re.search(source, expr):
                return True
        return False

    def _contains_tainted(self, expr: str, tainted: Set[str]) -> bool:
        for var in tainted:
            if re.search(rf"\b{re.escape(var)}\b", expr):
                return True
        return False

    def _append_sink_findings(
        self,
        findings: List[Finding],
        path: Path,
        line_no: int,
        line: str,
        tainted: Set[str],
    ) -> None:
        self._append_findings_for_sinks(
            findings,
            path,
            line_no,
            line,
            tainted,
            COMMAND_SINKS,
            "LUA-CMD-INJECTION",
            "high",
            "Command injection risk via Lua sink",
        )
        self._append_findings_for_sinks(
            findings,
            path,
            line_no,
            line,
            tainted,
            FILE_SINKS,
            "LUA-PATH-TRAVERSAL",
            "medium",
            "Path traversal risk via file operation",
        )
        self._append_findings_for_sinks(
            findings,
            path,
            line_no,
            line,
            tainted,
            EVAL_SINKS,
            "LUA-EVAL-INJECTION",
            "high",
            "Dynamic code execution risk in Lua",
        )
        self._append_findings_for_sinks(
            findings,
            path,
            line_no,
            line,
            tainted,
            XSS_SINKS,
            "LUA-XSS",
            "medium",
            "Potential XSS via HTTP output",
        )

    def _append_findings_for_sinks(
        self,
        findings: List[Finding],
        path: Path,
        line_no: int,
        line: str,
        tainted: Set[str],
        sinks: Iterable[str],
        rule_id: str,
        severity: str,
        message: str,
    ) -> None:
        for sink in sinks:
            if re.search(rf"\b{re.escape(sink)}\s*\(", line):
                if self._contains_tainted(line, tainted) or self._contains_source(line) or ".." in line:
                    findings.append(
                        Finding(
                            file_path=str(path),
                            line=line_no,
                            rule_id=rule_id,
                            severity=severity,
                            message=message,
                            code=line.strip(),
                        )
                    )
                return
