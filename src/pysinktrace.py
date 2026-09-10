#!/usr/bin/env python3
"""Small, explainable inter-statement taint tracer for Python security review."""

from __future__ import annotations

import argparse
import ast
import json
from dataclasses import asdict, dataclass
from pathlib import Path


SOURCE_SUFFIXES = {
    "request.args.get", "request.form.get", "request.values.get",
    "request.cookies.get", "request.headers.get", "request.json.get",
    "input",
}
SANITIZER_SUFFIXES = {"int", "float", "shlex.quote", "html.escape", "urllib.parse.quote"}
SINKS = {
    "os.system": ("PST001", "critical", "command execution"),
    "subprocess.Popen": ("PST001", "critical", "process execution"),
    "subprocess.run": ("PST001", "high", "process execution"),
    "subprocess.call": ("PST001", "high", "process execution"),
    "eval": ("PST002", "critical", "dynamic evaluation"),
    "exec": ("PST002", "critical", "dynamic execution"),
    "cursor.execute": ("PST003", "high", "SQL execution"),
}


@dataclass(frozen=True)
class Trace:
    source: str
    source_line: int
    path: tuple[int, ...]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str
    function: str
    source: str
    source_line: int
    sink: str
    sink_line: int
    path: tuple[int, ...]


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        left = dotted(node.value)
        return f"{left}.{node.attr}" if left else node.attr
    return ""


class FunctionTracer(ast.NodeVisitor):
    def __init__(self, filename: str, function: str):
        self.filename, self.function = filename, function
        self.state: dict[str, tuple[Trace, ...]] = {}
        self.findings: list[Finding] = []

    def traces(self, node: ast.AST) -> tuple[Trace, ...]:
        if isinstance(node, ast.Name):
            return self.state.get(node.id, ())
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in SOURCE_SUFFIXES:
                return (Trace(name, node.lineno, (node.lineno,)),)
            carried = tuple(trace for arg in [*node.args, *(kw.value for kw in node.keywords)] for trace in self.traces(arg))
            if name in SANITIZER_SUFFIXES:
                return ()
            return carried
        children: list[Trace] = []
        for child in ast.iter_child_nodes(node):
            children.extend(self.traces(child))
        unique = {(t.source, t.source_line, t.path): t for t in children}
        return tuple(unique.values())

    def assign(self, target: ast.AST, traces: tuple[Trace, ...], line: int) -> None:
        if isinstance(target, ast.Name):
            self.state[target.id] = tuple(Trace(t.source, t.source_line, (*t.path, line)) for t in traces)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.assign(element, traces, line)

    def visit_Assign(self, node: ast.Assign) -> None:
        traces = self.traces(node.value)
        for target in node.targets:
            self.assign(target, traces, node.lineno)
        self.generic_visit(node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self.assign(node.target, self.traces(node.value), node.lineno)
            self.generic_visit(node.value)

    def visit_Call(self, node: ast.Call) -> None:
        sink = dotted(node.func)
        config = SINKS.get(sink)
        if not config:
            self.generic_visit(node)
            return
        traces = tuple(trace for arg in [*node.args, *(kw.value for kw in node.keywords)] for trace in self.traces(arg))
        if sink.startswith("subprocess."):
            shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True for kw in node.keywords)
            if shell_true:
                config = (config[0], "critical", f"{config[2]} with shell=True")
        rule, severity, operation = config
        for trace in traces:
            self.findings.append(Finding(
                rule, severity, f"Untrusted data reaches {operation}", self.filename,
                self.function, trace.source, trace.source_line, sink, node.lineno,
                (*trace.path, node.lineno),
            ))
        self.generic_visit(node)


class ModuleTracer(ast.NodeVisitor):
    def __init__(self, filename: str):
        self.filename = filename
        self.findings: list[Finding] = []

    def _trace_body(self, body: list[ast.stmt], function: str) -> None:
        tracer = FunctionTracer(self.filename, function)
        for statement in body:
            tracer.visit(statement)
        self.findings.extend(tracer.findings)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._trace_body(node.body, node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def trace_module(self, tree: ast.Module) -> None:
        module_body = [node for node in tree.body if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        self._trace_body(module_body, "<module>")
        self.visit(tree)


def scan(path: Path) -> list[Finding]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    tracer = ModuleTracer(str(path))
    tracer.trace_module(tree)
    unique = {(f.rule_id, f.source_line, f.sink_line, f.function): f for f in tracer.findings}
    return sorted(unique.values(), key=lambda f: (f.file, f.sink_line, f.rule_id))


def sarif(findings: list[Finding]) -> dict:
    rules = {
        "PST001": "Untrusted data reaches process execution",
        "PST002": "Untrusted data reaches dynamic code evaluation",
        "PST003": "Untrusted data reaches SQL execution",
    }
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "PySinkTrace", "rules": [
            {"id": key, "shortDescription": {"text": value}} for key, value in rules.items()
        ]}},
        "results": [{
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity in {"critical", "high"} else "warning",
            "message": {"text": finding.message + f" via {finding.source}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.file}, "region": {"startLine": finding.sink_line}}}],
            "properties": asdict(finding),
        } for finding in findings],
    }]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", type=Path, nargs="+")
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--fail-on-findings", action="store_true")
    args = parser.parse_args()
    files = sorted({file for path in args.paths for file in ([path] if path.is_file() else path.rglob("*.py"))})
    findings = [finding for file in files for finding in scan(file)]
    payload = sarif(findings) if args.format == "sarif" else {"findings": [asdict(f) for f in findings]}
    output = json.dumps(payload, indent=2)
    args.output.write_text(output, encoding="utf-8") if args.output else print(output)
    return 1 if findings and args.fail_on_findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
