# PySinkTrace

An explainable Python source-to-sink tracer for focused application-security
review. It shows the line-by-line path from an untrusted input to a sensitive
operation instead of returning a context-free pattern match.

## What it detects

| Rule | Flow |
| --- | --- |
| PST001 | request or console input → process execution |
| PST002 | request or console input → `eval` / `exec` |
| PST003 | request or console input → SQL execution |

The analyzer uses Python's AST, tracks assignments and expression propagation,
recognizes a small explicit sanitizer set, and can emit SARIF for code-scanning
interfaces. It also builds lightweight function summaries: request-source
wrappers and process/SQL sink wrappers are followed across calls, so helper
functions do not erase the evidence path.

## Install

```bash
git clone https://github.com/MEZ111/pysinktrace.git
cd pysinktrace
python3 -m pip install .
```

## Run

```bash
pysinktrace examples/vulnerable.py
pysinktrace src/ --format sarif -o results.sarif
pysinktrace src/ --fail-on-findings
```

Example trace:

```json
{
  "rule_id": "PST003",
  "source": "request.args.get",
  "source_line": 2,
  "sink": "cursor.execute",
  "sink_line": 4,
  "path": [2, 2, 3, 4]
}
```

## Design boundary

PySinkTrace is intentionally small and inspectable. It performs inter-statement
analysis plus bounded interprocedural tracing through local source and sink
wrappers; it does not claim whole-program soundness. Dynamic dispatch, aliases,
framework wrappers, recursion, and custom sanitizers can require manual review.
Findings identify review paths; they do not prove exploitability.

## Verification

```bash
PYTHONPATH=src python3 -m unittest -v tests/test_pysinktrace.py
```

Five tests verify assignment propagation, sanitizer handling, SQL sink mapping,
source wrappers, and sink wrappers.

## License

MIT
