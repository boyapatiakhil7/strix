---
name: golangci_lint
description: Go code quality — run golangci-lint, parse JSON output, report quality findings
---

# golangci-lint

[golangci-lint](https://golangci-lint.run) aggregates many Go linters into a single fast run. Use it for quality and correctness issues.

## Check Availability

```bash
which golangci-lint || echo "NOT_INSTALLED"
```

If not installed:
```bash
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin 2>&1
which golangci-lint || echo "golangci-lint unavailable"
```

If unavailable, record `tools_skipped="golangci-lint: not installed"` and stop.

## Run

```bash
cd /workspace/<subdir>
golangci-lint run \
  --out-format json \
  --timeout 5m \
  --enable errcheck,staticcheck,gosimple,unused,ineffassign,typecheck,govet \
  ./... 2>&1 | tee /tmp/golangci_results.json
```

If the run fails due to missing dependencies:
```bash
go mod download 2>&1
golangci-lint run --out-format json --timeout 5m ./... 2>&1 | tee /tmp/golangci_results.json
```

For vendor mode repos:
```bash
golangci-lint run --out-format json --timeout 5m --modules-download-mode vendor ./... 2>&1
```

## Output Schema

```json
{
  "Issues": [
    {
      "FromLinter": "errcheck",
      "Text": "Error return value of `db.Close` is not checked",
      "Pos": {
        "Filename": "internal/db/conn.go",
        "Line": 47,
        "Column": 2
      },
      "Severity": ""
    }
  ]
}
```

## Severity Mapping

| Linter        | Default severity | Notes                                              |
|---------------|------------------|----------------------------------------------------|
| staticcheck   | medium           | SA* rules are medium; S* style are low             |
| errcheck      | medium           | unhandled errors can hide failures                 |
| govet         | medium           | printf format mismatches etc.                      |
| unused        | low              | dead code                                          |
| ineffassign   | low              | value assigned but never used                      |
| gosimple      | low              | simplification suggestions                         |
| typecheck     | high             | compilation failure — must fix                     |
| gosec         | skip             | gosec handles this separately                      |

## Reporting

```python
for issue in golangci_results["Issues"]:
    linter = issue["FromLinter"]
    if linter == "gosec":
        continue  # already covered by gosec agent

    severity = linter_severity_map.get(linter, "medium")
    file_rel = issue["Pos"]["Filename"]

    create_code_finding(
        finding_type="quality",
        severity=severity,
        rule_id=f'{linter}',
        file_path=file_rel,
        line_number=issue["Pos"]["Line"],
        description=f'{linter}: {issue["Text"]} at {file_rel}:{issue["Pos"]["Line"]}',
        impact=derive_impact(linter, issue["Text"]),
        source_tool="golangci-lint",
    )
```

Impact derivation by linter:
- `errcheck`: "Unhandled errors may mask failures silently, leading to incorrect program state or data loss"
- `typecheck`: "Code will not compile; blocks deployment"
- `staticcheck SA*`: "Incorrect assumption about library behaviour; potential runtime panic or data corruption"
- `unused`: "Dead code increases maintenance burden and may confuse future contributors"
- `ineffassign`: "Assignment has no effect; possible logic error where the value was intended to be used"

## Noise Filtering

Report issues from these linters only:
- `errcheck`, `staticcheck`, `gosimple`, `govet`, `unused`, `ineffassign`, `typecheck`

Skip:
- `gofmt`, `goimports`, `godot`, `wsl`, `nlreturn` — pure formatting, zero security relevance
- Any linter ending in `fmt`

## agent_finish Summary Format

```
golangci-lint: <N> issues (high=X, medium=Y, low=Z).
Linters triggered: errcheck (12), staticcheck (4), govet (2).
Linters skipped: gosec (handled by SAST agent).
```
