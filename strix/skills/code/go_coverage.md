---
name: go_coverage
description: Go test coverage — run go test with coverprofile, parse output, report low-coverage packages
---

# Go Test Coverage

Measure test coverage using the built-in `go test` toolchain. No extra install required.

## Prerequisites

```bash
cd /workspace/<subdir>
go version  # Verify Go is available
go mod download 2>&1 || go mod tidy 2>&1  # Ensure dependencies are present
```

## Run

```bash
cd /workspace/<subdir>
go test \
  -coverprofile=/tmp/coverage.out \
  -covermode=atomic \
  -timeout 300s \
  ./... 2>&1 | tee /tmp/go_test_output.txt
```

If some packages fail to compile (common in partial repos):
```bash
go test -coverprofile=/tmp/coverage.out -covermode=atomic -timeout 300s \
  $(go list ./... 2>/dev/null | grep -v 'integration\|e2e\|cmd/main') 2>&1
```

## Parse Coverage

```bash
# Per-function breakdown
go tool cover -func=/tmp/coverage.out | tee /tmp/coverage_func.txt

# Total coverage line
grep "^total:" /tmp/coverage_func.txt
```

Example output:
```
github.com/example/repo/internal/auth.ValidateToken   87.5%
github.com/example/repo/internal/db.QueryUser          12.3%
github.com/example/repo/internal/db.QueryAll            0.0%
total:                                              (statements)     47.2%
```

## Reporting Strategy

1. Record overall coverage as one `info` finding (always):
```python
create_code_finding(
    finding_type="coverage",
    severity="info",
    rule_id="go-coverage-total",
    file_path=".",
    line_number=0,
    description=f"Overall Go test coverage: {total_pct}% ({statements} statements)",
    impact=f"{'Insufficient' if total_pct < 60 else 'Adequate'} coverage. Below 60% significantly increases risk of undetected defects.",
    source_tool="go-coverage",
)
```

2. For each function with coverage **below 20%** in a non-test, non-generated file:
```python
create_code_finding(
    finding_type="coverage",
    severity="medium" if pct == 0 else "low",
    rule_id="go-coverage-function",
    file_path=file_relative,
    line_number=0,
    description=f"Function {func_name} has {pct:.1f}% coverage ({file_relative})",
    impact=f"Untested function {func_name} may contain latent bugs or security defects that regression testing would catch. Risk is higher for auth, crypto, or input handling functions.",
    source_tool="go-coverage",
)
```

Only report the **10 lowest-coverage functions** to avoid noise. Prioritize:
- Files in `auth/`, `crypto/`, `db/`, `handler/`, `middleware/` packages
- Functions that start with `Validate`, `Check`, `Parse`, `Execute`, `Handle`

## Thresholds

| Coverage | Severity  | Meaning                                 |
|----------|-----------|-----------------------------------------|
| < 20%    | medium    | Severe gap; high risk                   |
| 20-40%   | low       | Insufficient; needs attention           |
| 40-60%   | info      | Below recommended threshold (60-80%)    |
| > 60%    | info      | Acceptable; note in summary             |
| > 80%    | info      | Good; note in summary                   |

## agent_finish Summary Format

```
go-coverage: total=47.2% (statements). Packages with 0% coverage: 3. Lowest: internal/db/query.go.
Tests run: 142 passed, 3 failed (failing tests noted separately if compilation errors).
```

If `go test` fails entirely (e.g., compilation errors):
```
go-coverage: skipped — go test failed to compile. Errors: <first 200 chars of stderr>.
```
