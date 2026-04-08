---
name: gosec
description: Go security scanner — run gosec, parse JSON output, report SAST findings
---

# gosec

[gosec](https://github.com/securego/gosec) inspects Go source code for security issues by checking the AST and SSA form against a set of rules.

## Check Availability

```bash
which gosec || echo "NOT_INSTALLED"
```

If not installed:
```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest 2>&1 || echo "install failed"
which gosec || echo "gosec unavailable"
```

If still unavailable, record `tools_skipped="gosec: not installed"` in `agent_finish` and stop.

## Run

```bash
cd /workspace/<subdir>
gosec -fmt json -out /tmp/gosec_results.json ./... 2>&1
cat /tmp/gosec_results.json
```

Flags:
- `-fmt json` — machine-readable output
- `-severity medium` — filter low-noise findings (optional; default reports all)
- `-confidence medium` — filter low-confidence findings
- `./...` — all packages recursively

If the repo has a `vendor/` directory:
```bash
gosec -fmt json -out /tmp/gosec_results.json -exclude-dir vendor ./... 2>&1
```

## Output Schema

```json
{
  "Issues": [
    {
      "rule_id": "G401",
      "details": "Use of weak cryptographic primitive",
      "file": "/workspace/repo/internal/hash.go",
      "line": "23",
      "severity": "HIGH",
      "confidence": "MEDIUM",
      "code": "crypto/md5.New()"
    }
  ],
  "Stats": {"files": 42, "lines": 3012, "nosec": 2, "found": 7}
}
```

## Reporting

For each issue in `Issues`:
```python
create_code_finding(
    finding_type="sast",
    severity=issue["severity"].lower(),   # HIGH → "high"
    rule_id=issue["rule_id"],             # "G401"
    file_path=issue["file"].replace("/workspace/<subdir>/", ""),  # strip prefix
    line_number=int(issue["line"]),
    description=f'{issue["rule_id"]}: {issue["details"]} in {file_relative}:{issue["line"]}. Code: {issue["code"].strip()}',
    impact="<derive from rule — see table below>",
    source_tool="gosec",
    cwe=rule_to_cwe.get(issue["rule_id"], ""),
    remediation="<see table below>",
)
```

## Key Rule Reference

| Rule  | Issue                            | CWE     | Impact                                              | Remediation                                     |
|-------|----------------------------------|---------|-----------------------------------------------------|-------------------------------------------------|
| G101  | Hardcoded credential             | CWE-798 | Credential exposure; auth bypass if key is valid    | Use env vars or secrets manager; rotate key     |
| G104  | Errors unhandled                 | CWE-391 | Undetected failures; silent data corruption         | Check all returned errors explicitly            |
| G107  | URL provided to HTTP request     | CWE-88  | SSRF if URL is user-controlled                      | Validate/allowlist URLs before use              |
| G202  | SQL query string formatting      | CWE-89  | SQL injection; full DB compromise                   | Use parameterised queries / prepared statements |
| G204  | Subprocess cmd built from var    | CWE-78  | OS command injection                                | Use exec.Command with separate args             |
| G304  | File path from variable          | CWE-22  | Path traversal; read arbitrary files                | Validate/clean path; use filepath.Clean         |
| G401  | Use of MD5                       | CWE-327 | Weak hash; collision attacks, broken integrity      | Replace with sha256/sha512; bcrypt for passwords|
| G402  | TLS MinVersion too low           | CWE-326 | Downgrade attacks; eavesdropping                    | Set tls.VersionTLS12 minimum                    |
| G501  | Import of crypto/md5 or sha1     | CWE-327 | Same as G401                                        | Same as G401                                    |
| G601  | Implicit memory aliasing in loop | CWE-118 | Pointer aliasing bug; incorrect behaviour           | Take explicit address: `v := v`                 |

## Noise Reduction

- `#nosec G101` on a line disables that rule for that line — note these in findings as "suppressed"
- `gosec` may flag test files (paths ending in `_test.go`) — include them; test credential leaks are still real
- Confidence LOW findings: report as `info` severity unless the rule is G101/G202/G204

## agent_finish Summary Format

```
gosec: <N> findings (critical=X, high=Y, medium=Z).
Rules triggered: G101, G202, G401.
Files scanned: <stats.files>.
```
