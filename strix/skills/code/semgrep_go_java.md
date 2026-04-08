---
name: semgrep_go_java
description: Semgrep SAST for Go and Java — run with security rulesets, parse JSON output, report findings
---

# semgrep (Go + Java)

[semgrep](https://semgrep.dev) is a fast, source-aware static analysis tool. Use the OWASP/security rulesets for Go and Java.

## Check Availability

```bash
which semgrep || echo "NOT_INSTALLED"
```

If not installed:
```bash
pip install semgrep 2>&1 || pipx install semgrep 2>&1
which semgrep || echo "semgrep unavailable"
```

If unavailable, record `tools_skipped="semgrep: not installed"` and stop.

## Run — Go

```bash
cd /workspace/<subdir>
semgrep scan \
  --config p/golang \
  --config p/secrets \
  --config p/owasp-top-ten \
  --json \
  --timeout 120 \
  --output /tmp/semgrep_results.json \
  2>&1
cat /tmp/semgrep_results.json
```

## Run — Java

```bash
cd /workspace/<subdir>
semgrep scan \
  --config p/java \
  --config p/secrets \
  --config p/owasp-top-ten \
  --json \
  --timeout 180 \
  --output /tmp/semgrep_results.json \
  2>&1
cat /tmp/semgrep_results.json
```

For large repos, scope to relevant paths:
```bash
semgrep scan --config p/java --json --timeout 180 -o /tmp/semgrep_results.json src/ 2>&1
```

## Output Schema

```json
{
  "results": [
    {
      "check_id": "go.lang.security.audit.crypto.use-of-md5.use-of-md5",
      "path": "internal/hash.go",
      "start": {"line": 23},
      "end": {"line": 23},
      "extra": {
        "message": "Detected MD5 hash algorithm...",
        "severity": "WARNING",
        "metadata": {"cwe": ["CWE-327"], "owasp": ["A02:2021"]}
      }
    }
  ],
  "errors": []
}
```

## Severity Mapping

| semgrep severity | strix severity |
|------------------|---------------|
| ERROR            | high           |
| WARNING          | medium         |
| INFO             | low            |

Upgrade to `critical` if:
- `check_id` contains `injection`, `sqli`, `rce`, `command`, `ssrf`, `secrets`, `hardcoded`
- `metadata.cwe` includes CWE-89, CWE-78, CWE-798, CWE-22

## Reporting

```python
for result in semgrep_results["results"]:
    severity = map_severity(result["extra"]["severity"])
    file_rel = result["path"]  # already relative
    cwe_list = result["extra"].get("metadata", {}).get("cwe", [])
    cwe = cwe_list[0] if cwe_list else ""

    create_code_finding(
        finding_type="sast",
        severity=severity,
        rule_id=result["check_id"].split(".")[-1],  # last segment
        file_path=file_rel,
        line_number=result["start"]["line"],
        description=f'{result["check_id"]} at {file_rel}:{result["start"]["line"]}: {result["extra"]["message"][:300]}',
        impact="<derive from check_id and CWE>",
        source_tool="semgrep",
        cwe=cwe,
    )
```

Skip results with `check_id` containing `test` or `tests` path unless severity is high/critical.

## Deduplication with gosec

If both gosec and semgrep flag the same line for the same issue:
- Report ONCE with `source_tool="semgrep"` and note `also detected by gosec` in description
- Do NOT call `create_code_finding` twice for identical file+line+rule

## agent_finish Summary Format

```
semgrep: <N> findings (high=X, medium=Y, low=Z). Rulesets: p/golang, p/secrets, p/owasp-top-ten. Errors: <count>.
```
