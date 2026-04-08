---
name: gitleaks
description: Secrets detection — run gitleaks on repo and git history, parse JSON output, report leaked credentials
---

# gitleaks

[gitleaks](https://github.com/gitleaks/gitleaks) detects hardcoded secrets, API keys, tokens, and credentials in source files and git history.

## Check Availability

```bash
which gitleaks || echo "NOT_INSTALLED"
```

If not installed:
```bash
# Try package manager
apt-get install gitleaks -y 2>/dev/null || brew install gitleaks 2>/dev/null

# Or download binary
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_amd64.tar.gz \
  | tar -xz -C /usr/local/bin gitleaks 2>&1
which gitleaks || echo "gitleaks unavailable"
```

If unavailable, record `tools_skipped="gitleaks: not installed"` and stop.

## Run — Current Files

```bash
cd /workspace/<subdir>
gitleaks detect \
  --source . \
  --report-format json \
  --report-path /tmp/gitleaks_results.json \
  --no-git \
  2>&1
cat /tmp/gitleaks_results.json
```

## Run — Git History (if repo has git)

```bash
cd /workspace/<subdir>
git log --oneline 2>/dev/null | wc -l  # check if git repo

gitleaks detect \
  --source . \
  --report-format json \
  --report-path /tmp/gitleaks_git_results.json \
  2>&1  # scans git history by default
cat /tmp/gitleaks_git_results.json
```

## Output Schema

```json
[
  {
    "Description": "AWS Access Token",
    "StartLine": 14,
    "EndLine": 14,
    "StartColumn": 13,
    "EndColumn": 33,
    "Match": "AKIAIOSFODNN7EXAMPLE",
    "Secret": "AKIAIOSFODNN7EXAMPLE",
    "File": "config/staging.yaml",
    "Commit": "a3f2c1b",
    "Author": "dev@example.com",
    "Date": "2024-01-15T10:30:00Z",
    "RuleID": "aws-access-token",
    "Tags": ["key", "AWS"]
  }
]
```

If output is `[]` or file is empty, no secrets were found.

## Severity Mapping

| Rule pattern                              | Severity |
|-------------------------------------------|----------|
| `aws-access-token`, `aws-secret-key`      | critical |
| `gcp-*`, `azure-*`, `github-*-token`      | critical |
| `private-key`, `rsa-private-key`          | critical |
| `password`, `passwd`, `secret`            | high     |
| `api-key`, `api-token`                    | high     |
| `jwt`, `bearer`                           | high     |
| `generic-api-key` (low confidence)        | medium   |

## Reporting

```python
for finding in gitleaks_results:
    rule_id = finding.get("RuleID", "unknown")
    secret_preview = finding.get("Secret", "")[:8] + "..." if finding.get("Secret") else ""

    severity = derive_severity(rule_id)
    file_rel = finding.get("File", "unknown")
    commit_info = f" (commit: {finding['Commit'][:8]})" if finding.get("Commit") else ""

    create_code_finding(
        finding_type="secret",
        severity=severity,
        rule_id=rule_id,
        file_path=file_rel,
        line_number=finding.get("StartLine", 0),
        description=f'Hardcoded secret detected by gitleaks rule "{rule_id}" in {file_rel}:{finding.get("StartLine","?")}{commit_info}. Matched pattern: {finding.get("Description","")}.  Secret preview (redacted): {secret_preview}',
        impact=derive_impact(rule_id, finding),
        source_tool="gitleaks",
        cwe="CWE-798",
        remediation="1. Immediately rotate/revoke the exposed credential. 2. Remove from source and git history (git filter-branch or BFG). 3. Add pre-commit hooks (gitleaks / detect-secrets) to prevent future leaks.",
    )
```

Impact derivation:
- AWS key: "Attacker can authenticate to AWS services; depending on IAM policy could lead to S3 data exfiltration, EC2 takeover, or full account compromise"
- Private key: "Attacker can impersonate the key holder; decrypt TLS traffic; forge signatures"
- DB password: "Attacker gains direct database access; full data exfiltration, modification, or destruction"
- Generic API key: "Attacker can use the API key to invoke authenticated endpoints; scope depends on key permissions"

## Deduplication

If the same secret appears in both file scan and git history scan, report ONCE. Note in description: `"also found in git history at commit <sha>"`.

## agent_finish Summary Format

```
gitleaks: <N> secrets found. Critical: AWS key in config/staging.yaml. High: DB password in .env.example.
Scanned: current files + git history (<N> commits).
```

If zero findings:
```
gitleaks: no secrets detected (0 findings). Scanned: current files + git history.
```
