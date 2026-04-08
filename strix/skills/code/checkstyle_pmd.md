---
name: checkstyle_pmd
description: Java code quality — run Checkstyle and PMD, parse XML/JSON output, report quality findings
---

# Checkstyle + PMD (Java)

Run both tools for maximum Java quality coverage:
- **Checkstyle**: style, naming, Javadoc
- **PMD**: bug patterns, complexity, best practices

## Check Availability

```bash
which checkstyle && echo "checkstyle OK" || echo "checkstyle NOT_INSTALLED"
which pmd && echo "pmd OK" || echo "pmd NOT_INSTALLED"
```

If checkstyle not found, try:
```bash
ls /opt/checkstyle* /usr/local/bin/checkstyle* 2>/dev/null
# Or run via Maven plugin if pom.xml present
```

If PMD not found, try:
```bash
ls /opt/pmd* /usr/local/bin/pmd* 2>/dev/null
```

## Run — Checkstyle

```bash
cd /workspace/<subdir>

# Try standalone binary first
checkstyle -c /google_checks.xml -f xml -o /tmp/checkstyle_results.xml -r src/ 2>&1

# If not installed, run via Maven plugin
mvn checkstyle:check -Dcheckstyle.config.location=google_checks \
    -Dcheckstyle.output.format=xml \
    -Dcheckstyle.output.file=/tmp/checkstyle_results.xml 2>&1
```

Checkstyle XML output:
```xml
<checkstyle version="10.0">
  <file name="/workspace/repo/src/main/java/com/example/App.java">
    <error line="42" column="5" severity="error"
           message="Variable 'password' must be private, it is package protected."
           source="com.puppycrawl.tools.checkstyle.checks.design.VisibilityModifierCheck"/>
  </file>
</checkstyle>
```

## Run — PMD

```bash
cd /workspace/<subdir>

# Standalone PMD
pmd check \
  -d src/ \
  -R rulesets/java/quickstart.xml,rulesets/java/security.xml \
  -f json \
  --report-file /tmp/pmd_results.json \
  --minimum-priority 3 2>&1

# Or via Maven
mvn pmd:pmd -Dpmd.outputFormat=json 2>&1
cat target/pmd.json
```

PMD JSON output:
```json
{
  "formatVersion": 0,
  "pmdVersion": "7.0.0",
  "files": [
    {
      "filename": "/workspace/repo/src/.../App.java",
      "violations": [
        {
          "rule": "SystemPrintln",
          "ruleset": "Best Practices",
          "priority": 2,
          "beginline": 15,
          "description": "System.out.println is used",
          "externalInfoUrl": "..."
        }
      ]
    }
  ]
}
```

## Severity Mapping

Checkstyle:
- `error` → medium
- `warning` → low
- `info` → info

PMD priority:
- 1 (High) → high
- 2 (Medium-High) → medium
- 3 (Medium) → medium
- 4 (Medium-Low) → low
- 5 (Low) → info

Promote to `high` if rule name contains: `Security`, `Injection`, `HardCodedPassword`, `DoPrivileged`, `CryptographicHash`

## Reporting

Checkstyle:
```python
for file_elem in checkstyle_xml:
    file_rel = file_elem.attrib["name"].replace("/workspace/<subdir>/", "")
    for error in file_elem:
        create_code_finding(
            finding_type="quality",
            severity=cs_severity_map[error.attrib.get("severity","warning")],
            rule_id=error.attrib["source"].split(".")[-1],
            file_path=file_rel,
            line_number=int(error.attrib["line"]),
            description=f'Checkstyle: {error.attrib["message"]} ({error.attrib["source"].split(".")[-1]})',
            impact="Code quality violation; may indicate hidden logic error or security issue if field visibility or error handling is involved",
            source_tool="checkstyle",
        )
```

PMD:
```python
for file_entry in pmd_results["files"]:
    file_rel = file_entry["filename"].replace("/workspace/<subdir>/", "")
    for v in file_entry["violations"]:
        create_code_finding(
            finding_type="quality",
            severity=pmd_priority_map[v["priority"]],
            rule_id=v["rule"],
            file_path=file_rel,
            line_number=v["beginline"],
            description=f'PMD {v["ruleset"]}/{v["rule"]}: {v["description"]} at {file_rel}:{v["beginline"]}',
            impact=derive_impact_java(v["rule"], v["ruleset"]),
            source_tool="pmd",
        )
```

## Impact Derivation (Java)

- `HardCodedPassword` / `HardCodedCryptoKey`: Credential exposed in source; auth bypass if key is valid; rotate immediately
- `SQL*` / `*Injection*`: SQL injection potential; database compromise
- `CryptographicHash` (MD5/SHA1): Weak hash; integrity bypass, password cracking
- `SystemPrintln`: Sensitive data may reach logs; information disclosure
- `EmptyCatchBlock`: Silent failure; undetected errors in production
- `VisibilityModifier`: Broader access than needed; encapsulation violation; harder to reason about security boundary

## agent_finish Summary Format

```
checkstyle: <N> issues.
pmd: <M> violations (high=X, medium=Y, low=Z).
Tools skipped: <list if any>.
```
