---
name: jacoco
description: Java test coverage via JaCoCo — run Maven/Gradle test with jacoco report, parse XML, report low-coverage classes
---

# JaCoCo (Java Coverage)

[JaCoCo](https://www.jacoco.org) produces line, branch, and method coverage for Java projects.

## Detect Build System

```bash
ls /workspace/<subdir>/pom.xml 2>/dev/null && echo "MAVEN"
ls /workspace/<subdir>/build.gradle 2>/dev/null && echo "GRADLE"
ls /workspace/<subdir>/build.gradle.kts 2>/dev/null && echo "GRADLE_KTS"
```

## Run — Maven

```bash
cd /workspace/<subdir>
mvn test jacoco:report \
  -Dmaven.test.failure.ignore=true \
  -q 2>&1 | tail -50

# Report location
find . -name "jacoco.xml" -o -name "jacoco-ut.xml" 2>/dev/null | head -5
```

If jacoco plugin is not in pom.xml:
```bash
mvn test jacoco:report \
  -Pjacoco \
  -Djacoco.version=0.8.11 2>&1 | tail -50
```

## Run — Gradle

```bash
cd /workspace/<subdir>

# Standard
./gradlew test jacocoTestReport --continue 2>&1 | tail -50

# Report location
find . -name "jacocoTestReport.xml" 2>/dev/null | head -5
```

If Gradle wrapper is not executable:
```bash
chmod +x gradlew && ./gradlew test jacocoTestReport --continue 2>&1 | tail -50
```

## Parse JaCoCo XML

```bash
cat build/reports/jacoco/test/jacocoTestReport.xml | head -100
# or
cat target/site/jacoco/jacoco.xml | head -100
```

JaCoCo XML structure:
```xml
<report name="...">
  <package name="com/example/service">
    <class name="com/example/service/AuthService" sourcefilename="AuthService.java">
      <method name="validateToken" desc="..." line="42">
        <counter type="INSTRUCTION" missed="12" covered="34"/>
        <counter type="BRANCH" missed="2" covered="4"/>
      </method>
      <counter type="LINE" missed="15" covered="42"/>
    </class>
    <counter type="LINE" missed="80" covered="200"/>
  </package>
  <counter type="LINE" missed="300" covered="1200"/>
</report>
```

## Coverage Calculation

```python
def line_pct(missed, covered):
    total = missed + covered
    return 0.0 if total == 0 else round(100.0 * covered / total, 1)

# Total coverage from root counter
total_covered = int(root_counter["LINE"]["covered"])
total_missed = int(root_counter["LINE"]["missed"])
total_pct = line_pct(total_missed, total_covered)
```

## Reporting Strategy

1. Overall summary (always report as `info`):
```python
create_code_finding(
    finding_type="coverage",
    severity="info",
    rule_id="jacoco-line-coverage-total",
    file_path=".",
    line_number=0,
    description=f"Overall JaCoCo line coverage: {total_pct}% ({total_covered}/{total_covered+total_missed} lines)",
    impact=f"{'Insufficient' if total_pct < 60 else 'Adequate'} coverage. Low coverage increases risk of undetected defects in production.",
    source_tool="jacoco",
)
```

2. Per-class low coverage (report top 10 lowest):
```python
for cls in sorted_low_coverage_classes[:10]:
    pct = cls["line_pct"]
    class_name = cls["name"].replace("/", ".")
    create_code_finding(
        finding_type="coverage",
        severity="medium" if pct < 20 else "low",
        rule_id="jacoco-class-low-coverage",
        file_path=cls["source_file"],   # relative path
        line_number=0,
        description=f"Class {class_name} has {pct:.1f}% line coverage ({cls['covered']} covered, {cls['missed']} missed)",
        impact=f"Untested class {class_name} may harbour latent defects. Security-sensitive classes with low coverage pose heightened risk for auth bypass, injection, or data corruption bugs.",
        source_tool="jacoco",
    )
```

## Thresholds (same as Go)

| Coverage | Severity  |
|----------|-----------|
| < 20%    | medium    |
| 20-40%   | low       |
| ≥ 40%    | info      |

Prioritise reporting classes in packages: `auth`, `security`, `crypto`, `controller`, `service`, `repository`, `filter`.

## agent_finish Summary Format

```
jacoco: total line coverage=54.3%. Classes with <20% coverage: 5. Lowest: AuthService.java at 8.3%.
Build: Maven/Gradle. Tests: <N> passed, <M> failed (test failures do not block coverage report).
```

If `mvn test` / `gradlew test` fails completely:
```
jacoco: skipped — build failed. Error: <first 200 chars>. Suggest: run `mvn dependency:resolve` first.
```
