"""
SARIF Ingestor — parses Static Analysis Results Interchange Format (SARIF).

SARIF is the standard output format for:
- Coverity (SAST)
- Semgrep
- CodeQL
- Bandit
- SpotBugs / FindSecBugs

SARIF Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import logging
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from src.core.exceptions import SARIFParseError

logger = logging.getLogger(__name__)


class NormalizedFinding(BaseModel):
    """A normalized SAST/DAST finding (common format for all ingestors)."""

    id: str
    title: str
    description: str = ""
    severity: str = "Medium"
    confidence: float = 0.7
    cwe_id: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    column: Optional[int] = None
    url: Optional[str] = None
    tool_name: str = ""
    rule_id: Optional[str] = None
    category: Optional[str] = None
    snippet: Optional[str] = None
    fix_suggestion: Optional[str] = None
    metadata: dict[str, str] = Field(default_factory=dict)


class SARIFIngestor:
    """
    Parses SARIF v2.1.0 files into normalized findings.

    Handles:
    - Single-run and multi-run SARIF files
    - Multiple results per run
    - CWE extraction from rule metadata
    - Severity mapping (SARIF level → normalized severity)
    - Code snippet extraction from regions
    """

    # SARIF level → normalized severity
    SEVERITY_MAP = {
        "error": "High",
        "warning": "Medium",
        "note": "Low",
        "none": "Informational",
    }

    def parse(self, sarif_path: Path) -> list[NormalizedFinding]:
        """
        Parse a SARIF file and return normalized findings.

        Args:
            sarif_path: Path to the SARIF JSON file

        Returns:
            List of normalized findings

        Raises:
            SARIFParseError: If the file cannot be parsed
        """
        logger.info(f"Parsing SARIF file: {sarif_path}")

        try:
            content = sarif_path.read_text(encoding="utf-8")
            sarif_data = json.loads(content)
        except FileNotFoundError:
            raise SARIFParseError(f"SARIF file not found: {sarif_path}")
        except json.JSONDecodeError as e:
            raise SARIFParseError(f"Invalid JSON in SARIF file: {e}")

        # Validate SARIF structure
        if "$schema" not in sarif_data and "version" not in sarif_data:
            raise SARIFParseError("File does not appear to be valid SARIF format")

        version = sarif_data.get("version", "unknown")
        logger.info(f"SARIF version: {version}")

        findings: list[NormalizedFinding] = []

        # Process each run
        runs = sarif_data.get("runs", [])
        for run_index, run in enumerate(runs):
            tool = run.get("tool", {}).get("driver", {})
            tool_name = tool.get("name", "unknown")
            rules = self._build_rule_index(tool.get("rules", []))

            results = run.get("results", [])
            logger.info(f"Run {run_index} ({tool_name}): {len(results)} results")

            for result_index, result in enumerate(results):
                finding = self._parse_result(
                    result, tool_name, rules, run_index, result_index
                )
                if finding:
                    findings.append(finding)

        logger.info(f"Parsed {len(findings)} findings from {sarif_path.name}")
        return findings

    def parse_string(self, sarif_json: str) -> list[NormalizedFinding]:
        """Parse SARIF content from a string (for API uploads)."""
        try:
            sarif_data = json.loads(sarif_json)
        except json.JSONDecodeError as e:
            raise SARIFParseError(f"Invalid JSON: {e}")

        # Write to temp and reuse file parser logic
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".sarif", delete=False) as f:
            f.write(sarif_json)
            temp_path = Path(f.name)

        try:
            return self.parse(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def _parse_result(
        self,
        result: dict,
        tool_name: str,
        rules: dict[str, dict],
        run_index: int,
        result_index: int,
    ) -> Optional[NormalizedFinding]:
        """Parse a single SARIF result into a NormalizedFinding."""
        try:
            rule_id = result.get("ruleId", "")
            rule_index = result.get("ruleIndex")

            # Get rule metadata
            rule_meta = rules.get(rule_id, {})
            if not rule_meta and rule_index is not None:
                # Try by index
                rule_meta = rules.get(str(rule_index), {})

            # Extract message
            message = result.get("message", {})
            title = message.get("text", rule_meta.get("shortDescription", "Unknown finding"))
            description = message.get("markdown", message.get("text", ""))

            # Extract severity from level
            level = result.get("level", "warning")
            severity = self.SEVERITY_MAP.get(level, "Medium")

            # Override severity from rule properties if available
            rule_severity = rule_meta.get("defaultConfiguration", {}).get("level")
            if rule_severity:
                severity = self.SEVERITY_MAP.get(rule_severity, severity)

            # Extract location
            file_path = None
            line_number = None
            column = None
            snippet = None

            locations = result.get("locations", [])
            if locations:
                location = locations[0]
                physical = location.get("physicalLocation", {})
                artifact = physical.get("artifactLocation", {})
                file_path = artifact.get("uri", "")

                # Remove file:// prefix if present
                if file_path and file_path.startswith("file://"):
                    file_path = file_path[7:]

                region = physical.get("region", {})
                line_number = region.get("startLine")
                column = region.get("startColumn")

                # Extract code snippet
                snippet_data = region.get("snippet", {})
                snippet = snippet_data.get("text")

            # Extract CWE
            cwe_id = self._extract_cwe(rule_meta, result)

            # Build finding ID
            finding_id = f"sarif-{run_index}-{result_index}-{rule_id or 'unknown'}"

            return NormalizedFinding(
                id=finding_id,
                title=self._truncate(title, 200),
                description=self._truncate(description, 1000),
                severity=severity,
                confidence=self._calculate_confidence(result, rule_meta),
                cwe_id=cwe_id,
                file_path=file_path,
                line_number=line_number,
                column=column,
                tool_name=tool_name,
                rule_id=rule_id,
                category=rule_meta.get("category", None),
                snippet=snippet,
                fix_suggestion=self._extract_fix(result, rule_meta),
                metadata={
                    "sarif_level": level,
                    "sarif_kind": result.get("kind", "fail"),
                    "rule_name": rule_meta.get("name", ""),
                },
            )

        except Exception as e:
            logger.warning(f"Failed to parse SARIF result {result_index}: {e}")
            return None

    def _build_rule_index(self, rules: list[dict]) -> dict[str, dict]:
        """Build a lookup index of rule definitions."""
        index = {}
        for i, rule in enumerate(rules):
            rule_id = rule.get("id", "")
            if rule_id:
                index[rule_id] = rule
            index[str(i)] = rule
        return index

    def _extract_cwe(self, rule_meta: dict, result: dict) -> Optional[str]:
        """Extract CWE ID from rule metadata or result properties."""
        # Check rule properties
        properties = rule_meta.get("properties", {})
        tags = properties.get("tags", [])
        for tag in tags:
            if tag.startswith("CWE-") or tag.startswith("cwe-"):
                return tag.upper()
            # Handle "external/cwe/cwe-89" format (CodeQL)
            if "/cwe/" in tag.lower():
                parts = tag.split("/")
                for part in parts:
                    if part.lower().startswith("cwe-"):
                        return part.upper()

        # Check relationships (SARIF 2.1.0)
        relationships = rule_meta.get("relationships", [])
        for rel in relationships:
            target = rel.get("target", {})
            target_id = target.get("id", "")
            if target_id.upper().startswith("CWE-"):
                return target_id.upper()

        # Check taxa (taxonomies)
        taxa = result.get("taxa", [])
        for taxon in taxa:
            if "cwe" in taxon.get("toolComponent", {}).get("name", "").lower():
                return f"CWE-{taxon.get('id', '')}"

        return None

    def _calculate_confidence(self, result: dict, rule_meta: dict) -> float:
        """Calculate confidence score from SARIF properties."""
        # Check for rank (probability) in properties
        properties = result.get("properties", {})
        if "confidence" in properties:
            try:
                return float(properties["confidence"])
            except (ValueError, TypeError):
                pass

        # Map SARIF level to confidence
        level = result.get("level", "warning")
        confidence_map = {
            "error": 0.9,
            "warning": 0.7,
            "note": 0.5,
            "none": 0.3,
        }
        return confidence_map.get(level, 0.7)

    def _extract_fix(self, result: dict, rule_meta: dict) -> Optional[str]:
        """Extract fix suggestion from result or rule help."""
        # Check fixes in result
        fixes = result.get("fixes", [])
        if fixes:
            fix_desc = fixes[0].get("description", {})
            return fix_desc.get("text")

        # Check rule help text
        help_text = rule_meta.get("help", {})
        if isinstance(help_text, dict):
            return help_text.get("text")

        # Check fullDescription
        full_desc = rule_meta.get("fullDescription", {})
        if isinstance(full_desc, dict):
            return full_desc.get("text")

        return None

    def _truncate(self, text: str, max_length: int) -> str:
        """Truncate text to max length."""
        if len(text) <= max_length:
            return text
        return text[: max_length - 3] + "..."
