"""
ZAP XML Ingestor — parses OWASP ZAP and Netsparker/Invicti reports.

Supports:
- OWASP ZAP XML export (native format)
- Netsparker/Invicti XML export (compatible structure)
- Generic DAST XML formats with similar structure

ZAP XML structure:
<OWASPZAPReport>
  <site host="..." port="..." ...>
    <alerts>
      <alertitem>
        <alert>XSS</alert>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <cweid>79</cweid>
        <uri>http://example.com/page</uri>
        ...
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>
"""

import logging
from pathlib import Path
from typing import Optional
from xml.etree import ElementTree as ET

from src.core.exceptions import ZAPParseError
from src.ingestors.sarif_ingestor import NormalizedFinding

logger = logging.getLogger(__name__)


class ZAPIngestor:
    """
    Parses OWASP ZAP XML reports into normalized findings.

    Also handles Netsparker/Invicti XML exports which share
    a similar structure of vulnerability alerts with URL evidence.
    """

    # ZAP riskcode → severity
    RISK_MAP = {
        "0": "Informational",
        "1": "Low",
        "2": "Medium",
        "3": "High",
    }

    # ZAP confidence level → float
    CONFIDENCE_MAP = {
        "0": 0.2,   # False Positive
        "1": 0.4,   # Low
        "2": 0.7,   # Medium
        "3": 0.9,   # High
        "4": 1.0,   # Confirmed
    }

    def parse(self, xml_path: Path) -> list[NormalizedFinding]:
        """
        Parse a ZAP/Netsparker XML report.

        Args:
            xml_path: Path to the XML report file

        Returns:
            List of normalized findings

        Raises:
            ZAPParseError: If the file cannot be parsed
        """
        logger.info(f"Parsing DAST report: {xml_path}")

        try:
            tree = ET.parse(str(xml_path))
            root = tree.getroot()
        except FileNotFoundError:
            raise ZAPParseError(f"Report file not found: {xml_path}")
        except ET.ParseError as e:
            raise ZAPParseError(f"Invalid XML in report: {e}")

        # Detect format and parse accordingly
        root_tag = root.tag.lower()

        if root_tag == "owaspzapreport" or root_tag == "report":
            findings = self._parse_zap_format(root)
        elif root_tag == "netsparker" or root_tag == "invicti":
            findings = self._parse_netsparker_format(root)
        else:
            # Try generic alert-based format
            findings = self._parse_generic_format(root)

        logger.info(f"Parsed {len(findings)} DAST findings from {xml_path.name}")
        return findings

    def parse_string(self, xml_content: str) -> list[NormalizedFinding]:
        """Parse XML content from a string (for API uploads)."""
        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            raise ZAPParseError(f"Invalid XML: {e}")

        root_tag = root.tag.lower()
        if root_tag == "owaspzapreport" or root_tag == "report":
            return self._parse_zap_format(root)
        elif root_tag == "netsparker" or root_tag == "invicti":
            return self._parse_netsparker_format(root)
        return self._parse_generic_format(root)

    def _parse_zap_format(self, root: ET.Element) -> list[NormalizedFinding]:
        """Parse OWASP ZAP native XML format."""
        findings = []
        finding_index = 0

        # ZAP structure: <site> → <alerts> → <alertitem>
        for site in root.iter("site"):
            host = site.get("host", "unknown")
            port = site.get("port", "")
            ssl = site.get("ssl", "false")
            base_url = f"{'https' if ssl == 'true' else 'http'}://{host}"
            if port and port not in ["80", "443"]:
                base_url += f":{port}"

            # Find alerts - could be directly under site or nested
            alerts = site.find("alerts")
            if alerts is None:
                alerts = site

            for alert_item in alerts.iter("alertitem"):
                finding = self._parse_zap_alert(alert_item, base_url, finding_index)
                if finding:
                    findings.append(finding)
                    finding_index += 1

        # Also check for direct alertitem elements (some ZAP exports)
        if not findings:
            for alert_item in root.iter("alertitem"):
                finding = self._parse_zap_alert(alert_item, "", finding_index)
                if finding:
                    findings.append(finding)
                    finding_index += 1

        return findings

    def _parse_zap_alert(
        self, alert_item: ET.Element, base_url: str, index: int
    ) -> Optional[NormalizedFinding]:
        """Parse a single ZAP alert item."""
        try:
            alert_name = self._get_text(alert_item, "alert", "Unknown Alert")
            risk_code = self._get_text(alert_item, "riskcode", "2")
            confidence_code = self._get_text(alert_item, "confidence", "2")
            description = self._get_text(alert_item, "desc", "")
            solution = self._get_text(alert_item, "solution", "")
            cwe_id_raw = self._get_text(alert_item, "cweid", "")
            wasc_id = self._get_text(alert_item, "wascid", "")
            plugin_id = self._get_text(alert_item, "pluginid", "")

            # Extract URLs from instances
            urls = []
            instances = alert_item.find("instances")
            if instances is not None:
                for instance in instances.iter("instance"):
                    uri = self._get_text(instance, "uri", "")
                    method = self._get_text(instance, "method", "GET")
                    param = self._get_text(instance, "param", "")
                    evidence = self._get_text(instance, "evidence", "")
                    if uri:
                        urls.append({
                            "uri": uri,
                            "method": method,
                            "param": param,
                            "evidence": evidence,
                        })

            # Fallback: check for direct uri element
            if not urls:
                uri = self._get_text(alert_item, "uri", "")
                if uri:
                    urls.append({"uri": uri, "method": "GET", "param": "", "evidence": ""})

            # Map severity
            severity = self.RISK_MAP.get(risk_code, "Medium")
            confidence = self.CONFIDENCE_MAP.get(confidence_code, 0.7)

            # Build CWE reference
            cwe_id = f"CWE-{cwe_id_raw}" if cwe_id_raw and cwe_id_raw != "0" else None

            # Primary URL for this finding
            primary_url = urls[0]["uri"] if urls else base_url

            # Clean HTML from description
            description_clean = self._strip_html(description)
            solution_clean = self._strip_html(solution)

            return NormalizedFinding(
                id=f"zap-{index}-{plugin_id or alert_name[:20]}",
                title=alert_name,
                description=description_clean,
                severity=severity,
                confidence=confidence,
                cwe_id=cwe_id,
                url=primary_url,
                tool_name="OWASP ZAP",
                rule_id=plugin_id or None,
                category=self._categorize_alert(alert_name),
                fix_suggestion=solution_clean if solution_clean else None,
                metadata={
                    "risk_code": risk_code,
                    "confidence_code": confidence_code,
                    "wasc_id": wasc_id,
                    "total_instances": str(len(urls)),
                    "methods": ", ".join(set(u["method"] for u in urls)),
                    "affected_params": ", ".join(set(u["param"] for u in urls if u["param"])),
                },
            )

        except Exception as e:
            logger.warning(f"Failed to parse ZAP alert at index {index}: {e}")
            return None

    def _parse_netsparker_format(self, root: ET.Element) -> list[NormalizedFinding]:
        """
        Parse Netsparker/Invicti XML format.

        Netsparker structure:
        <netsparker>
          <vulnerability>
            <url>...</url>
            <type>SqlInjection</type>
            <severity>High</severity>
            <certainty>95</certainty>
            ...
          </vulnerability>
        </netsparker>
        """
        findings = []

        for index, vuln in enumerate(root.iter("vulnerability")):
            try:
                vuln_type = self._get_text(vuln, "type", "Unknown")
                url = self._get_text(vuln, "url", "")
                severity_raw = self._get_text(vuln, "severity", "Medium")
                certainty = self._get_text(vuln, "certainty", "70")
                description = self._get_text(vuln, "description", "")
                remedy = self._get_text(vuln, "remedy", "")
                cwe_raw = self._get_text(vuln, "classification/cwe", "")

                # Map severity (Netsparker uses: Critical, High, Medium, Low, Information)
                severity_map = {
                    "critical": "Critical",
                    "high": "High",
                    "medium": "Medium",
                    "low": "Low",
                    "information": "Informational",
                    "informational": "Informational",
                }
                severity = severity_map.get(severity_raw.lower(), severity_raw)

                # Confidence from certainty percentage
                try:
                    confidence = float(certainty) / 100.0
                except ValueError:
                    confidence = 0.7

                cwe_id = f"CWE-{cwe_raw}" if cwe_raw else None

                finding = NormalizedFinding(
                    id=f"netsparker-{index}-{vuln_type[:30]}",
                    title=self._humanize_vuln_type(vuln_type),
                    description=self._strip_html(description),
                    severity=severity,
                    confidence=confidence,
                    cwe_id=cwe_id,
                    url=url,
                    tool_name="Netsparker/Invicti",
                    rule_id=vuln_type,
                    category=self._categorize_alert(vuln_type),
                    fix_suggestion=self._strip_html(remedy) if remedy else None,
                    metadata={
                        "certainty": certainty,
                        "vuln_type": vuln_type,
                    },
                )
                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse Netsparker vulnerability {index}: {e}")

        return findings

    def _parse_generic_format(self, root: ET.Element) -> list[NormalizedFinding]:
        """Attempt to parse a generic vulnerability XML format."""
        findings = []

        # Try common element names
        vuln_tags = ["vulnerability", "issue", "finding", "alert", "result"]

        for tag in vuln_tags:
            for index, elem in enumerate(root.iter(tag)):
                title = (
                    self._get_text(elem, "name", "")
                    or self._get_text(elem, "title", "")
                    or self._get_text(elem, "alert", "")
                    or f"Finding {index}"
                )
                url = self._get_text(elem, "url", "") or self._get_text(elem, "uri", "")
                severity = (
                    self._get_text(elem, "severity", "")
                    or self._get_text(elem, "risk", "Medium")
                )
                description = self._get_text(elem, "description", "")

                finding = NormalizedFinding(
                    id=f"generic-{index}",
                    title=title,
                    description=self._strip_html(description),
                    severity=severity.title(),
                    confidence=0.6,
                    url=url or None,
                    tool_name="Generic DAST",
                    metadata={"source_tag": tag},
                )
                findings.append(finding)

            if findings:
                break  # Found results with this tag

        return findings

    # ──── HELPERS ────────────────────────────────────────────────────────

    def _get_text(self, element: ET.Element, path: str, default: str = "") -> str:
        """Safely get text content from an XML element by path."""
        # Handle nested paths (e.g., "classification/cwe")
        parts = path.split("/")
        current = element
        for part in parts:
            child = current.find(part)
            if child is None:
                return default
            current = child
        return (current.text or "").strip() if current is not None else default

    def _strip_html(self, text: str) -> str:
        """Remove HTML tags from text."""
        import re

        if not text:
            return ""
        # Remove HTML tags
        clean = re.sub(r"<[^>]+>", "", text)
        # Normalize whitespace
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean

    def _categorize_alert(self, alert_name: str) -> str:
        """Categorize a vulnerability alert name into a high-level category."""
        name_lower = alert_name.lower()

        categories = {
            "injection": ["sql", "injection", "sqli", "command", "ldap", "xpath"],
            "xss": ["xss", "cross-site scripting", "script"],
            "authentication": ["auth", "login", "session", "password", "credential"],
            "information_disclosure": ["disclosure", "information", "leak", "exposure", "header"],
            "configuration": ["config", "misconfiguration", "header", "tls", "ssl", "cors"],
            "access_control": ["access", "permission", "privilege", "idor", "authorization"],
            "cryptography": ["crypto", "cipher", "encrypt", "certificate", "ssl", "tls"],
        }

        for category, keywords in categories.items():
            if any(kw in name_lower for kw in keywords):
                return category

        return "other"

    def _humanize_vuln_type(self, vuln_type: str) -> str:
        """Convert a camelCase/PascalCase vulnerability type to human-readable text."""
        import re

        # Insert spaces before capitals
        spaced = re.sub(r"([A-Z])", r" \1", vuln_type).strip()
        # Handle common abbreviations
        spaced = spaced.replace("Sql", "SQL").replace("Xss", "XSS")
        spaced = spaced.replace("Csrf", "CSRF").replace("Ssl", "SSL")
        return spaced
