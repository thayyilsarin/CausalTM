"""Detector for common code patterns (HTTP clients, DB queries, auth, crypto)."""

import logging
import re
from pathlib import Path

from src.analyzer.detectors.base import BaseDetector, DetectionResult
from src.analyzer.models.component import (
    Component,
    ComponentType,
    DataFlow,
    DataSensitivity,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class CodePatternDetector(BaseDetector):
    """
    Language-agnostic pattern detector using regex.

    Scans source files for common patterns that indicate:
    - HTTP client calls (outbound data flows)
    - Database queries (data store interactions)
    - Authentication/authorization logic
    - Cryptographic operations
    - File I/O operations
    - Logging/audit patterns
    """

    @property
    def name(self) -> str:
        return "Code Pattern Detector"

    @property
    def description(self) -> str:
        return "Detects data flows and security patterns from source code using regex heuristics"

    @property
    def target_files(self) -> list[str]:
        return [
            "*.py", "*.js", "*.ts", "*.java", "*.go", "*.rb",
            "*.cs", "*.php", "*.rs", "*.kt", "*.scala",
        ]

    def detect(self, repo_path: Path, files: list[Path]) -> DetectionResult:
        result = DetectionResult()
        source_files = self._filter_files(files)

        patterns_found: dict[str, list[str]] = {
            "http_clients": [],
            "db_queries": [],
            "auth_patterns": [],
            "crypto_patterns": [],
            "file_io": [],
            "logging": [],
        }

        for f in source_files:
            full_path = repo_path / f
            if not full_path.exists():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # Skip files that are too large (likely generated)
            if len(content) > 500_000:
                continue

            self._scan_http_clients(content, str(f), patterns_found)
            self._scan_db_queries(content, str(f), patterns_found)
            self._scan_auth_patterns(content, str(f), patterns_found)
            self._scan_crypto_patterns(content, str(f), patterns_found)
            self._scan_logging(content, str(f), patterns_found)

        # Convert detected patterns into components and flows
        self._build_results(patterns_found, result)
        return result

    def _scan_http_clients(
        self, content: str, file_path: str, patterns: dict[str, list[str]]
    ) -> None:
        """Detect outbound HTTP calls (indicates external dependencies)."""
        http_patterns = [
            # Python
            r"requests\.(get|post|put|delete|patch)\s*\(",
            r"httpx\.(get|post|put|delete|patch|AsyncClient)\s*\(",
            r"aiohttp\.ClientSession",
            r"urllib\.request",
            # JavaScript/TypeScript
            r"fetch\s*\(['\"]https?://",
            r"axios\.(get|post|put|delete|patch)\s*\(",
            r"http\.request\s*\(",
            r"superagent\.(get|post|put|delete)",
            # Java
            r"HttpClient\.",
            r"RestTemplate\.",
            r"WebClient\.",
            r"OkHttpClient",
            # Go
            r"http\.(?:Get|Post|Do)\s*\(",
            r"resty\.New\(\)",
            # General
            r"fetch\s*\(",
            r"XMLHttpRequest",
        ]

        for pattern in http_patterns:
            matches = re.findall(pattern, content)
            if matches:
                patterns["http_clients"].append(file_path)
                break

    def _scan_db_queries(
        self, content: str, file_path: str, patterns: dict[str, list[str]]
    ) -> None:
        """Detect database query patterns."""
        db_patterns = [
            # SQL
            r"(?:SELECT|INSERT|UPDATE|DELETE|CREATE)\s+",
            r"\.execute\s*\(",
            r"\.query\s*\(",
            r"\.raw\s*\(",
            # ORMs
            r"\.findOne\s*\(",
            r"\.find\s*\(",
            r"\.create\s*\(",
            r"\.save\s*\(",
            r"\.aggregate\s*\(",
            # Python ORMs
            r"session\.query\(",
            r"Model\.objects\.",
            # MongoDB
            r"\.collection\.",
            r"\.insertOne\(",
            r"\.findOneAndUpdate\(",
        ]

        for pattern in db_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                patterns["db_queries"].append(file_path)
                break

    def _scan_auth_patterns(
        self, content: str, file_path: str, patterns: dict[str, list[str]]
    ) -> None:
        """Detect authentication/authorization patterns."""
        auth_patterns = [
            r"(?:authenticate|authorize|isAuthenticated|requireAuth)",
            r"(?:jwt|JsonWebToken|jsonwebtoken)",
            r"(?:passport\.|OAuth|oauth2)",
            r"(?:bcrypt|argon2|scrypt)\.(?:hash|compare|verify)",
            r"(?:session|cookie).*(?:token|auth)",
            r"@(?:login_required|authenticated|requires_auth)",
            r"(?:middleware|guard).*(?:auth|permission)",
            r"(?:role|permission|rbac|acl)",
            r"Bearer\s+",
        ]

        for pattern in auth_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                patterns["auth_patterns"].append(file_path)
                break

    def _scan_crypto_patterns(
        self, content: str, file_path: str, patterns: dict[str, list[str]]
    ) -> None:
        """Detect cryptographic operations."""
        crypto_patterns = [
            r"(?:crypto|cryptography)\.",
            r"(?:AES|RSA|SHA256|SHA512|HMAC|MD5)",
            r"\.(?:encrypt|decrypt|sign|verify)\s*\(",
            r"(?:createCipher|createHash|createHmac)",
            r"(?:privateKey|publicKey|secretKey)",
            r"(?:ssl|tls|certificate)",
        ]

        for pattern in crypto_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                patterns["crypto_patterns"].append(file_path)
                break

    def _scan_logging(
        self, content: str, file_path: str, patterns: dict[str, list[str]]
    ) -> None:
        """Detect logging/audit trail patterns."""
        logging_patterns = [
            r"(?:logger|logging|log)\.\w+\s*\(",
            r"console\.(?:log|warn|error)\s*\(",
            r"(?:audit|auditLog|audit_log)\.",
            r"(?:winston|bunyan|pino|log4j|slf4j)\.",
        ]

        for pattern in logging_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                patterns["logging"].append(file_path)
                break

    def _build_results(self, patterns: dict[str, list[str]], result: DetectionResult) -> None:
        """Convert pattern detections into architecture observations (metadata)."""
        # HTTP clients suggest outbound data flows to external services
        if patterns["http_clients"]:
            result.components.append(Component(
                id="meta-code-patterns",
                name="Code Pattern Analysis",
                type=ComponentType.PROCESS,
                metadata={
                    "type": "metadata",
                    "http_client_files": str(len(patterns["http_clients"])),
                    "db_query_files": str(len(patterns["db_queries"])),
                    "auth_files": str(len(patterns["auth_patterns"])),
                    "crypto_files": str(len(patterns["crypto_patterns"])),
                    "logging_files": str(len(patterns["logging"])),
                    "has_auth": str(bool(patterns["auth_patterns"])),
                    "has_crypto": str(bool(patterns["crypto_patterns"])),
                    "has_logging": str(bool(patterns["logging"])),
                    "files_with_http_calls": ", ".join(patterns["http_clients"][:10]),
                    "files_with_db_access": ", ".join(patterns["db_queries"][:10]),
                },
            ))
