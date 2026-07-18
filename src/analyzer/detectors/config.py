"""Detector for configuration files (env, connection strings, etc.)."""

import json
import logging
import re
from pathlib import Path

import yaml

from src.analyzer.detectors.base import BaseDetector, DetectionResult
from src.analyzer.models.component import (
    Component,
    ComponentType,
    DataFlow,
    DataSensitivity,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class ConfigDetector(BaseDetector):
    """Detects databases, external services, and credentials from config files."""

    @property
    def name(self) -> str:
        return "Configuration Detector"

    @property
    def description(self) -> str:
        return "Extracts external services, databases, and credentials from config files"

    @property
    def target_files(self) -> list[str]:
        return [
            ".env", ".env.example", ".env.sample", ".env.production",
            "appsettings.json", "appsettings.Development.json",
            "application.yml", "application.yaml", "application.properties",
            "config.yaml", "config.yml", "config.json",
            "settings.py", "database.yml",
        ]

    def detect(self, repo_path: Path, files: list[Path]) -> DetectionResult:
        result = DetectionResult()

        for f in self._filter_files(files):
            full_path = repo_path / f
            if not full_path.exists():
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            if f.name.startswith(".env"):
                self._parse_env(content, result)
            elif f.suffix == ".json":
                self._parse_json_config(content, result)
            elif f.suffix in [".yaml", ".yml"]:
                self._parse_yaml_config(content, result)
            elif f.suffix == ".properties":
                self._parse_properties(content, result)

        return result

    def _parse_env(self, content: str, result: DetectionResult) -> None:
        """Parse .env file for database URLs, API keys, and service endpoints."""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue

            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip("'\"")

            self._analyze_config_entry(key, value, result)

    def _parse_json_config(self, content: str, result: DetectionResult) -> None:
        """Parse JSON config files."""
        try:
            config = json.loads(content)
            self._walk_config(config, result)
        except json.JSONDecodeError:
            pass

    def _parse_yaml_config(self, content: str, result: DetectionResult) -> None:
        """Parse YAML config files."""
        try:
            config = yaml.safe_load(content)
            if isinstance(config, dict):
                self._walk_config(config, result)
        except yaml.YAMLError:
            pass

    def _parse_properties(self, content: str, result: DetectionResult) -> None:
        """Parse Java .properties files."""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            self._analyze_config_entry(key.strip(), value.strip(), result)

    def _walk_config(self, config: dict, result: DetectionResult, prefix: str = "") -> None:
        """Recursively walk a config dict looking for service references."""
        for key, value in config.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                self._walk_config(value, result, full_key)
            elif isinstance(value, str):
                self._analyze_config_entry(full_key, value, result)

    def _analyze_config_entry(self, key: str, value: str, result: DetectionResult) -> None:
        """Analyze a single config key-value pair for service references."""
        key_lower = key.lower()

        # Database connection strings
        db_match = self._detect_database_url(key_lower, value)
        if db_match:
            comp_id = f"data_store-{db_match['type']}"
            if not any(c.id == comp_id for c in result.components):
                result.components.append(Component(
                    id=comp_id,
                    name=f"{db_match['type'].title()} Database",
                    type=ComponentType.DATA_STORE,
                    technology=db_match["type"].title(),
                    ports=[db_match["port"]] if db_match.get("port") else [],
                    trust_level=TrustLevel.INTERNAL,
                    has_authentication=True,
                    metadata={"detected_from": key},
                ))

        # External API endpoints
        if self._is_api_url(key_lower, value):
            service_name = self._extract_service_name(key_lower, value)
            comp_id = f"ext-{service_name}"
            if not any(c.id == comp_id for c in result.components):
                result.components.append(Component(
                    id=comp_id,
                    name=service_name.replace("-", " ").title(),
                    type=ComponentType.EXTERNAL_ENTITY,
                    trust_level=TrustLevel.EXTERNAL,
                    is_public_facing=True,
                    has_encryption=value.startswith("https"),
                    metadata={"detected_from": key, "url_pattern": value[:50]},
                ))

        # Message brokers / queues
        if any(q in key_lower for q in ["rabbitmq", "amqp", "kafka", "sqs", "queue"]):
            comp_id = "data_store-message-broker"
            if not any(c.id == comp_id for c in result.components):
                result.components.append(Component(
                    id=comp_id,
                    name="Message Broker",
                    type=ComponentType.DATA_STORE,
                    technology=self._infer_broker_tech(key_lower, value),
                    trust_level=TrustLevel.INTERNAL,
                    metadata={"detected_from": key},
                ))

    def _detect_database_url(self, key: str, value: str) -> dict | None:
        """Detect database connection strings."""
        # URL-style: postgres://user:pass@host:port/db
        db_url_pattern = re.compile(
            r"(postgres|postgresql|mysql|mongodb|redis|mssql|sqlite)://",
            re.IGNORECASE,
        )
        match = db_url_pattern.search(value)
        if match:
            db_type = match.group(1).lower()
            port_map = {
                "postgres": 5432, "postgresql": 5432, "mysql": 3306,
                "mongodb": 27017, "redis": 6379, "mssql": 1433,
            }
            return {"type": db_type, "port": port_map.get(db_type)}

        # Key-based detection
        if any(k in key for k in ["database_url", "db_host", "db_connection", "connection_string"]):
            return {"type": "database", "port": None}

        return None

    def _is_api_url(self, key: str, value: str) -> bool:
        """Check if a value looks like an external API URL."""
        if not (value.startswith("http://") or value.startswith("https://")):
            return False
        # Skip localhost/internal
        if any(internal in value for internal in ["localhost", "127.0.0.1", "0.0.0.0"]):
            return False
        # Key should suggest it's an API/service URL
        api_indicators = ["url", "endpoint", "api", "host", "base_url", "service"]
        return any(ind in key for ind in api_indicators)

    def _extract_service_name(self, key: str, value: str) -> str:
        """Extract a service name from a config key or URL."""
        # Try from key: STRIPE_API_URL -> stripe
        parts = key.replace("_url", "").replace("_api", "").replace("_endpoint", "")
        parts = parts.replace("_base", "").replace("_host", "").split("_")
        name = parts[0] if parts else "external-service"

        # Clean up
        for prefix in ["spring.datasource.", "app.", "services."]:
            if name.startswith(prefix):
                name = name[len(prefix):]

        return name.lower().replace(".", "-")

    def _infer_broker_tech(self, key: str, value: str) -> str:
        """Infer message broker technology."""
        combined = f"{key} {value}".lower()
        if "rabbit" in combined or "amqp" in combined:
            return "RabbitMQ"
        if "kafka" in combined:
            return "Kafka"
        if "sqs" in combined:
            return "AWS SQS"
        return "Message Queue"
