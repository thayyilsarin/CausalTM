"""Detector for API specifications (OpenAPI/Swagger, GraphQL)."""

import json
import logging
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


class APISpecDetector(BaseDetector):
    """Detects API endpoints, data models, and auth schemes from API specifications."""

    @property
    def name(self) -> str:
        return "API Specification Detector"

    @property
    def description(self) -> str:
        return "Extracts endpoints, data flows, and auth from OpenAPI/Swagger specs"

    @property
    def target_files(self) -> list[str]:
        return [
            "openapi.yaml", "openapi.yml", "openapi.json",
            "swagger.yaml", "swagger.yml", "swagger.json",
            "api-spec.yaml", "api-spec.json",
            "schema.graphql", "schema.gql",
        ]

    def detect(self, repo_path: Path, files: list[Path]) -> DetectionResult:
        result = DetectionResult()

        for f in self._filter_files(files):
            full_path = repo_path / f
            if not full_path.exists():
                continue

            if f.suffix in [".graphql", ".gql"]:
                self._parse_graphql(full_path, result)
            else:
                self._parse_openapi(full_path, result)

        return result

    def _parse_openapi(self, path: Path, result: DetectionResult) -> None:
        """Parse an OpenAPI/Swagger specification."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            if path.suffix == ".json":
                spec = json.loads(content)
            else:
                spec = yaml.safe_load(content)
        except Exception as e:
            logger.warning(f"Failed to parse API spec {path}: {e}")
            return

        if not spec:
            return

        # Extract API title/name
        info = spec.get("info", {})
        api_name = info.get("title", "API Service")

        # Detect authentication schemes
        security_schemes = (
            spec.get("components", {}).get("securitySchemes", {})
            or spec.get("securityDefinitions", {})
        )
        has_auth = bool(security_schemes)

        # Create API component
        api_id = f"process-api-{api_name.lower().replace(' ', '-')}"
        api_component = Component(
            id=api_id,
            name=api_name,
            type=ComponentType.PROCESS,
            technology="REST API",
            has_authentication=has_auth,
            is_public_facing=True,
            metadata={
                "spec_version": spec.get("openapi", spec.get("swagger", "unknown")),
                "auth_schemes": ", ".join(security_schemes.keys()) if security_schemes else "none",
            },
        )
        result.components.append(api_component)

        # Extract endpoints and data flows
        paths = spec.get("paths", {})
        for endpoint_path, methods in paths.items():
            for method, operation in methods.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    self._extract_endpoint_flow(
                        api_id, endpoint_path, method, operation, spec, result
                    )

    def _extract_endpoint_flow(
        self, api_id: str, endpoint_path: str, method: str,
        operation: dict, spec: dict, result: DetectionResult
    ) -> None:
        """Extract data flow information from an endpoint definition."""
        # Detect data types from request/response schemas
        data_types = []
        sensitivity = []

        # Check request body
        request_body = operation.get("requestBody", {})
        if request_body:
            schemas = self._extract_schema_fields(request_body, spec)
            data_types.extend(schemas)

        # Check if endpoint handles sensitive data
        endpoint_lower = endpoint_path.lower()
        sensitive_patterns = {
            "auth": DataSensitivity.CREDENTIALS,
            "login": DataSensitivity.CREDENTIALS,
            "password": DataSensitivity.CREDENTIALS,
            "user": DataSensitivity.PII,
            "profile": DataSensitivity.PII,
            "payment": DataSensitivity.FINANCIAL,
            "billing": DataSensitivity.FINANCIAL,
            "card": DataSensitivity.FINANCIAL,
        }
        for pattern, sens in sensitive_patterns.items():
            if pattern in endpoint_lower:
                sensitivity.append(sens)

        # Check if endpoint has security requirement
        endpoint_security = operation.get("security", [])
        is_authenticated = bool(endpoint_security) or bool(
            spec.get("security", [])
        )

        # Create a user/client external entity if we see auth-related endpoints
        if any(p in endpoint_lower for p in ["login", "auth", "register"]):
            user_id = "ext-user-client"
            user_exists = any(c.id == user_id for c in result.components)
            if not user_exists:
                result.components.append(Component(
                    id=user_id,
                    name="User/Client",
                    type=ComponentType.EXTERNAL_ENTITY,
                    trust_level=TrustLevel.EXTERNAL,
                    is_public_facing=True,
                ))

            result.data_flows.append(DataFlow(
                id=f"flow-user-{method}-{endpoint_path.replace('/', '-')}",
                source_id=user_id,
                target_id=api_id,
                protocol="HTTPS",
                data_types=data_types or [f"{method.upper()} {endpoint_path}"],
                data_sensitivity=sensitivity,
                is_authenticated=is_authenticated,
                crosses_trust_boundary=True,
                description=f"{method.upper()} {endpoint_path}",
            ))

    def _extract_schema_fields(self, body: dict, spec: dict) -> list[str]:
        """Extract field names from a request body schema."""
        fields = []
        content = body.get("content", {})
        for media_type, media_config in content.items():
            schema = media_config.get("schema", {})
            if "$ref" in schema:
                ref_path = schema["$ref"].split("/")
                # Resolve simple references
                resolved = spec
                for part in ref_path[1:]:  # Skip the initial '#'
                    resolved = resolved.get(part, {})
                schema = resolved

            properties = schema.get("properties", {})
            fields.extend(properties.keys())

        return fields

    def _parse_graphql(self, path: Path, result: DetectionResult) -> None:
        """Parse a GraphQL schema for types and queries."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Failed to read GraphQL schema {path}: {e}")
            return

        # Basic GraphQL type extraction (simplified)
        api_id = "process-graphql-api"
        result.components.append(Component(
            id=api_id,
            name="GraphQL API",
            type=ComponentType.PROCESS,
            technology="GraphQL",
            is_public_facing=True,
            metadata={"schema_file": str(path.name)},
        ))

        # Detect mutations (write operations = higher risk)
        if "type Mutation" in content:
            result.components[-1].metadata["has_mutations"] = "true"
