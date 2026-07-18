"""Detector for Docker and Docker Compose configurations."""

import logging
import re
from pathlib import Path
from typing import Optional

import yaml

from src.analyzer.detectors.base import BaseDetector, DetectionResult
from src.analyzer.models.component import (
    Component,
    ComponentType,
    DataFlow,
    TrustBoundary,
    TrustLevel,
)

logger = logging.getLogger(__name__)


class DockerDetector(BaseDetector):
    """Detects services, databases, and data flows from Docker/Compose configurations."""

    @property
    def name(self) -> str:
        return "Docker/Compose Detector"

    @property
    def description(self) -> str:
        return "Extracts architecture from Dockerfile and docker-compose.yml"

    @property
    def target_files(self) -> list[str]:
        return [
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
        ]

    def detect(self, repo_path: Path, files: list[Path]) -> DetectionResult:
        result = DetectionResult()

        for f in self._filter_files(files):
            full_path = repo_path / f
            if not full_path.exists():
                continue

            if f.name == "Dockerfile":
                self._parse_dockerfile(full_path, f, result)
            else:
                self._parse_compose(full_path, result)

        return result

    def _parse_dockerfile(
        self, path: Path, relative_path: Path, result: DetectionResult
    ) -> None:
        """Extract component info from a Dockerfile."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            logger.warning(f"Failed to read {path}: {e}")
            return

        # Determine service name from directory
        service_dir = relative_path.parent
        service_name = str(service_dir) if str(service_dir) != "." else "main-service"

        # Extract exposed ports
        ports = []
        for match in re.finditer(r"EXPOSE\s+(\d+)", content):
            ports.append(int(match.group(1)))

        # Detect base image for technology inference
        base_image = None
        for match in re.finditer(r"FROM\s+([^\s]+)", content):
            base_image = match.group(1)

        technology = self._infer_technology(base_image) if base_image else None

        component = Component(
            id=f"process-{service_name.replace('/', '-')}",
            name=service_name,
            type=ComponentType.PROCESS,
            technology=technology,
            ports=ports,
            is_public_facing=any(p in [80, 443, 8080, 8443, 3000] for p in ports),
            source_paths=[str(relative_path)],
            metadata={"base_image": base_image or "unknown"},
        )
        result.components.append(component)

    def _parse_compose(self, path: Path, result: DetectionResult) -> None:
        """Extract services, databases, and connections from docker-compose."""
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            compose = yaml.safe_load(content)
        except Exception as e:
            logger.warning(f"Failed to parse {path}: {e}")
            return

        if not compose or "services" not in compose:
            return

        services = compose["services"]
        internal_boundary = TrustBoundary(
            id="tb-docker-internal",
            name="Docker Internal Network",
            trust_level=TrustLevel.INTERNAL,
            component_ids=[],
        )

        for service_name, service_config in services.items():
            component = self._parse_service(service_name, service_config)
            result.components.append(component)
            internal_boundary.component_ids.append(component.id)

        # Detect data flows from depends_on and links
        for service_name, service_config in services.items():
            flows = self._detect_flows(service_name, service_config, services)
            result.data_flows.extend(flows)

        # Detect exposed services (ports mapped to host)
        external_boundary = TrustBoundary(
            id="tb-external",
            name="External/Host Network",
            trust_level=TrustLevel.EXTERNAL,
            component_ids=[],
        )

        for service_name, service_config in services.items():
            if "ports" in service_config:
                # Service is exposed to host — mark as public facing
                comp_id = f"process-{service_name}"
                for comp in result.components:
                    if comp.id == comp_id:
                        comp.is_public_facing = True

        result.trust_boundaries.append(internal_boundary)
        if external_boundary.component_ids:
            result.trust_boundaries.append(external_boundary)

    def _parse_service(self, name: str, config: dict) -> Component:
        """Parse a single docker-compose service into a Component."""
        image = config.get("image", "")
        build_context = config.get("build", "")

        # Classify component type
        comp_type = self._classify_service(name, image)
        technology = self._infer_technology_from_image(image)

        # Extract ports
        ports = []
        for port_mapping in config.get("ports", []):
            port_str = str(port_mapping)
            # Handle "8080:80" or "80" format
            if ":" in port_str:
                container_port = int(port_str.split(":")[-1].split("/")[0])
            else:
                container_port = int(port_str.split("/")[0])
            ports.append(container_port)

        # Check for environment variables that suggest auth/encryption
        env = config.get("environment", {})
        if isinstance(env, list):
            env_dict = {}
            for item in env:
                if "=" in item:
                    k, v = item.split("=", 1)
                    env_dict[k] = v
            env = env_dict

        has_auth = any(
            k.lower() in ["password", "auth", "secret", "token", "api_key"]
            or "password" in k.lower()
            or "secret" in k.lower()
            for k in env.keys()
        )

        return Component(
            id=f"{'data_store' if comp_type == ComponentType.DATA_STORE else 'process'}-{name}",
            name=name,
            type=comp_type,
            technology=technology,
            ports=ports,
            has_authentication=has_auth,
            is_public_facing=bool(config.get("ports")),
            metadata={"image": image, "build": str(build_context)},
        )

    def _detect_flows(
        self, service_name: str, config: dict, all_services: dict
    ) -> list[DataFlow]:
        """Detect data flows from depends_on, links, and environment references."""
        flows = []
        source_id = f"process-{service_name}"

        # depends_on implies a data flow
        depends = config.get("depends_on", [])
        if isinstance(depends, dict):
            depends = list(depends.keys())

        for dep in depends:
            dep_service = all_services.get(dep, {})
            target_type = self._classify_service(dep, dep_service.get("image", ""))
            target_prefix = "data_store" if target_type == ComponentType.DATA_STORE else "process"
            target_id = f"{target_prefix}-{dep}"

            # Infer protocol from target type
            protocol = self._infer_protocol(dep, dep_service.get("image", ""))

            flow = DataFlow(
                id=f"flow-{service_name}-to-{dep}",
                source_id=source_id,
                target_id=target_id,
                protocol=protocol,
                description=f"{service_name} depends on {dep}",
            )
            flows.append(flow)

        return flows

    def _classify_service(self, name: str, image: str) -> ComponentType:
        """Classify a service as process, data_store, or external_entity."""
        data_store_indicators = [
            "postgres", "mysql", "mariadb", "mongo", "redis", "memcached",
            "elasticsearch", "minio", "s3", "rabbitmq", "kafka", "sqlite",
            "dynamodb", "cassandra", "couchdb", "influxdb", "neo4j",
        ]
        name_lower = name.lower()
        image_lower = image.lower()

        for indicator in data_store_indicators:
            if indicator in name_lower or indicator in image_lower:
                return ComponentType.DATA_STORE

        return ComponentType.PROCESS

    def _infer_technology(self, base_image: Optional[str]) -> Optional[str]:
        """Infer technology from Dockerfile FROM image."""
        if not base_image:
            return None
        image_lower = base_image.lower()
        tech_map = {
            "python": "Python", "node": "Node.js", "golang": "Go",
            "openjdk": "Java", "java": "Java", "ruby": "Ruby",
            "php": "PHP", "dotnet": ".NET", "rust": "Rust",
            "nginx": "Nginx", "httpd": "Apache", "alpine": "Alpine Linux",
        }
        for key, tech in tech_map.items():
            if key in image_lower:
                return tech
        return base_image.split(":")[0]

    def _infer_technology_from_image(self, image: str) -> Optional[str]:
        """Infer technology from docker-compose image field."""
        return self._infer_technology(image)

    def _infer_protocol(self, service_name: str, image: str) -> str:
        """Infer the likely protocol for communication with a service."""
        combined = f"{service_name} {image}".lower()
        if any(db in combined for db in ["postgres"]):
            return "TCP/5432"
        if any(db in combined for db in ["mysql", "mariadb"]):
            return "TCP/3306"
        if "mongo" in combined:
            return "TCP/27017"
        if "redis" in combined:
            return "TCP/6379"
        if "rabbitmq" in combined:
            return "AMQP/5672"
        if "kafka" in combined:
            return "TCP/9092"
        if "elasticsearch" in combined:
            return "HTTP/9200"
        return "TCP"
