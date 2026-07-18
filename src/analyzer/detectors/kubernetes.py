"""Detector for Kubernetes manifests."""

import logging
from pathlib import Path

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


class KubernetesDetector(BaseDetector):
    """Detects services, deployments, and network policies from K8s manifests."""

    @property
    def name(self) -> str:
        return "Kubernetes Detector"

    @property
    def description(self) -> str:
        return "Extracts architecture from Kubernetes YAML manifests"

    @property
    def target_files(self) -> list[str]:
        return ["*.yaml", "*.yml"]

    def detect(self, repo_path: Path, files: list[Path]) -> DetectionResult:
        result = DetectionResult()
        k8s_files = self._find_k8s_files(repo_path, files)

        namespaces: dict[str, TrustBoundary] = {}

        for f in k8s_files:
            full_path = repo_path / f
            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
                # Handle multi-document YAML
                for doc in yaml.safe_load_all(content):
                    if not doc or not isinstance(doc, dict):
                        continue
                    self._parse_k8s_resource(doc, result, namespaces)
            except Exception as e:
                logger.debug(f"Skipping {f}: {e}")

        result.trust_boundaries.extend(namespaces.values())
        return result

    def _find_k8s_files(self, repo_path: Path, files: list[Path]) -> list[Path]:
        """Filter to likely Kubernetes manifest files."""
        k8s_files = []
        k8s_dirs = {"k8s", "kubernetes", "deploy", "manifests", "helm", "charts"}

        for f in files:
            if f.suffix not in [".yaml", ".yml"]:
                continue
            # Check if in a k8s-related directory or has k8s content markers
            parts = set(p.lower() for p in f.parts)
            if parts & k8s_dirs:
                k8s_files.append(f)
            elif f.name in ["deployment.yaml", "service.yaml", "ingress.yaml", "configmap.yaml"]:
                k8s_files.append(f)

        return k8s_files

    def _parse_k8s_resource(
        self, doc: dict, result: DetectionResult, namespaces: dict[str, TrustBoundary]
    ) -> None:
        """Parse a single Kubernetes resource document."""
        kind = doc.get("kind", "").lower()
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace", "default")

        # Ensure namespace boundary exists
        if namespace not in namespaces:
            namespaces[namespace] = TrustBoundary(
                id=f"tb-k8s-{namespace}",
                name=f"K8s Namespace: {namespace}",
                trust_level=TrustLevel.INTERNAL,
                component_ids=[],
            )

        if kind == "deployment":
            self._parse_deployment(doc, name, namespace, result, namespaces)
        elif kind == "service":
            self._parse_service(doc, name, namespace, result, namespaces)
        elif kind == "ingress":
            self._parse_ingress(doc, name, namespace, result, namespaces)
        elif kind == "statefulset":
            self._parse_deployment(doc, name, namespace, result, namespaces)

    def _parse_deployment(
        self, doc: dict, name: str, namespace: str,
        result: DetectionResult, namespaces: dict[str, TrustBoundary]
    ) -> None:
        """Parse a Deployment/StatefulSet into a Component."""
        spec = doc.get("spec", {}).get("template", {}).get("spec", {})
        containers = spec.get("containers", [])

        for container in containers:
            container_name = container.get("name", name)
            image = container.get("image", "")
            ports = [
                p.get("containerPort", 0)
                for p in container.get("ports", [])
                if p.get("containerPort")
            ]

            comp_id = f"process-k8s-{namespace}-{container_name}"
            component = Component(
                id=comp_id,
                name=f"{namespace}/{container_name}",
                type=ComponentType.PROCESS,
                technology=self._infer_tech(image),
                ports=ports,
                trust_level=TrustLevel.INTERNAL,
                metadata={"image": image, "namespace": namespace, "kind": doc.get("kind", "")},
            )
            result.components.append(component)
            namespaces[namespace].component_ids.append(comp_id)

    def _parse_service(
        self, doc: dict, name: str, namespace: str,
        result: DetectionResult, namespaces: dict[str, TrustBoundary]
    ) -> None:
        """Parse a K8s Service — may indicate external exposure."""
        spec = doc.get("spec", {})
        service_type = spec.get("type", "ClusterIP")
        ports = spec.get("ports", [])

        # LoadBalancer or NodePort = externally exposed
        if service_type in ["LoadBalancer", "NodePort"]:
            comp_id = f"process-k8s-{namespace}-{name}"
            # Mark the associated component as public-facing
            for comp in result.components:
                if comp.id == comp_id:
                    comp.is_public_facing = True

    def _parse_ingress(
        self, doc: dict, name: str, namespace: str,
        result: DetectionResult, namespaces: dict[str, TrustBoundary]
    ) -> None:
        """Parse an Ingress — indicates external entry points."""
        spec = doc.get("spec", {})
        rules = spec.get("rules", [])
        tls = spec.get("tls", [])

        has_tls = bool(tls)

        for rule in rules:
            host = rule.get("host", "unknown")
            paths = rule.get("http", {}).get("paths", [])

            for path_entry in paths:
                backend = path_entry.get("backend", {})
                service = backend.get("service", {})
                service_name = service.get("name", backend.get("serviceName", "unknown"))

                # Create an external entity for the user/internet
                ext_id = f"ext-ingress-{host}"
                ext_exists = any(c.id == ext_id for c in result.components)
                if not ext_exists:
                    result.components.append(Component(
                        id=ext_id,
                        name=f"Internet ({host})",
                        type=ComponentType.EXTERNAL_ENTITY,
                        trust_level=TrustLevel.EXTERNAL,
                        is_public_facing=True,
                    ))

                # Create flow from internet to service
                target_id = f"process-k8s-{namespace}-{service_name}"
                result.data_flows.append(DataFlow(
                    id=f"flow-ingress-{host}-to-{service_name}",
                    source_id=ext_id,
                    target_id=target_id,
                    protocol="HTTPS" if has_tls else "HTTP",
                    is_encrypted=has_tls,
                    crosses_trust_boundary=True,
                    description=f"Ingress route from {host} to {service_name}",
                ))

    def _infer_tech(self, image: str) -> str:
        """Infer technology from container image."""
        image_lower = image.lower()
        tech_map = {
            "python": "Python", "node": "Node.js", "golang": "Go",
            "java": "Java", "ruby": "Ruby", "php": "PHP",
            "dotnet": ".NET", "nginx": "Nginx", "postgres": "PostgreSQL",
            "mysql": "MySQL", "redis": "Redis", "mongo": "MongoDB",
        }
        for key, tech in tech_map.items():
            if key in image_lower:
                return tech
        return image.split(":")[0].split("/")[-1]
