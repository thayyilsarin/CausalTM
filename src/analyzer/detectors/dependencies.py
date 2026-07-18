"""Detector for dependency/package manifests."""

import json
import logging
from pathlib import Path

from src.analyzer.detectors.base import BaseDetector, DetectionResult
from src.analyzer.models.component import Component, ComponentType, TrustLevel

logger = logging.getLogger(__name__)


class DependencyDetector(BaseDetector):
    """Detects technologies, frameworks, and security-relevant libraries from package manifests."""

    @property
    def name(self) -> str:
        return "Dependency Detector"

    @property
    def description(self) -> str:
        return "Identifies technology stack and security-relevant dependencies"

    @property
    def target_files(self) -> list[str]:
        return [
            "package.json", "requirements.txt", "Pipfile", "pyproject.toml",
            "pom.xml", "build.gradle", "go.mod", "Cargo.toml",
            "Gemfile", "composer.json",
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

            if f.name == "package.json":
                self._parse_package_json(content, result)
            elif f.name in ["requirements.txt", "Pipfile"]:
                self._parse_python_deps(content, result)
            elif f.name == "go.mod":
                self._parse_go_mod(content, result)

        return result

    def _parse_package_json(self, content: str, result: DetectionResult) -> None:
        """Analyze package.json for framework and security-relevant packages."""
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return

        all_deps = {}
        all_deps.update(pkg.get("dependencies", {}))
        all_deps.update(pkg.get("devDependencies", {}))

        # Detect frameworks (informs component type)
        frameworks = self._detect_node_frameworks(all_deps)

        # Detect security-relevant packages
        security_packages = self._detect_security_packages(all_deps)

        # Store as metadata on existing components or create annotations
        # This enriches existing components rather than creating new ones
        if frameworks or security_packages:
            # Store detection results as metadata
            result.components.append(Component(
                id="meta-tech-stack",
                name="Technology Stack (Node.js)",
                type=ComponentType.PROCESS,
                technology="Node.js",
                language="JavaScript/TypeScript",
                metadata={
                    "frameworks": ", ".join(frameworks),
                    "security_packages": ", ".join(security_packages),
                    "total_dependencies": str(len(all_deps)),
                    "type": "metadata",
                },
            ))

    def _parse_python_deps(self, content: str, result: DetectionResult) -> None:
        """Analyze Python dependencies for frameworks and security packages."""
        deps = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Extract package name (before ==, >=, etc.)
            pkg_name = line.split("==")[0].split(">=")[0].split("<=")[0].split("[")[0].strip()
            deps.add(pkg_name.lower())

        frameworks = []
        security_packages = []

        framework_map = {
            "flask": "Flask", "django": "Django", "fastapi": "FastAPI",
            "tornado": "Tornado", "bottle": "Bottle", "starlette": "Starlette",
        }
        security_map = {
            "cryptography": "cryptography", "pyjwt": "PyJWT",
            "authlib": "AuthLib", "python-jose": "python-jose",
            "bcrypt": "bcrypt", "passlib": "passlib",
        }

        for dep in deps:
            if dep in framework_map:
                frameworks.append(framework_map[dep])
            if dep in security_map:
                security_packages.append(security_map[dep])

        if frameworks or deps:
            result.components.append(Component(
                id="meta-tech-stack",
                name="Technology Stack (Python)",
                type=ComponentType.PROCESS,
                technology="Python",
                language="Python",
                metadata={
                    "frameworks": ", ".join(frameworks) if frameworks else "none detected",
                    "security_packages": ", ".join(security_packages),
                    "type": "metadata",
                },
            ))

    def _parse_go_mod(self, content: str, result: DetectionResult) -> None:
        """Analyze go.mod for module info and key dependencies."""
        module_name = ""
        deps = []

        for line in content.splitlines():
            if line.startswith("module "):
                module_name = line.split(" ", 1)[1].strip()
            elif line.startswith("\t") and not line.strip().startswith("//"):
                dep = line.strip().split(" ")[0]
                deps.append(dep)

        frameworks = []
        if any("gin" in d for d in deps):
            frameworks.append("Gin")
        if any("echo" in d for d in deps):
            frameworks.append("Echo")
        if any("fiber" in d for d in deps):
            frameworks.append("Fiber")
        if any("grpc" in d for d in deps):
            frameworks.append("gRPC")

        result.components.append(Component(
            id="meta-tech-stack",
            name=f"Technology Stack (Go)",
            type=ComponentType.PROCESS,
            technology="Go",
            language="Go",
            metadata={
                "module": module_name,
                "frameworks": ", ".join(frameworks) if frameworks else "none detected",
                "type": "metadata",
            },
        ))

    def _detect_node_frameworks(self, deps: dict) -> list[str]:
        """Detect Node.js web frameworks."""
        frameworks = []
        framework_map = {
            "express": "Express.js", "fastify": "Fastify", "koa": "Koa",
            "hapi": "Hapi", "next": "Next.js", "nuxt": "Nuxt.js",
            "nestjs": "NestJS", "@nestjs/core": "NestJS",
            "socket.io": "Socket.IO",
        }
        for dep, name in framework_map.items():
            if dep in deps:
                frameworks.append(name)
        return frameworks

    def _detect_security_packages(self, deps: dict) -> list[str]:
        """Detect security-relevant packages."""
        security_pkgs = []
        security_map = {
            "helmet": "helmet (HTTP headers)",
            "cors": "cors",
            "bcrypt": "bcrypt (password hashing)",
            "jsonwebtoken": "jsonwebtoken (JWT)",
            "passport": "passport (auth)",
            "express-rate-limit": "rate-limit",
            "csurf": "CSRF protection",
            "express-validator": "input validation",
            "joi": "schema validation",
            "zod": "schema validation",
        }
        for dep, description in security_map.items():
            if dep in deps:
                security_pkgs.append(description)
        return security_pkgs
