"""Analyzer engine — orchestrates all detectors to build the component graph."""

import logging
from pathlib import Path

from src.analyzer.detectors.api_spec import APISpecDetector
from src.analyzer.detectors.base import BaseDetector, DetectionResult
from src.analyzer.detectors.code_patterns import CodePatternDetector
from src.analyzer.detectors.config import ConfigDetector
from src.analyzer.detectors.dependencies import DependencyDetector
from src.analyzer.detectors.docker import DockerDetector
from src.analyzer.detectors.kubernetes import KubernetesDetector
from src.analyzer.models.component import ComponentGraph
from src.analyzer.models.graph import infer_trust_boundary_crossings
from src.core.config import get_config

logger = logging.getLogger(__name__)


class AnalyzerEngine:
    """
    Orchestrates all detectors to build a unified component graph.

    The engine runs each detector against the repository and merges
    their results into a single ComponentGraph that represents the
    discovered architecture.
    """

    def __init__(self):
        config = get_config()
        self.detectors: list[BaseDetector] = self._initialize_detectors(config)

    def _initialize_detectors(self, config) -> list[BaseDetector]:
        """Set up the active detectors based on configuration."""
        detectors: list[BaseDetector] = [
            DockerDetector(),
            KubernetesDetector(),
            ConfigDetector(),
            DependencyDetector(),
        ]

        if config.analyzer.enable_api_spec_detection:
            detectors.append(APISpecDetector())

        if config.analyzer.enable_code_patterns:
            detectors.append(CodePatternDetector())

        return detectors

    async def analyze(self, repo_path: Path) -> dict:
        """
        Run all detectors and merge results into a ComponentGraph.

        Args:
            repo_path: Path to the cloned repository

        Returns:
            ComponentGraph as a dictionary
        """
        logger.info(f"Starting analysis of {repo_path}")

        # Collect all files in the repository
        all_files = self._collect_files(repo_path)
        logger.info(f"Found {len(all_files)} files to analyze")

        # Run each detector
        merged_result = DetectionResult()
        for detector in self.detectors:
            logger.info(f"Running detector: {detector.name}")
            try:
                result = detector.detect(repo_path, all_files)
                merged_result.merge(result)
                logger.info(
                    f"  {detector.name}: found {len(result.components)} components, "
                    f"{len(result.data_flows)} flows, {len(result.trust_boundaries)} boundaries"
                )
            except Exception as e:
                logger.warning(f"Detector {detector.name} failed: {e}")
                continue

        # Build the component graph
        graph = ComponentGraph(
            components=self._deduplicate_components(merged_result.components),
            data_flows=merged_result.data_flows,
            trust_boundaries=self._merge_boundaries(merged_result.trust_boundaries),
            metadata={"repo_path": str(repo_path), "files_scanned": str(len(all_files))},
        )

        # Post-processing: infer trust boundary crossings
        graph = infer_trust_boundary_crossings(graph)

        logger.info(
            f"Analysis complete: {len(graph.components)} components, "
            f"{len(graph.data_flows)} flows, {len(graph.trust_boundaries)} boundaries"
        )

        return graph.model_dump()

    def _collect_files(self, repo_path: Path) -> list[Path]:
        """Collect all files in the repo, excluding ignored directories."""
        ignored_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
            ".next", ".nuxt", "target", "bin", "obj", ".terraform",
            "vendor", ".gradle",
        }
        files = []
        for file_path in repo_path.rglob("*"):
            if file_path.is_file():
                parts = file_path.relative_to(repo_path).parts
                if not any(part in ignored_dirs for part in parts):
                    files.append(file_path.relative_to(repo_path))
        return files

    def _deduplicate_components(self, components: list) -> list:
        """Remove duplicate components (same ID), keeping the most informative."""
        seen: dict[str, object] = {}
        for comp in components:
            if comp.id not in seen:
                seen[comp.id] = comp
            else:
                # Keep the one with more metadata
                existing = seen[comp.id]
                if len(comp.metadata) > len(existing.metadata):
                    seen[comp.id] = comp
        return list(seen.values())

    def _merge_boundaries(self, boundaries: list) -> list:
        """Merge trust boundaries with the same ID."""
        merged: dict[str, object] = {}
        for boundary in boundaries:
            if boundary.id not in merged:
                merged[boundary.id] = boundary
            else:
                # Merge component_ids
                existing = merged[boundary.id]
                for comp_id in boundary.component_ids:
                    if comp_id not in existing.component_ids:
                        existing.component_ids.append(comp_id)
        return list(merged.values())
