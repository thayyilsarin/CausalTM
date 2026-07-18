"""Base class for all architecture detectors."""

import logging
from abc import ABC, abstractmethod
from pathlib import Path

from src.analyzer.models.component import Component, DataFlow, TrustBoundary

logger = logging.getLogger(__name__)


class DetectionResult:
    """Results from a single detector run."""

    def __init__(self):
        self.components: list[Component] = []
        self.data_flows: list[DataFlow] = []
        self.trust_boundaries: list[TrustBoundary] = []

    def merge(self, other: "DetectionResult") -> "DetectionResult":
        """Merge another detection result into this one."""
        self.components.extend(other.components)
        self.data_flows.extend(other.data_flows)
        self.trust_boundaries.extend(other.trust_boundaries)
        return self


class BaseDetector(ABC):
    """
    Abstract base class for architecture detectors.

    Each detector is responsible for finding specific types of
    components by analyzing particular file types or patterns.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable detector name."""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """What this detector looks for."""
        ...

    @property
    @abstractmethod
    def target_files(self) -> list[str]:
        """
        File patterns this detector is interested in.
        
        Examples: ['Dockerfile', 'docker-compose.yml', '*.yaml']
        """
        ...

    @abstractmethod
    def detect(self, repo_path: Path, files: list[Path]) -> DetectionResult:
        """
        Run detection on the repository.

        Args:
            repo_path: Root path of the cloned repository
            files: List of all files in the repo (relative paths)

        Returns:
            DetectionResult with discovered components, flows, and boundaries
        """
        ...

    def _matches_target(self, file_path: Path) -> bool:
        """Check if a file matches this detector's target patterns."""
        name = file_path.name
        for pattern in self.target_files:
            if pattern.startswith("*"):
                if name.endswith(pattern[1:]):
                    return True
            elif name == pattern or str(file_path).endswith(pattern):
                return True
        return False

    def _filter_files(self, files: list[Path]) -> list[Path]:
        """Filter file list to only those matching target patterns."""
        return [f for f in files if self._matches_target(f)]
