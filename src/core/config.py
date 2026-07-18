"""Application configuration."""

from pathlib import Path
from pydantic import BaseModel


class StorageConfig(BaseModel):
    """Storage paths configuration."""

    base_dir: Path = Path("./data")
    scans_dir: Path = Path("./data/scans")
    reports_dir: Path = Path("./data/reports")
    diagrams_dir: Path = Path("./data/diagrams")


class GitConfig(BaseModel):
    """Git operations configuration."""

    clone_timeout_seconds: int = 300
    max_repo_size_mb: int = 500
    temp_dir: Path = Path("./data/tmp")


class AnalyzerConfig(BaseModel):
    """Analyzer engine configuration."""

    enable_code_patterns: bool = True
    enable_manifest_detection: bool = True
    enable_api_spec_detection: bool = True
    max_file_size_kb: int = 1024


class CausalConfig(BaseModel):
    """Causal engine configuration."""

    enable_counterfactual: bool = True
    enable_confounder_detection: bool = True
    max_attack_path_depth: int = 10
    severity_weights: dict[str, float] = {
        "data_sensitivity": 0.3,
        "exposure_level": 0.25,
        "trust_boundary_crossing": 0.25,
        "exploitability": 0.2,
    }


class AppConfig(BaseModel):
    """Root application configuration."""

    app_name: str = "CausalTM"
    version: str = "0.1.0"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    storage: StorageConfig = StorageConfig()
    git: GitConfig = GitConfig()
    analyzer: AnalyzerConfig = AnalyzerConfig()
    causal: CausalConfig = CausalConfig()


def get_config() -> AppConfig:
    """Load and return application configuration."""
    return AppConfig()
