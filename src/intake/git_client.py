"""Git operations for cloning and managing repositories."""

import shutil
import logging
from pathlib import Path
from typing import Optional

from git import Repo, GitCommandError

from src.core.config import get_config
from src.core.exceptions import GitCloneError

logger = logging.getLogger(__name__)


class GitClient:
    """Handles git clone and repository management."""

    def __init__(self, temp_dir: Optional[Path] = None):
        config = get_config()
        self.temp_dir = temp_dir or config.git.temp_dir
        self.timeout = config.git.clone_timeout_seconds
        self.temp_dir.mkdir(parents=True, exist_ok=True)

    def clone(
        self,
        repo_url: str,
        branch: str = "main",
        token: Optional[str] = None,
        scan_id: Optional[str] = None,
    ) -> Path:
        """
        Clone a remote repository into a temporary workspace.

        Args:
            repo_url: Git repository URL (HTTPS or SSH)
            branch: Branch to checkout
            token: Optional access token for private repos
            scan_id: Scan identifier for directory naming

        Returns:
            Path to the cloned repository directory

        Raises:
            GitCloneError: If cloning fails
        """
        clone_dir = self.temp_dir / (scan_id or "repo")

        # Clean up if directory already exists
        if clone_dir.exists():
            shutil.rmtree(clone_dir)

        # Inject token into HTTPS URL if provided
        authenticated_url = self._inject_token(repo_url, token) if token else repo_url

        logger.info(f"Cloning {repo_url} (branch: {branch}) into {clone_dir}")

        try:
            repo = Repo.clone_from(
                authenticated_url,
                str(clone_dir),
                branch=branch,
                depth=1,  # Shallow clone for speed
                single_branch=True,
            )
            logger.info(f"Clone successful: {repo.head.commit.hexsha[:8]}")
            return clone_dir

        except GitCommandError as e:
            logger.error(f"Git clone failed: {e}")
            raise GitCloneError(f"Failed to clone {repo_url}: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error during clone: {e}")
            raise GitCloneError(f"Unexpected error cloning {repo_url}: {e}") from e

    def cleanup(self, repo_path: Path) -> None:
        """Remove a cloned repository from disk."""
        if repo_path.exists():
            shutil.rmtree(repo_path)
            logger.info(f"Cleaned up: {repo_path}")

    def list_files(self, repo_path: Path, extensions: Optional[list[str]] = None) -> list[Path]:
        """
        List all files in the repository, optionally filtered by extension.

        Args:
            repo_path: Path to the cloned repository
            extensions: Optional list of extensions to filter (e.g., ['.py', '.yaml'])

        Returns:
            List of file paths relative to repo root
        """
        files = []
        for file_path in repo_path.rglob("*"):
            if file_path.is_file() and not self._is_ignored(file_path, repo_path):
                if extensions is None or file_path.suffix in extensions:
                    files.append(file_path.relative_to(repo_path))
        return files

    def _inject_token(self, url: str, token: str) -> str:
        """Inject access token into HTTPS git URL."""
        if url.startswith("https://"):
            # https://gitlab.example.com/repo.git -> https://oauth2:TOKEN@gitlab.example.com/repo.git
            return url.replace("https://", f"https://oauth2:{token}@")
        return url

    def _is_ignored(self, file_path: Path, repo_root: Path) -> bool:
        """Check if a file should be ignored (e.g., .git directory, node_modules)."""
        ignored_dirs = {
            ".git", "node_modules", "__pycache__", ".venv", "venv",
            ".tox", ".mypy_cache", ".pytest_cache", "dist", "build",
            ".next", ".nuxt", "target", "bin", "obj",
        }
        parts = file_path.relative_to(repo_root).parts
        return any(part in ignored_dirs for part in parts)
