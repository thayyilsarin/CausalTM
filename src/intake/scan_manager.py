"""Scan lifecycle management — orchestrates the full threat modeling pipeline."""

import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.api.models.scan import ScanRequest, ScanStatus, ScanStatusResponse
from src.core.config import get_config
from src.core.exceptions import ScanError
from src.intake.git_client import GitClient

logger = logging.getLogger(__name__)


class ScanManager:
    """
    Orchestrates the full scan pipeline:
    1. Clone repository
    2. Run analyzer (detect components)
    3. Ingest SAST/DAST reports
    4. Run correlation engine (causal)
    5. Build DFD
    6. Apply STRIDE threats
    7. Render diagram
    8. Generate report
    """

    def __init__(self):
        self.git_client = GitClient()
        self._scans: dict[str, ScanContext] = {}
        self._last_causal_engine = None  # Preserved for interactive what-if queries

    def create_scan(self, request: ScanRequest) -> str:
        """Create a new scan and return its ID."""
        scan_id = str(uuid.uuid4())
        context = ScanContext(
            scan_id=scan_id,
            request=request,
            status=ScanStatus.QUEUED,
            created_at=datetime.now(timezone.utc),
        )
        self._scans[scan_id] = context
        logger.info(f"Scan created: {scan_id} for {request.repo_url}")
        return scan_id

    async def run_pipeline(self, scan_id: str) -> None:
        """
        Execute the full threat modeling pipeline for a scan.

        This is the main orchestration method that drives
        the entire analysis process.
        """
        context = self._scans.get(scan_id)
        if not context:
            raise ScanError(f"Scan {scan_id} not found")

        try:
            # Step 1: Clone repository
            context.status = ScanStatus.CLONING
            logger.info(f"[{scan_id}] Cloning repository...")
            repo_path = self.git_client.clone(
                repo_url=context.request.repo_url,
                branch=context.request.branch,
                token=context.request.token,
                scan_id=scan_id,
            )
            context.repo_path = repo_path

            # Step 2: Analyze — detect architecture components
            context.status = ScanStatus.ANALYZING
            logger.info(f"[{scan_id}] Analyzing repository...")
            component_graph = await self._run_analysis(repo_path)
            context.component_graph = component_graph

            # Step 3: Ingest SAST/DAST reports (if provided)
            sast_findings = await self._ingest_sast(context)
            dast_findings = await self._ingest_dast(context)

            # Step 4: Correlate — causal engine
            context.status = ScanStatus.CORRELATING
            logger.info(f"[{scan_id}] Running causal correlation...")
            causal_result = await self._run_correlation(
                component_graph, sast_findings, dast_findings
            )
            context.causal_result = causal_result

            # Step 5: Build DFD + Apply STRIDE
            dfd_model = await self._build_dfd(component_graph, causal_result)
            threats = await self._apply_stride(dfd_model, causal_result)
            context.threats = threats

            # Step 6: Render diagram
            context.status = ScanStatus.RENDERING
            logger.info(f"[{scan_id}] Rendering DFD diagram...")
            diagram_path = await self._render_diagram(dfd_model, scan_id)
            context.diagram_path = diagram_path

            # Step 7: Generate report
            report_path = await self._generate_report(context)
            context.report_path = report_path

            # Done
            context.status = ScanStatus.COMPLETED
            context.completed_at = datetime.now(timezone.utc)
            logger.info(f"[{scan_id}] Scan completed successfully")

        except Exception as e:
            context.status = ScanStatus.FAILED
            context.error_message = str(e)
            logger.error(f"[{scan_id}] Scan failed: {e}")
            raise

        finally:
            # Cleanup cloned repo
            if context.repo_path:
                self.git_client.cleanup(context.repo_path)

    async def _run_analysis(self, repo_path: Path) -> dict:
        """Run the analyzer engine to detect components."""
        from src.analyzer.engine import AnalyzerEngine

        engine = AnalyzerEngine()
        return await engine.analyze(repo_path)

    async def _ingest_sast(self, context: "ScanContext") -> list:
        """Ingest SAST report if provided."""
        if not context.request.sast_report_path:
            return []
        from src.ingestors.sarif_ingestor import SARIFIngestor

        ingestor = SARIFIngestor()
        findings = ingestor.parse(Path(context.request.sast_report_path))
        # Convert Pydantic models to dicts for the causal engine
        return [f.model_dump() for f in findings]

    async def _ingest_dast(self, context: "ScanContext") -> list:
        """Ingest DAST report if provided."""
        if not context.request.dast_report_path:
            return []
        from src.ingestors.zap_ingestor import ZAPIngestor

        ingestor = ZAPIngestor()
        findings = ingestor.parse(Path(context.request.dast_report_path))
        # Convert Pydantic models to dicts for the causal engine
        return [f.model_dump() for f in findings]

    async def _run_correlation(
        self, component_graph: dict, sast_findings: list, dast_findings: list
    ) -> dict:
        """Run the Federated Causal correlation engine."""
        from src.causal.federated.engine import FederatedCausalEngine

        engine = FederatedCausalEngine()
        engine.build_graph(component_graph, sast_findings, dast_findings)
        result = engine.analyze()

        # Store the engine instance for later interactive what-if queries
        self._last_causal_engine = engine

        return result

    async def _build_dfd(self, component_graph: dict, causal_result: dict) -> dict:
        """Build the DFD model from component graph."""
        from src.dfd.builder import DFDBuilder

        builder = DFDBuilder()
        return builder.build(component_graph, causal_result)

    async def _apply_stride(self, dfd_model: dict, causal_result: dict) -> list:
        """Apply STRIDE threat classification."""
        from src.stride.engine import StrideEngine

        engine = StrideEngine()
        return engine.classify(dfd_model, causal_result)

    async def _render_diagram(self, dfd_model: dict, scan_id: str) -> Path:
        """Render the DFD as a diagram."""
        from src.renderer.graphviz_renderer import GraphvizRenderer

        config = get_config()
        renderer = GraphvizRenderer()
        output_path = config.storage.diagrams_dir / f"{scan_id}.svg"
        renderer.render(dfd_model, output_path)
        return output_path

    async def _generate_report(self, context: "ScanContext") -> Path:
        """Generate the threat model report."""
        from src.reporter.generator import ReportGenerator

        config = get_config()
        generator = ReportGenerator()
        output_path = config.storage.reports_dir / f"{context.scan_id}.html"
        generator.generate(context, output_path)
        return output_path

    def get_status(self, scan_id: str) -> Optional[ScanStatusResponse]:
        """Get current scan status."""
        context = self._scans.get(scan_id)
        if not context:
            return None
        return ScanStatusResponse(
            scan_id=context.scan_id,
            status=context.status,
            project_name=context.request.project_name,
            repo_url=context.request.repo_url,
            branch=context.request.branch,
            created_at=context.created_at,
            completed_at=context.completed_at,
            error_message=context.error_message,
        )


class ScanContext:
    """Holds all state for a scan throughout the pipeline."""

    def __init__(
        self,
        scan_id: str,
        request: ScanRequest,
        status: ScanStatus,
        created_at: datetime,
    ):
        self.scan_id = scan_id
        self.request = request
        self.status = status
        self.created_at = created_at
        self.completed_at: Optional[datetime] = None
        self.error_message: Optional[str] = None
        self.repo_path: Optional[Path] = None
        self.component_graph: Optional[dict] = None
        self.causal_result: Optional[dict] = None
        self.threats: Optional[list] = None
        self.diagram_path: Optional[Path] = None
        self.report_path: Optional[Path] = None
        # Federated causal engine specific
        self.federated_result: Optional[dict] = None  # Full FederatedAnalysisResult
