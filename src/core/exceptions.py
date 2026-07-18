"""Custom exceptions for CausalTM."""


class CausalTMError(Exception):
    """Base exception for all CausalTM errors."""


class ScanError(CausalTMError):
    """Error during scan operations."""


class GitCloneError(ScanError):
    """Failed to clone repository."""


class AnalysisError(CausalTMError):
    """Error during code analysis."""


class DetectorError(AnalysisError):
    """Error in a specific detector."""


class IngestionError(CausalTMError):
    """Error parsing SAST/DAST reports."""


class SARIFParseError(IngestionError):
    """Error parsing SARIF format."""


class ZAPParseError(IngestionError):
    """Error parsing OWASP ZAP XML."""


class CausalEngineError(CausalTMError):
    """Error in causal reasoning engine."""


class DFDBuildError(CausalTMError):
    """Error building DFD model."""


class RenderError(CausalTMError):
    """Error rendering diagram."""


class ReportError(CausalTMError):
    """Error generating report."""
