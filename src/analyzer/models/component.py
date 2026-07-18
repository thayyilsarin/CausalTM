"""Data models for architectural components discovered during analysis."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class ComponentType(str, Enum):
    """DFD element types."""

    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"


class TrustLevel(str, Enum):
    """Trust level classification."""

    INTERNAL = "internal"
    DMZ = "dmz"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


class DataSensitivity(str, Enum):
    """Data sensitivity classification."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    FINANCIAL = "financial"
    CREDENTIALS = "credentials"
    SECRET = "secret"


class Component(BaseModel):
    """A discovered architectural component (service, database, external entity)."""

    id: str
    name: str
    type: ComponentType
    technology: Optional[str] = None
    language: Optional[str] = None
    ports: list[int] = []
    trust_level: TrustLevel = TrustLevel.UNKNOWN
    has_authentication: bool = False
    has_encryption: bool = False
    is_public_facing: bool = False
    source_paths: list[str] = Field(default_factory=list, description="Source files belonging to this component")
    metadata: dict[str, str] = Field(default_factory=dict)


class DataFlow(BaseModel):
    """A data flow between two components."""

    id: str
    source_id: str
    target_id: str
    protocol: Optional[str] = None
    port: Optional[int] = None
    data_types: list[str] = []
    data_sensitivity: list[DataSensitivity] = []
    is_encrypted: bool = False
    is_authenticated: bool = False
    crosses_trust_boundary: bool = False
    description: Optional[str] = None


class TrustBoundary(BaseModel):
    """A trust boundary grouping components."""

    id: str
    name: str
    trust_level: TrustLevel
    component_ids: list[str] = []
    description: Optional[str] = None


class ComponentGraph(BaseModel):
    """The complete discovered architecture — input to DFD builder and causal engine."""

    components: list[Component] = []
    data_flows: list[DataFlow] = []
    trust_boundaries: list[TrustBoundary] = []
    metadata: dict[str, str] = Field(default_factory=dict, description="Scan metadata")

    def get_component(self, component_id: str) -> Optional[Component]:
        """Look up a component by ID."""
        for c in self.components:
            if c.id == component_id:
                return c
        return None

    def get_flows_from(self, component_id: str) -> list[DataFlow]:
        """Get all outgoing flows from a component."""
        return [f for f in self.data_flows if f.source_id == component_id]

    def get_flows_to(self, component_id: str) -> list[DataFlow]:
        """Get all incoming flows to a component."""
        return [f for f in self.data_flows if f.target_id == component_id]
