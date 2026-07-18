"""Data Flow Diagram models — formal DFD representation."""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class DFDLevel(str, Enum):
    """DFD abstraction levels."""

    CONTEXT = "context"    # Level 0: System as single process + external entities
    LEVEL_0 = "level_0"   # Level 1: Major subsystems and data stores
    LEVEL_1 = "level_1"   # Level 2: Detailed processes within subsystems


class DFDElementType(str, Enum):
    """Standard DFD element types."""

    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"
    TRUST_BOUNDARY = "trust_boundary"


class DFDElement(BaseModel):
    """A single element in the DFD."""

    id: str
    name: str
    element_type: DFDElementType
    description: Optional[str] = None
    technology: Optional[str] = None
    trust_level: Optional[str] = None
    is_public_facing: bool = False
    has_authentication: bool = False
    has_encryption: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)
    # Position hints for rendering
    layer: int = 0  # Used for layout grouping
    group: Optional[str] = None  # Trust boundary group


class DFDDataFlow(BaseModel):
    """A directed data flow between two DFD elements."""

    id: str
    source_id: str
    target_id: str
    label: str
    protocol: Optional[str] = None
    data_types: list[str] = []
    data_sensitivity: list[str] = []
    is_encrypted: bool = False
    is_authenticated: bool = False
    crosses_trust_boundary: bool = False
    is_bidirectional: bool = False


class DFDBoundary(BaseModel):
    """A trust boundary in the DFD (drawn as dashed box)."""

    id: str
    name: str
    trust_level: str
    element_ids: list[str] = []
    color: str = "#cccccc"


class DFDModel(BaseModel):
    """
    Complete Data Flow Diagram model.

    Contains all elements, flows, and boundaries needed
    to render the diagram and apply STRIDE analysis.
    """

    title: str
    level: DFDLevel = DFDLevel.LEVEL_0
    description: Optional[str] = None
    elements: list[DFDElement] = []
    data_flows: list[DFDDataFlow] = []
    boundaries: list[DFDBoundary] = []
    metadata: dict[str, str] = Field(default_factory=dict)

    def get_processes(self) -> list[DFDElement]:
        """Get all process elements."""
        return [e for e in self.elements if e.element_type == DFDElementType.PROCESS]

    def get_data_stores(self) -> list[DFDElement]:
        """Get all data store elements."""
        return [e for e in self.elements if e.element_type == DFDElementType.DATA_STORE]

    def get_external_entities(self) -> list[DFDElement]:
        """Get all external entity elements."""
        return [e for e in self.elements if e.element_type == DFDElementType.EXTERNAL_ENTITY]

    def get_element(self, element_id: str) -> Optional[DFDElement]:
        """Look up an element by ID."""
        for e in self.elements:
            if e.id == element_id:
                return e
        return None

    def get_flows_for_element(self, element_id: str) -> list[DFDDataFlow]:
        """Get all flows connected to an element (incoming and outgoing)."""
        return [
            f for f in self.data_flows
            if f.source_id == element_id or f.target_id == element_id
        ]

    def get_boundary_for_element(self, element_id: str) -> Optional[DFDBoundary]:
        """Find which boundary contains an element."""
        for b in self.boundaries:
            if element_id in b.element_ids:
                return b
        return None
