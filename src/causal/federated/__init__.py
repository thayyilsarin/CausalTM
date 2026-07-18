"""
Federated Structural Causal Model (FSCM) Architecture.

This module implements a hierarchical causal graph system where:
- Domain-specific sub-graphs reason independently about their layer
- Aggregated variables (edge nodes) propagate to a master DAG
- The master DAG performs cross-layer causal reasoning
- Multi-level counterfactuals operate at strategic and tactical levels

Architecture:
    [SAST Sub-Graph] ──edge nodes──┐
    [DAST Sub-Graph] ──edge nodes──┼──▶ [Master DAG] ──▶ Risk/Impact
    [Repo Sub-Graph] ──edge nodes──┘
"""
