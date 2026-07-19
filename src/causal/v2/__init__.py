"""
CausalTM v2 — Federated Causal Architecture with STRIDE as Cream Layer.

Architecture:
  Layer 5: STRIDE Threat Model (evaluates architecture against 6 categories)
  Layer 4: Master DAG (cross-layer reasoning, bidirectional propagation)
  Layer 3: Sub-DAGs (extract architectural posture from each source)
  Layer 2: Ingestors (parse raw reports)
  Layer 1: Input Sources (SAST/DAST tools, Git repo)

Key difference from v1:
  - Sub-DAGs extract ARCHITECTURAL STATE, not vulnerability counts
  - Edge nodes represent security POSTURE (auth_posture, crypto_posture, etc.)
  - STRIDE sits ABOVE the Master DAG as the reasoning layer
  - Bidirectional propagation: forward (fix → impact) + backward (target → what to fix)
  - Cross-layer dependencies: fixing in one layer predicts effects in others
"""
