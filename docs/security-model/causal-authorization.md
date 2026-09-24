# Causal Authorization Security Model

## Core Philosophy

Traditional authorization models ask:
> *"Does Agent A have permission to call Tool X?"*

CAGE asks:
> *"Given the historical causal trajectory $T$, originating from verified intent $I$, and traversing intermediate data nodes $\{D_1, D_2, \dots, D_n\}$, is proposed action $A_{n+1}$ authorized under policy $P$?"*

## Formal Trajectory Representation

A trajectory $T$ is represented as a directed graph:
$$G = (V, E)$$
Where:
- $V = V_{\text{intent}} \cup V_{\text{action}} \cup V_{\text{observation}} \cup V_{\text{artifact}}$
- $E \subseteq V \times V$ represents causal dependencies:
  - $(v_i, v_j) \in E_{\text{causes}}$: Action $v_i$ triggered action or observation $v_j$.
  - $(v_i, v_j) \in E_{\text{flow}}$: Data or artifact $v_i$ was consumed by action $v_j$.
