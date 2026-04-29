"""
core/adaptive — Adaptive memory, dynamic playbooks, anti-monotony runtime.

Phased rollout (see /memories/session/plan.md):
    Phase 1  baseline KPIs + decision audit events           (this package)
    Phase 2  grounded memory: confidence / provenance / freshness  (this package)
    Phase 3  scenario classifier + playbook router (YAML templates)
    Phase 4  repetition handler + tactical memory + auto-pivot
    Phase 5  finding verification loop + operator feedback
    Phase 6  observability + feature-flagged rollout

All capabilities here are opt-in via the `adaptive:` block in config.yaml so
they cannot regress the stable execution path.
"""

from core.adaptive.confidence import (
    ConfidenceScore,
    score_finding,
    score_from_execution,
)
from core.adaptive.decisions import (
    DecisionKind,
    emit_decision,
)
from core.adaptive.kpi import (
    KPIReport,
    compute_kpi_from_path,
    compute_kpi_report,
    iter_audit_rows,
)
from core.adaptive.playbook import (
    Playbook,
    PlaybookNotFound,
    PlaybookRouter,
    PlaybookStep,
    render_advisory,
)
from core.adaptive.repetition import (
    PivotSuggestion,
    RepetitionHandler,
    derive_tactic_status,
    format_tactic_entry,
)
from core.adaptive.scenario import (
    Scenario,
    ScenarioClassifier,
)
from core.adaptive.settings import (
    AdaptiveSettings,
    RolloutMode,
    load_adaptive_settings,
)
from core.adaptive.verification import (
    ConfidenceUpdate,
    FindingManifest,
    apply_operator_feedback,
    apply_verification,
    build_manifest,
)

__all__ = [
    "AdaptiveSettings",
    "ConfidenceScore",
    "ConfidenceUpdate",
    "DecisionKind",
    "FindingManifest",
    "KPIReport",
    "PivotSuggestion",
    "Playbook",
    "PlaybookNotFound",
    "PlaybookRouter",
    "PlaybookStep",
    "RepetitionHandler",
    "RolloutMode",
    "Scenario",
    "ScenarioClassifier",
    "apply_operator_feedback",
    "apply_verification",
    "build_manifest",
    "compute_kpi_from_path",
    "compute_kpi_report",
    "derive_tactic_status",
    "emit_decision",
    "format_tactic_entry",
    "iter_audit_rows",
    "load_adaptive_settings",
    "render_advisory",
    "score_finding",
    "score_from_execution",
]
