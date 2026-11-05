"""Data models and schemas for SecCode Mobile."""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class OWASPCategory(str, Enum):
    M1 = "M1: Improper Credential Usage"
    M2 = "M2: Inadequate Supply Chain Security"
    M3 = "M3: Insecure Authentication/Authorization"
    M4 = "M4: Insufficient Input/Output Validation"
    M5 = "M5: Insecure Communication"
    M6 = "M6: Inadequate Privacy Controls"
    M7 = "M7: Insufficient Binary Protections"
    M8 = "M8: Security Misconfiguration"
    M9 = "M9: Insecure Data Storage"
    M10 = "M10: Insufficient Cryptography"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class Evidence(BaseModel):
    file_path: str
    line_start: int
    line_end: int
    snippet: str
    rule_id: str
    context_before: Optional[str] = None
    context_after: Optional[str] = None


class VulnerabilityFinding(BaseModel):
    id: str
    category: OWASPCategory
    cwe_id: str
    title: str
    description: str
    severity: Severity
    evidence: Evidence
    xai_justification: str
    confidence_score: float = Field(ge=0.0, le=1.0, default=0.9)
    status: FindingStatus = FindingStatus.CONFIRMED


class PatchProposal(BaseModel):
    finding_id: str
    file_path: str
    diff: str
    explanation: str
    original_snippet: str
    repaired_snippet: str


class VerificationResult(BaseModel):
    finding_id: str
    syntax_valid: bool
    guards_passed: bool
    rescan_passed: bool
    plausible: bool
    notes: List[str] = Field(default_factory=list)


class AuditMetrics(BaseModel):
    total_candidates: int = 0
    total_confirmed: int = 0
    total_patches: int = 0
    plausible_patches: int = 0
    plausibility_rate: float = 0.0
    findings_by_category: Dict[str, int] = Field(default_factory=dict)
    duration_seconds: float = 0.0


class AuditReport(BaseModel):
    id: str
    repo_path: str
    timestamp: str
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    patches: List[PatchProposal] = Field(default_factory=list)
    verifications: List[VerificationResult] = Field(default_factory=list)
    metrics: AuditMetrics
