"""Minimal models for image refs and parsed SARIF findings."""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class ImageRef:
    org: str
    repo: str
    tag: str

    @property
    def full_name(self) -> str:
        return f"{self.org}/{self.repo}:{self.tag}"

    def registry_uri(self) -> str:
        return f"registry://{self.full_name}"


@dataclass
class ParsedFinding:
    rule_id: str
    message: str
    artifact_path: str
    severity: str
    security_score: Optional[float]
    purls: List[str]
    affected_version: Optional[str]
    fixed_version: Optional[str]
    short_description: str
    help_text: str
    help_uri: Optional[str] = None
    sarif_version: Optional[str] = None
    sarif_schema: Optional[str] = None
    rule_raw: Dict[str, Any] = field(default_factory=dict)
    result_raw: Dict[str, Any] = field(default_factory=dict)
    tool_driver_full_name: Optional[str] = None

    def to_json_dict(self) -> Dict[str, Any]:
        return asdict(self)
