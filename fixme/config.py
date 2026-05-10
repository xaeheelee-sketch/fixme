from __future__ import annotations
import os
import uuid
from pathlib import Path
from typing import Any
import yaml
from pydantic import BaseModel, Field


class ScopeConfig(BaseModel):
    enabled_cwes: list[str]
    min_severity: str
    path_allowlist: list[str] = Field(default_factory=list)
    path_blocklist: list[str] = Field(default_factory=list)
    safety_critical_paths: list[str] = Field(default_factory=list)


class ModelsConfig(BaseModel):
    triage: str
    fixer: str
    analyzer: str


class LimitsConfig(BaseModel):
    max_retries: int = 3
    max_diff_lines: int = 30
    per_run_token_budget: int = 5_000_000


class RunnersConfig(BaseModel):
    build_cmd: str
    test_cmd: str
    sanitizer_cmd: str = ""
    metis_cmd: str
    sanitizer_enabled: bool = True


class PathsConfig(BaseModel):
    whitelist_rules: str = "config/whitelist_rules.yaml"
    feedback_db: str = "feedback/decisions.jsonl"
    output_dir: str = "out"


class Config(BaseModel):
    run_id: str
    api_base: str
    api_key_env: str = "INTERNAL_LLM_API_KEY"
    scope: ScopeConfig
    models: ModelsConfig
    limits: LimitsConfig
    runners: RunnersConfig
    paths: PathsConfig

    @property
    def api_key(self) -> str:
        return os.environ.get(self.api_key_env, "")

    @property
    def output_run_dir(self) -> Path:
        return Path(self.paths.output_dir) / self.run_id


def load_config(path: str | Path) -> Config:
    data: dict[str, Any] = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if data.get("run_id") in (None, "auto", ""):
        data["run_id"] = uuid.uuid4().hex[:12]
    return Config(**data)
