"""Configuration settings for SecCode Mobile."""

import os
from pydantic import BaseModel


def _resolve_api_credentials() -> tuple[str, str]:
    """Auto-resolves 9router base URL and API key from environment or ~/.hermes/.env."""
    base_url = os.getenv("LLM_API_BASE", "http://127.0.0.1:20128/v1")
    api_key = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY")

    if not api_key:
        env_file = os.path.expanduser("~/.hermes/.env")
        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, v = line.split("=", 1)
                            if k.strip() == "OPENAI_API_KEY":
                                api_key = v.strip()
                                break
            except Exception:
                pass

    return base_url, api_key or "default-key"


_default_base, _default_key = _resolve_api_credentials()


class EngineConfig(BaseModel):
    api_base: str = _default_base
    api_key: str = _default_key

    # Model routing by capability & task difficulty (Antigravity free tier via 9router)
    # Agent 1 (Planner): Fast structural exploration and candidate triage
    planner_model: str = os.getenv("SECCODE_PLANNER_MODEL", "ag/gemini-3.8-flash-high")
    
    # Agent 2 (Detector & Explainer): Deep reasoning, evidence grounding, XAI justification
    detector_model: str = os.getenv("SECCODE_DETECTOR_MODEL", "ag/claude-sonnet-5-5-high")
    
    # Agent 3 (Repairer / Fixer): High-precision code generation and constraint-adherent patches
    repairer_model: str = os.getenv("SECCODE_REPAIRER_MODEL", "ag/claude-sonnet-5-5-high")
    
    # Agent 4 (Deterministic Verifier): PURE PYTHON CODE (No LLM, zero hallucination)

    # Fallback model when frontier rate limits are encountered
    fallback_model: str = "ag/gemini-3.8-flash-high"

    # Deterministic verifier rules
    forbidden_modified_patterns: list[str] = [
        r"test/.*",
        r".*_test\.dart$",
        r"analysis_options\.yaml$",
    ]

    forbidden_suppression_tokens: list[str] = [
        "// ignore:",
        "// ignore_for_file:",
        "nosemgrep",
        "# nosec",
    ]

    request_timeout: float = 60.0
    max_retries: int = 2


default_config = EngineConfig()
