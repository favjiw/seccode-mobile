"""Configuration settings for SecCode Mobile."""

import os
from pydantic import BaseModel


class EngineConfig(BaseModel):
    api_base: str = os.getenv("LLM_API_BASE", "http://127.0.0.1:20128/v1")
    api_key: str = os.getenv("LLM_API_KEY", os.getenv("OPENAI_API_KEY", "default-key"))
    
    # Model routing by capability
    planner_model: str = os.getenv("SECCODE_PLANNER_MODEL", "ag/gemini-3.8-flash-high")
    detector_model: str = os.getenv("SECCODE_DETECTOR_MODEL", "ag/claude-sonnet-5-5-high")
    repairer_model: str = os.getenv("SECCODE_REPAIRER_MODEL", "ag/claude-sonnet-5-5-high")
    
    # Fallback model if frontier rate limits hit
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
