"""D810G engine configuration -- user-configurable settings."""

from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class D810GConfig:
    """Engine configuration with sensible defaults."""

    # MBA settings
    mba_max_iterations: int = 10
    mba_verify: bool = True
    mba_rules_dir: str = ""  # empty = use default

    # Opaque predicate settings
    opaque_timeout_ms: int = 5000
    opaque_bit_width: int = 32

    # Pipeline settings
    pipeline_max_iterations: int = 3
    pipeline_enabled_passes: list[str] = field(default_factory=list)  # empty = all

    # Symbolic execution settings
    symbolic_max_instructions: int = 200
    symbolic_timeout_seconds: int = 5

    # String decryption settings
    strings_score_threshold: float = 0.80
    strings_max_results: int = 5


# Global default config
_config = D810GConfig()


def get_config() -> D810GConfig:
    """Get the current engine configuration."""
    return _config


def set_config(config: D810GConfig) -> None:
    """Set the engine configuration."""
    global _config
    _config = config
