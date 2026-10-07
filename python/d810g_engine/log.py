"""Centralized logging for D810G engine."""

import logging


def get_logger(name: str) -> logging.Logger:
    """Get a named logger for a D810G module."""
    logger = logging.getLogger(f"d810g.{name}")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "[D810G %(name)s] %(levelname)s: %(message)s"
        ))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
