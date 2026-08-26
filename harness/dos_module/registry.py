"""Module registry: config-driven vector selection.

ASSUMED INTERFACE -- see interface.py's module docstring and
harness/REPORT.md. No upstream MCPSecBench registry exists to conform to;
this is a conventional decorator-based registry pattern.
"""
from __future__ import annotations

from typing import Dict, Type

from .interface import AttackModule

_REGISTRY: Dict[str, Type[AttackModule]] = {}


def register_module(vector_id: str):
    """Class decorator: `@register_module("oversized_body")` on an
    AttackModule subclass registers it under that vector id and stamps
    `cls.vector_id` to match."""

    def _decorator(cls: Type[AttackModule]) -> Type[AttackModule]:
        if vector_id in _REGISTRY and _REGISTRY[vector_id] is not cls:
            raise ValueError(f"duplicate vector_id registration: {vector_id!r}")
        cls.vector_id = vector_id
        _REGISTRY[vector_id] = cls
        return cls

    return _decorator


def get_module(vector_id: str) -> Type[AttackModule]:
    try:
        return _REGISTRY[vector_id]
    except KeyError as exc:
        raise KeyError(
            f"unknown vector_id {vector_id!r}; registered: {sorted(_REGISTRY)}"
        ) from exc


def list_modules() -> list[str]:
    return sorted(_REGISTRY)


def all_modules() -> Dict[str, Type[AttackModule]]:
    return dict(_REGISTRY)


def clear_registry() -> None:
    """Test-only helper: reset registry state between isolated test runs."""
    _REGISTRY.clear()
