from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AuthResult:
    provider: str
    status: str
    details: dict[str, Any]


@dataclass
class ShoppingList:
    id: str
    name: str
    rows: list[dict[str, Any]]
