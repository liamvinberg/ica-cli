from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ProviderError(RuntimeError):
    pass


class IcaProvider(ABC):
    name: str

    @abstractmethod
    def login(self, username: str, password: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def list_lists(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    def add_item(
        self, list_name: str, item_name: str, quantity: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def search_products(self, store_id: str, query: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def search_deals(
        self,
        store_id: str,
        query: str | None = None,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def search_stores(self, query: str) -> dict[str, Any]:
        raise NotImplementedError
