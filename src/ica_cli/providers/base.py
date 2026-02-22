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

    def add_items(
        self,
        list_name: str,
        item_names: list[str],
        quantity: str | None = None,
    ) -> dict[str, Any]:
        added: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        for item_name in item_names:
            try:
                result = self.add_item(
                    list_name=list_name,
                    item_name=item_name,
                    quantity=quantity,
                )
                added.append({"item": item_name, "result": result.get("result")})
            except ProviderError as error:
                errors.append({"item": item_name, "error": str(error)})

        if len(added) == 0 and len(errors) > 0:
            first = errors[0]
            raise ProviderError(
                f"Failed to add items to '{list_name}'. First error for '{first['item']}': {first['error']}"
            )

        return {
            "list": list_name,
            "count": len(added),
            "added": added,
            "errors": errors,
        }

    @abstractmethod
    def remove_item(
        self,
        list_name: str,
        item_name: str,
        all_matches: bool = False,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def set_item_striked(
        self,
        list_name: str,
        item_name: str,
        striked: bool,
        all_matches: bool = False,
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def clear_striked(self, list_name: str) -> dict[str, Any]:
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

    @abstractmethod
    def get_store(self, store_id: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def list_favorite_stores(self) -> dict[str, Any]:
        raise NotImplementedError
