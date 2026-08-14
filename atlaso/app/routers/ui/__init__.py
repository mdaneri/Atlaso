"""Expose the UI domain-router registry without importing the UI facade."""

from atlaso.app.routers.ui.registry import UI_ROUTER_REGISTRY

__all__ = ["UI_ROUTER_REGISTRY"]
