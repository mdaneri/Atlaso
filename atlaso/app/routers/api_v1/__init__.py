"""Expose the API v1 domain-router registry without importing the API facade."""

from atlaso.app.routers.api_v1.registry import API_V1_ROUTER_REGISTRY

__all__ = ["API_V1_ROUTER_REGISTRY"]
