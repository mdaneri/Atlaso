"""Preserve proxy intent and route relationships through desired-state recovery."""

from copy import deepcopy

import pytest
from sqlalchemy import select

from atlaso.app.database import SessionLocal
from atlaso.app.models import EsxStorageSettings, PhysicalInterface, ReverseProxy
from atlaso.app.services.reverse_proxies import save_proxy
from atlaso.app.services.settings_archive import (
    export_settings_archive,
    restore_settings_archive,
)
from tests.services.test_reverse_proxies import payload


def test_archive_round_trip_uses_names_and_legacy_v2_remains_supported(client):
    """Restore nested routes by stable proxy name and accept pre-proxy archives."""
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        assert archive["data"]["reverse_proxy_routes"][0]["proxy_name"] == saved.name
        assert "proxy_id" not in archive["data"]["reverse_proxy_routes"][0]
        assert "id" not in archive["data"]["reverse_proxies"][0]
        result = restore_settings_archive(db, archive)
        assert result["reverse_proxies"] == result["reverse_proxy_routes"] == 1
        db.expire_all()
        restored = db.scalar(select(ReverseProxy))
        assert restored.routes[0].upstream_host == "10.10.20.30"
        legacy = deepcopy(archive)
        legacy["data"].pop("reverse_proxies")
        legacy["data"].pop("reverse_proxy_routes")
        result = restore_settings_archive(db, legacy)
        assert result["reverse_proxies"] == result["reverse_proxy_routes"] == 0


@pytest.mark.parametrize("target", ["served", "upstream"])
def test_archive_reserves_esx_storage_hostname_before_replacement(client, target):
    """Reject archived storage collisions while retaining the saved proxy."""
    with SessionLocal() as db:
        storage = db.scalar(select(EsxStorageSettings))
        if storage is None:
            storage = EsxStorageSettings(hostname="nfs.atlaso.internal")
            db.add(storage)
            db.commit()
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        if target == "served":
            archive["data"]["reverse_proxies"][0]["hostname"] = storage.hostname
        else:
            archive["data"]["reverse_proxy_routes"][0]["upstream_host"] = storage.hostname
        with pytest.raises(ValueError, match="Atlaso"):
            restore_settings_archive(db, archive)
        assert db.get(ReverseProxy, saved.id).hostname == "application.example.test"


@pytest.mark.parametrize("corruption", ["missing_owner", "credentials", "reserved_path", "mixed_protocol", "position"])
def test_invalid_proxy_archive_preserves_saved_state(client, corruption):
    """Reject invalid route ownership and traffic intent before deleting current rows."""
    with SessionLocal() as db:
        interface = db.scalar(select(PhysicalInterface).where(PhysicalInterface.name == "eth2"))
        saved = save_proxy(db, payload(listeners=[{"interface": "eth2", "address": interface.ip_cidr.split("/")[0]}]), actor="test")
        archive = export_settings_archive(db, actor="test")
        route = archive["data"]["reverse_proxy_routes"][0]
        if corruption == "missing_owner":
            route["proxy_name"] = "absent"
        elif corruption == "credentials":
            route["upstream_host"] = "https://user:password@app.example.test"
        elif corruption == "reserved_path":
            route["path_prefix"] = "/api/"
        elif corruption == "position":
            route["position"] = 8
        else:
            archive["data"]["reverse_proxies"][0].update(scheme="http", redirect_http=True)
        with pytest.raises(ValueError):
            restore_settings_archive(db, archive)
        db.expire_all()
        assert db.get(ReverseProxy, saved.id).routes[0].path_prefix == "/"
