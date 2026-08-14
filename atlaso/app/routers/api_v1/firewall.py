from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi import Path as ApiPath
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from atlaso.app.adapters.system import SystemAdapter
from atlaso.app.audit import record_audit
from atlaso.app.config import get_settings
from atlaso.app.database import get_db
from atlaso.app.models import (
    FirewallRule,
    PhysicalInterface,
    ServiceState,
    VlanInterface,
    utcnow,
)
from atlaso.app.openapi import DocumentedAPIRoute
from atlaso.app.schemas import (
    ConfigApplyResponse,
    ConfigValidationResponse,
    FirewallRuleCreate,
    FirewallRuleResponse,
    FirewallSettingsResponse,
    FirewallSettingsUpdate,
    FirewallStatusResponse,
    ServiceStateResponse,
)
from atlaso.app.security import Identity, require_scope
from atlaso.app.services.firewall import (
    FIREWALL_POLICIES,
    FIREWALL_SOURCE_GROUPS_SETTING_KEY,
    firewall_interface_networks,
    firewall_source_group_state,
    validate_firewall_rule,
)

Endpoint = Callable[..., Any]


@dataclass(frozen=True)
class FirewallApiDependencies:
    assign_firewall_rule_values: Endpoint
    firewall_validation_payload: Endpoint
    get_firewall_settings: Endpoint
    setting_value: Endpoint
    stage_api_firewall_config: Endpoint


@dataclass(frozen=True)
class FirewallApiRouter:
    router: APIRouter
    endpoints: Mapping[str, Endpoint]


def build_router(dependencies: FirewallApiDependencies) -> FirewallApiRouter:
    """Build the extracted domain router without importing its compatibility facade."""
    router = APIRouter(prefix="/api/v1", route_class=DocumentedAPIRoute)
    assign_firewall_rule_values = dependencies.assign_firewall_rule_values
    firewall_validation_payload = dependencies.firewall_validation_payload
    get_firewall_settings = dependencies.get_firewall_settings
    setting_value = dependencies.setting_value
    stage_api_firewall_config = dependencies.stage_api_firewall_config

    @router.get("/firewall/status", response_model=FirewallStatusResponse, tags=["Firewall"], operation_id="getFirewallStatus")
    def get_firewall_status(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> FirewallStatusResponse:
        """Get Firewall Status.

        Requires the `read:firewall` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_firewall_settings(db)
        service = db.execute(select(ServiceState).where(ServiceState.service == "firewall")).scalar_one_or_none()
        rule_count = db.scalar(select(func.count()).select_from(FirewallRule)) or 0
        return FirewallStatusResponse(
            enabled=settings.enabled,
            service=ServiceStateResponse.model_validate(service) if service else None,
            rule_count=rule_count,
            config_path=settings.config_path,
            dry_run=get_settings().dry_run_system_adapters,
        )


    @router.get("/firewall/settings", response_model=FirewallSettingsResponse, tags=["Firewall"], operation_id="getFirewallSettings")
    def get_firewall_settings_api(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> FirewallSettingsResponse:
        """Get Firewall Settings.

        Requires the `read:firewall` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return FirewallSettingsResponse.model_validate(get_firewall_settings(db))


    @router.patch("/firewall/settings", response_model=FirewallSettingsResponse, tags=["Firewall"], operation_id="updateFirewallSettings")
    def update_firewall_settings_api(
        payload: FirewallSettingsUpdate,
        identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
        db: Session = Depends(get_db),
    ) -> FirewallSettingsResponse:
        """Update Firewall Settings.

        Requires the `write:firewall` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings = get_firewall_settings(db)
        values = payload.model_dump()
        if values["default_input_policy"] not in FIREWALL_POLICIES or values["default_forward_policy"] not in FIREWALL_POLICIES or values["default_output_policy"] not in FIREWALL_POLICIES:
            raise HTTPException(status_code=422, detail="Firewall default policies must be accept or drop.")
        for key, value in values.items():
            setattr(settings, key, value)
        settings.updated_at = utcnow()
        db.add(settings)
        db.commit()
        record_audit(db, actor=identity.username, action="update_firewall_settings", resource_type="firewall", resource_id=str(settings.id))
        db.refresh(settings)
        return FirewallSettingsResponse.model_validate(settings)


    @router.get("/firewall/rules", response_model=list[FirewallRuleResponse], tags=["Firewall"], operation_id="listFirewallRules")
    def list_firewall_rules(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> list[FirewallRuleResponse]:
        """List Firewall Rules.

        Requires the `read:firewall` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        return [FirewallRuleResponse.model_validate(row) for row in db.execute(select(FirewallRule).order_by(FirewallRule.priority, FirewallRule.name)).scalars().all()]


    def firewall_groups_for_api_validation(db: Session) -> list[dict[str, Any]]:
        """Return firewall groups for api validation.

        Args:
            db: Active database session.
        """
        physical_interfaces = db.execute(select(PhysicalInterface).order_by(PhysicalInterface.name)).scalars().all()
        vlan_interfaces = db.execute(select(VlanInterface).order_by(VlanInterface.parent_interface, VlanInterface.vlan_id)).scalars().all()
        interface_networks = firewall_interface_networks(
            list(physical_interfaces),
            list(vlan_interfaces),
        )
        state = firewall_source_group_state(
            setting_value(db, FIREWALL_SOURCE_GROUPS_SETTING_KEY),
            interface_networks,
        )
        return list(state["groups"])


    @router.post("/firewall/rules", response_model=FirewallRuleResponse, tags=["Firewall"], operation_id="createFirewallRule")
    def create_firewall_rule_api(
        payload: FirewallRuleCreate,
        identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
        db: Session = Depends(get_db),
    ) -> FirewallRuleResponse:
        """Create Firewall Rule.

        Requires the `write:firewall` API scope. The operation changes saved Atlaso application state;
        any appliance host enforcement remains subject to the documented apply or task boundary for the
        resource.

        Args:
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rule = assign_firewall_rule_values(FirewallRule(), payload.model_dump())
        errors = validate_firewall_rule(rule, firewall_groups_for_api_validation(db), require_group_addresses=True)
        if errors:
            raise HTTPException(status_code=422, detail=" ".join(errors))
        db.add(rule)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"Firewall rule {rule.name} already exists.") from exc
        record_audit(db, actor=identity.username, action="create_firewall_rule", resource_type="firewall_rule", resource_id=str(rule.id))
        db.refresh(rule)
        return FirewallRuleResponse.model_validate(rule)


    @router.patch("/firewall/rules/{rule_id}", response_model=FirewallRuleResponse, tags=["Firewall"], operation_id="updateFirewallRule")
    def update_firewall_rule_api(
        rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')],
        payload: FirewallRuleCreate,
        identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
        db: Session = Depends(get_db),
    ) -> FirewallRuleResponse:
        """Update Firewall Rule.

        Requires the `write:firewall` API scope. The operation updates saved Atlaso state and does not
        bypass the documented global Appliance Apply or service lifecycle boundary.

        Args:
            rule_id: Stable identifier of the associated rule resource.
            payload: Validated request or task payload consumed by the operation.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rule = db.get(FirewallRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Firewall rule not found")
        assign_firewall_rule_values(rule, payload.model_dump())
        errors = validate_firewall_rule(rule, firewall_groups_for_api_validation(db), require_group_addresses=True)
        if errors:
            raise HTTPException(status_code=422, detail=" ".join(errors))
        db.add(rule)
        try:
            db.commit()
        except IntegrityError as exc:
            db.rollback()
            raise HTTPException(status_code=409, detail=f"Firewall rule {rule.name} already exists.") from exc
        record_audit(db, actor=identity.username, action="update_firewall_rule", resource_type="firewall_rule", resource_id=str(rule.id))
        db.refresh(rule)
        return FirewallRuleResponse.model_validate(rule)


    @router.delete("/firewall/rules/{rule_id}", response_model=dict, tags=["Firewall"], operation_id="deleteFirewallRule")
    def delete_firewall_rule_api(
        rule_id: Annotated[int, ApiPath(description='Unique identifier of the rule record addressed by this operation.')],
        identity: Annotated[Identity, Depends(require_scope("write:firewall"))],
        db: Session = Depends(get_db),
    ) -> dict[str, bool]:
        """Delete Firewall Rule.

        Requires the `write:firewall` API scope. Removal or revocation takes effect in Atlaso
        application state; appliance host changes remain subject to the documented apply boundary for
        the resource.

        Args:
            rule_id: Stable identifier of the associated rule resource.
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        rule = db.get(FirewallRule, rule_id)
        if not rule:
            raise HTTPException(status_code=404, detail="Firewall rule not found")
        db.delete(rule)
        db.commit()
        record_audit(db, actor=identity.username, action="delete_firewall_rule", resource_type="firewall_rule", resource_id=str(rule_id))
        return {"deleted": True}


    @router.get("/firewall/validate", response_model=ConfigValidationResponse, tags=["Firewall"], operation_id="validateFirewall")
    def validate_firewall(identity: Annotated[Identity, Depends(require_scope("read:firewall"))], db: Session = Depends(get_db)) -> ConfigValidationResponse:
        """Validate Firewall.

        Requires the `read:firewall` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        settings, _rules, config_preview, errors = firewall_validation_payload(db)
        adapter = SystemAdapter()
        config_path = settings.config_path
        if not adapter.dry_run:
            config_path = stage_api_firewall_config(config_preview)
        result = adapter.validate_firewall_config(config_path)
        return ConfigValidationResponse(
            valid=not errors,
            dry_run=result.dry_run,
            command=result.command,
            config_path=config_path,
            config_preview=config_preview,
            errors=errors,
        )


    @router.post(
        "/firewall/apply",
        response_model=ConfigApplyResponse,
        tags=["Firewall"],
        operation_id="applyFirewall",
        include_in_schema=False,
    )
    def apply_firewall(identity: Annotated[Identity, Depends(require_scope("write:firewall"))], db: Session = Depends(get_db)) -> ConfigApplyResponse:
        """Apply Firewall.

        Requires the `write:firewall` API scope. The action runs through the endpoint's existing audited
        adapter or task boundary; inspect the returned state before treating the operation as complete.

        Args:
            identity: Authenticated identity authorizing the operation.
            db: Active database session used by the operation.
        """
        validation = validate_firewall(identity, db)
        apply_result = SystemAdapter().apply_firewall_config(validation.config_path)
        record_audit(db, actor=identity.username, action="apply_firewall_dry_run", resource_type="firewall", detail=" ".join(apply_result.command))
        payload = validation.model_dump()
        payload["command"] = apply_result.command
        return ConfigApplyResponse(**payload, reloaded=not apply_result.dry_run)


    @router.get("/firewall/logs", response_model=list[str], tags=["Firewall"], operation_id="getFirewallLogs")
    def get_firewall_logs(identity: Annotated[Identity, Depends(require_scope("read:firewall"))]) -> list[str]:
        """Get Firewall Logs.

        Requires the `read:firewall` API scope. This read-only operation does not change saved desired
        state or appliance runtime state.

        Args:
            identity: Authenticated identity authorizing the operation.
        """
        return ["dry-run log source for nftables", "Host nftables logs are not read in development mode."]

    endpoints: dict[str, Endpoint] = {
        "get_firewall_status": get_firewall_status,
        "get_firewall_settings_api": get_firewall_settings_api,
        "update_firewall_settings_api": update_firewall_settings_api,
        "list_firewall_rules": list_firewall_rules,
        "firewall_groups_for_api_validation": firewall_groups_for_api_validation,
        "create_firewall_rule_api": create_firewall_rule_api,
        "update_firewall_rule_api": update_firewall_rule_api,
        "delete_firewall_rule_api": delete_firewall_rule_api,
        "validate_firewall": validate_firewall,
        "apply_firewall": apply_firewall,
        "get_firewall_logs": get_firewall_logs,
    }
    return FirewallApiRouter(router=router, endpoints=endpoints)
