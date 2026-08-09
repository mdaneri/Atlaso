from collections.abc import Iterator
from typing import Any

from atlaso.app.api.network_boot import public_router as network_boot_public_router
from atlaso.app.oidc import public_router as oidc_public_router
from atlaso.app.ui import router as ui_router
from atlaso.app.web_terminal import router as web_terminal_router


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def iter_operations(schema: dict[str, Any]) -> Iterator[tuple[str, str, dict[str, Any]]]:
    for path, path_item in schema["paths"].items():
        for method, operation in path_item.items():
            if method in HTTP_METHODS:
                yield path, method, operation


def iter_schema_properties(
    node: object,
    *,
    location: str,
) -> Iterator[tuple[str, str, dict[str, Any]]]:
    if isinstance(node, dict):
        for name, value in node.get("properties", {}).items():
            yield location, name, value
        for key, value in node.items():
            yield from iter_schema_properties(value, location=f"{location}/{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from iter_schema_properties(value, location=f"{location}/{index}")


def test_openapi_document_is_31_and_has_bearer_security(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["openapi"].startswith("3.1")
    security_schemes = schema["components"]["securitySchemes"]
    assert "HTTPBearer" in security_schemes
    assert security_schemes["HTTPBearer"]["scheme"] == "bearer"
    assert security_schemes["HTTPBearer"]["bearerFormat"] == "JWT"
    assert len(security_schemes["HTTPBearer"]["description"].strip()) >= 40
    assert "/api/v1" in schema["info"]["description"]


def test_openapi_contains_only_the_versioned_management_api(client):
    schema = client.get("/openapi.json").json()

    assert schema["paths"]
    assert all(path.startswith("/api/v1") for path in schema["paths"])
    assert "/identity/.well-known/openid-configuration" not in schema["paths"]
    assert "/pxe/boot.ipxe" not in schema["paths"]
    assert "/terminal" not in schema["paths"]
    assert "/dashboard" not in schema["paths"]


def test_non_versioned_protocol_and_ui_routes_remain_registered():
    assert "/identity/.well-known/openid-configuration" in {route.path for route in oidc_public_router.routes}
    assert "/pxe/boot.ipxe" in {route.path for route in network_boot_public_router.routes}
    assert "/terminal" in {route.path for route in web_terminal_router.routes}
    assert "/dashboard" in {route.path for route in ui_router.routes}


def test_every_openapi_operation_has_detailed_documentation(client):
    schema = client.get("/openapi.json").json()
    declared_tags = {tag["name"]: tag for tag in schema["tags"]}
    used_tags: set[str] = set()

    for path, method, operation in iter_operations(schema):
        assert operation.get("operationId"), f"{method.upper()} {path} has no operation ID"
        assert operation.get("summary", "").strip(), f"{method.upper()} {path} has no summary"
        description = operation.get("description", "").strip()
        assert len(description) >= 80, f"{method.upper()} {path} has no detailed description"
        assert operation.get("tags"), f"{method.upper()} {path} has no tag"
        used_tags.update(operation["tags"])

        for parameter in operation.get("parameters", []):
            parameter_description = parameter.get("description", "").strip()
            assert len(parameter_description) >= 20, (
                f"{method.upper()} {path} parameter {parameter['name']} has no detailed description"
            )

        success_responses = [
            response for status_code, response in operation["responses"].items() if status_code.startswith("2")
        ]
        assert success_responses, f"{method.upper()} {path} has no success response"
        for response in success_responses:
            response_description = response.get("description", "").strip()
            assert response_description != "Successful Response"
            assert len(response_description) >= 30, f"{method.upper()} {path} has no detailed success response"

        validation_schema = operation["responses"]["422"]["content"]["application/json"]["schema"]
        assert validation_schema == {"$ref": "#/components/schemas/ProblemDetails"}

    assert used_tags == set(declared_tags)
    for name in used_tags:
        assert len(declared_tags[name]["description"].strip()) >= 20


def test_every_openapi_schema_property_has_a_description(client):
    schema = client.get("/openapi.json").json()
    properties = [
        property_entry
        for schema_name, component in schema["components"]["schemas"].items()
        for property_entry in iter_schema_properties(component, location=schema_name)
    ]

    assert properties
    for location, name, property_schema in properties:
        description = property_schema.get("description", "").strip()
        assert len(description) >= 20, f"{location} property {name} has no detailed description"


def test_operation_ids_are_unique(client):
    schema = client.get("/openapi.json").json()
    operation_ids = [operation["operationId"] for _, _, operation in iter_operations(schema)]
    assert len(operation_ids) == len(set(operation_ids))


def test_initial_api_resources_are_documented(client):
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    expected = [
        "/api/v1/version",
        "/api/v1/auth/me",
        "/api/v1/api-tokens",
        "/api/v1/dashboard",
        "/api/v1/interfaces/physical",
        "/api/v1/vlans",
        "/api/v1/routes",
        "/api/v1/nat/rules",
        "/api/v1/wan/policies",
        "/api/v1/wan/status",
        "/api/v1/dns/status",
        "/api/v1/dns/settings",
        "/api/v1/dns/records",
        "/api/v1/dhcp/status",
        "/api/v1/dhcp/settings",
        "/api/v1/dhcp/scopes",
        "/api/v1/firewall/status",
        "/api/v1/firewall/settings",
        "/api/v1/firewall/rules",
        "/api/v1/vcf-offline-depot/status",
        "/api/v1/repository/status",
        "/api/v1/esxi-pxe/custom-variables",
        "/api/v1/esxi-pxe/kickstarts",
        "/api/v1/esxi-pxe/isos",
        "/api/v1/esxi-pxe/hosts",
        "/api/v1/vcf-backups/status",
        "/api/v1/esx-storage/status",
        "/api/v1/esx-storage/disks",
        "/api/v1/esx-storage/volumes",
        "/api/v1/esx-storage/shares",
        "/api/v1/services",
        "/api/v1/logs",
        "/api/v1/audit",
        "/api/v1/jobs",
        "/api/v1/settings",
        "/api/v1/oidc/group-mappings",
        "/api/v1/oidc/clients/{client_record_id}",
        "/api/v1/oidc/clients/{client_record_id}/integration-export",
        "/api/v1/oidc/signing-keys/{key_id}",
    ]
    for path in expected:
        assert path in paths


def test_appliance_version_openapi_contract_is_public(client):
    schema = client.get("/openapi.json").json()
    operation = schema["paths"]["/api/v1/version"]["get"]

    assert operation["operationId"] == "getApplianceVersion"
    assert operation["tags"] == ["Appliance"]
    assert operation.get("security", []) == []
    response_schema = operation["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema == {"$ref": "#/components/schemas/ApplianceVersionResponse"}
    properties = schema["components"]["schemas"]["ApplianceVersionResponse"]["properties"]
    assert set(properties) == {"version", "base_version", "git_commit", "built_at"}


def test_esxi_custom_variable_openapi_contract(client):
    schema = client.get("/openapi.json").json()
    collection = schema["paths"]["/api/v1/esxi-pxe/custom-variables"]
    item = schema["paths"]["/api/v1/esxi-pxe/custom-variables/{variable_name}"]
    assert collection["get"]["operationId"] == "listEsxiCustomVariables"
    assert collection["post"]["operationId"] == "createEsxiCustomVariable"
    assert item["put"]["operationId"] == "updateEsxiCustomVariable"
    assert item["delete"]["operationId"] == "deleteEsxiCustomVariable"
    assert "EsxiCustomVariableCreate" in schema["components"]["schemas"]
    assert "EsxiCustomVariableResponse" in schema["components"]["schemas"]
    assert "EsxiCustomVariableUpdate" in schema["components"]["schemas"]


def test_oidc_group_mapping_openapi_contract(client):
    schema = client.get("/openapi.json").json()
    path = schema["paths"]["/api/v1/oidc/group-mappings"]
    assert path["get"]["operationId"] == "listOidcGroupMappings"
    assert path["post"]["operationId"] == "createOidcGroupMapping"
    assert "OidcGroupMappingCreate" in schema["components"]["schemas"]
    assert "OidcGroupMappingResponse" in schema["components"]["schemas"]


def test_oidc_administration_lifecycle_openapi_contract(client):
    schema = client.get("/openapi.json").json()
    client_path = schema["paths"]["/api/v1/oidc/clients/{client_record_id}"]
    assert client_path["put"]["operationId"] == "updateOidcClient"
    export_path = schema["paths"][
        "/api/v1/oidc/clients/{client_record_id}/integration-export"
    ]
    assert export_path["get"]["operationId"] == "exportOidcClientIntegration"
    key_path = schema["paths"]["/api/v1/oidc/signing-keys/{key_id}"]
    assert key_path["delete"]["operationId"] == "deleteRetiredOidcSigningKey"
    assert "OidcClientUpdate" in schema["components"]["schemas"]
    assert "OidcIntegrationExport" in schema["components"]["schemas"]


def test_route_wan_mode_contract_is_interface_only(client):
    schema = client.get("/openapi.json").json()
    wan_mode = schema["components"]["schemas"]["RouteCreate"]["properties"]["wan_mode"]

    assert wan_mode.get("const") == "interface" or wan_mode.get("enum") == ["interface"]


def test_api_routes_have_response_models_or_documented_204(client):
    schema = client.get("/openapi.json").json()
    for path, path_item in schema["paths"].items():
        if not path.startswith("/api/v1"):
            continue
        for method, operation in path_item.items():
            if method not in HTTP_METHODS:
                continue
            responses = operation["responses"]
            assert responses
            assert any("content" in response or status_code == "204" for status_code, response in responses.items())
