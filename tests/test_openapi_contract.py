def test_openapi_document_is_31_and_has_bearer_security(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["openapi"].startswith("3.1")
    security_schemes = schema["components"]["securitySchemes"]
    assert "HTTPBearer" in security_schemes
    assert security_schemes["HTTPBearer"]["scheme"] == "bearer"


def test_operation_ids_are_unique(client):
    schema = client.get("/openapi.json").json()
    operation_ids = []
    for path_item in schema["paths"].values():
        for operation in path_item.values():
            if isinstance(operation, dict) and "operationId" in operation:
                operation_ids.append(operation["operationId"])
    assert len(operation_ids) == len(set(operation_ids))


def test_initial_api_resources_are_documented(client):
    schema = client.get("/openapi.json").json()
    paths = schema["paths"]
    expected = [
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
            if method not in {"get", "post", "patch", "delete"}:
                continue
            responses = operation["responses"]
            assert responses
            assert any("content" in response or status_code == "204" for status_code, response in responses.items())
