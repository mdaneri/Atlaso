# Router contract baselines

`route_inventory.json` records every effective Atlaso route in application order, including its plane, path, methods,
name, operation ID, schema visibility, and route kind. `openapi_v1.json` records the complete generated OpenAPI document
after removing only `info.version`, which is generated from the installed application version.

Regenerate both files only for an intentional, reviewed contract change:

```powershell
python scripts/generate_router_contract_baselines.py
python scripts/generate_router_contract_baselines.py --check
```

An ordinary domain extraction under issue #317 must leave both baselines byte-for-byte unchanged.
