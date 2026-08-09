---
title: Python documentation
description: Write maintainable Python docstrings and implementation comments without duplicating type hints.
audience:
  - contributor
  - maintainer
status: current
---

# Python documentation

Every tracked Python module, class, function, and method should explain its purpose at the point of definition. Atlaso
uses PEP 257 docstrings with Google-style sections where a summary alone cannot express the contract.

## Docstrings

- Start with a concise imperative summary that describes observable behavior, such as `Return`, `Validate`, `Create`,
  or `Render`.
- Document arguments when their meaning, units, trust boundary, or lifecycle role is not clear from the name and type
  hint. Do not repeat type information from the signature.
- Describe a return value in the summary for a simple accessor or predicate. Use a `Returns` section when the returned
  object, ownership, normalization, or state needs more explanation.
- List exceptions intentionally raised by the function under `Raises`. Describe the condition that triggers each
  exception rather than restating its class name.
- Record important side effects, security boundaries, persistence behavior, cleanup guarantees, and ordering
  constraints in the docstring body.
- Describe public class fields and initialized instance attributes in a Google-style `Attributes` section. Reuse
  Pydantic field descriptions where they already define the API contract, and do not repeat Python type annotations.
- Document `@property` accessors on the accessor itself, including lifecycle or side-effect behavior that is not clear
  from the property name.
- Keep test docstrings focused on the behavior or regression being verified. Test setup remains in fixtures and code,
  not a narration of each statement.

Use Google-style sections only when needed:

```python
def create_host(hostname: str, mac_address: str, enabled: bool = True) -> Host:
    """Create a PXE host.

    Args:
        hostname: DNS hostname assigned to the host.
        mac_address: MAC address used to identify the provisioning target.
        enabled: Whether provisioning is enabled for this host.

    Returns:
        The newly created host.

    Raises:
        ValueError: If the MAC address is invalid.
        HostExistsError: If a host with the same identity already exists.
    """
```

## Implementation comments

Use `#` comments for rationale that cannot be made clear through naming or structure. Good subjects include protocol
requirements, platform compatibility, security decisions, unusual limits, race prevention, lifecycle ordering, and
workarounds with a still-relevant reason.

Do not narrate the next statement or preserve old code in comments. Remove obsolete commented-out code and rely on Git
history. Keep useful existing comments accurate when the surrounding implementation changes.

## Validation

Run the repository's normal Python and documentation checks after changing docstrings or comments:

```powershell
python -m compileall atlaso scripts tests
python scripts/check_repo.py
npm run lint:markdown
python scripts/check_docs.py
git diff --check
```

Review the rendered diff as prose as well as code. A docstring can be syntactically valid while still being redundant,
misleading, or incomplete.
