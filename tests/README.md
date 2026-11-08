# Atlaso test fixtures

The task-history database fixture isolates installed operational log redactors and restores the original filter
objects at teardown. Its copies preserve parser state, destination thresholds, and sharing between handlers. Synthetic
private-key fragments therefore remain concealed during the test without affecting later logging assertions.
Production handler replacement continues to preserve redaction state.

The following ordered regression initializes application logging, exercises fragmented task-history audit input, and
then checks ordinary file output and audit redaction:

```powershell
python -m pytest `
  tests/routers/api_v1/test_settings.py::test_settings_api_updates_root_ssh_desired_state `
  'tests/test_task_log_history.py::test_task_marker_fragments_survive_commits[20000-audit]' `
  tests/test_ui.py::test_configure_logging_writes_main_app_log `
  tests/test_ui.py::test_record_audit_writes_redacted_operational_log
```

The ordered run catches process-state leaks that isolated invocations can miss. See
[CONTRIBUTING.md](../CONTRIBUTING.md) for the contribution and validation workflow.
