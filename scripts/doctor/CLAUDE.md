# Maintain startup checks

Report observable faults without claiming that an unobservable setup is safe.

- Give each concern one executable script, one registered SessionStart command, and at most one JSON object. Source the shared helpers.
- Keep healthy and inapplicable checks silent. Show acknowledged optional findings as ⚪; never hide them entirely or emit green status lines.
- Let the dependency check alone print the static missing-jq alarm before sourcing helpers. Register it before other doctor checks. Let every other check inherit the shared silent exit when jq is absent.
- Keep missing-jq and integrity alarms unsilenceable. Send dynamic values through `jq --arg` and emit through the shared helpers.
- Inspect only local state. Treat RC text and workflow references as evidence of configuration, never proof of active wrappers or enforced branch protection.
