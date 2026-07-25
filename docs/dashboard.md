# Dashboard

`/dashboard` is Atlaso's authenticated operations command center. It is a
read-only orientation surface: operators can see current health and follow
links into the owning workflow, but the dashboard never applies configuration,
restarts a service, or mutates appliance state.

## Overall state

The status band reports one of three states:

- `Setup incomplete` while management networking is not healthy or no global
  appliance-apply task has succeeded;
- `Needs attention` when setup is complete and an actionable exception exists;
- `Healthy` when setup is complete and no actionable exception exists.

The primary action follows the current state. Setup links to the first
incomplete readiness item, attention links to the highest-priority exception,
valid pending changes link to Appliance Apply, active work links to Tasks, and
an otherwise healthy appliance links to Monitor.

## Readiness and attention

Readiness covers management-interface discovery, management address/link
health, Appliance Settings validity, whole desired-state validity, and the
first successful global appliance apply. Readiness mode ends only after the
management path is healthy and a global appliance-apply task has succeeded.

Actionable exceptions use this fixed priority:

1. changed appliance-apply units that fail validation;
2. failed tasks created during the last 24 hours;
3. enabled services that are stopped or unhealthy;
4. configured physical interfaces that are missing or unexpectedly down.

Valid changed units stay in the separate Changes & Tasks summary. Disabled
optional services and interfaces whose desired role and mode are both `unused`
do not create attention items.

## Private snapshot and refresh

The initial page and session-authenticated `GET /dashboard/data` endpoint use
the same snapshot builder. The private response contains generated time,
overall state, readiness, attention, pending-change and task summaries, service
and network summaries, and six recent activity rows. Activity rows expose only
source, title, outcome, actor, time, and destination URL. Task results, command
output, raw errors, audit detail, and secrets are never dashboard fields.

The browser refreshes every 30 seconds while the page is visible, pauses while
hidden, and refreshes immediately after becoming visible. A failed refresh
keeps the last successful DOM and displays a stale-data notice.

`/api/v1/dashboard` remains the existing bearer-authenticated public API and is
not backed by this private UI response.
