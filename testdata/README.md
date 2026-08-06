# Shared test fixtures

## `stop_marker_cases.json`

The `STOPPED` marker is read twice, by different code in different languages:

- `box/probe.go` decides whether the report says an app is stopped, and
  `box/diagnose.go` keys `app_down` off that;
- the deploy script `scripts/alpine.sh` generates decides whether a deploy
  starts the app.

**They must agree about the same file.** An app the report calls stopped while
the deploy starts it is komizo#57's state: running, never pages, nothing says
alerting is off.

Both tests read these cases -- `box/probe_test.go` and
`scripts/deploy_stopped_test.go` -- so the pair cannot drift apart. They used to
be two hand-maintained tables kept in step by a comment, and deleting a case
from either one left the whole suite green, including in the direction that
matters: the shell growing a case the Go reader was never asked about.

`record` is the app's record as it appears on disk. `stopped` is what BOTH
readers must conclude. `why` is for whoever is reading a failure.

The shell side has one case that is not here -- no record at all -- because it
means different things on the two sides: to the deploy it means "proceed", and
to the report it means the app does not exist. It is asserted where it belongs,
with that reason written beside it.
