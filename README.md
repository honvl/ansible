# ansible

## Dataplane freeze poller (`panos_dp_poller.yml`)

Captures per-second evidence around the ~5 s PAN-OS dataplane freezes (new sessions stop, packet buffer fills, LACP / path
monitor sometimes trip). One-minute counters and tech support files cannot see them.

| File | Purpose |
|---|---|
| `scripts/pa_dp_poller.py` | The poller. Standard library only. Polls both firewalls directly and in parallel (no HA-active detection step). |
| `panos_dp_poller.yml` | AAP2 playbook: runs the poller as one long task, emails event bundles. |
| `tests/` | `python3 -m unittest discover -s tests` |

### Why one long job and not a job every minute
An AAP job needs 10-40 s to start, longer than the freezes. The job pays that once, then the script samples every 5 s
inside it. Each job also begins with `show running resource-monitor second last 60`, which returns the previous 60 s of
per-core CPU, packet buffer and descriptor use in one call, so any gap between two jobs is filled in afterwards. Startup
lag only delays the fetch; it does not lose data.

### AAP2 setup
* Inventory: hosts in `ha_pair` with `primary_ip_address` / `secondary_ip_address` (same as `monitor_memory.yml`).
* Credential: inject `username` / `password` (or `api_key`) as extra vars. They are passed to the script by environment
  variable, never on the command line.
* Job template: playbook `panos_dp_poller.yml`, Timeout 900, **Enable Concurrent Jobs** on, Verbosity 0.
* Schedule: `RRULE:FREQ=MINUTELY;INTERVAL=10` (each job samples for 660 s, so consecutive jobs overlap by about a minute).
* Event bundles (`event_<ip>_<time>.json.gz`) are emailed; nothing is kept in the job container.

### First run: check it understands your firewalls
```
PANOS_USERNAME=... PANOS_PASSWORD=... python3 scripts/pa_dp_poller.py --fw <fw1> --fw <fw2> --once
```
It prints the format it parsed, the number of seconds found and one point sample. `seconds parsed=60` means per-second
history works. If it says 0, the response layout differs from what the parser expects; the raw XML is still saved in the
next event bundle (`second_raw`), send that over.

### What triggers an event
Packet buffer >= 20 %, packet descriptor >= 15 %, 8 or more DP cores at 100 % in one second (`--buf-thresh`,
`--desc-thresh`, `--cores-thresh`), or new connections/s collapsing to under 10 % of its recent median while it was above
500/s (`--freeze-frac`, `--freeze-min-cps`). A bundle holds per-second rows, point samples with response times
(`clock_ms` slow = management plane stalled; `session_ms` slow or `cps` 0 with `clock_ms` fast = dataplane stalled),
ingress backlogs and a counter diff. One sustained event makes one bundle per 120 s (`--cooldown`).

### Notes
* Per-second times are estimated from the fetch time: good to about +-2 s when matching Panorama logs.
* Load on the management plane: a `show clock`, `show session info` and `ingress-backlogs` probe every 5 s, one
  `second last 60` per 45 s and `show counter global` per minute (the heaviest call; raise `--counter-interval` if
  management-plane CPU is a concern). Use `--interval 10` to halve the probe rate.
* The text form of the per-second output is tested against real PA-3420 output. The structured XML form follows the
  documented field names but has not been run against a live firewall, so use `--once` first.
* Management certificates are not verified unless `--verify-tls` is given (the other playbooks here do the same).
