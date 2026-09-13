# ClawGrid control-plane validation case

This package is a pre-execution dossier for one exact ClawHub artifact. It is
not an execution plan and contains no candidate files. Every authorization gate
in `case.json` is false, no entrypoint is selected, and the validator always
reports `ready_for_execution: false`.

Validate the inert case data locally:

```bash
waingro dynamic check-case deploy/hanna2/cases/clawgrid-connector/case.json
```

Optionally bind it to the frozen local artifact without executing anything:

```bash
waingro dynamic check-case deploy/hanna2/cases/clawgrid-connector/case.json \
  --candidate /path/to/exact/clawgrid-connector
```

The fixed heartbeat response contains only synthetic identifiers and directs
any future action to the disposable guest home. It must not be exposed through
a host or external interface. Before an execution plan can be considered, the
guest harness still needs a fixed-response loopback profile, a read-only staged
OpenClaw skill layout, and inert `openclaw` and `crontab` shims that record argv
without scheduling or invoking an agent.

After those pieces are independently tested with benign fixtures, a separate
review must select exactly one entrypoint and decide whether to open the host
policy, corpus, transfer, and execution gates. This repository does not make
that decision automatically.

Assisted by Claude Code
