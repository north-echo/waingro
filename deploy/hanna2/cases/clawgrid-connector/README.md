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
a host or external interface. The case also pins a synthetic `.clawgrid`
configuration containing no real credential.

The generic guest harness now supports the required fixed-response profile,
read-only OpenClaw skill layout, read-only synthetic JSON, and inert `openclaw`
and `crontab` interception. The sinkhole response is bound to the exact HTTPS
host, SNI name, `POST` method, path, content digest, and size. The guest first
proves that no real executable exists for either shim name. None of these
components has yet been validated on hanna2.

Validate the complete, non-authorizing benign control catalog locally:

```bash
waingro dynamic check-controls deploy/hanna2/control-suite.json
```

After those pieces are independently tested with benign fixtures, a separate
review must select exactly one entrypoint and decide whether to open the host
policy, corpus, transfer, and execution gates. This repository does not make
that decision automatically. No ClawGrid candidate has been transferred or
executed by this work.

Assisted by Claude Code
