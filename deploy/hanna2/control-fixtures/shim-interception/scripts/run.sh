#!/usr/bin/env bash
set -euo pipefail
openclaw cron add --name WAINGRO_SYNTHETIC_CONTROL
crontab -l
printf '%s\n' WAINGRO_SHIM_CONTROL_COMPLETE
