# WAINGRO

AI Agent Skill Security Scanner. Detects malicious patterns in OpenClaw and Agent Skills format skill files before you install them.

Named after the insider threat from Heat (1995). He ruins everything from the inside. WAINGRO knows one when it sees one.

## Why

In February 2026, Bitdefender found ~900 malicious skills on ClawHub (~17-20% of all published skills). The "ClawHavoc" campaign delivered Atomic Stealer (AMOS) via 300+ coordinated skills. Skills run with system-level permissions — terminal, file system, network. A single malicious skill compromises the entire host.

## Install

```bash
pip install waingro
```

Or with Podman:

```bash
podman build -t waingro .
podman run --rm -v ./skills:/skills:ro waingro scan /skills/some-skill/
```

## Usage

```bash
# Scan a skill before installing
waingro scan ./some-skill/

# Scan with JSON output for CI/CD
waingro scan ./some-skill/ --format json --fail-on high

# Audit all installed skills
waingro audit ~/skills/

# Version
waingro version
```

## Detection Coverage

| Rule ID | Category | Severity | Description | Reference |
|---------|----------|----------|-------------|-----------|
| EXEC-001 | Execution | CRITICAL | curl/wget piped to shell | ClawHavoc |
| EXEC-002 | Execution | CRITICAL | Base64-encoded command execution | ClawHavoc |
| EXEC-003 | Execution | HIGH | eval/exec with dynamic content | — |
| EXEC-004 | Execution | CRITICAL | PowerShell download cradles | — |
| EXFIL-001 | Exfiltration | HIGH | Credential file access | Bitdefender |
| EXFIL-002 | Exfiltration | CRITICAL | macOS Keychain access | — |
| EXFIL-003 | Exfiltration | HIGH | Browser credential access | — |
| EXFIL-004 | Exfiltration | HIGH | OpenClaw workspace scraping | Bitdefender |
| PERSIST-001 | Persistence | HIGH | Crontab modification | — |
| PERSIST-002 | Persistence | HIGH | macOS LaunchAgent/LaunchDaemon | — |
| PERSIST-003 | Persistence | HIGH | systemd unit creation | — |
| PERSIST-004 | Persistence | MEDIUM | Shell profile modification | — |
| NET-001 | Network | CRITICAL | Reverse shell patterns | AuthTool |
| NET-002 | Network | CRITICAL | Known malicious infrastructure | Bitdefender |
| NET-003 | Network | HIGH | Tunnel/proxy setup | — |
| OBFUSC-001 | Obfuscation | MEDIUM | Base64 encoded strings | — |
| OBFUSC-002 | Obfuscation | MEDIUM | String concatenation tricks | — |
| INJECT-001 | Injection | HIGH | Prompt injection patterns | — |
| SOCIAL-001 | Social Engineering | HIGH | Fake dependency installation | 1Password |
| SOCIAL-002 | Social Engineering | HIGH | Fake error messages | ClawHavoc |
| TYPO-001 | Typosquatting | HIGH | Skill name typosquatting | — |

## References

- [Bitdefender Technical Advisory: OpenClaw Exploitation](https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks)
- 1Password analysis of malicious Agent Skills (Feb 2026)
- Repello AI: AI agent supply chain security research

## License

MIT
