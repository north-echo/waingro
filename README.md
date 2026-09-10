# WAINGRO

AI Agent Security Scanner. Detects malicious patterns in OpenClaw skills and MCP (Model Context Protocol) servers before you install them.

Named after the insider threat from Heat (1995). He ruins everything from the inside. WAINGRO knows one when it sees one.

## Why

Agent tool ecosystems have a trust gap. In February 2026, Bitdefender documented the "ClawHavoc" campaign — coordinated exploitation of the OpenClaw skill ecosystem via malicious skills. In March 2026, we scanned 1,139 MCP servers and found systemic security gaps: 21% access credentials, 13% lack authentication, 9% have path traversal vulnerabilities. Zero tool poisoning — but the implementation bugs are everywhere.

WAINGRO scans both ecosystems from a single tool.

## Install

```bash
pip install git+https://github.com/north-echo/waingro.git
```

Not on PyPI yet.

## Usage

### OpenClaw Skills

```bash
# Scan a skill before installing
waingro scan ./some-skill/

# Scan with JSON output for CI/CD
waingro scan ./some-skill/ --format json --fail-on high

# Audit all installed skills
waingro audit ~/skills/

# Add semantic analysis for skills static rules cannot resolve
waingro scan ./some-skill/ --semantic
```

### Semantic analysis

Static rules cannot tell "block inputs matching this pattern" from "execute this
pattern". That distinction is what separates a security tool from a malicious
skill, and it is the largest source of false positives in this ecosystem: in the
March 2026 ClawHub audit, 20 of 43 initially flagged skills turned out to be
legitimate defensive tools carrying detection signatures.

`--semantic` sends skills that static analysis leaves unresolved (verdict REVIEW
or SUSPICIOUS with a moderate security-tool score) to the Claude API for an
intent judgement. It requires `ANTHROPIC_API_KEY`. Cap spend with
`--semantic-budget`. Skills that static rules already settle are not sent.

### MCP Servers

```bash
# Scan a single MCP server
waingro mcp scan ./mcp-server-github/

# Discover MCP servers from npm, GitHub, and awesome lists
waingro mcp discover --awesome awesome-mcp-servers/README.md -o manifest.json

# Batch scan from discovery manifest
waingro mcp batch manifest.json --results results.json --cleanup
```

## Detection Coverage

### OpenClaw Rules (31 rules)

| Rule ID | Category | Severity | Description | Reference |
|---------|----------|----------|-------------|-----------|
| EXEC-001 | Execution | CRITICAL | curl/wget piped to shell | ClawHavoc |
| EXEC-002 | Execution | CRITICAL | Base64-encoded command execution | ClawHavoc |
| EXEC-003 | Execution | HIGH | eval/exec with dynamic content | — |
| EXEC-004 | Execution | CRITICAL | PowerShell download cradles | — |
| EXEC-005 | Execution | CRITICAL | Hex-decoded command execution | — |
| EXEC-006 | Execution | CRITICAL | Hidden execution in bundled scripts | Polymarket trojan |
| EXFIL-001 | Exfiltration | HIGH | Credential file access | Bitdefender |
| EXFIL-002 | Exfiltration | CRITICAL | macOS Keychain access | — |
| EXFIL-003 | Exfiltration | HIGH | Browser credential access | — |
| EXFIL-004 | Exfiltration | HIGH | OpenClaw workspace scraping | Bitdefender |
| EXFIL-005 | Exfiltration | HIGH | Environment variable harvesting | — |
| EXFIL-006 | Exfiltration | HIGH | Embedded credential patterns | — |
| EXFIL-007 | Exfiltration | HIGH | Clipboard monitoring | — |
| PERSIST-001 | Persistence | HIGH | Crontab modification | — |
| PERSIST-002 | Persistence | HIGH | macOS LaunchAgent/LaunchDaemon | — |
| PERSIST-003 | Persistence | HIGH | systemd unit creation | — |
| PERSIST-004 | Persistence | MEDIUM | Shell profile modification | — |
| NET-001 | Network | CRITICAL | Reverse shell patterns | AuthTool |
| NET-002 | Network | CRITICAL | Known malicious infrastructure | Bitdefender |
| NET-003 | Network | HIGH | Tunnel/proxy setup | — |
| NET-004 | Network | CRITICAL | DNS data exfiltration | — |
| OBFUSC-001 | Obfuscation | LOW–CRITICAL | Base64 blobs, graded by decode/exec sink | — |
| OBFUSC-002 | Obfuscation | MEDIUM | String concatenation tricks | — |
| OBFUSC-003 | Obfuscation | HIGH | Machine-obfuscated bundled code | — |
| INJECT-001 | Injection | HIGH | Prompt injection patterns | — |
| INJECT-002 | Injection | CRITICAL | Jailbreak/DAN patterns | — |
| INJECT-003 | Injection | CRITICAL | Metadata injection | — |
| SOCIAL-001 | Social Engineering | HIGH | Fake dependency installation | 1Password |
| SOCIAL-002 | Social Engineering | HIGH | Fake error messages | ClawHavoc |
| SOCIAL-003 | Social Engineering | CRITICAL | Malicious npm lifecycle hooks | — |
| TYPO-001 | Typosquatting | HIGH | Skill name typosquatting | — |

### MCP Rules (16 rules)

Mapped to [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) and [Adversa AI MCP Security Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/).

| Rule ID | Category | Severity | Description | Maps To |
|---------|----------|----------|-------------|---------|
| MCP-001 | Injection | CRITICAL | Tool description prompt injection | OWASP-03, Adversa #3 |
| MCP-002 | Injection | HIGH | Parameter schema injection | Adversa #11 |
| MCP-003 | Obfuscation | CRITICAL | Obfuscated tool handler code | OWASP-05, Adversa #4 |
| MCP-004 | Execution | CRITICAL | Remote code fetch in handlers | OWASP-04, Adversa #4 |
| MCP-005 | Exfiltration | HIGH | Credential file/env access | OWASP-01, Adversa #8 |
| MCP-006 | Exfiltration | HIGH | Sensitive file access | Adversa #8 |
| MCP-007 | Cross-tool | HIGH-CRIT | MCP client config manipulation | Adversa #7 |
| MCP-008 | Network | CRITICAL | Transport exfiltration (tunnels, shells) | Adversa #13 |
| MCP-009 | Supply chain | HIGH | Rug pull indicators (lifecycle hooks) | OWASP-04, Adversa #14 |
| MCP-010 | Scope escalation | HIGH-CRIT | Capabilities beyond stated purpose | OWASP-02, Adversa #19 |
| MCP-011 | Scope escalation | HIGH | Missing authentication | OWASP-07, Adversa #5 |
| MCP-012 | Execution | HIGH | Path traversal patterns | Adversa #10 |
| MCP-013 | Injection | HIGH-CRIT | Tool name spoofing / homoglyphs | Adversa #12 |
| MCP-014 | Network | HIGH | Unsafe network binding (NeighborJack) | Adversa #13 |
| MCP-015 | Injection | MEDIUM | Resource content poisoning surface | Adversa #18 |
| MCP-016 | Supply chain | HIGH | Package name typosquatting | Adversa #14 |

## Reporting model

Findings are graded and aggregated rather than counted per matching line.

- Encoded content is decoded before it is reported. A blob that is not valid
  base64, or that decodes to an image, font or hash, is not a finding.
- Severity follows the sink on the same line. Decoded and executed outranks
  decoded, which outranks a blob nobody touches.
- Repeats collapse. Many hits of one rule in one file become one finding with
  an occurrence count; a rule firing across four or more files becomes one
  skill-level finding. Nothing is discarded, and severity carries the maximum
  seen in the group.

## Research

- [ClawHub Ecosystem Security Audit](research/clawhub-audit/) — March 2026 audit of 30,037 skills
- MCP Ecosystem Security Scan — March 2026 scan of 1,139 MCP servers (paper forthcoming)

## References

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Adversa AI MCP Security Top 25](https://adversa.ai/mcp-security-top-25-mcp-vulnerabilities/)
- [Vulnerable MCP Project](https://vulnerablemcp.info/)
- [Bitdefender Technical Advisory: OpenClaw Exploitation](https://businessinsights.bitdefender.com/technical-advisory-openclaw-exploitation-enterprise-networks)

## License

MIT
