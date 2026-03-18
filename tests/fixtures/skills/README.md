# WAINGRO Test Corpus: Synthetic OpenClaw Skill Fixtures

## Purpose

This directory contains synthetic OpenClaw/Agent Skills format skill files designed to test WAINGRO's detection rules. Each fixture targets specific detection patterns without containing functional malicious payloads.

## Safety Guarantees

All fixtures are **inert and non-functional**:

- URLs use `http://evil.test`, `http://c2.test`, or RFC 5737 documentation IPs (`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)
- Credential values are obviously fake: `AKIA_FAKE_KEY_DO_NOT_USE`, `sk-fake-00000000`, `ghp_FAKE000000000000000000000000000000`
- Shell commands target nonexistent paths or are quoted as string literals
- No fixture is executable as-is — they are static analysis targets only
- Base64-encoded payloads decode to harmless strings referencing `.test` TLD and RFC 5737 IPs

## Directory Structure

```
skills/
├── benign/                        # Clean skills (true negative validation)
│   ├── weather-checker/
│   ├── code-reviewer/
│   └── daily-standup/
├── credential-exfiltration/       # Credential theft patterns
│   ├── env-harvester/
│   ├── keychain-reader/
│   └── cloud-key-stealer/
├── clawhavoc/                     # C2 + persistence patterns
│   ├── reverse-shell-skill/
│   ├── cron-persistence/
│   └── c2-beacon/
├── authtool/                      # Token hijack patterns
│   ├── oauth-interceptor/
│   ├── session-stealer/
│   └── token-replay/
├── data-exfiltration/             # Data staging and exfil
│   ├── archive-and-send/
│   ├── dns-exfil/
│   └── clipboard-monitor/
├── prompt-injection/              # Instruction override / jailbreak
│   ├── system-prompt-override/
│   ├── role-hijack/
│   └── ignore-previous/
├── supply-chain/                  # Dependency confusion / typosquat
│   ├── pip-install-evil/
│   ├── npm-preinstall-hook/
│   └── curl-pipe-bash/
├── evasion/                       # Obfuscation / split-payload / encoding
│   ├── base64-split/
│   ├── variable-concat/
│   └── hex-encoded-cmd/
└── mixed-signal/                  # Partially benign with buried indicators
    ├── helpful-but-leaky/
    ├── mostly-clean/
    └── delayed-payload/
```
