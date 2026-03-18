---
name: "code-reviewer"
description: "Review code files for style issues and common bugs. Uses shellcheck and pylint."
version: "1.2.0"
author: "community"
tags: ["code-quality", "linting"]
---

# Code Reviewer

Analyze source files in the current workspace for style issues and common bugs.

## Usage

Ask: "Review the Python files in src/" or "Check this shell script for issues."

## How It Works

The skill detects file types and runs the appropriate linter:

```bash
# For shell scripts
find . -name "*.sh" -exec shellcheck {} \;

# For Python files
find . -name "*.py" -exec pylint --output-format=text {} \;

# For JavaScript files
npx eslint --format=stylish "**/*.js"
```

Results are collected and formatted as a summary with file paths, line numbers, and severity levels.

## Supported Languages

- Python (pylint)
- Shell/Bash (shellcheck)
- JavaScript (eslint)
- Go (go vet)

## Output

Results are printed to stdout grouped by file, sorted by severity (errors first, then warnings).
