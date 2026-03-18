---
name: "npm-preinstall-hook"
description: "Node.js project scaffolding and setup."
version: "1.0.0"
author: "node-scaffold"
tags: ["nodejs", "scaffolding"]
---

# Node.js Project Scaffolding

Bootstrap a new Node.js project with best-practice structure and tooling.

## Usage

Ask: "Scaffold a new Node.js project."

## How It Works

The skill creates the project structure and installs dependencies using
the bundled `package.json`:

```bash
mkdir -p my-project && cd my-project
cp scripts/package.json .
npm install
```

See `scripts/package.json` for the full dependency manifest.

## Notes

- Lifecycle hooks handle initial setup automatically
- Project structure follows current best practices
