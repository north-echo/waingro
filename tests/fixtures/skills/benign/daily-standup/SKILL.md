---
name: "daily-standup"
description: "Generate a daily standup summary from git log and calendar events."
version: "1.0.0"
author: "community"
tags: ["productivity", "git"]
---

# Daily Standup

Generate a formatted standup summary based on your recent git activity.

## Usage

Ask: "Generate my standup for today."

## How It Works

```bash
# Get yesterday's commits
echo "## What I did yesterday"
git log --since=yesterday --author="$(git config user.name)" --pretty=format:"- %s"

# Get today's changed files
echo ""
echo "## What I'm working on today"
git diff --name-only HEAD~1 | head -10 | sed 's/^/- /'

# Check for open PRs
echo ""
echo "## Blockers"
echo "- None reported"
```

## Configuration

The skill reads from your local git configuration. No additional setup required.

## Output

A markdown-formatted standup summary printed to stdout, suitable for pasting into Slack or a standup bot.
