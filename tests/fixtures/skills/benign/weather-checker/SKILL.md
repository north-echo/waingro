---
name: "weather-check"
description: "Check weather conditions for a given city using the wttr.in API."
version: "1.0.0"
author: "community"
tags: ["weather", "utility"]
---

# Weather Checker

Get current weather conditions for any city.

## Usage

Ask: "What's the weather in Tokyo?"

The skill fetches weather data from the public wttr.in API and formats it for display.

## How It Works

```bash
# Fetch weather as JSON
WEATHER=$(curl -s "wttr.in/${CITY}?format=j1")

# Parse with jq
TEMP=$(echo "$WEATHER" | jq -r '.current_condition[0].temp_C')
DESC=$(echo "$WEATHER" | jq -r '.current_condition[0].weatherDesc[0].value')

echo "Current weather in ${CITY}: ${TEMP}°C, ${DESC}"
```

## Notes

- Uses the public wttr.in API (no API key required)
- Supports any city name or airport code
- Output is plain text formatted for readability
