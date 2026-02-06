#!/bin/bash

SOURCE_BASE="${GEMINI_SKILLS_SOURCE:-$HOME/.gemini/skills}"
DEST_BASE="${SEC_SKILLZ_REPO:-$HOME/github/sec-skillz}"

# 2. Check for the skill name argument
if [ -z "$1" ]; then
    echo "Error: No skill name provided."
    echo "Usage: $0 <skill-name>"
    exit 1
fi

SKILL_NAME="$1"
SRC_PATH="$SOURCE_BASE/$SKILL_NAME"
DEST_PATH="$DEST_BASE/$SKILL_NAME"

# 3. Validation
# Check if the source skill exists
if [ ! -d "$SRC_PATH" ]; then
    echo "❌ Error: Source directory does not exist: $SRC_PATH"
    exit 1
fi

# Check if the destination base repo exists
if [ ! -d "$DEST_BASE" ]; then
    echo "❌ Error: Destination repository root does not exist: $DEST_BASE"
    exit 1
fi

# 4. Perform the Sync
echo "🔄 Syncing '$SKILL_NAME'..."
echo "   From: $SRC_PATH"
echo "   To:   $DEST_PATH"

# Rsync Options:
# -a : Archive mode (recursive, preserves permissions, timestamps, owners, groups)
# -v : Verbose (shows output of what is being transferred)
# --delete : Deletes files in destination that are no longer in source
# The trailing slash on $SRC_PATH/ is CRITICAL. It tells rsync to copy contents, not the folder itself.

rsync -av --delete "$SRC_PATH/" "$DEST_PATH/"

if [ $? -eq 0 ]; then
    echo "✅ Synchronization complete."
else
    echo "⚠️ Synchronization failed."
fi
