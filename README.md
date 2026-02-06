# Security Skillz

A collection of specialized agent skills for security analysis.

## Available Skills

### Suricata Analyst
**Location:** `skills/suricata-analyst/`  
**Description:** Analyzes Suricata EVE JSON logs using Python, DuckDB, polars, and jq, emphasizing performance, persistence, and structured logging.

### CloudTrail Analyst
**Location:** `skills/cloudtrail-analyst/`  
**Description:** Analyzes AWS CloudTrail logs using Python, DuckDB, and jq, emphasizing performance, persistence, and structured logging.

## Non-Skill Content

### Utility Scripts
- `bin/skill-sync.sh`: rsync-based helper for syncing a single skill directory from a local skills source into this repo (see `GEMINI_SKILLS_SOURCE` and `SEC_SKILLZ_REPO` env vars inside the script).

### Reference / Original Work
- `original/`: archived or exploratory scripts and notes that are not packaged as Codex skills (e.g., `original/ndr/suricata/` and `original/asm/amass/`).
