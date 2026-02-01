# Project: Suricata EVE JSON Analysis

## General Instructions
- Do not read in the entire file unless instructed to. 
- Use `head` because the files are probably over the limit
- Search suricata file format so you will know which event_type to use
- Files will be in the logs directory and may be greater than the agent file limit

## Suricata (EVE) File Format
- Ignore `event_type` of `stats`
- Focus on public destination IPs, not internal RFC 1918 Traffic
- The most important event_types are: dns, tls, quic, flow

## Coding Style
- Use Python or JQ to parse and analyze log files as necessary use `orjson` instead of the built-in `json` library
- Do not remove any scripts after they have been created
- Use `uv` instead of pip and to create a virtual environments
- Do not hardcode file-names use sys.argv for  command-line argument and NOT argparse
- Create a time-stamped markdown file for any work you do (use `analyst_log-YY-DD-HH-MM.md`) that captures how analysis was performed and sample details
- Do not clean up temporary output from analyst scripts but rename them to a a suffix of `YY-DD-HH-MM.md`
