# cc-things

Claude Code plugin marketplace.

## Install

```
/plugin marketplace add oleggohman/cc-things
/plugin install mitre-attack@oleggohman-cc-things
/plugin install whatsapp@oleggohman-cc-things
```

## Plugins

### mitre-attack

MITRE ATT&CK v20 and ATLAS for Claude Code: map incidents, alerts and CloudTrail events to techniques, mitigations, detections and log sources, look up threat groups, and build Navigator layers.

- MCP server: [oleggohman/mitre-attack-mcp](https://github.com/oleggohman/mitre-attack-mcp), run with `uvx`
- Skill: `using-mitre-attack-mcp`, with helper scripts for revoked IDs, detections and Navigator layers

Requires [uv](https://docs.astral.sh/uv/).

### whatsapp

Search, read and send your personal WhatsApp messages and media from Claude, through a local Go bridge linked to your account as a device.

- MCP server: [oleggohman/whatsapp-mcp](https://github.com/oleggohman/whatsapp-mcp). It builds and starts the bridge on first use (1-2 minutes).
- Pair once: ask Claude to "pair WhatsApp with &lt;your number&gt;" and enter the code under Linked devices on your phone.
- Messages, session and token are kept in the plugin data folder, so they survive plugin updates.

Requires [uv](https://docs.astral.sh/uv/), Go and a C compiler; `ffmpeg` is optional for voice notes. Review every send call before approving it: an incoming message can carry prompt injection.
