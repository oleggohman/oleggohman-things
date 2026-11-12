# cc-things

Plugins for [Claude Code](https://claude.com/claude-code): MCP servers and skills, organized as a marketplace of independent plugins. Install only the ones you need.

## Install

Add the marketplace, then install the plugins you want:

    /plugin marketplace add oleggohman/cc-things

    /plugin install mitre-attack@oleggohman-cc-things

Update later with:

    /plugin marketplace update oleggohman-cc-things

## Plugins

| Plugin | Type | Description |
|---|---|---|
| [mitre-attack](#mitre-attack) | MCP server + skill | MITRE ATT&CK v20 and ATLAS lookups for incident response and threat mapping |

### mitre-attack

Maps incidents, alerts, CloudTrail/API events and threat-actor activity to MITRE ATT&CK and ATLAS: technique and tactic IDs, mitigations, detection strategies, log sources, groups, software, campaigns, and ATT&CK Navigator layers. It also covers AI/LLM threats such as LLM-jacking, prompt injection and Bedrock abuse.

**What it adds**

- **MCP server `mitre-attack`.** Runs [oleggohman/mitre-attack-mcp](https://github.com/oleggohman/mitre-attack-mcp) over stdio with `uvx`. It serves local STIX bundles (ATT&CK v20 enterprise/mobile/ics plus ATLAS) cached under `~/.mitre-mcp-server/data/`. Tools appear as `mcp__plugin_mitre-attack_mitre-attack__*`.
- **Skill `using-mitre-attack-mcp`.** Tells Claude where ATT&CK v20 differs from what it remembers (149 revoked techniques, Defense Evasion split into Stealth and Defense Impairment, the new detection model) and where the MCP tools give wrong answers. It ships three helper scripts that read the same STIX data:

  | Script | Purpose |
  |---|---|
  | `attack_detections.py` | Validates technique IDs (flags revoked ones and their replacements) and lists tactics, mitigations, detection strategies, analytics and log sources. `--event` maps API names or event IDs (such as `CreateAccessKey`, `4625`) to candidate techniques. |
  | `group_ttps.py` | Shows a threat group's techniques in one table, filterable by platform, with mitigation and detection IDs. |
  | `build_layer.py` | Builds an ATT&CK Navigator layer from a list of techniques with scores and comments. |

**Requirements:** [uv](https://docs.astral.sh/uv/) (`uvx` fetches Python 3.12 and the server on first run) and `python3` for the skill scripts.

**Example prompts**

- "Map these CloudTrail events to ATT&CK techniques with mitigations and log sources: CreateAccessKey, StopLogging, RunInstances."
- "Which IaaS techniques does APT29 use? Build a Navigator layer."
- "Is T1562.008 still valid in ATT&CK v20?"

## Repository layout

```
.claude-plugin/marketplace.json     # marketplace catalog
plugins/<name>/
  .claude-plugin/plugin.json        # plugin manifest (MCP servers declared inline)
  skills/<skill>/SKILL.md           # skills, with optional scripts/
```

## Development

Test a plugin locally without installing it:

    claude --plugin-dir plugins/mitre-attack

Validate manifests before pushing:

    claude plugin validate .
    claude plugin validate plugins/mitre-attack

To add a plugin, create `plugins/<name>/` with a `.claude-plugin/plugin.json`, then add an entry to `.claude-plugin/marketplace.json` and to the table above.
