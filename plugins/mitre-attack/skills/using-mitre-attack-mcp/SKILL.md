---
name: using-mitre-attack-mcp
description: Use when mapping incidents, alerts, CloudTrail/API events or threat-actor activity to MITRE ATT&CK or ATLAS (technique/tactic IDs, mitigations, detections, log sources, groups, software, campaigns, Navigator layers), or when calling any mcp__plugin_mitre-attack_mitre-attack__* tool — including AI/LLM threats like LLM-jacking, prompt injection, Bedrock abuse.
---

# Using the MITRE ATT&CK MCP

## Overview
`mcp__plugin_mitre-attack_mitre-attack__*` serves local STIX bundles under `~/.mitre-mcp-server/data/`: ATT&CK **v20** (enterprise/mobile/ics) + ATLAS (`domain="atlas"`). v20 differs from what you remember and several MCP tools are wrong on it. The bundled scripts read the same files and fill the gaps. Run them as `python3 -I <skill-dir>/scripts/<name>.py`; each has `--help` and `--json`. `attack_detections.py --json` → `{bundle, results:[{technique, name, stix_id, tactics, mitigations:[{id,name,via_parent?}], platforms, detection_strategies:[{id,name,analytics:[{id,platforms,log_sources:[{data_component,data_component_id,log_source,channel}]}]}]}]}`; a bad ID gives `{technique, error}`. With `--event`, an extra top-level `events:[{event, techniques:[{technique,name,tactics,analytics:["AN… [platforms] log_source :: channel"]}]}]` is added (`--platform` applies to event hits too).

## v20 facts that beat memory
- **149 techniques revoked.** Remembered IDs may be dead (T1562.008 → **T1685.002**). MCP lookups still return revoked techniques as "found", with 0 mitigations. **Every ID in your output must pass through `attack_detections.py`** — it prints `REVOKED -> use …`.
- **Defense Evasion is gone**: TA0005 **Stealth**, TA0112 **Defense Impairment**.
- **Detections = detection strategies (DETxxxx) → analytics (ANxxxx) → log sources.** MCP detection tools ignore this and return 0. Never fill detection/log-source columns from memory.
- Platform labels are case-sensitive (`IaaS`, `SaaS`, `Identity Provider`, `Office Suite`, `Containers`, `ESXi`, `Windows`, `Linux`, `macOS`, `Network Devices`) and sometimes surprising: T1496.004 Cloud Service Hijacking is `SaaS` only. Run without `--platform` before concluding "no detection".

## Quick reference
| Need | Use |
|---|---|
| Validate IDs + tactics + mitigations (names) + detections/log sources | `scripts/attack_detections.py T1552.005 T1078.004 [--platform IaaS,"Identity Provider"]` |
| Same for ATLAS (`AML.*`; no detections exist) | `scripts/attack_detections.py --domain atlas AML.T0040 AML.T0051.001` |
| API name / event ID → candidate techniques | `scripts/attack_detections.py --event CreateAccessKey --event 4625` |
| Group TTPs, per platform, with M/DET IDs + mitigation legend | `scripts/group_ttps.py "<name/alias/G-ID>" --platform IaaS,SaaS [--via-software]` |
| Navigator layer for a technique list (items `ID[:score[:comment]]`; multi-tactic techniques get one cell per tactic) | `scripts/build_layer.py --name "Case X" -o out.json T1552.005:100:"comment" T1530:50` |
| Navigator layer for a G/M/S/D object | MCP `generate_layer` (~100K → file; `jq '.result.layer'`) |
| Groups/software/campaigns using a technique, procedure examples | MCP tools taking **`technique_stix_id`** — `stix_id` is in `attack_detections.py --json` or `get_technique_tactics` |
| Keyword → technique | MCP `search_techniques(query, include_description=false)` |

## Mapping events to techniques
1. `--event <API>` first: matches MITRE's own analytic log-source text. It is a lead generator — wording varies (`--event StopLogging` misses T1685.002, whose analytic says "Stop logging"), and hits can be noise (`GetObject` → 8 techniques). Also search the behavior. No technique fits identity checks like `sts:GetCallerIdentity`; mark your choice (usually T1087.004) as judgement.
2. `search_techniques` / `get_objects_by_content` are raw substring matches over prose ("LLM" hits "WellMess"; "log" → 185 hits incl. "logon"). Search a multi-word *behavior* phrase ("cloud log", "account discovery"), never short tokens or API names.
3. Validate the chosen IDs with `attack_detections.py`. Label mappings that are your judgement, not tool text.
4. Analytic log-source text in the bundle is occasionally implausible (e.g. IMDS reads under CloudTrail). Quote it as MITRE's, and flag oddities.

## Output size
Responses repeat data in a `formatted` field (~2×). Pass `include_description=false` (ignored by `get_technique_by_id`). `get_group_techniques`, `get_objects_by_type`, `generate_layer` overflow → saved to file → `jq` it, never Read it. Prefer the scripts.

## ATLAS (AI/LLM threats)
No groups, software, campaigns or case studies in the bundle — case studies (AML.CS0030 LLM Jacking) appear only as links in descriptions; state that once instead of searching. MCP `get_mitigations_mitigating_technique` misses some ATLAS sub-technique mitigations — use the script. Layers: not supported.
LLM-jacking mapping that tool text supports: ATLAS **AML.T0075** Cloud Service Discovery, **AML.T0040** AI Model Inference API Access, **AML.T0008.005** AI Service Proxies, plus **AML.T0034** Cost Harvesting as the impact (note: its text calls itself distinct from resource hijacking — say so); ATT&CK **T1078.004**, **T1526**, **T1496.004**. MITRE has no Bedrock analytic: T1496.004's only detection (DET0147) is SES/email-oriented, so Bedrock detection logic is your own — label it. Prompt injection: **AML.T0051.000/.001** (no ATT&CK equivalent).

## Common mistakes
| Mistake | Fix |
|---|---|
| Recalled ID used unvalidated / "no mitigations" for T1562.x | Script → replacement ID |
| `found:false` from mitigation tool read as "technique missing" | Means 0 mitigations too; check `technique` field |
| Log sources written from memory | `attack_detections.py` |
| `--platform` filter hides the only detection | Rerun without it |
| Layer hand-built from `get_layer_metadata` | Template says ATT&CK 16; use `build_layer.py` |
| T-ID passed where `*_stix_id` required | Get `stix_id` first |
