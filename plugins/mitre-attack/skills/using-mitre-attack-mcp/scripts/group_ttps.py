#!/usr/bin/env python3
"""Compact group -> techniques table, optionally filtered by platform.

Replaces the MCP pattern get_group_techniques (75K+ chars, no platform field)
+ get_techniques_by_platform x N + manual intersection. One row per technique
with tactics, platforms, mitigation IDs and detection-strategy IDs.

Usage:
  python3 -I group_ttps.py "Scattered Spider" [--platform IaaS,SaaS,"Identity Provider"]
         [--via-software] [--json] [--data PATH]
  Group may be a name, alias (case-insensitive substring) or G-ID.
  --via-software also includes techniques of software the group uses.
"""
import argparse
import glob
import json
import os
import sys


def find_bundle(explicit):
    if explicit:
        return explicit
    paths = glob.glob(os.path.expanduser("~/.mitre-mcp-server/data/v*/enterprise-attack.json"))
    if not paths:
        sys.exit("enterprise-attack.json not found; pass --data PATH")

    def ver(p):
        d = os.path.basename(os.path.dirname(p)).lstrip("v")
        return tuple(int(x) for x in d.split(".") if x.isdigit())
    return max(paths, key=ver)


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def live(o):
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("group")
    ap.add_argument("--platform", help="comma-separated, case-sensitive ATT&CK platform names")
    ap.add_argument("--via-software", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--data")
    args = ap.parse_args()

    objs = json.load(open(find_bundle(args.data)))["objects"]
    by_id = {o["id"]: o for o in objs}
    rels = [o for o in objs if o["type"] == "relationship" and live(o)]

    q = args.group.lower()
    groups = [o for o in objs if o["type"] == "intrusion-set" and live(o) and (
        (ext_id(o) or "").lower() == q or q in o["name"].lower()
        or any(q in a.lower() for a in o.get("aliases", [])))]
    exact = [o for o in groups if (ext_id(o) or "").lower() == q or o["name"].lower() == q
             or any(a.lower() == q for a in o.get("aliases", []))]
    if exact:
        groups = exact
    if len(groups) != 1:
        sys.exit("group match: " + (", ".join(f"{ext_id(g)} {g['name']}" for g in groups) or "none")
                 + " -- refine the name")
    g = groups[0]

    sources = {g["id"]: "group"}
    if args.via_software:
        for r in rels:
            if r["relationship_type"] == "uses" and r["source_ref"] == g["id"] \
                    and r["target_ref"].split("--")[0] in ("malware", "tool"):
                sw = by_id.get(r["target_ref"])
                if sw and live(sw):
                    sources[r["target_ref"]] = ext_id(sw)

    techs = {}
    for r in rels:
        if r["relationship_type"] == "uses" and r["source_ref"] in sources \
                and r["target_ref"].startswith("attack-pattern--"):
            t = by_id.get(r["target_ref"])
            if t and live(t):
                techs.setdefault(t["id"], set()).add(sources[r["source_ref"]])

    mit, det = {}, {}
    for r in rels:
        src = by_id.get(r["source_ref"])
        if not src or not live(src):
            continue
        if r["relationship_type"] == "mitigates" and src["type"] == "course-of-action":
            mit.setdefault(r["target_ref"], []).append(ext_id(src))
        elif r["relationship_type"] == "detects" and src["type"] == "x-mitre-detection-strategy":
            det.setdefault(r["target_ref"], []).append(ext_id(src))

    want = None
    if args.platform:
        want = {p.strip() for p in args.platform.split(",") if p.strip()}
        known = {p for o in objs if o["type"] == "attack-pattern" for p in o.get("x_mitre_platforms", [])}
        bad = want - known
        if bad:
            sys.exit(f"unknown platform(s) {sorted(bad)}; valid (case-sensitive): {sorted(known)}")
    rows = []
    for sid, via in techs.items():
        t = by_id[sid]
        plats = t.get("x_mitre_platforms", [])
        if want and not want & set(plats):
            continue
        rows.append({"id": ext_id(t), "name": t["name"],
                     "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])],
                     "platforms": plats, "via": sorted(via),
                     "mitigations": sorted(set(mit.get(sid, []))),
                     "detection_strategies": sorted(set(det.get(sid, [])))})
    rows.sort(key=lambda r: r["id"])

    if args.json:
        json.dump({"group": {"id": ext_id(g), "name": g["name"], "aliases": g.get("aliases", [])},
                   "count": len(rows), "techniques": rows}, sys.stdout, indent=2)
        print()
        return
    print(f"{ext_id(g)} {g['name']} (aliases: {', '.join(g.get('aliases', []))})")
    print(f"{len(rows)} techniques" + (f" on {sorted(want)}" if want else ""))
    for r in rows:
        print(f"{r['id']:<10} {r['name'][:45]:<45} | {','.join(r['tactics'])} | "
              f"M:{','.join(r['mitigations']) or '-'} | DET:{','.join(r['detection_strategies']) or '-'}"
              + ("" if r["via"] == ["group"] else f" | via {','.join(r['via'])}"))
    # Legend so callers need no extra lookups for mitigation names.
    mids = sorted({m for r in rows for m in r["mitigations"]})
    names = {ext_id(o): o["name"] for o in objs if o["type"] == "course-of-action"}
    if mids:
        print("\nMitigations: " + "; ".join(f"{m} {names.get(m, '?')}" for m in mids))


if __name__ == "__main__":
    main()
