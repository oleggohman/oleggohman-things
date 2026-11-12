#!/usr/bin/env python3
"""Build an ATT&CK Navigator layer from an explicit technique list.

The MCP generate_layer tool only accepts G/M/S/D IDs. Use this for case
techniques, detection-coverage maps, or any hand-picked set. IDs are
validated against the local STIX bundle; revoked IDs are rewritten to their
replacement, unknown IDs abort the build.

Usage:
  python3 -I build_layer.py --name "Case 123" -o layer.json \
      T1552.005 T1078.004:100:"stolen role creds" T1685.002:50
  Each item is ID[:score[:comment]]. Default score 1.
  --domain enterprise|mobile|ics   --data PATH (STIX bundle)
"""
import argparse
import glob
import json
import os
import sys

BUNDLE = {"enterprise": "enterprise-attack.json", "mobile": "mobile-attack.json", "ics": "ics-attack.json"}


def find_bundle(domain, explicit):
    if explicit:
        return explicit
    paths = glob.glob(os.path.expanduser(f"~/.mitre-mcp-server/data/v*/{BUNDLE[domain]}"))
    if not paths:
        sys.exit(f"{BUNDLE[domain]} not found; pass --data PATH")

    def ver(p):
        d = os.path.basename(os.path.dirname(p)).lstrip("v")
        return tuple(int(x) for x in d.split(".") if x.isdigit())
    return max(paths, key=ver)


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("items", nargs="+")
    ap.add_argument("--name", default="Custom layer")
    ap.add_argument("--description", default="")
    ap.add_argument("--domain", default="enterprise", choices=list(BUNDLE))
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--data")
    args = ap.parse_args()

    path = find_bundle(args.domain, args.data)
    objs = json.load(open(path))["objects"]
    by_id = {o["id"]: o for o in objs}
    techs = {}
    for o in objs:
        if o["type"] == "attack-pattern":
            techs.setdefault(ext_id(o), o)
    revoked_by = {o["source_ref"]: o["target_ref"] for o in objs
                  if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by"}
    # Version comes from the bundle itself; the directory name is not reliable with --data.
    attack_version = None
    for o in objs:
        if o["type"] == "x-mitre-collection" and o.get("x_mitre_version"):
            attack_version = o["x_mitre_version"].split(".")[0]
            break

    entries, errors = [], []
    for item in args.items:
        parts = item.split(":", 2)
        tid = parts[0].upper()
        score = 1
        if len(parts) > 1 and parts[1]:
            try:
                score = int(parts[1])
            except ValueError:
                score = -1
            if score < 0:
                ap.error(f"bad score in {item!r}: expected ID[:score[:comment]] with a non-negative integer score")
        comment = parts[2] if len(parts) > 2 else ""
        t = techs.get(tid)
        if t and t.get("revoked"):
            # Follow the revoked-by chain to its end; guard against cycles.
            orig, cur, seen = tid, t, {t["id"]}
            while cur.get("revoked"):
                nxt = by_id.get(revoked_by.get(cur["id"], ""))
                if not nxt or nxt["id"] in seen:
                    cur = None
                    break
                seen.add(nxt["id"])
                cur = nxt
            if cur is None:
                errors.append(f"{tid}: revoked, no replacement")
                continue
            print(f"note: {orig} revoked -> {ext_id(cur)} {cur['name']}", file=sys.stderr)
            t, tid = cur, ext_id(cur)
        if not t:
            errors.append(f"{tid}: not found")
            continue
        if t.get("x_mitre_deprecated"):
            errors.append(f"{tid}: deprecated")
            continue
        # One entry per tactic so the cell is highlighted under every tactic column.
        for phase in t.get("kill_chain_phases", []):
            # An explicit item replaces a parent placeholder auto-added for a sub-technique.
            ph = next((e for e in entries if e.get("_auto") and e["techniqueID"] == tid
                       and e["tactic"] == phase["phase_name"]), None)
            if ph:
                entries.remove(ph)
            entries.append({"techniqueID": tid, "tactic": phase["phase_name"], "score": score,
                            "comment": comment, "enabled": True, "showSubtechniques": ph is not None and ph["showSubtechniques"]})
            if "." in tid:
                # Navigator expands sub-techniques via the flag on the parent entry.
                parent = tid.split(".")[0]
                pe = next((e for e in entries if e["techniqueID"] == parent and e["tactic"] == phase["phase_name"]), None)
                if pe:
                    pe["showSubtechniques"] = True
                else:
                    entries.append({"techniqueID": parent, "tactic": phase["phase_name"], "_auto": True,
                                    "comment": "", "enabled": True, "showSubtechniques": True})
    if errors:
        sys.exit("aborted:\n  " + "\n  ".join(errors))

    for e in entries:
        e.pop("_auto", None)
    layer = {
        "name": args.name,
        "versions": {**({"attack": attack_version} if attack_version else {}),
                     "navigator": "5.1.0", "layer": "4.5"},
        "domain": f"{args.domain}-attack",
        "description": args.description,
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {"colors": ["#ffe766", "#ff6666"], "minValue": 0,
                     "maxValue": max([e.get("score", 0) for e in entries] + [1])},
        "legendItems": [],
        "showTacticRowBackground": False,
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    with open(args.output, "w") as fh:
        json.dump(layer, fh, indent=2)
    print(f"wrote {args.output}: {len({e['techniqueID'] for e in entries})} techniques, "
          f"{len(entries)} cells" + (f", ATT&CK v{attack_version}" if attack_version else ""))


if __name__ == "__main__":
    main()
