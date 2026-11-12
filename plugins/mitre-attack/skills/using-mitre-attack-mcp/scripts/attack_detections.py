#!/usr/bin/env python3
"""Detection lookup for ATT&CK v18+ data that the mitre-attack MCP cannot do.

Since ATT&CK v18, detections are modelled as:
  x-mitre-detection-strategy (DETxxxx) --detects--> attack-pattern (Txxxx)
  detection-strategy.x_mitre_analytic_refs -> x-mitre-analytic (ANxxxx)
  analytic.x_mitre_log_source_references -> data component + log source + channel
The MCP tool get_datacomponents_detecting_technique only reads the legacy
model, so it returns 0 results on v18+. This script reads the same local STIX
bundle the MCP server downloaded and resolves the new chain.

Usage:
  python3 -I attack_detections.py T1552.005 [T1078.004 ...] [--platform IaaS]
         [--include-subtechniques] [--event NAME ...] [--json] [--data PATH]
"""
import argparse
import glob
import json
import os
import sys


BUNDLE_GLOB = {
    "enterprise": "v*/enterprise-attack.json",
    "mobile": "v*/mobile-attack.json",
    "ics": "v*/ics-attack.json",
    "atlas": "atlas-v*/stix-atlas.json",
}


def find_bundle(domain, explicit):
    if explicit:
        return explicit
    paths = glob.glob(os.path.expanduser("~/.mitre-mcp-server/data/" + BUNDLE_GLOB[domain]))
    if not paths:
        sys.exit(f"{domain} bundle not found; pass --data PATH")

    # Pick the highest version directory (v20.0 > v9.0, atlas-v1.16.0 > atlas-v1.9.0).
    def ver(p):
        d = os.path.basename(os.path.dirname(p)).split("v")[-1]
        return tuple(int(x) for x in d.split(".") if x.isdigit())
    return max(paths, key=ver)


def ext_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-atlas"):
            return ref.get("external_id")
    return None


def live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("technique_ids", nargs="*")
    ap.add_argument("--event", action="append",
                    help="reverse lookup: techniques whose analytics mention this API/event "
                         "(e.g. CreateAccessKey, 4625); repeatable, case-insensitive substring")
    ap.add_argument("--platform", help="keep analytics for this platform only (e.g. IaaS, Windows)")
    ap.add_argument("--include-subtechniques", action="store_true",
                    help="also report detections of sub-techniques of a parent ID")
    ap.add_argument("--domain", default="enterprise", choices=list(BUNDLE_GLOB),
                    help="atlas: validates AML.* IDs, tactics, mitigations (ATLAS has no detections)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--data")
    args = ap.parse_args()
    if not args.technique_ids and not args.event:
        ap.error("give technique IDs and/or --event")

    path = find_bundle(args.domain, args.data)
    with open(path) as fh:
        objs = json.load(fh)["objects"]
    by_id = {o["id"]: o for o in objs}

    tech_by_ext = {}
    dead_by_ext = {}  # revoked/deprecated techniques, to explain stale IDs
    for o in objs:
        if o["type"] == "attack-pattern":
            (tech_by_ext if live(o) else dead_by_ext)[ext_id(o)] = o
    revoked_by = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            revoked_by[o["source_ref"]] = o["target_ref"]

    def why_missing(t_ext):
        dead = dead_by_ext.get(t_ext)
        if not dead:
            return "not found (wrong ID?)"
        # Follow the revoked-by chain to a live terminal; guard against cycles.
        cur, seen = dead, {dead["id"]}
        while cur.get("revoked"):
            nxt = by_id.get(revoked_by.get(cur["id"], ""))
            if not nxt or nxt["id"] in seen:
                return "REVOKED (no replacement)"
            seen.add(nxt["id"])
            cur = nxt
        if cur is dead:
            return "DEPRECATED (no replacement)"
        if not live(cur):
            return f"REVOKED -> {ext_id(cur)} {cur['name']}, which is DEPRECATED (no replacement)"
        return f"REVOKED -> use {ext_id(cur)} {cur['name']}"

    detects = {}  # technique stix id -> [strategy objects]
    mitigations = {}  # technique stix id -> [(M-ID, name)]
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "detects" and live(o):
            src = by_id.get(o["source_ref"])
            if src and src["type"] == "x-mitre-detection-strategy" and live(src):
                detects.setdefault(o["target_ref"], []).append(src)
        elif o["type"] == "relationship" and o.get("relationship_type") == "mitigates" and live(o):
            src = by_id.get(o["source_ref"])
            if src and src["type"] == "course-of-action" and live(src):
                mitigations.setdefault(o["target_ref"], []).append((ext_id(src), src["name"]))

    parent_of = {}  # sub-technique stix id -> parent stix id (live relationship and live parent only)
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "subtechnique-of" and live(o):
            par = by_id.get(o["target_ref"])
            if par and live(par):
                parent_of[o["source_ref"]] = o["target_ref"]
    children_of = {}  # parent stix id -> [live sub-technique external IDs]
    for sub, par in parent_of.items():
        s_obj = by_id.get(sub)
        if s_obj and live(s_obj):
            children_of.setdefault(par, []).append(ext_id(s_obj))

    def mitigations_of(t):
        # Sub-techniques often carry no mitigations of their own (always so in
        # ATLAS); fall back to the parent's and say so.
        own = sorted(set(mitigations.get(t["id"], [])))
        if own or t["id"] not in parent_of:
            return [{"id": m, "name": n} for m, n in own]
        p = by_id[parent_of[t["id"]]]  # parent_of only holds live parents
        return [{"id": m, "name": n, "via_parent": ext_id(p)}
                for m, n in sorted(set(mitigations.get(p["id"], [])))]

    def tactics_of(t):
        return [p["phase_name"] for p in t.get("kill_chain_phases", [])]

    # Comma-separated platform filter; reject unknown names instead of
    # silently returning "no detection strategy".
    want = None
    if args.platform:
        want = {p.strip() for p in args.platform.split(",") if p.strip()}
        known = {p for o in objs if o["type"] == "attack-pattern" for p in o.get("x_mitre_platforms", [])}
        bad = want - known
        if bad:
            sys.exit(f"unknown platform(s) {sorted(bad)}; valid (case-sensitive): {sorted(known)}")

    events = None
    if args.event:
        # Reverse map: analytic -> strategies -> techniques.
        strat_by_analytic = {}
        for t_sid, strats in detects.items():
            for s in strats:
                for aref in s.get("x_mitre_analytic_refs", []):
                    strat_by_analytic.setdefault(aref, []).append((s, t_sid))
        hits = {}
        for an in objs:
            if an["type"] != "x-mitre-analytic" or not live(an):
                continue
            if want and not want & set(an.get("x_mitre_platforms", [])):
                continue
            for ev in args.event:
                e = ev.lower()
                for ls in an.get("x_mitre_log_source_references", []):
                    text = f"{ls.get('name', '')} {ls.get('channel', '')}"
                    if e in text.lower():
                        for s, t_sid in strat_by_analytic.get(an["id"], []):
                            hits.setdefault((ev, t_sid), []).append(
                                f"{ext_id(an)} [{','.join(an.get('x_mitre_platforms', []))}] "
                                f"{ls.get('name')} :: {ls.get('channel')}")
        events = []
        for ev in args.event:
            rows = [(t_sid, ev_hits) for (e, t_sid), ev_hits in hits.items() if e == ev]
            techs_out = []
            for t_sid, ev_hits in sorted(rows, key=lambda r: ext_id(by_id[r[0]])):
                t = by_id[t_sid]
                techs_out.append({"technique": ext_id(t), "name": t["name"], "tactics": tactics_of(t),
                                  "analytics": sorted(set(ev_hits))})
            events.append({"event": ev, "techniques": techs_out})
        if not args.json:
            print(f"# bundle: {path}")
            print("# matches are MITRE analytic log-source text, not proof of the mapping; judge fit")
            for e in events:
                print(f"\n== {e['event']}: {len(e['techniques'])} technique(s)")
                for t in e["techniques"]:
                    print(f"{t['technique']} {t['name']} | {','.join(t['tactics'])}")
                    for h in t["analytics"][:3]:
                        print(f"    {h}")
        if not args.technique_ids:
            if args.json:
                json.dump({"bundle": path, "results": [], "events": events}, sys.stdout, indent=2)
                print()
            return

    out = []
    for tid in args.technique_ids:
        tid = tid.upper()
        targets = [tid]
        if args.include_subtechniques:
            # Decided by subtechnique-of relationships, not by ID shape (ATLAS parents contain a dot).
            parent = tech_by_ext.get(tid)
            if parent:
                targets += sorted(children_of.get(parent["id"], []))
        for t_ext in targets:
            tech = tech_by_ext.get(t_ext)
            if not tech:
                out.append({"technique": t_ext, "error": why_missing(t_ext)})
                continue
            strategies = []
            for det in detects.get(tech["id"], []):
                analytics = []
                for aref in det.get("x_mitre_analytic_refs", []):
                    an = by_id.get(aref)
                    if not an or not live(an):
                        continue
                    if want and not want & set(an.get("x_mitre_platforms", [])):
                        continue
                    sources = []
                    for ls in an.get("x_mitre_log_source_references", []):
                        dc = by_id.get(ls.get("x_mitre_data_component_ref"), {})
                        if not live(dc):
                            dc = {}
                        sources.append({"data_component": dc.get("name"),
                                        "data_component_id": ext_id(dc),
                                        "log_source": ls.get("name"),
                                        "channel": ls.get("channel")})
                    analytics.append({"id": ext_id(an),
                                      "platforms": an.get("x_mitre_platforms", []),
                                      "description": an.get("description", ""),
                                      "log_sources": sources})
                if analytics or not args.platform:
                    strategies.append({"id": ext_id(det), "name": det["name"], "analytics": analytics})
            out.append({"technique": t_ext, "name": tech["name"], "stix_id": tech["id"],
                        "tactics": tactics_of(tech),
                        "mitigations": mitigations_of(tech),
                        "platforms": tech.get("x_mitre_platforms", []),
                        "detection_strategies": strategies})

    if args.json:
        doc = {"bundle": path, "results": out}
        if events is not None:
            doc["events"] = events
        json.dump(doc, sys.stdout, indent=2)
        print()
        return
    print(f"# bundle: {path}")
    for r in out:
        if "error" in r:
            print(f"\n{r['technique']}: {r['error']}")
            continue
        print(f"\n{r['technique']} {r['name']}  [{', '.join(r['platforms'])}]")
        print(f"  tactics: {', '.join(r['tactics'])}")
        via = {m.get("via_parent") for m in r["mitigations"]} - {None}
        print("  mitigations" + (f" (inherited from parent {via.pop()})" if via else "") + ": "
              + ("; ".join(f"{m['id']} {m['name']}" for m in r["mitigations"]) or "none"))
        if args.domain == "atlas":
            continue  # ATLAS has no detection strategies
        if not r["detection_strategies"]:
            print("  (no detection strategy" + (f" for platform {args.platform}" if args.platform else "") + ")")
        for s in r["detection_strategies"]:
            print(f"  {s['id']} {s['name']}")
            for a in s["analytics"]:
                print(f"    {a['id']} [{', '.join(a['platforms'])}]")
                for ls in a["log_sources"]:
                    print(f"      - {ls['data_component']} ({ls['data_component_id']}): "
                          f"{ls['log_source']} :: {ls['channel']}")


if __name__ == "__main__":
    main()
