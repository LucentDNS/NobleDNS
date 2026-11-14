#!/usr/bin/env python3
"""Fetch DNS list snapshots and report exact-rule differentials in supported syntax only.

This is a rule-set inventory, not an efficacy or false-positive benchmark.
Unsupported syntax remains visible and is never silently normalized.
"""
from __future__ import annotations
import argparse, hashlib, json, sys, urllib.error, urllib.request
from datetime import datetime, timezone
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import score_benchmark as scorer

COMPARATORS = {
 "adguard_dns": ("AdGuard DNS Filter", "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"),
 "hagezi_multi_pro": ("HaGeZi Multi PRO", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt"),
 "oisd_big": ("OISD Big", "https://big.oisd.nl/"),
 "anti_ad_adguard": ("anti-AD AdGuard", "https://anti-ad.net/adguard.txt"),
}
MAX_BYTES = 80 * 1024 * 1024

def download(url: str, destination: Path) -> bytes:
 request=urllib.request.Request(url, headers={"User-Agent":"NobleDNS-Comparator/1.0 (+https://github.com/LucentDNS/NobleDNS)"})
 with urllib.request.urlopen(request, timeout=90) as response:
  data=response.read(MAX_BYTES+1)
  if len(data)>MAX_BYTES: raise ValueError(f"download exceeds {MAX_BYTES} bytes: {url}")
  if response.status!=200: raise ValueError(f"unexpected HTTP status {response.status}: {url}")
 if not data: raise ValueError(f"empty comparator response: {url}")
 destination.parent.mkdir(parents=True, exist_ok=True); destination.write_bytes(data); return data

def stats(path: Path) -> dict:
 raw=path.read_bytes(); raw.decode("utf-8-sig", errors="strict")
 lines=[x.strip() for x in raw.decode("utf-8-sig").splitlines() if x.strip() and not x.lstrip().startswith(("!","#"))]
 blocks, exceptions, unsupported=scorer.load_rules(path)
 return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"raw_non_comment_lines":len(lines),
  "blocks":blocks,"exceptions":exceptions,"unsupported":unsupported}

def compare(noble_path: Path, other_path: Path, name: str, url: str) -> dict:
 n,o=stats(noble_path),stats(other_path); nb,ob=n["blocks"],o["blocks"]; ne,oe=n["exceptions"],o["exceptions"]
 d={"nobledns_blocks":len(nb),"comparator_blocks":len(ob),"exact_shared_blocks":len(nb&ob),
 "nobledns_only_blocks":len(nb-ob),"comparator_only_blocks":len(ob-nb),
 "nobledns_exceptions":len(ne),"comparator_exceptions":len(oe),"exact_shared_exceptions":len(ne&oe),
 "nobledns_only_exceptions":len(ne-oe),"comparator_only_exceptions":len(oe-ne),
 "nobledns_unsupported_lines":len(n["unsupported"]),"comparator_unsupported_lines":len(o["unsupported"]),
 "comparator_unsupported_examples":o["unsupported"][:25]}
 return {"name":name,"url":url,"snapshot":{"bytes":o["bytes"],"sha256":o["sha256"],"raw_non_comment_lines":o["raw_non_comment_lines"]},
 "supported_syntax_subset":d,"interpretation":"Exact string overlap within scorer-supported syntax only; not semantic equivalence, efficacy, safety or false-positive evidence."}

def main() -> int:
 p=argparse.ArgumentParser(description=__doc__); p.add_argument("--nobledns",required=True,type=Path); p.add_argument("--out-dir",required=True,type=Path); p.add_argument("--output",required=True,type=Path); a=p.parse_args()
 try:
  n=stats(a.nobledns); a.out_dir.mkdir(parents=True,exist_ok=True); reports={}; failures={}
  for key,(name,url) in COMPARATORS.items():
   path=a.out_dir/f"{key}.txt"
   try: download(url,path); reports[key]=compare(a.nobledns,path,name,url)
   except (OSError,UnicodeError,ValueError,urllib.error.URLError) as exc: failures[key]=str(exc)
  payload={"schema_version":1,"generated_at_utc":datetime.now(timezone.utc).isoformat(),
   "nobledns":{"bytes":n["bytes"],"sha256":n["sha256"],"raw_non_comment_lines":n["raw_non_comment_lines"],
   "supported_block_rules":len(n["blocks"]),"supported_exception_rules":len(n["exceptions"]),"unsupported_non_comment_lines":len(n["unsupported"])},
   "comparators":reports,"fetch_failures":failures,"limitations":[
   "Rule-set differential only; no independently labelled hostname corpus.",
   "Exact string overlap does not establish semantic equivalence across filter grammars.",
   "Unsupported syntax is counted but not evaluated.",
   "Moving URLs can change between runs; byte size and SHA-256 identify each downloaded snapshot.",
   "No efficacy, precision, recall, false-positive, app compatibility or performance claim is made."]}
  a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(json.dumps(payload,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
  print(f"NobleDNS supported block rules: {len(n['blocks'])}")
  for key,r in reports.items():
   d=r["supported_syntax_subset"]; print(f"{key}: shared={d['exact_shared_blocks']} NobleDNS-only={d['nobledns_only_blocks']} comparator-only={d['comparator_only_blocks']} unsupported={d['comparator_unsupported_lines']}")
  for key,reason in failures.items(): print(f"FETCH FAILURE {key}: {reason}",file=sys.stderr)
  if not reports: print("No comparator snapshots could be fetched.",file=sys.stderr); return 2
  print(f"Differential report: {a.output}"); print("LIMITATION: exact supported-syntax differential only; not an efficacy score."); return 0
 except (OSError,UnicodeError,ValueError) as exc: print(f"ERROR: {exc}",file=sys.stderr); return 2

if __name__=="__main__": raise SystemExit(main())
