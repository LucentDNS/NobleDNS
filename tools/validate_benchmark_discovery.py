#!/usr/bin/env python3
"""Validate discovery/triage integrity; this does not establish benchmark ground truth."""
from __future__ import annotations
import argparse, csv, re, sys
from collections import Counter
from pathlib import Path
SOURCE_FIELDS=["request_domain","pages_seen_on","share_of_pages","requests_total","requests_setting_cookies","cookie_setting_request_share"]
TRIAGE_FIELDS=SOURCE_FIELDS+["owner","owner_category","preliminary_lane","evidence","review_status","review_note"]
LANES={"adtech_candidate","functional_control","mixed_or_contextual","unmapped"}
HOST_RE=re.compile(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\Z")
def read_csv(path:Path,fields:list[str])->list[dict[str,str]]:
    with path.open(encoding="utf-8-sig",newline="") as f:
        reader=csv.DictReader(f)
        if reader.fieldnames!=fields: raise ValueError(f"{path}: columns must exactly match {','.join(fields)}")
        return list(reader)
def expected_lane(category:str)->str:
    if not category:return "unmapped"
    if category=="ads":return "adtech_candidate"
    if category in {"infra","platform"}:return "functional_control"
    return "mixed_or_contextual"
def validate(source_path:Path,triage_path:Path):
    errors=[]; source=read_csv(source_path,SOURCE_FIELDS); triage=read_csv(triage_path,TRIAGE_FIELDS)
    source_by={}
    for n,row in enumerate(source,2):
        d=row["request_domain"].strip().lower()
        if not HOST_RE.fullmatch(d):errors.append(f"{source_path}:{n}: invalid request_domain {d!r}")
        if d in source_by:errors.append(f"{source_path}:{n}: duplicate source domain {d}")
        source_by[d]=row
    seen=set(); counts=Counter()
    for n,row in enumerate(triage,2):
        d=row["request_domain"].strip().lower(); lane=row["preliminary_lane"].strip(); category=row["owner_category"].strip()
        counts[lane]+=1
        if d in seen:errors.append(f"{triage_path}:{n}: duplicate triage domain {d}")
        seen.add(d)
        if d not in source_by:errors.append(f"{triage_path}:{n}: domain absent from discovery source: {d}")
        else:
            for field in SOURCE_FIELDS[1:]:
                if row[field]!=source_by[d][field]:errors.append(f"{triage_path}:{n}: source field changed for {d}: {field}")
        if not HOST_RE.fullmatch(d):errors.append(f"{triage_path}:{n}: invalid hostname {d!r}")
        if lane not in LANES:errors.append(f"{triage_path}:{n}: unknown lane {lane!r}")
        if lane!=expected_lane(category):errors.append(f"{triage_path}:{n}: lane {lane!r} conflicts with owner_category {category!r}")
        if row["review_status"].strip()!="primary_triage_only":errors.append(f"{triage_path}:{n}: row must remain primary_triage_only")
        if not row["evidence"].strip() or not row["review_note"].strip():errors.append(f"{triage_path}:{n}: evidence and review_note are required")
        if lane=="adtech_candidate" and "not approved" not in row["review_note"].lower():errors.append(f"{triage_path}:{n}: adtech candidate must remain unapproved for blocking")
    missing=set(source_by)-seen; extra=seen-set(source_by)
    if missing:errors.append(f"triage is missing {len(missing)} source domains")
    if extra:errors.append(f"triage contains {len(extra)} non-source domains")
    if len(source)!=len(triage):errors.append(f"row count mismatch: source={len(source)} triage={len(triage)}")
    return counts,errors
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=Path("benchmark/discovery/http-archive-third-party-domains-2026-06.csv"))
    p.add_argument("--triage",type=Path,default=Path("benchmark/discovery/first-pass-review-queue.csv"))
    a=p.parse_args()
    try:
        counts,errors=validate(a.source,a.triage)
        if errors:
            print("Benchmark discovery integrity validation failed:",file=sys.stderr);print("\n".join(errors),file=sys.stderr);return 1
        print(f"Validated {sum(counts.values())} discovery rows; preliminary lanes: {dict(sorted(counts.items()))}")
        print("LIMITATION: integrity only; no domain is approved or scored as block/allow ground truth.")
        return 0
    except (OSError,ValueError) as exc:print(f"ERROR: {exc}",file=sys.stderr);return 1
if __name__=="__main__":raise SystemExit(main())
