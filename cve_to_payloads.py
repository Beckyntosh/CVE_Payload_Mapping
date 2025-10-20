#!/usr/bin/env python3

from __future__ import annotations
import argparse
import csv
import json
import shlex
import subprocess
import re
import sys
import signal
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any

SEARCHSPLOIT_CMD = "searchsploit"
MSFCONSOLE_CMD = "msfconsole"
CVE_RE = re.compile(r'^(CVE-\d{4}-\d{4,7})$', re.IGNORECASE)

# Default output/checkpoint file names
OUT_JSON = "exploitdb_msf_catalog.json"
OUT_CSV = "exploitdb_msf_catalog.csv"
CHECKPOINT_JSON = "exploitdb_msf_catalog.partial.json"
CHECKPOINT_CSV = "exploitdb_msf_catalog.partial.csv"

# ---- Utilities ----
def run_cmd_list(cmd_list: List[str], timeout: int = 30) -> str:
    try:
        p = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return (p.stdout or "") + (("\n" + p.stderr) if p.stderr else "")
    except FileNotFoundError as e:
        raise
    except subprocess.TimeoutExpired:
        return ""

def run_searchsploit_cve(cve: str) -> List[Dict[str, Any]]:
    """Call `searchsploit --cve <CVE> -j` and return list of EDB result dicts."""
    cmd = [SEARCHSPLOIT_CMD, "--cve", cve, "-j"]
    try:
        out = run_cmd_list(cmd, timeout=30)
    except FileNotFoundError:
        print(f"[ERROR] {SEARCHSPLOIT_CMD} not found on PATH. Install exploitdb (or make searchsploit available).")
        sys.exit(2)
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return []
    results = []
    for k in ("RESULTS_EXPLOIT", "RESULTS_SHELLCODE"):
        arr = data.get(k)
        if isinstance(arr, list):
            results.extend(arr)
    return results

def extract_tokens_from_edb_entry(edb: Dict[str, Any]) -> List[str]:
    """Derive candidate search tokens from an Exploit-DB entry."""
    tokens: List[str] = []
    title = (edb.get("Title") or edb.get("title") or "").strip()
    platform = (edb.get("Platform") or edb.get("platform") or "").strip()
    path = (edb.get("Path") or edb.get("path") or "").strip()

    # basename from path (file stem)
    if path:
        try:
            stem = Path(path).stem
            if stem:
                tokens.append(stem.lower())
        except Exception:
            pass

    # platform tokens
    if platform:
        for p in re.split(r'[^A-Za-z0-9_\-]+', platform):
            p = p.strip().lower()
            if p:
                tokens.append(p)

    # title tokens (prefer >=4 char words)
    for t in re.split(r'[^A-Za-z0-9_\-]+', title):
        t = t.strip().lower()
        if len(t) >= 4 and not t.isdigit():
            tokens.append(t)

    # dedupe while preserving order
    seen = set()
    out = []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            out.append(t)
    return out

def msf_search_with_terms(terms: List[str], max_hits: int = 12) -> List[str]:
    """Search Metasploit for modules using the given terms. Returns module paths."""
    found: List[str] = []
    # try cve-like terms first
    for t in terms:
        if CVE_RE.match(t):
            try:
                out = run_cmd_list([MSFCONSOLE_CMD, "-q", "-x", f"search cve:{t}; exit"], timeout=30)
                mods = parse_msf_modules(out)
                for m in mods:
                    if m not in found:
                        found.append(m)
                        if len(found) >= max_hits:
                            return found
            except FileNotFoundError:
                print(f"[ERROR] {MSFCONSOLE_CMD} not found on PATH.")
                sys.exit(2)
    # then plain keyword terms
    added = 0
    for t in terms:
        if added >= max_hits:
            break
        try:
            out = run_cmd_list([MSFCONSOLE_CMD, "-q", "-x", f"search {shlex.quote(t)}; exit"], timeout=30)
            mods = parse_msf_modules(out)
            for m in mods:
                if m not in found:
                    found.append(m)
                    added += 1
                    if added >= max_hits:
                        break
        except Exception:
            continue
    return found

def parse_msf_modules(msf_output: str) -> List[str]:
    mods: List[str] = []
    for line in (msf_output or "").splitlines():
        line = line.strip()
        m = re.match(r'^(?P<module>(?:exploit|auxiliary|post|scanner|encoder)/\S+)', line)
        if m:
            mods.append(m.group("module"))
    return mods

def msf_show_payloads(module: str) -> List[str]:
    try:
        out = run_cmd_list([MSFCONSOLE_CMD, "-q", "-x", f"use {module}; show payloads; exit"], timeout=30)
    except FileNotFoundError:
        print(f"[ERROR] {MSFCONSOLE_CMD} not found on PATH.")
        sys.exit(2)
    plds: List[str] = []
    for line in (out or "").splitlines():
        line = line.strip()
        if '/' in line and line.count('/') >= 2:
            token = line.split()[0]
            if token.count('/') >= 2 and token not in plds:
                plds.append(token)
    return plds

def read_cves_from_csv(path: str) -> List[str]:
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] CSV not found: {p}")
        sys.exit(1)
    cves: List[str] = []
    with p.open(newline='') as fh:
        fh.seek(0)
        dr = csv.DictReader(fh)
        if dr.fieldnames and any(f.lower() == "cve" for f in dr.fieldnames):
            fh.seek(0)
            for row in dr:
                for k, v in row.items():
                    if k and k.lower() == "cve" and v:
                        m = CVE_RE.match(v.strip())
                        if m:
                            cves.append(m.group(1).upper())
                        else:
                            print(f"[WARN] skipping malformed CVE value: '{v}'")
                        break
            return cves
        fh.seek(0)
        r = csv.reader(fh)
        for row in r:
            if not row:
                continue
            v = row[0].strip()
            if not v:
                continue
            m = CVE_RE.match(v)
            if m:
                cves.append(m.group(1).upper())
            else:
                print(f"[WARN] skipping malformed/non-CVE line: '{v}'")
    return cves

# ---- Checkpointing / graceful shutdown ----
def atomic_write_text(path: Path, content: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content)
    tmp.replace(path)

def save_checkpoint(catalog: Dict[str, Any], csv_rows: List[List[str]],
                    json_path: str = CHECKPOINT_JSON, csv_path: str = CHECKPOINT_CSV) -> None:
    """
    Atomically write full checkpoint JSON and CSV (overwrite).
    Called frequently (after each CVE).
    """
    try:
        # write JSON
        atomic_write_text(Path(json_path), json.dumps(catalog, indent=2))
    except Exception as e:
        print(f"[WARN] failed to write checkpoint JSON: {e}")
    try:
        p = Path(csv_path)
        with p.open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["CVE", "EDB-ID", "EDB-Title", "MSF-Module", "Payload"])
            for r in csv_rows:
                w.writerow(r)
    except Exception as e:
        print(f"[WARN] failed to write checkpoint CSV: {e}")
    print(f"[*] Checkpoint saved (json={json_path}, csv={csv_path}) at {datetime.now(timezone.utc).isoformat()}")

def load_checkpoint(json_path: str = CHECKPOINT_JSON) -> Dict[str, Any] | None:
    p = Path(json_path)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        return data
    except Exception as e:
        print(f"[WARN] failed to load checkpoint {json_path}: {e}")
        return None

# Signal handler: save and exit
def _signal_handler_factory(current_catalog_ref: Dict[str, Any], csv_rows_ref: List[List[str]]):
    def handler(signum, frame):
        print(f"\n[!] Received signal {signum}: saving checkpoint and exiting...")
        try:
            save_checkpoint(current_catalog_ref, csv_rows_ref)
        except Exception as e:
            print("[ERROR] checkpoint on signal failed:", e)
        sys.exit(0)
    return handler

# ---- Main ----
def main():
    ap = argparse.ArgumentParser(description="Exploit-DB -> Metasploit payload catalog with checkpointing and resume.")
    ap.add_argument("--csv", default="cves.csv", help="CSV with CVEs (one per line or header 'cve')")
    ap.add_argument("--limit", type=int, default=10, help="Process first N CVEs (0 = all). Default: 10")
    ap.add_argument("--only-exploitdb", action="store_true", help="Only collect Exploit-DB entries (skip Metasploit lookups)")
    ap.add_argument("--out-json", default=OUT_JSON, help="Final output JSON path")
    ap.add_argument("--out-csv", default=OUT_CSV, help="Final output CSV path")
    ap.add_argument("--checkpoint-json", default=CHECKPOINT_JSON, help="Checkpoint JSON path")
    ap.add_argument("--checkpoint-csv", default=CHECKPOINT_CSV, help="Checkpoint CSV path")
    args = ap.parse_args()

    # read CVEs
    cves = read_cves_from_csv(args.csv)
    if args.limit and args.limit > 0:
        cves = cves[:args.limit]
    total = len(cves)
    print(f"[*] Processing {total} CVE(s) (limit={args.limit})")

    # try resume from checkpoint if exists
    checkpoint = load_checkpoint(args.checkpoint_json)
    processed_cves = set()
    catalog: Dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries": []
    }
    csv_rows: List[List[str]] = []

    if checkpoint:
        # If checkpoint contains entries, extract processed CVEs
        try:
            for e in checkpoint.get("entries", []):
                c = e.get("cve")
                if c:
                    processed_cves.add(c)
            catalog = checkpoint  # resume catalog object (we'll append further entries)
            # try to load csv checkpoint too
            cp_csv = Path(args.checkpoint_csv)
            if cp_csv.exists():
                with cp_csv.open(newline='') as fh:
                    r = csv.reader(fh)
                    next(r, None)  # header
                    for row in r:
                        if row:
                            csv_rows.append(row)
            print(f"[*] Resuming from checkpoint: {len(processed_cves)} CVE(s) already processed.")
        except Exception as ex:
            print(f"[WARN] failed to fully resume from checkpoint: {ex}")
            # fall back to fresh run (catalog was set above)
            catalog = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "entries": []
            }
            csv_rows = []

    # register signal handlers that capture current catalog/csv_rows by closure
    handler = _signal_handler_factory(catalog, csv_rows)
    signal.signal(signal.SIGINT, handler)
    try:
        signal.signal(signal.SIGTERM, handler)
    except Exception:
        pass  

    # main loop
    try:
        for idx, cve in enumerate(cves, start=1):
            if cve in processed_cves:
                print(f"[SKIP] {cve} already in checkpoint; skipping ({idx}/{total})")
                continue
            print(f"\n=== ({idx}/{total}) CVE {cve} ===")

            entry: Dict[str, Any] = {"cve": cve, "exploitdb": [], "msf_modules": []}

            # 1) Exploit-DB
            edb_results = run_searchsploit_cve(cve)
            if not edb_results:
                print(f"[!] Exploit-DB: no results for {cve}")
            else:
                print(f"[*] Exploit-DB: found {len(edb_results)} entry(ies)")
                for ed in edb_results:
                    edb_entry = {
                        "edb_id": ed.get("EDB-ID") or ed.get("id") or "",
                        "title": ed.get("Title") or ed.get("title") or "",
                        "platform": ed.get("Platform") or ed.get("platform") or "",
                        "path": ed.get("Path") or ed.get("path") or "",
                        "author": ed.get("Author") or ed.get("author") or "",
                        "type": ed.get("Type") or ed.get("type") or ""
                    }
                    entry["exploitdb"].append(edb_entry)

            if args.only_exploitdb:
                # append, checkpoint, continue
                catalog["entries"].append(entry)
                processed_cves.add(cve)
                # add no csv rows in this mode
                save_checkpoint(catalog, csv_rows, json_path=args.checkpoint_json, csv_path=args.checkpoint_csv)
                continue

            # 2) derive tokens from Exploit-DB entries
            tokens: List[str] = []
            for ed in edb_results:
                tks = extract_tokens_from_edb_entry(ed)
                for t in tks:
                    if t not in tokens:
                        tokens.append(t)
            # always try CVE token first
            if cve not in tokens:
                tokens.insert(0, cve)

            if not tokens:
                print(f"[!] No tokens derived from Exploit-DB for {cve}; skipping Metasploit search.")
                catalog["entries"].append(entry)
                processed_cves.add(cve)
                save_checkpoint(catalog, csv_rows, json_path=args.checkpoint_json, csv_path=args.checkpoint_csv)
                continue

            print(f"[*] Searching Metasploit with tokens sample: {tokens[:8]}")
            modules = msf_search_with_terms(tokens, max_hits=12)
            if not modules:
                print(f"[!] No Metasploit modules found for {cve}")
                catalog["entries"].append(entry)
                processed_cves.add(cve)
                save_checkpoint(catalog, csv_rows, json_path=args.checkpoint_json, csv_path=args.checkpoint_csv)
                continue

            print(f"[*] Found Metasploit modules: {modules}")
            for mod in modules:
                payloads = msf_show_payloads(mod)
                entry["msf_modules"].append({"module": mod, "payloads": payloads})
                if payloads:
                    for p in payloads:
                        csv_rows.append([cve, edb_results[0].get("EDB-ID") if edb_results else "", edb_results[0].get("Title") if edb_results else "", mod, p])
                else:
                    csv_rows.append([cve, edb_results[0].get("EDB-ID") if edb_results else "", edb_results[0].get("Title") if edb_results else "", mod, ""])

            # append entry and checkpoint
            catalog["entries"].append(entry)
            processed_cves.add(cve)
            # update generated_at for checkpoint freshness
            catalog["generated_at"] = datetime.now(timezone.utc).isoformat()
            save_checkpoint(catalog, csv_rows, json_path=args.checkpoint_json, csv_path=args.checkpoint_csv)

    except KeyboardInterrupt:
        # signal handler should have saved, but be safe and save here too
        print("\n[!] KeyboardInterrupt: saving checkpoint and exiting...")
        save_checkpoint(catalog, csv_rows, json_path=args.checkpoint_json, csv_path=args.checkpoint_csv)
        sys.exit(0)

    # finished loop: write final outputs (overwrite)
    try:
        Path(args.out_json).write_text(json.dumps(catalog, indent=2))
        with Path(args.out_csv).open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["CVE", "EDB-ID", "EDB-Title", "MSF-Module", "Payload"])
            for r in csv_rows:
                w.writerow(r)
        # remove checkpoint files (optional)
        try:
            Path(args.checkpoint_json).unlink(missing_ok=True)
            Path(args.checkpoint_csv).unlink(missing_ok=True)
        except Exception:
            pass
        print(f"\n[*] Done. Final outputs written: {args.out_json}, {args.out_csv}")
    except Exception as e:
        print(f"[ERROR] failed to write final outputs: {e}")
        # leave checkpoint files in place for resume
        print(f"[*] Checkpoint files remain: {args.checkpoint_json}, {args.checkpoint_csv}")

if __name__ == "__main__":
    main()
