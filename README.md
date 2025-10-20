# CVE Payload Mapping

**Purpose**  
RESEARCH
Build an+ auditable catalog that maps **CVE → public PoCs (Exploit-DB) → Metasploit modules → supported payload names**.  


---

## Repo files 
- `cve_to_payloads.py`: main script (contains the Exploit-DB → Metasploit catalog flow with checkpointing & resume).  
- `cves.csv`: CVE list (one CVE per line or CSV with `cve` column).  
- `exploitdb_msf_catalog.json`: sample/previous catalog output (JSON).  
- `exploitdb_msf_catalog.csv`: sample/previous catalog output (CSV).

---

## What the script does (`cve_to_payloads.py`)
- For each CVE in `cves.csv`:
  - Calls `searchsploit --cve <CVE> -j` (Exploit-DB) to get PoCs.  
  - Derives tokens from PoC metadata (title/platform/path).  
  - Searches Metasploit (`msfconsole`) using derived tokens to find modules.  
  - Runs `use <module>; show payloads` and collects **payload names** (no exploit execution).  
- Writes outputs and checkpoints:
  - Final JSON: default `exploitdb_msf_catalog.json` (structured).  
  - Final CSV: default `exploitdb_msf_catalog.csv` (flat table).  
  - Checkpoints (written after each CVE): `exploitdb_msf_catalog.partial.json` and `.partial.csv`.  
- Supports resume: if a partial checkpoint exists it resumes from the last processed CVE.
- Option `--only-exploitdb` will skip Metasploit lookups and only collect Exploit-DB entries.

---

## Outputs produced
- **JSON** (structured): `exploitdb_msf_catalog.json`  
  - For each CVE: Exploit-DB hits + matching Metasploit modules + `payloads` array (payload names only).
- **CSV** (flat): `exploitdb_msf_catalog.csv`  
  - Columns: `CVE, EDB-ID, EDB-Title, MSF-Module, Payload`
- **Checkpoint files** (created if run interrupted): `*.partial.json`, `*.partial.csv`


---

## Prerequisites (Kali)
Install on VM:

```bash
sudo apt update
sudo apt install -y python3 git exploitdb metasploit-framework
searchsploit (from exploitdb) — used to lookup Exploit-DB entries by CVE.

msfconsole (Metasploit Framework) — used to search modules and show payloads.

git — optional, for cloning repo.
```


## Quick start (recommended safe flow)

Ensure the repository files are present (or clone it):
```
git clone https://github.com/Beckyntosh/CVE_Payload_Mapping.git
cd CVE_Payload_Mapping
```

Confirm tools are available:
```
which searchsploit msfconsole || echo "install searchsploit or metasploit"
```

To process all CVEs in cves.csv (may take time):
```
python3 cve_to_payloads.py --limit 0
```

If you only want Exploit-DB entries (skip Metasploit lookups):
```
python3 cve_to_payloads.py  --only-exploitdb
```


## File formats (what is saved)

JSON (exploitdb_msf_catalog.json) — sample entry:
```
{
  "generated_at": "2025-10-07T14:51:47Z",
  "entries": [
    {
      "cve": "CVE-2014-7169",
      "exploitdb": [
        { "edb_id": "12345", "title": "Shellshock PoC", "platform": "Unix", "path": "/..." }
      ],
      "msf_modules": [
        { "module": "exploit/multi/http/apache_mod_cgi_bash_env_exec",
          "payloads": ["linux/x86/meterpreter/reverse_tcp","cmd/unix/reverse"] }
      ]
    }
  ]
}
```

CSV (exploitdb_msf_catalog.csv) — columns:
```
CVE, EDB-ID, EDB-Title, MSF-Module, Payload
```