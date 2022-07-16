# CVE Search Quick Start

## Creating CVE Database

```bash
# Generates the CVE database in cvedb.json
python3 bomsh_create_cve.py --use_git_tags --cveinfo_dir <directory with cveinfo yaml files> -j cvedb.json
```

Optionally add `--cve_check_dir <directory with cve-add and cve-fix files>`

## Software Vulnerability CVE Search

```bash
# Results are stored in result.json
python3 bomsh_search_cve.py -r <the treedb from generated gitbom> -d <cve database> -f <list of comma-separated files to search> -j result.json
```

