# Quick Start

## Install Pre-Requisites

- Python 3
- Docker
- `git`
- `head`
- `xxd`

For generating non-java boms:
- `ar`
- `readelf`
- `objcopy`

For generating java boms:
- Java
- `zip`
- `diff`

## Compile Bombash and Bomtrace from Source

```bash
git clone https://github.com/git-bom/bomsh.git bomsh
cd bomsh
docker build -t bomsh .devcontainer
# Copies the bombash/bomtrace/bomtrace2 binaries to the current working directory
docker run -it --rm -v ${PWD}:/out bomsh
```

## Generate GitBOM Docs

For C, Rust, and Go

```bash
bomtrace2 <build command>
# Generates the GitBOM metadata in treedb.json
python3 bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -j treedb.json
```

For Java

```bash
# Generates the GitBOM metadata in treedb.json
python3 bomsh_create_bom_java.py -r <root directory of build workspace> -f <list of comma-separated jar files> -j treedb.json
```

## Creating CVE Database

(TODO: describe how to create/find the cveinfo files needed)

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

