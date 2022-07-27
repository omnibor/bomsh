# Quick Start

## Install Pre-Requisites

- Python 3
- Docker
- `git`
- `head`
- `xxd`

For generating C, Rust, and Go gitoids:
- `ar`
- `readelf`
- `objcopy`

For generating Java gitoids:
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

For C, Rust, and Go:

The [bomtrace2](Bomtrace2.md) tool generates a GitBOM artifact tree, then the `bomsh_create_bom.py` script generates the metadata.

```bash
cp scripts/bomsh_hook2.py /tmp
cp scripts/bomsh_create_bom.py /tmp
bomtrace2 <build command>
# Generates the GitBOM metadata in the .gibtom directory
python3 bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile
```

Building and generating GitBOM Docs for RPM/DEB packages described [here](RPM%20and%20DEB%20Packages.md).

For Java:

```bash
# Generates the GitBOM metadata in the .gitbom directory
# and the artifact tree in treedb.json
python3 bomsh_create_bom_java.py -r <root directory of build workspace> -b .gitbom -j treedb.json
```

The root directory of build workspace should contain the `.java` source files, the corresponding `.class` files, and the compiled JARs.

### Embedding BOMs

The bomsh tool automatically embeds a `.bom` section into compiled binaries or JAR files. Details on how to customize or disable this embedding [here](Embed%20BOM.md).

