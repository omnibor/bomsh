# Bomsh

A collection of tools to explore the [GitBOM](https://gitbom.dev/) idea. Bomsh contains tools to generate GitBOM docs:

- [Bomtrace2](Bomtrace2.md): Generates GitBOM [artifact trees](https://gitbom.dev/glossary/artifact_tree/) for software during the build process.
- [Bombash](Bombash.md) and [Bomtrace](Bomtrace.md): Previous versions of the bomtrace2 tool.
- `bomsh_create_bom.py`: Processes the raw bomtrace2 logs and creates GitBOM docs.
- `bomsh_create_bom_java.py`: Scans the build workspace and creates GitBOM docs for generated JAR files.

As well as tools to search for vulnerabilities:

- `bomsh_create_cve.py`: Creates a CVE database by scanning a Git repo.
- `bomsh_search_cve.py`: Uses the CVE database and GitBOM docs to search for vulnerabilities in software.

## Getting Started

Check the [quickstart guide](Quickstart.md) for instructions on how to use the tool to generate GitBOM docs.

The [CVE search quickstart guide](CVE%20Search%20Quickstart) has instructions on how to generate a CVE database and use it to search for vulnerabilities.

Sample GitBOM docs for popular Linux binaries are available in the [gitbom-repo](https://github.com/yonhan3/gitbom-repo). Bomsh supports [reproducible builds](Reproducible%20Build.md) of these binaries.

## Notes

This has been tested on Ubuntu20.04/AlmaLinux8/Centos8/RedHat8.

Most of the generated files by the scripts are put in `/tmp` directory by default, except the gitBOM docs are put in `${PWD}/.gitbom` directory. This is configurable. The tmp directory can be changed with the `--tmpdir` option. The gitbom directory can be changed with the `-b`/`--bom_dir` option.

## References

1. Towards a GitBOM Specification : https://hackmd.io/@aeva/draft-gitbom-spec

2. [Bomsh/Bomtrace: Tools to Generate gitBOM Artifact Trees and Search CVE for Software Build](https://docs.google.com/presentation/d/14HuQ2_4kJYkDNumd7w7WgXJTOup0tp-AkCY7jtBNHjg)

