# Bomtrace2

Bomtrace2 uses the `strace` command to watch which programs are executed during a software build to find and record the input files, generating a GitBOM [artifact tree](https://gitbom.dev/glossary/artifact_tree/).

An example for generating an artifact tree for a C program, such as the HelloWorld program in `src`, is to run `bomtrace2 make`.

Bomtrace2 works together with the `bomsh_hook2.py` script to record the raw info necessary to generate GitBOM docs. The raw info is recorded in `/tmp/bomsh_hook_raw_logfile` by default unless overriden with the `-r` option. For each process involved in building a complete program, the script records the checksums of the parsed input/output files and the shell command used to build the output file. An example for the HelloWorld program is:

```
outfile: 6c7744ecf42790fb8073d0e822eb0a2b9b7c39e7 path: /home/bomsh/src/hello.o
infile: 29039dc7dd32210e38e949fcf483ec8ce6f7a054 path: /home/bomsh/src/hello.c
infile: c2ab78a2d4c20711295a501c61dd038bfa029934 path: /usr/include/stdc-predef.h
infile: 739e08610d54f341cf14247ec38f254e1520e5b1 path: /usr/include/stdio.h
...
infile: 4f725e95ffa2663083b66a557b12751261cbcf05 path: /usr/include/bits/sys_errlist.h
build_cmd: gcc -c -o hello.o hello.c
==== End of raw info for this process
```

After the software build is done, the `bomsh_create_bom.py` script is used to read the raw logfile, generate the hash tree, and create the GitBOM docs. The hash tree database is saved in `/tmp/bomsh_createbom_jsonfile` by default.

## Config

The `-c config_file` argument is used to read configuration options from file. A sample config file with documentation on each option is provided in `bin/bomtrace.conf`.

## Watched Programs

The `-w watched_programs_file` argument is used to tell bomtrace2 to only record commands for a limited set of programs. The watched programs file is formatted like:

- List of watched programs.
- An exact line of "---"
- List of pre-exec mode only programs
- An exact line of "==="
- List of ignored programs (`strace` will detach when executed)

Lines starting with `#` are ignored. An example watched programs file is in `bin/bomtrace_watched_programs`.

Some programs, such as `./configure`, do not process additional input source files. Adding those programs to the ignored programs list can result in performance benefits.

