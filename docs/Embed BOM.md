# Embed BOM

The bomsh tool embeds a `.bom` section into compiled ELF binaries. The BOM section contains the output file's 20-byte [gitoid](https://gitbom.dev/glossary/git/#git-object-id-gitoid) that can be used to uniquely identify the output [artifact](https://gitbom.dev/glossary/artifact). There is no need to modify the build Makefiles, the embedding is done transparently to the software build.

The latest `bomsh_hook2.py` script (run by bomtrace2) automatically embeds the `.bom` section by default when running compilers/linkers (cc/gcc/clang). The eu-strip program is known to strip the `.bom` section while GNU strip does not, so the script also re-inserts the gitoid when running eu-strip.

Use the `-n` option in the `bomsh_hook2.py` script to disable automatic bom section embedding.

## Customize when BOM is embedded

The `--embed_bom_after_commands` option in the `bomsh_hook2.py` script allows the user to choose which commands in the build process will generate an embedded BOM section. The option is a comma-separated list of programs that will be added to the compilers and linkers that embed BOMs by default. The `-n` option turns off automatic embedding for compilers and linkers, allowing for full control over when the `.bom` section is embedded into compiled binaries.

## Java BOM embedding

The `bomsh_create_bom_java.py` script also automatically embeds a `.bom` section into the compiled JAR files. The originally built JARs are not modified, new JARs with the embedded BOM are included in the GitBOM metadata, in the `with_bom_files` directory.

The `--not_embed_bom_section` option turns off embedding.

