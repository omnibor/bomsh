# bomsh

Table of Contents
-----------------
* [Overview](#Overview)
* [Compile Bomsh and Bomtrace from Source](#Compile-Bomsh-and-Bomtrace-from-Source)
* [Generating gitBOM docs with Bomtrace2](#Generating-gitBOM-docs-with-Bomtrace2)
* [Generating gitBOM docs with Bomtrace](#Generating-gitBOM-docs-with-Bomtrace)
* [Generating gitBOM docs with Bomsh](#Generating-gitBOM-docs-with-Bomsh)
* [Software Vulnerability CVE Search](#Software-Vulnerability-CVE-Search)
* [Software Vulnerability CVE Search for JAVA Packages](#Software-Vulnerability-CVE-Search-for-JAVA-Packages)
* [Software Vulnerability CVE Search for Rust Packages](#Software-Vulnerability-CVE-Search-for-Rust-Packages)
* [Software Vulnerability CVE Search for GoLang Packages](#Software-Vulnerability-CVE-Search-for-GoLang-Packages)
* [Some Notes](#Notes)
* [Bibliography](#References)

Overview
--------

Bomsh: a BASH-based shell to generate [GitBOM](https://gitbom.dev/) [artifact trees](https://gitbom.dev/glossary/artifact_tree/) for software.

Bomtrace: a STRACE-based tool to generate [GitBOM](https://gitbom.dev/) [artifact trees](https://gitbom.dev/glossary/artifact_tree/) for software.

Compile Bomsh and Bomtrace from Source
--------------------------------------

The Bomsh tool is based on BASH, and Bomtrace is based on STRACE. The corresponding patch files are stored in the patches directory.
To compile Bomsh/Bomtrace from source, do the following steps:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://git.savannah.gnu.org/git/bash.git
    $ # or github repo # git clone https://github.com/bminor/bash.git
    $ cd bash ; patch -p1 < ../bomsh/patches/bombash.patch
    $ ./configure ; make ; cp ./bash ../bomsh/bin/bombash
    $ cd ..
    $ git clone https://github.com/strace/strace.git
    $ cd strace ; patch -p1 < ../bomsh/patches/bomtrace2.patch
    $ ./bootstrap ; ./configure ; make
    $ # if configure fails, try add --disable-mpers or --enable-mpers=check
    $ cp src/strace ../bomsh/bin/bomtrace2

To automatically create the bombash/bomtrace/bomtrace2 binaries run:

    $ git clone URL-of-this-git-repo bomsh
    $ cd bomsh
    $ docker run -it --rm -v ${PWD}:/out $(cd .devcontainer && docker build -q .)

And you will find the bombash, bomtrace, and bomtrace2 files have been copied into '.' on your host.

Generating gitBOM docs with Bomtrace2
-------------------------------------

Do the following to generate gitBOM docs for the HelloWorld program with Bomtrace2.

    $ git clone URL-of-this-git-repo bomsh
    $ cd bomsh
    $ cp scripts/bomsh_hook2.py /tmp
    $ cd src
    $ ../bin/bomtrace2 make
    $ ../scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -b /tmp/bomdir
    $ ls -tl /tmp/bomdir/objects /tmp/bomdir/metadata/bomsh
    $ cat /tmp/bomsh_hook_raw_logfile
    $ cat /tmp/bomsh_createbom_jsonfile

Bomtrace2 works together with the new bomsh_hook2.py script, which records only necessary raw info.
The raw info is recorded in /tmp/bomsh_hook_raw_logfile, which only contains the checksums of the parsed input/output files of the shell commands.
After software build is done, a new bomsh_create_bom.py script is run to read the raw_logfile
and do the hash-tree generation, as well as gitBOM doc creation and .bom section embedding.
The generated hash-tree database is saved in /tmp/bomsh_createbom_jsonfile.
The original bomsh_hook.py is essentially divided into two scripts: bomsh_hook2.py + bomsh_create_bom.py
The two new scripts should generate the exact same gitBOM artifact database /tmp/bomsh_createbom_jsonfile as the /tmp/bomsh_hook_jsonfile of the old bomsh_hook.py script.

The below is a sample run of C HelloWorld program compilation, and the generated bomsh_hook_raw_logfile recorded by Bomtrace2:

```
[root@000b478b5d68 src]# pwd
/home/bomsh/src
[root@000b478b5d68 src]# ../bin/bomtrace2 make
gcc -c -o hello.o hello.c
gcc -o hello hello.o
[root@000b478b5d68 src]# more /tmp/bomsh_hook_raw_logfile

outfile: 6c7744ecf42790fb8073d0e822eb0a2b9b7c39e7 path: /home/bomsh/src/hello.o
infile: 29039dc7dd32210e38e949fcf483ec8ce6f7a054 path: /home/bomsh/src/hello.c
infile: c2ab78a2d4c20711295a501c61dd038bfa029934 path: /usr/include/stdc-predef.h
infile: 739e08610d54f341cf14247ec38f254e1520e5b1 path: /usr/include/stdio.h
infile: b4a429b83c345681b269bdee0785363f3d2c1f3c path: /usr/include/bits/libc-header-start.h
infile: 5bed0a499605a3a26d55443f3c8b7e67de152f74 path: /usr/include/features.h
infile: 3f6fe3cc8563b49311327647fad53eb18d94da2c path: /usr/include/sys/cdefs.h
infile: 70f652bca14d65c1de5a21669e7c0ffb8ecfe5ea path: /usr/include/bits/wordsize.h
infile: 28488e0b05954ccf87c779f5f9258987e4d68ac5 path: /usr/include/bits/long-double.h
infile: 70a1ba017357d3111cc510e73b269541ca2aaf09 path: /usr/include/gnu/stubs.h
infile: 477c8e4931c0d7191187acb42f0ed4255e3619aa path: /usr/include/gnu/stubs-64.h
infile: 31b96a7e5e17f8da4cb8e6262869f643eddbd477 path: /usr/lib/gcc/x86_64-redhat-linux/8/include/stddef.h
infile: e4c73fd23a271b0b452cece0212ff244d2b55d48 path: /usr/lib/gcc/x86_64-redhat-linux/8/include/stdarg.h
infile: 64f344c6e7897491c7c7430f52ad06c61fa85dad path: /usr/include/bits/types.h
infile: e6f7481a19cbc7857dbbfebef5adbeeaf80a70b8 path: /usr/include/bits/typesizes.h
infile: bb04576651b9097b3027e4299cc30c88f334535f path: /usr/include/bits/types/__fpos_t.h
infile: 1d8a4e28d1b62a2bfeba837fe18422cd106e6ddf path: /usr/include/bits/types/__mbstate_t.h
infile: 06a6891154fff74e1ddb6245f4a0467b09c617c5 path: /usr/include/bits/types/__fpos64_t.h
infile: 06dd79bc831bb06a6267a36ad2d62beccd7900b2 path: /usr/include/bits/types/__FILE.h
infile: f2682632090ba3e7f2caa1736394cbb235ceab0c path: /usr/include/bits/types/FILE.h
infile: 359f94945346c9eb4f92d1551e5e1a6d63a63dfb path: /usr/include/bits/types/struct_FILE.h
infile: 1be90e6fab4ab9b7dd3b27cea5bb1fe29acc0204 path: /usr/include/bits/stdio_lim.h
infile: 4f725e95ffa2663083b66a557b12751261cbcf05 path: /usr/include/bits/sys_errlist.h
build_cmd: gcc -c -o hello.o hello.c
==== End of raw info for this process


outfile: dfad3d1a11801f146a94b2ad50024945b82efef6 path: /home/bomsh/src/hello
infile: ff3b4838fba28e31dedd3703f4337107e6bc3ac0 path: /usr/libexec/gcc/x86_64-redhat-linux/8/liblto_plugin.so
infile: fc3bd83b45151f219d7efeac952c567ddb9f86d0 path: /lib64/ld-linux-x86-64.so.2
infile: 596b81d3834f6f7f3aa888e09885505539c2f5ad path: /usr/lib64/crt1.o
infile: 232fd2c41d204d23899069fc89e6516aab57421b path: /usr/lib64/crti.o
infile: df02dffda2dc9c8a306829c31b540348165a3b92 path: /usr/lib/gcc/x86_64-redhat-linux/8/crtbegin.o
infile: 6c7744ecf42790fb8073d0e822eb0a2b9b7c39e7 path: /home/bomsh/src/hello.o
infile: e4af8bf4f89bdb8bb6a890d8a9f07dce5c638138 path: /usr/lib/gcc/x86_64-redhat-linux/8/crtend.o
infile: 3d5810339f0b219eb80dfa7cbd8883c3ef944351 path: /usr/lib64/crtn.o
build_cmd: /usr/bin/ld -plugin /usr/libexec/gcc/x86_64-redhat-linux/8/liblto_plugin.so -plugin-opt=/usr/libexec/gcc/x86_64-redhat-linux/8/lto-wrapper -plugin-opt=-fresolution=/tmp/ccPRtOFM.res -plug
in-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s -plugin-opt=-pass-through=-lc -plugin-opt=-pass-through=-lgcc -plugin-opt=-pass-through=-lgcc_s --build-id --no-add-needed --eh-frame-hdr
 --hash-style=gnu -m elf_x86_64 -dynamic-linker /lib64/ld-linux-x86-64.so.2 -o hello /usr/lib/gcc/x86_64-redhat-linux/8/../../../../lib64/crt1.o /usr/lib/gcc/x86_64-redhat-linux/8/../../../../lib64/
crti.o /usr/lib/gcc/x86_64-redhat-linux/8/crtbegin.o -L/usr/lib/gcc/x86_64-redhat-linux/8 -L/usr/lib/gcc/x86_64-redhat-linux/8/../../../../lib64 -L/lib/../lib64 -L/usr/lib/../lib64 -L/usr/lib/gcc/x8
6_64-redhat-linux/8/../../.. hello.o -lgcc --as-needed -lgcc_s --no-as-needed -lc -lgcc --as-needed -lgcc_s --no-as-needed /usr/lib/gcc/x86_64-redhat-linux/8/crtend.o /usr/lib/gcc/x86_64-redhat-linu
x/8/../../../../lib64/crtn.o
==== End of raw info for this process


outfile: dfad3d1a11801f146a94b2ad50024945b82efef6 path: /home/bomsh/src/hello
infile: 6c7744ecf42790fb8073d0e822eb0a2b9b7c39e7 path: /home/bomsh/src/hello.o
build_cmd: gcc -o hello hello.o
==== End of raw info for this process

[root@000b478b5d68 src]#
```

A new [-w watched_programs_file] option is added for bomtrace2 so that only commands for a limited set of programs are recorded.
Make sure that this program list covers all the watched programs in bomsh_hook2.py script.
A list of pre-exec mode only programs can also be provided in the same watched_programs_file.
This pre-exec mode only list is provided in the same watched_programs_file after the list of watched programs, separated by an exact line of "---".
Make sure that this pre-exec program list covers all the pre-exec watched programs in bomsh_hook2.py script too.
Also an aditional list of programs can be detached immediately upon execve syscall for perfomance benefits.
This detach list is provided in the same watched_programs_file after the list of watched or pre-exec programs, separated by an exact line of "===".
A good use case for this detach program list is the configure command for software build.
An example watched_programs file has been provided in the bin/bomtrace_watched_programs file.
Note that empty lines or lines starting with '#' character are ignored, so you can add comments in your watched_programs file.
If there is no -w option, then it is the same behavior as before, recording all commands by default.

Here are the new commands to generate gitBOM docs with the -w option.

    $ git clone URL-of-this-git-repo bomsh
    $ cd bomsh
    $ cp scripts/bomsh_hook2.py /tmp
    $ cd src
    $ ../bin/bomtrace2 -w ../bin/bomtrace_watched_programs make
    $ ../scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -b /tmp/bomdir
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_createbom_jsonfile

You can customize this bomtrace_watched_programs for your own software, to further improve the performance.
The generated /tmp/bomsh_createbom_jsonfile should be the same as the old /tmp/bomsh_hook_jsonfile, which is used by the scripts/bomsh_search_cve.py script.

A new -c option is added for Bomtrace2 to read some configurations from a config file.
Five options are now supported: hook_script_file, hook_script_cmdopt, shell_cmd_file, logfile, and syscalls.
Especially with the hook_script_cmdopt parameter, now we will be able to run the hook script with various different options more conveniently.
A sample Bomtrace config file is provided in bin/bomtrace.conf file.

The bomsh_create_bom.py script takes care of gitBOM docs creation when reading and processing bomsh_hook_raw_logfile.
Here is the adopted algorithm to create gitBOM docs in the bomsh_create_bom.py script:
- if there are multiple input files, then a new GitBOM doc is generated, and the 20-byte gitBOM ID is embedded in the output file if necessary (by default for cc/ld output only);
- if there is only one input file (unary transformation), then the same gitBOM id of the input file is reused by the output file.

The -b option of bomsh_create_bom.py script specifies the gitBOM repo directory to store all the gitBOM docs and metadata.
If user does not specify the -b option, then $PWD/.gitbom directory is used as the default location.
The gitBOM docs are stored in .gitbom/objects/ directory, while bomsh tool's metadata is stored in .gitbom/metadata/bomsh/ directory.
The bomsh tool's metadata includes:
- bomsh_hook_raw_logfile, the raw info recorded by bomsh_hook2.py script for software build
- bomsh_gitbom_treedb, the hash-tree JSON format file with metadata, created by bomsh_create_bom.py script
- bomsh_gitbom_doc_mapping, the file-githash to its gitBOM doc ID mapping file, for all output files generated during software build

A new --embed_bom_after_commands is added for bomsh_hook2.py script to allow user to select a list of commands to automatically
insert an embedded .bom ELF section (or .bom archive entry) into the compiled binary files during software build.
The embedding of the .bom ELF section is done transparently to the software build, so you don't need to modify your build Makefiles at all.
And user can conveniently select where in the middle of the build process to perform this .bom section insertion.
To find the appropriate place to do this, user can inspect the generated bomsh_hook_raw_logfile or bomsh_hook_trace_logfile to see the list of shell commands
and their execution order in the sequence of build process, and figure out where to do it the best.

Note that this automatic .bom section embedding impacts performance, since it needs to build the hash-tree and generate gitBOM docs.
From our experiments, the performance impact is less than 10%, and the runtime increase is linear to the number of bom-id-embedding operations.

A new --lseek_lines_file option is added for bomsh_create_bom.py script to avoid duplicate reading/processing of bomsh_hook_raw_logfile
if a previous run has already read/processed some lines of bomsh_hook_raw_logfile.
This code optimization is done specifically for the above scenario of automatic .bom section embedding during RPM/Debian packaging.
User should not need this --lseek_lines_file option for regular use scenarios.

The bomsh_create_bom.py script also supports creating gitBOM docs for RPM/DEB packages via the -p option of the bomsh_create_bom.py script.
For example, to do it for hostname RPM package, here is the workflow:

    $ git clone URL-of-this-git-repo bomsh
    $ cp bomsh/scripts/bomsh_hook2.py bomsh/scripts/bomsh_create_bom.py /tmp
    $ dnf download hostname --source
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_*
    $ bomsh/bin/bomtrace2 -w bomsh/bin/bomtrace_watched_programs rpmbuild --rebuild hostname-3.20-6.el8.src.rpm
    $ bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -p /root/rpmbuild/RPMS/x86_64/hostname-3.20-6.el8.x86_64.rpm
    $ cat /tmp/bomsh_hook_raw_logfile /tmp/bomsh_createbom_jsonfile
    $ echo "{}" > hostname_cvedb.json
    $ bomsh/scripts/bomsh_search_cve.py -vv -b .gitbom -d hostname_cvedb.json -f /root/rpmbuild/RPMS/x86_64/hostname-3.20-6.el8.x86_64.rpm
    $ cat /tmp/bomsh_search_jsonfile-details.json

Note that rpm2cpio and cpio are used to unbundle RPM package, and dpkg-deb is used to unbundle DEB package, so make sure they are installed.

With latest bomtrace2/bomsh_hook2.py script, we have enabled automatic .bom section embedding into ELF binary files by default
for compilers/linkers (cc/gcc/clang/ld, etc.) and eu-strip (elfutils strip) program.
The eu-strip program is known to strip the .bom ELF section while GNU strip does not, so we must perform bom-id re-insertion for eu-strip program.

To disable this auto-bom-id-embedding, user must provide -n option to the bomsh_hook2.py script, which requires the use of "-c bomtrace.conf" option when running bomtrace2.
Therefore, user can still choose to do bom-id embedding into binary files at any build steps they prefer, with the "-c bomtrace.conf" option.
For example, to build the hostname RPM package with embedded .bom ELF section in the hostname binary at the last build step only,
here is the workflow:

    $ git clone URL-of-this-git-repo bomsh
    $ cp bomsh/scripts/bomsh_hook2.py bomsh/scripts/bomsh_create_bom.py /tmp
    $ dnf download hostname --source
    $ sed -i "s|hook_script_cmdopt=-vv > |hook_script_cmdopt=-vv -n --embed_bom_after_commands /usr/lib/rpm/sepdebugcrcfix > |" bomsh/bin/bomtrace.conf
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_*
    $ bomsh/bin/bomtrace2 -c bomsh/bin/bomtrace.conf -w bomsh/bin/bomtrace_watched_programs rpmbuild --rebuild hostname-3.20-6.el8.src.rpm
    $ bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -p /root/rpmbuild/RPMS/x86_64/hostname-3.20-6.el8.x86_64.rpm
    $ cat /tmp/bomsh_hook_raw_logfile /tmp/bomsh_createbom_jsonfile
    $ echo "{}" > hostname_cvedb.json
    $ bomsh/scripts/bomsh_search_cve.py -vv -b .gitbom -d hostname_cvedb.json -f /root/rpmbuild/RPMS/x86_64/hostname-3.20-6.el8.x86_64.rpm
    $ cat /tmp/bomsh_search_jsonfile-details.json

If you just want to capture all the build commands for your software build, you can do similar steps with the "bomtrace2 -c bomtrace.conf make" command.
Then you check the generated /tmp/bomsh_hook_trace_logfile for a list of recorded shell commands.

Generating gitBOM docs with Bomtrace
------------------------------------

Do the following to generate gitBOM docs for the HelloWorld program with Bomtrace.

    $ git clone URL-of-this-git-repo bomsh
    $ cd bomsh
    $ cp scripts/bomsh_hook.py /tmp
    $ cd src
    $ ../bin/bomtrace make
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile

Do the following to generate gitBOM docs for the RPM or DEB package of OpenOSC with Bomtrace.

    $ git clone URL-of-this-git-repo bomsh
    $ rm -rf /tmp/bomdir; rm /tmp/bomsh_hook_*; cp bomsh/scripts/bomsh_hook.py /tmp
    $ git clone https://github.com/cisco/OpenOSC.git
    $ cd OpenOSC
    $ autoreconf -vfi ; ./configure
    $ ../bomsh/bin/bomtrace make deb  # on debian Linux distro
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile
    $ echo "{}" > openosc_cvedb.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_hook_jsonfile -d openosc_cvedb.json -f debian/openosc/usr/lib/x86_64-linux-gnu/libopenosc.so.0.0.0,debian/openosc/usr/lib/x86_64-linux-gnu/libopenosc.a
    $ cat /tmp/bomsh_search_jsonfile-details.json
    $
    $ # the below are only for AlmaLinux/Centos/RedHat Linux distro
    $ ../bomsh/bin/bomtrace make rpm  # on RedHat Linux distro
    $ mkdir rpm-extractdir ; cd rpm-extractdir
    $ rpm2cpio ../rpmbuild/RPMS/x86_64/openosc-1.0.5-1.el8.x86_64.rpm | cpio -idmv
    $ rpm2cpio ../rpmbuild/RPMS/x86_64/openosc-static-1.0.5-1.el8.x86_64.rpm | cpio -idmv ; cd ..
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_hook_jsonfile -d openosc_cvedb.json -f rpm-extractdir/usr/lib64/libopenosc.a,rpm-extractdir/usr/lib64/libopenosc.so.0.0.0

Generating gitBOM docs with Bomsh
---------------------------------

Do the following to generate gitBOM docs for the HelloWorld program with Bomsh.

    $ git clone URL-of-this-git-repo bomsh
    $ cd bomsh
    $ cp scripts/bomsh_hook.py /tmp
    $ BOMSH= bin/bombash
    $ cd src
    $ make
    $ exit
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile

All the gitBOM documents have been automatically generated by Bomsh/Bomtrace,
which contain the C header dependencies for the compiled binary files.
The generated ELF binary files are embeded with the .bom ELF section,
and the generated archive files have the additional .bom archive entry, containing the gitBOM identifier.
Here is the file content of /tmp/bomsh_hook_jsonfile and the /tmp/bomdir directory for HelloWorld:

```
[yonhan@rtp-gpu-02 src]$ more /tmp/bomdir/*
::::::::::::::
/tmp/bomdir/576e4e24b6af4311b4c51816fea2a21b1f152dbf
::::::::::::::
blob af4f09c6bbd7813b308541ae1659e7087d0de194 bom 5e1750281326e9fe14f29adc0198fc24cc8964c6
::::::::::::::
/tmp/bomdir/5e1750281326e9fe14f29adc0198fc24cc8964c6
::::::::::::::
blob 06a6891154fff74e1ddb6245f4a0467b09c617c5
blob 06dd79bc831bb06a6267a36ad2d62beccd7900b2
blob 1be90e6fab4ab9b7dd3b27cea5bb1fe29acc0204
blob 1d8a4e28d1b62a2bfeba837fe18422cd106e6ddf
blob 28488e0b05954ccf87c779f5f9258987e4d68ac5
blob 29039dc7dd32210e38e949fcf483ec8ce6f7a054
blob 31b96a7e5e17f8da4cb8e6262869f643eddbd477
blob 359f94945346c9eb4f92d1551e5e1a6d63a63dfb
blob 3f6fe3cc8563b49311327647fad53eb18d94da2c
blob 477c8e4931c0d7191187acb42f0ed4255e3619aa
blob 4f725e95ffa2663083b66a557b12751261cbcf05
blob 5bed0a499605a3a26d55443f3c8b7e67de152f74
blob 64f344c6e7897491c7c7430f52ad06c61fa85dad
blob 70a1ba017357d3111cc510e73b269541ca2aaf09
blob 70f652bca14d65c1de5a21669e7c0ffb8ecfe5ea
blob 739e08610d54f341cf14247ec38f254e1520e5b1
blob b4a429b83c345681b269bdee0785363f3d2c1f3c
blob bb04576651b9097b3027e4299cc30c88f334535f
blob c2ab78a2d4c20711295a501c61dd038bfa029934
blob e4c73fd23a271b0b452cece0212ff244d2b55d48
blob e6f7481a19cbc7857dbbfebef5adbeeaf80a70b8
blob f2682632090ba3e7f2caa1736394cbb235ceab0c
::::::::::::::
/tmp/bomdir/bomsh_gitbom_doc_mapping
::::::::::::::
{
    "1fcb431b32c201c6aaeeb0273153d146e225e52d": "576e4e24b6af4311b4c51816fea2a21b1f152dbf",
    "af4f09c6bbd7813b308541ae1659e7087d0de194": "5e1750281326e9fe14f29adc0198fc24cc8964c6"
}
[yonhan@rtp-gpu-02 src]$ readelf -x .bom /tmp/bomdir/with_bom_files/1fcb431b32c201c6aaeeb0273153d146e225e52d-with_bom-hello

Hex dump of section '.bom':
  0x00000000 576e4e24 b6af4311 b4c51816 fea2a21b WnN$..C.........
  0x00000010 1f152dbf                            ..-.

[yonhan@rtp-gpu-02 src]$ cat /tmp/bomsh_hook_jsonfile
{
    "06a6891154fff74e1ddb6245f4a0467b09c617c5": {
        "file_path": "/usr/include/bits/types/__fpos64_t.h"
    },
    "06dd79bc831bb06a6267a36ad2d62beccd7900b2": {
        "file_path": "/usr/include/bits/types/__FILE.h"
    },
    "1be90e6fab4ab9b7dd3b27cea5bb1fe29acc0204": {
        "file_path": "/usr/include/bits/stdio_lim.h"
    },
    "1d8a4e28d1b62a2bfeba837fe18422cd106e6ddf": {
        "file_path": "/usr/include/bits/types/__mbstate_t.h"
    },
    "1fcb431b32c201c6aaeeb0273153d146e225e52d": {
        "build_cmd": "gcc -o hello hello.o",
        "file_path": "/data/yonhan/some-git-dir/bomsh-gitdir/src/hello",
        "hash_tree": [
            "af4f09c6bbd7813b308541ae1659e7087d0de194"
        ]
    },
    "28488e0b05954ccf87c779f5f9258987e4d68ac5": {
        "file_path": "/usr/include/bits/long-double.h"
    },
    "29039dc7dd32210e38e949fcf483ec8ce6f7a054": {
        "file_path": "/data/yonhan/some-git-dir/bomsh-gitdir/src/hello.c"
    },
    "31b96a7e5e17f8da4cb8e6262869f643eddbd477": {
        "file_path": "/usr/lib/gcc/x86_64-redhat-linux/8/include/stddef.h"
    },
    "359f94945346c9eb4f92d1551e5e1a6d63a63dfb": {
        "file_path": "/usr/include/bits/types/struct_FILE.h"
    },
    "3f6fe3cc8563b49311327647fad53eb18d94da2c": {
        "file_path": "/usr/include/sys/cdefs.h"
    },
    "477c8e4931c0d7191187acb42f0ed4255e3619aa": {
        "file_path": "/usr/include/gnu/stubs-64.h"
    },
    "4f725e95ffa2663083b66a557b12751261cbcf05": {
        "file_path": "/usr/include/bits/sys_errlist.h"
    },
    "5bed0a499605a3a26d55443f3c8b7e67de152f74": {
        "file_path": "/usr/include/features.h"
    },
    "64f344c6e7897491c7c7430f52ad06c61fa85dad": {
        "file_path": "/usr/include/bits/types.h"
    },
    "70a1ba017357d3111cc510e73b269541ca2aaf09": {
        "file_path": "/usr/include/gnu/stubs.h"
    },
    "70f652bca14d65c1de5a21669e7c0ffb8ecfe5ea": {
        "file_path": "/usr/include/bits/wordsize.h"
    },
    "739e08610d54f341cf14247ec38f254e1520e5b1": {
        "file_path": "/usr/include/stdio.h"
    },
    "af4f09c6bbd7813b308541ae1659e7087d0de194": {
        "build_cmd": "gcc -c -o hello.o hello.c",
        "file_path": "/data/yonhan/some-git-dir/bomsh-gitdir/src/hello.o",
        "hash_tree": [
            "739e08610d54f341cf14247ec38f254e1520e5b1",
            "5bed0a499605a3a26d55443f3c8b7e67de152f74",
            "e6f7481a19cbc7857dbbfebef5adbeeaf80a70b8",
            "06a6891154fff74e1ddb6245f4a0467b09c617c5",
            "31b96a7e5e17f8da4cb8e6262869f643eddbd477",
            "e4c73fd23a271b0b452cece0212ff244d2b55d48",
            "b4a429b83c345681b269bdee0785363f3d2c1f3c",
            "f2682632090ba3e7f2caa1736394cbb235ceab0c",
            "3f6fe3cc8563b49311327647fad53eb18d94da2c",
            "359f94945346c9eb4f92d1551e5e1a6d63a63dfb",
            "4f725e95ffa2663083b66a557b12751261cbcf05",
            "29039dc7dd32210e38e949fcf483ec8ce6f7a054",
            "28488e0b05954ccf87c779f5f9258987e4d68ac5",
            "64f344c6e7897491c7c7430f52ad06c61fa85dad",
            "1d8a4e28d1b62a2bfeba837fe18422cd106e6ddf",
            "70a1ba017357d3111cc510e73b269541ca2aaf09",
            "70f652bca14d65c1de5a21669e7c0ffb8ecfe5ea",
            "477c8e4931c0d7191187acb42f0ed4255e3619aa",
            "bb04576651b9097b3027e4299cc30c88f334535f",
            "c2ab78a2d4c20711295a501c61dd038bfa029934",
            "1be90e6fab4ab9b7dd3b27cea5bb1fe29acc0204",
            "06dd79bc831bb06a6267a36ad2d62beccd7900b2"
        ]
    },
    "b4a429b83c345681b269bdee0785363f3d2c1f3c": {
        "file_path": "/usr/include/bits/libc-header-start.h"
    },
    "bb04576651b9097b3027e4299cc30c88f334535f": {
        "file_path": "/usr/include/bits/types/__fpos_t.h"
    },
    "c2ab78a2d4c20711295a501c61dd038bfa029934": {
        "file_path": "/usr/include/stdc-predef.h"
    },
    "e4c73fd23a271b0b452cece0212ff244d2b55d48": {
        "file_path": "/usr/lib/gcc/x86_64-redhat-linux/8/include/stdarg.h"
    },
    "e6f7481a19cbc7857dbbfebef5adbeeaf80a70b8": {
        "file_path": "/usr/include/bits/typesizes.h"
    },
    "f2682632090ba3e7f2caa1736394cbb235ceab0c": {
        "file_path": "/usr/include/bits/types/FILE.h"
    }
}
[yonhan@rtp-gpu-02 src]$
```

If you need to generate gitBOM docs for another software like OpenOSC,

    $ git clone URL-of-this-git-repo bomsh
    $ rm -rf /tmp/bomdir; rm /tmp/bomsh_hook_*; cp bomsh/scripts/bomsh_hook.py /tmp
    $ git clone https://github.com/cisco/OpenOSC.git
    $ cd OpenOSC
    $ autoreconf -vfi ; ./configure CC=clang
    $ BOMSH= ../bomsh/bin/bombash
    $ make
    $ exit
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile

Here is the new libopenosc.a archive file with embedded .bom archive entry:

```
root@0b3023697a46:/home/OpenOSC# git hash-object src/.libs/libopenosc.a
6bc61598a60ea60fcfb51b76bc47b45ee8b6946c
root@0b3023697a46:/home/OpenOSC# ar -tv src/.libs/libopenosc.a
rw-r--r-- 0/0  27408 Jan  1 00:00 1970 libopenosc_la-openosc_map.o
rw-r--r-- 0/0  11312 Jan  1 00:00 1970 libopenosc_la-openosc_support.o
rw-r--r-- 0/0   2784 Jan  1 00:00 1970 libopenosc_la-openosc_package_info.o
rw-r--r-- 0/0 104544 Jan  1 00:00 1970 libopenosc_la-openosc_fortify_map.o
root@0b3023697a46:/home/OpenOSC# ar -tv /tmp/bomdir/with_bom_files/6bc61598a60ea60fcfb51b76bc47b45ee8b6946c-with_bom-libopenosc.a
rw-r--r-- 0/0  27408 Jan  1 00:00 1970 libopenosc_la-openosc_map.o
rw-r--r-- 0/0  11312 Jan  1 00:00 1970 libopenosc_la-openosc_support.o
rw-r--r-- 0/0   2784 Jan  1 00:00 1970 libopenosc_la-openosc_package_info.o
rw-r--r-- 0/0 104544 Jan  1 00:00 1970 libopenosc_la-openosc_fortify_map.o
rw-r--r-- 0/0     20 Jan  1 00:00 1970 .bom
root@0b3023697a46:/home/OpenOSC# ar -x /tmp/bomdir/with_bom_files/6bc61598a60ea60fcfb51b76bc47b45ee8b6946c-with_bom-libopenosc.a .bom
root@0b3023697a46:/home/OpenOSC# hexdump -C .bom
00000000  41 d3 3f 44 eb 60 cb e6  d2 76 0f 7f db a5 36 c2  |A.?D.`...v....6.|
00000010  f3 62 a3 8e                                       |.b..|
00000014
root@0b3023697a46:/home/OpenOSC# cat /tmp/bomdir/41d33f44eb60cbe6d2760f7fdba536c2f362a38e
blob 438bf647db266e2b7d71557436beda2ca21afb27 bom 54e7d1011d2dbc7d786b4e07bd9216c89ae08d16
blob 88eea30ff5cb11cc2c54c36ecbb7d350723d1063 bom c7d70100720bc7f329e8994e48d3e88611569861
blob b4661cd71c95124d8da0bfba6b97d1d1c313750b bom 1297782f73770700c5eea7fb66d07c6f1eeeabe9
blob b655de6691f64b0ecb445c68ff98815204c9f521 bom 81e3016686ed2c4330a525254170cdc3e75be17c
root@0b3023697a46:/home/OpenOSC#
```

If you need to generate gitBOM docs for another software like OpenSSL,

    $ git clone URL-of-this-git-repo bomsh
    $ rm -rf /tmp/bomdir; rm /tmp/bomsh_hook_*; cp bomsh/scripts/bomsh_hook.py /tmp
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ./Configure
    $ BOMSH= ../bomsh/bin/bombash
    $ make
    $ exit
    $ ls -tl /tmp/bomdir
    $ cat /tmp/bomsh_hook_jsonfile

The bomsh_hook.py script is a Python script, make sure that you have Python3 installed.
This script is invoked for each recorded shell command under the Bomsh shell or with Bomtrace.
You can play with the bomsh_hook.py script and observe the output changes.

Software Vulnerability CVE Search
---------------------------------

The generated hash tree database is /tmp/bomsh_hook_jsonfile, which can be fed to
the scripts/bomsh_search_cve.py script for CVE vulnerability search.

To create the CVE database and search for CVEs for a software like OpenSSL, with Bomsh, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j openssl_cvedb.json
    $ git checkout OpenSSL_1_1_1k
    $ ./config
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_*; cp ../bomsh/scripts/bomsh_hook.py /tmp
    $ BOMSH= ../bomsh/bin/bombash
    $ make
    $ exit
    $ ../bomsh/scripts/bomsh_search_cve.py -r /tmp/bomsh_hook_jsonfile -d openssl_cvedb.json -f libssl.so.1.1,libcrypto.so.1.1

To create the CVE database and search for CVEs for a software like OpenSSL, with Bomtrace2, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j openssl_cvedb.json
    $ git checkout OpenSSL_1_1_1k
    $ ./config
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_*
    $ cp ../bomsh/scripts/bomsh_hook2.py ../bomsh/scripts/bomsh_create_bom.py /tmp
    $ ../bomsh/bin/bomtrace2 make
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -b /tmp/bomdir
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d openssl_cvedb.json -f libssl.so.1.1,libcrypto.so.1.1
    $ cat /tmp/bomsh_search_jsonfile-details.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -b /tmp/bomdir -d openssl_cvedb.json -f /tmp/bomdir/with_bom_files/*libcrypto.so.1.1
    $ # You can also directly provide checksums (blob_ids) with -c option, or gitBOM bom_ids with -g option
    $ cat /tmp/bomsh_search_jsonfile-details.json

To create the CVE database and search for CVEs for a software like Linux kernel, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/torvalds/linux.git
    $ cd linux
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j linux_cvedb.json
    $ git checkout v4.18
    $ make menuconfig
    $ rm -rf /tmp/bomdir; rm /tmp/bomsh_hook_*; cp ../bomsh/scripts/bomsh_hook.py /tmp
    $ BOMSH= ../bomsh/bin/bombash
    $ make
    $ exit
    $ ../bomsh/scripts/bomsh_search_cve.py -r /tmp/bomsh_hook_jsonfile -d linux_cvedb.json -f vmlinux,arch/x86/boot/bzImage

If you want to accurately create the CVE DB, please identify all the vulnerable source files for each CVE,
specify the blob ID ranges of the source files that are vulnerable to the CVE in a text file, and run
bomsh_create_cve script with the -r option.
A sample text file is provided in scripts/sample_vulnerable_ranges.txt file.

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/openssl/openssl.git
    $ cd openssl
    $ ../bomsh/scripts/bomsh_create_cve.py -v -j openssl_cvedb.json -r openssl_vulnerable_cve_ranges.txt

Software Vulnerability CVE Search for JAVA Packages
---------------------------------------------------

To create the gitBOM database and the CVE database for Log4j2 CVE-2021-44228, and search for CVEs for the Log4j2 software, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone --branch rel/2.17.0 https://gitbox.apache.org/repos/asf/logging-log4j2.git log4j-2.17.0
    $ cd log4j-2.17.0
    $ ../bomsh/scripts/bomsh_create_cve.py -v -r ../bomsh/scripts/log4j2_CVE_2021_44228_ranges.txt -j ../log4j2_cvedb.json
    $ ./mvnw package -Dmaven.test.skip=true
    $ ../bomsh/scripts/bomsh_create_bom_java.py -r . -f log4j-core/target/log4j-core-2.17.0.jar -j log4j-treedb.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r log4j-treedb.json -d ../log4j2_cvedb.json -j result.json -f log4j-core/target/log4j-core-2.17.0.jar
    $ grep -6 CVElist result.json-details.json
    $
    $ cd ..
    $ git clone --branch rel/2.14.0 https://gitbox.apache.org/repos/asf/logging-log4j2.git log4j-2.14.0
    $ cd log4j-2.14.0
    $ ../bomsh/scripts/bomsh_create_cve.py -v -r ../bomsh/scripts/log4j2_CVE_2021_44228_ranges.txt -j ../log4j2_cvedb.json
    $ ./mvnw package -Dmaven.test.skip=true
    $ ../bomsh/scripts/bomsh_create_bom_java.py -r . -f log4j-core/target/log4j-core-2.14.0.jar -j log4j-treedb.json
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r log4j-treedb.json -d ../log4j2_cvedb.json -j result.json -f log4j-core/target/log4j-core-2.14.0.jar
    $ grep -6 CVElist result.json-details.json

Here are the CVE search results for two versions of Log4j2 software:

```
[root@000b478b5d68 log4j-2.17.0]# /tmp/bomsh_search_cve.py -r bomsh_createbom_jsonfile -d ../log4j2_cvedb.json -vv -j mysearchcve-result.json -f log4j-core/target/log4j-core-2.17.0.jar

Here is the CVE search results:
{
    "log4j-core/target/log4j-core-2.17.0.jar": {
        "CVElist": [],
        "FixedCVElist": [
            "CVE-2021-44228"
        ]
    }
}
[root@000b478b5d68 log4j-2.17.0]# grep -6 CVElist mysearchcve-result.json-details.json
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/config/plugins/convert/TypeConverterRegistry.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/config/plugins/convert/TypeConverterRegistry.class"
        },
        "71e9c7daeb6f4e3819403a1e37f8171f548e50ed": {
            "a783ea43c171982723e87cc6afd29287c63c1b53": {
                "FixedCVElist": [
                    "CVE-2021-44228"
                ],
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/lookup/JndiLookup.class"
        },
[root@000b478b5d68 log4j-2.17.0]#

[root@000b478b5d68 log4j-2.14.0]# /tmp/bomsh_search_cve.py -r bomsh_createbom_jsonfile -d ../log4j2_cvedb.json -vv -j mysearchcve-result.json -f log4j-core/target/log4j-core-2.14.0.jar

Here is the CVE search results:
{
    "log4j-core/target/log4j-core-2.14.0.jar": {
        "CVElist": [
            "CVE-2021-44228"
        ],
        "FixedCVElist": []
    }
}
[root@000b478b5d68 log4j-2.14.0]# grep -6 CVElist mysearchcve-result.json-details.json
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/pattern/DatePatternConverter.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/pattern/DatePatternConverter$CachedTime.class"
        },
        "605c82e7442a5693745e1e28736446a8ced01d3c": {
            "30e65ad24f4b4d799e52cfd70fcbebc0490b7343": {
                "CVElist": [
                    "CVE-2021-44228"
                ],
                "file_path": "./log4j-core/src/main/java/org/apache/logging/log4j/core/lookup/JndiLookup.java"
            },
            "file_path": "./log4j-core/target/classes/org/apache/logging/log4j/core/lookup/JndiLookup.class"
        },
[root@000b478b5d68 log4j-2.14.0]#
```

It shows that the 2.14.0 version log4j-core-2.14.0.jar is vulnerable to CVE-2021-44228, while the 2.17.0 version log4j-core-2.17.0.jar is not vulnerable (CVE has fixed).
Also it reports the root cause: it is due to the specific version of the JndiLookup.java file with the githash of 30e65ad24f4b4d799e52cfd70fcbebc0490b7343.
Note the git commit logs of log4j2 are manually inspected, and the "bomsh_create_cve.py -r ranges.txt" command is run to create log4j2_cvedb.json for CVE-2021-44228 in this example.

The bomsh_create_bom_java.py script also inserts .bom entry into .jar files automatically.

```
[root@000b478b5d68 log4j-2.17.0]# ../bomsh/scripts/bomsh_create_bom_java.py -r . -f log4j-core/target/log4j-core-2.17.0.jar -b bomdir -j log4j-treedb.json

[root@000b478b5d68 log4j-2.17.0]# jar tvf bomdir/with_bom_files/d4f6bcc969db60298df329972b9b6e83f3aec2e2-with_bom-0dc986b732c75ba0050cdbc859cd9b97eb2cf325-log4j-core-2.17.0.jar | tail -3
   650 Sat Jan 22 18:22:14 UTC 2022 org/apache/logging/log4j/core/jmx/LoggerConfigAdminMBean.class
  5833 Sat Jan 22 18:22:16 UTC 2022 org/apache/logging/log4j/core/jmx/StatusLoggerAdmin.class
    20 Mon Jan 24 04:38:45 UTC 2022 .bom
[root@000b478b5d68 log4j-2.17.0]# jar -xvf bomdir/with_bom_files/d4f6bcc969db60298df329972b9b6e83f3aec2e2-with_bom-0dc986b732c75ba0050cdbc859cd9b97eb2cf325-log4j-core-2.17.0.jar .bom
extracted: .bom
[root@000b478b5d68 log4j-2.17.0]# hexdump -C .bom
00000000  0d c9 86 b7 32 c7 5b a0  05 0c db c8 59 cd 9b 97  |....2.[.....Y...|
00000010  eb 2c f3 25                                       |.,.%|
00000014
[root@000b478b5d68 log4j-2.17.0]#
```

The bomsh_create_bom_java.py script can also work with strace to more accurately create the gitBOM hash-tree database.
Strace can be run first to collect the strace log, which is then read by bomsh_create_bom_java.py with the "-s" option.
This tracks the read/write of .java/.class files, and should be able to more accurately associate .class files to .java files.
The below is an example of creating the hash-tree database for Maven with strace logfile.

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/apache/maven.git ; cd maven
    $ strace -f -s99999 --seccomp-bpf -e trace=openat -qqq -o strace_logfile mvn -Drat.numUnapprovedLicenses=1000 package
    $ ../bomsh/scripts/bomsh_create_bom_java.py -r . -s strace_logfile -f maven-core/target/maven-core-4.0.0-alpha-1-SNAPSHOT.jar -j maven-treedb.json
    $ cat maven-treedb.json

Software Vulnerability CVE Search for Rust Packages
---------------------------------------------------

To create the gitBOM database for a Rust package like kalker, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ git clone https://github.com/PaddiM8/kalker.git
    $ cd kalker ; echo "{}" > kalker_cvedb.json
    $ ../bomsh/bin/bomtrace2 cargo build --release
    $ cat /tmp/bomsh_hook_raw_logfile
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -vv -b /tmp/bomdir
    $ cat /tmp/bomsh_createbom_jsonfile
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d kalker_cvedb.json -j result.json -f target/release/kalker
    $ cat result.json-details.json

All the gitBOM docs are created in /tmp/bomdir (the -b option of bomsh_create_bom.py script).
And all the ELF files are automatically inserted with .bom ELF section, and all archive files are embedded with .bom entry.
All these .bom-section-embedded files are saved in /tmp/bomdir/metadata/bomsh/with_bom_files/ directory.

Software Vulnerability CVE Search for GoLang Packages
-----------------------------------------------------

To create the gitBOM database for a golang package like outyet, do the below:

    $ git clone URL-of-this-git-repo bomsh
    $ # you need to find out the locaiton of your go compiler and tell bomtrace.
    $ # on Ubuntu20.04, it is /usr/lib/go-1.13/pkg/tool/linux_amd64/compile
    $ # the below is for RedHat/Centos/AlmaLinux
    $ sed -i "s|hook_script_cmdopt=-vv > |hook_script_cmdopt=-vv -w /usr/lib/golang/pkg/tool/linux_amd64/compile,/usr/lib/golang/pkg/tool/linux_amd64/link > |" bomsh/bin/bomtrace.conf
    $ sed -i "s|#syscalls=openat|syscalls=openat|" bomsh/bin/bomtrace.conf
    $ git clone https://github.com/golang/example
    $ cd example/outyet; echo "{}" > outyet_cvedb.json
    $ rm -rf /tmp/bomdir /tmp/bomsh_hook_* /tmp/bomsh_createbom_*
    $ ../bomsh/bin/bomtrace2 -c ../bomsh/bin/bomtrace.conf go build -a
    $ cat /tmp/bomsh_hook_raw_logfile
    $ ../bomsh/scripts/bomsh_create_bom.py -r /tmp/bomsh_hook_raw_logfile -vv -b /tmp/bomdir
    $ cat /tmp/bomsh_createbom_jsonfile
    $ ../bomsh/scripts/bomsh_search_cve.py -vv -r /tmp/bomsh_createbom_jsonfile -d outyet_cvedb.json -j result.json -f outyet
    $ cat result.json-details.json

Notice that "go build" by default caches previously built packages. The -a option makes "go build" ignore the cache.
This is required for bomtrace to record all build steps.
Also remember to compile bin/bomtrace2 with the latest patches/bomtrace2.patch file, and a customized bomtrace.conf file must be used
because the bomtrace tool needs to know the location of go compiler and two more syscalls need to be traced.
Again all the gitBOM docs are created in /tmp/bomdir (the -b option of bomsh_create_bom.py script).
And all the ELF files are automatically inserted with .bom ELF section, and all archive files are embedded with .bom entry.
All these .bom-section-embedded files are saved in /tmp/bomdir/metadata/bomsh/with_bom_files/ directory.

Notes
-----

1. This has been tested on Ubuntu20.04/AlmaLinux8/Centos8/RedHat8.

2. Most of the generated files by the scripts are put in /tmp directory by default, except the gitBOM docs are put in ${PWD}/.gitbom directory.
This is configurable. The tmp directory can be changed with the --tmpdir option. The gitbom directory can be changed with the -b/--bom_dir option.

3. The performance is not optimized for the script. The build time is roughly doubled with Bomsh for now.

4. The bomsh_hook.py and bomsh_create_bom.py scripts call git/head/ar/readelf/xxd/objcopy, make sure they are installed.

5. The bomsh_create_bom_java.py script calls git/head/diff/xxd/javap/jar/zip, make sure they are installed.

References
----------

1. Towards a GitBOM Specification : https://hackmd.io/@aeva/draft-gitbom-spec

2. [Bomsh/Bomtrace: Tools to Generate gitBOM Artifact Trees and Search CVE for Software Build](https://docs.google.com/presentation/d/14HuQ2_4kJYkDNumd7w7WgXJTOup0tp-AkCY7jtBNHjg)
