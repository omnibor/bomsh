#! /bin/env python3
# Copyright (c) 2022 Cisco and/or its affiliates.
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Bomsh hookup script to record raw info of input/output file checksums during software build.

Use by Bomsh or Bomtrace.

December 2021, Yongkui Han
"""

import argparse
import sys
import os
import subprocess
import json

# for special filename handling with shell
try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

TOOL_VERSION = '0.0.1'
VERSION = '%(prog)s ' + TOOL_VERSION

LEVEL_0 = 0
LEVEL_1 = 1
LEVEL_2 = 2
LEVEL_3 = 3
LEVEL_4 = 4

args = None

g_tmpdir = "/tmp"
g_create_bom_script = "/tmp/bomsh_create_bom.py"
g_raw_logfile = "/tmp/bomsh_hook_raw_logfile"
g_trace_logfile = "/tmp/bomsh_hook_trace_logfile"
g_logfile = "/tmp/bomsh_hook_logfile"
g_cc_compilers = ["/usr/bin/gcc", "/usr/bin/clang", "/usr/bin/cc", "/usr/bin/g++", "/usr/bin/gcc-10"]
g_cc_linkers = ["/usr/bin/ld", "/usr/bin/ld.bfd", "/usr/bin/gold"]
g_strip_progs = ["/usr/bin/strip", "/usr/bin/eu-strip"]
# list of binary converting programs of the same file
g_samefile_converters = ["/usr/bin/ranlib", "./tools/objtool/objtool", "/usr/lib/rpm/debugedit", "/usr/lib/rpm/sepdebugcrcfix",
                         "./scripts/sortextable", "./scripts/sorttable", "./tools/bpf/resolve_btfids/resolve_btfids"]
g_embed_bom_after_commands = g_cc_compilers + g_cc_linkers + ["/usr/bin/eu-strip",]
g_last_embed_outfile_checksum = ''
# a flag to skip bom-id-embedding for a shell command
g_not_embed_bom_flag = False
g_shell_cmd_rootdir = "/"

#
# Helper routines
#########################
def verbose(string, level=1, logfile=None):
    """
    Prints information to stdout depending on the verbose level.
    :param string: String to be printed
    :param level: Unsigned Integer, listing the verbose level
    :param logfile: file to write, if not provided, g_logfile is used
    """
    if args.verbose >= level:
        afile = g_logfile
        if logfile:
            afile = logfile
        if afile:
            append_text_file(afile, string + "\n")
        # also print to stdout, but be aware that it is not reliable
        # since stdout may be closed when running under BOMSH hook
        #print(string)


def write_text_file(afile, text):
    '''
    Write a string to a text file.

    :param afile: the text file to write
    '''
    with open(afile, 'w') as f:
         return f.write(text)


def append_text_file(afile, text):
    '''
    Append a string to a text file.

    :param afile: the text file to write
    '''
    with open(afile, 'a+') as f:
         return f.write(text)


def read_text_file(afile):
    '''
    Read a text file as a string.

    :param afile: the text file to read
    '''
    with open(afile, 'r') as f:
         return (f.read())


def get_shell_cmd_output(cmd):
    """
    Returns the output of the shell command "cmd".

    :param cmd: the shell command to execute
    """
    #print (cmd)
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output


# def find_specific_file_in_modification_time_order(builddir, filename):
def find_specific_file(builddir, filename):
    """
    Find all files with a specific filename in the build dir, excluding symbolic link files.
    // The search results are planned to be ordered by file modification time, but not yet.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :param filename: String, a specific filename, like libosc.so/lib4arg.so
    :returns a list that contains all the binary file names.
    """
    # findcmd = "find " + cmd_quote(builddir) + " -type f -name '" + filename + "' -exec ls -1t '{}' + || true "
    findcmd = "find " + cmd_quote(builddir) + " -type f -name '" + filename + "' -print || true "
    #print(findcmd)
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    #print(len(files))
    if len(files) > 1:
        verbose("Warning: filename: " + filename + " multiple files found: " + str(files), LEVEL_2)
    return files


def get_filetype(afile):
    """
    Returns the output of the shell command "file afile".

    :param afile: the file to check its file type
    """
    cmd = "file " + cmd_quote(afile) + " || true"
    #print (cmd)
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    res = output.strip().split(": ")
    if len(res) > 1:
        return ": ".join(res[1:])
    return "empty"


def is_archive_file(afile):
    """
    Check if a file is an archive file.

    :param afile: String, name of file to be checked
    :returns True if the file is archive file. Otherwise, return False.
    """
    return get_filetype(afile) == "current ar archive"


def is_jar_file(afile):
    """
    Check if a file is a Java archive file.

    :param afile: String, name of file to be checked
    :returns True if the file is JAR file. Otherwise, return False.
    """
    return " archive data" in get_filetype(afile)


def get_embedded_bom_id_of_archive(afile):
    '''
    Get the embedded 20bytes githash of the associated gitBOM doc for an archive file.
    :param afile: the file to extract the 20-bytes embedded .bom archive entry.
    '''
    abspath = os.path.abspath(afile)
    cmd = 'cd ' + g_tmpdir + ' ; rm -rf .bom ; ar x ' + cmd_quote(abspath) + ' .bom 2>/dev/null || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    bomfile = os.path.join(g_tmpdir, ".bom")
    if os.path.exists(bomfile):
        return get_shell_cmd_output('xxd -p ' + bomfile + ' || true').strip()
    return ''


def get_embedded_bom_id_of_jar_file(afile):
    '''
    Get the embedded 20bytes githash of the associated gitBOM doc for a .jar file.
    :param afile: the file to extract the 20-bytes embedded .bom archive entry.
    '''
    abspath = os.path.abspath(afile)
    cmd = 'cd ' + g_tmpdir + ' ; rm -rf .bom ; jar xf ' + cmd_quote(abspath) + ' .bom 2>/dev/null || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    bomfile = os.path.join(g_tmpdir, ".bom")
    if os.path.exists(bomfile):
        return get_shell_cmd_output('xxd -p ' + bomfile + ' || true').strip()
    return ''


def get_embedded_bom_id_of_elf_file(afile):
    '''
    Get the embedded 20bytes githash of the associated gitBOM doc for an ELF file.
    :param afile: the file to extract the 20-bytes embedded .bom ELF section.
    '''
    abspath = os.path.abspath(afile)
    cmd = 'readelf -x .bom ' + cmd_quote(afile) + ' 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if not output:
        return ''
    lines = output.splitlines()
    if len(lines) < 3:
        return ''
    result = []
    for line in lines:
        tokens = line.strip().split()
        if len(tokens) > 5 and tokens[0] == "0x00000000":
            result.extend( (tokens[1], tokens[2], tokens[3], tokens[4]) )
        elif len(tokens) > 2 and tokens[0] == "0x00000010":
            result.append(tokens[1])
            break
    return ''.join(result)


def get_embedded_bom_id(afile):
    '''
    Get the embedded 20bytes githash of the associated gitBOM doc for a binary file.
    :param afile: the file to extract the 20-bytes embedded .bom section.
    returns a string of 40 characters
    '''
    if is_archive_file(afile):
        return get_embedded_bom_id_of_archive(afile)
    elif is_jar_file(afile):
        return get_embedded_bom_id_of_jar_file(afile)
    else:
        return get_embedded_bom_id_of_elf_file(afile)


def load_json_db(db_file):
    """ Load the the data from a JSON file

    :param db_file: the JSON database file
    :returns a dictionary that contains the data
    """
    db = dict()
    with open(db_file, 'r') as f:
        db = json.load(f)
    return db


def save_json_db(db_file, db, indentation=4):
    """ Save the dictionary data to a JSON file

    :param db_file: the JSON database file
    :param db: the python dict struct
    :returns None
    """
    if not db:
        return
    verbose("save_json_db: db_size: " + str(len(db)) + " db_file is " + db_file, LEVEL_3)
    try:
        f = open(db_file, 'w')
    except IOError as e:
        verbose("I/O error({0}): {1}".format(e.errno, e.strerror))
        verbose("Error in save_json_db, skipping it.")
    else:
        with f:
            json.dump(db, f, indent=indentation, sort_keys=True)


############################################################
#### Start of shell command read/parse routines ####
############################################################

'''
Format of /tmp/bomsh_cmd file, which records shell command info:
pid: 75627 ppid: 75591 pgid: 73910
/home/OpenOSC/src /tmp/chroot
/usr/bin/gcc
gcc -DHAVE_CONFIG_H -I. -I.. -Wsign-compare -U_FORTIFY_SOURCE -fno-stack-protector -g -O2 -MT libopenosc_la-openosc_fortify_map.lo -MD -MP -MF .deps/libopenosc_la-openosc_fortify_map.Tpo -c openosc_fortify_map.c -fPIC -DPIC -o .libs/libopenosc_la-openosc_fortify_map.o
'''

def read_shell_command(shell_cmd_file):
    """
    Read the shell command from file and return (pwd, prog, argv_str)

    :param shell_cmd_file: the file that contains the shell command
    """
    contents = read_text_file(shell_cmd_file)
    #verbose("cmd_file: " + shell_cmd_file + " contents:\n" + contents, LEVEL_2)
    lines = contents.splitlines()
    pid = ''
    pwd = ''
    rootdir = '/'
    prog = ''
    # omitting the pid line should still work
    if lines and contents[:5] == "pid: ":
        pid = lines[0]
        lines = lines[1:]
    if lines:
        pwd = lines[0]
    if len(lines) > 1:
        prog = lines[1]
    ret = (pid, pwd, prog, '\n'.join(lines[2:]))
    verbose("cmd_file: " + shell_cmd_file + " return tuple: " + str(ret), LEVEL_2)
    return ret


############################################################
#### End of shell command read/parse routines ####
############################################################

def is_cc_compiler(prog):
    """
    Whether a program (absolute path) is C compiler.
    """
    return prog in g_cc_compilers


def is_cc_linker(prog):
    """
    Whether a program (absolute path) is C linker.
    """
    return prog in g_cc_linkers


def is_golang_prog(prog):
    """
    Whether a program (absolute path) is golang compiler/linker.
    /usr/lib/go-1.13/pkg/tool/linux_amd64/compile, /usr/lib/go-1.13/pkg/tool/linux_amd64/link
    /usr/lib/golang/pkg/tool/linux_amd64/compile, /usr/lib/golang/pkg/tool/linux_amd64/link
    """
    if "lib/go" not in prog or "pkg/tool" not in prog:
        return False
    return os.path.basename(prog) in ("compile", "link")


def get_input_files_from_subfiles(subfiles, outfile):
    """
    Returns the input files only, excluding the outfile
    :param subfiles: the list of all files, including the outfile
    :param outfile: the output file, to filter out from the subfiles
    """
    return [f for f in subfiles if f != outfile]


def get_real_path(afile, pwd):
    """
    Get the real file path, taking into account pwd and rootdir.
    :param afile: the file path, either relative path or absolute path
    :param pwd: current working directory of the shell command
    """
    if afile[0] != '/':
        afile = os.path.join(pwd, afile)
    afile = os.path.normpath(afile)
    if not afile.startswith(g_shell_cmd_rootdir):
        afile = g_shell_cmd_rootdir + afile
    return afile


'''
root@c1931bdfd4e8:/home/linux-kernel-gitdir# more arch/x86/boot/compressed/piggy.S
.section ".rodata..compressed","a",@progbits
.globl z_input_len
z_input_len = 8076046
.globl z_output_len
z_output_len = 30524908
.globl input_data, input_data_end
input_data:
.incbin "arch/x86/boot/compressed/vmlinux.bin.gz"
input_data_end:
root@c1931bdfd4e8:/home/linux-kernel-gitdir#
'''

def handle_linux_kernel_piggy_object(outfile, infiles, pwd):
    """
    Special handling on Linux kernel piggy.o build, which piggybacks compressed vmlinux in its data section.
    gcc -Wp,-MD,arch/x86/boot/compressed/.piggy.o.d -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include -I./arch/x86/include -I./arch/x86/include/generated -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -D__KERNEL__ -m64 -O2 -fno-strict-aliasing -fPIE -DDISABLE_BRANCH_PROFILING -mcmodel=small -mno-mmx -mno-sse -ffreestanding -fno-stack-protector -Wno-address-of-packed-member -D__ASSEMBLY__ -c -o arch/x86/boot/compressed/piggy.o arch/x86/boot/compressed/piggy.S
    :param outfile: the output file
    :param infiles: the list of input files
    :param pwd: the present working directory for this gcc command
    """
    #verbose("handle_linux_kernel_piggy_object pwd: " + pwd + " outfile: " + outfile + " infiles: " + str(infiles))
    if not infiles or outfile[-7:] != "piggy.o":
        return infiles
    piggy_S_file = ''
    for afile in infiles:
        if afile[-7:] == "piggy.S":
            piggy_S_file = afile
            break
    if not piggy_S_file or not os.path.isfile(piggy_S_file):
        return infiles
    lines = read_text_file(piggy_S_file).splitlines()
    vmlinux_bin = ''
    for line in lines:
        if line[:9] == '.incbin "':
            vmlinux_bin = line[9: len(line)-1]  # this is vmlinux.bin.gz or vmlinux.bin.xz or vmlinux.bin.lz4 or piggy_data
            tokens = vmlinux_bin.split(".")
            if len(tokens) > 1:
                vmlinux_bin = ".".join(tokens[:-1])
            vmlinux_bin = get_real_path(vmlinux_bin, pwd)
            break
    if vmlinux_bin and os.path.isfile(vmlinux_bin):
        return infiles + [vmlinux_bin,]  # add vmlinux.bin file to the list of input files
    return infiles


'''
root@a114722fcf1d:/home/gohello# more /tmp/go-build426453512/b001/importcfg
# import config
packagefile fmt=/tmp/go-build426453512/b002/_pkg_.a
packagefile runtime=/tmp/go-build426453512/b005/_pkg_.a
root@a114722fcf1d:/home/gohello# more /tmp/go-build819882048/b001/importcfg.link
packagefile _/home/gohello=/tmp/go-build819882048/b001/_pkg_.a
packagefile errors=/tmp/go-build819882048/b003/_pkg_.a
packagefile internal/fmtsort=/tmp/go-build819882048/b012/_pkg_.a
root@a114722fcf1d:/home/gohello#

'''

def handle_golang_importcfg(outfile, infiles, pwd):
    """
    Special handling on golang importcfg.
    /usr/lib/go-1.13/pkg/tool/linux_amd64/compile -o /tmp/go-build426453512/b001/_pkg_.a -trimpath /tmp/go-build426453512/b001=> -p main -complete -buildid ay67G1S8EmRK
Leyd8dwY/ay67G1S8EmRKLeyd8dwY -goversion go1.13.8 -D _/home/gohello -importcfg /tmp/go-build426453512/b001/importcfg -pack -c=8 /home/gohello/main.go
    /usr/lib/golang/pkg/tool/linux_amd64/link -o /tmp/go-build246437691/b001/exe/a.out -importcfg /tmp/go-build246437691/b001/importcfg.link -buildmode=exe -buildid=m01KuIh_BbmsX7huT2rC/tj8kQfHNdWp1zM6Gb7Ig/g50bYJrn9NLErZBX7dr0/m01KuIh_BbmsX7huT2rC -extld=gcc /tmp/go-build246437691/b001/_pkg_.a
    :param outfile: the output file
    :param infiles: the list of input files
    :param pwd: the present working directory for this golang command
    """
    if not infiles:
        return infiles
    importcfg_file = ''
    for afile in infiles:
        # only add it for link, not for compile, otherwise, the search_cve result is too redundant
        if afile[-14:] == "importcfg.link":
        #if afile[-9:] == "importcfg" or afile[-14:] == "importcfg.link":
            importcfg_file = afile
            break
    if not importcfg_file or not os.path.isfile(importcfg_file):
        return infiles
    lines = read_text_file(importcfg_file).splitlines()
    packages = []
    for line in lines:
        if line[:12] == 'packagefile ':
            tokens = line.split("=")
            packages.append(tokens[1])
    infiles.extend(get_real_path(packages, pwd))  # add packages to the list of infiles
    return infiles


# a list of skip tokens for some shell commands
g_cmd_skip_token_list = {
    "/usr/bin/strip": ("-F", "--target", "-I", "--input-target", "-O", "--output-target",
                       "-K", "--keep-symbol", "-N", "--strip-symbol", "-R", "--remove-section",
                       "--keep-section", "--remove-relocations"),
    "/usr/bin/eu-strip": ("-F", "-f", "-R", "--remove-section"),
    "/usr/bin/dwz": ("-m", "--multifile", "-M", "--multifile-name", "-l", "--low-mem-die-limit", "-L", "--max-die-limit"),
}

def get_all_subfiles_in_shell_cmdline(cmdline, pwd, prog):
    """
    Returns the input/output files of a generic shell command line.
    :param cmdline: the shell command line
    :param pwd: the present working directory for this shell command
    :param prog: the program binary
    """
    output_file = ''
    tokens = cmdline.split()
    outfile_token = False
    subfiles = []
    skip_token = False
    skip_token_list = []
    if prog in g_cmd_skip_token_list:
        skip_token_list = g_cmd_skip_token_list[prog]
    for token in tokens[1:]:
        if token in skip_token_list:
            # the next token must be skipped
            skip_token = True
            continue
        if skip_token:
            skip_token = False  # turn off this flag after skipping this token
            continue
        if token == '-o' or token == '--output':
            outfile_token = True
            continue
        if outfile_token:
            outfile_token = False
            output_file = get_real_path(token, pwd)
            continue
        if token[0] == '-':
            continue
        subfile = get_real_path(token, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
        else:
            verbose("Warning: this subfile is not file: " + subfile)
    return (output_file, subfiles)


def get_all_subfiles_in_gcc_cmdline(gccline, pwd, prog):
    """
    Returns the input/output files of the gcc shell command line.
    :param gccline: the gcc command line
    :param pwd: the present working directory for this gcc command
    :param prog: the program binary
    """
    if " -o " not in gccline and " -c " not in gccline:
        verbose("Warning: no output file for gcc line: " + gccline)
        return ('', [])
    tokens = gccline.split()
    if " -o " in gccline:
        oindex = tokens.index("-o")
        output_file = tokens[oindex + 1]
    else:  # must have " -c " in gcc_line
        compile_file = tokens[-1]  # let's use the last token as compile file
        tokens2 = compile_file.split(".")
        tokens2[-1] = "o"
        output_file = ".".join(tokens2)
    if output_file == "/dev/null":
        return ('', [])
    output_file = get_real_path(output_file, pwd)
    skip_token_list = set(("-MT", "-MF", "-x", "-I", "-B", "-L", "-isystem", "-iquote", "-idirafter", "-iprefix", "-isysroot", "-iwithprefix", "-iwithprefixbefore", "-imultilib", "-include"))
    linker_skip_tokens = set(("-m", "-z", "-a", "-A", "-b", "-c", "-e", "-f", "-F", "-G", "-u", "-y", "-Y", "-soname", "--wrap",
                          "--architecture", "--format", "--mri-script", "--entry", "--auxiliary", "--filter", "--gpsize", "--oformat",
                          "--defsym", "--split-by-reloc", "-rpath", "-rpath-link", "--dynamic-linker", "-dynamic-linker"))
    subfiles = []
    skip_token = False  # flag for skipping one single token
    for token in tokens[1:]:
        # C linker ld has a few more options that come with next token
        if token in skip_token_list or (is_cc_linker(prog) and token in linker_skip_tokens):
            # the next token must be skipped
            skip_token = True
            continue
        if token[0] == '-':
            continue
        if skip_token:
            skip_token = False  # turn off this flag after skipping this token
            continue
        subfile = get_real_path(token, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
        else:
            verbose("Warning: this subfile is not file: " + subfile)
    # subfiles contain both input files and the output file
    infiles = [afile for afile in subfiles if afile != output_file]
    infiles = handle_linux_kernel_piggy_object(output_file, infiles, pwd)
    return (output_file, infiles)


def get_all_subfiles_in_rustc_cmdline(gccline, pwd, prog):
    """
    Returns the input/output files of the rustc shell command line.
    :param gccline: the rustc command line
    :param pwd: the present working directory for this rustc command
    :param prog: the program binary
    """
    output_file = ''
    output_dir = ''
    crate_name = ''
    extra_filename = ''
    crate_prefix = ''
    crate_suffix = ''
    tokens = gccline.split()
    if " -o " in gccline:
        oindex = tokens.index("-o")
        output_file = get_real_path(tokens[oindex + 1], pwd)
    skip_token_list = ("-C", "-F", "-L", "-W", "-A", "-D", "--out-dir", "--target", "--explain", "--crate-type", "--crate-name", "--edition", "--emit", "--print", "--extern", "--cfg")
    subfiles = []
    skip_token = False  # flag for skipping one single token
    skip_token_type = ''
    for token in tokens[1:]:
        if token in skip_token_list:
            # the next token must be skipped
            skip_token = True
            skip_token_type = token
            continue
        if skip_token:
            skip_token = False  # turn off this flag after skipping this token
            if skip_token_type == "--crate-name":
                crate_name = token
            elif skip_token_type == "--out-dir":
                output_dir = token
            elif skip_token_type == "--crate-type":
                if token == "lib":
                    crate_prefix = "lib"
                    crate_suffix = ".rlib"
                elif token == "cdylib":
                    crate_prefix = "lib"
                    crate_suffix = ".so"
            elif token[:15] == "extra-filename=":
                extra_filename = token[15:]
            continue
        if token[0] == '-':
            continue
        subfile = get_real_path(token, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
        else:
            verbose("Warning: this subfile is not file: " + subfile)
    # subfiles contain both input files and the output file
    if crate_name:
        if not output_dir:
            output_dir = pwd
        output_dir = get_real_path(output_dir, pwd)
        output_file = os.path.join(output_dir, crate_prefix + crate_name + extra_filename + crate_suffix)
    elif len(subfiles) == 1 and not output_file:
        output_file = subfiles[0].rstrip(".rs")
    infiles = [afile for afile in subfiles if afile != output_file]
    #verbose("rustc subfiles: " + str(subfiles) + " outfile: " + output_file)
    return (output_file, infiles)


def get_all_subfiles_in_golang_cmdline(gccline, pwd, prog):
    """
    Returns the input/output files of the golang compile/link shell command line.
    :param gccline: the golang command line
    :param pwd: the present working directory for this golang command
    :param prog: the program binary
    """
    if " -o " not in gccline:
        verbose("Warning: no output file for golang line: " + gccline)
        return ('', [])
    tokens = gccline.split()
    oindex = tokens.index("-o")
    output_file = get_real_path(tokens[oindex + 1], pwd)
    skip_token_list = ("-D", "-goversion", "-p", "-buildid", "-trimpath")
    subfiles = []
    skip_token = False  # flag for skipping one single token
    skip_token_type = ''
    for token in tokens[1:]:
        if token in skip_token_list:
            # the next token must be skipped
            skip_token = True
            skip_token_type = token
            continue
        if skip_token:
            skip_token = False  # turn off this flag after skipping this token
            if skip_token_type == "-D" and token[0] == '-': # this means -D option is empty, which needs special handling
                # need to check if this token is a skip_token
                if token in skip_token_list:
                    # the next token must be skipped
                    skip_token = True
                    skip_token_type = token
                    continue
            # normal continue case
            continue
        if token[0] == '-':
            continue
        subfile = get_real_path(token, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
        else:
            verbose("Warning: this subfile is not file: " + subfile)
    # subfiles contain both input files and the output file
    infiles = [afile for afile in subfiles if afile != output_file]
    infiles = handle_golang_importcfg(output_file, infiles, pwd)
    return (output_file, infiles)


def get_all_subfiles_in_ar_cmdline(arline, pwd):
    """
    Returns the input/output files of the ar shell command line.
    :param arline: the ar command line
    :param pwd: the present working directory for this ar command
    """
    tokens = arline.split()
    if len(tokens) < 3:
        return ('', [])
    output_file = get_real_path(tokens[2], pwd)
    subfiles = []
    for token in tokens[3:]:
        subfile = get_real_path(token, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
    return (output_file, subfiles)


############################################################
#### End of gcc command read/parse routines ####
############################################################

def get_git_file_hash(afile):
    '''
    Get the git object hash value of a file.
    :param afile: the file to calculate the git hash or digest.
    '''
    cmd = 'git hash-object ' + cmd_quote(afile) + ' || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    #verbose("output of git_hash:\n" + output, LEVEL_3)
    if output:
        return output.strip()
    return ''


def get_noroot_path(afile):
    '''
    Get the path without rootdir prefix.
    :param afile: the file path to simplify
    '''
    if g_shell_cmd_rootdir != "/" and afile.startswith(g_shell_cmd_rootdir):
        return afile[len(g_shell_cmd_rootdir):]
    return afile


# save githash of header files in a cache file for performance
g_githash_cache_file = os.path.join(g_tmpdir, "bomsh_hook_githash_file")
g_githash_cache = {}
g_githash_cache_initial_size = 0
# the below ld linker implicit object files are also cached
g_githash_link_objects_list = ("crtbeginS.o", "crtendS.o", "liblto_plugin.so", "Scrt1.o", "crti.o", "crtn.o")

def get_git_file_hash_with_cache(afile):
    '''
    Check the githash cache before calling "git hash-object".
    Also update the githash cache after calling "git hash-object".
    :param afile: the file to get git-hash
    '''
    if g_githash_cache and afile in g_githash_cache:
        return g_githash_cache[afile]
    ahash = get_git_file_hash(afile)
    if not args.no_githash_cache_file and afile[-2:] == ".h" or os.path.basename(afile) in g_githash_link_objects_list:
        # only cache header files or the ld linker implicit object files
        verbose("Saving header githash cache, hash: " + ahash + " afile: " + afile, LEVEL_3)
        g_githash_cache[afile] = ahash
    return ahash


def record_raw_info(outfile, infiles, pwd, argv_str, pid='', outfile_checksum='', ignore_this_record=False):
    '''
    Record the raw info for a list of infiles and outfile

    :param outfile: the output file
    :param infiles: a list of input files
    :param pwd: present working directory of the shell command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    :param outfile_checksum: the checksum of the output file
    :param ignore_this_record: info only, ignore this record for create_bom processing
    '''
    # infiles can be empty, but outfile must not be empty
    if not outfile:
        return
    if not args.no_githash_cache_file:
        global g_githash_cache
        global g_githash_cache_initial_size
        if len(infiles) > 1 and not g_githash_cache and os.path.exists(g_githash_cache_file):
            g_githash_cache = load_json_db(g_githash_cache_file)
            g_githash_cache_initial_size = len(g_githash_cache)
            verbose("load_json_db githash cache db, initial_size: " + str(g_githash_cache_initial_size), LEVEL_3)
    if not outfile_checksum:
        outfile_checksum = get_git_file_hash(outfile)
    bomid = ''
    if args.record_raw_bomid:
        bomid = get_embedded_bom_id(outfile)
    if bomid:
        lines = ["\noutfile: " + outfile_checksum + " path: " + get_noroot_path(outfile) + " bomid: " + bomid,]
    else:
        lines = ["\noutfile: " + outfile_checksum + " path: " + get_noroot_path(outfile),]
    for infile in infiles:
        bomid = ''
        if args.record_raw_bomid:
            bomid = get_embedded_bom_id(infile)
        if bomid:
            lines.append("infile: " + get_git_file_hash_with_cache(infile) + " path: " + get_noroot_path(infile) + " bomid: " + bomid)
        else:
            lines.append("infile: " + get_git_file_hash_with_cache(infile) + " path: " + get_noroot_path(infile))
    #lines.append("working_dir: " + pwd)
    if pid:
        if args.pre_exec:
            lines.append("PID: " + pid + " pre_exec")
        else:
            lines.append("PID: " + pid + " post_exec")
    if ignore_this_record:
        lines.append("ignore_this_record: information only")
    lines.append("build_cmd: " + argv_str)
    if pid:
        lines.append("==== End of raw info for PID " + pid + " process\n\n")
    else:
        lines.append("==== End of raw info for this process\n\n")
    outstr = '\n'.join(lines)
    append_text_file(g_raw_logfile, outstr)

############################################################
#### End of hash/checksum routines ####
############################################################

def does_c_file_exist_in_files(infiles):
    '''
    Does the list of files contain C/C++ source code files.
    :param infiles: a list of input files
    '''
    for afile in infiles:
        if afile[-2:] == ".c" or afile[-4:] == ".cpp":
            return True
    return False


def read_depend_file(depend_file, pwd):
    '''
    Read all the depend files from gcc "-MD -MF" generated depend.d file
    :param depend_file: the generated dependency file
    :param pwd: the working directory for the gcc command
    '''
    if not os.path.exists(depend_file):
        return ('', [])
    contents = read_text_file(depend_file)
    all_parts = contents.split("\n\n")  # get the first part only, due to -MP option.
    all_files = all_parts[0].split(": ")
    outfile = get_real_path(all_files[0].strip(), pwd)
    afiles = all_files[1].strip()
    afiles = ' '.join(afiles.split("\\\n"))  # each continuation line by "\\\n"
    afiles = afiles.split()
    depend_files = [get_real_path(afile, pwd) for afile in afiles]
    return (outfile, depend_files)


def replace_output_file_in_shell_command(gcc_cmd, outfile):
    '''
    Try to replace the -o output file for the gcc shell command.
    :param gcc_cmd: the gcc compile command
    :param outfile: the new output file
    '''
    if " -o " in gcc_cmd:
        tokens = gcc_cmd.split()
        oindex = tokens.index("-o")
        output_file = tokens[oindex + 1]
        if outfile:
            tokens[oindex + 1] = outfile
        else:
            tokens[oindex + 1] = output_file + ".bomsh_hook.o"
        return ' '.join(tokens)
    else:
        return gcc_cmd


def escape_shell_command(gcc_cmd):
    '''
    Try to escape some characters for the shell command to run successfully.
    '''
    for c in ('(', ')', '"'):
        if c in gcc_cmd:
            gcc_cmd = gcc_cmd.replace(c, '\\' + c)
    return gcc_cmd


def get_c_file_depend_files(gcc_cmd, pwd):
    '''
    Get all the depend files for a gcc command which compiles C source code file
    We add "-MD -MF /tmp/bomsh_target.d" to the gcc command
    :param gcc_cmd: the gcc compile command
    :param pwd: the working directory for the gcc command
    '''
    depends = ('', [])
    if " -MF " in gcc_cmd:
        tokens = gcc_cmd.split()
        for i in range(len(tokens)):
            if tokens[i] == "-MF":
                depend_file = get_real_path(tokens[i+1], pwd)
                return read_depend_file(depend_file, pwd)
        return depends
    if " -Wp,-MD," in gcc_cmd or " -Wp,-MMD," in gcc_cmd:
        tokens = gcc_cmd.split()
        for token in tokens:
            if token.startswith("-Wp,-MD,") or token.startswith("-Wp,-MMD,"):
                tokens2 = token.split(",")
                depend_file = get_real_path(tokens2[-1], pwd)
                #verbose("Wp,MMD token: " + token + " depend_file: " + depend_file)
                return read_depend_file(depend_file, pwd)
        return depends
    output_file = os.path.join(g_tmpdir, "bomsh_hook_cc_outfile.o")
    gcc_cmd = replace_output_file_in_shell_command(gcc_cmd, output_file)
    depend_file = os.path.join(g_tmpdir, "bomsh_hook_target_dependency.d")
    if g_shell_cmd_rootdir != "/":
        chroot_pwd = pwd
        if pwd.startswith(g_shell_cmd_rootdir):
            chroot_pwd = pwd[len(g_shell_cmd_rootdir):]
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' sh -c "cd ' + chroot_pwd + " ; " + escape_shell_command(gcc_cmd) + " -MD -MF " + depend_file + '" || true'
    else:
        cmd = "cd " + pwd + " ; " + escape_shell_command(gcc_cmd) + " -MD -MF " + depend_file + " || true"
    #verbose("get_c_depend cmd: " + cmd)
    get_shell_cmd_output(cmd)
    real_depend_file = get_real_path(depend_file, pwd)
    if os.path.exists(real_depend_file):
        depends = read_depend_file(real_depend_file, pwd)
        os.remove(real_depend_file)
    real_output_file = get_real_path(output_file, pwd)
    if os.path.exists(real_output_file):
        os.remove(real_output_file)
    return depends


def check_if_ignore_this_record(prog, outfile_checksum):
    '''
    Check if this shell command is redundant, thus no need to record, or record for information only
    One such example is the cc command which invokes ld, and we do embed_bom for ld.
    :param prog: the program binary
    :param outfile_checksum: the checksum of the output file of this shell command
    '''
    # find out if outfile is same as last embed_bom command's outfile
    if g_last_embed_outfile_checksum == outfile_checksum:
        return True
    return False


def process_gcc_command(prog, pwddir, argv_str):
    '''
    Process the gcc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    #gcc_logfile = os.path.join(g_tmpdir, "bomsh_hook_gcc_logfile")
    #verbose("\npwd: " + pwddir + " Found one gcc command: " + argv_str, LEVEL_0, gcc_logfile)
    (outfile, infiles) = get_all_subfiles_in_gcc_cmdline(argv_str, pwddir, prog)
    verbose("get_all_subfiles_in_gcc_cmdline, outfile: " + outfile + " infiles: " + str(infiles), LEVEL_4)
    infiles2 = []
    # for C source code file, we can try add the C header file dependency
    if not args.no_dependent_headers and does_c_file_exist_in_files(infiles):
        (outfile2, infiles2) = get_c_file_depend_files(argv_str, pwddir)
        verbose("get_c_depend_files, outfile2: " + outfile2 + " infiles2: " + str(infiles2), LEVEL_4)
    if infiles2:
        infiles = infiles2
    verbose("get_all_subfiles, outfile: " + outfile + " infiles: " + str(infiles), LEVEL_3)
    if not infiles:  # if infiles is empty, no need to record info for this gcc cmd
        return ''
    checksum = get_git_file_hash(outfile)
    if g_last_embed_outfile_checksum and g_last_embed_outfile_checksum == checksum:
        verbose("ignore_this_record, it is redundant for bom-id-embedding because it invokes ld command")
        # also set not_embed_bom_flag to skip bom_id-embedding for this gcc command
        global g_not_embed_bom_flag
        g_not_embed_bom_flag = True
        record_raw_info(outfile, infiles, pwddir, argv_str, outfile_checksum=checksum, ignore_this_record=True)
    else:
        record_raw_info(outfile, infiles, pwddir, argv_str, outfile_checksum=checksum)
    return outfile


def process_ld_command(prog, pwddir, argv_str):
    '''
    Process the ld command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    #ld_logfile = os.path.join(g_tmpdir, "bomsh_hook_gcc_logfile")
    #verbose("\npwd: " + pwddir + " Found one ld command: " + argv_str, LEVEL_0, ld_logfile)
    # ld command can be handled the same way as gcc command, for outfile,infiles
    (outfile, infiles) = get_all_subfiles_in_gcc_cmdline(argv_str, pwddir, prog)
    if not infiles:  # if infiles is empty, no need to record info for this ld cmd
        return ''
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_rustc_command(prog, pwddir, argv_str):
    '''
    Process the rustc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    #rustc_logfile = os.path.join(g_tmpdir, "bomsh_hook_gcc_logfile")
    #verbose("\npwd: " + pwddir + " Found one rustc command: " + argv_str, LEVEL_0, rustc_logfile)
    (outfile, infiles) = get_all_subfiles_in_rustc_cmdline(argv_str, pwddir, prog)
    if not infiles:  # if infiles is empty, no need to record info for this rustc cmd
        return ''
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_golang_command(prog, pwddir, argv_str):
    '''
    Process the golang compile/link command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    #golang_logfile = os.path.join(g_tmpdir, "bomsh_hook_gcc_logfile")
    #verbose("\npwd: " + pwddir + " Found one golang compile/link command: " + argv_str, LEVEL_0, golang_logfile)
    # golang link command can be handled the same way as golang compile command, for outfile,infiles
    (outfile, infiles) = get_all_subfiles_in_golang_cmdline(argv_str, pwddir, prog)
    if not infiles:  # if infiles is empty, no need to record info for this golang cmd
        return ''
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_generic_shell_command(prog, pwddir, argv_str, pid):
    '''
    Process a generic shell command like strip/eu-strip/dwz
    strip --strip-debug -o drivers/firmware/efi/libstub/x86-stub.stub.o drivers/firmware/efi/libstub/x86-stub.o
    dwz -mdebian/libssl1.1/usr/lib/debug/.dwz/x86_64-linux-gnu/libssl1.1.debug -- debian/libcrypto1.1-udeb/usr/lib/libcrypto.so.1.1 debian/libssl1.1/usr/lib/x86_64-linux-gnu/libssl.so.1.1
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command, this is a str, not integer
    '''
    (outfile, infiles) = get_all_subfiles_in_shell_cmdline(argv_str, pwddir, prog)
    verbose(prog + " outfile: " + outfile + " infiles: " + str(infiles), LEVEL_3)
    if not infiles:  # if infiles is empty, no need to record info for this cmd
        return ''
    if outfile and outfile != infiles[0]:
        if args.pre_exec:
            # no need to record info for pre-exec mode
            return ''
        # outfile is different from infile, record info for post-exec mode only
        record_raw_info(outfile, infiles, pwddir, argv_str)
        return outfile
    # there is no outfile or outfile is same as infile, record info for both pre-exec and post-exec mode.
    for infile in infiles:
        record_raw_info(infile, [], pwddir, argv_str, pid)
    return outfile


def shell_command_record_same_file(prog, pwddir, argv_str, pid, cmdname):
    '''
    The shell command update the single file, like objtool/strip/ranlib. the last token must the file to update.
    '''
    tokens = argv_str.split()
    outfile = get_real_path(tokens[-1], pwddir)
    if not os.path.isfile(outfile):
        verbose("outfile " + outfile + " is not a file, ignore this command", LEVEL_0)
        return ''
    record_raw_info(outfile, [], pwddir, argv_str, pid)
    return outfile


def process_samefile_converter_command(prog, pwddir, argv_str, pid):
    '''
    Process the samefile converter command like strip/ranlib, etc.
    For example, the below commands in Linux kernel build or rpm build.
    ./tools/objtool/objtool orc generate --no-fp --retpoline kernel/fork.o
    ./scripts/sortextable vmlinux
    ./scripts/sorttable vmlinux
    ./tools/bpf/resolve_btfids/resolve_btfids vmlinux
    /usr/lib/rpm/sepdebugcrcfix usr/lib/debug .//usr/lib64/libopenosc.so.0.0.0
    /usr/lib/rpm/debugedit -b /home/OpenOSC/rpmbuild/BUILD/openosc-1.0.5 -d /usr/src/debug/openosc-1.0.5-1.el8.x86_64 -i --build-id-seed=1.0.5-1.el8 -l /home/OpenOSC/rpmbuild/BUILD/openosc-1.0.5/debugsources.list /home/OpenOSC/rpmbuild/BUILDROOT/openosc-1.0.5-1.el8.x86_64/usr/lib64/libopenosc.so.0.0.0

    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command, this is a str, not integer
    '''
    cmdname = os.path.basename(prog)
    verbose("\npwd: " + pwddir + " Found one " + cmdname + " command: " + argv_str)
    outfile = shell_command_record_same_file(prog, pwddir, argv_str, pid, cmdname)
    return outfile


def process_install_command(prog, pwddir, argv_str):
    '''
    Process the install command.
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    verbose("\npwd: " + pwddir + " Found one install command: " + argv_str)
    tokens = argv_str.split()
    if len(tokens) < 3 or tokens[-2][0] == '-':
        verbose("Warning: not yet interested in this install command with the same input/output file", LEVEL_0)
        return ''
    outfile = get_real_path(tokens[-1], pwddir)
    infile = get_real_path(tokens[-2], pwddir)
    if not os.path.isfile(infile):
        verbose("Warning: install command's infile not a file: " + infile, LEVEL_0)
        return ''
    if not os.path.isfile(outfile):
        verbose("Warning: not yet interested in this install command with the output file is probably a directory", LEVEL_0)
        return ''
    infiles = [infile,]
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_objcopy_command(prog, pwddir, argv_str, pid):
    '''
    Process the objcopy command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    verbose("\npwd: " + pwddir + " Found one objcopy command: " + argv_str)
    tokens = argv_str.split()
    if len(tokens) < 3:
        verbose("Warning: not yet interested in this short objcopy command", LEVEL_0)
        return ''
    if tokens[-2][0] == '-' or "=" in tokens[-2]:
        # the input and output file are the same file
        return shell_command_record_same_file(prog, pwddir, argv_str, pid, "objcopy")
    # the input and output file are not the same file
    outfile = get_real_path(tokens[-1], pwddir)
    infile = get_real_path(tokens[-2], pwddir)
    if not os.path.isfile(infile):
        verbose("Warning: this infile is not a file: " + infile, LEVEL_0)
        return outfile
    if infile == outfile:
        # the input and output file are the same file, this is possible for "make rpm" of OpenOSC
        shell_command_record_same_file(prog, pwddir, argv_str, pid, "objcopy")
        return outfile
    if not args.pre_exec:  # different input/output file, record only if post_exec
        infiles = [infile,]
        record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_bzImage_build_command(prog, pwddir, argv_str):
    '''
    Process the bzImage build command in Linux kernel build.
    arch/x86/boot/tools/build arch/x86/boot/setup.bin arch/x86/boot/vmlinux.bin arch/x86/boot/zoffset.h arch/x86/boot/bzImage
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    verbose("\npwd: " + pwddir + " Found one bzImage build command: " + argv_str)
    tokens = argv_str.split()
    if len(tokens) < 5:
        verbose("Warning: not well-formated bzImage build command", LEVEL_0)
        return ''
    outfile = get_real_path(tokens[-1], pwddir)
    infiles = tokens[1 : len(tokens)-1]
    infiles = [get_real_path(afile, pwddir) for afile in infiles]
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_ar_command(prog, pwddir, argv_str):
    '''
    Process the gcc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    verbose("\npwd: " + pwddir + " Found one ar command: " + argv_str)
    (outfile, infiles) = get_all_subfiles_in_ar_cmdline(argv_str, pwddir)
    if infiles:  # if empty infiles, no need to record
        record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


# found out that java compiler like maven can compile .java to .class in memory without creating new process
# so this javac process hookup will not work, same reason for jar command hookup.
def process_javac_command(prog, pwddir, argv_str):
    '''
    Process the javac command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    verbose("\npwd: " + pwddir + " Found one javac command: " + argv_str)
    if ".java " not in argv_str and argv_str[-5:] != ".java":
        verbose("Warning: no input .java file for javac line: " + argv_str)
        return
    tokens = argv_str.split()
    for token in tokens:
        if token[-5:] == ".java":
            java_file = token
            outfile = token[:-5] + ".class"
            break
    java_file = get_real_path(java_file, pwddir)
    outfile = get_real_path(outfile, pwddir)
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_jar_command(prog, pwddir, argv_str):
    '''
    Process the jar command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    verbose("\npwd: " + pwddir + " Found one jar command: " + argv_str)
    # jar command is exactly like ar command
    (outfile, infiles) = get_all_subfiles_in_ar_cmdline(argv_str, pwddir)
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def find_bom_outfile_in_bomdir(outfile, bomdir):
    '''
    Try to find the .bom-embedded outfile in the bomdir
    :param outfile: the output file of the shell command
    :param bomdir: the directory to find the bom-embedded outfile
    '''
    if not os.path.exists(outfile):
        return ''
    checksum = get_git_file_hash(outfile)
    afiles = find_specific_file(bomdir, checksum + "*" + os.path.basename(outfile))
    # afiles = find_specific_file_in_modification_time_order(bomdir, checksum + "*" + os.path.basename(outfile))
    if not afiles:
        return ''
    if len(afiles) > 1:
        verbose("Warning: multiple with_bom files found: " + str(afiles));
    return afiles[0]


def embed_bom_after_cmd(prog, pwddir, argv_str, outfile):
    '''
    Embed .bom section into outfile and overwrite original outfile
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param outfile: the output file of the shell command
    returns True if embedding is successful, otherwise False.
    '''
    if not outfile or not os.path.exists(outfile):
        return
    # Use /tmp/embed_bomdir instead of the default ${PWD}/.gitbom directory as gitBOM repo dir
    bomdir = os.path.join(g_tmpdir, "embed_bomdir")
    lseek_lines_file = os.path.join(g_tmpdir, "bomsh_hook_lseek_lines")
    # Invoke the bomsh_create_bom script to generate hash-tree and gitBOM docs
    cmd = g_create_bom_script + ' --embed_bom_section -r ' + cmd_quote(g_raw_logfile) + ' --tmpdir ' + g_tmpdir + ' -b ' + bomdir + ' --lseek_lines_file ' + lseek_lines_file + ' || true'
    #cmd = g_create_bom_script + ' --new_gitbom_doc_for_unary_transform -r ' + cmd_quote(g_raw_logfile) + ' --tmpdir ' + g_tmpdir + ' -b ' + bomdir + ' --lseek_lines_file ' + lseek_lines_file + ' || true'
    get_shell_cmd_output(cmd)
    # find the bom-embedded outfile in bomdir
    with_bom_dir = os.path.join(bomdir, "metadata", "bomsh", "with_bom_files")
    embed_outfile = find_bom_outfile_in_bomdir(outfile, with_bom_dir)
    if not embed_outfile:
        return
    # record this operation as a binary converting command. This is required in order to create hash-tree from bomsh_hook_raw_logfile later.
    checksum = get_git_file_hash(embed_outfile)
    infiles = [outfile,]
    record_raw_info(embed_outfile, infiles, pwddir, "embed_bom_after_cmd for " + outfile + " orig_build_cmd: " + argv_str, outfile_checksum=checksum)
    # overwrite the outfile and keep a copy of the original outfile
    embed_outfile_orig = embed_outfile + ".orig"
    os.system("cp " + outfile + " " + embed_outfile_orig + " ; cp " + embed_outfile + " " + outfile)
    verbose("After " + prog + " command, overwrite with bom-embedded outfile: " + outfile)
    afile = os.path.join(g_tmpdir, "bomsh_hook_embed_bom_file")
    write_text_file(afile, checksum)
    #verbose("embed_bom_after_cmd, writing embed_outfile_checksum: " + checksum + " to file: " + afile)


def read_hook_embed_bom_file():
    '''
    Read the saved outfile checksum from the hook_embed_bom_file
    '''
    afile = os.path.join(g_tmpdir, "bomsh_hook_embed_bom_file")
    if not os.path.exists(afile):
        return ''
    return read_text_file(afile).strip()


def process_shell_command(prog, pwd_str, argv_str, pid_str):
    '''
    Process the shell command that we are interested in.
    :param prog: the program binary
    :param pwd_str: the line of present working directory for the command, it can optionally contain rootdir after pwd
    :param argv_str: the full command with all its command line options/parameters
    :param pid_str: the string with process ID, in format of "PID: pid XXX YYY"
    '''
    pid = ''
    tokens = pid_str.split()
    if len(tokens) > 1:
        pid = tokens[1]
    tokens = pwd_str.split()
    pwddir = tokens[0]
    # pwd line can optionally add the rootdir of the shell command
    global g_shell_cmd_rootdir
    if len(tokens) > 1:
        g_shell_cmd_rootdir = tokens[1]
    if args.pre_exec:
        verbose("pre_exec run")
    global g_last_embed_outfile_checksum
    if g_embed_bom_after_commands and prog in g_embed_bom_after_commands:
        # read saved embed_outfile_checksum to later check if this shell command is redundant command
        g_last_embed_outfile_checksum = read_hook_embed_bom_file()
    # Process the shell command, to record the raw info
    if is_cc_compiler(prog):
        outfile = process_gcc_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/ar":
        outfile = process_ar_command(prog, pwddir, argv_str)
    elif is_cc_linker(prog):
        outfile = process_ld_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/objcopy":
        outfile = process_objcopy_command(prog, pwddir, argv_str, pid)
    elif prog == "arch/x86/boot/tools/build":
        outfile = process_bzImage_build_command(prog, pwddir, argv_str)
    elif prog in g_strip_progs or prog == "/usr/bin/dwz":
        outfile = process_generic_shell_command(prog, pwddir, argv_str, pid)
    elif prog in g_samefile_converters:
        outfile = process_samefile_converter_command(prog, pwddir, argv_str, pid)
    elif prog == "/usr/bin/install":
        outfile = process_install_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/rustc":
        outfile = process_rustc_command(prog, pwddir, argv_str)
    elif prog == "bomsh_openat_file":
        outfile = process_samefile_converter_command(prog, pwddir, argv_str, pid)
    elif prog == "/usr/bin/javac":
        outfile = process_javac_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/jar":
        outfile = process_jar_command(prog, pwddir, argv_str)
    elif is_golang_prog(prog):
        outfile = process_golang_command(prog, pwddir, argv_str)
    # if user wants to embed .bom into binaries for some commands
    if not g_not_embed_bom_flag and not args.pre_exec and prog in g_embed_bom_after_commands:
        # only if this command is not redundant, not pre-exec mode
        embed_bom_after_cmd(prog, pwddir, argv_str, outfile)
    # try to save the githash_cache file
    if not args.no_githash_cache_file and g_githash_cache:
        if len(g_githash_cache) > 1 and len(g_githash_cache) > g_githash_cache_initial_size:
            save_json_db(g_githash_cache_file, g_githash_cache)


############################################################
#### End of shell command handling routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool parses the command and records raw info of input/output file checksums")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-s', '--shell_cmd_file',
                    help = "the shell command file to analyze the command")
    parser.add_argument('-r', '--raw_logfile',
                    help = "the raw log file, to store input/output file checksums")
    parser.add_argument('-l', '--logfile',
                    help = "the log file, must be absolute path, not relative path")
    parser.add_argument('-w', '--watched_programs',
                    help = "the comma-separated list of programs to watch")
    parser.add_argument('--watched_pre_exec_programs',
                    help = "the comma-separated list of pre_exec programs to watch")
    parser.add_argument('-t', '--trace_logfile',
                    help = "the verbose trace log file")
    parser.add_argument('--create_bom_script',
                    help = "the bomsh_create_bom script file")
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('--cc_compilers',
                    help = "the comma-separated C compiler paths, like /usr/bin/gcc,/usr/bin/clang")
    parser.add_argument('--cc_linkers',
                    help = "the comma-separated C linker paths, like /usr/bin/ld,/usr/bin/llvm-ld")
    parser.add_argument("--embed_bom_after_commands",
                    help = "embed .bom ELF section after a command on an ELF binary, which is a list of comma-separated programs")
    parser.add_argument("--pre_exec",
                    action = "store_true",
                    help = "pre-exec mode, invoked before executing the process")
    parser.add_argument("-n", "--no_auto_embed_bom_for_compiler_linker",
                    action = "store_true",
                    help = "not automatically embed bom-id to ELF binary for cc/ld commands")
    parser.add_argument("--no_dependent_headers",
                    action = "store_true",
                    help = "not include C header files for hash tree dependency")
    parser.add_argument("--record_raw_bomid",
                    action = "store_true",
                    help = "record raw info for bom_id of input/output files if it exists")
    parser.add_argument("--no_githash_cache_file",
                    action = "store_true",
                    help = "not use a helper cache file to store githash of header files")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.shell_cmd_file):
        print ("Please specify the shell command file with -s option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_create_bom_script
    if args.create_bom_script:
        g_create_bom_script = args.create_bom_script
    global g_logfile
    global g_trace_logfile
    global g_raw_logfile
    global g_tmpdir
    if args.tmpdir:
        g_tmpdir = args.tmpdir
        g_logfile = os.path.join(g_tmpdir, "bomsh_hook_logfile")
        g_trace_logfile = os.path.join(g_tmpdir, "bomsh_hook_trace_logfile")
        g_raw_logfile = os.path.join(g_tmpdir, "bomsh_hook_raw_logfile")
    if args.logfile:
        g_logfile = args.logfile
    if args.trace_logfile:
        g_trace_logfile = args.trace_logfile
    if args.raw_logfile:
        g_raw_logfile = args.raw_logfile
    if args.no_auto_embed_bom_for_compiler_linker:
        g_embed_bom_after_commands.clear()
    if args.embed_bom_after_commands:
        g_embed_bom_after_commands.extend(args.embed_bom_after_commands.split(","))
    if args.cc_compilers:
        g_cc_compilers.extend(args.cc_compilers.split(","))
    if args.cc_linkers:
        g_cc_linkers.extend(args.cc_linkers.split(","))

    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    verbose("\n==== BOM-HOOK PID: " + str(os.getpid()) + " started ====", LEVEL_0)

    (pid, pwddir, prog, argv_str) = read_shell_command(args.shell_cmd_file)
    # always record the shell command in trace_logfile for normal post_exec mode
    if not args.pre_exec:
        append_text_file(g_trace_logfile, ' '.join((pid, pwddir, prog, argv_str, '\n')))

    if args.pre_exec:
        # Fewer number of programs to watch in pre_exec mode
        progs_to_watch = g_samefile_converters + g_strip_progs + ["/usr/bin/objcopy", "/usr/bin/dwz", "bomsh_openat_file"]
        if args.watched_pre_exec_programs:
            progs_to_watch.extend(args.watched_pre_exec_programs.split(","))
    else:
        progs_to_watch = g_cc_compilers + g_cc_linkers + g_samefile_converters + g_strip_progs + ["/usr/bin/ar", "/usr/bin/objcopy", "arch/x86/boot/tools/build",
                     "/usr/bin/rustc", "/usr/bin/dwz", "bomsh_openat_file", "/usr/bin/javac", "/usr/bin/jar"]
        if args.watched_programs:
            progs_to_watch.extend(args.watched_programs.split(","))
    if prog in progs_to_watch:
        verbose(prog + " is on the list, processing the command...", LEVEL_0)
        process_shell_command(prog, pwddir, argv_str, pid)
    else:
        if args.pre_exec:
            verbose(prog + " is not on the pre-exec list, we are done", LEVEL_0)
        else:
            verbose(prog + " is not on the list, we are done", LEVEL_0)
    verbose("==== BOM-HOOK PID: " + str(os.getpid()) + " exited ====", LEVEL_0)


if __name__ == '__main__':
    main()
