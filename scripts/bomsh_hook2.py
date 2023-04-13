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
import yaml

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
g_bomdir = os.path.join(os.getcwd(), ".omnibor")
g_raw_logfile = "/tmp/bomsh_hook_raw_logfile"
g_trace_logfile = "/tmp/bomsh_hook_trace_logfile"
g_logfile = "/tmp/bomsh_hook_logfile"
g_cc_compilers = ["/usr/bin/gcc", "/usr/bin/clang", "/usr/bin/g++", "/usr/bin/cc"]
g_cc_linkers = ["/usr/bin/ld", "/usr/bin/ld.bfd", "/usr/bin/ld.gold", "/usr/bin/ld.lld", "/usr/bin/gold"]
g_strip_progs = ["/usr/bin/strip", "/usr/bin/eu-strip"]
# list of binary converting programs of the same file
g_samefile_converters = ["/usr/bin/ranlib", "./tools/objtool/objtool", "/usr/lib/rpm/debugedit",
                         "./scripts/sortextable", "./scripts/sorttable", "./tools/bpf/resolve_btfids/resolve_btfids"]
g_embed_bom_after_commands = g_cc_compilers + g_cc_linkers + ["/usr/bin/eu-strip",]
#g_embed_bom_after_commands = g_cc_compilers + g_cc_linkers + ["/usr/bin/eu-strip", "/usr/bin/ar"]
g_hashtypes = []
g_shell_cmd_rootdir = "/"
g_cve_check_rules = None

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


def write_binary_file(afile, barray):
    '''
    Write a string to a text file.

    :param afile: the binary file to write
    :param barray: the byte array to write
    '''
    with open(afile, 'wb') as f:
         return f.write(barray)


def get_shell_cmd_output(cmd):
    """
    Returns the output of the shell command "cmd".

    :param cmd: the shell command to execute
    """
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    return output


def find_all_regular_files(builddir):
    """
    Find all regular files in the build dir, excluding symbolic link files.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :returns a list that contains all the regular file names.
    """
    #verbose("entering find_all_regular_files: the build dir is " + builddir, LEVEL_4)
    builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' -type f -print || true '
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    return files


def find_specific_file(builddir, filename, maxdepth=0):
    """
    Find all files with a specific filename in the build dir, excluding symbolic link files.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :param filename: String, a specific filename, like libosc.so/lib4arg.so
    :param maxdepth: Integer, Descend at most levels (a non-negative integer) levels of directories below the command line arguments
    :returns a list that contains all the binary file names.
    """
    if maxdepth:
        findcmd = "find " + cmd_quote(builddir) + " -maxdepth " + str(maxdepth) + " -type f -name '" + filename + "' -print 2>/dev/null || true "
    else:
        findcmd = "find " + cmd_quote(builddir) + " -type f -name '" + filename + "' -print 2>/dev/null || true "
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    return files


def get_embedded_bom_id_of_elf_file(afile, hash_alg):
    '''
    Get the embedded 20 or 32 bytes githash of the associated OmniBOR doc for an ELF file.
    :param afile: the file to extract the embedded .note.omnibor ELF section.
    :param hash_alg: the hashing algorithm, sha1 or sha256
    '''
    abspath = os.path.abspath(afile)
    cmd = 'readelf -x .note.omnibor ' + cmd_quote(afile) + ' 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if not output:
        return ''
    lines = output.splitlines()
    if len(lines) < 4:
        return ''
    result = []
    for line in lines:
        tokens = line.strip().split()
        len_tokens = len(tokens)
        if len_tokens < 2 or tokens[0][:2] != '0x':
            continue
        if len_tokens > 5:
            result.extend( tokens[1:5] )
        else:
            result.extend( tokens[1: len_tokens - 1] )
    if len(result) < 10:
        return ''
    if result[2] == '01000000' and hash_alg == 'sha1':
        return ''.join(result[5:10])
    if result[2] == '02000000' and hash_alg == 'sha256':
        return ''.join(result[5:13])
    if len(result) >= 23 and result[12] == '02000000' and hash_alg == 'sha256':
        return ''.join(result[15:23])
    return ''


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


def get_or_create_dir(destdir):
    """
    Create a directory if it does not exist. otherwise, return it directly
    return absolute path of destdir
    """
    if destdir and os.path.exists(destdir):
        return os.path.abspath(destdir)
    os.makedirs(destdir)
    return os.path.abspath(destdir)


############################################################
#### Start of shell command read/parse routines ####
############################################################

def get_usr_merged_path(path):
    """ Convert /bin/gcc to /usr/bin/gcc, due to usrmerge feature
    """
    if path[0] != "/":
        return path
    tokens = path.split(os.sep)
    topdir = os.sep.join(tokens[:2])
    real_topdir = os.path.realpath(topdir)
    if real_topdir != topdir:
        newpath = os.path.join(real_topdir, *tokens[2:])
        verbose("Convert " + path + " to " + newpath + " due to usrmerge", LEVEL_3)
        return newpath
    return path


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
        if args.check_usr_merge:
            prog = get_usr_merged_path(lines[1])  # convert to possible usr-merged real path
        else:
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
        verbose("Warning: no output file for gcc line: " + gccline, LEVEL_3)
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
    if len(tokens) > 3 and args.pre_exec:
        return ('', [])
    if not ((len(tokens) > 3 and "c" in tokens[1]) or (len(tokens) == 3 and "s" in tokens[1])):
        # Only "ar -c archive file1...fileN", "ar -c archive @filelist", and "ar -s archive" are supported
        return ('', [])
    output_file = get_real_path(tokens[2], pwd)
    subfiles = []
    lines = tokens[3:]
    if len(tokens) > 3:
        afile = tokens[3]
        if afile[0] == '@':  # this is the content list file
            content_file = get_real_path(afile[1:], pwd)
            lines = read_text_file(content_file).splitlines()
    for line in lines:
        subfile = get_real_path(line, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
    return (output_file, subfiles)



def get_all_subfiles_in_jar_cmdline(jarline, pwd):
    """
    Returns the input/output files of the jar shell command line.
    Only the simple "jar cfmv Main.jar Manifest.txt HelloWorld/Main.class" format is supported.
    :param jarline: the jar command line
    :param pwd: the present working directory for this jar command
    """
    tokens = jarline.split()
    if len(tokens) < 3 or "c" not in tokens[1]:
        return ('', [])
    output_file = get_real_path(tokens[2], pwd)
    subfiles = []
    for token in tokens[3:]:
        subfile = get_real_path(token, pwd)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
    return (output_file, subfiles)


def read_name_ver_arch_from_deb_control(control_file):
    """
    Read package name, version, and arch from the DEBIAN/control file
    """
    lines = read_text_file(control_file).splitlines()
    for line in lines:
        tokens = line.split()
        if len(tokens) < 2:
            continue
        attr = tokens[0]
        if attr == "Package:":
            name = tokens[1]
        elif attr == "Version:":
            version = tokens[1]
        elif attr == "Architecture:":
            arch = tokens[1]
    return name, version, arch


def get_all_subfiles_in_dpkg_deb_cmdline(dpkgline, pwd):
    """
    Returns the input/output files of the dpkg-deb shell command line.
    Only the simple "dpkg-deb --build debian/openosc" or "dpkg-deb -b debian/openosc .." format is supported.
    :param dpkgline: the dpkg-deb command line
    :param pwd: the present working directory for this command
    """
    tokens = dpkgline.split()
    if len(tokens) < 3:
        return ('', [])
    found_build_opt = False
    new_tokens = []
    for token in tokens[1:]:
        if token == "-b" or token == "--build":
            found_build_opt = True
        elif token[0] != '-':
            new_tokens.append(token)
    if not found_build_opt or not new_tokens:
        return ('', [])
    debdir = get_real_path(new_tokens[0], pwd)
    control_file = os.path.join(debdir, "DEBIAN", "control")
    if not os.path.exists(control_file):
        return ('', [])
    if len(new_tokens) == 1:  # this is "dpkg-deb --build debian/openosc" cmd
        output_file = debdir + ".deb"  # the ouput archive is debdir.deb
    elif len(new_tokens) == 2:  # this is "dpkg-deb -b debian/openosc .." cmd
        output_file = get_real_path(new_tokens[1], pwd)  # if this is a file, then it will be the output archive
        if os.path.isdir(output_file):  # if this is a dir, then it will be dir/name_version_arch.deb output archive
            name, version, arch = read_name_ver_arch_from_deb_control(control_file)
            output_file = os.path.join(output_file, name + "_" + version + "_" + arch + ".deb")
    else:
        verbose("Warning: unsupported dpkg-deb cmd: " + dpkgline)
        return ('', [])
    subfiles = find_all_regular_files(debdir)
    return (output_file, subfiles)


def unbundle_package(pkgfile, destdir=''):
    '''
    unbundle RPM/DEB package to destdir.
    :param pkgfile: the RPM/DEB package file to unbundle
    :param destdir: the destination directory to save unbundled files, must be tmp dir to safely delete
    '''
    if not destdir:
        destdir = os.path.join(g_tmpdir, "bomsh_hook_" + os.path.basename(pkgfile) + ".extractdir")
    if pkgfile[-4:] == ".rpm":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; cd " + destdir + " ; rpm2cpio " + pkgfile + " | cpio -idm 2>/dev/null || true"
    elif pkgfile[-4:] == ".deb" or pkgfile[-5:] == ".udeb":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; dpkg-deb -xv " + pkgfile + " " + destdir + " || true"
    elif pkgfile[-7:] == ".tar.gz" or pkgfile[-7:] == ".tar.xz" or pkgfile[-8:] == ".tar.bz2":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; tar -xf " + pkgfile + " -C " + destdir + " || true"
    else:
        verbose("Warning: Unsupported package format in " + pkgfile + " file, skipping it.")
        return ''
    get_shell_cmd_output(cmd)
    return destdir


def get_subfiles_of_package_file(pkgfile):
    '''
    Get all subfiles in a single package file. Unbundle the package, find all subfiles and return

    :param pkgfile: the RPM/DEB package file to process
    '''
    destdir = unbundle_package(pkgfile)
    if not destdir:
        return [], ''
    afiles = find_all_regular_files(destdir)
    return afiles, destdir


def read_rpm_info_from_src_rpm(afile):
    """
    Get name,version,release info from a .src.rpm file
    """
    name, version, release = '', '', ''
    cmd = "rpm -qpi " + afile + " 2>/dev/null || true"
    lines = get_shell_cmd_output(cmd).splitlines()
    if not lines:
        return name, version, release
    for line in lines:
        tokens = line.split(":")
        if line[:4] == "Name":
            name = tokens[1].strip()
        elif line[:7] == "Version":
            version = tokens[1].strip()
        elif line[:7] == "Release":
            release = tokens[1].strip()
    return name, version, release


def read_rpm_info_from_spec_file(afile):
    """
    Get name,version,release info from a .spec file
    """
    name, version, release = '', '', ''
    lines = read_text_file(afile).splitlines()
    if not lines:
        return name, version, release
    for line in lines:
        tokens = line.split(":")
        if line[:4] == "Name":
            name = tokens[1].strip()
        elif line[:7] == "Version":
            version = tokens[1].strip()
        elif line[:7] == "Release":
            release = tokens[1].strip()
    return name, version, release


def rpm_eval_macro(rpmstring):
    """
    Evaluate a string that contains rpm macros
    """
    cmd = 'rpm --eval "' + rpmstring + '" || true'
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_rpmbuild_dist():
    """
    Get the dist macro value for rpmbuild
    """
    if g_shell_cmd_rootdir != "/":
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' /usr/lib/rpm/redhat/dist.sh 2>/dev/null || true'
    else:
        cmd = 'rpm --eval "%{?dist}" || true'
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_rpmbuild_topdir():
    """
    Get the rpmbuild _topdir.
    """
    if g_shell_cmd_rootdir != "/":
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' sh -c "find / -maxdepth 2 -type f -name \.rpmmacros | xargs grep \'%_topdir \' 2>/dev/null | head -1"'
        output = get_shell_cmd_output(cmd)
        tokens = output.split()
        if len(tokens) > 1:
            return tokens[1]
    else:
        cmd = "rpmbuild --eval %{_topdir}"
        output = get_shell_cmd_output(cmd)
        return output.strip()
    return ''


def get_all_subfiles_in_rpmbuild_cmdline(rpmline, pwd):
    """
    Returns the input/output files of the rpmbuilld shell command line.
    rpmbuild --define "_topdir /home/OpenOSC/rpmbuild" -ba SPECS/openosc.spec
    rpmbuild --rebuild sysstat-11.7.3-6.el8.src.rpm
    Building rpm from tarball is not supported
    :param rpmline: the rpmbuild command line
    :param pwd: the present working directory for this rpmbuild command
    returns a list of (rpmfile, subfiles of rpmfile, unbundle_dir of this rpmfile)
    """
    ret = []
    tokens = rpmline.split()
    if len(tokens) < 3:
        return ret
    found_build_opt = False
    new_tokens = []
    found_topdir = ''
    next_token_is_topdir = False
    for token in tokens[1:]:
        if token in ("-ba", "-bb", "-bs", "--rebuild"):
            found_build_opt = True
        elif next_token_is_topdir:
            next_token_is_topdir = False
            found_topdir = token
        elif token == "_topdir":
            next_token_is_topdir = True
        elif token[0] != '-' and (token[-8:] == ".src.rpm" or token[-5:] == ".spec"):
            new_tokens.append(token)
    if not found_build_opt or len(new_tokens) != 1:
        return ret
    spec_or_srcrpm = get_real_path(new_tokens[0], pwd)
    if not os.path.exists(spec_or_srcrpm):
        return ret
    if spec_or_srcrpm[-5:] == ".spec":  # this is .spec file
        name, version, release = read_rpm_info_from_spec_file(spec_or_srcrpm)
    else:
        name, version, release = read_rpm_info_from_src_rpm(spec_or_srcrpm)
    if "%{?dist}" in release:
        release = release.replace("%{?dist}", get_rpmbuild_dist())
    rpmbuild_topdir = found_topdir
    if not rpmbuild_topdir:
        rpmbuild_topdir = get_rpmbuild_topdir()
    rpmbuild_topdir = get_real_path(rpmbuild_topdir, pwd)
    if " -bs " in rpmline:
        name_pattern = name + "-*" + version + "-" + release + "*.src.rpm"
    else:
        name_pattern = name + "-*" + version + "-" + release + "*.rpm"
    rpmfiles = find_specific_file(rpmbuild_topdir, name_pattern)
    if " -ba " not in rpmline and " -bs " not in rpmline:  # filter out src rpm files
        rpmfiles = [rpmfile for rpmfile in rpmfiles if rpmfile[-8:] != ".src.rpm"]
    for rpmfile in rpmfiles:
        infiles, unbundle_dir = get_subfiles_of_package_file(rpmfile)
        ret.append( (rpmfile, infiles, unbundle_dir) )
    return ret


############################################################
#### End of gcc command read/parse routines ####
############################################################

# a dict to cache the computed hash of files
g_git_file_hash_cache = {}

def get_file_hash(afile, hash_alg="sha1", use_cache=True):
    '''
    Get the git object hash value of a file.
    :param afile: the file to calculate the git hash or digest.
    :param hash_alg: the hashing algorithm, either SHA1 or SHA256
    '''
    if use_cache:
        afile_key = afile + "." + hash_alg
        if afile_key in g_git_file_hash_cache:
            return g_git_file_hash_cache[afile_key]
    if hash_alg == "sha256":
        cmd = 'printf "blob $(wc -c < ' + afile + ')\\0" | cat - ' + afile + ' 2>/dev/null | sha256sum | head --bytes=-4 || true'
    else:
        cmd = 'git hash-object ' + cmd_quote(afile) + ' 2>/dev/null || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd).strip()
    #verbose("output of get_file_hash:\n" + output, LEVEL_3)
    if output:
        if use_cache:
            g_git_file_hash_cache[afile_key] = output
        return output
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
g_githash_link_objects_list = ("crtbeginS.o", "crtendS.o", "Scrt1.o", "crti.o", "crtn.o", "crt1.o", "crtbegin.o", "crtend.o", "liblto_plugin.so")

def get_git_file_hash_with_cache(afile, hash_alg="sha1"):
    '''
    Check the githash cache before calling "git hash-object".
    Also update the githash cache after calling "git hash-object".
    :param afile: the file to get git-hash
    '''
    afile_key = afile + "." + hash_alg
    if g_githash_cache and afile_key in g_githash_cache:
        return g_githash_cache[afile_key]
    ahash = get_file_hash(afile, hash_alg)
    if not args.no_githash_cache_file and (afile[-2:] == ".h" or os.path.basename(afile) in g_githash_link_objects_list):
        # only cache header files or the ld linker implicit object files
        verbose("Saving header githash cache, hash: " + ahash + " afile: " + afile, LEVEL_3)
        g_githash_cache[afile_key] = ahash
    return ahash


def get_infile_hashes(infiles, hash_alg):
    '''
    Get hashes for a list of input files
    :param infiles: a list of input files
    returns a dict of {infile : hash}
    '''
    global g_githash_cache
    if not args.no_githash_cache_file and not g_githash_cache:
        global g_githash_cache_initial_size
        if len(infiles) > 4 and os.path.exists(g_githash_cache_file):
            g_githash_cache = load_json_db(g_githash_cache_file)
            g_githash_cache_initial_size = len(g_githash_cache)
            verbose("load_json_db githash cache db, initial_size: " + str(g_githash_cache_initial_size), LEVEL_3)
    if len(infiles) > 4:
        return {infile:get_git_file_hash_with_cache(infile, hash_alg) for infile in infiles}
    return {infile:get_file_hash(infile, hash_alg) for infile in infiles}


def get_build_tool_version(prog, pwd):
    '''
    Get the build tool version.
    :param prog: the program binary
    :param pwd: present working directory of the shell command
    '''
    if g_shell_cmd_rootdir != "/":
        chroot_pwd = pwd
        if pwd.startswith(g_shell_cmd_rootdir):
            chroot_pwd = pwd[len(g_shell_cmd_rootdir):]
        if not chroot_pwd:
            chroot_pwd = "/"
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' sh -c "cd ' + chroot_pwd + " ; " + prog + ' --version" || true'
    else:
        mypwd = pwd
        if not mypwd:
            mypwd = "/"
        cmd = "cd " + mypwd + " ; " + prog + " --version || true"
    version_output = get_shell_cmd_output(cmd)
    if not version_output:
        cmd = cmd.replace(" --version", " version")
        version_output = get_shell_cmd_output(cmd)
    if version_output:
        lines = version_output.splitlines()
        return lines[0]
    return ''


def get_build_tool_info(prog, pwd, hash_alg):
    '''
    Get the build tool information.
    :param prog: the program binary
    :param pwd: present working directory of the shell command
    '''
    afile = get_real_path(prog, pwd)
    ahash = get_file_hash(afile, hash_alg)
    version_output = get_build_tool_version(prog, pwd)
    if version_output:
        ret = "build_tool: " + ahash + " path: " + get_noroot_path(afile) + " tool_version: " + version_output
    else:
        ret = "build_tool: " + ahash + " path: " + get_noroot_path(afile)
    return ret


############################################################
#### Start of gitbom ADG doc save routines ####
############################################################

def create_gitbom_doc_text(infiles, infile_checksums, destdir, hash_alg="sha1"):
    """
    Create the OmniBOR doc text contents
    :param infiles: the list of input files
    :param infile_checksums: a dict of checksums of input files
    :param destdir: destination directory to create the gitbom doc file
    :param hash_alg: the hashing algorithm, sha1 or sha256
    """
    if not infiles:
        return ''
    lines = []
    for infile in infiles:
        ahash = infile_checksums[infile]
        line = "blob " + ahash
        bom_id = get_hash_of_adg_doc(read_symlink_for_adg_doc(ahash, destdir))
        if bom_id:
            verbose("Read bom_id " + bom_id + " from symlink for blob " + ahash, LEVEL_4)
        # if symlink does not exist, we try to extract the embedded bom_id in the infile if configured
        if not bom_id and args.read_bomid_from_file_for_adg:
            bom_id = get_embedded_bom_id_of_elf_file(infile, hash_alg)
            if bom_id:
                verbose("Read bom_id " + bom_id + " from ELF file for blob " + ahash, LEVEL_4)
        if bom_id:
            line += " bom " + bom_id
        lines.append(line)
    lines.sort()
    return '\n'.join(lines) + '\n'


def get_hash_of_adg_doc(adg_doc_file):
    """
    Return the hash of the ADG doc file: the 1238... part of objects/12/38...
    """
    tokens = adg_doc_file.split(os.sep)
    if len(tokens) < 2:
        return ''
    return tokens[-2] + tokens[-1]


def read_symlink_for_adg_doc(ahash, destdir):
    """
    Read the symlink file of artifact hash, to get the OmniBOR doc
    :param ahash: the artifact hash to read symlink for
    :param destdir: destination directory to store the gitbom doc file and symlinks
    returns the real path of the ADG doc that this symlink file pointing to
    """
    symlink = os.path.join(destdir, "symlinks", ahash)
    if not os.path.exists(symlink):
        return ''
    cmd = "realpath " + symlink + " || true"
    #cmd = "readlink " + symlink + " || true"
    #print(cmd)
    output = get_shell_cmd_output(cmd).strip()
    if not output:
        return output
    return output


def update_symlink_dir_for_artifact_conflict(ahash, old_adg_doc, adg_doc, destdir):
    """
    Update the artifact's symlinks directory for an artifact ID conflict
    :param ahash: the hash of output file
    :param old_adg_doc: the old existing ADG doc for this artifact ID
    :param adg_doc: the newly created ADG doc for this artifact ID
    :param destdir: destination directory to store the gitbom doc file
    """
    artifact_symlink_dir = os.path.join(destdir, "symlinks", ahash + ".symlinks")
    new_symlink = os.path.join(artifact_symlink_dir, get_hash_of_adg_doc(adg_doc))
    if os.path.exists(artifact_symlink_dir):
        if not os.path.exists(new_symlink):
            cmd = "ln -sfr " + adg_doc + " " + new_symlink
            os.system(cmd)
        return
    old_symlink = os.path.join(artifact_symlink_dir, get_hash_of_adg_doc(old_adg_doc))
    cmd = "mkdir -p " + artifact_symlink_dir + " ; ln -sfr " + old_adg_doc + " " + old_symlink + " ; ln -sfr " + adg_doc + " " + new_symlink
    os.system(cmd)


def create_symlink_for_adg_doc(ahash, adg_doc, destdir):
    """
    Create the symlink to the OmniBOR doc for an artifact ID
    :param ahash: the hash of output file, that is, the artifact ID
    :param adg_doc: the created ADG doc to create symlink for
    :param destdir: destination directory to store the gitbom doc file
    returns the symlink file
    """
    symlink_dir = os.path.join(destdir, "symlinks")
    symlink = os.path.join(destdir, "symlinks", ahash)
    if os.path.exists(symlink):
        old_adg_doc = read_symlink_for_adg_doc(symlink, destdir)
        #print("create_symlink_for_adg_doc, old_adg_doc: " + old_adg_doc + " new_adg_doc: " + adg_doc)
        if old_adg_doc == adg_doc:
            verbose("No update of effective symlink for artifact " + ahash + ", we got same ADG doc: " + adg_doc, LEVEL_3)
            return symlink
        verbose("Warning: artifact ID conflict detected for " + ahash)
        update_symlink_dir_for_artifact_conflict(ahash, old_adg_doc, adg_doc, destdir)
    # the latter adg_doc will overwrite previous one if there is artifact ID conflict
    cmd = "mkdir -p " + symlink_dir + " ; ln -sfr " + adg_doc + " " + symlink
    os.system(cmd)
    verbose("Updated effective symlink for artifact " + ahash + ", new adg_doc: " + adg_doc, LEVEL_3)
    return symlink


# The "--set-section-alignment <name>=<align>" option was introduced in objcopy 2.33 version.
# so "--set-section-alignment .note.omnibor=4" cannot yet be used for objcopy < 2.33 version
g_embed_bom_script = '''
if objdump -s -j .note.omnibor HELLO_FILE >/dev/null 2>/dev/null ; then
  GITBOM_BUILD_MODE= objcopy --update-section .note.omnibor=NOTE_FILE --set-section-flags .note.omnibor=alloc,readonly HELLO_FILE >/dev/null 2>/dev/null
else
  GITBOM_BUILD_MODE= objcopy --add-section .note.omnibor=NOTE_FILE --set-section-flags .note.omnibor=alloc,readonly HELLO_FILE >/dev/null 2>/dev/null
fi
'''

def gitbom_record_hash(outfile_checksum, outfile, infiles, infile_checksums, pwd, argv_str, pid='', prog='', hash_alg="sha1", ignore_this_record=False):
    '''
    Record the raw info for a list of infiles and outfile

    :param outfile_checksum: the checksum of the output file
    :param outfile: the output file
    :param infiles: a list of input files
    :param infile_checksums: a dict of checksums of input files
    :param pwd: present working directory of the shell command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    :param prog: the program binary
    :param hash_alg: the hashing algorithm, sha1 or sha256
    :param ignore_this_record: info only, ignore this record for create_bom processing
    '''
    # infiles can be empty, but outfile must not be empty
    if not outfile:
        return ''
    if not infiles:
        verbose("Warning: infiles is empty in record_raw! outfile: " + outfile + " prog: " + prog)
    if not outfile_checksum:
        outfile_checksum = get_file_hash(outfile, hash_alg)
    if not infile_checksums:
        infile_checksums = get_infile_hashes(infiles, hash_alg)
    bomid = ''
    if args.record_raw_bomid:
        bomid = get_embedded_bom_id_of_elf_file(outfile, hash_alg)
    if bomid:
        lines = ["\noutfile: " + outfile_checksum + " path: " + get_noroot_path(outfile) + " bomid: " + bomid,]
    else:
        lines = ["\noutfile: " + outfile_checksum + " path: " + get_noroot_path(outfile),]
    for infile in infiles:
        cve_result = ''
        if g_cve_check_rules:
            cve_result = cve_check_rule_for_file(infile)
        bomid = ''
        if args.record_raw_bomid:
            bomid = get_embedded_bom_id_of_elf_file(infile, hash_alg)
        infile_str = "infile: " + infile_checksums[infile] + " path: " + get_noroot_path(infile)
        if cve_result:
            infile_str += cve_result
        if bomid:
            infile_str += " bomid: " + bomid
        lines.append(infile_str)
    if ignore_this_record:
        lines.append("ignore_this_record: information only")
    lines.append("build_cmd: " + argv_str)
    if args.record_build_tool and prog:
        build_tool_info = get_build_tool_info(prog, pwd, hash_alg)
        lines.append(build_tool_info)
    if pid:
        lines.append("==== End of raw info for PID " + pid + " process\n\n")
    else:
        lines.append("==== End of raw info for this process\n\n")
    outstr = '\n'.join(lines)
    append_text_file(g_raw_logfile + "." + hash_alg, outstr)
    return outstr


def gitbom_create_temp_adg_doc(infiles, infile_hashes, destdir, hash_alg):
    '''
    Create the temporary ADG doc for a list of infiles and their hashes
    :param infiles: a list of input files
    :param infile_hashes: a dict of {infile => hash}
    :param destdir: the destination directory to save this ADG doc file
    :param hash_alg: the hashing algorithm, sha1 or sha256
    '''
    lines = create_gitbom_doc_text(infiles, infile_hashes, destdir, hash_alg)
    output_file = os.path.join(g_tmpdir, "bomsh_temp_gitbom_file." + hash_alg)
    firstline = "gitoid:blob:" + hash_alg + "\n"
    write_text_file(output_file, firstline + lines)
    verbose("Create temp ADG doc: " + output_file + " for #infiles: " + str(len(infiles)), LEVEL_4)
    return output_file


def gitbom_rename_adg_doc(adg_doc, adg_hash, destdir):
    '''
    Rename temporary ADG doc to its .omnibor/objects/xx/yy..yy file.
    :param adg_doc: the temporary ADG doc file
    :param adg_hash: the sha1 or sha256 hash of the ADG doc file
    :param destdir: the destination directory to save this ADG doc file
    '''
    verbose("created ADG doc, doc_id: " + adg_hash, LEVEL_4)
    object_dir = os.path.join(destdir, "objects", adg_hash[:2])
    object_file = os.path.join(object_dir, adg_hash[2:])
    if not os.path.exists(object_file):
        cmd = 'mkdir -p ' + object_dir + ' && mv ' + adg_doc + ' ' + object_file + ' || true'
        os.system(cmd)
    return object_file


def gitbom_embed_bomid_elf(outfile, bomid_sha1, bomid_sha256):
    '''
    Embed bomid ELF note section into outfile
    :param outfile: the output file
    :param bomid_sha1: the bomid string of SHA1 hash
    :param bomid_sha256: the bomid string of SHA256 hash
    '''
    if not bomid_sha1 and not bomid_sha256:
        return
    note = b''
    if bomid_sha1:
        note += b'\x08\x00\x00\x00\x14\x00\x00\x00\x01\x00\x00\x00\x4f\x4d\x4e\x49\x42\x4f\x52\x00' + bytes.fromhex(bomid_sha1)
    if bomid_sha256:
        note += b'\x08\x00\x00\x00\x20\x00\x00\x00\x02\x00\x00\x00\x4f\x4d\x4e\x49\x42\x4f\x52\x00' + bytes.fromhex(bomid_sha256)
    afile = os.path.join(g_tmpdir, "bomsh_hook_bomid")
    #afile = os.path.join(g_tmpdir, "bomsh_hook_bomid_pid" + str(os.getpid()))
    write_binary_file(afile, note)
    embed_script = g_embed_bom_script.replace("HELLO_FILE", outfile).replace("NOTE_FILE", afile)
    get_shell_cmd_output(embed_script)
    #os.remove(afile)
    verbose("Embed bomid into outfile: " + outfile + " bomid_sha1: " + bomid_sha1 + " bomid_sha256: " + bomid_sha256, LEVEL_3)


def gitbom_create_adg_and_record_hash(outfile, infiles, infile_hashes, adg_doc, adg_hash, pwd, argv_str, pid='', prog='', outhash='', hash_alg="sha1", ignore_this_record=False):
    '''
    Create ADG docs and record the raw info for a list of infiles and outfile

    :param outfile: the output file
    :param infiles: a list of input files
    :param infile_hashes: a dict of {infile => hash}
    :param adg_doc: the temporary ADG doc file
    :param adg_hash: the sha1 or sha256 hash of the ADG doc file
    :param pwd: present working directory of the shell command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    :param prog: the program binary
    :param outhash: the checksum of the output file
    :param hash_alg: the hashing algorithm, sha1 or sha256
    :param ignore_this_record: info only, ignore this record for create_bom processing
    '''
    verbose("Entering gitbom_create_adg_and_record_hash, outhash: " + outhash + " outfile: " + outfile + " adg_doc: " + adg_doc, LEVEL_4)
    if not outhash:
        outhash = get_file_hash(outfile, hash_alg, use_cache=False)
    destdir = g_bomdir
    if not infile_hashes:
        infile_hashes = get_infile_hashes(infiles, hash_alg)
    if not args.create_no_adg and not ignore_this_record:
        if not adg_doc:
            adg_doc = gitbom_create_temp_adg_doc(infiles, infile_hashes, destdir, hash_alg)
            adg_hash = get_file_hash(adg_doc, hash_alg, use_cache=False)
        new_adg_doc = gitbom_rename_adg_doc(adg_doc, adg_hash, destdir)
        create_symlink_for_adg_doc(outhash, new_adg_doc, destdir)
    gitbom_record_hash(outhash, outfile, infiles, infile_hashes, pwd, argv_str, pid=pid, prog=prog, hash_alg=hash_alg, ignore_this_record=ignore_this_record)


def record_raw_info(outfile, infiles, pwd, argv_str, pid='', prog='', outfile_checksum='', infile_checksums='', ignore_this_record=False):
    '''
    Not just record the raw info for a list of infiles and outfile.
    The OmniBOR extra work to do for the build step

    :param outfile: the output file
    :param infiles: a list of input files
    :param pwd: present working directory of the shell command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    :param prog: the program binary
    :param outfile_checksum: the checksum of the output file
    :param infile_checksums: a dict of checksums of input files, { hash_alg : { infile : hash } }
    :param ignore_this_record: info only, ignore this record for create_bom processing
    '''
    sha1_infile_hashes = []
    sha1_adg_doc = ''
    sha1_adg_hash = ''
    sha256_infile_hashes = []
    sha256_adg_doc = ''
    sha256_adg_hash = ''
    destdir = g_bomdir
    if "sha1" in g_hashtypes and infile_checksums and "sha1" in infile_checksums:
        sha1_infile_hashes = infile_checksums["sha1"]
    if "sha256" in g_hashtypes and infile_checksums and "sha256" in infile_checksums:
        sha256_infile_hashes = infile_checksums["sha256"]
    # bom_id embedding must occur before creating OmniBOR doc and symlink, also before recording hashes of output file
    if not args.no_auto_embed_bom_for_compiler_linker and not ignore_this_record:
        if "sha1" in g_hashtypes:
            if not sha1_infile_hashes:
                sha1_infile_hashes = get_infile_hashes(infiles, "sha1")
            sha1_adg_doc = gitbom_create_temp_adg_doc(infiles, sha1_infile_hashes, destdir, "sha1")
            sha1_adg_hash = get_file_hash(sha1_adg_doc, "sha1", use_cache=False)
        if "sha256" in g_hashtypes:
            if not sha256_infile_hashes:
                sha256_infile_hashes = get_infile_hashes(infiles, "sha256")
            sha256_adg_doc = gitbom_create_temp_adg_doc(infiles, sha256_infile_hashes, destdir, "sha256")
            sha256_adg_hash = get_file_hash(sha256_adg_doc, "sha256", use_cache=False)
        gitbom_embed_bomid_elf(outfile, sha1_adg_hash, sha256_adg_hash)
    if "sha1" in g_hashtypes:
        gitbom_create_adg_and_record_hash(outfile, infiles, sha1_infile_hashes, sha1_adg_doc, sha1_adg_hash, pwd, argv_str, pid, prog=prog, ignore_this_record=ignore_this_record, hash_alg="sha1")
    if "sha256" in g_hashtypes:
        gitbom_create_adg_and_record_hash(outfile, infiles, sha256_infile_hashes, sha256_adg_doc, sha256_adg_hash, pwd, argv_str, pid, prog=prog, ignore_this_record=ignore_this_record, hash_alg="sha256")

############################################################
#### End of hash/checksum routines ####
############################################################

def is_c_source_file(afile):
    '''
    Is a file C/C++ source code file?
    '''
    tokens = afile.split(".")
    return tokens[-1] in ("c", "cpp", "s", "S", "cc", "cxx", "c++", "CPP")
    #return afile[-2:] == ".c" or afile[-3:] == ".cc" or afile[-4:] == ".cpp" or afile[-2:] == ".s" or afile[-2:] == ".S"


def does_source_file_exist_in_files(infiles):
    '''
    Does the list of files contain C/C++ source code files.
    :param infiles: a list of input files
    '''
    for afile in infiles:
        if is_c_source_file(afile):
            return True
    return False


def get_source_files_in_files(infiles):
    '''
    Get a list of C/C++ source code files in a list of files.
    :param infiles: a list of input files
    '''
    return [afile for afile in infiles if is_c_source_file(afile)]


def get_d_file_path(cfile, pwd, prefix):
    '''
    Get the src.d dependency file path for a C/C++ source file
    :param cfile: the C/C++ source file
    :param pwd: the working directory for the gcc command
    :param prefix: possible prefix of filename, usually "a-"
    '''
    dirname, basename = os.path.split(cfile)
    tokens = basename.split(".")
    basename2 = ".".join(tokens[:-1])
    dfile = os.path.join(dirname, prefix + basename2 + ".d")
    return get_real_path(dfile, pwd)


def get_d_files_from_files(infiles, pwd):
    '''
    Get a list of src1.d/src2.d files from a list of C/C++ source files.
    :param infiles: a list of input files, must not be empty
    :param pwd: the working directory for the gcc command
    '''
    dfile = get_d_file_path(infiles[0], pwd, "")
    if os.path.exists(dfile):
        return [get_d_file_path(afile, pwd, "") for afile in infiles]
    else:
        return [get_d_file_path(afile, pwd, "a-") for afile in infiles]


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


def remove_output_file_in_shell_command(gcc_cmd):
    '''
    Try to remove the -o output file for the gcc shell command.
    :param gcc_cmd: the gcc compile command
    '''
    if " -o " in gcc_cmd:
        tokens = gcc_cmd.split()
        oindex = tokens.index("-o")
        return ' '.join(tokens[:oindex] + tokens[oindex+2:])
    else:
        return gcc_cmd


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


def rerun_shell_command(pwd, gcc_cmd):
    '''
    Try to rerun a shell command, usually gcc_cmd or ld_cmd
    '''
    if g_shell_cmd_rootdir != "/":
        chroot_pwd = pwd
        if pwd.startswith(g_shell_cmd_rootdir):
            chroot_pwd = pwd[len(g_shell_cmd_rootdir):]
        if not chroot_pwd:
            chroot_pwd = "/"
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' sh -c "cd ' + chroot_pwd + " ; " + escape_shell_command(gcc_cmd) + '" 2>/dev/null || true'
    else:
        mypwd = pwd
        if not mypwd:
            mypwd = "/"
        cmd = "cd " + mypwd + " ; " + escape_shell_command(gcc_cmd) + " 2>/dev/null || true"
    verbose("rerun shell cmd: " + cmd)
    get_shell_cmd_output(cmd)


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
        if not chroot_pwd:
            chroot_pwd = "/"
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' sh -c "cd ' + chroot_pwd + " ; " + escape_shell_command(gcc_cmd) + " -MD -MF " + depend_file + '" 2>/dev/null || true'
    else:
        mypwd = pwd
        if not mypwd:
            mypwd = "/"
        cmd = "cd " + mypwd + " ; " + escape_shell_command(gcc_cmd) + " -MD -MF " + depend_file + " 2>/dev/null || true"
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


def get_c_file_depend_files_multi(gcc_cmd, pwd, cfiles):
    '''
    Get all the depend files for a gcc command which compiles multiple C source code files
    This function applies to gcc command which contains multiple C/C++ source files
    We add "-MD" to the gcc command, and remove the "-o outfile" option
    :param gcc_cmd: the gcc compile command
    :param pwd: the working directory for the gcc command
    returns a list of depends that are read from srcN.d files.
    '''
    depends = ('', [])
    gcc_cmd = remove_output_file_in_shell_command(gcc_cmd)
    if g_shell_cmd_rootdir != "/":
        chroot_pwd = pwd
        if pwd.startswith(g_shell_cmd_rootdir):
            chroot_pwd = pwd[len(g_shell_cmd_rootdir):]
        if not chroot_pwd:
            chroot_pwd = "/"
        cmd = 'chroot ' + g_shell_cmd_rootdir + ' sh -c "cd ' + chroot_pwd + " ; " + escape_shell_command(gcc_cmd) + ' -MD 2>/dev/null || true'
    else:
        mypwd = pwd
        if not mypwd:
            mypwd = "/"
        cmd = "cd " + mypwd + " ; " + escape_shell_command(gcc_cmd) + " -MD 2>/dev/null || true"
    verbose("get_c_depend multi_cmd: " + cmd)
    os.system(cmd)
    dfiles = get_d_files_from_files(cfiles, pwd)
    #print("get_c_file_depend_files_multi, dfiles: " + str(dfiles))
    depends_list = []
    for dfile in dfiles:
        if os.path.exists(dfile):
            depends = read_depend_file(dfile, pwd)
            #print("get_c_file_depend_files_multi, depends: " + str(depends))
            depends_list.append(depends)
            os.remove(dfile)
    real_output_file = get_real_path("a.out", pwd)
    if os.path.exists(real_output_file):
        os.remove(real_output_file)
    return depends_list


def handle_gcc_ctoexe_command(prog, pwddir, argv_str, pid, outfile, infiles):
    '''
    Process the gcc command that compiles C/C++ source files to executable/.so directly
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    :param outfile: the output file
    :param infiles: the list of input files
    returns the outfile
    '''
    ldout_files = { hash_alg: get_bomsh_ldout_file(get_file_hash(outfile, hash_alg)) for hash_alg in g_hashtypes }
    for hash_alg in ldout_files:
        ldout_file = ldout_files[hash_alg]
        if not os.path.exists(ldout_file):
            verbose("Warning: ldout file is not found, simply record outfile/infiles for this command")
            record_raw_info(outfile, infiles, pwddir, argv_str, pid, prog=prog)
            return outfile
    cfiles = get_source_files_in_files(infiles)
    if not args.no_dependent_headers:
        if len(cfiles) == 1:
            depends = get_c_file_depend_files(argv_str, pwddir)
            depends_list = [(cfiles[0], depends[1]),]
        else:
            depends_list = get_c_file_depend_files_multi(argv_str, pwddir, cfiles)
    else:
        depends_list = [(afile, (afile,)) for afile in cfiles]
    # Read all text lines from ldout_files
    ldout_lines = { hash_alg: read_text_file( ldout_files[hash_alg] ).splitlines() for hash_alg in ldout_files }
    d_tmp_infiles = { hash_alg: get_tmp_infiles_from_ldout_lines( ldout_lines[hash_alg] ) for hash_alg in ldout_lines }
    for hash_alg in g_hashtypes:
        tmp_infiles = d_tmp_infiles[hash_alg]
        # number of depends_list must match number of tmp_infiles
        new_depends_list = [ (tmp_infiles[i][0], tmp_infiles[i][1], depends_list[i][1]) for i in range(len(depends_list)) ]
        #print("handle_gcc_ctoexe_command, the new depends_list: " + str(new_depends_list))
        for depends in new_depends_list:
            # no need to embed bomid for intermediate /tmp/cc*.o files, so skip calling gitbom_embed_bomid_elf
            # but we still try to create ADG docs and record the hashes of output and input files.
            gitbom_create_adg_and_record_hash(depends[1], depends[2], '', '', '', pwddir, argv_str, pid, prog=prog, outhash=depends[0], hash_alg=hash_alg)
            #record_raw_info(depends[1], depends[2], pwddir, argv_str, pid, prog=prog, outfile_checksum=depends[0], skip_embed_bomid=True)
    d_infiles = { hash_alg: get_infiles_from_ldout_lines( ldout_lines[hash_alg] ) for hash_alg in ldout_files }
    new_infiles = []
    for hash_alg in d_infiles:
        new_infiles = d_infiles[hash_alg].keys()
        # sha1 and sha256 should have the exactly same list of infiles
        break
    # still try to embed bomid for the output file
    record_raw_info(outfile, new_infiles, pwddir, argv_str, pid, prog=prog, infile_checksums=d_infiles)
    # the ldout file can now be removed
    for hash_alg in ldout_files:
        os.remove(ldout_files[hash_alg])
    return outfile


def gcc_is_compile_only(argv_str):
    '''
    Whether the gcc command compiles from C/C++ source files to intermediate .o/.s/.E only
    :param argv_str: the full command with all its command line options/parameters
    '''
    for option in (" -c ", " -S ", " -E "):
        if option in argv_str:
            return True
    return False


def process_gcc_command(prog, pwddir, argv_str, pid):
    '''
    Process the gcc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    '''
    global g_cve_check_rules
    if args.cve_check_dir:
        g_cve_check_rules = convert_to_srcfile_cve_rules_db(read_cve_check_rules(args.cve_check_dir))
    (outfile, infiles) = get_all_subfiles_in_gcc_cmdline(argv_str, pwddir, prog)
    verbose("get_all_subfiles_in_gcc_cmdline, outfile: " + outfile + " infiles: " + str(infiles), LEVEL_4)
    if not outfile:  # we don't support a.out as output file
        return ''
    if not infiles:  # if infiles is empty, no need to record info for this gcc cmd
        return ''
    if not os.path.exists(outfile):
        verbose("Warning: gcc outfile does not exist: " + outfile)
        return ''
    if gcc_is_compile_only(argv_str):  # this gcc will not invoke LD
        infiles2 = []
        if not args.no_dependent_headers and does_source_file_exist_in_files(infiles):
            # Get the dependency list of source file, there should be one single source file for this gcc cmd
            (outfile2, infiles2) = get_c_file_depend_files(argv_str, pwddir)
            verbose("get_c_depend_files, outfile2: " + outfile2 + " infiles2: " + str(infiles2), LEVEL_4)
            if infiles2:
                infiles = infiles2
        record_raw_info(outfile, infiles, pwddir, argv_str, pid, prog=prog)
    elif does_source_file_exist_in_files(infiles):  # compile source to exe/.so directly
        return handle_gcc_ctoexe_command(prog, pwddir, argv_str, pid, outfile, infiles)
    else:  # this gcc only invokes LD to link *.o files, and is redundant, so record it for information only
        record_raw_info(outfile, infiles, pwddir, argv_str, pid, prog=prog, ignore_this_record=True)
    return outfile


def get_first_tmp_o_file(afiles):
    '''
    Get the first one if there is any /tmp/cc*.o file in a list of files
    '''
    for afile in afiles:
        bfile = get_noroot_path(afile)
        if bfile[:5] == "/tmp/" and bfile[-2:] == ".o":
            return afile
    return ''


def get_tmp_infiles_from_ldout_lines(ldout_lines):
    '''
    Get a list of /tmp/cc*.o files from LD out file
    :param ldout_file: the ldout file that stores the record raw_info for this LD command
    '''
    infiles = []
    for line in ldout_lines:
        if line[:8] == "infile: ":
            tokens = line.split()
            infile = tokens[3]
            if infile[:5] == "/tmp/":
                infiles.append( (tokens[1], infile) )
    return infiles


def get_infiles_from_ldout_lines(ldout_lines):
    '''
    Get the list of infiles and their hashes from LD out file
    :param ldout_file: the ldout file that stores the record raw_info for this LD command
    '''
    infiles = {}
    for line in ldout_lines:
        if line[:8] == "infile: ":
            tokens = line.split()
            infiles[tokens[3]] = tokens[1]
    return infiles


def is_gcc_invoked_ld_cmd(argv_str):
    '''
    GCC invoked LD must have some special *.o files in the ld cmd
    :param argv_str: the ld command string
    '''
    return "crti.o " in argv_str and "crtn.o" in argv_str


def get_bomsh_ldout_file(ahash):
    '''
    Get the full file path of the ldout file for the LD cmd
    :param ahahs: the artifact hash, that is, the hash of the output file of the LD cmd
    '''
    return os.path.join(g_tmpdir, "bomsh_hook_ldout." + ahash)


def write_bomsh_ldout_file(outfile, raw_str, hash_alg="sha1"):
    '''
    Write a file to indicate an outfile is linker output
    :param prog: the program binary
    :param raw_str: the str to write, this is actually the raw-info recorded for this LD cmd
    '''
    ahash = get_file_hash(outfile, hash_alg)
    afile = get_bomsh_ldout_file(ahash)
    write_text_file(afile, raw_str)


def is_shared_library(afile):
    '''
    Is this file a shared library?
    '''
    return afile[-3:] == ".so"


def process_ld_command(prog, pwddir, argv_str, pid):
    '''
    Process the ld command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command
    '''
    # ld command can be handled the same way as gcc command, for outfile,infiles
    (outfile, infiles) = get_all_subfiles_in_gcc_cmdline(argv_str, pwddir, prog)
    if not outfile:  # we don't support a.out as output file
        return ''
    if not infiles:  # if infiles is empty, no need to record info for this ld cmd
        return ''
    if not os.path.exists(outfile):
        # sometimes, ld cmd fails, for example, missing library -lciscosafec to link
        verbose("Warning: ld outfile does not exist: " + outfile)
        return ''
    # explicitly remove shared libraries from the list of infiles
    infiles = [afile for afile in infiles if not is_shared_library(afile)]
    first_tmp_o = get_first_tmp_o_file(infiles)
    if first_tmp_o and is_gcc_invoked_ld_cmd(argv_str):
        if not args.no_auto_embed_bom_for_compiler_linker:
            # insert a dummy .note.omnibor ELF section to be linked into the executable
            gitbom_embed_bomid_elf(first_tmp_o, '1'*40, '2'*64)
            rerun_shell_command(pwddir, argv_str)
        # this ld is invoked by gcc_ctoexe, and will be processed by later gcc, so this ld record is for info only
        for hash_alg in g_hashtypes:
            raw_str = gitbom_record_hash('', outfile, infiles, '', pwddir, argv_str, pid=pid, ignore_this_record=True, hash_alg=hash_alg)
            # Write the raw info to a file for later use by gcc
            write_bomsh_ldout_file(outfile, raw_str, hash_alg)
    else:
        record_raw_info(outfile, infiles, pwddir, argv_str, pid, prog=prog)
    return outfile


def process_rustc_command(prog, pwddir, argv_str):
    '''
    Process the rustc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    (outfile, infiles) = get_all_subfiles_in_rustc_cmdline(argv_str, pwddir, prog)
    if not infiles:  # if infiles is empty, no need to record info for this rustc cmd
        return ''
    record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
    return outfile


def process_golang_command(prog, pwddir, argv_str):
    '''
    Process the golang compile/link command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    # golang link command can be handled the same way as golang compile command, for outfile,infiles
    (outfile, infiles) = get_all_subfiles_in_golang_cmdline(argv_str, pwddir, prog)
    if not infiles:  # if infiles is empty, no need to record info for this golang cmd
        return ''
    record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
    return outfile


def save_pre_exec_file_hashes(afiles, pid, hash_alg="sha1"):
    '''
    Save the file hashes of pre_exec mode
    :param afiles: a list of files to save hashes
    :param pid: the process PID, must not be empty
    '''
    lines = []
    for afile in afiles:
        ahash = get_file_hash(afile, hash_alg)
        lines.append(ahash + ' ' + afile)
    afile = os.path.join(g_tmpdir, "bomsh_hook_pid" + str(pid) + ".pre_exec_hashes." + hash_alg)
    write_text_file(afile, '\n'.join(lines))


def collect_pre_exec_file_hashes(pid, hash_alg="sha1"):
    '''
    Collect the saved file hashes of pre_exec mode
    :param pid: the process PID, must not be empty
    returns a dict of file-path => hash mappings
    '''
    afile = os.path.join(g_tmpdir, "bomsh_hook_pid" + str(pid) + ".pre_exec_hashes." + hash_alg)
    lines = read_text_file(afile).splitlines()
    hashes = {}
    for line in lines:
        tokens = line.split()
        hashes[tokens[1]] = tokens[0]
    verbose("collected pre_exec hashes: " + str(hashes), LEVEL_3)
    # remove the file after use
    os.remove(afile)
    return hashes


def process_sepdebugcrcfix_command(prog, pwddir, argv_str, pid):
    '''
    Process the sepdebugcrcfix command
    /usr/lib/rpm/sepdebugcrcfix usr/lib/debug .//usr/bin/openssl .//usr/lib64/engines-1.1/afalg.so .//usr/lib64/engines-1.1/capi.so .//usr/lib64/libcrypto.so.1.1.1k .//usr/lib64/engines-1.1/padlock.so .//usr/lib64/libssl.so.1.1.1k
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command, this is a str, not integer
    '''
    tokens = argv_str.split()
    if len(tokens) < 3: # infiles is empty, no need to record info for this cmd
        return ''
    infiles = [get_real_path(afile, pwddir) for afile in tokens[2:]]
    verbose(prog + " infiles: " + str(infiles), LEVEL_3)
    # save hashes of infiles to a temp file for later use in post-exec mode
    if args.pre_exec:
        for hash_alg in g_hashtypes:
            save_pre_exec_file_hashes(infiles, pid, hash_alg)
    else:
        hashes = { hash_alg : collect_pre_exec_file_hashes(pid, hash_alg) for hash_alg in g_hashtypes }
        for infile in infiles:
            record_raw_info(infile, [infile,], pwddir, argv_str, pid, prog=prog, infile_checksums=hashes)
    return ''


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
        record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
        return outfile
    # there is no outfile or outfile is same as infile, need to handle both pre-exec and post-exec mode.
    # save hashes of infiles to a temp file for later use in post-exec mode
    if args.pre_exec:
        for hash_alg in g_hashtypes:
            save_pre_exec_file_hashes(infiles, pid, hash_alg)
    else:
        hashes = { hash_alg : collect_pre_exec_file_hashes(pid, hash_alg) for hash_alg in g_hashtypes }
        for infile in infiles:
            record_raw_info(infile, [infile,], pwddir, argv_str, pid, prog=prog, infile_checksums=hashes)
    return outfile


def shell_command_record_same_file(prog, pwddir, argv_str, pid, cmdname):
    '''
    The shell command update the single file, like objtool/sorttable/ranlib. the last token must the file to update.
    '''
    tokens = argv_str.split()
    outfile = get_real_path(tokens[-1], pwddir)
    if not os.path.isfile(outfile):
        verbose("Warning: " + prog + " outfile " + outfile + " is not a file, ignore this command", LEVEL_1)
        return ''
    # save hashes of infiles to a temp file for later use in post-exec mode
    if args.pre_exec:
        for hash_alg in g_hashtypes:
            if cmdname == "sign-file":
                x509_path = get_real_path(tokens[-2], pwddir)
                save_pre_exec_file_hashes([outfile, x509_path,], pid, hash_alg)
            else:
                save_pre_exec_file_hashes([outfile,], pid, hash_alg)
    else:
        hashes = { hash_alg : collect_pre_exec_file_hashes(pid, hash_alg) for hash_alg in g_hashtypes }
        if cmdname == "sign-file":
            x509_path = get_real_path(tokens[-2], pwddir)
            record_raw_info(outfile, [outfile, x509_path,], pwddir, argv_str, pid, prog=prog, infile_checksums=hashes)
        else:
            record_raw_info(outfile, [outfile,], pwddir, argv_str, pid, prog=prog, infile_checksums=hashes)
    return outfile


def process_samefile_converter_command(prog, pwddir, argv_str, pid):
    '''
    Process the samefile converter command like strip/ranlib, etc.
    For example, the below commands in Linux kernel build or rpm build.
    ./tools/objtool/objtool orc generate --no-fp --retpoline kernel/fork.o
    ./scripts/sortextable vmlinux
    ./scripts/sorttable vmlinux
    ./tools/bpf/resolve_btfids/resolve_btfids vmlinux
    /usr/lib/rpm/debugedit -b /home/OpenOSC/rpmbuild/BUILD/openosc-1.0.5 -d /usr/src/debug/openosc-1.0.5-1.el8.x86_64 -i --build-id-seed=1.0.5-1.el8 -l /home/OpenOSC/rpmbuild/BUILD/openosc-1.0.5/debugsources.list /home/OpenOSC/rpmbuild/BUILDROOT/openosc-1.0.5-1.el8.x86_64/usr/lib64/libopenosc.so.0.0.0

    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command, this is a str, not integer
    '''
    cmdname = os.path.basename(prog)
    outfile = shell_command_record_same_file(prog, pwddir, argv_str, pid, cmdname)
    return outfile


def process_install_command(prog, pwddir, argv_str):
    '''
    Process the install command.
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    tokens = argv_str.split()
    if len(tokens) < 3 or tokens[-2][0] == '-':
        verbose("Warning: not yet interested in this install command with the same input/output file", LEVEL_1)
        return ''
    outfile = get_real_path(tokens[-1], pwddir)
    infile = get_real_path(tokens[-2], pwddir)
    if not os.path.isfile(infile):
        verbose("Warning: install command's infile not a file: " + infile, LEVEL_1)
        return ''
    if not os.path.isfile(outfile):
        verbose("Warning: not yet interested in this install command with the output file is probably a directory", LEVEL_1)
        return ''
    infiles = [infile,]
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def process_sign_file_command(prog, pwddir, argv_str, pid):
    '''
    Process the sign-file command
    Usage: scripts/sign-file [-dp] <hash algo> <key> <x509> <module> [<dest>]
           scripts/sign-file -s <raw sig> <hash algo> <x509> <module> [<dest>]
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    tokens = argv_str.split()
    if len(tokens) < 5:
        verbose("Warning: not interested in this short sign-file command", LEVEL_1)
        return ''
    new_tokens = []
    for token in tokens[1:]:
        if token == "-s":
            found_raw_sig_opt = True
        elif token[0] != '-':
            new_tokens.append(token)
    if len(new_tokens) not in (4,5):
        verbose("Warning: not interested in this mal-formed sign-file command", LEVEL_1)
        return ''
    module_name = new_tokens[3]
    if len(new_tokens) == 5 and module_name != new_tokens[4]:
        outfile = get_real_path(new_tokens[4], pwddir)
        infile = get_real_path(module_name, pwddir)
        x509_path = get_real_path(new_tokens[2], pwddir)
        if not args.pre_exec:  # different input/output file, record only if post_exec
            record_raw_info(outfile, [infile, x509_path,], pwddir, argv_str, prog=prog)
        return outfile
    else:
        # the input and output file are the same file
        shell_command_record_same_file(prog, pwddir, argv_str, pid, "sign-file")
        return get_real_path(module_name, pwddir)


def process_objcopy_command(prog, pwddir, argv_str, pid):
    '''
    Process the objcopy command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    tokens = argv_str.split()
    if len(tokens) < 3:
        verbose("Warning: not yet interested in this short objcopy command", LEVEL_1)
        return ''
    if tokens[-2][0] == '-' or "=" in tokens[-2]:
        # the input and output file are the same file
        return shell_command_record_same_file(prog, pwddir, argv_str, pid, "objcopy")
    # the input and output file are not the same file
    outfile = get_real_path(tokens[-1], pwddir)
    infile = get_real_path(tokens[-2], pwddir)
    if not os.path.isfile(infile):
        verbose("Warning: objcopy this infile is not a file: " + infile, LEVEL_1)
        return outfile
    if infile == outfile:
        # the input and output file are the same file, this is possible for "make rpm" of OpenOSC
        shell_command_record_same_file(prog, pwddir, argv_str, pid, "objcopy")
        return outfile
    if not args.pre_exec:  # different input/output file, record only if post_exec
        record_raw_info(outfile, [infile,], pwddir, argv_str, prog=prog)
    return outfile


def process_bzImage_build_command(prog, pwddir, argv_str):
    '''
    Process the bzImage build command in Linux kernel build.
    arch/x86/boot/tools/build arch/x86/boot/setup.bin arch/x86/boot/vmlinux.bin arch/x86/boot/zoffset.h arch/x86/boot/bzImage
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    tokens = argv_str.split()
    if len(tokens) < 5:
        verbose("Warning: not well-formated bzImage build command", LEVEL_1)
        return ''
    outfile = get_real_path(tokens[-1], pwddir)
    infiles = tokens[1 : len(tokens)-1]
    infiles = [get_real_path(afile, pwddir) for afile in infiles]
    record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
    return outfile


def is_empty_archive(afile):
    '''
    if an archive file is empty.
    '''
    cmd = 'ar -t ' + afile + ' 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if output:
        return False
    return True


def process_ar_command(prog, pwddir, argv_str, pid):
    '''
    Process the ar command
    Only "ar -c archive file1 file2", "ar -c archive @filelist", and "ar -s archive" are supported
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command, this is a str, not integer
    '''
    (outfile, infiles) = get_all_subfiles_in_ar_cmdline(argv_str, pwddir)
    if not outfile:
        return outfile
    if infiles:  # this should be "ar -cr archive file1 file2" cmd
        if not args.pre_exec:  # no need to do anything for pre-exec mode
            if is_empty_archive(outfile):  # no need to record or process if it is empty archive
                return outfile
            record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
        return outfile
    # this should be "ar -s archive" cmd, equivalent of "ranlib archive" cmd
    if is_empty_archive(outfile):  # no need to record or process if it is empty archive
        return outfile
    # save hashes of infiles to a temp file for later use in post-exec mode
    if args.pre_exec:
        for hash_alg in g_hashtypes:
            save_pre_exec_file_hashes([outfile,], pid, hash_alg)
    else:
        hashes = { hash_alg : collect_pre_exec_file_hashes(pid, hash_alg) for hash_alg in g_hashtypes }
        record_raw_info(outfile, [outfile,], pwddir, argv_str, pid, prog=prog, infile_checksums=hashes)
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
    record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
    return outfile


def process_jar_command(prog, pwddir, argv_str):
    '''
    Process the jar command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    # jar command is exactly like ar command
    (outfile, infiles) = get_all_subfiles_in_jar_cmdline(argv_str, pwddir)
    if not outfile:
        return outfile
    record_raw_info(outfile, infiles, pwddir, argv_str)
    return outfile


def create_pkg_symlink(outfile, hash_alg):
    '''
    Create symlink to ADG doc for .deb/.rpm package for user convenience
    :param outfile: the .deb or .rpm output file
    :param hash_alg: the hashing algorithm, sha1 or sha256
    '''
    symlink = os.path.join(g_bomdir, "symlinks", get_file_hash(outfile, hash_alg))
    if os.path.exists(symlink):
        # create additional symlink for convenience
        adg_link = outfile + ".omnibor_adg." + hash_alg
        pkgs_dir = os.path.join(g_bomdir, "pkgs")
        adg_link2 = os.path.join(pkgs_dir, os.path.basename(outfile) + ".omnibor_adg." + hash_alg)
        cmd = "ln -sfr " + symlink + " " + adg_link + " ; mkdir -p " + pkgs_dir + " ; ln -sfr " + symlink + " " + adg_link2
        os.system(cmd)


def create_pkg_symlinks(outfile):
    '''
    Create symlink to ADG doc for .deb/.rpm package for user convenience
    :param outfile: the .deb or .rpm output file
    '''
    for hash_alg in g_hashtypes:
        create_pkg_symlink(outfile, hash_alg)


def process_dpkg_deb_command(prog, pwddir, argv_str):
    '''
    Process the dpkg-deb command
    dpkg-deb --build debian/openosc ..
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    (outfile, infiles) = get_all_subfiles_in_dpkg_deb_cmdline(argv_str, pwddir)
    if not outfile or not infiles:
        return outfile
    record_raw_info(outfile, infiles, pwddir, argv_str, prog=prog)
    if "scratch-space" in outfile:  # example like building package 'openosc-dbgsym' in 'debian/.debhelper/scratch-space/build-openosc/openosc-dbgsym_1.0.5-1_amd64.deb'
        # build_and_rename_deb pattern: $build_dir = "debian/.debhelper/scratch-space/build-${package}"
        return outfile
    create_pkg_symlinks(outfile)
    return outfile


def process_rpmbuild_command(prog, pwddir, argv_str, pid):
    '''
    Process the rpmbuild command
    Only build from spec file or src rpm are supported, build from tarball is not supported
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    :param pid: PID of the shell command, this is a str, not integer
    '''
    rpmlist = get_all_subfiles_in_rpmbuild_cmdline(argv_str, pwddir)
    if not rpmlist:
        verbose("Warning: No RPM files generated by rpmbuild")
        return ''
    for outfile, infiles, unbundle_dir in rpmlist:
        record_raw_info(outfile, infiles, pwddir, argv_str, pid, prog=prog)
        os.system("rm -rf " + unbundle_dir)
        #shutil.rmtree(unbundle_dir)
        create_pkg_symlinks(outfile)
    return ''


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

    # Process the shell command, to record the raw info
    if is_cc_compiler(prog):
        outfile = process_gcc_command(prog, pwddir, argv_str, pid)
    elif is_cc_linker(prog):
        outfile = process_ld_command(prog, pwddir, argv_str, pid)
    elif prog == "/usr/bin/ar":
        outfile = process_ar_command(prog, pwddir, argv_str, pid)
    elif prog == "/usr/bin/objcopy":
        outfile = process_objcopy_command(prog, pwddir, argv_str, pid)
    elif prog == "arch/x86/boot/tools/build":
        outfile = process_bzImage_build_command(prog, pwddir, argv_str)
    elif prog == "/usr/lib/rpm/sepdebugcrcfix":
        outfile = process_sepdebugcrcfix_command(prog, pwddir, argv_str, pid)
    elif prog in g_strip_progs or prog == "/usr/bin/dwz":
        outfile = process_generic_shell_command(prog, pwddir, argv_str, pid)
    elif prog in g_samefile_converters:
        outfile = process_samefile_converter_command(prog, pwddir, argv_str, pid)
    elif prog == "/usr/bin/dpkg-deb":
        outfile = process_dpkg_deb_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/rpmbuild":
        outfile = process_rpmbuild_command(prog, pwddir, argv_str, pid)
    # install cmd does not change file hash, thus no need to process
    #elif prog == "/usr/bin/install":
    #    outfile = process_install_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/rustc":
        outfile = process_rustc_command(prog, pwddir, argv_str)
    elif prog == "scripts/sign-file":
        outfile = process_sign_file_command(prog, pwddir, argv_str, pid)
    elif prog == "bomsh_openat_file":
        outfile = process_samefile_converter_command(prog, pwddir, argv_str, pid)
    elif prog == "/usr/bin/javac":
        outfile = process_javac_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/jar":
        outfile = process_jar_command(prog, pwddir, argv_str)
    elif is_golang_prog(prog):
        outfile = process_golang_command(prog, pwddir, argv_str)
    # try to save the githash_cache file
    if not args.no_githash_cache_file and g_githash_cache:
        if len(g_githash_cache) > 1 and len(g_githash_cache) > g_githash_cache_initial_size:
            save_json_db(g_githash_cache_file, g_githash_cache)


############################################################
#### End of shell command handling routines ####
############################################################

def read_cve_check_rules(cve_check_dir):
    """
    Read cveadd/cvefix files for the CVE check rules.
    :param cve_check_dir: the directory to store the cveadd/cvefix files.
    returns a dict with all rules.
    """
    ret = {}
    if not os.path.exists(cve_check_dir):
        return ret
    cveadd_file = os.path.join(cve_check_dir, "cveadd")
    cvefix_file = os.path.join(cve_check_dir, "cvefix")
    if not (os.path.exists(cveadd_file) and os.path.exists(cvefix_file)):
        return ret
    ret["cveadd"] = yaml.safe_load(open(cveadd_file, "r"))
    ret["cvefix"] = yaml.safe_load(open(cvefix_file, "r"))
    #print(json.dumps(ret, indent=4, sort_keys=True))
    return ret


def convert_to_srcfile_cve_rules_db(cve_rules_db):
    """
    Convert to srcfile DB from the original cve_rules DB.
    :param cve_rules_db: the original DB read from cve_check_dir files
    returns a new dict with srcfile as key
    """
    ret = {}
    for rule_type in ("cveadd", "cvefix"):
        cve_rules = cve_rules_db[rule_type]
        update_srcfile_cve_rules_db(ret, cve_rules, rule_type)
    #print(json.dumps(ret, indent=4, sort_keys=True))
    return ret


def update_srcfile_cve_rules_db(srcfile_db, cve_rules, rule_type):
    """
    Update the srcfile CVE rules DB, from the cve_rules DB with cve as key.
    :param srcfile_db: cve_rules db to update, with src_file as key
    :param cve_rules: cve_rules db, with cve as key
    :param rule_type: cveadd or cvefix
    """
    for cve in cve_rules:
        cve_file_rules = cve_rules[cve]
        for afile in cve_file_rules:
            afile_rule_value = cve_file_rules[afile]
            if afile in srcfile_db:
                srcfile_rules = srcfile_db[afile]
                if cve in srcfile_rules:
                    srcfile_rules[cve][rule_type] = afile_rule_value
                else:
                    srcfile_rules[cve] = {rule_type: afile_rule_value}
            else:
                srcfile_db[afile] = {cve: {rule_type: afile_rule_value} }


def cve_check_rule(afile, rule, content=''):
    """
    Check if a file satisfies a CVE check rule.
    :param afile: the file to check against the CVE rule
    :param rule: the CVE rule to check
    returns True if the rule is satisfied, otherwise, False
    """
    if not content:
        content = read_text_file(afile)
    includes = []
    if "include" in rule:
        includes = rule["include"]
    for string in includes:
        verbose("CVE checking include string: " + str(string), LEVEL_3)
        if isinstance(string, dict):
            for key in string:
                strings = [key,] + string[key]
                if not any_string_in_content(strings, content):
                    return False
        elif string not in content:
            return False
    excludes = []
    if "exclude" in rule:
        excludes = rule["exclude"]
    for string in excludes:
        verbose("CVE checking exclude string: " + str(string), LEVEL_3)
        if isinstance(string, dict):
            for key in string:
                strings = [key,] + string[key]
                if any_string_in_content(strings, content):
                    return False
        elif string in content:
            return False
    return True


def cve_check_rules(afile, rules, content=''):
    ret = {}
    if not content:
        content = read_text_file(afile)
    for rule_type in ("cveadd", "cvefix"):
        if rule_type not in rules:
            continue
        verbose("Checking " + rule_type + " for source file: " + afile, LEVEL_3)
        rule = rules[rule_type]
        ret[rule_type] = cve_check_rule(afile, rule, content)
    return ret


def get_cve_check_source_file(afile, src_files):
    """
    Get the CVE check src_file for a file.
    :param afile: the file to check
    :param src_files: a dict with src_file as key
    """
    for src_file in src_files:
        if afile.endswith(src_file):
            return src_file
    return ''


def get_concise_str_for_cve_result(cve_result):
    """
    Get a concise string for CVE check result
    :param cve_result: the CVE check result, a dict
    """
    has_cve_list = []
    fixed_cve_list = []
    for cve in cve_result:
        result = cve_result[cve]
        if "cvefix" in result and result["cvefix"]:
            fixed_cve_list.append(cve)
        elif "cveadd" in result and result["cveadd"]:
            has_cve_list.append(cve)
    ret = ''
    if has_cve_list:
        ret += " has_cve:" + ",".join(has_cve_list)
    if fixed_cve_list:
        ret += " fixed_cve:" + ",".join(fixed_cve_list)
    return ret


def cve_check_rule_for_file(afile):
    """
    Check the CVE rule for a file and return a string for the CVE result
    :param afile: the file to check against the CVE rules
    returns a string
    """
    ret = {}
    src_file = get_cve_check_source_file(afile, g_cve_check_rules)
    if not src_file:
        return ''
    content = read_text_file(afile)
    cve_rules = g_cve_check_rules[src_file]
    for cve in cve_rules:
        cve_rule = cve_rules[cve]
        verbose("Checking " + cve + " for source file: " + afile, LEVEL_3)
        ret[cve] = cve_check_rules(afile, cve_rule, content)
    verbose("cve check result for file: " + afile, LEVEL_3)
    verbose(json.dumps(ret, indent=4, sort_keys=True), LEVEL_3)
    return get_concise_str_for_cve_result(ret)

############################################################
#### End of CVE check rules handling routines ####
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
    parser.add_argument('-b', '--bom_dir',
                    help = "the directory to store the generated OmniBOR doc files")
    parser.add_argument('-l', '--logfile',
                    help = "the log file, must be absolute path, not relative path")
    parser.add_argument('-w', '--watched_programs',
                    help = "the comma-separated list of programs to watch")
    parser.add_argument('--watched_pre_exec_programs',
                    help = "the comma-separated list of pre_exec programs to watch")
    parser.add_argument('-t', '--trace_logfile',
                    help = "the verbose trace log file")
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('--cc_compilers',
                    help = "the comma-separated C compiler paths, like /usr/bin/gcc,/usr/bin/clang")
    parser.add_argument('--cc_linkers',
                    help = "the comma-separated C linker paths, like /usr/bin/ld,/usr/bin/llvm-ld")
    #parser.add_argument('--strip_programs',
    #                help = "the comma-separated strip-like program paths, like /usr/bin/eu-strip")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument("--embed_bom_after_commands",
                    help = "embed .bom ELF section after a command on an ELF binary, which is a list of comma-separated programs")
    parser.add_argument('--cve_check_dir',
                    help = "do additional CVE check for source files defined in cveadd/cvefix files of the directory")
    parser.add_argument("--pre_exec",
                    action = "store_true",
                    help = "pre-exec mode, invoked before executing the process")
    parser.add_argument("-n", "--no_auto_embed_bom_for_compiler_linker",
                    action = "store_true",
                    help = "not automatically embed bom-id to ELF binary for cc/ld commands")
    parser.add_argument("--no_dependent_headers",
                    action = "store_true",
                    help = "not include C header files for hash tree dependency")
    parser.add_argument("--new_omnibor_doc_for_unary_transform",
                    action = "store_true",
                    help = "generate new OmniBOR doc/identifier for single input/output file transform")
    parser.add_argument("--record_raw_bomid",
                    action = "store_true",
                    help = "record raw info for bom_id of input/output files if it exists")
    parser.add_argument("--record_build_tool",
                    action = "store_true",
                    help = "record build tool information")
    parser.add_argument("--no_githash_cache_file",
                    action = "store_true",
                    help = "not use a helper cache file to store githash of header files")
    parser.add_argument("--check_usr_merge",
                    action = "store_true",
                    help = "check if usrmerge feature is enabled")
    parser.add_argument("--create_no_adg",
                    action = "store_true",
                    help = "not create ADG (Artifact Dependency Graph) documents, as well as symlinks")
    parser.add_argument("--read_bomid_from_file_for_adg",
                    action = "store_true",
                    help = "record bom-id from ELF file when creating ADG doc")
    parser.add_argument("--create_no_adg_for_pkgs",
                    action = "store_true",
                    help = "not create ADG docs for .deb/.rpm package")
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

    global g_logfile
    global g_trace_logfile
    global g_raw_logfile
    global g_tmpdir
    global g_bomdir
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
    if args.bom_dir:
        g_bomdir = args.bom_dir
    g_bomdir = get_or_create_dir(g_bomdir)
    if args.no_auto_embed_bom_for_compiler_linker:
        g_embed_bom_after_commands.clear()
    if args.embed_bom_after_commands:
        g_embed_bom_after_commands.extend(args.embed_bom_after_commands.split(","))
    if args.cc_compilers:
        g_cc_compilers.extend(args.cc_compilers.split(","))
    if args.cc_linkers:
        g_cc_linkers.extend(args.cc_linkers.split(","))
    #if args.strip_programs:
    #    g_strip_progs.extend(args.strip_programs.split(","))
    if args.hashtype:  # only sha1 and sha256 are supported for now
        if "sha1" in args.hashtype:
            g_hashtypes.append("sha1")
        if "sha256" in args.hashtype:
            g_hashtypes.append("sha256")
    if not g_hashtypes:
        g_hashtypes.append("sha1")

    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    verbose("\n==== BOM-HOOK PID: " + str(os.getpid()) + " started ====", LEVEL_1)

    (pid, pwddir, prog, argv_str) = read_shell_command(args.shell_cmd_file)
    # always record the shell command in trace_logfile for normal post_exec mode
    if not args.pre_exec and args.verbose:
        append_text_file(g_trace_logfile, ' '.join((pid, pwddir, prog, argv_str, '\n')))

    if args.pre_exec:
        # Fewer number of programs to watch in pre_exec mode
        progs_to_watch = g_samefile_converters + g_strip_progs + ["/usr/bin/ar", "/usr/bin/objcopy", "/usr/bin/dwz", "/usr/lib/rpm/sepdebugcrcfix", "scripts/sign-file", "bomsh_openat_file"]
        if args.watched_pre_exec_programs:
            progs_to_watch.extend(args.watched_pre_exec_programs.split(","))
    else:
        progs_to_watch = g_cc_compilers + g_cc_linkers + g_samefile_converters + g_strip_progs + ["/usr/bin/ar", "/usr/bin/objcopy", "arch/x86/boot/tools/build",
                     "/usr/bin/rustc", "/usr/bin/dwz", "/usr/lib/rpm/sepdebugcrcfix", "scripts/sign-file", "bomsh_openat_file", "/usr/bin/javac", "/usr/bin/jar"]
        if not args.create_no_adg_for_pkgs:
            progs_to_watch.extend( ("/usr/bin/dpkg-deb", "/usr/bin/rpmbuild") )
        if args.watched_programs:
            progs_to_watch.extend(args.watched_programs.split(","))
    if prog in progs_to_watch:
        verbose(prog + " is on the list, processing the command...", LEVEL_1)
        process_shell_command(prog, pwddir, argv_str, pid)
    else:
        if args.pre_exec:
            verbose(prog + " is not on the pre-exec list, we are done", LEVEL_1)
        else:
            verbose(prog + " is not on the list, we are done", LEVEL_1)
    verbose("==== BOM-HOOK PID: " + str(os.getpid()) + " exited ====", LEVEL_1)


if __name__ == '__main__':
    main()
