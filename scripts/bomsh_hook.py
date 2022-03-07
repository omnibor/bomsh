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
Bomsh hookup script to generate BOM hash tree and gitBOM docs during software build.

Use by Bomsh or Bomtrace.

December 2021, Yongkui Han
"""

import argparse
import sys
import os
import shutil
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
BOM_HOOK_STR = "### BOM-HOOK ###"
BOM_HOOK_END_STR = "### BOM-HOOK-END ###\n"

g_tmpdir = "/tmp"
g_trace_logfile = "/tmp/bomsh_hook_trace_logfile"
g_logfile = "/tmp/bomsh_hook_logfile"
g_jsonfile = "/tmp/bomsh_hook_jsonfile"
g_bomdir = os.path.join(os.getcwd(), ".gitbom")
g_object_bomdir = os.path.join(g_bomdir, "objects")
g_bomsh_bomdir = os.path.join(g_bomdir, "metadata", "bomsh")
g_with_bom_dir = os.path.join(g_bomsh_bomdir, "with-bom-files")
g_cc_compilers = ["/usr/bin/gcc", "/usr/bin/clang", "/usr/bin/cc", "/usr/bin/g++"]
g_cc_linkers = ["/usr/bin/ld", "/usr/bin/ld.bfd", "/usr/bin/gold"]

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
        print(string)


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
    print ("save_json_db: db file is " + db_file)
    #db["version"] = TOOL_VERSION
    #db["bomsh_hook_runcmd"] = g_bomsh_runcmd
    #db["bomsh_hook_cwd"] = g_bomsh_cwd
    try:
        f = open(db_file, 'w')
    except IOError as e:
        print ("I/O error({0}): {1}".format(e.errno, e.strerror))
        print ("Error in save_json_db, skipping it.")
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
#### Start of gitbom routines ####
############################################################

def save_gitbom_doc(gitbom_doc_file, destdir, checksum=''):
    '''
    Save the generated gitBOM doc file to destdir.
    :param gitbom_doc_file: the generated gitBOM doc file to save
    :param destdir: destination directory to store the created gitBOM doc file
    :param checksum: the githash of gitbom_doc_file
    '''
    if checksum:
        ahash = checksum
    else:
        ahash = get_git_file_hash(gitbom_doc_file)
    subdir = os.path.join(destdir, ahash[:2])
    object_file = os.path.join(subdir, ahash[2:])
    if os.path.exists(object_file):
        return
    cmd = 'mkdir -p ' + subdir + ' && /usr/bin/cp ' + gitbom_doc_file + ' ' + object_file + ' || true'
    os.system(cmd)


def create_gitbom_doc_text(infile_hashes, db):
    """
    Create the gitBOM doc text contents
    :param infile_hashes: the list of input files, with its hashes, essentially a dict
    :param db: gitBOM DB with {file-hash => its gitBOM hash} mapping
    """
    if not infile_hashes:
        return ''
    lines = []
    for afile in infile_hashes:
        ahash = infile_hashes[afile]
        line = "blob " + ahash
        if ahash in db:
            gitbom_hash = db[ahash]
            line += " bom " + gitbom_hash
        lines.append(line)
    lines.sort()
    return '\n'.join(lines) + '\n'


def create_gitbom_doc(infile_hashes, db, destdir):
    """
    Create the gitBOM doc text contents
    :param infile_hashes: the list of input files with its hashes
    :param db: gitBOM DB with {file-hash => its gitBOM hash} mapping
    :param destdir: destination directory to create the gitbom doc file
    returns the git-hash of the created gitBOM doc.
    """
    lines = create_gitbom_doc_text(infile_hashes, db)
    output_file = os.path.join(g_tmpdir, "bomsh_temp_gitbom_file")
    write_text_file(output_file, lines)
    ahash = get_git_file_hash(output_file)
    save_gitbom_doc(output_file, destdir, ahash)
    return ahash


g_embed_bom_script = '''
git hash-object HELLO_GITBOM_FILE | head --bytes=-1 | xxd -r -p > /tmp/bomsh_bom_gitref_file
objcopy --add-section .bom=/tmp/bomsh_bom_gitref_file HELLO_FILE HELLO_WITH_BOM_FILE
'''

g_update_bom_script = '''
git hash-object HELLO_GITBOM_FILE | head --bytes=-1 | xxd -r -p > /tmp/bomsh_bom_gitref_file
objcopy --remove-section=.bom HELLO_FILE /tmp/hello.no_bom
objcopy --add-section .bom=/tmp/bomsh_bom_gitref_file /tmp/hello.no_bom HELLO_WITH_BOM_FILE
'''

g_embed_script = '''
echo -n "blob " > /tmp/hello.with_bom.gitbom
git hash-object HELLO_FILE | head --bytes=-1 >> /tmp/hello.with_bom.gitbom
echo -n " bom " >> /tmp/hello.with_bom.gitbom
git hash-object HELLO_GITBOM_FILE >> /tmp/hello.with_bom.gitbom
git hash-object /tmp/hello.with_bom.gitbom | head --bytes=-1 | xxd -r -p > /tmp/bomsh_bom_gitref_file
objcopy --add-section .bom=/tmp/bomsh_bom_gitref_file HELLO_FILE HELLO_WITH_BOM_FILE
'''

def embed_gitbom_hash_elf_section(afile, gitbom_doc, outfile):
    """
    Embed the .bom ELF section into an ELF file.
    :param afile: the ELF file to insert the embedded .bom section
    :param gitbom_doc: gitBOM doc for this afile
    :param outfile: output file with the .bom ELF section
    """
    #verbose("afile: " + afile + "gitbom_doc: " + gitbom_doc + " outfile: " + outfile)
    embed_script = g_embed_bom_script.replace("HELLO_FILE", afile).replace("HELLO_GITBOM_FILE", gitbom_doc).replace("HELLO_WITH_BOM_FILE", outfile)
    #verbose("The embed_bom script:" + embed_script)
    output = get_shell_cmd_output(embed_script)
    return


def embed_gitbom_hash_archive_entry(afile, gitbom_doc, outfile, pwd, argv_str):
    """
    Embed the .bom archive entry into an archive file.
    The original ar command is re-run with one extra .bom file
    :param afile: the archive file to insert the embedded .bom archive entry
    :param gitbom_doc: gitBOM doc for this afile
    :param outfile: output file with the .bom archive entry
    :param pwd: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    """
    #verbose("afile: " + afile + "gitbom_doc: " + gitbom_doc + " outfile: " + outfile)
    tokens = argv_str.split()
    if afile != os.path.abspath(os.path.join(pwd, tokens[2])):
        return
    tokens[2] = outfile
    if g_with_bom_dir:
        temp_bom_file = os.path.join(g_with_bom_dir, ".bom")
    else:
        temp_bom_file = g_tmpdir + "/.bom"
    cmd = 'git hash-object ' + gitbom_doc + ' | head --bytes=-1 | xxd -r -p > ' + temp_bom_file
    cmd += " ; cd " + pwd + " ; " + ' '.join(tokens) + " " + temp_bom_file + " || true"
    verbose("The embed_archive_bom cmd: " + cmd)
    output = get_shell_cmd_output(cmd)
    return


############################################################
#### Start of shell command read/parse routines ####
############################################################

'''
Format of /tmp/bomsh_cmd file, which records shell command info:
pid: 75627 ppid: 75591 pgid: 73910
/home/OpenOSC/src
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


def get_input_files_from_subfiles(subfiles, outfile):
    """
    Returns the input files only, excluding the outfile
    :param subfiles: the list of all files, including the outfile
    :param outfile: the output file, to filter out from the subfiles
    """
    return [f for f in subfiles if f != outfile]


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
    if not infiles or outfile[-7:] != "piggy.o":
        return infiles
    piggy_S_file = ''
    for afile in infiles:
        if afile[-7:] == "piggy.S":
            piggy_S_file = os.path.abspath(os.path.join(pwd, afile))
            break
    if not piggy_S_file or not os.path.isfile(piggy_S_file):
        return infiles
    lines = read_text_file(piggy_S_file).splitlines()
    vmlinux_bin = ''
    for line in lines:
        if line[:9] == '.incbin "':
            vmlinux_bin = line[9: len(line)-4]  # directly get vmlinux.bin instead of vmlinux.bin.gz
            vmlinux_bin = os.path.abspath(os.path.join(pwd, vmlinux_bin))
            break
    if vmlinux_bin and os.path.isfile(vmlinux_bin):
        return infiles + [vmlinux_bin,]  # add vmlinux.bin file to the list of input files
    return infiles


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
    if output_file[0] != '/':
        output_file = os.path.join(pwd, output_file)
    output_file = os.path.abspath(output_file)
    skip_token_list = ("-MT", "-MF", "-x", "-I", "-B", "-L", "-isystem", "-iquote", "-idirafter", "-iprefix", "-isysroot", "-iwithprefix", "-iwithprefixbefore", "-imultilib", "-include")
    subfiles = []
    skip_token = False  # flag for skipping one single token
    for token in tokens[1:]:
        # C linker ld has a few more options that come with next token
        if token in skip_token_list or (is_cc_linker(prog) and token in ("-m", "-z", "-y", "-Y", "-soname")):
            # the next token must be skipped
            skip_token = True
        if token[0] == '-':
            continue
        if skip_token:
            skip_token = False  # turn off this flag after skipping this token
            continue
        subfile = token
        if token[0] != '/':
            subfile = os.path.join(pwd, subfile)
        if os.path.isfile(subfile):
            subfiles.append(subfile)
        else:
            verbose("Warning: this subfile is not file: " + subfile)
    # subfiles contain both input files and the output file
    subfiles = [os.path.abspath(afile) for afile in subfiles]
    infiles = [afile for afile in subfiles if afile != output_file]
    infiles = handle_linux_kernel_piggy_object(output_file, infiles, pwd)
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
    output_file = tokens[2]
    if output_file[0] != '/':
        output_file = os.path.join(pwd, output_file)
    output_file = os.path.abspath(output_file)
    subfiles = []
    for token in tokens[3:]:
        subfile = token
        if token[0] != '/':
            subfile = os.path.join(pwd, subfile)
        subfiles.append(subfile)
    # subfiles contain only input files
    subfiles = [os.path.abspath(afile) for afile in subfiles]
    return (output_file, subfiles)


def get_all_subfiles_in_jar_cmdline(jarline, pwd):
    """
    Returns the input/output files of the jar shell command line.
    :param jarline: the jar command line
    :param pwd: the present working directory for this ar command
    """
    tokens = jarline.split()
    if len(tokens) < 3:
        return ('', [])
    output_file = tokens[2]
    if output_file[0] != '/':
        output_file = os.path.join(pwd, output_file)
    output_file = os.path.abspath(output_file)
    subfiles = []
    for token in tokens[3:]:
        subfile = token
        if token[0] != '/':
            subfile = os.path.join(pwd, subfile)
        if os.path.exists(subfile):
            subfiles.append(subfile)
    # subfiles contain only input files
    subfiles = [os.path.abspath(afile) for afile in subfiles]
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
    verbose("output of git_hash:\n" + output, LEVEL_3)
    if output:
        return output.strip()
    return ''


def get_git_files_hash(afiles):
    '''
    Get the git hash of a list of files.
    :param afiles: the files to calculate the git hash or digest.
    '''
    hashes = {}
    for afile in afiles:
        hashes[afile] = get_git_file_hash(afile)
    return hashes


def update_hash_tree_db(hashes, outfile, argv_str):
    '''
    Update the hashtree DB with new hashes and its outfile
    :param hashes: dict of {file : checksum}, including both outfile and all input files
    :param outfile: the output file, one of the key in the hashes dict
    :param argv_str: the full command with all its command line options/parameters
    '''
    # update the hash tree
    db = {}
    if os.path.exists(g_jsonfile):
        db = load_json_db(g_jsonfile)
    for afile, ahash in hashes.items():
        if not ahash:  # afile must not exist, thus empty hash from get_git_file_hash
            continue
        if ahash not in db:  # not exist, then create this hash entry
            db[ahash] = {"file_path": afile}
        afile_db = db[ahash]
        if afile_db["file_path"] != afile:
            verbose("Warning: checksum " + ahash + " has two file paths: " + afile + " and " + afile_db["file_path"])
            # create file_paths with the list of all file_paths
            if "file_paths" in afile_db:
                if afile not in afile_db["file_paths"]:
                    afile_db["file_paths"].append(afile)
            else:
                afile_db["file_paths"] = [afile_db["file_path"], afile]
        if afile == outfile:  # hash tree update for outfile only
            input_files = get_input_files_from_subfiles(hashes.keys(), outfile)
            hash_tree = sorted([hashes[f] for f in input_files])
            if "hash_tree" in afile_db:
                verbose("Warning: checksum " + ahash + " already has hash tree. new file path: " + afile)
                set1 = set(afile_db["hash_tree"])
                set2 = set(hash_tree)
                if set1 == set2:  # this should be the common case: same .c file is compiled twice to generated two .o files with different file name.
                    verbose("Warning: Good that checksum " + ahash + " has the same hash tree. old file path: " + str(afile_db["file_path"]))
                    if "file_paths" in afile_db:
                        verbose("Warning: file paths: " + str(afile_db["file_paths"]))
                else:
                    verbose("Warning!! Bad that checksum " + ahash + " has a different hash tree. old file path: " + str(afile_db["file_path"]))
                    if "file_paths" in afile_db:
                        verbose("Warning!! file paths: " + str(afile_db["file_paths"]))
                    # create hash_trees with the list of all hash_trees
                    if "hash_trees" in afile_db:
                        afile_db["hash_trees"].append(hash_tree)
                    else:
                        afile_db["hash_trees"] = [afile_db["hash_tree"], hash_tree]
            else:
                afile_db["hash_tree"] = hash_tree
            # Also add the build command to the database
            verbose(outfile + " is outfile, update build_cmd: " + argv_str)
            if "build_cmd" in afile_db and afile_db["build_cmd"] != argv_str:
                verbose("Warning: checksum " + ahash + " already has build command. new file path: " + afile)
                # create build_cmds with the list of all build commands
                if "build_cmds" in afile_db:
                    if argv_str not in afile_db["build_cmds"]:
                        afile_db["build_cmds"].append(argv_str)
                else:
                    afile_db["build_cmds"] = [afile_db["build_cmd"], argv_str]
            if "build_cmd" not in afile_db:
                afile_db["build_cmd"] = argv_str
    # Finally save the updated DB to the JSON file
    save_json_db(g_jsonfile, db)


def update_gitbom_dir(bomdir, hashes, outfile, prog, pwd, argv_str):
    '''
    Update the gitBOM directory with new hashes and its outfile
    :param bomdir: the gitBOM directory
    :param hashes: dict of {file : checksum}, including both outfile and all input files
    :param outfile: the output file, one of the key in the hashes dict
    :param prog: the program binary
    :param pwd: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    jsonfile = os.path.join(g_bomsh_bomdir, "bomsh_gitbom_doc_mapping")
    db = {}
    if os.path.exists(jsonfile):
        db = load_json_db(jsonfile)
    infile_hashes = {afile:ahash for afile,ahash in hashes.items() if afile != outfile}
    if not infile_hashes:
        verbose("Warning: prog is " + prog + ", its infile is empty, skipping gitBOM doc update for outfile " + outfile)
        return
    gitbom_doc_hash = create_gitbom_doc(infile_hashes, db, bomdir)
    verbose("prog is " + prog + ", Created gitBOM file " + gitbom_doc_hash + " for outfile " + outfile)
    db[hashes[outfile]] = gitbom_doc_hash
    # Finally save the updated DB to the JSON file
    save_json_db(jsonfile, db)
    if not args.embed_bom_section:
        return
    # Try to embed the .bom ELF section or archive entry
    gitbom_doc = os.path.join(bomdir, gitbom_doc_hash[:2], gitbom_doc_hash[2:])
    with_bom_file = os.path.join(g_with_bom_dir, hashes[outfile] + "-with_bom-" + gitbom_doc_hash + "-" + os.path.basename(outfile))
    if is_cc_compiler(prog) or is_cc_linker(prog):
        verbose("Create ELF with_bom file: " + with_bom_file)
        embed_gitbom_hash_elf_section(outfile, gitbom_doc, with_bom_file)
    elif prog == "/usr/bin/ar":
        verbose("Create archive with_bom file: " + with_bom_file)
        embed_gitbom_hash_archive_entry(outfile, gitbom_doc, with_bom_file, pwd, argv_str)


def update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, logfile, pwd):
    '''
    Update the hash tree DB and the gitBOM doc for an output file.
    :param outfile: the output file for the shell command
    :param infiles: the list of input files for the shell command
    :param prog: the program binary
    :param argv_str: the full command with all its command line options/parameters
    :param logfile: the log file to write verbose debug info
    :param pwd: the present working directory for the command
    '''
    verbose("update_gitbom, outfile: " + outfile + " infiles: " + str(infiles), LEVEL_3, logfile)
    if not outfile or not os.path.exists(outfile):
        verbose("Warning: outfile " + outfile + " does not exist, skipping hash tree DB update")
        return
    subfiles = [outfile,] + infiles
    hashes = get_git_files_hash(subfiles)
    verbose("output file: " + outfile + " input files of shell command line: " + str(infiles), LEVEL_0, logfile)
    verbose("all subfiles githash: " + str(hashes), LEVEL_3, logfile)
    update_hash_tree_db(hashes, outfile, argv_str)
    if not infiles or not is_elf_file(outfile):  # archive file must also contain valid ELF files.
        verbose("Warning: empty infiles or outfile " + outfile + " is not ELF file, skipping gitBOM doc update")
        return
    if args.bom_dir:
        update_gitbom_dir(g_object_bomdir, hashes, outfile, prog, pwd, argv_str)


############################################################
#### End of hash/checksum routines ####
############################################################

def is_elf_file(afile):
    """
    Check if a file is an ELF file.

    :param afile: String, name of file to be checked
    :returns True if the file is ELF format file. Otherwise, return False.
    """
    cmd = "readelf -Sl " + cmd_quote(afile) + " 2>/dev/null || true"
    if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6):
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    else:
        output = subprocess.check_output(cmd, shell=True, errors="backslashreplace", universal_newlines=True)
    if output:
        return True
    return False


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
    outfile = all_files[0].strip()
    if outfile[0] != '/':
        outfile = os.path.join(pwd, outfile)
    outfile = os.path.abspath(outfile)
    afiles = all_files[1].strip()
    afiles = ' '.join(afiles.split("\\\n"))  # each continuation line by "\\\n"
    afiles = afiles.split()
    depend_files = [afile if afile[0] == '/' else os.path.join(pwd, afile) for afile in afiles]
    depend_files = [os.path.abspath(afile) for afile in depend_files]
    return (outfile, depend_files)


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
                depend_file = tokens[i+1]
                if depend_file[0] != '/':
                    depend_file = os.path.join(pwd, depend_file)
                return read_depend_file(depend_file, pwd)
        return depends
    depend_file = os.path.join(g_tmpdir, "bomsh_hook_target_dependency.d")
    cmd = "cd " + pwd + " ; " + escape_shell_command(gcc_cmd) + " -MD -MF " + depend_file + " || true"
    get_shell_cmd_output(cmd)
    if os.path.exists(depend_file):
        depends = read_depend_file(depend_file, pwd)
        os.remove(depend_file)
    return depends


def process_gcc_command(prog, pwddir, argv_str):
    '''
    Process the gcc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    gcc_logfile = os.path.join(g_tmpdir, "bomsh_hook_gcc_logfile")
    verbose("\npwd: " + pwddir + " Found one gcc command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one gcc command: " + argv_str, LEVEL_0, gcc_logfile)
    (outfile, infiles) = get_all_subfiles_in_gcc_cmdline(argv_str, pwddir, prog)
    verbose("get_all_subfiles_in_gcc_cmdline, outfile: " + outfile + " infiles: " + str(infiles), LEVEL_4)
    infiles2 = []
    # for C source code file, we can try add the C header file dependency
    if does_c_file_exist_in_files(infiles) and not args.no_dependent_headers:
        (outfile2, infiles2) = get_c_file_depend_files(argv_str, pwddir)
        verbose("get_c_depend_files, outfile2: " + outfile2 + " infiles2: " + str(infiles2), LEVEL_4)
    if infiles2:
        infiles = infiles2
    verbose("get_all_subfiles, outfile: " + outfile + " infiles: " + str(infiles), LEVEL_3)
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, gcc_logfile, pwddir)


def process_ld_command(prog, pwddir, argv_str):
    '''
    Process the ld command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    ld_logfile = os.path.join(g_tmpdir, "bomsh_hook_ld_logfile")
    verbose("\npwd: " + pwddir + " Found one ld command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one ld command: " + argv_str, LEVEL_0, ld_logfile)
    # ld command can be handled the same way as gcc command, for ouptfile,infiles
    (outfile, infiles) = get_all_subfiles_in_gcc_cmdline(argv_str, pwddir, prog)
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, ld_logfile, pwddir)


def find_objtool_original_hash(outfile):
    '''
    Try to find the checksum of the original objtool output file.
    '''
    db = {}
    if os.path.exists(g_jsonfile):
        db = load_json_db(g_jsonfile)
    for ahash in db:
        entry = db[ahash]
        if "file_path" in entry and entry["file_path"] == outfile or ("file_paths" in entry and outfile in entry["file_paths"]):
            return ahash
    return ''


def shell_command_update_same_file(prog, pwddir, argv_str, logfile, cmdname):
    '''
    The shell command update the single file, like objtool/strip/ranlib. the last token must the file to update.
    '''
    tokens = argv_str.split()
    outfile = tokens[-1]
    if outfile[0] != "/":
        outfile = os.path.abspath(os.path.join(pwddir, outfile))
    if not os.path.isfile(outfile):
        verbose("outfile " + outfile + " is not a file, ignore this command", LEVEL_0, logfile)
        return
    orig_hash = find_objtool_original_hash(outfile)
    if not orig_hash:
        verbose("cannot find the original hash of outfile " + outfile, LEVEL_0, logfile)
        return
    new_hash = get_git_file_hash(outfile)
    if orig_hash == new_hash:
        verbose("the new hash is the same as the original hash of outfile " + outfile, LEVEL_0, logfile)
        return
    hashes = {outfile + "." + cmdname + "-pre" : orig_hash, outfile: new_hash}
    verbose(cmdname + " output file: " + outfile + " githash: " + str(hashes), LEVEL_0, logfile)
    update_hash_tree_db(hashes, outfile, argv_str)
    if not is_elf_file(outfile):
        verbose("Warning: outfile " + outfile + " is not ELF file, skipping gitBOM doc update")
        return
    if args.bom_dir:
        update_gitbom_dir(g_object_bomdir, hashes, outfile, prog, pwddir, argv_str)


def process_objtool_command(prog, pwddir, argv_str):
    '''
    Process the objtool command in Linux kernel build.
    ./tools/objtool/objtool orc generate --no-fp --retpoline kernel/fork.o
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    objtool_logfile = os.path.join(g_tmpdir, "bomsh_hook_objtool_logfile")
    verbose("\npwd: " + pwddir + " Found one objtool command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one objtool command: " + argv_str, LEVEL_0, objtool_logfile)
    shell_command_update_same_file(prog, pwddir, argv_str, objtool_logfile, "objtool")


def process_strip_command(prog, pwddir, argv_str):
    '''
    Process the strip command.
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one strip command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one strip command: " + argv_str, LEVEL_0, logfile)
    shell_command_update_same_file(prog, pwddir, argv_str, logfile, "strip")


def process_ranlib_command(prog, pwddir, argv_str):
    '''
    Process the ranlib command.
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one ranlib command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one ranlib command: " + argv_str, LEVEL_0, logfile)
    shell_command_update_same_file(prog, pwddir, argv_str, logfile, "ranlib")


def process_sepdebugcrcfix_command(prog, pwddir, argv_str):
    '''
    Process the sepdebugcrcfix command.
    /usr/lib/rpm/sepdebugcrcfix usr/lib/debug .//usr/lib64/libopenosc.so.0.0.0
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one sepdebugcrcfix command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one sepdebugcrcfix command: " + argv_str, LEVEL_0, logfile)
    shell_command_update_same_file(prog, pwddir, argv_str, logfile, "sepdebugcrcfix")


def process_install_command(prog, pwddir, argv_str):
    '''
    Process the install command.
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one install command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one install command: " + argv_str, LEVEL_0, logfile)
    tokens = argv_str.split()
    if len(tokens) < 3 or tokens[-2][0] == '-':
        verbose("Warning: not yet interested in this install command with the same input/output file", LEVEL_0, logfile)
        return
    outfile = tokens[-1]
    if outfile[0] != "/":
        outfile = os.path.abspath(os.path.join(pwddir, outfile))
    infile = tokens[-2]
    if infile[0] != "/":
        infile = os.path.abspath(os.path.join(pwddir, infile))
    if not os.path.isfile(infile):
        verbose("Warning: install command's infile not a file: " + infile, LEVEL_0, logfile)
        return
    if not os.path.isfile(outfile):
        verbose("Warning: not yet interested in this install command with the output file is probably a directory", LEVEL_0, logfile)
        return
    infiles = [infile,]
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, logfile, pwddir)


def process_objcopy_command(prog, pwddir, argv_str):
    '''
    Process the objcopy command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one objcopy command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one objcopy command: " + argv_str, LEVEL_0, logfile)
    tokens = argv_str.split()
    if len(tokens) < 3:
        verbose("Warning: not yet interested in this short objcopy command", LEVEL_0, logfile)
        return
    if tokens[-2][0] == '-' or "=" in tokens[-2]:
        # the input and output file are the same file
        shell_command_update_same_file(prog, pwddir, argv_str, logfile, "objcopy")
        return
    # the input and output file are not the same file
    outfile = tokens[-1]
    if outfile[0] != "/":
        outfile = os.path.abspath(os.path.join(pwddir, outfile))
    infile = tokens[-2]
    if infile[0] != "/":
        infile = os.path.abspath(os.path.join(pwddir, infile))
    if not os.path.isfile(infile):
        verbose("Warning: this infile is not a file: " + infile, LEVEL_0, logfile)
        return
    if infile == outfile:
        # the input and output file are the same file, this is possible for "make rpm" of OpenOSC
        shell_command_update_same_file(prog, pwddir, argv_str, logfile, "objcopy")
        return
    infiles = [infile,]
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, logfile, pwddir)


def process_sortextable_command(prog, pwddir, argv_str):
    '''
    Process the sortextable command in Linux kernel build.
    ./scripts/sortextable vmlinux
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one sortextable command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one sortextable command: " + argv_str, LEVEL_0, logfile)
    shell_command_update_same_file(prog, pwddir, argv_str, logfile, "sortextable")


def process_bzImage_build_command(prog, pwddir, argv_str):
    '''
    Process the bzImage build command in Linux kernel build.
    arch/x86/boot/tools/build arch/x86/boot/setup.bin arch/x86/boot/vmlinux.bin arch/x86/boot/zoffset.h arch/x86/boot/bzImage
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    logfile = os.path.join(g_tmpdir, "bomsh_hook_objcopy_logfile")
    verbose("\npwd: " + pwddir + " Found one bzImage build command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one bzImage build command: " + argv_str, LEVEL_0, logfile)
    tokens = argv_str.split()
    if len(tokens) < 5:
        verbose("Warning: not well-formated bzImage build command", LEVEL_0, logfile)
        return
    outfile = os.path.abspath(os.path.join(pwddir, tokens[-1]))
    infiles = tokens[1 : len(tokens)-1]
    infiles = [os.path.abspath(os.path.join(pwddir, afile)) for afile in infiles]
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, logfile, pwddir)


def process_ar_command(prog, pwddir, argv_str):
    '''
    Process the gcc command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    ar_logfile = os.path.join(g_tmpdir, "bomsh_hook_ar_logfile")
    verbose("\npwd: " + pwddir + " Found one ar command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one ar command: " + argv_str, LEVEL_0, ar_logfile)
    (outfile, infiles) = get_all_subfiles_in_ar_cmdline(argv_str, pwddir)
    if infiles:  # if empty infiles, no need to proceed
        update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, ar_logfile, pwddir)


# found out that java compiler like maven can compile .java to .class in memory without creating new process
# so this javac process hookup will not work, same reason for jar command hookup.
def process_javac_command(prog, pwddir, argv_str):
    '''
    Process the javac command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    javac_logfile = os.path.join(g_tmpdir, "bomsh_hook_javac_logfile")
    verbose("\npwd: " + pwddir + " Found one javac command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one javac command: " + argv_str, LEVEL_0, javac_logfile)
    if ".java " not in argv_str and argv_str[-5:] != ".java":
        verbose("Warning: no input .java file for javac line: " + argv_str)
        return
    tokens = argv_str.split()
    for token in tokens:
        if token[-5:] == ".java":
            java_file = token
            outfile = token[:-5] + ".class"
            break
    if java_file[0] != '/':
        java_file = os.path.join(pwddir, java_file)
    java_file = os.path.abspath(java_file)
    if outfile[0] != '/':
        outfile = os.path.join(pwddir, outfile)
    output_file = os.path.abspath(output_file)
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, javac_logfile, pwddir)


def process_jar_command(prog, pwddir, argv_str):
    '''
    Process the jar command
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    jar_logfile = os.path.join(g_tmpdir, "bomsh_hook_jar_logfile")
    verbose("\npwd: " + pwddir + " Found one jar command: " + argv_str)
    verbose("\npwd: " + pwddir + " Found one jar command: " + argv_str, LEVEL_0, jar_logfile)
    (outfile, infiles) = get_all_subfiles_in_jar_cmdline(argv_str, pwddir)
    update_hash_tree_and_gitbom(outfile, infiles, prog, argv_str, jar_logfile, pwddir)


def process_shell_command(prog, pwddir, argv_str):
    '''
    Process the shell command that we are interested in.
    :param prog: the program binary
    :param pwddir: the present working directory for the command
    :param argv_str: the full command with all its command line options/parameters
    '''
    if is_cc_compiler(prog):
        process_gcc_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/ar":
        process_ar_command(prog, pwddir, argv_str)
    elif prog == "./tools/objtool/objtool":
        process_objtool_command(prog, pwddir, argv_str)
    elif is_cc_linker(prog):
        process_ld_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/objcopy":
        process_objcopy_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/install":
        process_install_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/strip":
        process_strip_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/ranlib":
        process_ranlib_command(prog, pwddir, argv_str)
    elif prog == "arch/x86/boot/tools/build":
        process_bzImage_build_command(prog, pwddir, argv_str)
    elif prog == "./scripts/sortextable":
        process_sortextable_command(prog, pwddir, argv_str)
    elif prog == "/usr/lib/rpm/sepdebugcrcfix":
        process_sepdebugcrcfix_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/javac":
        process_javac_command(prog, pwddir, argv_str)
    elif prog == "/usr/bin/jar":
        process_jar_command(prog, pwddir, argv_str)


############################################################
#### End of shell command handling routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool parses the command and generates hash tree")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-s', '--shell_cmd_file',
                    help = "the shell command file to analyze the command")
    parser.add_argument('-b', '--bom_dir',
                    help = "the directory to store the generated gitBOM doc files")
    parser.add_argument('-l', '--logfile',
                    help = "the log file, must be absolute path, not relative path")
    parser.add_argument('-w', '--watched_programs',
                    help = "the comma-separated list of programs to watch")
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('-j', '--jsonfile',
                    help = "the generated gitBOM artifact tree JSON file")
    parser.add_argument('-t', '--trace_logfile',
                    help = "the verbose trace log file")
    parser.add_argument('--cc_compilers',
                    help = "the comma-separated C compiler paths, like /usr/bin/gcc,/usr/bin/clang")
    parser.add_argument('--cc_linkers',
                    help = "the comma-separated C linker paths, like /usr/bin/ld,/usr/bin/llvm-ld")
    parser.add_argument("-n", "--no_dependent_headers",
                    action = "store_true",
                    help = "not include C header files for hash tree dependency")
    parser.add_argument("--embed_bom_section",
                    action = "store_true",
                    help = "embed the .bom ELF section or archive entry")
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

    global g_bomdir
    global g_object_bomdir
    global g_bomsh_bomdir
    global g_with_bom_dir
    global g_logfile
    global g_trace_logfile
    global g_jsonfile
    global g_tmpdir
    if args.tmpdir:
        g_tmpdir = args.tmpdir
        g_jsonfile = os.path.join(g_tmpdir, "bomsh_hook_jsonfile")
        g_logfile = os.path.join(g_tmpdir, "bomsh_hook_logfile")
        g_trace_logfile = os.path.join(g_tmpdir, "bomsh_hook_trace_logfile")
    if args.bom_dir:
        g_bomdir = args.bom_dir
    g_bomdir = get_or_create_dir(g_bomdir)
    g_object_bomdir = get_or_create_dir(os.path.join(g_bomdir, "objects"))
    g_bomsh_bomdir = os.path.join(g_bomdir, "metadata", "bomsh")
    if args.embed_bom_section:
        g_with_bom_dir = get_or_create_dir(os.path.join(g_bomsh_bomdir, "with_bom_files"))
    else:
        g_bomsh_bomdir = get_or_create_dir(g_bomsh_bomdir)
    if args.logfile:
        g_logfile = args.logfile
    if args.jsonfile:
        g_jsonfile = args.jsonfile
    if args.trace_logfile:
        g_trace_logfile = args.trace_logfile
    if args.cc_compilers:
        g_cc_compilers.extend(args.cc_compilers.split(","))
    if args.cc_linkers:
        g_cc_linkers.extend(args.cc_linkers.split(","))

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    pppid = os.popen("ps -p %d -oppid=" % os.getppid()).read().strip()
    verbose("\n==== BOM-HOOK PID: " + str(os.getpid()) + " PPPID: " + pppid + " started ====", LEVEL_0)

    (pid, pwddir, prog, argv_str) = read_shell_command(args.shell_cmd_file)
    # always record the shell command in trace_logfile
    append_text_file(g_trace_logfile, ' '.join((pid, pwddir, prog, argv_str, '\n')))

    # clang is handled the same way as gcc
    progs_to_watch = g_cc_compilers + g_cc_linkers + ["/usr/bin/ar", "/usr/bin/javac", "/usr/bin/jar"]
    progs_to_watch.extend( ["./tools/objtool/objtool", "/usr/bin/objcopy", "/usr/bin/strip", "/usr/bin/install", "/usr/bin/ranlib"] )
    progs_to_watch.extend( ["/usr/lib/rpm/sepdebugcrcfix", "arch/x86/boot/tools/build", "./scripts/sortextable"] )
    if args.watched_programs:
        progs_to_watch.extend(args.watched_programs)
    if prog in progs_to_watch:
        verbose(prog + " is on the list, processing the command...", LEVEL_0)
        process_shell_command(prog, pwddir, argv_str)
    else:
        verbose(prog + " is not on the list, we are done", LEVEL_0)
    verbose("==== BOM-HOOK PID: " + str(os.getpid()) + " PPPID: " + pppid + " exited ====", LEVEL_0)


if __name__ == '__main__':
    main()
