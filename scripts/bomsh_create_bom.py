#! /usr/bin/env python3
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
Bomsh script to generate OmniBOR artifact tree and OmniBOR docs from the bomsh_hook_raw_logfile generated during software build.

Use by Bomsh or Bomtrace.

December 2021, Yongkui Han
"""

import argparse
import sys
import os
import shutil
import subprocess
import json
import re

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
g_raw_logfile = "/tmp/bomsh_hook_raw_logfile"
g_logfile = "/tmp/bomsh_createbom_logfile"
g_jsonfile = "/tmp/bomsh_createbom_jsonfile"
g_bomdir = os.path.join(os.getcwd(), ".omnibor")
g_object_bomdir = os.path.join(g_bomdir, "objects")
g_bomsh_bomdir = os.path.join(g_bomdir, "metadata", "bomsh")
g_with_bom_dir = os.path.join(g_bomsh_bomdir, "with-bom-files")

# the constructed hash-tree DB from bomsh_hook_raw_logfile
# { githash of binary file => list of githashes + metadata }
g_treedb = {}
# g_bomdb stores the binary file githash to OmniBOR doc githash mapping
# { githash of binary file => githash of its OmniBOR doc }
g_bomdb = {}
# g_pre_exec_db temporarily stores the pre-exec checksum of the same input/output file for strip/ranlib commands.
g_pre_exec_db = {}
# index DB with checksum (blob_id) as key, containing package/component name/version, etc.
# format of { blob_id => package_string } dict
g_index_db = {}

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
    if args.verbose > level:
        afile = g_logfile
        if logfile:
            afile = logfile
        if afile:
            append_text_file(afile, string + "\n")
        # also print to stdout
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


def get_filetype(afile):
    """
    Returns the output of the shell command "file afile".

    :param afile: the file to check its file type
    """
    cmd = "file " + cmd_quote(afile) + " || true"
    #print (cmd)
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    res = re.split(r":\s+", output.strip())
    if len(res) > 1:
        return ": ".join(res[1:])
    return "empty"


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


def find_all_regular_files(builddir):
    """
    Find all regular files in the build dir, excluding symbolic link files.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :returns a list that contains all the regular file names.
    """
    builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' -type f -print || true '
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    return files


def find_all_package_files_in_dir(builddir):
    """
    Find all package files in the build dir, excluding symbolic link files.
    Only RPM and DEB files are supported.

    :param builddir: String, build dir of the workspace
    :returns a list that contains all the package file names.
    """
    #builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' -type f -name "*.rpm" -print || true '
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    findcmd = "find " + cmd_quote(builddir) + ' -type f -name "*.deb" -print || true '
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files.extend(output.splitlines())
    return files


def find_all_package_files(builddirs):
    """
    Find all package files in a list of build dir, excluding symbolic link files.

    :param builddirs: a list of build dir to find package files.
    :returns a list that contains all the package file names.
    """
    files = []
    for builddir in builddirs:
        files.extend(find_all_package_files_in_dir(builddir))
    return files


############################################################
#### Start of gitbom routines ####
############################################################

def save_gitbom_doc(gitbom_doc_file, destdir, checksum=''):
    '''
    Save the generated OmniBOR doc file to destdir.
    :param gitbom_doc_file: the generated OmniBOR doc file to save
    :param destdir: destination directory to store the created OmniBOR doc file
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


def remove_adjacent_duplicates(lines):
    """
    Remove adjacent duplicate lines.
    :param lines: a sorted list of lines, there should be no empty string in the list
    returns a new list, with duplicate lines removed
    """
    new_lines = []
    prev_line = ''
    for line in lines:
        if line != prev_line:
            new_lines.append(line)
            prev_line = line
    return new_lines


def create_gitbom_doc_text(infiles, db):
    """
    Create the OmniBOR doc text contents
    :param infiles: the list of checksum for input files
    :param db: OmniBOR DB with {file-hash => its OmniBOR hash} mapping
    """
    if not infiles:
        return ''
    lines = []
    for ahash in infiles:
        line = "blob " + ahash
        # if ahash is not in db, should we try to extract the embedded bom_id in the infile? probably NOT, due to impact on performance
        # plus, this infile may not exist in the file system when this script is run offline later.
        if ahash in db and (ahash in g_treedb and "prune" not in g_treedb[ahash]):  # ahash must not have the prune attribute
            gitbom_hash = db[ahash]
            line += " bom " + gitbom_hash
        if args.verbose > 1 and ahash in db and db[ahash] and ahash in g_treedb and "prune" in g_treedb[ahash]:
            verbose("Info: non-leaf blob " + ahash + " has prune attribute", LEVEL_2)
        lines.append(line)
    lines.sort()
    if not args.keep_duplicate_lines_in_omnibor_doc:
        lines = remove_adjacent_duplicates(lines)
    return '\n'.join(lines) + '\n'


def create_gitbom_doc(infile_hashes, db, destdir):
    """
    Create the OmniBOR doc text contents
    :param infile_hashes: the list of input file hashes
    :param db: OmniBOR DB with {file-hash => its OmniBOR hash} mapping
    :param destdir: destination directory to create the gitbom doc file
    returns the git-hash of the created OmniBOR doc.
    """
    lines = create_gitbom_doc_text(infile_hashes, db)
    output_file = os.path.join(g_tmpdir, "bomsh_temp_gitbom_file")
    if args.hashtype and args.hashtype.lower() == "sha256":
        firstline = "gitoid:blob:sha256\n"
    else:
        firstline = "gitoid:blob:sha1\n"
    write_text_file(output_file, firstline + lines)
    ahash = get_git_file_hash(output_file)
    save_gitbom_doc(output_file, destdir, ahash)
    return ahash


g_embed_bom_script = '''
git hash-object HELLO_GITBOM_FILE | head --bytes=-1 | xxd -r -p > /tmp/bomsh_bom_gitref_file
if objdump -s -j .bom HELLO_FILE 2>/dev/null ; then
  objcopy --update-section .bom=/tmp/bomsh_bom_gitref_file HELLO_FILE HELLO_WITH_BOM_FILE
else
  objcopy --add-section .bom=/tmp/bomsh_bom_gitref_file HELLO_FILE HELLO_WITH_BOM_FILE
fi
'''

def embed_gitbom_hash_elf_section(afile, gitbom_doc, outfile):
    """
    Embed the .bom ELF section into an ELF file.
    :param afile: the ELF file to insert the embedded .bom section
    :param gitbom_doc: OmniBOR doc for this afile
    :param outfile: output file with the .bom ELF section
    """
    #verbose("afile: " + afile + "gitbom_doc: " + gitbom_doc + " outfile: " + outfile)
    embed_script = g_embed_bom_script.replace("HELLO_FILE", afile).replace("HELLO_GITBOM_FILE", gitbom_doc).replace("HELLO_WITH_BOM_FILE", outfile)
    #verbose("The embed_bom script:" + embed_script)
    get_shell_cmd_output(embed_script)


def embed_gitbom_hash_archive_entry(afile, gitbom_doc, outfile):
    """
    Embed the .bom archive entry into an archive file.
    :param afile: the archive file to insert the embedded .bom archive entry
    :param gitbom_doc: OmniBOR doc for this afile
    :param outfile: output file with the .bom archive entry
    """
    #verbose("afile: " + afile + "gitbom_doc: " + gitbom_doc + " outfile: " + outfile)
    if g_with_bom_dir:
        temp_bom_file = os.path.join(g_with_bom_dir, ".bom")
    else:
        temp_bom_file = os.path.join(g_tmpdir, ".bom")
    cmd = 'git hash-object ' + gitbom_doc + ' | head --bytes=-1 | xxd -r -p > ' + temp_bom_file
    cmd += " ; cp " + afile + " " + outfile
    cmd += " ; ar -r " + outfile + " " + temp_bom_file + " || true"
    #verbose("The embed_archive_bom cmd: " + cmd)
    get_shell_cmd_output(cmd)


def update_gitbom_dir(bomdir, infiles, checksum, outfile):
    '''
    Update the OmniBOR directory with hashes of input files and outfile
    :param bomdir: the OmniBOR directory
    :param infiles: a list of the hashes of input files
    :param checksum: the checksum/hash of the output file
    :param outfile: the output file
    '''
    if not infiles:
        verbose("Warning: infile is empty, skipping OmniBOR doc update for outfile " + outfile)
        return
    if len(infiles) == 1 and not args.new_omnibor_doc_for_unary_transform and infiles[0] in g_bomdb:
        gitbom_doc_hash = g_bomdb[infiles[0]]
        verbose("Unary transform, reused OmniBOR file " + gitbom_doc_hash + " for outfile " + outfile)
    else:
        gitbom_doc_hash = create_gitbom_doc(infiles, g_bomdb, g_object_bomdir)
        verbose("Created OmniBOR file " + gitbom_doc_hash + " for outfile " + outfile)
    # record the checksum => gitbom_doc_hash/bom_id mapping
    g_bomdb[checksum] = gitbom_doc_hash
    if not args.embed_bom_section:
        return
    if not os.path.isfile(outfile) or get_git_file_hash(outfile) != checksum:
        verbose("Warning: outfile with checksum " + checksum + " does not exist, skip embedding OmniBOR for outfile " + outfile)
        return
    if not args.embed_o_file and outfile[-2:] == ".o":  # not embed intermediate *.o files by default
        verbose("Warning: outfile " + outfile + " is intermediate .o file, skipping embedding .bom section")
        return
    if not is_elf_file(outfile):  # archive file must also contain valid ELF files.
        verbose("Warning: outfile " + outfile + " is not ELF file, skipping embedding .bom section")
        return
    # Try to embed the .bom ELF section or archive entry
    gitbom_doc = os.path.join(g_object_bomdir, gitbom_doc_hash[:2], gitbom_doc_hash[2:])
    with_bom_file = os.path.join(g_with_bom_dir, checksum + "-with_bom-" + gitbom_doc_hash + "-" + os.path.basename(outfile))
    if args.embed_archive_file and is_archive_file(outfile):
        verbose("Create archive with_bom file: " + with_bom_file)
        embed_gitbom_hash_archive_entry(outfile, gitbom_doc, with_bom_file)
    elif outfile[-2:] != ".a":
        verbose("Create ELF with_bom file: " + with_bom_file)
        embed_gitbom_hash_elf_section(outfile, gitbom_doc, with_bom_file)


############################################################
#### Start of hash tree DB update routines ####
############################################################

def update_hash_tree_node_filepath(db, ahash, afile, cvehint=None):
    '''
    Update the file_path of a single node in the hash tree

    :param db: the hash tree DB to update
    :param ahash: the hash of the afile
    :param afile: a file, either input file or output file
    :param cvehint: a tuple of (has_cve_list, fixed_cvelist)
    '''
    if afile in g_bomdb and ahash not in g_bomdb:
        # this afile is outfile with empty checksum in previous records, and now it is infile, we assume this afile is never overwritten by a different checksum
        g_bomdb[ahash] = g_bomdb[afile]
    if ahash not in db:  # not exist, then create this hash entry
        if afile in db:  # this afile is outfile with empty checksum in previous records, and now it is infile
            db[ahash] = db[afile]
        else:
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
    # extra handling of provider pkg_info
    if ahash in g_index_db:
        afile_db["prov_pkg"] = g_index_db[ahash]
    # extra handling of cvehint
    if not cvehint:
        return
    verbose("afile: " + afile + " Processing cvehint: " + str(cvehint))
    has_cve_list, fixed_cve_list = cvehint
    if has_cve_list:
        if "cvehint_CVElist" in afile_db:
            afile_db["cvehint_CVElist"].extend(has_cve_list)
        else:
            afile_db["cvehint_CVElist"] = has_cve_list
    if fixed_cve_list:
        if "cvehint_FixedCVElist" in afile_db:
            afile_db["cvehint_FixedCVElist"].extend(fixed_cve_list)
        else:
            afile_db["cvehint_FixedCVElist"] = fixed_cve_list


def update_hash_tree_node_build_info(afile_db, ahash, outfile, key_value, key_str):
    '''
    Update the build_cmd/build_tool of a single node in the hash tree

    :param afile_db: the hash tree DB node to update
    :param ahash: the hash of the outfile
    :param outfile: the output file for the shell command
    :param key_value: the value, for example, the full shell command with all its command line options/parameters
    :param key_str: build_cmd or build_tool, the key string for the dict
    '''
    key_strs = key_str + "s"
    # First add the build command to the database
    verbose(outfile + " is outfile, update " + key_str + ": " + key_value)
    if key_str in afile_db and afile_db[key_str] != key_value:
        verbose("Warning: checksum " + ahash + " already has " + key_str + " info. outfile: " + outfile)
        # create build_cmds with the list of all build commands
        if key_strs in afile_db:
            if key_value not in afile_db[key_strs]:
                afile_db[key_strs].append(key_value)
        else:
            afile_db[key_strs] = [afile_db[key_str], key_value]
    if key_str not in afile_db:
        afile_db[key_str] = key_value


def update_hash_tree_node_hashtree(db, ahash, outfile, infiles, argv_str, pid='', build_tool='', pkg_info='', dynlibs=[]):
    '''
    Update the build_cmd and hashtree of a single node in the hash tree

    :param db: the hash tree DB to update
    :param ahash: the hash of the outfile
    :param outfile: the output file for the shell command
    :param infiles: the list of (checksum, file_path) for input files
    :param argv_str: the full shell command with all its command line options/parameters
    :param pid: the PID of the shell command
    :param build_tool: the build_tool info
    :param pkg_info: the RPM/DEB package info
    :param dynlibs: the dynamic library dependencies for the outfile
    returns the newly created hash_tree, empty or not. This is a list of checksums
    '''
    afile_db = db[ahash]
    # First add the build command to the database
    update_hash_tree_node_build_info(afile_db, ahash, outfile, argv_str, "build_cmd")
    if build_tool:
        update_hash_tree_node_build_info(afile_db, ahash, outfile, build_tool, "build_tool")
    if pkg_info:
        update_hash_tree_node_build_info(afile_db, ahash, outfile, pkg_info, "pkg_info")
    if len(infiles) == 1 and not args.new_omnibor_doc_for_unary_transform and infiles[0][0] in db:
        # unary transform and reuse bom_id, dyn_libs metadata will be lost if not pass from infile to outfile
        infile_db = db[infiles[0][0]]
        if "dyn_libs" in infile_db:
            # pass dyn_libs metadata from child gitoid to parent gitoid
            if dynlibs:
                dynlibs.extend(infile_db["dyn_libs"])
            else:
                dynlibs = infile_db["dyn_libs"]  # no need to copy
            verbose("Unary transform, pass dyn_libs metadata from infile " + str(infiles[0]) + " to outfile " + str((ahash, outfile)))
    if dynlibs and "dyn_libs" not in afile_db:  # not overwrite existing dyn_libs value
        #afile_db["dyn_libs"] = [f[0] for f in dynlibs]
        afile_db["dyn_libs"] = dynlibs  # easier to keep both checksum and path
    # Next update the hashtree as needed
    hash_tree = [f[0] for f in infiles]
    if pid and pid in g_pre_exec_db:
        pid_db = g_pre_exec_db[pid]
        if outfile not in pid_db:
            verbose("Warning: pid: " + pid + " missing old checksum, new checksum: " + ahash + " outfile: " + outfile)
        else:
            checksum = g_pre_exec_db[pid][outfile]
            verbose("Consuming pre_exec record, pid: " + pid + " checksum: " + checksum + " new checksum: " + ahash + " outfile: " + outfile)
            if checksum != ahash:  # must be different to deserve a hash tree dependency
                hash_tree = [checksum,]
            del g_pre_exec_db[pid][outfile]
            if not g_pre_exec_db[pid]:
                del g_pre_exec_db[pid]
    if not hash_tree:
        verbose("Warning: checksum " + ahash + " has empty hashtree. outfile: " + outfile)
        return hash_tree
    new_hash_tree = sorted(hash_tree)
    if "hash_tree" in afile_db:
        verbose("Warning: checksum " + ahash + " already has hash tree. outfile: " + outfile)
        old_hash_tree = afile_db["hash_tree"]
        if old_hash_tree == new_hash_tree:  # this should be the common case: same .c file is compiled twice to generated two .o files with different file name.
            verbose("Warning: Good that checksum " + ahash + " has the same hash tree. old file path: " + str(afile_db["file_path"]))
            if "file_paths" in afile_db:
                verbose("Warning: file paths: " + str(afile_db["file_paths"]))
        else:
            verbose("Warning!! Bad that checksum " + ahash + " has a different hash tree. old file path: " + str(afile_db["file_path"]))
            if "file_paths" in afile_db:
               verbose("Warning!! file paths: " + str(afile_db["file_paths"]))
            # create hash_trees with the list of all hash_trees
            if "hash_trees" in afile_db:
                afile_db["hash_trees"].append(new_hash_tree)
            else:
                afile_db["hash_trees"] = [old_hash_tree, new_hash_tree]
            # let's combine the new hash tree with the existing hash tree
            afile_db["hash_tree"] = sorted(set(old_hash_tree) | set(new_hash_tree))
            verbose("Merged new hash tree into existing hash tree for outfile: " + outfile, LEVEL_3)
    else:
        afile_db["hash_tree"] = new_hash_tree
    return afile_db["hash_tree"]


def any_infile_is_same_as_outfile(outfile_checksum, infiles):
    """
    Is there any input file which has the same checksum as the outfile?

    :param outfile_checksum: the checksum of the outfile
    :param infiles: the list of (checksum, file_path) for input files
    """
    for infile in infiles:
        if infile[0] == outfile_checksum:
            return True
    return False


def update_hash_tree_db_and_gitbom(db, record):
    """
    Update the hash tree DB and the OmniBOR doc for an output file.

    :param db: the hash tree DB to update
    :param record: the raw_info record for a single shell command
    """
    if "ignore_this_record" in record:
        verbose("Warning: ignore_this_record for outfile " + record["outfile"][1] + ", skipping hash tree and OmniBOR doc update")
        return
    if "outfile" not in record:
        verbose("Warning: there is no outfile for this record, skipping hash tree and OmniBOR doc update: " + str(record), LEVEL_0)
        return
    checksum, outfile = record["outfile"]
    verbose("\n=== Update treedb and OmniBOR for checksum: " + checksum + " outfile: " + outfile, LEVEL_0)
    if not checksum and outfile:  # for llvm-gitbom generated .metadata files, which have empty checksum for outfile
        checksum = outfile
    if not checksum:
        verbose("Warning: empty checksum for outfile " + outfile + ", skipping hash tree and OmniBOR doc update")
        return
    pid = ''
    if "pid" in record:
        pid = record["pid"]
    if "exec_mode" in record and record["exec_mode"] == "pre_exec":
        verbose("pre_exec record, pid: " + pid + " checksum: " + checksum + " outfile: " + outfile)
        if pid in g_pre_exec_db:
            g_pre_exec_db[pid][outfile] = checksum
        else:
            g_pre_exec_db[pid] = {outfile: checksum}
        return
    update_hash_tree_node_filepath(db, checksum, outfile)
    infiles = []
    if "infiles" in record:
        infiles = record["infiles"]
    for ahash, afile, cvehint in infiles:
        if not ahash:
            continue
        update_hash_tree_node_filepath(db, ahash, afile, cvehint)
    dynlibs = []
    if "dynlibs" in record:
        dynlibs = record["dynlibs"]
    for ahash, afile in dynlibs:
        if not ahash:
            continue
        update_hash_tree_node_filepath(db, ahash, afile)
    if any_infile_is_same_as_outfile(checksum, infiles):
        # There is at least one input file which has the the exact same checksum as outfile, skip it
        verbose("Warning: transform of same checksum, skip updating hash tree DB.")
        return
    verbose("Updating hash tree DB for outfile " + outfile)
    argv_str = record["build_cmd"]
    build_tool, pkg_info = '', ''
    if "build_tool" in record:
        build_tool = record["build_tool"]
    if "pkg_info" in record:
        pkg_info = record["pkg_info"]
    if "prune" in record:  # simply pass the prune attribute from record to g_treedb[checksum]
        verbose("From raw_logfile, checksum " + checksum + " has prune attribute", LEVEL_2)
        db[checksum]["prune"] = record["prune"]
    hash_tree = update_hash_tree_node_hashtree(db, checksum, outfile, infiles, argv_str, pid, build_tool=build_tool, pkg_info=pkg_info, dynlibs=dynlibs)
    verbose("There are " + str(len(hash_tree)) + " checksums in hash_tree for outfile: " + outfile)
    if g_bomdir:
        update_gitbom_dir(g_bomdir, hash_tree, checksum, outfile)


############################################################
#### End of shell command handling routines ####
############################################################

def process_lseek_lines_file(lseek_lines_file):
    """
    Special processing with lseek_lines_file.

    :param lseek_lines_file: the cache file containing the number of lines previously read from raw_logfile
    returns the lseek_lines to start reading from raw_logfile
    """
    jsonfile = os.path.join(g_bomsh_bomdir, "bomsh_omnibor_doc_mapping")
    if lseek_lines_file and os.path.exists(jsonfile):
        global g_bomdb
        g_bomdb = load_json_db(jsonfile)
        verbose("\nLoad the OmniBOR DOCDB " + str(len(g_bomdb)) + " checksums from existing file: " + jsonfile)
    if lseek_lines_file and os.path.exists(g_jsonfile):
        global g_treedb
        g_treedb = load_json_db(g_jsonfile)
        verbose("Load the hash tree DB " + str(len(g_treedb)) + " checksums from existing file: " + g_jsonfile)
    lseek_lines = 0
    if lseek_lines_file and os.path.isfile(lseek_lines_file):
        content = read_text_file(lseek_lines_file)
        lseek_lines = int(content)
        verbose("We will read raw_logfile starting at lseek_lines: " + content)
    return lseek_lines


def read_cve_hint(tokens):
    """
    Read the CVE helpful hint from infile line.

    :param tokens: the list of ["has_cve:CVE-2020-1967,CVE-2020-1971", "fixed_cve:CVE-2014-0160"]
    """
    has_cve_list = []
    fixed_cve_list = []
    for token in tokens:
        if token.startswith("has_cve:CVE-"):
            has_cve_list = token[8:].split(",")
        elif token.startswith("fixed_cve:CVE-"):
            fixed_cve_list = token[10:].split(",")
    return (has_cve_list, fixed_cve_list)


def read_raw_logfile(raw_logfile):
    """
    Read and process the recorded raw info from bomsh_hook script.

    :param raw_logfile: the log file that contains the raw info
    """
    # Need to do some special handling if args.lseek_lines_file is provided
    lseek_lines = process_lseek_lines_file(args.lseek_lines_file)
    line_num = 0
    record = {}
    with open(raw_logfile, 'r') as f:
        # Skip lseek_lines, before processing lines in raw_logfile
        for _ in range(lseek_lines):
            next(f)
        for line in f:
            line_num += 1
            line = line.strip()
            if not line:
                continue
            if line.startswith("outfile: "):
                tokens = line.split()
                if len(tokens) > 3:
                    checksum = tokens[1]
                    file_path = tokens[3]
                elif len(tokens) > 2:
                    checksum = ''
                    file_path = tokens[2]
                record["outfile"] = (checksum, file_path)
            elif line.startswith("infile: "):
                tokens = line.split()
                if len(tokens) > 3:
                    checksum = tokens[1]
                    file_path = tokens[3]
                elif len(tokens) > 2:
                    checksum = ''
                    file_path = tokens[2]
                cve_hint = None
                if len(tokens) > 4 and "_cve:CVE-" in line:
                    cve_hint = read_cve_hint(tokens[4:])
                if "infiles" not in record:
                    record["infiles"] = [(checksum, file_path, cve_hint),]
                else:
                    record["infiles"].append( (checksum, file_path, cve_hint) )
            elif line.startswith("dynlib: "):
                tokens = line.split()
                if len(tokens) > 3:
                    checksum = tokens[1]
                    file_path = tokens[3]
                elif len(tokens) > 2:
                    checksum = ''
                    file_path = tokens[2]
                if "dynlibs" not in record:
                    record["dynlibs"] = [(checksum, file_path),]
                else:
                    record["dynlibs"].append( (checksum, file_path) )
            elif line.startswith("build_cmd: "):
                record["build_cmd"] = line[11:]
            elif line.startswith("build_tool: "):
                record["build_tool"] = line[12:]
            elif line.startswith("pkg_info: "):
                record["pkg_info"] = line[10:]
            elif line.startswith("==== End of raw info for "):
                record["raw_line_num"] = line_num
                record["last_pid_line"] = line
                update_hash_tree_db_and_gitbom(g_treedb, record)
                record = {}  # create the next record
            elif line.startswith("PID: "):
                tokens = line.split()
                record["pid"] = tokens[1]
                record["exec_mode"] = tokens[2]
            elif line.startswith("prune: "):
                tokens = line.split()
                if len(tokens) > 1:
                    record["prune"] = tokens[1]
                else:
                    record["prune"] = ''
            elif line.startswith("ignore_this_record:"):
                record["ignore_this_record"] = True
                #elif line.startswith("working_dir: "):
                #tokens = line.split()
                #record['pwd'] = tokens[1]
    if args.lseek_lines_file:
        lseek_lines += line_num
        lseek_lines_str = str(lseek_lines)
        write_text_file(args.lseek_lines_file, lseek_lines_str)
        verbose("Write new lseek_lines " + lseek_lines_str + " to file " + args.lseek_lines_file)


def save_gitbom_dbs(bomsh_pkgs_raw_logfile):
    '''
    Save all OmniBOR databases to JSON file, and print summary.
    '''
    # Finally save the updated DB to the JSON file
    save_json_db(g_jsonfile, g_treedb)
    # always save a copy in OmniBOR repo's metadata/bomsh or g_bomsh_bomdir directory
    if g_bomsh_bomdir:
        jsonfile = os.path.join(g_bomsh_bomdir, "bomsh_omnibor_doc_mapping")
        save_json_db(jsonfile, g_bomdb)
        treedb_jsonfile = os.path.join(g_bomsh_bomdir, "bomsh_omnibor_treedb")
        shutil.copy(g_jsonfile, treedb_jsonfile)
        raw_logfile = os.path.join(g_bomsh_bomdir, "bomsh_hook_raw_logfile")
        if bomsh_pkgs_raw_logfile and os.path.getsize(bomsh_pkgs_raw_logfile) > 0:
            os.system("cat " + g_raw_logfile + " " + bomsh_pkgs_raw_logfile + " > "  + raw_logfile)
        else:
            shutil.copy(g_raw_logfile, raw_logfile)
        if args.index_db_file:
            index_dbfile = os.path.join(g_bomsh_bomdir, "bomsh_index_blob_pkg_db")
            shutil.copy(args.index_db_file, index_dbfile)
        elif args.pkg_db_file:
            pkg_dbfile = os.path.join(g_bomsh_bomdir, "bomsh_index_pkg_db")
            shutil.copy(args.pkg_db_file, pkg_dbfile)
            if g_index_db:
                index_dbfile = os.path.join(g_bomsh_bomdir, "bomsh_index_blob_pkg_db")
                save_json_db(index_dbfile, g_index_db)
    if bomsh_pkgs_raw_logfile:
        os.remove(bomsh_pkgs_raw_logfile)
    verbose("pre_exec DB:" + json.dumps(g_pre_exec_db, indent=4, sort_keys=True), LEVEL_3)
    #print (json.dumps(db, indent=4, sort_keys=True))
    verbose("Number of checksums in GITBOM DOCDB: " + str(len(g_bomdb)), LEVEL_0)
    verbose("Number of checksums in GITBOM TREEDB: " + str(len(g_treedb)), LEVEL_0)


def unbundle_package(pkgfile, destdir=''):
    '''
    unbundle RPM/DEB package to destdir.
    :param pkgfile: the RPM/DEB package file to unbundle
    :param destdir: the destination directory to save unbundled files
    '''
    if not destdir:
        extract_dir = os.path.join(g_tmpdir, "bomsh_extract_dir")
        if not os.path.exists(extract_dir):
            os.makedirs(extract_dir)
        destdir = os.path.join(extract_dir, os.path.basename(pkgfile) + ".extractdir")
    if pkgfile[-4:] == ".rpm":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; cd " + destdir + " ; rpm2cpio " + pkgfile + " | cpio -idm || true"
    elif pkgfile[-4:] == ".deb" or pkgfile[-5:] in (".udeb", ".ddeb"):
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; dpkg-deb -xv " + pkgfile + " " + destdir + " || true"
    elif pkgfile[-4:] == ".tgz" or pkgfile[-7:] in (".tar.gz", ".tar.xz") or pkgfile[-8:] == ".tar.bz2":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; tar -xf " + pkgfile + " -C " + destdir + " || true"
    elif pkgfile[-4:] == ".jar":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; unzip " + pkgfile + " -d " + destdir + " || true"
    else:
        print("Unsupported package format in " + pkgfile + " file, skipping it.")
        return ''
    get_shell_cmd_output(cmd)
    return destdir


def get_pkg_info_from_rpm_file(pkgfile):
    '''
    Get package name/version info from a .rpm file.
    '''
    cmd = 'rpm -qp --queryformat "%{NAME} %{VERSION} %{RELEASE}" ' + cmd_quote(pkgfile) + ' || true'
    output = get_shell_cmd_output(cmd)
    if not output:
        return ''
    pkg_name, pkg_version, pkg_release = output.split()
    return "RPM Name: " + pkg_name + " Version: " + pkg_version + " Release: " + pkg_release


def get_pkg_info_from_deb_file(pkgfile):
    '''
    Get package name/version info from a .deb file.
    '''
    cmd = 'dpkg-deb --show ' + cmd_quote(pkgfile) + ' || true'
    output = get_shell_cmd_output(cmd)
    if not output:
        return ''
    pkg_name, pkg_version = output.split()
    return "DEB Name: " + pkg_name + " Version: " + pkg_version


def get_pkg_info(pkgfile):
    '''
    Get package name/version info from a .rpm/.deb file.
    '''
    if pkgfile[-4:] == '.rpm':
        return get_pkg_info_from_rpm_file(pkgfile)
    elif pkgfile[-4:] == ".deb" or pkgfile[-5:] in (".udeb", ".ddeb"):
        return get_pkg_info_from_deb_file(pkgfile)
    return ''


def process_package_file(pkgfile, f_raw_logfile):
    '''
    Process a single package file. Unbundle the package, create the outfile/infiles record, and update OmniBOR repo.

    :param pkgfile: the RPM/DEB package file to process
    :param f_raw_logfile: the raw_logfile file object to write the raw record lines for package
    '''
    destdir = unbundle_package(pkgfile)
    if not destdir:
        return
    afiles = find_all_regular_files(destdir)
    record = {}
    lines = []
    ahash = get_git_file_hash(pkgfile)
    record['outfile'] = (ahash, pkgfile)
    lines.append("outfile: " + ahash + " path: " + pkgfile)
    infiles = []
    for afile in afiles:
        ahash = get_git_file_hash(afile)
        infiles.append( (ahash, afile, None) )
        lines.append("infile: " + ahash + " path: " + afile)
    record['infiles'] = infiles
    record['build_cmd'] = "unbundle package"
    lines.append("build_cmd: unbundle package")
    record['pkg_info'] = get_pkg_info(pkgfile)
    update_hash_tree_db_and_gitbom(g_treedb, record)
    shutil.rmtree(destdir)
    raw_lines = '\n' + '\n'.join(lines) + '\n\n'
    f_raw_logfile.write(raw_lines)


def process_package_files(pkgfiles):
    '''
    Process a list of package files.
    '''
    raw_logfile = os.path.join(g_tmpdir, "bomsh_pkgs_raw_logfile")
    f_raw_logfile = open(raw_logfile, 'w')
    for pkgfile in pkgfiles:
        if pkgfile[0] != "/":
            pkgfile = os.path.abspath(pkgfile)
        process_package_file(pkgfile, f_raw_logfile)
    f_raw_logfile.close()
    return raw_logfile

############################################################
#### End of shell command read/parse routines ####
############################################################

def get_git_file_hash_sha256(afile):
    '''
    Get the git object hash value of a file for SHA256 hash type.
    :param afile: the file to calculate the git hash or digest.
    '''
    cmd = 'printf "blob $(wc -c < ' + afile + ')\\0" | cat - ' + afile + ' | sha256sum | head --bytes=-4 || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    #verbose("output of git_hash_sha256:\n" + output, LEVEL_3)
    if output:
        return output.strip()
    return ''


def get_git_file_hash(afile):
    '''
    Get the git object hash value of a file.
    :param afile: the file to calculate the git hash or digest.
    '''
    if args.hashtype and args.hashtype.lower() == "sha256":
        return get_git_file_hash_sha256(afile)
    cmd = 'git hash-object ' + cmd_quote(afile) + ' || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    #verbose("output of git_hash:\n" + output, LEVEL_3)
    if output:
        return output.strip()
    return ''


def is_archive_file(afile):
    """
    Check if a file is an archive file.

    :param afile: String, name of file to be checked
    :returns True if the file is archive file. Otherwise, return False.
    """
    filetype = get_filetype(afile)
    return filetype == "current ar archive" or filetype[:22] == "Debian binary package "


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


def convert_pkg_db_to_blob_db(pkg_db):
    '''
    Convert a dict keyed with package to a dict keyed with blob ID.
    :param pkg_db: a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    returns a dict of { blob_id => (package, path) }
    '''
    blob_db = {}
    for package in pkg_db:
        pkg_entry = pkg_db[package]
        if "blobs" not in pkg_entry:
            continue
        blobs = pkg_entry["blobs"]
        for blob in blobs:
            checksum, path = blob
            overwrite = True  # overwrite with newer package by default
            if checksum in blob_db:
                old_package = blob_db[checksum][0]
                if package != old_package:  # usually this is the COPYING file
                    verbose("Warning: new package " + str( (package, path) ) + " differs from old package: " + str( blob_db[checksum] ))
                    if old_package.endswith(".src.rpm") and package.endswith(".rpm"):
                        # src RPM has higher priority than arch-specific RPM, so do not overwrite it
                        overwrite = False
                else:
                    verbose("Warning: new path " + str( (package, path) ) + " differs from existing path: " + str( blob_db[checksum] ), LEVEL_2)
            if overwrite:
                blob_db[checksum] = (package, path)  # only keep a single package, newer package overwrites older package
    return blob_db


############################################################
#### End of hash/checksum routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool parses bomsh_hook_raw_logfile and generates artifact tree and OmniBOR docs")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-r', '--raw_logfile',
                    help = "the raw_logfile from bomsh_hook script to read and process")
    parser.add_argument('-b', '--bom_dir',
                    help = "the directory to store the generated OmniBOR doc files")
    parser.add_argument('-l', '--logfile',
                    help = "the log file for verbose output")
    parser.add_argument('--lseek_lines_file',
                    help = "the file to save #lines read from raw_logfile, this option also means to read jsonfile for inital hash tree and read raw_logfile starting at #lseek_lines line")
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('--index_db_file',
                    help = "the JSON database file containing package name/version info for file checksums")
    parser.add_argument('--pkg_db_file',
                    help = "the JSON database file containing list of blobs for packages")
    parser.add_argument('-j', '--jsonfile',
                    help = "the generated OmniBOR artifact tree JSON file")
    parser.add_argument('-p', '--package_files',
                    help = "an extra comma-separated list of RPM/DEB package files to create OmniBOR docs")
    parser.add_argument('--package_list_file',
                    help = "a text file that contains a list of RPM/DEB package files to create OmniBOR docs")
    parser.add_argument('--package_dir',
                    help = "an extra comma-separated list of directories which contain RPM/DEB package files to create OmniBOR docs")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument('--dependency_criteria',
                    help = "the criteria for dependency, like normal/broad/compact, the default is normal")
    parser.add_argument("-g", "--new_omnibor_doc_for_unary_transform",
                    action = "store_true",
                    help = "generate new OmniBOR doc/identifier for single input/output file transform")
    parser.add_argument("--not_generate_gitbom_doc",
                    action = "store_true",
                    help = "do not generate OmniBOR docs")
    parser.add_argument("--embed_bom_section",
                    action = "store_true",
                    help = "embed the .bom ELF section for ELF files")
    parser.add_argument("--embed_o_file",
                    action = "store_true",
                    help = "embed .bom ELF section for intermediate *.o files")
    parser.add_argument("--embed_archive_file",
                    action = "store_true",
                    help = "embed .bom entry for archive files")
    parser.add_argument("--keep_duplicate_lines_in_omnibor_doc",
                    action = "store_true",
                    help = "even if there are duplicate lines in omnibor_doc, keep them")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    global args
    # Parse the command line arguments
    args = parser.parse_args()

    if not args.raw_logfile:
        print ("Please specify the raw_logfile with -r option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_bomdir
    global g_object_bomdir
    global g_bomsh_bomdir
    global g_with_bom_dir
    global g_raw_logfile
    global g_logfile
    global g_index_db
    global g_jsonfile
    global g_tmpdir
    if args.tmpdir:
        g_tmpdir = args.tmpdir
        g_jsonfile = os.path.join(g_tmpdir, "bomsh_createbom_jsonfile")
        g_logfile = os.path.join(g_tmpdir, "bomsh_createbom_logfile")
        g_raw_logfile = os.path.join(g_tmpdir, "bomsh_hook_raw_logfile")
    if args.not_generate_gitbom_doc:
        g_bomdir = g_object_bomdir = g_bomsh_bomdir = g_with_bom_dir = ''
    else:
        if args.bom_dir:
            g_bomdir = args.bom_dir
        g_bomdir = get_or_create_dir(g_bomdir)
        g_object_bomdir = get_or_create_dir(os.path.join(g_bomdir, "objects"))
        g_bomsh_bomdir = os.path.join(g_bomdir, "metadata", "bomsh")
        if args.embed_bom_section:
            g_with_bom_dir = get_or_create_dir(os.path.join(g_bomsh_bomdir, "with_bom_files"))
        else:
            g_bomsh_bomdir = get_or_create_dir(g_bomsh_bomdir)
    if args.raw_logfile:
        g_raw_logfile = args.raw_logfile
    if args.logfile:
        g_logfile = args.logfile
    if args.index_db_file:
        g_index_db = load_json_db(args.index_db_file)
    elif args.pkg_db_file:
        pkg_db = load_json_db(args.pkg_db_file)
        # Convert pkg_db to blob_db for prov_pkg metadata query
        blob_db = convert_pkg_db_to_blob_db(pkg_db)
        g_index_db = { blob : v[0] for blob,v in blob_db.items() }
    if args.jsonfile:
        g_jsonfile = args.jsonfile

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    # parse command line options first
    rtd_parse_options()

    read_raw_logfile(g_raw_logfile)
    package_files = []
    if args.package_dir:
        package_dirs = args.package_dir.split(",")
        package_files = find_all_package_files(package_dirs)
    if args.package_list_file:
        package_files.extend(read_text_file(args.package_list_file).splitlines())
    if args.package_files:
        package_files.extend(args.package_files.split(","))
    bomsh_pkgs_raw_logfile = ''
    if package_files:
        bomsh_pkgs_raw_logfile = process_package_files(package_files)
    # Finally save the generated databases
    save_gitbom_dbs(bomsh_pkgs_raw_logfile)


if __name__ == '__main__':
    main()
