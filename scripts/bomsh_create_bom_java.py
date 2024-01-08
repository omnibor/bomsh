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
Bomsh script to generate gitBOM artifact tree and gitBOM docs for java .jar files.

The created JSON hash-tree DB file can be used for CVE search
by the bomsh_search_cve.py script.

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

g_rootdir = ''
g_abs_rootdir = ''
g_tmp_unbundle_dir = "/tmp/bomjdir"
g_jsonfile = "/tmp/bomsh_createbom_jsonfile"
g_bomdir = "/tmp/bomdir"
g_with_bom_dir = "/tmp/bomdir/with-bom-files"
g_use_zip = False

# the below two dicts store the file basename to full path mapping for all the .java/.class files in the rootdir.
g_java_files = {}
g_class_files = {}
# this below dict saves the .class file to .java file mapping recorded by strace logfile.
g_classfile_records = {}

# g_treedb stores the binary file githash to hash-tree mapping
# { githash of binary file => list of githash of its dependencies }
g_treedb = {}
# g_bomdb stores the binary file githash to gitBOM doc githash mapping
# { githash of binary file => githash of its gitBOM doc }
g_bomdb = {}
# g_pre_exec_db temporarily stores the pre-exec checksum of the same input/output file for strip/ranlib commands.
g_pre_exec_db = {}

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
        '''
        afile = g_logfile
        if logfile:
            afile = logfile
        if afile:
            append_text_file(afile, string + "\n")
        '''
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


def which_tool_exist(tool):
    """
    Check whether tool is on PATH.
    """
    retcode = os.system('which ' + tool + ' > /dev/null')
    return retcode == 0


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
    res = re.split(":\s+", output.strip())
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


def is_same_file_content(afile, bfile):
    """
    Check if the two files have the same contents.
    """
    cmd = 'diff -q ' + cmd_quote(afile) + ' ' + cmd_quote(bfile) + ' || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    #print (output)
    if output:
        return False
    return True


def find_all_suffix_files(builddir, suffix):
    """
    Find all files with the specified suffix in the build dir.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :param suffix: the suffix of files to find
    :returns a list that contains all the file names with the suffix.
    """
    findcmd = "find " + cmd_quote(builddir) + ' -type f -name "*' + suffix + '" -print || true'
    # print(findcmd)
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    #print(len(files))
    return files

############################################################
#### Start of gitbom routines ####
############################################################

def create_gitbom_doc_text(infiles, db):
    """
    Create the gitBOM doc text contents
    :param infiles: the list of checksum for input files
    :param db: gitBOM DB with {file-hash => its gitBOM hash} mapping
    """
    if not infiles:
        return ''
    lines = []
    for ahash in infiles:
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
    :param infile_hashes: the list of input file hashes
    :param db: gitBOM DB with {file-hash => its gitBOM hash} mapping
    :param destdir: destination directory to create the gitbom doc file
    returns the git-hash of the created gitBOM doc.
    """
    lines = create_gitbom_doc_text(infile_hashes, db)
    output_file = "/tmp/bomsh_temp_gitbom_file"
    write_text_file(output_file, lines)
    ahash = get_git_file_hash(output_file)
    newfile = os.path.join(destdir, ahash)
    if os.path.exists(newfile):
        if infile_hashes:
            verbose("Warning: gitBOM file " + newfile + " already exists for infiles " + str(infile_hashes), LEVEL_4)
            verbose("Warning: gitBOM file " + newfile + " already exists, file contents: " + lines, LEVEL_3)
    else:
        shutil.move(output_file, newfile)
    return ahash


def embed_gitbom_hash_jar_entry(afile, gitbom_doc, outfile):
    """
    Embed the .bom archive entry into a jar file.
    :param afile: the jar file to insert the embedded .bom archive entry
    :param gitbom_doc: gitBOM doc for this afile
    :param outfile: output file with the .bom archive entry
    """
    #verbose("afile: " + afile + "gitbom_doc: " + gitbom_doc + " outfile: " + outfile)
    dirname = os.path.dirname(outfile)
    basename = os.path.basename(outfile)
    temp_bom_file = os.path.join(dirname, ".bom")
    cmd = 'git hash-object ' + gitbom_doc + ' | head --bytes=-1 | xxd -r -p > ' + temp_bom_file
    cmd += " ; cp " + afile + " " + outfile
    cmd += " ; cd " + dirname
    if g_use_zip:
        cmd += " ; zip " + basename + " .bom || true"
    else:
        cmd += " ; jar -uf " + basename + " .bom || true"
    #verbose("The embed_archive_bom cmd: " + cmd)
    get_shell_cmd_output(cmd)


def update_gitbom_dir(bomdir, infiles, checksum, outfile):
    '''
    Update the gitBOM directory with hashes of input files and outfile
    :param bomdir: the gitBOM directory
    :param infiles: a list of the hashes of input files
    :param checksum: the checksum/hash of the output file
    :param outfile: the output file
    '''
    if not infiles:
        verbose("Warning: infile is empty, skipping gitBOM doc update for outfile " + outfile)
        return
    gitbom_doc_hash = create_gitbom_doc(infiles, g_bomdb, bomdir)
    verbose("Created gitBOM file " + gitbom_doc_hash + " for outfile " + outfile)
    g_bomdb[checksum] = gitbom_doc_hash
    if args.not_embed_bom_section:
        return
    if False:  # for JAVA, all .jar/.class outfiles must exist and match the calculated checksum
    #if not os.path.isfile(outfile) or get_git_file_hash(outfile) != checksum:
        verbose("Warning: outfile with checksum " + checksum + " does not exist, skip embedding gitBOM for outfile " + outfile)
        return
    # Try to embed the .bom JAR archive entry
    if outfile[-4:] == ".jar" and is_jar_file(outfile):
        gitbom_doc = os.path.join(bomdir, gitbom_doc_hash)
        with_bom_file = os.path.join(g_with_bom_dir, checksum + "-with_bom-" + gitbom_doc_hash + "-" + os.path.basename(outfile))
        verbose("Create JAR with_bom file: " + with_bom_file)
        embed_gitbom_hash_jar_entry(outfile, gitbom_doc, with_bom_file)


############################################################
#### Start of hash tree DB update routines ####
############################################################

def update_hash_tree_node_filepath(db, ahash, afile):
    '''
    Update the file_path of a single node in the hash tree

    :param db: the hash tree DB to update
    :param ahash: the hash of the afile
    :param afile: a file, either input file or output file
    '''
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


def update_hash_tree_node_buildcmd(afile_db, ahash, outfile, argv_str):
    '''
    Update the build_cmd of a single node in the hash tree

    :param afile_db: the hash tree DB node to update
    :param ahash: the hash of the outfile
    :param outfile: the output file for the shell command
    :param argv_str: the full shell command with all its command line options/parameters
    '''
    # First add the build command to the database
    verbose(outfile + " is outfile, update build_cmd: " + argv_str)
    if "build_cmd" in afile_db and afile_db["build_cmd"] != argv_str:
        verbose("Warning: checksum " + ahash + " already has build command. outfile: " + outfile)
        # create build_cmds with the list of all build commands
        if "build_cmds" in afile_db:
            if argv_str not in afile_db["build_cmds"]:
                afile_db["build_cmds"].append(argv_str)
        else:
            afile_db["build_cmds"] = [afile_db["build_cmd"], argv_str]
    if "build_cmd" not in afile_db:
        afile_db["build_cmd"] = argv_str


def update_hash_tree_node_hashtree(db, ahash, outfile, infiles, argv_str, pid=''):
    '''
    Update the build_cmd and hashtree of a single node in the hash tree

    :param db: the hash tree DB to update
    :param ahash: the hash of the outfile
    :param outfile: the output file for the shell command
    :param infiles: the list of (checksum, file_path) for input files
    :param argv_str: the full shell command with all its command line options/parameters
    :param pid: the PID of the shell command
    returns the newly created hash_tree, empty or not. This is a list of checksums
    '''
    afile_db = db[ahash]
    if argv_str:
        update_hash_tree_node_buildcmd(afile_db, ahash, outfile, argv_str)
    # Next update the hashtree as needed
    hash_tree = [f[0] for f in infiles]
    if pid and pid in g_pre_exec_db:
        checksum = g_pre_exec_db[pid][1]
        verbose("Consuming pre_exec record, pid: " + pid + " checksum: " + checksum + " new checksum: " + ahash + " outfile: " + outfile)
        if checksum != ahash:  # must be different to deserve a hash tree dependency
            hash_tree = [checksum,]
        del g_pre_exec_db[pid]
    if not hash_tree:
        verbose("Warning: checksum " + ahash + " has empty hashtree. outfile: " + outfile)
        return hash_tree
    if "hash_tree" in afile_db:
        verbose("Warning: checksum " + ahash + " already has hash tree. outfile: " + outfile)
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
    return hash_tree


def update_hash_tree_db_and_gitbom(db, record):
    """
    Update the hash tree DB and the gitBOM doc for an output file.

    :param db: the hash tree DB to update
    :param record: the raw_info record for a single shell command
    """
    checksum, outfile = record["outfile"]
    verbose("\n=== Update treedb and gitBOM for checksum: " + checksum + " outfile: " + outfile, LEVEL_0)
    if not checksum:
        verbose("Warning: empty checksum for outfile " + outfile + ", skipping hash tree and gitBOM doc update")
        return
    pid = ''
    if "pid" in record:
        pid = record["pid"]
    if "exec_mode" in record and record["exec_mode"] == "pre_exec":
        verbose("pre_exec record, pid: " + pid + " checksum: " + checksum + " outfile: " + outfile)
        if pid:
            g_pre_exec_db[pid] = (outfile, checksum)
        return
    update_hash_tree_node_filepath(db, checksum, outfile)
    infiles = []
    if "infiles" in record:
        infiles = record["infiles"]
    for ahash, afile in infiles:
        if not ahash:
            continue
        update_hash_tree_node_filepath(db, ahash, afile)
    verbose("updated hash tree DB for outfile " + outfile)
    argv_str = ''
    if "build_cmd" in argv_str:
        argv_str = record["build_cmd"]
    hash_tree = update_hash_tree_node_hashtree(db, checksum, outfile, infiles, argv_str, pid)
    if args.bom_dir:
        update_gitbom_dir(g_bomdir, hash_tree, checksum, outfile)


############################################################
#### End of shell command handling routines ####
############################################################

def get_source_file_of_class_file(classfile):
    """
    Get the SourceFile attribute of a Java .class file.
    """
    cmd = "javap " + cmd_quote(classfile) + " || true"
    # print(cmd)
    output = get_shell_cmd_output(cmd)
    lines = output.splitlines()
    source_file = ''
    if not lines:
        return source_file
    line0 = lines[0]
    if line0[:15] == 'Compiled from "':
        source_file = line0[15:-1]
    return source_file


def get_source_file_of_class_files_internal(classfiles):
    """
    Get the SourceFile attribute of a list of Java .class files.
    """
    all_classfiles = ' '.join([cmd_quote(f) for f in classfiles])
    #cmd = "javap " + cmd_quote(all_classfiles) + ' | grep "Compiled from " || true'
    cmd = "javap " + all_classfiles + ' | grep "Compiled from " || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd)
    lines = output.splitlines()
    if len(lines) != len(classfiles):
        print("Warning: Different number " + str(len(lines)) + " of SourceFile attributes than number " + str(len(classfiles)) + " of .class files");
        return []
    source_files = []
    for line in lines:
        source_file = line[15:-1]
        source_files.append(source_file)
    verbose("Number of SourceFile attributes found: " + str(len(source_files)), LEVEL_2)
    return source_files


bash_cmd_line_maxlimit = 100000

def get_source_file_of_class_files(afiles):
    """
    Get the SourceFile attribute of a list of Java .class files.
    """
    afiles_arg = ' '.join(afiles)
    len_afiles_arg = len(afiles_arg)
    if len_afiles_arg > bash_cmd_line_maxlimit:
        num_cmd = len_afiles_arg // bash_cmd_line_maxlimit + 1
        len_afiles = len(afiles)
        step = len_afiles // num_cmd + 1
        verbose("Get SourceFile for " + str(len(afiles)) + " class files: divided into " + str(num_cmd) + " steps, each step processes " + str(step) + " files.")
        bundle_files = []
        for i in range(num_cmd):
            sub_afiles = afiles[i * step : (i+1) * step]
            if not sub_afiles:
                continue
            afiles_arg = ' '.join(sub_afiles)
            if len(afiles_arg) > bash_cmd_line_maxlimit:  # still possible to exceed the 100K bash limit, if so, divide into two more commands
                sub_afiles = afiles[i * step: (i * step + step // 2)]
                source_files = get_source_file_of_class_files_internal(sub_afiles)
                verbose("get_source_file_of_class_files is divided into " + str(num_cmd) + " steps. This is step " + str(i) + " substep 1", LEVEL_3)
                if not source_files:
                    return []
                bundle_files.extend(source_files)
                sub_afiles = afiles[(i * step + step // 2) : (i + 1) * step]
            source_files = get_source_file_of_class_files_internal(sub_afiles)
            if not source_files:
                #print("Warning: Different number " + str(len(bundlefiles)) + " of SourceFile attributes than number " + str(len(afiles)) + " of .class files");
                return []
            bundle_files.extend(source_files)
            verbose("get_source_file_of_class_files is divided into " + str(num_cmd) + " steps. This is step " + str(i), LEVEL_2)
    else:
        bundle_files = get_source_file_of_class_files_internal(afiles)
    verbose("Total number of SourceFile attributes found: " + str(len(bundle_files)))
    return bundle_files


def get_class_name_of_class_file(classfile):
    """
    Get the full class name of a Java .class file.
    """
    cmd = "javap " + cmd_quote(classfile) + " || true"
    # print(cmd)
    output = get_shell_cmd_output(cmd)
    lines = output.splitlines()
    if not lines:
        return ''
    for line in lines:
        tokens = line.split()
        if len(tokens) > 4 and line[-2:] == " {":
            return line[3]
    return ''


def get_javap_info_of_class_file(classfile):
    """
    Get the SourceFile and class name or interface name of a Java .class file.
    """
    cmd = "javap " + cmd_quote(classfile) + " || true"
    # print(cmd)
    output = get_shell_cmd_output(cmd)
    lines = output.splitlines()
    if not lines:
        return ('', '')
    source_file, class_name = ('', '')
    for line in lines:
        tokens = line.split()
        if line[:15] == 'Compiled from "':
            source_file = line[15:-1]
        elif line[-2:] == " {":
            if " class " in line and len(tokens) > 4:
                class_name = tokens[3]
            elif " interface " in line and len(tokens) > 3:
                class_name = tokens[2]
    return (source_file, class_name)


def get_next_token(tokens, match_token):
    """
    Get the next token after the match_token in the list of tokens.
    """
    next_token = False
    for token in tokens:
        if token == match_token:
            next_token = True
        if next_token:
            return token
    return ''


def get_java_file_class_name(javafile):
    """
    Get the full class name or interface name of a .java file
    """
    package = ''
    class_name = ''
    with open(javafile, 'r') as f:
        for line in f:
            if line[:8] == "package ":
                tokens = line.split()
                package = tokens[1].rstrip(";");
            elif " class " in line and line[-2:] == " {":
                tokens = line.split()
                class_name = getnext_token(tokens, "class")
            elif " interface " in line and line[-2:] == " {":
                tokens = line.split()
                class_name = getnext_token(tokens, "interface")
    if package:
        return package + "." + class_name
    return class_name


def get_list_similarity_score(list1, list2):
    """
    Compare two lists and calculate a similarity score between the two lists.
    returns the number of first few identical elements between the two lists.
    """
    length = len(list1)
    if len(list2) < length:
        length = len(list2)
    score = 0
    for i in range(length):
        if list1[i] == list2[i]:
            score +=1
        else:
            break
    return score


def get_file_path_similarity_score(path1, path2):
    """
    Compare two file paths and calculate a similarity score between the two paths.
    """
    tokens1 = path1.split("/")
    tokens2 = path2.split("/")
    score1 = get_list_similarity_score(tokens1, tokens2)
    score2 = get_list_similarity_score(tokens1[:-1][::-1], tokens2[:-1][::-1])
    return score1 + score2


def find_matching_file_in_dict(in_file, adict):
    """
    Find a matching file in a dict of files. The matching file must have same file content
    :param in_file: a .class file unbundled from a .jar file
    :param adict: a dict of .class files, with basename as dict key
    """
    basename = os.path.basename(in_file)
    afiles = []
    if basename in adict:
        afiles = adict[basename]
    if not afiles:
        return ''
    for afile in afiles:
        if is_same_file_content(afile, in_file):
            return afile
    return ''


def find_java_file_in_dict(in_file, adict, classfile):
    """
    Find a matching .java file in a list of files. The matching file must have similar path as classfile.
    :param in_file: the source .java file of a .class file from javap.
    :param adict: a dict of .java files, with basename as dict key
    :param classfile: the .class file to find its matching source .java file.
    """
    basename = os.path.basename(in_file)
    afiles = []
    if basename in adict:
        afiles = adict[basename]
    if not afiles:
        return ''
    best_file = ''
    # example: ./maven-settings/target/classes/org/apache/maven/settings/Proxy.class
    best_score = 2  # minimum score of 3, like aaa/bbb/target/classes/org/apache/xxx/yyy.class
    scores = {}
    for afile in afiles:
        score = get_file_path_similarity_score(classfile, afile)
        scores[afile] = score
        if score > best_score:
            best_score = score
            best_file = afile
    if len(afiles) > 1:
        verbose("\n---- classfile: " + classfile + " Found multiple .java files: " + str(afiles), LEVEL_2)
        verbose("Warning: multiple files found for " + basename + " picked " + best_file + " with best score of " + str(best_score))
        verbose("All path similarity scores are: " + str(scores), LEVEL_3)
    if best_file and (best_score <= 4 or best_score < len(classfile.split("/")) - 5):
        verbose("Warning: picked " + best_file + " with low similarity score " + str(best_score) + " for " + classfile)
        verbose("All path similarity scores are: " + str(scores), LEVEL_3)
    return best_file


def find_java_file_for_classfile(classfile, source_file):
    """
    Find a matching .java file in a list of files. The matching file must have similar path as classfile.
    :param classfile: the .class file to find its matching source .java file.
    :param source_file: the source .java file of a .class file from javap.
    """
    if not source_file:
        source_file = get_source_file_of_class_file(classfile)
    if source_file:
        source_file = find_java_file_in_dict(source_file, g_java_files, classfile)
    return source_file


def get_java_file_for_classfile_from_strace(classfile, d_records, rootdir):
    """
    Find the JAVA file for a class file in the dict from strace.
    """
    if classfile[0] != "/":
        classfile = os.path.abspath(classfile)
    if classfile not in d_records:
        return ''
    java_file = d_records[classfile].replace(g_abs_rootdir, rootdir, 1)
    return java_file


def process_class_file(classfile, rootdir, source_file=''):
    """
    Process a single .class file.
    """
    if not os.path.isfile(classfile):
        return
    match_classfile = find_matching_file_in_dict(classfile, g_class_files)
    if not match_classfile:
        # No need to search for .java source file if no matching .class file found in rootdir build workspace.
        verbose("Warning: Cannot find this .class file: " + classfile)
        return classfile
    #print("Initial source file: " + source_file + " class_file: " + classfile)
    classfile = match_classfile
    strace_source_file = ''
    if g_classfile_records:
        strace_source_file = get_java_file_for_classfile_from_strace(match_classfile, g_classfile_records, rootdir)
        verbose("From strace logfile, Find SourceFile " + strace_source_file + " for class file " + classfile, LEVEL_3)
    if strace_source_file:
        source_file = strace_source_file
    else:
        source_file = find_java_file_for_classfile(classfile, source_file)
        verbose("From SourceFile attribute, Find SourceFile " + source_file + " for class file " + classfile, LEVEL_3)
    #print("source file: " + source_file + " class_file: " + classfile)
    record = {"outfile": (get_git_file_hash(classfile), classfile)}
    if source_file:
        record["infiles"] = [(get_git_file_hash(source_file), source_file),]
    #print("Created record: " + str(record))
    update_hash_tree_db_and_gitbom(g_treedb, record)
    return classfile


def unbundle_jar_file(jarfile, destdir):
    """
    Unbundle a .jar file to destination directory.
    """
    cmd = "rm -rf " + destdir + " 2>/dev/null ; mkdir -p " + destdir + "; cd " + destdir + "; jar -xf " + cmd_quote(jarfile) + " || true"
    # print(cmd)
    get_shell_cmd_output(cmd)


def process_jar_file(jarfile, rootdir):
    """
    Process a single .jar file.
    """
    if not os.path.isfile(jarfile):
        return
    jarfile_abspath = jarfile
    if jarfile[0] != "/":
        jarfile_abspath = os.path.abspath(jarfile)
    destdir = os.path.join(g_tmp_unbundle_dir, os.path.basename(jarfile))
    unbundle_jar_file(jarfile_abspath, destdir)
    classfiles = find_all_suffix_files(destdir, ".class")
    source_files = get_source_file_of_class_files(classfiles)
    #print(classfiles)
    record = {"outfile": (get_git_file_hash(jarfile), jarfile), "infiles": []}
    for i in range(len(classfiles)):
         classfile = classfiles[i]
         if source_files:
             source_file = source_files[i]
         classfile = process_class_file(classfile, rootdir, source_file)
         record["infiles"].append( (get_git_file_hash(classfile), classfile) )
    #print("jarfile: " + jarfile + " Created record: " + str(record))
    update_hash_tree_db_and_gitbom(g_treedb, record)
    shutil.rmtree(destdir, True)


def add_files_to_dict(d, afiles):
    """
    Add all files to dict, using basename as key.
    """
    for afile in afiles:
        basename = os.path.basename(afile)
        if basename in d:
            d[basename].append(afile)
        else:
            d[basename] = [afile,]


def find_all_java_and_class_files(rootdir):
    """
    Find all .java and .class files in rootdir. Also add these files to global dicts.
    """
    javafiles = find_all_suffix_files(rootdir, ".java")
    classfiles = find_all_suffix_files(rootdir, ".class")
    add_files_to_dict(g_java_files, javafiles)
    add_files_to_dict(g_class_files, classfiles)
    print("\nFound " + str(len(javafiles)) + " .java files and " + str(len(classfiles)) + " .class files in rootdir " + rootdir + "\n")
    return (javafiles, classfiles)


def find_and_process_jar_files(rootdir):
    """
    Find and process all .jar files in the rootdir.
    """
    if not rootdir:
        return
    if args.jar_files:
        jarfiles = args.jar_files.split(",")
    elif args.jar_dirs:
        jar_dirs = args.jar_dirs.split(",")
        jarfiles = []
        for adir in jar_dirs:
            jarfiles.extend( find_all_suffix_files(adir, ".jar") )
    else:
        jarfiles = find_all_suffix_files(rootdir, ".jar")
    #print(jarfiles)
    find_all_java_and_class_files(rootdir)
    for jarfile in jarfiles:
        process_jar_file(jarfile, rootdir)
    # Finally save the updated DB to the JSON file
    jsonfile = os.path.join(g_bomdir, "bomsh_gitbom_doc_mapping")
    save_json_db(jsonfile, g_bomdb)
    save_json_db(g_jsonfile, g_treedb)
    #print (json.dumps(g_treedb, indent=4, sort_keys=True))
    verbose("Number of checksums in GITBOM DOCDB: " + str(len(g_bomdb)), LEVEL_0)
    verbose("Number of checksums in GITBOM TREEDB: " + str(len(g_treedb)), LEVEL_0)


############################################################
#### End of shell command read/parse routines ####
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


def is_jar_file(afile):
    """
    Check if a file is a Java archive file.

    :param afile: String, name of file to be checked
    :returns True if the file is JAR file. Otherwise, return False.
    """
    return " archive data" in get_filetype(afile)


def read_strace_logfile(strace_logfile):
    """
    Read and process the recorded strace info from strace JAVA compilation.

    :param strace_logfile: the log file that contains the strace recorded info
    """
    print("Reading and processing strace logfile: " + strace_logfile)
    classfile_records = {}
    javafiles = []
    classfiles = []
    with open(strace_logfile, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or not " openat(" in line:
                continue
            tokens = line.split('"')
            if len(tokens) < 3:
                continue
            afile = tokens[1]
            if afile[-5:] != ".java" and afile[-6:] != ".class":
                continue
            tokens = line.split(', ')
            if len(tokens) < 3:
                continue
            mode = tokens[2]
            if ") " in mode:
                tokens = mode.split(") ")
                mode = tokens[0]
            if afile[-5:] == ".java" and "O_RDONLY" in mode:
                javafiles.append(afile)
            elif afile[-6:] == ".class" and "O_WRONLY" in mode:
                classfiles.append(afile)
    print("Number of .java files: " + str(len(javafiles)))
    print("Number of .class files: " + str(len(classfiles)))
    source_files = get_source_file_of_class_files(classfiles)
    for i in range(len(classfiles)):
        classfile = classfiles[i]
        if source_files:
            source_file = source_files[i]
        else:
            source_file = get_source_file_of_class_file(classfile)
        a_source_files = [afile for afile in javafiles if os.path.basename(afile) == source_file]
        best_afile = find_java_file_in_dict(source_file, {source_file: a_source_files}, classfile)
        classfile_records[classfile] = best_afile
    print("Number of .class files with source .java file found: " + str(len(classfile_records)))
    #print (json.dumps(classfile_records, indent=4, sort_keys=True))
    return classfile_records


############################################################
#### End of hash/checksum routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool scans JAVA build workspace and generates artifact tree and gitBOM docs")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-r', '--root_directory',
                    help = "the root directory of the build workspace")
    parser.add_argument('-f', '--jar_files',
                    help = "a list of comma-separated .jar/.class files to build gitBOM database")
    parser.add_argument('-d', '--jar_dirs',
                    help = "a list of comma-separated directories to search .jar/.class files")
    parser.add_argument('-b', '--bom_dir',
                    help = "the directory to store the generated gitBOM doc files")
    parser.add_argument('-s', '--strace_logfile',
                    help = "the strace log file to read for JAVA compilation")
    parser.add_argument('--tmp_unbundle_dir',
                    help = "temporary directory for unbundling .jar file, which is /tmp/bomjdir by default")
    parser.add_argument('-j', '--jsonfile',
                    help = "the generated artifact tree JSON file")
    parser.add_argument("-m", "--not_embed_bom_section",
                    action = "store_true",
                    help = "not embed the .bom ELF section or archive entry")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.root_directory):
        print ("Please specify the root directory with -r option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_bomdir
    global g_with_bom_dir
    if args.bom_dir:
        g_bomdir = get_or_create_dir(args.bom_dir)
        g_with_bom_dir = get_or_create_dir(os.path.join(args.bom_dir, "with_bom_files"))
    global g_use_zip
    g_use_zip = which_tool_exist("zip")
    global g_rootdir
    global g_abs_rootdir
    if args.root_directory:
        g_rootdir = args.root_directory
        g_abs_rootdir = os.path.abspath(g_rootdir)
    global g_jsonfile
    if args.jsonfile:
        g_jsonfile = args.jsonfile
    global g_tmp_unbundle_dir
    if args.tmp_unbundle_dir:
        g_tmp_unbundle_dir = args.tmp_unbundle_dir

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    global g_classfile_records
    if args.strace_logfile:
        g_classfile_records = read_strace_logfile(args.strace_logfile)
    find_and_process_jar_files(g_rootdir)


if __name__ == '__main__':
    main()
