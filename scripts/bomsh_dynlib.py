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
Bomsh script to create raw_logfile of runtime-dependency fragments for ELF executables.
Other Bomsh scripts can then generate snapshot OmniBOR artifact trees for Linux ELF binaries.

September 2023, Yongkui Han
"""

import pdb
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
LEVEL_5 = 5

args = None
g_chroot_dir = ''
g_tmpdir = "/tmp"
g_jsonfile = "/tmp/bomsh_dynlib_jsonfile"
g_raw_logfile = "/tmp/bomsh_dynlib_raw_logfile"
g_hashtypes = []
g_dynlib_namedb = { "32bit": {}, "64bit": {} }

#
# Helper routines
#########################
def verbose(string, level=1, logfile=None):
    """
    Prints information to stdout depending on the verbose level.
    :param string: String to be printed
    :param level: Unsigned Integer, listing the verbose level
    :param logfile: file to write
    """
    if args.verbose >= level:
        if logfile:
            append_text_file(logfile, string + "\n")
        # also print to stdout
        print(string)


def get_or_create_dir(destdir):
    """
    Create a directory if it does not exist. otherwise, return it directly
    return absolute path of destdir
    """
    if destdir and os.path.exists(destdir):
        return os.path.abspath(destdir)
    os.makedirs(destdir)
    return os.path.abspath(destdir)


def append_text_file(afile, text):
    '''
    Append a string to a text file.

    :param afile: the text file to write
    '''
    with open(afile, 'a+') as f:
         return f.write(text)


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


def find_all_elf_soexe_files(builddir):
    """
    Find all ELF shared object and executable files in the build dir.
    It simply runs the shell's find command and saves the result.
    :param builddir: String, build dir of the workspace
    :returns a list that contains all the binary file names.
    """
    print ("entering find_all_elf_soexe_files: the build dir is " + builddir)
    if builddir[0] != "/":
        builddir = os.path.abspath(builddir)
    #print ("the absolute build dir is " + builddir)
    findcmd = "find " + cmd_quote(builddir) + " -type f -exec sh -c 'file  \"$1\" | grep -E \" ELF.*shared object| ELF.*executable\"  >/dev/null ' _ {} \; -print  || true"
    print (findcmd)
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    print("Found " + str(len(files)) + " files in dir " + builddir)
    return files


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
    if g_chroot_dir != "/" and afile.startswith(g_chroot_dir):
        return afile[len(g_chroot_dir):]
    return afile


def get_chroot_path(path):
    """
    Get the real path in chroot environment.
    """
    if g_chroot_dir and not path.startswith(g_chroot_dir):
        return g_chroot_dir + path
    return path


def get_chroot_cmd(cmd):
    """
    Get the real cmd in chroot environment.
    """
    if g_chroot_dir:
        return 'chroot ' + g_chroot_dir + ' ' + cmd
    return cmd

############################################################
#### End of helper routines ####
############################################################

# a dict of { afile => list-of-rpaths }, cache for performance
g_rpaths_dict = {}

def get_elf_rpaths(afile):
    """
    Get list of RPATH or RUNPATH directories for an ELF file.
    :param afile: an ELF exec/so file
    returns a list of directories which is RPATH/RUNPATH.
    """
    if afile in g_rpaths_dict:
        return g_rpaths_dict[afile]
    #cmd = 'readelf -d ' + cmd_quote(afile) + ' | \(grep R.*PATH\) || true'
    cmd = get_chroot_cmd('readelf -d ' + cmd_quote(afile) + ' | grep R.*PATH || true')
    output = get_shell_cmd_output(cmd)
    rpaths = []
    if not output:
        g_rpaths_dict[afile] = rpaths
        return rpaths
    lines = output.splitlines()
    for line in lines:
        tokens = line.split()
        if len(tokens) < 5:
            continue
        paths = tokens[4].rstrip("]").lstrip("[")
        rpaths.extend(paths.split(":"))  # colon-separated list of directories
    verbose("elf file " + afile + " has rpaths: " + str(rpaths))
    rpaths = [ convert_rpath_origin(rpath, afile) for rpath in rpaths ]
    g_rpaths_dict[afile] = rpaths
    return rpaths


def convert_rpath_origin(rpath, afile):
    '''
    $ORIGIN means current directory of afile, do the conversion.
    '''
    if rpath == '$ORIGIN':
        return os.path.dirname(afile)
    return rpath


def get_dynamic_lib_in_dirs(rpaths, dep):
    '''
    Get the dynamic library file in a list of directories, for a specific libname.
    :param rpaths: a list of directories which is RPATH/RUNPATH
    :param dep: the specific libname for a dynamic library dependency
    returns the libfile if it exists in one of rpaths directory.
    Symbolic link is converted to its real path.
    '''
    for rpath in rpaths:
        lib = os.path.join(rpath, dep)
        chroot_path = get_chroot_path(lib)
        if os.path.exists(chroot_path):
            return get_noroot_path(os.path.realpath(chroot_path))
    return ''


def get_elf_dynamic_deps(afile):
    """
    Get direct dependencies for an ELF file.
    :param afile: the top-level file of dynlib dependency tree
    returns a list of libnames which are direct dependencies of afile.
    """
    cmd = get_chroot_cmd('readelf -d ' + cmd_quote(afile) + ' | grep NEEDED || true')
    output = get_shell_cmd_output(cmd)
    if not output:
        return []
    deps = []
    lines = output.splitlines()
    for line in lines:
        tokens = line.split()
        if len(tokens) < 5:
            continue
        deps.append(tokens[4].rstrip("]").lstrip("["))
    return deps


def get_dynamic_depfiles_for_Nbit(afile, name_libs):
    """
    Get direct dependencies for an ELF exec/so file.
    :param afile: the top-level file of dynlib dependency tree
    :param name_libs: the 32bit or 64bit dict of {libname => libfile}
    returns a list of libfiles which are direct dependencies of afile.
    """
    if name_libs == g_dynlib_namedb["32bit"]:
        extra_libs = g_dynlib_namedb["extra_32bit"]
    else:
        extra_libs = g_dynlib_namedb["extra_64bit"]
    deps = get_elf_dynamic_deps(afile)
    ret = []
    for dep in deps:
        lib = ''
        if dep in name_libs:
            lib = name_libs[dep]
        elif dep in extra_libs:
            lib = extra_libs[dep]
        else:
            rpaths = get_elf_rpaths(afile)  # RPATH/RUNPATH is also used to find libraries
            if rpaths:
                lib = get_dynamic_lib_in_dirs(rpaths, dep)
                if lib:
                    extra_libs[dep] = lib
        if lib:
            ret.append(lib)
        else:
            #pdb.set_trace()
            verbose("Warning: " + afile + " cannot find library file for library " + dep)
    return ret


def get_all_shared_libraries():
    """
    Get all the shared libraries in the build system/instance ldconfig cache.
    returns a dict of { "32bit": { libname => libfile }, "64bit": { libname => libfile } }
    """
    all_libs = { "32bit": {}, "64bit": {}, "extra_32bit": {}, "extra_64bit": {} }
    cmd = get_chroot_cmd("ldconfig -v -X -N 2>/dev/null || true")
    verbose(cmd)
    output = get_shell_cmd_output(cmd)
    verbose(output, LEVEL_2)
    if not output:
        return libs
    libs_32bit, libs_64bit = all_libs["32bit"], all_libs["64bit"]
    lib_dir, lib_dir_changed = '', False
    lines = output.splitlines()
    libs = libs_64bit
    for line in lines:
        tokens = line.strip().split()
        if ": (from " in line:
            lib_dir = tokens[0].rstrip(":")
            lib_dir_changed = True
            verbose("See a new lib_dir " + lib_dir)
            continue
        if " -> " in line:
            libname, libfilename = tokens[0], tokens[2]
            libfile = os.path.join(lib_dir, libfilename)
            if not lib_dir_changed:  # assume all libfiles in the same dir has the same Nbit
                libs[libname] = libfile
                continue
            filetype = get_filetype( get_chroot_path(libfile) )
            verbose("lib_dir changed, " + libfile + " filetype: " + filetype)
            if filetype.startswith("ELF 32-bit "):
                libs = libs_32bit
            else:
                libs = libs_64bit
            libs[libname] = libfile
            lib_dir_changed = False
            continue
    return all_libs


def get_all_dynlib_files(all_libs):
    '''
    Get a list of dynlib files in g_dynlib_namedb.
    :param all_libs: dict of { "32bit" => { libname => libfile} }, should be g_dynlib_namedb
    returns a list of all libfiles in this database.
    '''
    ret = []
    for key in all_libs:  # key is "32bit"/"64bit", etc.
        libs = all_libs[key]
        ret.extend( [ v for k,v in libs.items() ] )
    return ret


def create_dependency_fragment(afile, depfiles, hash_alg='sha1'):
    '''
    Create the dependency fragment to write to raw_logfile for a specific outfile.
    :param afile: the out file that depends on depfiles
    :param depfiles: a list of dependency files
    :param hash_alg: either sha1 or sha256
    returns a string for the dependency fragment.
    '''
    lines = []
    checksum = get_file_hash(get_chroot_path(afile), hash_alg)
    lines.append("outfile: " + checksum + " path: " + afile)
    for depfile in depfiles:
        checksum = get_file_hash(get_chroot_path(depfile), hash_alg)
        lines.append("infile: " + checksum + " path: " + depfile)
    lines.append("build_cmd: bomsh_elf_deps " + afile)
    lines.append("==== End of raw info for this process")
    text = "\n" + '\n'.join(lines) + "\n\n"
    return text


# a set of files to record if a file has been visited
g_dynlib_visited = set()

def append_raw_logfile_for_dynlib_node(afile, name_libs):
    '''
    Append to raw_logfile with fragments for afile itself and all its dependencies.
    This function recurses on itself.
    :param afile: the top-level file of dynlib dependency tree
    :param name_libs: the 32bit or 64bit dict of {libname => libfile}
    appends to raw_logfile, with build fragments written in correct order.
    it also updates g_dynlib_visited dict, flagging True for files that have dependency-fragments appended to raw_logfile.
    '''
    if afile in g_dynlib_visited:  # dependency-fragment for afile has been appended to raw_logfile
        return
    depfiles = get_dynamic_depfiles_for_Nbit(afile, name_libs)
    if not depfiles:  # leaf node, do nothing
        return
    for depfile in depfiles:
        append_raw_logfile_for_dynlib_node(depfile, name_libs)
    if "sha1" in g_hashtypes:
        fragment = create_dependency_fragment(afile, depfiles)
        append_text_file(g_raw_logfile + ".sha1", fragment)
    if "sha256" in g_hashtypes:
        fragment = create_dependency_fragment(afile, depfiles, "sha256")
        append_text_file(g_raw_logfile + ".sha256", fragment)
    g_dynlib_visited.add(afile)
    

def create_raw_logfile_for_files(afiles):
    '''
    Create raw_logfile with dependency fragments for a list of files.
    :param afiles: a list of ELF files
    writes new raw_logfile, with dependency fragments written in correct order.
    '''
    if len(afiles) < 11:
        print("==Creating raw_logfile for " + str(len(afiles)) + " files: " + str(afiles))
    else:
        print("==Creating raw_logfile for " + str(len(afiles)) + " files.")
    for afile in afiles:
        filetype = get_filetype( get_chroot_path(afile) )
        name_libs = g_dynlib_namedb["64bit"]
        if filetype.startswith("ELF 32-bit "):
            name_libs = g_dynlib_namedb["32bit"]
        append_raw_logfile_for_dynlib_node(afile, name_libs)
    if "sha1" in g_hashtypes:
        print("==Created sha1 raw_logfile: " + g_raw_logfile + ".sha1")
    if "sha256" in g_hashtypes:
        print("==Created sha256 raw_logfile: " + g_raw_logfile + ".sha256")


############################################################
#### End of shared library parsing routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool creates raw_logfile of runtime-dependency fragments for ELF executables")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('-r', '--raw_logfile',
                    help = "the raw log file, to store input/output file checksums")
    parser.add_argument('-O', '--output_dir',
                    help = "the output directory to store generated artifact tree dir")
    parser.add_argument('-j', '--jsonfile',
                    help = "the output JSON file for the search result")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument('-f', '--files',
                    help = "comma-separated files to change embedded bom-id")
    parser.add_argument('-d', '--dirs',
                    help = "comma-separated directories to search for files that need to change embedded bom-id")
    parser.add_argument('--chroot_dir',
                    help = "the mock chroot directory")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    global g_jsonfile
    global g_tmpdir
    global g_raw_logfile
    if args.tmpdir:
        g_tmpdir = args.tmpdir
        g_jsonfile = os.path.join(g_tmpdir, "bomsh_dynlib_jsonfile")
        g_raw_logfile = os.path.join(g_tmpdir, "bomsh_dynlib_raw_logfile")
    if args.output_dir:
        output_dir = get_or_create_dir(args.output_dir)
        g_jsonfile = os.path.join(output_dir, "bomsh_dynlib_jsonfile")
        g_raw_logfile = os.path.join(output_dir, "bomsh_dynlib_raw_logfile")
    if args.raw_logfile:
        g_raw_logfile = args.raw_logfile
    if args.jsonfile:
        g_jsonfile = args.jsonfile
    global g_chroot_dir
    if args.chroot_dir:
        g_chroot_dir = args.chroot_dir
    if args.hashtype:  # only sha1 and sha256 are supported for now
        if "sha1" in args.hashtype:
            g_hashtypes.append("sha1")
        if "sha256" in args.hashtype:
            g_hashtypes.append("sha256")
    if not g_hashtypes:
        g_hashtypes.append("sha1")

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    afiles = []
    if args.files:
        afiles = args.files.split(",")
        bfiles = []
        for afile in afiles:
            if os.path.exists( get_chroot_path(afile) ):
                bfiles.append(afile)
            else:
                print("Warning!!! file " + afile + " does not exist.")
        afiles = bfiles
    elif args.dirs:
        for adir in args.dirs.split(","):
            afiles.extend(find_all_elf_soexe_files( get_chroot_path(adir) ))
        afiles = [ get_noroot_path(afile) for afile in afiles]

    global g_dynlib_namedb
    g_dynlib_namedb = get_all_shared_libraries()
    save_json_db(g_jsonfile + "-namedb.json", g_dynlib_namedb)
    if not afiles:
        afiles = get_all_dynlib_files(g_dynlib_namedb)
    create_raw_logfile_for_files(afiles)


if __name__ == '__main__':
    main()
