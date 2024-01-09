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
Bomsh script to create index DB for blobs of OpenEmbedded/Yocto projects.

May 2023, Yongkui Han
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
g_tmpdir = "/tmp"
g_download_dir = ''
g_unbundle_dir = ''
g_download_stats = {}


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


def get_size_of_dir(destdir):
    """
    Run "du -sb destdir" to get the total size of a directory.
    return total size in unit of bytes
    """
    cmd = 'du -sb ' + destdir + ' || true'
    output = get_shell_cmd_output(cmd)
    tokens = output.split()
    return int(tokens[0])


def read_text_file(afile, encoding=None):
    '''
    Read a text file as a string.

    :param afile: the text file to read
    '''
    with open(afile, 'r', encoding=encoding) as f:
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
    try:
        f = open(db_file, 'w')
    except IOError as e:
        print ("I/O error({0}): {1}".format(e.errno, e.strerror))
        print ("Error in save_json_db, skipping it.")
    else:
        with f:
            json.dump(db, f, indent=indentation, sort_keys=True)


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
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True, errors='backslashreplace')
    files = output.splitlines()
    return files


def find_all_recipe_files(builddir):
    """
    Find all recipe files in the build dir, excluding symbolic link files.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :returns a list that contains all the recipe file names.
    """
    builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' -name "recipe-*.spdx.json" -type f -print || true '
    verbose(findcmd, LEVEL_2)
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True, errors='backslashreplace')
    files = output.splitlines()
    return files


############################################################
#### End of helper routines ####
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


def get_git_files_hash(afiles):
    '''
    Get the git hash of a list of files.
    :param afiles: the files to calculate the git hash or digest.
    '''
    hashes = {}
    for afile in afiles:
        hashes[afile] = get_git_file_hash(afile)
    return hashes


def unbundle_package(pkgfile, destdir=''):
    '''
    unbundle RPM/DEB package to destdir.
    :param pkgfile: the RPM/DEB package file to unbundle
    :param destdir: the destination directory to save unbundled files
    '''
    if not destdir:
        destdir = os.path.join(g_unbundle_dir, "bomsh-extract-" + os.path.basename(pkgfile) + "-dir")
    if args.skip_download_if_exist and os.path.exists(destdir) and os.listdir(destdir):
        # if user wants to skip, and destdir is not empty, then return directly
        verbose("The extract dir " + destdir + " is not empty, skip unbundling package " + pkgfile, LEVEL_2)
        return destdir
    if pkgfile[-4:] == ".rpm":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; cd " + destdir + " ; rpm2cpio " + pkgfile + " | cpio -idm || true"
    elif pkgfile[-4:] == ".deb" or pkgfile[-5:] == ".udeb":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; dpkg-deb -xv " + pkgfile + " " + destdir + " || true"
    elif pkgfile[-4:] == ".tgz" or pkgfile[-7:] in (".tar.gz", ".tar.xz") or pkgfile[-8:] == ".tar.bz2":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; tar -xf " + pkgfile + " -C " + destdir + " || true"
    else:
        print("Unsupported package format in " + pkgfile + " file, skipping it.")
        return ''
    verbose("Unbundle package cmd: " + cmd, LEVEL_2)
    get_shell_cmd_output(cmd)
    return destdir


############################################################
#### End of helper routines ####
############################################################

def wget_url(url, destdir, destpath='', skip_if_exist=False, timeout=0):
    """
    run wget to download a file from url
    :param url: the URL to download file
    :param destdir: the destination directory to store the downloaded file
    :param destpath: the destination file name or path
    :param skip_if_exist: a True/False flag. if True and destpah already exists, then skip downloading.
    returns the downloaded file path
    """
    #cmd = "wget " + url + " -P " + destdir + " || true"
    #get_shell_cmd_output(cmd)
    if destpath:
        cmds = ['wget', url, '-O', destpath, '--no-check-certificate', '--tries=2']
    else:
        cmds = ['wget', url, '-P', destdir, '--no-check-certificate', '--tries=2']
        basename = os.path.basename(url)
        if not basename:
            basename = "index.html"
        destpath = os.path.join(destdir, basename)
    if timeout:
        cmds.append("--timeout=" + str(timeout))
    verbose("wget_url cmd: " + str(cmds))
    if os.path.exists(destpath):
        if skip_if_exist:  # Assume this local destpath file is same as the URL file to download
            verbose(destpath + " already exists, skip downloading again", LEVEL_2)
            return destpath
        os.remove(destpath)  # Otherwise, needs to remove it before downloading
    retcode = subprocess.run(cmds, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    verbose("retcode: " + str(retcode) + " when downloading URL " + url, LEVEL_4)
    if retcode != 0:
        return ''
    return destpath


def get_all_blobs_of_git_commit(commit, git_dir=''):
    """
    Run the "git rev-list -n 1 commit_id" command to get all blobs of a a commit.
    """
    if git_dir:
        cmd = "cd " + git_dir + " ; git rev-list -n 1 --objects " + commit
    else:
        cmd = "git rev-list -n 1 --objects " + commit
    cmd += " | git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize) %(rest)' |  grep '^[^ ]* blob' | cut -d' ' -f1,3- || true"
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    #print(output)
    lines = output.splitlines()
    blobs = []
    for line in lines:
        #print(line)
        tokens = line.split()
        checksum, size = tokens[0], tokens[1]
        width = len(size)
        # len of git SHA1 checksum must be 40
        filename = line[42 + width : ]
        size = int(size)
        if filename[0] != '.':  # let's exclude hidden files?
            blobs.append( (checksum, size, filename) )
    return blobs


def convert_git_url(git_url):
    '''
    Convert git_url to approripate url for "git clone" command.
    :param git_url: a URL like ssh://wwwin-github.cisco.com/xr-oe/netstack.git
    '''
    if git_url.startswith("git:"):
        return "https" + git_url[3:]
    elif git_url.startswith("ssh://"):
        url = git_url[6:]
        tokens = url.split("/")
        return "git@" + tokens[0] + ":" + '/'.join(tokens[1:])
    return git_url


def bomsh_git_clone_url(git_url, destdir):
    '''
    git clone a URL to destdir.
    '''
    git_url = convert_git_url(git_url)
    # well, if destdir is not empty, the below git clone will fail
    cmd = 'git clone -n ' + git_url + ' ' + destdir + ' || true'
    verbose(cmd, LEVEL_2)
    os.system(cmd)
    if not os.path.exists(destdir):
        verbose("Warning: Failed to git clone " + git_url)
        return ''
    return destdir


def get_git_clone_dest_dir(git_url):
    '''
    Convert git_url of ssh://wwwin-github.cisco.com/xr-oe/cisco-libtam.git
    to wwwin-github.cisco.com.xr-oe.cisco-libtam.git as destdir for git clone
    '''
    tokens = git_url.split("//")
    return tokens[1].replace("/", ".")


def get_all_blobs_of_git_commit_url(downloadLocation, destdir=''):
    '''
    download git repo to destdir and get all blobs of a commit.
    git+https://github.com/missinglinkelectronics/libuio.git@e09e93f9dd94fd507a9931febfcb5d237764fb3e
    git+git://sourceware.org/git/lvm2.git@b9391b1b9f0b73303fa21f8f92574d17ce4c2b02
    git+ssh://wwwin-github.cisco.com/xr-oe/netstack.git@2c3c2569d05fa5fcca27f8db32af43ae4ef302ad
    gitsm+https://github.com/tianocore/edk2.git@06dc822d045c2bb42e497487935485302486e151
    '''
    tokens = downloadLocation.split("@")
    commit = tokens[1]
    tokens2 = tokens[0].split("+")
    git_url = tokens2[1]
    #tokens3 = git_url.split("/")
    #git_name = tokens3[-1]
    git_name = get_git_clone_dest_dir(git_url)
    if not destdir:
        #destdir = os.path.join(g_download_dir, "bomshindex-yocto-" + git_name)
        destdir = os.path.join(g_download_dir, git_name)
    if args.skip_download_if_exist and os.path.exists(destdir) and os.listdir(destdir):
        # if user wants to skip, and destdir is not empty, then return directly
        verbose("The git clone dir " + destdir + " is not empty, skip git clone " + git_url, LEVEL_2)
    else:
        destdir = bomsh_git_clone_url(git_url, destdir)
    if not destdir:
        g_download_stats[downloadLocation] = [destdir, 0]
        return []
    download_size = get_size_of_dir(destdir)
    g_download_stats[downloadLocation] = [destdir, download_size]
    if args.download_only:
        return []
    blobs = get_all_blobs_of_git_commit(commit, destdir)
    if not args.keep_intermediate_files:
        shutil.rmtree(destdir)
    return blobs


def get_all_blobs_of_dir(src_dir, len_prefix=0):
    '''
    Get all source blobs in a directory.
    :param len_prefix: the length of the directory prefix, which is not so useful, thus remove this dir prefix
    '''
    afiles = find_all_regular_files(src_dir)
    verbose("There are " + str(len(afiles)) + " files in directory " + src_dir, LEVEL_2)
    blobs = []
    for afile in afiles:
        ahash = get_git_file_hash(afile)
        size = os.path.getsize(afile)
        blobs.append( (ahash, size, afile[len_prefix:]) )
    return blobs


def get_all_blobs_of_tarball_url(downloadLocation, destdir=''):
    '''
    download a tarball to destdir and get all blobs of this tarball.
    https://download.savannah.gnu.org/releases/acl/acl-2.2.53.tar.gz
    ftp://ftp.invisible-island.net/dialog/dialog-1.3-20190808.tgz
    '''
    url = downloadLocation
    if not destdir:
        destdir = g_download_dir
    verbose("Downloading URL: " + url, LEVEL_2)
    # some URLs may fail to download or the connection timeouts. let's make the timeout as 30 seconds
    # like https://trust-artifact.cisco.com/download/trust-src-release/ciscosafec/4/1/9/ciscosafec-4.1.9.tar.gz
    wget_url(url, destdir, skip_if_exist=args.skip_download_if_exist, timeout=30)
    tarball = os.path.join(destdir, os.path.basename(url))
    if not os.path.exists(tarball) and args.try_download_to_unbundle_dir and g_unbundle_dir != g_download_dir:
        destdir = g_unbundle_dir
        wget_url(url, destdir, skip_if_exist=args.skip_download_if_exist, timeout=30)
    tarball = os.path.join(destdir, os.path.basename(url))
    if not os.path.exists(tarball):
        verbose("Warning: Failed to download " + url)
        g_download_stats[url] = [tarball, 0]
        return []
    tarball_size = os.path.getsize(tarball)
    g_download_stats[url] = [tarball, tarball_size]
    if args.download_only:
        return []
    destdir = unbundle_package(tarball)
    if not destdir:
        return []
    len_prefix = len(destdir) + 1
    blobs = get_all_blobs_of_dir(destdir, len_prefix)
    if not args.keep_intermediate_files:
        os.remove(tarball)
        shutil.rmtree(destdir)
    return blobs


def get_all_blobs_of_download_location(downloadLocation, destdir=''):
    '''
    download a tarball or git repo to destdir and get all blobs of this downloadLocation.
    '''
    if downloadLocation.startswith("git"):
        return get_all_blobs_of_git_commit_url(downloadLocation, destdir)
    return get_all_blobs_of_tarball_url(downloadLocation, destdir)


def read_recipe_json_file(recipe_file):
    """
    Read a recipe-acl.spdx.json file and return its name, version, downloadLocation info.
    """
    cmd = 'grep -E "downloadLocation|versionInfo|^  \\"name\\"" ' + recipe_file + ' | grep -v NOASSERTION || true'
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    print(output)
    lines = output.splitlines()
    name, version, downloadLocations = '', '', []
    for line in lines:
        #print(line)
        tokens = line.strip().rstrip(",").strip('"').split('": "')
        if tokens[0] == 'name':
            name = tokens[1]
            if name.startswith("recipe-"):
                name = name[7:]
        elif tokens[0] == 'versionInfo':
            version = tokens[1]
        elif tokens[0] == 'downloadLocation':
            downloadLocations.append(tokens[1])
    return (name, version, downloadLocations)


def get_all_blobs_of_recipe_files(pkg_db, recipe_files, first_n, start_i=0):
    """
    Read a list of recipe files and get its name, version, downloadLocation info.
    It also downloads source packages and gets all the source blobs.
    """
    verbose("\n==== There are " + str(len(pkg_db)) + " packages/recipes initially.")
    if first_n >= 0:
        recipe_files = recipe_files[start_i : (start_i + first_n)]
    else:
        recipe_files = recipe_files[start_i : ]
    total_num = len(recipe_files)
    verbose("We will process " + str(total_num) + " recipe files.")
    file_num = 0
    for recipe_file in recipe_files:
        file_num += 1
        if args.skip_recipe_if_processed and recipe_file in pkg_db:
            verbose("\n--- Skip reading " + str(file_num) + " of " + str(total_num) + " recipes : " + recipe_file)
            continue
        else:
            verbose("\n--- Reading " + str(file_num) + " of " + str(total_num) + " recipes : " + recipe_file)
        name, version, downloads = read_recipe_json_file(recipe_file)
        verbose("(name, version, downloadLocations) = " + str((name, version, downloads)))
        download_stats = []
        blobs = []
        for downloadLocation in downloads:
            blobs.extend(get_all_blobs_of_download_location(downloadLocation))
            if downloadLocation in g_download_stats:
                download_stats.append( (downloadLocation, g_download_stats[downloadLocation]) )
        total_blob_size = sum([blob[1] for blob in blobs])
        pkg_db[recipe_file] = { "name" : name, "version" : version, "downloadLocations" : downloads,
                "download_stats" : download_stats, "total_blob_size" : total_blob_size, "num_blobs": len(blobs), "blobs" : sorted(blobs) }
    verbose("\n==== There are " + str(len(pkg_db)) + " packages/recipes after processing " + str(total_num) + " recipes.\n")


def save_package_db(pkg_db):
    '''
    Save pkg_db to JSON file.
    '''
    jsonfile = "bomsh-index"
    if args.jsonfile:
        jsonfile = args.jsonfile
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-pkg-db.json"), pkg_db)
    # Create the blob_db from pkg_db, with metadata of (name, version, file_size, file_path)
    blob_db = {}
    for pkg in pkg_db:
        info = pkg_db[pkg]
        name, version = info["name"], info["version"]
        blobs = info["blobs"]
        for blob, size, file_path in blobs:
            if blob in blob_db:
                blob_db[blob].append( (name, version, size, file_path) )
            else:
                blob_db[blob] = [ (name, version, size, file_path), ]
    # remove duplicates if there is any
    blob_db = {blob : list(set(value)) for blob, value in blob_db.items() }
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-blob-db.json"), blob_db)
    # Create a blob_db with concise info, with (name, version) only
    for blob, info in blob_db.items():
        blob_db[blob] = [ (name, version) for name, version, size, file_path in info ]
    # remove duplicates if there is any
    blob_db = {blob : list(set(value)) for blob, value in blob_db.items() }
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-blob-db-concise.json"), blob_db)
    # Create a pkg_db with concise info, with blob_id only
    for pkg, info in pkg_db.items():
        info["blobs"] = sorted(set([blob[0] for blob in info["blobs"]]))
        info["num_blobs"] = len(info["blobs"])
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-pkg-db-concise.json"), pkg_db)
    # Create a summary database
    summary_db = {}
    total_download_size, total_blob_size, total_num_blobs = 0, 0, 0
    for pkg in pkg_db:
        info = pkg_db[pkg]
        name, version, downloads = info["name"], info["version"], info["downloadLocations"]
        # info["download_stats"] = list of (downloadLocation, g_download_stats[downloadLocation]) = (downloadLocation, [destdir, download_size])
        download_size = sum( [ stat[1][1] for stat in info["download_stats"] ] )
        blob_size, num_blobs = info["total_blob_size"], info["num_blobs"]
        summary_db[pkg] = { "name" : name, "version" : version, "downloadLocations" : downloads,
                "num_blobs" : num_blobs, "download_size" : download_size, "total_blob_size" : blob_size}
        total_download_size += download_size
        total_blob_size += blob_size
        total_num_blobs += num_blobs
    summary_db["bomsh_summary_stats"] = { "total_recipes" : len(pkg_db), "total_download_size" : total_download_size,
            "total_blob_size" : total_blob_size, "total_num_blobs" : total_num_blobs }
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-summary.json"), summary_db)
    return blob_db


############################################################
#### End of gitBOM doc copy routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool creates index DB for source blobs of OpenEmbedded/Yocto projects")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('-i', '--input_jsonfile',
                    help = "the input JSON file with blob indexing result")
    parser.add_argument('--input_spdx_tgz',
                    help = "the input spdx.tgz file with recipe files to index blobs")
    parser.add_argument('-j', '--jsonfile',
                    help = "the output JSON file for blob indexing result")
    parser.add_argument('-r', '--recipe_files',
                    help = "a list of comma-separated recipe files to index blobs")
    parser.add_argument('--recipe_dir',
                    help = "a directory which contains recipe files")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument('--wget_timeout',
                    help = "the timeout value in seconds for wget, default is 900 seconds")
    parser.add_argument('-d', '--download_dir',
                    help = "the directory to download source package files")
    parser.add_argument('--unbundle_dir',
                    help = "the directory to unbundle downloaded source package tarball files")
    parser.add_argument('--start_with_ith_package',
                    help = "start with the i-th package or recipe")
    parser.add_argument('--first_n_packages',
                    help = "only download and process first N packages")
    parser.add_argument("--download_only",
                    action = "store_true",
                    help = "download source packages only, do not unbundle or index source packages")
    parser.add_argument("--try_download_to_unbundle_dir",
                    action = "store_true",
                    help = "try to download to unbundle dir if downloading to download_dir fails")
    parser.add_argument("--keep_intermediate_files",
                    action = "store_true",
                    help = "after run completes, keep all intermediate files like unbundled packages, etc.")
    parser.add_argument("--skip_download_if_exist",
                    action = "store_true",
                    help = "skip downloanding if local file already exists")
    parser.add_argument("--skip_recipe_if_processed",
                    action = "store_true",
                    help = "skip processing a recipe if it is found to have been processed in pkg_db")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.input_spdx_tgz or args.recipe_dir or args.recipe_files):
        print ("Please specify the spdx.tgz file with the -i or --input_spdx_tgz option,"
               "or the recipe directory with the --recipe_dir option,"
               "or the list of recipe files with the --recipe_files option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_tmpdir
    if args.tmpdir:
        g_tmpdir = args.tmpdir

    global g_download_dir
    if args.download_dir:
        g_download_dir = get_or_create_dir(args.download_dir)
    else:
        g_download_dir = get_or_create_dir(g_tmpdir + "/bomshindex-yocto-downloads")

    global g_unbundle_dir
    g_unbundle_dir = g_download_dir
    if args.unbundle_dir:
        g_unbundle_dir = get_or_create_dir(args.unbundle_dir)

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    start_i = 0
    first_n = -1
    if args.first_n_packages:
        first_n = int(args.first_n_packages)
    if args.start_with_ith_package:
        start_i = int(args.start_with_ith_package)
    pkg_db = {}
    if args.input_jsonfile:
        pkg_db = load_json_db(args.input_jsonfile)
    destdir = ''
    recipe_files = []
    if args.recipe_files:
        recipe_files = args.recipe_files.split(",")
    elif args.recipe_dir:
        recipe_files = find_all_recipe_files(args.recipe_dir)
    elif args.input_spdx_tgz:
        destdir = unbundle_package(args.input_spdx_tgz)
        recipe_files = find_all_recipe_files(destdir)
    get_all_blobs_of_recipe_files(pkg_db, recipe_files, first_n, start_i)
    save_package_db(pkg_db)
    if destdir and not args.keep_intermediate_files:
        shutil.rmtree(destdir)


if __name__ == '__main__':
    main()
