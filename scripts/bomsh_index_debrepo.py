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
Bomsh script to create index DB for blobs of Debian/Ubuntu source mirror repo.

April 2023, Yongkui Han
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
g_mirror_url = ''
g_blob_filepath_db = {}
g_summary_db = {}
g_tmpdir = "/tmp"

# Some well-known Debian repo mirrors
#g_debian_mirrors = ['http://ftp.debian.org/debian', 'https://archive.debian.org/debian']
#g_ubuntu_mirrors = ['http://archive.ubuntu.com/ubuntu',]
g_debian_archive_releases = {
    'buzz' : 'debian_1.1',
    'rex' : 'debian_1.2',
    'bo' : 'debian_1.3',
    'hamm' : 'debian_2.0',
    'slink' : 'debian_2.1',
    'potato' : 'debian_2.2',
    'woody' : 'debian_3.0',
    'sarge' : 'debian_3.1',
    'etch' : 'debian_4.0',
    'lenny' : 'debian_5.0',
    'squeeze' : 'debian_6.0',
    'wheezy' : 'debian_7.0',
    'jessie' : 'debian_8.0',
    'stretch' : 'debian_9.0',
    }
g_debian_current_releases = {
    'buster' : 'debian_10.0',
    'bullseye' : 'debian_11.0',
    'bookworm' : 'debian_12.0',
    }
g_ubuntu_releases = {
    'trusty' : 'ubuntu_14.04',
    'xenial' : 'ubuntu_16.04',
    'bionic' : 'ubuntu_18.04',
    'focal' : 'ubuntu_20.04',
    'jammy' : 'ubuntu_22.04',
    'kinetic' : 'ubuntu_22.10',
    'lunar' : 'ubuntu_23.04',
    'mantic' : 'ubuntu_23.10',
    }

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


def get_mirror_repo_for_deb_release(deb_release):
    '''
    Get the mirror repo URL for a few well-known Debian/Ubuntu releases.
    '''
    if deb_release in g_ubuntu_releases:
        return 'http://archive.ubuntu.com/ubuntu'
    elif deb_release in g_debian_current_releases:
        return 'http://ftp.debian.org/debian'
    elif deb_release in g_debian_archive_releases:
        return 'http://archive.debian.org/debian'
    else:
        return ''


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


############################################################
#### End of helper routines ####
############################################################

def wget_url(url, destdir, destpath='', skip_if_exist=False):
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
        cmds = ['wget', url, '-O', destpath, '--no-check-certificate']
    else:
        cmds = ['wget', url, '-P', destdir, '--no-check-certificate']
        basename = os.path.basename(url)
        if not basename:
            basename = "index.html"
        destpath = os.path.join(destdir, basename)
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


def download_deb_sources_file(mirror_url, deb_release, destdir):
    """
    Download the Debian Sources file from the mirror_url for a specific deb_release
    :param mirror_url: the URL of the mirror repo
    :param deb_release: the specific deb_release
    :param destdir: the destination directory to save the downloaded file
    returns the local path of the downloaded Sources file
    """
    if not deb_release:
        if 'ubuntu' in mirror_url:
            deb_release = 'devel'
        else:
            deb_release = 'stable'
        print("Debian release is not specified, use " + deb_release + " as the default")
    sources_url = os.path.join(mirror_url, "dists", deb_release, "main/source/Sources.gz")
    print("\n=== The mirror repo is " + str(mirror_url) + " and the deb release is " + deb_release)
    verbose("The Debian Sources URL: " + sources_url, LEVEL_2)
    if not destdir:
        destdir = '.'
    if not os.path.exists(destdir):
        os.makedirs(destdir)
    sources_gz_file = os.path.join(destdir, 'Sources.gz')
    if os.path.exists(sources_gz_file):
        os.remove(sources_gz_file)
    wget_url(sources_url, destdir)
    if not os.path.exists(sources_gz_file):
        return ''
    sources_file = sources_gz_file[:-3]
    os.system('rm -f ' + sources_file + ' ; gunzip ' + sources_gz_file)
    if not os.path.exists(sources_file):
        return ''
    return sources_file


def get_deb_pkg_file_url(mirror_url, pkg_name, afile):
    """
    Get the Debian package file URL in the mirror repo site.
    :param mirror_url: the Debian/Ubuntu mirror site URL
    :param pkg_name: the name of the Debian package
    :param afile: the source file of this Debian package
    returns the URL of this Debian package file
    """
    if pkg_name[:3] == "lib":
        return '/'.join([mirror_url, "pool", "main", pkg_name[:4], pkg_name, afile])
    else:
        return '/'.join([mirror_url, "pool", "main", pkg_name[0], pkg_name, afile])


def process_repo_sources_file(sources_file):
    """
    Read the Debian/Ubuntu repo Sources file and parse packages.
    :param sources_file: the file path of the Debian Sources file
    returns a list of packages and the total size of all packages
    """
    content = read_text_file(sources_file, encoding="ISO-8859-1")
    packages = content.strip().split("\n\n")
    total_size = 0
    pkgs = []
    for package in packages:
        files_line_seen = False
        lines = package.splitlines()
        pkg = {}
        pkg_files, file_urls = [], []
        for line in lines:
            if line[:9] == "Package: ":
                pkg_name = line[9:]
                pkg["Package"] = line[9:]
            elif line[:9] == "Version: ":
                pkg["Version"] = line[9:]
            elif line[:11] == "Directory: ":
                pkg["Directory"] = line[11:]
            elif line == "Checksums-Sha1:":
                files_line_seen = False
            elif line == "Files:":
                files_line_seen = True
                continue
            if files_line_seen and line[0] == ' ':
                tokens = line.strip().split()
                afile = tokens[2]
                filesize = int(tokens[1])
                total_size += filesize
                pkg_files.append(tokens[2])
                '''
                if g_mirror_url:
                    if "Directory" in pkg:
                        url = os.path.join(g_mirror_url, pkg["Directory"], afile)
                    else:
                        url = get_deb_pkg_file_url(g_mirror_url, pkg_name, afile)
                    file_urls.append(url)
                '''
            elif files_line_seen and line[0] != ' ':
                files_line_seen = False
        pkg["files"] = pkg_files
        pkg["file_urls"] = [os.path.join(g_mirror_url, pkg["Directory"], afile) for afile in pkg_files if g_mirror_url]
        #pkg["file_urls2"] = file_urls
        pkgs.append(pkg)
    for pkg in pkgs:
        verbose(json.dumps(pkg, indent=4, sort_keys=True), LEVEL_4)
    print("Total " + str(len(pkgs)) + " source packages total size: " + str(total_size) + " = " + str(total_size/(1024*1024)) + " MB")
    return pkgs, total_size


def download_package_from_repo(pkg, destdir):
    """
    Download all the source files of a single package and save them in destdir.
    :param package: a single source package
    :param destdir: the destination directory to save the downloaded source files
    """
    for url in pkg["file_urls"]:
        verbose("Downloading URL: " + url, LEVEL_2)
        wget_url(url, destdir, skip_if_exist=args.skip_download_if_exist)


def download_all_packages_from_repo(pkgs, destdir):
    """
    Download a list of packages from repo, and save them into destdir
    :param pkgs: a list of packages, parsed from Debian Sources file
    :param destdir: the destination directory save the downloaded packages
    """
    if not os.path.exists(destdir):
        os.makedirs(destdir)
    for pkg in pkgs:
        download_package_from_repo(pkg, destdir)


def unbundle_package(pkgfile, destdir=''):
    '''
    unbundle RPM/DEB package to destdir.
    :param pkgfile: the RPM/DEB package file to unbundle
    :param destdir: the destination directory to save unbundled files
    '''
    if not destdir:
        destdir = os.path.join(g_tmpdir, "bomshindex-" + os.path.basename(pkgfile))
    if pkgfile[-4:] == ".rpm":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; cd " + destdir + " ; rpm2cpio " + pkgfile + " | cpio -idm || true"
    elif pkgfile[-4:] == ".deb" or pkgfile[-5:] == ".udeb":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; dpkg-deb -xv " + pkgfile + " " + destdir + " || true"
    elif pkgfile[-4:] == ".tgz" or pkgfile[-7:] in (".tar.gz", ".tar.xz") or pkgfile[-8:] == ".tar.bz2":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; tar -xf " + pkgfile + " -C " + destdir + " || true"
    else:
        print("Unsupported package format in " + pkgfile + " file, skipping it.")
        return ''
    get_shell_cmd_output(cmd)
    return destdir


def index_source_file(blob_db, src_file, pkg):
    """
    Index one single source file, and add it to blob_db
    :param blob_db: the dict of { blob_id => (pkg_name, version) } mappings
    :param src_file: the source file to index
    :param pkg: the corresponding package that this src_file belongs to
    """
    if not os.path.exists(src_file):
        verbose("non-existent src_file: " + src_file, LEVEL_2)
        return
    blob_id = get_git_file_hash(src_file)
    if blob_id in blob_db:
        pkgs = blob_db[blob_id]
        if pkg not in pkgs:
            pkgs.append(pkg)
    else:
        blob_db[blob_id] = [pkg,]
    if blob_id in g_blob_filepath_db:
        g_blob_filepath_db[blob_id].append(src_file)
    else:
        g_blob_filepath_db[blob_id] = [src_file,]


def index_source_dir(blob_db, src_dir, pkg):
    """
    Index all the files in a directory.
    """
    afiles = find_all_regular_files(src_dir)
    verbose("There are " + str(len(afiles)) + " files in directory " + src_dir, LEVEL_2)
    for afile in afiles:
        index_source_file(blob_db, afile, pkg)


def index_tarball(blob_db, tarball, pkg):
    """
    Index a tarball.
    """
    destdir = unbundle_package(tarball)
    if not destdir:
        return
    index_source_dir(blob_db, destdir, pkg)
    shutil.rmtree(destdir)


def index_one_package(blob_db, pkg, download_dir):
    """
    Index all the source files in a single package.
    :param blob_db: the dict of { blob_id => (pkg_name, version) } mappings
    :param pkg: the corresponding package that this src_file belongs to
    """
    for afile in pkg["files"]:
        if not args.download_dir:
            continue
        afile = os.path.join(download_dir, afile)
        if not os.path.exists(afile):
            verbose("File does not exist: " + afile, LEVEL_3)
            continue
        verbose("Indexing " + afile + " for package " + pkg["Package"], LEVEL_2)
        if afile[-4:] in (".asc", ".dsc"):
            index_source_file(blob_db, afile, pkg)
        elif ".tar." in afile:
            index_tarball(blob_db, afile, pkg)
        else:
            index_source_file(blob_db, afile, pkg)


def index_all_packages(blob_db, packages, download_dir):
    """
    Index all the source files in a list of packages.
    :param blob_db: the dict of { blob_id => (pkg_name, version) } mappings
    :param packages: a list of source packages
    returns the dict of { blob_id => (pkg_name, version) } mappings
    """
    for pkg in packages:
        index_one_package(blob_db, pkg, download_dir)
    #print("There are now totally " + str(len(blob_db)) + " blobs in " + str(len(packages)) + " source packages")


def save_blob_db(blob_db):
    """
    Save blob_db as JSON files.
    :param blob_db: the dict of { blob_id => (pkg_name, version) } mappings
    """
    # only keep Package/Version fields for pkg
    blob_db2 = {}
    for blob_id in blob_db:
        pkgs = []
        old_pkgs = blob_db[blob_id]
        for i in range(len(old_pkgs)):
            old_pkg = old_pkgs[i]
            pkg = {}
            for field in ("Package", "Version"):
                pkg[field] = old_pkg[field]
            pkgs.append(pkg)
        blob_db2[blob_id] = pkgs
    print("\n=== Saving the blob_db: totally " + str(len(blob_db)) + " blobs in this blob_db")
    # Also creates the {pkg => list of blobs} DB with "pkg_name pkg_version" as key
    pkg_db = {}
    for blob_id in blob_db2:
        pkgs = blob_db2[blob_id]
        for pkg in pkgs:
            pkg_key = pkg["Package"] + " " + pkg["Version"]
            if pkg_key in pkg_db:
                pkg_db[pkg_key].append(blob_id)
            else:
                pkg_db[pkg_key] = [blob_id,]
    jsonfile = "bomsh-index"
    if args.jsonfile:
        jsonfile = args.jsonfile
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-pkg-db.json"), pkg_db)
    save_json_db(os.path.join(g_tmpdir, jsonfile + "-db.json"), blob_db2)
    if args.verbose > 1:
        save_json_db(os.path.join(g_tmpdir, jsonfile + "-db-verbose.json"), blob_db)
        save_json_db(os.path.join(g_tmpdir, jsonfile + "-filepath-db.json"), g_blob_filepath_db)
    if g_summary_db:
        save_json_db(os.path.join(g_tmpdir, jsonfile + "-summary.json"), g_summary_db)


def index_deb_release(blob_db, deb_release, download_dir, mirror_url='', sources_file='', first_n=-1, start_i=0):
    '''
    Index one specific deb_release.
    :param blob_db: the dict of { blob_id => (pkg_name, version) } mappings
    :param deb_release: a specific deb_release, like bullseye/focal
    :param download_dir: the directory to save the downloaded source files
    :param mirror_url: the mirror repo URL to download source files from
    :param sources_file: the Debian/Ubuntu repo Sources file, which contains metadata of packages
    :param first_n: only the first N packages will be processed
    '''
    global g_mirror_url
    if not deb_release:
        deb_release = "UNKNOWN_REL"
    if not mirror_url:
        mirror_url = get_mirror_repo_for_deb_release(deb_release)
    g_mirror_url = mirror_url
    if not sources_file and mirror_url:
        sources_file = download_deb_sources_file(mirror_url, deb_release, download_dir)
    if not mirror_url:
        print("Warning: No mirror URL for " + deb_release + ". You can specify the mirror URL with --mirror_url option!")
    if not sources_file:
        print("Error: Could not find Sources file in your mirror repo " + mirror_url + " for the deb_release " + deb_release)
        print("Please specify a different mirror_url and deb_release.")
        return
    pkgs, total_size = process_repo_sources_file(sources_file)
    g_summary_db[deb_release] = { "num_pkgs" : len(pkgs), "total_size" : total_size }
    if first_n >= 0:
        pkgs = pkgs[start_i : (start_i + first_n)]
        print("\nWe will only process the first " + str(len(pkgs)) + " packages start_i= " + str(start_i) + " for deb_release " + deb_release)
        verbose("the first " + str(first_n) + " packages: " + str(pkgs), LEVEL_2)
    else:
        pkgs = pkgs[start_i : ]
        print("\nWe will process all the " + str(len(pkgs)) + " packages start_i= " + str(start_i) + " for deb_release " + deb_release)
    if download_dir and mirror_url:
        download_all_packages_from_repo(pkgs, download_dir)
    index_all_packages(blob_db, pkgs, download_dir)
    print("There are now totally " + str(len(blob_db)) + " blobs with " + str(len(pkgs)) + " source packages of " + deb_release)


############################################################
#### End of gitBOM doc copy routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool downloads source packages from Debian/Ubuntu repo and indexes all source files")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('-i', '--input_jsonfile',
                    help = "the input JSON file with blob indexing result")
    parser.add_argument('-j', '--jsonfile',
                    help = "the output JSON file for blob indexing result")
    parser.add_argument('-m', "--mirror_url",
                    help = "the URL of the Debian/Ubuntu source mirror repo to download source files")
    parser.add_argument('-r', '--deb_release',
                    help = "a list of comma-separated Debian/Ubuntu releases, like bullseye,jammy")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument('-d', '--download_dir',
                    help = "the directory to download source package files")
    parser.add_argument('--start_with_ith_package',
                    help = "start with the i-th package or recipe")
    parser.add_argument('--first_n_packages',
                    help = "only download and index first N packages")
    parser.add_argument('--sources_file',
                    help = "the Debian/Ubuntu repo Sources file")
    parser.add_argument("--skip_download_if_exist",
                    action = "store_true",
                    help = "skip downloanding if local file already exists")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.download_dir):
        print ("Please specify the download directory with the -d or --download_dir option!")
        print ("")
        parser.print_help()
        sys.exit()

    global g_tmpdir
    if args.tmpdir:
        g_tmpdir = args.tmpdir

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
    blob_db = {}
    if args.input_jsonfile:
        blob_db = load_json_db(args.input_jsonfile)
    sources_file = args.sources_file
    if sources_file:
        index_deb_release(blob_db, args.deb_release, args.download_dir, args.mirror_url, sources_file, first_n, start_i)
        save_blob_db(blob_db)
        return
    deb_releases = args.deb_release.split(",")
    for deb_release in deb_releases:
        index_deb_release(blob_db, deb_release, args.download_dir, args.mirror_url, sources_file, first_n, start_i)
    save_blob_db(blob_db)


if __name__ == '__main__':
    main()
