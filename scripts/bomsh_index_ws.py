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
Bomsh script to create package blob index DB for build workspace.

September 2023, Yongkui Han
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
g_chroot_dir = ''
g_tmpdir = "/tmp"
g_jsonfile = "/tmp/bomsh-index"
g_package_type = "rpm"

# tarball/gitdir package blobs DB for prov_pkg of blobs in raw_logfile
g_targit_pkg_db = {}
g_targit_blob_pkg_db = {}

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


def find_all_regular_files(builddir, extra_opt=''):
    """
    Find all regular files in the build dir, excluding symbolic link files.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :returns a list that contains all the regular file names.
    """
    #verbose("entering find_all_regular_files: the build dir is " + builddir, LEVEL_4)
    builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' ' + extra_opt + ' -type f -print || true '
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True, errors='backslashreplace')
    files = output.splitlines()
    return files


def get_shell_cmd_output(cmd):
    """
    Returns the output of the shell command "cmd".
    :param cmd: the shell command to execute
    """
    #print (cmd)
    if sys.version_info[0] < 3 or (sys.version_info[0] == 3 and sys.version_info[1] < 6):
        output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    else:
        output = subprocess.check_output(cmd, shell=True, errors="backslashreplace", universal_newlines=True)
    return output


def get_file_hash(afile, hash_alg="sha1"):
    '''
    Get the git object hash value of a file.
    :param afile: the file to calculate the git hash or digest.
    :param hash_alg: the hashing algorithm, either SHA1 or SHA256
    '''
    if hash_alg == "sha256":
        cmd = 'printf "blob $(wc -c < ' + afile + ')\\0" | cat - ' + afile + ' 2>/dev/null | sha256sum | head --bytes=-4 || true'
    else:
        cmd = 'git hash-object ' + cmd_quote(afile) + ' 2>/dev/null || true'
    #print(cmd)
    output = get_shell_cmd_output(cmd).strip()
    #verbose("output of get_file_hash:\n" + output, LEVEL_3)
    return output


def unbundle_package(pkgfile, destdir=''):
    '''
    unbundle RPM/DEB package to destdir.
    :param pkgfile: the RPM/DEB package file to unbundle
    :param destdir: the destination directory to save unbundled files, must be tmp dir to safely delete
    '''
    if not destdir:
        extract_dir = os.path.join(g_tmpdir, "bomsh_extract_dir")
        if not os.path.exists(extract_dir):
            os.makedirs(extract_dir)
        destdir = os.path.join(extract_dir, os.path.basename(pkgfile) + ".extractdir")
        if args.skip_unbundle_if_exist and os.path.exists(destdir):
            return destdir
    if pkgfile[-4:] == ".rpm":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; cd " + destdir + " ; rpm2cpio " + pkgfile + " | cpio -idm 2>/dev/null || true"
    elif pkgfile[-4:] == ".deb" or pkgfile[-5:] in (".udeb", ".ddeb"):
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; dpkg-deb -xv " + pkgfile + " " + destdir + " || true"
    elif pkgfile[-4:] == ".tgz" or pkgfile[-7:] in (".tar.gz", ".tar.xz") or pkgfile[-8:] == ".tar.bz2":
        cmd = "rm -rf " + destdir + " ; mkdir -p " + destdir + " ; tar -xf " + pkgfile + " -C " + destdir + " || true"
    else:
        verbose("Warning: Unsupported package format in " + pkgfile + " file, skipping it.")
        return ''
    get_shell_cmd_output(cmd)
    return destdir


############################################################
#### End of helper routines ####
############################################################

def read_all_infiles_from_raw_logfile(raw_logfile, read_dynlib=True):
    """
    Read all input files from the bomsh_hook_raw_logfile.
    :param raw_logfile: the bomsh_hook_raw_logfile generated during software build
    returns a sequence of (checksum, file_path)
    """
    ret = set()
    with open(raw_logfile, 'r') as f:
        for line in f:
            if line[:8] in ("infile: ", "dynlib: ") or line.startswith("outfile: "):
                tokens = line.split()
                if len(tokens) > 3:
                    checksum = tokens[1]
                    path = tokens[3]
                else:
                    checksum = ''
                    path = tokens[2]
                ret.add( (checksum, path) )
    verbose("Read from raw_logfile, the number of unique file paths: " + str(len(ret)))
    return ret


def convert_single_raw_log_line(line, blob_db):
    '''
    Convert a single line read from raw_logfile, adding prov_pkg info.
    :param line: a single line
    :param blob_db: a dict of { blob_id => prov_pkg }
    returns the new line, adding possible prov_pkg info at the end.
    '''
    if line[:8] in ("infile: ", "dynlib: "):
        tokens = line.split()
        if len(tokens) > 3:
            checksum, path = tokens[1], tokens[3]
        else:
            checksum, path = '', tokens[2]
        if not (checksum and checksum in blob_db):
            return line
        src_pkg = blob_db[checksum]
        if src_pkg:
            tokens.extend(["prov_pkg:", src_pkg])
            return " ".join(tokens) + "\n"
    return line


def convert_raw_logfile(raw_logfile, output_file, blob_db):
    '''
    Process the bomsh_hook_raw_logfile, adding source package info for input files and dynlib files.
    :param raw_logfile: the bomsh_hook_raw_logfile generated during software build
    :param output_file: the new file to write with prov_pkg info
    :param blob_db: a dict of { blob_id => prov_pkg }
    returns None
    '''
    of = open(output_file, 'w')
    with open(raw_logfile, 'r') as f:
        for line in f:
            new_line = convert_single_raw_log_line(line, blob_db)
            of.write(new_line)
    of.close()
    verbose("The provider-pkg-updated new bomsh hook raw_logfile: " + output_file)


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


# a dict to cache the provider packages of files
g_prov_pkg_cache = {}

def get_prov_pkg(path, use_cache=True):
    """
    Get the installed rpm package which provides this file path.
    """
    if use_cache and path in g_prov_pkg_cache:
        return g_prov_pkg_cache[path]
    chroot_path = get_chroot_path(path)
    if not os.path.exists(chroot_path):
        verbose("Warning: this path does not exist: " + chroot_path, LEVEL_2)
        return ''
    if g_package_type == "deb":
        cmd = get_chroot_cmd('dpkg -S ' + path + ' 2>/dev/null')
    else:
        cmd = get_chroot_cmd('rpm -q --whatprovides ' + path + ' 2>/dev/null')
    verbose(cmd, LEVEL_2)
    try:
        output = get_shell_cmd_output(cmd)
        ret_pkg = output.splitlines()[0]  # if multiple packages, pick the first one only
    except subprocess.CalledProcessError:
        ret_pkg = ''
    if ret_pkg.endswith(path):  # for dpkg -S output, which contains path at the end, so strip it
        ret_pkg = ret_pkg[: - (len(path) + 2) ]
    if use_cache:
        g_prov_pkg_cache[path] = ret_pkg
    return ret_pkg


def get_provider_packages_for_files(infiles):
    '''
    Get the provider package database for a list of input files.
    :param infiles: a list of input files from bomsh_hook_raw_logfile
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    pkg_db = {}
    for infile in infiles:
        blob_id, path = infile
        # first check if this blob is in the src tarball/gitdir pkg DB
        if blob_id in g_targit_blob_pkg_db:
            package = g_targit_blob_pkg_db[blob_id]
        else:
            package = get_prov_pkg(path)
        # add this blob to the blobs of appropriate package
        if package in pkg_db:
            pkg_entry = pkg_db[package]
            if "blobs" in pkg_entry:
                pkg_entry["blobs"].append(infile)
            else:
                pkg_entry["blobs"] = [infile, ]
        else:
            pkg_db[package] = {"blobs" : [infile, ]}
    for package in pkg_db:
        # add pkg_info for the found packages of these infiles
        if package in g_targit_pkg_db and "pkg_info" in g_targit_pkg_db[package]:
            pkg_db[package]["pkg_info"] = g_targit_pkg_db[package]["pkg_info"]
            continue
        pkg_info = get_installed_pkg_info(package)
        pkg_db[package]["pkg_info"] = pkg_info
    return pkg_db


def get_all_installed_deb_packages():
    '''
    Get the list of all installed DEB packages in software build.
    '''
    cmd = get_chroot_cmd('dpkg -l || true')
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    lines = output.splitlines()
    return [ line.split()[1] for line in lines if line[:3] == 'ii ' ]


def get_all_installed_rpm_packages():
    '''
    Get the list of all installed RPM packages in software build.
    '''
    cmd = get_chroot_cmd('rpm -qa || true')
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_all_installed_packages():
    '''
    Get the list of all installed RPM/DEB packages in software build.
    '''
    if g_package_type == "deb":
        return get_all_installed_deb_packages()
    return get_all_installed_rpm_packages()


def get_deb_pkg_info(deb_file):
    '''
    Get the info of a DEB package file.
    :param deb_file: the deb file
    returns a list of lines of the package info.
    '''
    cmd = 'dpkg-deb -f ' + deb_file + ' || true'
    #cmd = 'dpkg-deb -I ' + deb_file + ' || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_rpm_pkg_info(rpm_file):
    '''
    Get the info of a RPM package file.
    :param rpm_file: the rpm file
    returns a list of lines of the package info.
    '''
    cmd = 'rpm -qpi ' + rpm_file + ' || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_installed_deb_pkg_info(package):
    '''
    Get the info of an installed DEB package.
    :param package: the installed DEB package name
    returns a list of lines of the package info.
    '''
    cmd = get_chroot_cmd('dpkg -s ' + package + ' || true')
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_installed_rpm_pkg_info(package):
    '''
    Get the info of an installed RPM package.
    :param package: the installed RPM package name
    returns a list of lines of the package info.
    '''
    cmd = get_chroot_cmd('rpm -qi ' + package + ' || true')
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_installed_pkg_info(package):
    '''
    Get the info of an installed RPM/DEB package.
    :param package: the installed package name
    returns a list of lines of the package info.
    '''
    if not package:
        return []
    if g_package_type == "deb":
        return get_installed_deb_pkg_info(package)
    return get_installed_rpm_pkg_info(package)


def get_list_of_files_of_installed_deb_package(package):
    '''
    Get a list of installed files for a DEB package.
    :param package: the installed RPM package name
    returns a list of (checksum, file_path)
    '''
    cmd = get_chroot_cmd('dpkg -L ' + package + ' || true')
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_list_of_files_of_installed_rpm_package(package):
    '''
    Get a list of installed files for a RPM package.
    :param package: the installed RPM package name
    returns a list of (checksum, file_path)
    '''
    cmd = get_chroot_cmd('rpm -ql ' + package + ' || true')
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    return output.splitlines()


def get_list_of_files_of_installed_package(package):
    '''
    Get a list of installed files for a RPM/DEB package.
    :param package: the installed RPM/DEB package name
    returns a list of (checksum, file_path)
    '''
    if g_package_type == "deb":
        return get_list_of_files_of_installed_deb_package(package)
    return get_list_of_files_of_installed_rpm_package(package)


def get_packages_index_db(packages):
    '''
    Get the package database for a list of installed RPM packages.
    :param packages: a list of installed RPM packages.
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    pkg_db = {}
    for package in packages:
        pkg_info = get_installed_pkg_info(package)
        afiles = get_list_of_files_of_installed_package(package)
        blobs = []
        for afile in afiles:
            bfile = get_chroot_path(afile)
            if os.path.isfile(bfile) and not os.path.islink(bfile):
                blobs.append( (get_file_hash(bfile), afile) )
        pkg_db[package] = {"blobs": blobs, "pkg_info": pkg_info}
        verbose("package " + package + " contains " + str(len(blobs)) + " blobs", LEVEL_3)
    return pkg_db


def get_rpm_pkg_blobs(rpm_file):
    '''
    Unbundle a RPM/DEB file and get a list of files inside this RPM/DEB package file.
    unbundle_package is called twice to unbundle the tarballs inside the RPM/DEB package file.
    :param rpm_file: the RPM file or the DEB file
    returns a list of (checksum, file_path)
    '''
    destdir = unbundle_package(rpm_file)
    if not destdir:
        return []
    len_prefix = len(destdir) + 1
    afiles = find_all_regular_files(destdir)
    verbose("There are " + str(len(afiles)) + " files in directory " + destdir, LEVEL_2)
    tarballs = [ afile for afile in afiles if ".tar." in os.path.basename(afile) ]
    if tarballs:
        for tarball in tarballs:
            destdir2 = os.path.join(destdir, os.path.basename(tarball) + ".extractdir")
            unbundle_package(tarball, destdir2)
        afiles = find_all_regular_files(destdir)
        verbose("Round 2, There are " + str(len(afiles)) + " files in directory " + destdir, LEVEL_2)
    blobs = [ (get_file_hash(afile), afile[len_prefix:]) for afile in afiles ]
    shutil.rmtree(destdir)
    return blobs


def get_rpm_pkgs_index_db(rpm_files):
    '''
    Get the package database for a list of user provided RPM packages.
    :param rpm_files: a list of RPM package files
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    pkg_db = {}
    for rpm_file in rpm_files:
        pkg_info = get_rpm_pkg_info(rpm_file)
        blobs = get_rpm_pkg_blobs(rpm_file)
        pkg_db[os.path.basename(rpm_file)] = {"blobs": blobs, "pkg_info": pkg_info}
    return pkg_db


def get_deb_pkgs_index_db(deb_files):
    '''
    Get the package database for a list of user provided DEB packages.
    :param deb_files: a list of DEB package files
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    dsc_file = get_deb_source_control_file()
    verbose("DEB source control file: " + str(dsc_file))
    dsc_pkg_info = []
    if dsc_file:
        dsc_pkg_info = read_pkg_info_from_dsc_file(dsc_file)
    # The *.tar.xz source tarballs are also needed to build the index DB
    tarballs = get_deb_source_tarball_files()
    verbose("DEB src tarballs: " + str(tarballs))
    pkg_db = {}
    for deb_file in deb_files:
        pkg_info = get_deb_pkg_info(deb_file)
        blobs = get_rpm_pkg_blobs(deb_file)
        pkg_db[os.path.basename(deb_file)] = {"blobs": blobs, "pkg_info": pkg_info}
    for tarball in tarballs:
        blobs = get_rpm_pkg_blobs(tarball)
        pkg_db[os.path.basename(tarball)] = {"blobs": blobs, "pkg_info": dsc_pkg_info}
    return pkg_db


def get_pkgs_index_db(afiles):
    '''
    Get the package database for a list of user provided RPM/DEB packages.
    :param afiles: a list of RPM/DEB package files or source tarballs
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    if g_package_type == "deb":
        return get_deb_pkgs_index_db(afiles)
    return get_rpm_pkgs_index_db(afiles)


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
                    if (old_package.endswith(".src.rpm") and package.endswith(".rpm")) or (".tar." in old_package and package.endswith(".deb")):
                        # src RPM or tarball has higher priority than arch-specific RPM/DEB, so do not overwrite it
                        overwrite = False
                else:
                    verbose("InfoWarning: new path " + str( (package, path) ) + " differs from existing path: " + str( blob_db[checksum] ), LEVEL_2)
            if overwrite:
                blob_db[checksum] = (package, path)  # only keep a single package, newer package overwrites older package
    return blob_db


def get_workspace_index_db(rpm_files, raw_logfile=''):
    '''
    Generate the pkg_db and blob_db for software build workspace.
    :param rpm_files: a list of user provided RPM files
    :param raw_logfile: the bomsh_hook_raw_logfile generated during software build
    '''
    pkg_db = {}
    # First get the pkg_db from raw_logfile or installed packages
    if raw_logfile:
        infiles = read_all_infiles_from_raw_logfile(raw_logfile)
        pkg_db = get_provider_packages_for_files(infiles)
    elif args.index_installed_pkgs:
        packages = get_all_installed_packages()
        if args.first_n_packages:
            first_n = int(args.first_n_packages)
            start_i = 0
            if args.start_with_ith_package:
                start_i = int(args.start_with_ith_package)
            packages = packages[ start_i : start_i + first_n ]
        pkg_db = get_packages_index_db(packages)
    # Then merge the pkg DB generated from source RPM files or DEB tarballs
    pkg_db2 = get_pkgs_index_db(rpm_files)
    pkg_db.update(pkg_db2)
    # Convert pkg_db to blob_db for use by bomsh_create_bom.py script
    blob_db = convert_pkg_db_to_blob_db(pkg_db)
    save_json_db(g_jsonfile + "-pkg-db.json", pkg_db)
    save_json_db(g_jsonfile + "-blob-db.json", blob_db)
    blob_pkg_db = { blob : v[0] for blob,v in blob_db.items() }
    save_json_db(g_jsonfile + "-blob-pkg-db.json", blob_pkg_db)
    if raw_logfile:
        convert_raw_logfile(raw_logfile, g_jsonfile + "-raw_logfile", blob_pkg_db)
    print("\nDone. Created " + g_jsonfile + "* package blob DBs.")


def read_pkg_info_from_dsc_file(dsc_file):
    '''
    Read package info from the debian source control .dsc file.
    returns a list of lines containing the package info.
    '''
    ret = []
    with open(dsc_file, 'r') as f:
        found = False
        for line in f:
            line = line.rstrip()
            if line.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
                found = True
                continue
            elif line.startswith("-----BEGIN PGP SIGNATURE-----"):
                return ret[2:-1]  # the first two lines and the last line are not useful
            if found:
                ret.append(line)
    return ret


def get_deb_source_control_filename_from_buildinfo_file(buildinfo_file):
    '''
    Get the source control filename from provided .buildinfo file.
    '''
    with open(buildinfo_file, 'r') as f:
        for line in f:
            if line.strip().endswith(".dsc"):
                tokens = line.split()
                return tokens[-1]
    return ''


def get_deb_source_control_file():
    '''
    Get the debian source control file for debian package build.
    The dsc file is supposed to have been copied to bomsh_logfiles directory or g_chroot_dir.
    '''
    dsc_filename = ''
    if args.buildinfo_file:
        dsc_filename = get_deb_source_control_file_from_buildinfo_file(args.buildinfo_file)
        verbose("from buildinfo_file " + args.buildinfo_file + " we get dsc filename: " + dsc_filename)
    if dsc_filename:
        return get_dsc_source_control_file_with_filename(dsc_filename)
    cmd = 'ls bomsh_logfiles/*.dsc 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if output:
        return output.splitlines()[0]
    if not (g_chroot_dir and os.path.exists(g_chroot_dir)):
        return ''
    cmd = 'ls ' + g_chroot_dir + '/*.dsc 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if output:
        return output.splitlines()[0]
    return ''


def get_dsc_source_control_file_with_filename(dsc_filename):
    '''
    Get the debian source control file with a known filename.
    The dsc file is supposed to have been copied to bomsh_logfiles directory or g_chroot_dir.
    '''
    dsc_file = os.path.join("bomsh_logfiles", dsc_filename)
    if os.path.exists(dsc_file):
        return dsc_file
    dsc_file = os.path.join(g_chroot_dir, dsc_filename)
    if os.path.exists(dsc_file):
        return dsc_file
    return ''


def get_deb_source_tarball_files():
    '''
    Get the list of source tarball files for debian package build.
    They are supposed to have been copied to bomsh_logfiles directory or g_chroot_dir.
    returns a list of tarball files.
    '''
    cmd = 'ls bomsh_logfiles/*.tar.* 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if output:
        return output.splitlines()
    if not (g_chroot_dir and os.path.exists(g_chroot_dir)):
        return []
    cmd = 'ls ' + g_chroot_dir + '/*.tar.* 2>/dev/null || true'
    output = get_shell_cmd_output(cmd)
    if output:
        return output.splitlines()
    return []

############################################################
#### End of package database processing routines ####
############################################################

def get_src_tarball_files_in_dir(adir):
    '''
    Get the list of source tarball files in a directory.
    returns a list of tarball files.
    '''
    cmd = 'find ' + adir + ' -name "*.tar.gz" -o -name "*.tar.xz" -o -name "*.tar.bz2" -o -name "*.tgz" -type f || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    if output:
        return output.splitlines()
    if not (g_chroot_dir and os.path.exists(g_chroot_dir)):
        return []
    cmd = 'find ' + g_chroot_dir + '/' + adir + ' -name "*.tar.gz" -o -name "*.tar.xz" -o -name "*.tar.bz2" -o -name "*.tgz" -type f || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    if output:
        return output.splitlines()
    return []


def get_all_src_tarball_files():
    '''
    Get a list of source tarball files for prov_pkg database.
    '''
    if not args.src_tarball_dir:
        return []
    adirs = args.src_tarball_dir.split(",")
    alist = []
    for adir in adirs:
        alist.extend(get_src_tarball_files_in_dir(adir))
    return alist


def find_version_in_dir(destdir):
    '''
    Try to find VERSION info from the src tarball unbundled dir.
    '''
    cmd = 'find ' + destdir + ' -name "VERSION" -type f | xargs cat || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    if output:
        return output.strip().split()[0]
    return ''


def get_tarball_pkg_info(tarball, destdir=''):
    '''
    Get name,version pkg_info for a src tarball file.
    We first split file name into tokens by ".", and then by "-", and then by "_",
    And then find the token with digits only, which is the start of version string.
    '''
    dirname, filename = os.path.split(tarball)
    tokens = filename.split(".")
    # strip the .tgz or .tar.gz/.tar.xz/.tar.bz2 suffix first
    if tokens[-1] == "tgz":
        # the middle tokens except the first and last token
        midtokens = tokens[1:-1]
    else:
        midtokens = tokens[1:-2]
    tokens2 = tokens[0].split("-")
    if midtokens: # like kexec-tools-2.0.18.tar.xz, gdb-linaro-7.6-2013.05.tar.bz2 or glibc-2.23-eabd6f4.tar.bz2
        if len(tokens2) > 1 and (tokens2[-1].isdigit() or
                (tokens2[-1][0] == 'v' and tokens2[-1][1:].isdigit())): # ebtables-v2.0.10-4.tar.gz
            # like kexec-tools-2.0.18.tar.xz, gdb-linaro-7.6-2013.05.tar.bz2 or glibc-2.23-eabd6f4.tar.bz2
            name = "-".join(tokens2[:-1])
            version = ".".join( [tokens2[-1],] + midtokens )
        elif len(midtokens) > 1: # backports.ssl_match_hostname-3.4.0.2.tar.gz
            tokens3 = midtokens[0].split("-")
            if len(tokens3) > 1 and tokens3[-1].isdigit():
                name = tokens[0] + '.' + "-".join(tokens3[:-1])
                version = ".".join( [tokens3[-1],] + midtokens[1:] )
            else:
                name = tokens[0] + '.' + midtokens[0]
                version = ".".join( midtokens[1:] )
        else: # wireless_tools.29.tar.gz
            name = tokens[0]
            version = ".".join( midtokens )
            if name.startswith("squashfs"): # special case for squashfs4.2.tar.gz
                version = name[len("squashfs"):] + "." + version
                name = "squashfs"
    else: # like boost_1_60_0.tar.gz, or sscep.tgz
        # or yaffs2_android-2008-12-18.tar.bz2, systemd-219-42-9.tar.xz, ca-certificates_20150426.tar.xz
        name = tokens2[0]
        version = "-".join( tokens2[1:] )
        # find the first digit from left
        if not version or (version and not tokens2[1].isdigit()): # for boost_1_60_0.tar.gz and ca-certificates_20150426.tar.xz
            tokens3 = tokens[0].split("_")
            if len(tokens3) > 1:
                name = tokens3[0]
                version = "_".join( tokens3[1:] )
    if not version and destdir: # for sscep.tgz, which has VERSION file in unbundled dir
            version = find_version_in_dir(destdir)
    # if this tarball is a committed object in git repo, then get its last commit as git_version
    # We will also set version if version is still empty
    git_version = get_last_git_commit_for_afile(tarball)
    if not version:
        version = git_version
        if args.prefer_git_tag:
            git_tag = get_associated_git_tag_for_commit(version, dirname)
            if git_tag:
                version = git_tag
    if not version:
        version = "UNKNOWN_VERSION"
    if not name:
        name = "UNKNOWN_PKG"
    remote_url = get_git_remote_url(dirname)
    #pkg_info = ["Name: " + name, "Version: " + version, "Architecture: all",
    #        "Source type: tarball", "Remote URL: " + remote_url, "Path: " + tarball]
    pkg_info_dict = {"Name" : name, "Version" : version, "Git-Version": git_version, "Architecture" : "all",
            "Package type" : "tarball", "Remote URL" : remote_url, "Path" : tarball}
    return pkg_info_dict


# the reference pkg_db to help populate pkg_db, in order to save unbundling/hash-computation time for tarballs.
# this ref pkg_db can only be keyed with tarball name, since the pkg name and version may not exist in its filename.
g_ref_pkg_db = {}

def get_packages_index_db_for_tarballs(tarballs):
    '''
    Get the package database for a list of src tarball files.
    :param tarballs: a list of src tarball files
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    pkg_db = {}
    ref_pkg_db = {}
    for tarball in tarballs:
        # tarball_ref_key is just the tarball file name
        tarball_ref_key = os.path.basename(tarball)
        tarball_sha1_gitoid = get_file_hash(tarball)
        if tarball_ref_key in g_ref_pkg_db:
            tarball_entry = g_ref_pkg_db[tarball_ref_key]
            if "sha1_gitoid" in tarball_entry:
                if tarball_entry["sha1_gitoid"] == tarball_sha1_gitoid:
                    verbose("Found a matched existing tarball pkg entry, reuse it for " + tarball_ref_key, LEVEL_1)
                    pkg_info = tarball_entry["pkg_info"]
                    # tarball_key contains Name/Version for easier use by other Bomsh tools
                    tarball_key = tarball_ref_key + " " + pkg_info["Name"] + " " + pkg_info["Version"]
                    pkg_db[tarball_key] = tarball_entry
                    ref_pkg_db[tarball_ref_key] = tarball_entry
                    continue
        # first unbundle the tarball
        verbose("Unbundle " + tarball + " and create pkg_db entry for its blobs", LEVEL_1)
        destdir = unbundle_package(tarball)
        len_prefix = len(destdir) + 1
        pkg_info = get_tarball_pkg_info(tarball, destdir)
        afiles = find_all_regular_files(destdir, "-size +0")
        blobs = []
        for afile in afiles:
            bfile = get_chroot_path(afile)
            if os.path.isfile(bfile) and not os.path.islink(bfile):
                blobs.append( (get_file_hash(bfile), afile[len_prefix:]) )
        # create the tarball entry in pkg_db
        # tarball_key is format "filename pkg_name pkg_version" for easier use by later bomsh scripts
        tarball_key = tarball_ref_key + " " + pkg_info["Name"] + " " + pkg_info["Version"]
        pkg_db[tarball_key] = {"blobs": blobs, "num_blobs": len(blobs), "pkg_info": pkg_info, "sha1_gitoid": tarball_sha1_gitoid}
        # ref_pkg_db is keyed by tarball filename only
        ref_pkg_db[tarball_ref_key] = pkg_db[tarball_key]
        verbose("tarball " + tarball + " contains " + str(len(blobs)) + " blobs", LEVEL_1)
        verbose("tarball " + tarball + " pkg_info " + str(pkg_info), LEVEL_1)
        if not args.keep_intermediate_files:
            shutil.rmtree(destdir)
    save_json_db(g_jsonfile + "-tarball-pkg-db.json", pkg_db)
    # Save the ref-pkg-db too, so next time we can save time
    save_json_db(g_jsonfile + "-tarball-ref-pkg-db.json", ref_pkg_db)
    return pkg_db


def get_tarball_packages_index_db():
    '''
    Get the package database for a user provided src tarball files.
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    tarballs = get_all_src_tarball_files()
    verbose("List of " + str(len(tarballs)) + " tarballs: " + str(tarballs), LEVEL_4)
    if args.first_n_packages:
            first_n = int(args.first_n_packages)
            start_i = 0
            if args.start_with_ith_package:
                start_i = int(args.start_with_ith_package)
            tarballs = tarballs[ start_i : start_i + first_n ]
    return get_packages_index_db_for_tarballs(tarballs)


def is_git_dir(git_dir):
    """
    Check if a directory is a git directory.
    "git rev-parse" has better performance than "git status".
    """
    verbose("Checking if this dir is git repo: " + git_dir, LEVEL_4)
    rc = subprocess.call(['git', "rev-parse"], cwd=git_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return rc == 0


def get_src_gitdirs_in_dir(adir):
    '''
    Get the list of source git_dir in a directory.
    returns a list of git_dir.
    '''
    cmd = 'find ' + adir + ' -name "\\.git" || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    if output:
        return [adir for adir in [os.path.dirname(afile) for afile in output.splitlines()] if is_git_dir(adir)]
    if not (g_chroot_dir and os.path.exists(g_chroot_dir)):
        return []
    cmd = 'find ' + g_chroot_dir + '/' + adir + ' -name "\\.git" || true'
    verbose(cmd, LEVEL_3)
    output = get_shell_cmd_output(cmd)
    if output:
        return [adir for adir in [os.path.dirname(afile) for afile in output.splitlines()] if is_git_dir(adir)]
    return []


def get_all_src_gitdirs():
    '''
    Get a list of source git directories for prov_pkg database.
    '''
    if not args.git_top_dir:
        return []
    adirs = args.git_top_dir.split(",")
    alist = []
    for adir in adirs:
        alist.extend(get_src_gitdirs_in_dir(adir))
    return alist


def get_git_remote_url(git_dir):
    """
    Get the remote URL of a git directory.
    """
    cmd = "cd " + git_dir + " ; git remote get-url origin || true"
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_associated_git_commit_for_tag(git_tag, git_dir=''):
    """
    Find the associated git commit ID for a git tag.
    This tells us which commit a tag points to in git.
    """
    if git_dir:
        cmd = "cd " + git_dir + " ; git rev-list -n 1 " + git_tag + " || true"
    else:
        cmd = "git rev-list -n 1 " + git_tag + " || true"
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_associated_git_tag_for_commit(git_commit, git_dir=''):
    """
    Find the associated git tag for a git commit ID.
    If there is not associated git tag, then return ''
    """
    if git_dir:
        cmd = "cd " + git_dir + " ; git describe --exact-match --tags " + git_commit + " 2>/dev/null || true"
    else:
        cmd = "git describe --exact-match --tags " + git_commit + " 2>/dev/null || true"
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_last_git_commit_for_afile(afile):
    """
    Get the last commit id for a file in git repo.
    """
    dirname, basename = os.path.split(afile)
    cmd = "cd " + dirname + " ; git log -n 1 --pretty=format:%H -- " + basename + " || true"
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_git_commit_head(git_dir):
    """
    Get the commit id for the git HEAD.
    """
    cmd = "cd " + git_dir + " ; git rev-parse HEAD || true"
    verbose(cmd, LEVEL_2)
    output = get_shell_cmd_output(cmd)
    return output.strip()


def get_gitdir_pkg_info(git_dir, head_commit=''):
    '''
    Get name,version,arch info for a src git directory.
    '''
    if not head_commit:
        head_commit = get_git_commit_head(git_dir)
    git_version = head_commit
    version = head_commit
    if args.prefer_git_tag:
        git_tag = get_associated_git_tag_for_commit(head_commit, git_dir)
        if git_tag:
            version = git_tag
    remote_url = get_git_remote_url(git_dir)
    if remote_url:
        name = os.path.basename(remote_url)
    else:
        name = os.path.basename(git_dir)
    #pkg_info = ["Name: " + name, "Version: " + head_commit, "Architecture: all",
    #        "Package type: gitrepo", "Remote URL: " + remote_url, "Path: " + git_dir]
    pkg_info_dict = {"Name" : name, "Version" : version, "Git-Version": git_version, "Architecture" : "all",
            "Package type" : "gitrepo", "Remote URL" : remote_url, "Path" : git_dir}
    return pkg_info_dict


def get_all_blobs_of_git_commit(commit, git_dir=''):
    """
    Run the "git rev-list -n 1 commit_id" command to get all blobs of a a commit.
    returns a list of (checksum, size, filename)
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
        tokens = line.split()
        checksum, size = tokens[0], tokens[1]
        width = len(size)
        # len of git SHA1 checksum must be 40
        filename = line[42 + width : ]
        #size = int(size)
        if filename[0] != '.':  # let's exclude hidden files?
            blobs.append( (checksum, filename) )
            # well, no need to save the file size
            #blobs.append( (checksum, size, filename) )
    return blobs


def get_packages_index_db_for_gitdirs(gitdirs):
    '''
    Get the package database for a list of git clone directories.
    :param gitdirs: a list of git directories
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    pkg_db = {}
    for git_dir in gitdirs:
        commit = get_git_commit_head(git_dir)
        blobs = get_all_blobs_of_git_commit(commit, git_dir)
        pkg_info = get_gitdir_pkg_info(git_dir, commit)
        pkg_key = git_dir + " " + pkg_info["Name"] + " " + pkg_info["Version"]
        pkg_db[pkg_key] = {"blobs": blobs, "num_blobs": len(blobs), "pkg_info": pkg_info}
        verbose("git_dir " + git_dir + " contains " + str(len(blobs)) + " blobs", LEVEL_1)
        verbose("git_dir " + git_dir + " pkg_info " + str(pkg_info), LEVEL_1)
    save_json_db(g_jsonfile + "-gitdir-pkg-db.json", pkg_db)
    return pkg_db


def get_gitdir_packages_index_db():
    '''
    Get the package database for a user provided src git directories.
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    gitdirs = get_all_src_gitdirs()
    verbose("List of " + str(len(gitdirs)) + " gitdirs: " + str(gitdirs), LEVEL_4)
    if args.first_n_packages:
            first_n = int(args.first_n_packages)
            start_i = 0
            if args.start_with_ith_package:
                start_i = int(args.start_with_ith_package)
            gitdirs = gitdirs[ start_i : start_i + first_n ]
    return get_packages_index_db_for_gitdirs(gitdirs)


def get_tarball_gitdir_packages_index_db():
    '''
    Get the package database for user provided src tarballs and git directories.
    returns a dict of { package => {"blobs": blobs, "pkg_info": pkg_info} }
    '''
    pkg_db = get_tarball_packages_index_db()
    # merge the gitdir pkg_db with tarball pkg_db
    pkg_db.update( get_gitdir_packages_index_db() )
    save_json_db(g_jsonfile + "-targit-pkg-db.json", pkg_db)
    global g_targit_pkg_db
    g_targit_pkg_db = pkg_db
    # Convert pkg_db to blob_db for use by bomsh_create_bom.py script
    blob_db = convert_pkg_db_to_blob_db(pkg_db)
    save_json_db(g_jsonfile + "-targit-blob-db.json", blob_db)
    blob_pkg_db = { blob : v[0] for blob,v in blob_db.items() }
    save_json_db(g_jsonfile + "-targit-blob-pkg-db.json", blob_pkg_db)
    global g_targit_blob_pkg_db
    g_targit_blob_pkg_db = blob_pkg_db

############################################################
#### End of package database processing routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool indexes source files for a software build workspace")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('--tmpdir',
                    help = "tmp directory, which is /tmp by default")
    parser.add_argument('-O', '--output_dir',
                    help = "the output directory to store generated index DB files")
    parser.add_argument('-j', '--jsonfile',
                    help = "the output JSON file for blob indexing result")
    parser.add_argument('-r', '--raw_logfile',
                    help = "the bomsh_hook_raw_logfile generated by Bomtrace/Bomsh")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument('-p', '--package_files',
                    help = "an extra comma-separated list of RPM/DEB package files to process")
    parser.add_argument('--package_list_file',
                    help = "a text file that contains a list of RPM/DEB package files to process")
    parser.add_argument('--package_dir',
                    help = "an extra comma-separated list of directories which contain RPM/DEB package files to process")
    parser.add_argument('--buildinfo_file',
                    help = "the buildinfo file for debian package build")
    parser.add_argument('--start_with_ith_package',
                    help = "start with the i-th package")
    parser.add_argument('--first_n_packages',
                    help = "only process first N packages")
    parser.add_argument('--package_type',
                    help = "the Linux packaging types, like RPM/DEB, etc.")
    parser.add_argument('--chroot_dir',
                    help = "the mock chroot directory")
    parser.add_argument('--src_tarball_dir',
                    help = "a comma-separated list of directories which contain src tarball files")
    parser.add_argument('--git_top_dir',
                    help = "a comma-separated list of directories which contain src git directoriest")
    parser.add_argument('--ref_pkg_db',
                    help = "a reference pkg_db to help populate the new pkg_db")
    parser.add_argument("--index_installed_pkgs",
                    action = "store_true",
                    help = "index the installed packages in the workspace")
    parser.add_argument("--keep_intermediate_files",
                    action = "store_true",
                    help = "after run completes, keep all intermediate files like unbundled packages, etc.")
    parser.add_argument("--skip_unbundle_if_exist",
                    action = "store_true",
                    help = "skip unbundling a package/tarball if the unbundle directory already exists")
    parser.add_argument("--prefer_git_tag",
                    action = "store_true",
                    help = "prefer to use git tag instead of git commit ID for git version")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    global g_jsonfile
    global g_tmpdir
    if args.tmpdir:
        g_tmpdir = args.tmpdir
        g_jsonfile = os.path.join(g_tmpdir, "bomsh-index")
    if args.output_dir:
        output_dir = args.output_dir
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        g_jsonfile = os.path.join(output_dir, "bomsh-index")
    if args.jsonfile:
        g_jsonfile = args.jsonfile
    global g_chroot_dir
    if args.chroot_dir:
        g_chroot_dir = args.chroot_dir
    global g_package_type
    if args.package_type:
        g_package_type = args.package_type.lower()
    global g_ref_pkg_db
    if args.ref_pkg_db and os.path.isfile(args.ref_pkg_db):
        g_ref_pkg_db = load_json_db(args.ref_pkg_db)

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    # First figure out the list of packages to process.
    package_files = []
    if args.package_dir:
        package_dirs = args.package_dir.split(",")
        package_files = find_all_package_files(package_dirs)
    if args.package_list_file:
        package_files.extend(read_text_file(args.package_list_file).splitlines())
    if args.package_files:
        package_files.extend(args.package_files.split(","))
    package_files = [os.path.abspath(afile) for afile in package_files]

    # Try to index the tarball and gitdir source files
    get_tarball_gitdir_packages_index_db()

    # the real work
    get_workspace_index_db(package_files, args.raw_logfile)


if __name__ == '__main__':
    main()
