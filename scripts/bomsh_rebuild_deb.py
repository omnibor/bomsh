#! /bin/env python3
# Copyright (c) 2023 Cisco and/or its affiliates.
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
Bomsh script to reproducibly rebuild a Debian package from its buildinfo.
It also generates OmniBOR documents for the rebuilt Debian packages.
It utilizes Docker container, so make sure Docker or podman is installed.

Even if the Debian src is not in official Debian repo, user can provide
a local src directory, which contains the src tarball and .dsc file.

April 2023, Yongkui Han
"""

import argparse
import sys
import os
import subprocess
import shutil

TOOL_VERSION = '0.0.1'
VERSION = '%(prog)s ' + TOOL_VERSION

LEVEL_0 = 0
LEVEL_1 = 1
LEVEL_2 = 2
LEVEL_3 = 3
LEVEL_4 = 4

args = None


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


def get_or_create_dir(destdir):
    """
    Create a directory if it does not exist. otherwise, return it directly
    return absolute path of destdir
    """
    if destdir and os.path.exists(destdir):
        return os.path.abspath(destdir)
    os.makedirs(destdir)
    return os.path.abspath(destdir)


def write_text_file(afile, text):
    '''
    Write a string to a text file.

    :param afile: the text file to write
    '''
    with open(afile, 'w') as f:
         return f.write(text)


def find_all_symlink_files(builddir, pattern):
    """
    Find all files with the specified pattern in the build dir.
    It simply runs the shell's find command and saves the result.
    :param builddir: String, build dir of the workspace
    :param pattern: string to match
    :returns a list that contains all the file names with the PATTERN string.
    """
    findcmd = "find " + builddir + ' -type l -name "*' + pattern + '*" -print || true'
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True)
    files = output.splitlines()
    return files


def fix_broken_symlink(symlink, new_omnibor_dir):
    """
    Fix a broken symlink.
    :param symlink: the broken symlink file to fix
    :param new_omnibor_dir: the new omnibor_dir to symbolically link to
    """
    afile = os.readlink(symlink)
    tokens = afile.split("/")
    bfile = "/".join(tokens[-3:])
    cmd = "ln -sfr " + os.path.join(new_omnibor_dir, bfile) + " " + symlink
    verbose("fix broken symlink cmd: " + cmd, LEVEL_1)
    os.system(cmd)


def fix_broken_symlinks(bomsher_outdir):
    """
    find and fix all broken symlinks for the rebuild .deb files.
    :param bomsher_outdir: the bomsher container output directory for rebuilt Debian packages
    """
    all_symlinks = find_all_symlink_files(os.path.join(bomsher_outdir, "debs"), ".deb.omnibor_adg.")
    verbose("All broken symlinks: " + str(all_symlinks), LEVEL_2)
    for symlink in all_symlinks:
        fix_broken_symlink(symlink, os.path.join(bomsher_outdir, "omnibor"))


g_bomsh_dockerfile_str = '''FROM debian:bookworm

# Set up debrebuild/mmdebstrap environment
RUN apt-get update ; apt-get install -y git wget mmdebstrap devscripts python3-pycurl python3-yaml apt-utils ; \\
    rm -rf /var/lib/apt/lists/* ;

# Set up bomtrace2/bomsh environment
RUN cd /root ; git clone https://github.com/omnibor/bomsh.git ; \\
    mv /usr/bin/debrebuild /usr/bin/debrebuild.bak ; cp bomsh/scripts/debrebuild /usr/bin/debrebuild ; \\
    cp bomsh/scripts/*.py bomsh/bin/bomtrace* /tmp ; \\
    perl -i -p0e 's|dpkg-buildpackage\\n/usr/bin/rpmbuild|dpkg-buildpackage|' /tmp/bomtrace_watched_programs ; \\
    git clone https://github.com/strace/strace.git ; \\
    cd strace ; patch -p1 < /root/bomsh/.devcontainer/patches/bomtrace2.patch ; \\
    ./bootstrap && ./configure --enable-mpers=check && make ; \\
    cp src/strace /tmp/bomtrace2 ;

# Bomtrace/Bomsh debrebuild run to generate OmniBOR documents
# if BASELINE_DEBREBUILD is not empty, then it will not use bomtrace2 to run debrebuild, that is, the baseline run.
# if SRC_TAR_DIR is not empty, then user must put tarball and .dsc file in the bomsher_in directory.
CMD if [ "${SRC_TAR_DIR}" ]; then srctardir_param="--srctardir=/out/bomsher_in" ; fi ; \\
    if [ -z "${BASELINE_DEBREBUILD}" ]; then bomtrace_cmd="/tmp/bomtrace2 -w /tmp/bomtrace_watched_programs -c /tmp/bomtrace.conf " ; fi ; \\
    mkdir -p /out/bomsher_out ; cd /out/bomsher_out ; \\
    $bomtrace_cmd debrebuild $srctardir_param --buildresult=./debs --builder=mmdebstrap /out/bomsher_in/$BUILDINFO_FILE ; \\
    if [ -z "${BASELINE_DEBREBUILD}" ]; then rm -rf omnibor ; mv .omnibor omnibor ; mkdir -p bomsh_logfiles ; cp -f /tmp/bomsh_hook_*logfile* bomsh_logfiles/ ; fi
'''

def create_dockerfile(work_dir):
    """
    Create the Dockerfile for rebuilding .deb packages.
    :param work_dir: the directory to save Dockerfile
    """
    dockerfile = os.path.join(work_dir, "Dockerfile")
    write_text_file(dockerfile, g_bomsh_dockerfile_str)


def run_docker(buildinfo_file, output_dir):
    """
    Run docker to rebuild .deb packages from its .buildinfo file.
    :param buildinfo_file: the .buildinfo file for Debian packages
    :param output_dir: the output directory to store rebuilt Debian packages and OmniBOR documents.
    """
    # Create bomsher_in dir to pass input files to the container
    # Create bomsher_out dir to save output files generated by the container
    bomsher_indir = get_or_create_dir(os.path.join(output_dir, "bomsher_in"))
    bomsher_outdir = get_or_create_dir(os.path.join(output_dir, "bomsher_out"))
    # The bomsher_in dir is also the docker build work directory
    create_dockerfile(bomsher_indir)
    os.system("cp -f " + buildinfo_file + " " + bomsher_indir)
    docker_cmd = 'docker run --cap-add MKNOD --cap-add SYS_ADMIN --cap-add=SYS_PTRACE -it --rm'
    docker_cmd += ' -e BUILDINFO_FILE=' + os.path.basename(buildinfo_file)
    # Set appropriate parameters to run docker
    if args.src_tar_dir:
        tardir_base = os.path.basename(args.src_tar_dir)
        new_tar_dir = os.path.join(output_dir, tardir_base)
        os.system("cp -f " + args.src_tar_dir + "/*.tar.* " + args.src_tar_dir + "/*.dsc " + bomsher_indir)
        docker_cmd += ' -e SRC_TAR_DIR=/out/bomsher_in'
    if args.baseline_debrebuild:
        docker_cmd += ' -e BASELINE_DEBREBUILD=baseline_only'
    docker_cmd += ' -v ' + output_dir + ':/out $(docker build -t bomsher -q ' + bomsher_indir + ')'
    verbose("==== Here is the docker run command: " + docker_cmd, LEVEL_1)
    os.system(docker_cmd)
    fix_broken_symlinks(bomsher_outdir)
    if args.remove_intermediate_files:
        shutil.rmtree(bomsher_indir)
    verbose("==== All generated files are in this output dir: " + output_dir, LEVEL_1)


############################################################
#### End of hash/checksum routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool rebuilds Debian packages and generates OmniBOR documents")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-s', '--src_tar_dir',
                    help = "the Debian src directory which contains tarball and .dsc file")
    parser.add_argument('-f', '--buildinfo_file',
                    help = "Debian package's .buildinfo file generated from a previous reproducible build")
    parser.add_argument('-o', '--output_dir',
                    help = "the output directory to store rebuilt .deb files and Bomsh/OmniBOR documents, the default is current dir")
    parser.add_argument("-b", "--baseline_debrebuild",
                    action = "store_true",
                    help = "baseline debrebuild only, do not run bomtrace2 to generate OmniBOR documents")
    parser.add_argument("-r", "--remove_intermediate_files",
                    action = "store_true",
                    help = "after run completes, delete all intermediate files like Dockerfile, etc.")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not (args.buildinfo_file):
        print ("Please specify the buildinfo file with -f option!")
        print ("")
        parser.print_help()
        sys.exit()

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    if args.output_dir:
        output_dir = get_or_create_dir(os.path.abspath(args.output_dir))
    else:
        output_dir = os.getcwd()
    run_docker(args.buildinfo_file, output_dir)


if __name__ == '__main__':
    main()
