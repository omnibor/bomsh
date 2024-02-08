#! /usr/bin/env python3
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
Bomsh script to rebuild RPM packages from its src RPM.
It also generates OmniBOR documents for the rebuilt RPM packages.
It utilizes Docker container, so make sure Docker or podman is installed.

May 2023, Yongkui Han
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
    all_symlinks = find_all_symlink_files(os.path.join(bomsher_outdir, "rpms"), ".rpm.omnibor_adg.")
    verbose("All broken symlinks: " + str(all_symlinks), LEVEL_2)
    for symlink in all_symlinks:
        fix_broken_symlink(symlink, os.path.join(bomsher_outdir, "omnibor"))


g_bomsh_dockerfile_str = '''

# Set up mock build environment
RUN     \\
    dnf group install -y "Development Tools" ; \\
    dnf install -y git wget mock rpm-build python3-pip python3-pyyaml which automake autoconf ; \\
    dnf clean all ;

# Set up bomtrace2/bomsh environment
RUN cd /root ; git clone https://github.com/omnibor/bomsh.git ; \\
    cp bomsh/scripts/*.py bomsh/bin/bomtrace* /tmp ; \\
    sed -i -e '/\/usr\/bin\/dpkg-source/d' /tmp/bomtrace_watched_programs ; \\
    sed -i -e '/\/usr\/bin\/dpkg-buildpackage/d' /tmp/bomtrace_watched_programs ; \\
    sed -i -e '/\/usr\/bin\/dh_auto_test/d' /tmp/bomtrace_watched_programs ; \\
    git clone https://github.com/strace/strace.git ; \\
    cd strace ; patch -p1 < /root/bomsh/.devcontainer/patches/bomtrace2.patch ; \\
    ./bootstrap && ./configure --enable-mpers=check && make ; \\
    cp src/strace /tmp/bomtrace2 ;

# Set up SPDX tools-python environment
RUN cd /root ; git clone https://github.com/spdx/tools-python.git ;

# Bomtrace/Bomsh mock build run to generate OmniBOR documents
# if BASELINE_REBUILD is not empty, then it will not use bomtrace2 to run mock, that is, the baseline run.
# if CHROOT_CFG is not empty, then the provided mock chroot_cfg will be used, otherwise, default.cfg is used.
CMD if [ -z "${BASELINE_REBUILD}" ]; then bomtrace_cmd="/tmp/bomtrace2 -w /tmp/bomtrace_watched_programs -c /tmp/bomtrace.conf -o /tmp/bomsh_hook_strace_logfile " ; fi ; \\
    if [ -z "${CHROOT_CFG}" ]; then CHROOT_CFG=$(basename $(readlink /etc/mock/default.cfg) .cfg) ; \\
    elif [ -h /etc/mock/${CHROOT_CFG}.cfg ] ; then CHROOT_CFG=$(basename $(readlink /etc/mock/${CHROOT_CFG}.cfg) .cfg) ; fi ; \\
    mkdir -p /out/bomsher_out ; cd /out/bomsher_out ; \\
    # Need to put the extra MOCK_OPTION into an array for use by later mock command ; \\
    echo $MOCK_OPTION ; eval "mock_opt=($MOCK_OPTION)" ; declare -p mock_opt ; \\
    echo $bomtrace_cmd mock -r /etc/mock/${CHROOT_CFG}.cfg --rebuild /out/bomsher_in/$SRC_RPM_FILE --resultdir=./tmprpms --no-cleanup-after "${mock_opt[@]}" ; \\
    # Run strace to collect artifact dependency fragments (ADF) for rpmbuild ; \\
    $bomtrace_cmd mock -r /etc/mock/${CHROOT_CFG}.cfg --rebuild /out/bomsher_in/$SRC_RPM_FILE --resultdir=./tmprpms --no-cleanup-after "${mock_opt[@]}" ; \\
    mkdir rpms ; cp tmprpms/*.rpm rpms ; rm -rf tmprpms ; \\
    if [ "${BASELINE_REBUILD}" ]; then exit 0 ; fi ; \\
    rpmfiles=`for i in rpms/*.rpm ; do  echo -n $i, ; done | sed 's/.$//'` ; \\
    rm -rf omnibor omnibor_dir ; mv .omnibor omnibor ; mkdir -p bomsh_logfiles ; cp -f /tmp/bomsh_hook_*logfile* bomsh_logfiles/ ; \\
    # Create the package index database for prov_pkg metadata of source files ; \\
    /tmp/bomsh_index_ws.py --chroot_dir /var/lib/mock/${CHROOT_CFG}/root -p $rpmfiles -r /tmp/bomsh_hook_raw_logfile.sha1 ; \\
    # Create the OmniBOR manifest document and metadata database ; \\
    /tmp/bomsh_create_bom.py -b omnibor_dir -r /tmp/bomsh_hook_raw_logfile.sha1 --pkg_db_file /tmp/bomsh-index-pkg-db.json ; \\
    cp /var/lib/mock/${CHROOT_CFG}/root/etc/os-release bomsh_logfiles/mock-os-release ; \\
    cp /etc/os-release /tmp/bomsh-index-* /tmp/bomsh_createbom_* bomsh_logfiles ; \\
    cp /tmp/bomsh*.py bomsh_logfiles ; cp /tmp/bomtrace* bomsh_logfiles ; \\
    if [ "${CVEDB_FILE}" ]; then cvedb_file_param="-d /out/bomsher_in/${CVEDB_FILE}" ; fi ; \\
    # Create the OmniBOR ADG trees for built RPM packages based on the OmniBOR manifest document and metadata database ; \\
    /tmp/bomsh_search_cve.py --derive_sbom -b omnibor_dir $cvedb_file_param -f $rpmfiles -vvv ; cp /tmp/bomsh_search_jsonfile* bomsh_logfiles/ ; \\
    # Extra handling of syft generated SPDX SBOM documents ; \\
    if [ "${SYFT_SBOM}" ]; then /tmp/bomsh_sbom.py -b omnibor_dir -F $rpmfiles -vv --output_dir syft_sbom --sbom_format spdx ; fi ; \\
    if [ "${SYFT_SBOM}" ]; then /tmp/bomsh_sbom.py -b omnibor_dir -F $rpmfiles -vv --output_dir syft_sbom --sbom_format spdx-json ; fi ; \\
    # Extra handling of bomsh-spdx generated SPDX SBOM documents ; \\
    export PYTHONPATH=/root/tools-python/src ; \\
    if [ "${BOMSH_SPDX}" ]; then /tmp/bomsh_spdx_rpm.py -r $rpmfiles --output_dir bomsh_sbom --sbom_server_url http://your.org ; fi ;
'''

def create_dockerfile(work_dir):
    """
    Create the Dockerfile for rebuilding .deb packages.
    :param work_dir: the directory to save Dockerfile
    """
    if args.docker_image_base:
        from_str = 'FROM ' + args.docker_image_base
    else:
        from_str = 'FROM almalinux:9'
    bomsh_dockerfile_str = g_bomsh_dockerfile_str
    if "fedora" not in from_str:
        bomsh_dockerfile_str = bomsh_dockerfile_str.replace("RUN     ", "RUN     dnf install -y epel-release ; ")
    if "almalinux" in from_str:
        bomsh_dockerfile_str = bomsh_dockerfile_str.replace("RUN     ", "RUN     dnf install -y almalinux-release ; ")
    if args.bomsh_spdx:
        # bomsh_spdx_rpm.py requires additional python libraries from pip3
        bomsh_dockerfile_str = bomsh_dockerfile_str.replace("dnf clean all ;",
                "pip3 install requests license-expression beartype uritools rdflib xmltodict pyyaml packageurl-python ; \\\n"
                "    dnf clean all ;")
    if args.bomsh_spdx and "almalinux:8" in from_str:
        # almalinux8 has python3.6 version as default, but we need at least python3.8 version for bomsh_spdx_rpm.py and spdx/tools-python library
        bomsh_dockerfile_str = bomsh_dockerfile_str.replace("dnf clean all ;",
                "dnf install -y python38 python38-pip ; ln -sf /usr/bin/python3.8 /usr/bin/python3 ; ln -sf /usr/bin/pip3.8 /usr/bin/pip3 ; \\\n"
                "    pip3.8 install requests license-expression beartype uritools rdflib xmltodict pyyaml packageurl-python ; \\\n"
                "    dnf clean all ;")
    if args.chroot_cfg and "mageia" in args.chroot_cfg:  # special handling for mageia platform due to file permission check with multiple levels of symlinks
        bomsh_dockerfile_str = bomsh_dockerfile_str.replace("cp bomsh/scripts/*.py bomsh/bin/bomtrace* /tmp ; ",
                "cp bomsh/scripts/*.py bomsh/bin/bomtrace* /tmp ; \\\n    sed -i -e 's/#skip_checking_prog_access=1/skip_checking_prog_access=1/' /tmp/bomtrace.conf ; ")
    dockerfile_str = from_str + bomsh_dockerfile_str
    dockerfile = os.path.join(work_dir, "Dockerfile")
    write_text_file(dockerfile, dockerfile_str)


def run_docker(src_rpm_file, output_dir):
    """
    Run docker to rebuild .deb packages from its .buildinfo file.
    :param src_rpm_file: the SRC RPM file for RPM packages
    :param output_dir: the output directory to store rebuilt RPM packages and OmniBOR documents.
    """
    # Create bomsher_in dir to pass input files to the container
    # Create bomsher_out dir to save output files generated by the container
    bomsher_indir = get_or_create_dir(os.path.join(output_dir, "bomsher_in"))
    bomsher_outdir = get_or_create_dir(os.path.join(output_dir, "bomsher_out"))
    # The bomsher_in dir is also the docker build work directory
    create_dockerfile(bomsher_indir)
    os.system("cp -f " + src_rpm_file + " " + bomsher_indir)
    docker_cmd = 'docker run --cap-add MKNOD --cap-add SYS_ADMIN --cap-add=SYS_PTRACE -it --rm'
    docker_cmd += ' -e SRC_RPM_FILE=' + os.path.basename(src_rpm_file)
    # Set appropriate parameters to run docker
    if args.chroot_cfg:
        docker_cmd += ' -e CHROOT_CFG=' + args.chroot_cfg
    if args.cve_db_file:
        os.system("cp -f " + args.cve_db_file + " " + bomsher_indir)
        docker_cmd += ' -e CVEDB_FILE=' + os.path.basename(args.cve_db_file)
    if args.baseline_rebuild:
        docker_cmd += ' -e BASELINE_REBUILD=baseline_only'
    if args.mock_option:
        # usually for the "--no-bootstrap-image" option for mock >= 5.0 version
        docker_cmd += ' -e MOCK_OPTION="' + args.mock_option + '"'
        verbose("Extra mock options: " + args.mock_option, LEVEL_2)
    if args.syft_sbom:
        # Generate SBOM document with the syft tool
        docker_cmd += ' -e SYFT_SBOM=1'
    if args.bomsh_spdx:
        # Generate SPDX SBOM document with the bomsh_spdx_rpm.py tool
        docker_cmd += ' -e BOMSH_SPDX=1'
    docker_cmd += ' -v ' + output_dir + ':/out $(docker build -t bomsher-rpm -q ' + bomsher_indir + ')'
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
    parser.add_argument('-s', '--src_rpm_file',
                    help = "the src RPM file to rebuild")
    parser.add_argument('-o', '--output_dir',
                    help = "the output directory to store rebuilt .deb files and Bomsh/OmniBOR documents, the default is current dir")
    parser.add_argument('--docker_image_base',
                    help = "the base docker image to start with")
    parser.add_argument('-c', '--chroot_cfg',
                    help = "the mock chroot_cfg to use, like alma+epel-9-x86_64 or rhel-9-x86_64, or eol/fedora-31-x86_64, "
                           "the available cfgs can be found at https://github.com/rpm-software-management/mock/tree/main/mock-core-configs/etc/mock")
    parser.add_argument('-d', '--cve_db_file',
                    help = "the CVE database file, with git blob ID to CVE mappings")
    parser.add_argument("--mock_option",
                    help = "additional command options to run mock from inside container image")
    parser.add_argument("--syft_sbom",
                    action = "store_true",
                    help = "run syft to generate RPM SBOM in spdx/spdx-json SBOM format")
    parser.add_argument("--bomsh_spdx",
                    action = "store_true",
                    help = "run bomsh_spdx_rpm.py to generate RPM SBOM in spdx/spdx-json SBOM format")
    parser.add_argument("-b", "--baseline_rebuild",
                    action = "store_true",
                    help = "baseline rebuild only, do not run bomtrace2 to generate OmniBOR documents")
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

    if not (args.src_rpm_file):
        print ("Please specify the SRC RPM file with -s option!")
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
    run_docker(args.src_rpm_file, output_dir)


if __name__ == '__main__':
    main()
