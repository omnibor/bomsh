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


# the patch text file to avoid deleting the mmdebstrap chroot directory
mmdebstrap_patch_text = """--- mmdebstrap.bak	2023-09-16 18:50:42.032552913 +0000
+++ mmdebstrap	2023-09-17 04:50:00.625270814 +0000
@@ -6187,6 +6187,7 @@
             error "$options->{root} does not exist";
         }
         info "removing tempdir $options->{root}...";
+        info "Instead we move tempdir $options->{root} to /tmp/bomsh-mmroot dir ...";
         if ($options->{mode} eq 'unshare') {
             # We don't have permissions to remove the directory outside
             # the unshared namespace, so we remove it here.
@@ -6223,9 +6224,13 @@
             # without unshare, we use the system's rm to recursively remove the
             # temporary directory just to make sure that we do not accidentally
             # remove more than we should by using --one-file-system.
-            0 == system('rm', '--interactive=never', '--recursive',
-                '--preserve-root', '--one-file-system', $options->{root})
-              or error "rm failed: $?";
+            0 == system('rm', '-rf', '/tmp/bomsh-mmroot')
+              or error "rm -rf bomsh-mmroot failed: $?";
+            0 == system('mv', $options->{root}, '/tmp/bomsh-mmroot')
+              or error "mv bomsh-mmroot failed: $?";
+            # 0 == system('rm', '--interactive=never', '--recursive',
+            #     '--preserve-root', '--one-file-system', $options->{root})
+            #   or error "rm failed: $?";
         } else {
             error "unknown mode: $options->{mode}";
         }
"""

g_bomsh_dockerfile_str = '''

# Set up debrebuild/mmdebstrap environment
RUN apt update ; export DEBIAN_FRONTEND=noninteractive DEBCONF_NONINTERACTIVE_SEEN=true ; \\
    apt install -y git wget mmdebstrap devscripts autoconf python3-pycurl python3-yaml apt-utils ; \\
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
# if BASELINE_REBUILD is not empty, then it will not use bomtrace2 to run debrebuild, that is, the baseline run.
# if SRC_TAR_DIR is not empty, then the python script must have copied tarball and .dsc file into the bomsher_in directory.
CMD if [ "${SRC_TAR_DIR}" ]; then srctardir_param="--srctardir=/out/bomsher_in" ; fi ; \\
    if [ -z "${BASELINE_REBUILD}" ]; then bomtrace_cmd="/tmp/bomtrace2 -w /tmp/bomtrace_watched_programs -c /tmp/bomtrace.conf -o /tmp/bomsh_hook_strace_logfile " ; fi ; \\
    mkdir -p /out/bomsher_out ; cd /out/bomsher_out ; \\
    if [ "${MM_NO_CLEANUP}" ]; then cp /usr/bin/mmdebstrap /usr/bin/mmdebstrap.bak ; echo "Patching mmdebstrap for no-cleanup." ; \\
    cp /usr/bin/mmdebstrap ./ ; patch -p0 < mmdebstrap_patch_file ; cp mmdebstrap /usr/bin/mmdebstrap ; fi ; \\
    echo $bomtrace_cmd debrebuild $srctardir_param --buildresult=./debs --builder=mmdebstrap /out/bomsher_in/$BUILDINFO_FILE ; \\
    # Run strace to collect artifact dependency fragments (ADF) for debrebuild ; \\
    $bomtrace_cmd debrebuild $srctardir_param --buildresult=./debs --builder=mmdebstrap /out/bomsher_in/$BUILDINFO_FILE ; \\
    if [ "${BASELINE_REBUILD}" ]; then exit 0 ; fi ; \\
    debfiles=`for i in debs/*.deb ; do  echo -n $i, ; done | sed 's/.$//'` ; \\
    rm -rf omnibor omnibor_dir ; mv .omnibor omnibor ; mkdir -p bomsh_logfiles ; cp -f /tmp/bomsh_hook_*logfile* bomsh_logfiles/ ; \\
    if [ "${MM_NO_CLEANUP}" ]; then index_db_param="--pkg_db_file /tmp/bomsh-index-pkg-db.json" ; \\
    # Create the package index database for prov_pkg metadata of source files ; \\
    /tmp/bomsh_index_ws.py --chroot_dir /tmp/bomsh-mmroot -p $debfiles -r /tmp/bomsh_hook_raw_logfile.sha1 --package_type deb ; \\
    cp /tmp/bomsh-mmroot/etc/os-release bomsh_logfiles/mock-os-release ; \\
    cp /tmp/bomsh-index-* bomsh_logfiles ; fi ; \\
    # Create the OmniBOR manifest document and metadata database ; \\
    /tmp/bomsh_create_bom.py -b omnibor_dir -r /tmp/bomsh_hook_raw_logfile.sha1 $index_db_param ; \\
    cp /etc/os-release /tmp/bomsh*.py /tmp/bomtrace* /tmp/bomsh_createbom_* bomsh_logfiles ; \\
    cp /tmp/yongkui-srcpkg/* bomsh_logfiles ; \\
    if [ "${CVEDB_FILE}" ]; then cvedb_file_param="-d /out/bomsher_in/${CVEDB_FILE}" ; fi ; \\
    # Create the OmniBOR ADG trees for built DEB packages based on the OmniBOR manifest document and metadata database ; \\
    /tmp/bomsh_search_cve.py --derive_sbom -b omnibor_dir $cvedb_file_param -f $debfiles -vvv ; cp /tmp/bomsh_search_jsonfile* bomsh_logfiles/ ; \\
    # Extra handling of syft generated SPDX SBOM documents ; \\
    if [ "${SYFT_SBOM}" ]; then /tmp/bomsh_sbom.py -b omnibor_dir -F $debfiles -vv --output_dir syft_sbom --sbom_format spdx --force_insert ; fi ; \\
    if [ "${SYFT_SBOM}" ]; then /tmp/bomsh_sbom.py -b omnibor_dir -F $debfiles -vv --output_dir syft_sbom --sbom_format spdx-json --force_insert ; fi ; \\
    # Extra handling of bomsh-spdx generated SPDX SBOM documents ; \\
    export PYTHONPATH=/root/tools-python/src:/root/beartype:/root/packageurl-python/src ; \\
    if [ "${BOMSH_SPDX}" ]; then /tmp/bomsh_spdx_deb.py -F $debfiles --output_dir bomsh_sbom --sbom_server_url http://your.org ; fi ;
'''

def create_dockerfile(work_dir):
    """
    Create the Dockerfile for rebuilding .deb packages.
    :param work_dir: the directory to save Dockerfile
    """
    if args.docker_image_base:
        from_str = 'FROM ' + args.docker_image_base
    else:
        from_str = 'FROM debian:bookworm'
    dockerfile_str = from_str + g_bomsh_dockerfile_str
    if args.bomsh_spdx:
        # bomsh_spdx_deb.py requires additional python libraries
        dockerfile_str = dockerfile_str.replace("rm -rf /var/lib/apt/lists/* ;",
                "apt install -y python3-requests python3-license-expression python3-uritools python3-rdflib python3-xmltodict python3-yaml ; \\\n"
                "    cd /root ; git clone https://github.com/spdx/tools-python.git ; \\\n"
                "    git clone https://github.com/beartype/beartype.git ; \\\n"
                "    git clone https://github.com/package-url/packageurl-python.git ; \\\n"
                "    rm -rf /var/lib/apt/lists/* ;")
    dockerfile = os.path.join(work_dir, "Dockerfile")
    write_text_file(dockerfile, dockerfile_str)


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
    if args.baseline_rebuild:
        docker_cmd += ' -e BASELINE_REBUILD=baseline_only'
    if args.cve_db_file:
        os.system("cp -f " + args.cve_db_file + " " + bomsher_indir)
        docker_cmd += ' -e CVEDB_FILE=' + os.path.basename(args.cve_db_file)
    if args.mmdebstrap_no_cleanup:
        # do not delete mmdebstrap chroot directory for bomsh_index_ws.py script
        docker_cmd += ' -e MM_NO_CLEANUP=1'
        # write the patch file for later use during docker run
        write_text_file(os.path.join(bomsher_outdir, "mmdebstrap_patch_file"), mmdebstrap_patch_text)
    if args.syft_sbom:
        # Generate SBOM document with the syft tool
        docker_cmd += ' -e SYFT_SBOM=1'
    if args.bomsh_spdx:
        # Generate SPDX SBOM document with the bomsh_spdx_rpm.py tool
        docker_cmd += ' -e BOMSH_SPDX=1'
    docker_cmd += ' -v ' + output_dir + ':/out $(docker build -t bomsher-deb -q ' + bomsher_indir + ')'
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
    parser.add_argument('--docker_image_base',
                    help = "the base docker image to start with")
    parser.add_argument('-o', '--output_dir',
                    help = "the output directory to store rebuilt .deb files and Bomsh/OmniBOR documents, the default is current dir")
    parser.add_argument('-d', '--cve_db_file',
                    help = "the CVE database file, with git blob ID to CVE mappings")
    parser.add_argument("-b", "--baseline_rebuild",
                    action = "store_true",
                    help = "baseline debrebuild only, do not run bomtrace2 to generate OmniBOR documents")
    parser.add_argument("--syft_sbom",
                    action = "store_true",
                    help = "run syft to generate DEB SBOM in spdx/spdx-json SBOM format")
    parser.add_argument("--bomsh_spdx",
                    action = "store_true",
                    help = "run bomsh_spdx_deb.py to generate DEB SBOM in spdx/spdx-json SBOM format")
    parser.add_argument("--mmdebstrap_no_cleanup",
                    action = "store_true",
                    help = "do not cleanup chroot directory after mmdebstrap run")
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
