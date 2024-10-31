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
Bomsh script to generate SPDX documents/CVE reports for images with docker.

January 2024, Yongkui Han
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
def verbose(string, level=1):
    """
    Prints information to stdout depending on the verbose level.
    :param string: String to be printed
    :param level: Unsigned Integer, listing the verbose level
    """
    if args.verbose >= level:
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


def find_file_in_dir(afile, adir, file_type="f"):
    '''
    Find a specific file or directory in a directory.
    :param afile: the specific file/dir to find its existence
    :param adir: the directory search inside
    :param file_type: default is regular file "f", can be changed to directory "d"
    returns the first matched file/directory.
    '''
    cmd = 'find ' + adir + ' -name "' + afile + '" -type ' + file_type + ' || true'
    output = get_shell_cmd_output(cmd)
    if not output:
        return ''
    return output.strip().split()[0]


def verify_bomsh_files_in_dir(adir, img_file):
    '''
    Verify that relevant bomsh logfiles do exist in the ADIR.
    :param adir: the directory to check
    :param img_file: the image file to check if its unpack_dir exist in this dir
    returns a list of [pkg_summary_file, bom_mappings_file, unpack_dir]
    '''
    ret = []
    len_prefix = len(adir.rstrip("/")) + 1
    #for afile in ("bomsh_search_jsonfile-img-pkgs-summary.json", "bomsh_search_jsonfile-bom-mappings.json"):
    # Use the details JSON files instead of summary JSON files for pkg-contains-file relations
    for afile in ("bomsh_search_jsonfile-img-pkgs.json", "bomsh_search_jsonfile-bom-mappings.json"):
        bfile = find_file_in_dir(afile, adir)
        if not bfile:
            print("Cannot find " + afile + " in directory " + adir)
            exit(1)
        ret.append(bfile[len_prefix:])
    if args.img_unbundle_dir:
        unbundle_dir = os.path.basename(args.img_unbundle_dir)
    else:
        unbundle_dir = os.path.basename(img_file)
    if unbundle_dir:
        bdir = find_file_in_dir(unbundle_dir, adir, 'd')
        if not bdir:
            print("Cannot find image unpack_dir " + unbundle_dir + " in directory " + adir)
            exit(1)
        ret.append(bdir[len_prefix:])
    verbose("Found bomsh files: " + str(ret), LEVEL_3)
    return ret


g_bomsh_dockerfile_str = '''

# Set up python3/pip3 environment
RUN     \\
    dnf install -y git python3-pip python3-pyyaml which automake autoconf file ; \\
    pip3 install requests license-expression beartype uritools rdflib xmltodict pyyaml packageurl-python ; \\
    dnf clean all ;

# Set up bomsh/spdx_tools-python environment
RUN cd /root ; git clone https://github.com/omnibor/bomsh.git ; \\
    cp bomsh/scripts/bomsh_*.py bomsh/bin/bomtrace* /tmp ; \\
    git clone https://github.com/spdx/tools-python.git ;

CMD cd /out ; export PYTHONPATH=/root/tools-python/src ; \\
    if [ ! -z "${SBOM_SERVER_URL}" ]; then sbom_server_opt="--sbom_server_url ${SBOM_SERVER_URL}" ; \\
    else sbom_server_opt="--sbom_server_url http://your.org" ; fi ; \\
    echo /tmp/bomsh_spdx_image.py -i ${IMG_FILE} --output_dir bomsh_sbom $sbom_server_opt \\
    --img_unbundle_dir ${UNPACK_DIR} --img_pkg_db_file ${IMG_PKG_SUMMARY} --bom_mappings_file ${BOM_MAPPINGS} ; \\
    time /tmp/bomsh_spdx_image.py -i ${IMG_FILE} --output_dir bomsh_sbom $sbom_server_opt \\
    --img_unbundle_dir ${UNPACK_DIR} --img_pkg_db_file ${IMG_PKG_SUMMARY} --bom_mappings_file ${BOM_MAPPINGS} ; \\
    echo "==Done creating SPDX documents" ; \\
    # Extra handling of generating CVE reports with cve-bin-tool ; \\
    if [ "${CVE_REPORT}" ]; then \\
    if [ ! -z "${OFFLINE_CVEDB}" ]; then mkdir -p /root/.cache/cve-bin-tool/ ; touch /root/.cache/cve-bin-tool/cve.db ; \\
    cve-bin-tool --import ${OFFLINE_CVEDB} ; offline_opt="--offline" ; fi ; \\
    # Need to put the extra CVE_OPTION into an array for use by later cve-bin-tool command ; \\
    #echo $CVE_OPTION ; \\
    eval "cve_opt=($CVE_OPTION)" ; declare -p cve_opt ; \\
    spdx_file=`ls -t bomsh_sbom/*.spdx | head -1` ; \\
    echo cve-bin-tool --sbom spdx --sbom-file $spdx_file -f csv,json,html,console -o bomsh_sbom/sbom-cve-report $offline_opt "${cve_opt[@]}" ; \\
    time cve-bin-tool --sbom spdx --sbom-file $spdx_file -f csv,json,html,console -o bomsh_sbom/sbom-cve-report $offline_opt "${cve_opt[@]}" ; \\
    echo cve-bin-tool ${UNPACK_DIR} --sbom-output bomsh_sbom/${IMG_FILE}.sbom -f csv,json,html,console \\
    -o bomsh_sbom/scan-cve-report $offline_opt $sbom_server_opt "${cve_opt[@]}" ; \\
    time cve-bin-tool ${UNPACK_DIR} --sbom-output bomsh_sbom/${IMG_FILE}.sbom -f csv,json,html,console \\
    -o bomsh_sbom/scan-cve-report $offline_opt $sbom_server_opt "${cve_opt[@]}" ; fi ;
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
    if args.cve_report:
        # the cve-bin-tool is required to create CVE reports
        bomsh_dockerfile_str = bomsh_dockerfile_str.replace("dnf clean all ;",
                "pip3 install cve-bin-tool ; \\\n"
                "    dnf clean all ;")
    dockerfile_str = from_str + bomsh_dockerfile_str
    dockerfile = os.path.join(work_dir, "Dockerfile")
    write_text_file(dockerfile, dockerfile_str)


def run_docker(img_file, output_dir):
    """
    Run docker to generate SPDX documents for the image.
    :param img_file: the image file to generate SPDX documents
    :param output_dir: the directory with Bomsh generated logfiles and to store output SPDX files
    """
    img_filename = os.path.basename(img_file)
    new_img_file = os.path.join(output_dir, img_filename)
    if not os.path.exists(new_img_file):
        # copy to the volume directory if necessary
        shutil.copyfile(img_file, new_img_file)
    pkg_summary, bom_mappings, unpack_dir = verify_bomsh_files_in_dir(output_dir, img_file)
    create_dockerfile(output_dir)
    docker_cmd = 'docker run --cap-add MKNOD --cap-add SYS_ADMIN --cap-add=SYS_PTRACE -it --rm'
    docker_cmd += ' -e IMG_FILE=' + img_filename
    # Set appropriate parameters to run docker
    if args.sbom_server_url:
        docker_cmd += ' -e SBOM_SERVER_URL=' + args.sbom_server_url
    if args.img_unbundle_dir:
        docker_cmd += ' -e UNPACK_DIR=' + args.img_unbundle_dir
    else:
        docker_cmd += ' -e UNPACK_DIR=' + unpack_dir
    if args.img_pkg_summary_file:
        docker_cmd += ' -e IMG_PKG_SUMMARY=' + args.img_pkg_summary_file
    else:
        docker_cmd += ' -e IMG_PKG_SUMMARY=' + pkg_summary
    if args.bom_mappings_file:
        docker_cmd += ' -e BOM_MAPPINGS=' + args.bom_mappings_file
    else:
        docker_cmd += ' -e BOM_MAPPINGS=' + bom_mappings
    if args.offline_cvedb:
        # offline mode without downloading CVEs
        docker_cmd += ' -e OFFLINE_CVEDB=' + args.offline_cvedb
    if args.cve_report:
        # Generate CVE report with cve-bin-tool
        docker_cmd += ' -e CVE_REPORT=1'
    if args.cve_option:
        # extra options for the cve-bin-tool
        docker_cmd += ' -e CVE_OPTION="' + args.cve_option + '"'
        verbose("Extra CVE options: " + args.cve_option, LEVEL_2)
    docker_cmd += ' -v ' + output_dir + ':/out $(docker build -t bomsher-img -q ' + output_dir + ')'
    verbose("==== Here is the docker run command: " + docker_cmd, LEVEL_1)
    os.system(docker_cmd)
    #verbose("==== All generated SPDX files are in this output dir: " + output_dir, LEVEL_1)


############################################################
#### End of docker container run routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool generates SPDX documents for images with docker")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-i', '--img_file',
                    help = "the image file to generate SPDX documents")
    parser.add_argument('-b', '--bomsh_logfiles_dir',
                    help = "the directory with Bomsh generated logfiles, the default is current dir")
    parser.add_argument('-o', '--output_dir',
                    help = "the output directory to store the generated SPDX documents, the default is current dir")
    parser.add_argument('--docker_image_base',
                    help = "the base docker image to start with")
    parser.add_argument('--sbom_server_url',
                    help = "the URL of the SBOM database server")
    parser.add_argument('--img_unbundle_dir',
                    help = "the unbundle directory of the image file")
    parser.add_argument('--img_pkg_summary_file',
                    help = "the package summary JSON file of the image file")
    parser.add_argument('--bom_mappings_file',
                    help = "the OmniBOR blob-id to bom-id mappings file")
    parser.add_argument("--offline_cvedb",
                    help = "pre-downloaded CVE database to avoid re-downloading CVEs online")
    parser.add_argument("--cve_option",
                    help = "additional command options to run cve-bin-tool from inside container image")
    parser.add_argument("--cve_report",
                    action = "store_true",
                    help = "run cve_bin_tool to generate CVE reports for the image")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not args.img_file:
        print ("Please specify the image file with -i option!")
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
    if args.bomsh_logfiles_dir:
        bomsh_logfiles_dir = args.bomsh_logfiles_dir
    else:
        bomsh_logfiles_dir = os.getcwd()

    # the real work
    run_docker(args.img_file, bomsh_logfiles_dir)

    # copy out results if necessary
    bomsh_sbom_dir = os.path.join(bomsh_logfiles_dir, "bomsh_sbom")
    if bomsh_sbom_dir != output_dir:
        verbose("Copy generated SPDX files to output dir", LEVEL_2)
        # the below dirs_exist_ok option was newly introduced in Python 3.8 version
        shutil.copytree(bomsh_sbom_dir, output_dir, dirs_exist_ok=True)
    verbose("==== All generated SPDX files are in this output dir: " + output_dir, LEVEL_1)


if __name__ == '__main__':
    main()
