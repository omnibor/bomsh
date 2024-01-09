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
Bomsh script to create or update SBOM documents with OmniBOR info.

September 2023, Yongkui Han
"""

import argparse
import sys
import os
import subprocess
import json
import shutil

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
# dict of { file gitoid => bom_id } mappings
g_omnibor_doc_mappings = {}

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
        print(string)


def load_json_db(db_file):
    """ Load the the data from a JSON file

    :param db_file: the JSON database file
    :returns a dictionary that contains the data
    """
    db = dict()
    with open(db_file, 'r') as f:
        db = json.load(f)
    return db


def save_json_db(db_file, db, indentation=4, sort_keys=True):
    """ Save the dictionary data to a JSON file

    :param db_file: the JSON database file
    :param db: the python dict struct
    :returns None
    """
    if not db:
        return
    verbose("save_json_db: db_size: " + str(len(db)) + " db_file is " + db_file, LEVEL_3)
    try:
        f = open(db_file, 'w')
    except IOError as e:
        verbose("I/O error({0}): {1}".format(e.errno, e.strerror))
        verbose("Error in save_json_db, skipping it.")
    else:
        with f:
            json.dump(db, f, indent=indentation, sort_keys=sort_keys)


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


def which_tool_exist(tool):
    """
    Check whether tool is on PATH.
    """
    rc = subprocess.call(['which', tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return rc == 0


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


############################################################
#### End of helper routines ####
############################################################

def install_syft(destdir):
    '''
    Install syft program to destination directory.
    :param destdir: the destination directory
    '''
    syft_prog = os.path.join(destdir, "syft")
    if os.path.exists(syft_prog):
        verbose("Info: the syft tool already exists: " + syft_prog)
        return syft_prog
    if which_tool_exist("wget"):
        cmd = 'wget -q -O - https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ' + destdir
    elif which_tool_exist("curl"):
        cmd = 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ' + destdir
    else:
        print("Error: Please install curl or wget, which is used to download the syft tool for creating SBOM document!")
        sys.exit(2)
    if args.verbose <= 1:
        cmd += " 2>/dev/null"
    verbose(cmd)
    status = os.system(cmd)
    if status:  # status of 0 means success
        print("Error: Failed to install the syft tool!")
        sys.exit(3)
    return syft_prog


def create_sbom_doc_with_syft(syft_prog, rpmfile, sbom_doc, sbom_format):
    '''
    Create SBOM document with syft program.
    :param syft_prog: the syft program
    :param rpmfile: the artifact file to create SBOM document
    :param sbom_doc: the SBOM document to write
    :param sbom_format: the syft output format for SBOM document
    returns process exit code
    '''
    if not syft_prog:
        return -2
    cmd = syft_prog + " " + rpmfile + " -o " + sbom_format + " > " + sbom_doc
    if args.verbose <= 1:
        cmd += " 2>/dev/null"
    verbose(cmd)
    return os.system(cmd)


def read_omnibor_doc_mapping(bomdir):
    '''
    Read the OmniBOR { gitoid => bom_id } mappings.
    :param bom_dir: the omnibor dir that contains bomsh metadata.
    returns a dict containing the mappings
    '''
    bom_db = {}
    jsonfile = os.path.join(bomdir, "metadata", "bomsh", "bomsh_omnibor_doc_mapping")
    if os.path.exists(jsonfile):
        bom_db = load_json_db(jsonfile)
    else:
        jsonfile = os.path.join(bomdir, ".omnibor", "metadata", "bomsh", "bomsh_omnibor_doc_mapping")
        if os.path.exists(jsonfile):
            bom_db = load_json_db(jsonfile)
    return bom_db


def force_insert_omnibor_into_sbom_doc_spdx_tag(lines, bom_id, hashtype="sha1"):
    '''
    Insert ExternalRef gitoid fields into SBOM document of SPDX-TAG-VALUE format.
    :param lines: the list of lines read from the SBOM document
    :param bom_id: the OmniBOR bom-id
    returns a new list of lines, and insert success/failure
    '''
    found_index = -1
    for i in range(len(lines)):
        line = lines[i]
        if line[:17] == "PackageChecksum: ":
            found_index = i
            break
    if found_index >= 0:
        omnibor_line = "ExternalRef: PERSISTENT-ID gitoid gitoid:blob:" + hashtype + ":" + bom_id + "\n"
        return lines[:found_index] + [omnibor_line,] + lines[found_index:], True
    return lines, False


def insert_omnibor_into_sbom_doc_spdx_tag(sbom_doc, bom_id, hashtype="sha1"):
    '''
    Insert ExternalRef gitoid fields into SBOM document of SPDX-TAG-VALUE format.
    :param sbom_doc: the SBOM document to update
    :param bom_id: the OmniBOR bom-id
    returns a text string, and insert success/failure
    '''
    lines = []
    insert_done = False
    with open(sbom_doc, 'r') as f:
        for line in f:
            lines.append(line)
            if not insert_done and line[:13] == "ExternalRef: ":
                omnibor_line = "ExternalRef: PERSISTENT-ID gitoid gitoid:blob:" + hashtype + ":" + bom_id + "\n"
                lines.append(omnibor_line)
                insert_done = True
    if not insert_done:
        if args.force_insert:
            print("Warning: Failed to find existing ExternalRef line, will try to force insert OmniBOR ExternalRef line to SBOM document")
            lines, insert_done = force_insert_omnibor_into_sbom_doc_spdx_tag(lines, bom_id, hashtype)
            if not insert_done:
                print("Warning: Failed to force insert OmniBOR ExternalRef to SBOM document")
        else:
            print("Warning: Failed to find existing ExternalRef line, thus failing to insert OmniBOR ExternalRef line to SBOM document")
    return "".join(lines), insert_done


def force_insert_omnibor_into_sbom_doc_spdx_json(sbom, bom_id, hashtype="sha1"):
    '''
    Force to insert ExternalRef gitoid fields into SBOM document of SPDX-JSON format.
    :param sbom: the SBOM dict loaded from the SBOM document
    :param bom_id: the OmniBOR bom-id
    returns insert success/failure, and updates sbom dict.
    '''
    packages = sbom["packages"]
    insert_done = False
    for package in packages:
        omniborRef = [{ "referenceCategory": "PERSISTENT-ID",
                       "referenceType": "gitoid",
                       "referenceLocator": "gitoid:blob:" + hashtype + ":" + bom_id
                     },]
        package["externalRefs"] = omniborRef
        insert_done = True
        break
    return insert_done


def insert_omnibor_into_sbom_doc_spdx_json(sbom_doc, bom_id, hashtype="sha1"):
    '''
    Insert ExternalRef gitoid fields into SBOM document of SPDX-JSON format.
    :param sbom_doc: the SBOM document to update
    :param bom_id: the OmniBOR bom-id
    returns a new dict, and insert success/failure
    '''
    sbom = load_json_db(sbom_doc)
    if "packages" not in sbom:
        return ''
    packages = sbom["packages"]
    insert_done = False
    for package in packages:
        if "externalRefs" not in package:
            continue
        externalRefs = package["externalRefs"]
        omniborRef = { "referenceCategory": "PERSISTENT-ID",
                       "referenceType": "gitoid",
                       "referenceLocator": "gitoid:blob:" + hashtype + ":" + bom_id
                     }
        externalRefs.append(omniborRef)
        insert_done = True
        break
    if not insert_done:
        if args.force_insert:  # force to insert even without ExternalRefs existence
            print("Warning: Failed to find existing ExternalRefs, will try to force insert OmniBOR ExternalRef to SBOM document")
            insert_done = force_insert_omnibor_into_sbom_doc_spdx_json(sbom, bom_id, hashtype)
            if not insert_done:
                print("Warning: Failed to force insert OmniBOR ExternalRef to SBOM document")
        else:
            print("Warning: Failed to find existing ExternalRefs, thus failing to insert OmniBOR ExternalRef to SBOM document")
    return sbom, insert_done


def insert_omnibor_into_sbom_doc(sbom_doc, new_sbom_doc, bom_id, sbom_format="spdx"):
    '''
    Insert ExternalRef gitoid fields into SBOM document.
    Only a single package is supported for now.
    :param sbom_doc: the SBOM document to update
    :param new_sbom_doc: the output SBOM document to write with OmniBOR info
    :param bom_id: the OmniBOR bom-id
    :param sbom_format: the syft output format for SBOM document
    returns insert success/failure, and writes new SBOM document.
    '''
    hashtype = "sha1"
    if args.hashtype and args.hashtype.lower() == "sha256":
        hashtype = "sha256"
    if sbom_format and sbom_format.lower() == "spdx-json":
        sbom, insert_done = insert_omnibor_into_sbom_doc_spdx_json(sbom_doc, bom_id, hashtype)
        save_json_db(new_sbom_doc, sbom, indentation=1, sort_keys=False)
        return insert_done
    new_doc_text, insert_done = insert_omnibor_into_sbom_doc_spdx_tag(sbom_doc, bom_id, hashtype)
    write_text_file(new_sbom_doc, new_doc_text)
    return insert_done


def insert_omnibor_into_sbom_doc_for_checksum(sbom_doc, new_sbom_doc, checksum, sbom_format):
    '''
    Insert ExternalRef gitoid fields into SBOM document for a specific gitoid/checksum.
    :param sbom_doc: the SBOM document to update
    :param new_sbom_doc: the output SBOM document to write with OmniBOR info
    :param checksum: the OmniBOR blob ID of an artifact file
    :param sbom_format: the syft output format for SBOM document
    returns insert success/failure, and writes new SBOM document.
    '''
    global g_omnibor_doc_mappings
    if not g_omnibor_doc_mappings and args.bom_dir:
        g_omnibor_doc_mappings = read_omnibor_doc_mapping(args.bom_dir)
    if not g_omnibor_doc_mappings:
        print("Warning: Failed to update SBOM document with OmniBOR info, because cannot find associated OmniBOR bom-ID for blob ID " + checksum)
        return False
    bom_id = ''
    if g_omnibor_doc_mappings and checksum in g_omnibor_doc_mappings:
        bom_id = g_omnibor_doc_mappings[checksum]
    if bom_id:
        return insert_omnibor_into_sbom_doc(sbom_doc, new_sbom_doc, bom_id, sbom_format)
    else:
        verbose("Warning: Cannot find associated OmniBOR bom-id for gitoid: " + checksum)
        return False


def insert_omnibor_into_sbom_doc_for_file(sbom_doc, new_sbom_doc, afile, sbom_format):
    '''
    Insert ExternalRef gitoid fields into SBOM document for a specific artifact file.
    :param sbom_doc: the SBOM document to update
    :param new_sbom_doc: the output SBOM document to write with OmniBOR info
    :param afile: an artifact file
    :param sbom_format: the syft output format for SBOM document
    returns insert success/failure, and writes new SBOM document.
    '''
    if args.hashtype and args.hashtype.lower() == "sha256":
        ahash = get_file_hash(afile, "sha256")
    else:
        ahash = get_file_hash(afile)
    return insert_omnibor_into_sbom_doc_for_checksum(sbom_doc, new_sbom_doc, ahash, sbom_format)


def get_output_omnibor_sbom_doc(sbom_doc, output_dir):
    '''
    Construct the output file name for the input sbom doc.
    '''
    return os.path.join(output_dir, "omnibor." + os.path.basename(sbom_doc))


def handle_input_sbom_doc(sbom_doc, output_dir, sbom_format):
    '''
    update SBOM document with OmniBOR info.
    :param sbom_doc: the SBOM document to update
    :param output_dir: the output directory to save the generated SBOM documents.
    :param sbom_format: the syft output format for SBOM document
    '''
    if args.output_sbom_doc:
        new_file = args.output_sbom_doc
    else:
        new_file = get_output_omnibor_sbom_doc(sbom_doc, output_dir)
    if args.gitbom_id:
        insert_done = insert_omnibor_into_sbom_doc(sbom_doc, new_file, args.gitbom_id, sbom_format=sbom_format)
    elif args.bom_dir:
        if args.file:
            insert_done = insert_omnibor_into_sbom_doc_for_file(sbom_doc, new_file, args.file, sbom_format=sbom_format)
        elif args.checksum_to_update:
            insert_done = insert_omnibor_into_sbom_doc_for_checksum(sbom_doc, new_file, args.checksum, sbom_format=bom_format)
        else:
            print("\nPlease specify OmniBOR artifact file info with -g/-c/-f option!")
            return
    if insert_done:
        print("\nDone. The updated SBOM document with OmniBOR info: " + new_file)
    else:
        print("\nDone. Failed to update SBOM document with OmniBOR info: " + new_file)


def handle_input_files(bom_dir, afiles, output_dir, sbom_format="spdx"):
    '''
    Generate SBOM documents with OmniBOR info for a list of artifact files.
    :param bom_dir: the omnibor dir that contains bomsh metadata.
    :param afiles: a list of artifact files.
    :param output_dir: the output directory to save the generated SBOM documents.
    '''
    global g_omnibor_doc_mappings
    if not g_omnibor_doc_mappings and bom_dir:
        g_omnibor_doc_mappings = read_omnibor_doc_mapping(bom_dir)
    if not g_omnibor_doc_mappings:
        print("Warning: Failed to find blob_id => bom_id mappings in directory " + bom_dir)
        return
    syft_prog = "syft"
    if not which_tool_exist("syft"):
        syft_dir = os.path.join(output_dir, "syft-dir")
        syft_prog = install_syft(syft_dir)
    omnibor_sbom_docs = []
    for afile in afiles:
        sbom_doc = os.path.join(output_dir, os.path.basename(afile) + ".syft." + sbom_format)
        exit_status = create_sbom_doc_with_syft(syft_prog, afile, sbom_doc, sbom_format)
        if exit_status:
            print("Error: The syft tool failed to create SBOM document " + sbom_doc)
            continue
        new_file = get_output_omnibor_sbom_doc(sbom_doc, output_dir)
        insert_done = insert_omnibor_into_sbom_doc_for_file(sbom_doc, new_file, afile, sbom_format=sbom_format)
        if insert_done:
            omnibor_sbom_docs.append(new_file)
    if args.remove_intermediate_files and syft_prog != "syft":
        syft_dir = os.path.join(output_dir, "syft-dir")
        if os.path.exists(syft_dir):
            shutil.rmtree(syft_dir)
    print("\nDone. All created SBOM documents with OmniBOR info are: " + str(omnibor_sbom_docs))


############################################################
#### End of SBOM document processing routines ####
############################################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool creates or updates SBOM documents with OmniBOR info")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-b', '--bom_dir',
                    help = "the single directory to store the generated OmniBOR doc files")
    parser.add_argument('-i', '--input_sbom_doc',
                    help = "the input SBOM file to update, usually generated by syft")
    parser.add_argument('-o', '--output_sbom_doc',
                    help = "the output SBOM file")
    parser.add_argument('-O', '--output_dir',
                    help = "the output directory to store SBOM documents, the default is current dir")
    parser.add_argument('-F', '--files',
                    help = "the comma-separated files to create SBOM documents")
    parser.add_argument('-c', '--checksum',
                    help = "the blob ID of artifact file to update OmniBOR info")
    parser.add_argument('-f', '--file',
                    help = "the artifact file to update OmniBOR info")
    parser.add_argument('-g', '--gitbom_id',
                    help = "the OmniBOR BOM-ID to update the SBOM document")
    parser.add_argument('-s', '--sbom_format',
                    help = "the syft output SBOM format, like SPDX, SPDX-JSON, etc.")
    parser.add_argument('--hashtype',
                    help = "the hash type, like sha1/sha256, the default is sha1")
    parser.add_argument("--force_insert",
                    action = "store_true",
                    help = "force to insert OmniBOR info to SBOM document")
    parser.add_argument("-r", "--remove_intermediate_files",
                    action = "store_true",
                    help = "after run completes, delete all intermediate files like downloaded syft, etc.")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    if not ((args.input_sbom_doc and (args.gitbom_id or args.checksum or args.file))
             or (args.bom_dir and args.files)):
        print ("Please specify the input SBOM document with -i option, "
               "or Bomsh OmniBOR directory with -b option and comma-separated "
               "artifact files with --files option!")
        print ("")
        parser.print_help()
        sys.exit(1)

    print ("Your command line is:")
    print (" ".join(sys.argv))
    print ("The current directory is: " + os.getcwd())
    print ("")
    return args


def main():
    global args
    # parse command line options first
    args = rtd_parse_options()

    output_dir = "."
    if args.output_dir:
        output_dir = args.output_dir
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    sbom_format = "spdx"
    if args.sbom_format:
        sbom_format = args.sbom_format

    if args.input_sbom_doc:
        handle_input_sbom_doc(args.input_sbom_doc, output_dir, sbom_format)
        return

    if args.bom_dir and args.files:
        handle_input_files(args.bom_dir, args.files.split(","), output_dir, sbom_format)


if __name__ == '__main__':
    main()
