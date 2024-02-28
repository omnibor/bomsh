#! /usr/bin/env python3
# Copyright (c) 2024 Cisco and/or its affiliates.
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
Bomsh script to create SPDX documents for software product images.

January 2024, Yongkui Han
"""

import sys
import stat
import os
import logging
import shutil
from datetime import datetime
from typing import List
import tempfile

import subprocess
import uuid
import secrets
#import requests
import argparse
import json
import re

# for special filename handling with shell
try:
    from shlex import quote as cmd_quote
except ImportError:
    from pipes import quote as cmd_quote

from spdx_tools.common.spdx_licensing import spdx_licensing
from spdx_tools.spdx.model import (
    Actor,
    ActorType,
    Checksum,
    ChecksumAlgorithm,
    CreationInfo,
    Document,
    ExternalPackageRef,
    ExternalPackageRefCategory,
    File,
    FileType,
    SpdxNoAssertion,
    Package,
    PackagePurpose,
    PackageVerificationCode,
    Relationship,
    RelationshipType,
)

from spdx_tools.spdx.model import Checksum, ChecksumAlgorithm, File, PackageVerificationCode
from spdx_tools.spdx.spdx_element_utils import calculate_file_checksum, calculate_package_verification_code

from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.validation.validation_message import ValidationMessage
from spdx_tools.spdx.writer.write_anything import write_file
from spdx_tools.spdx.writer.write_utils import convert, validate_and_deduplicate

from urllib.parse import urlsplit

#from packageurl import PackageURL

#from pathlib import Path
#from requests.adapters import HTTPAdapter
#from requests.packages.urllib3.util.retry import Retry

TOOL_VERSION = '0.0.1'
VERSION = '%(prog)s ' + TOOL_VERSION

LEVEL_0 = 0
LEVEL_1 = 1
LEVEL_2 = 2
LEVEL_3 = 3
LEVEL_4 = 4

args = None

g_tmpdir = "/tmp"

# This is the database of blob_id => bom_id mappings
g_bom_mappings_db = None

# This is the server where all the SBOM info goes
SBOM_SERVER_URL = "https://your.org"

# This is the server where all the OmniBOR ADG info goes
ADG_SERVER_URL = "https://your.org"

# This is the organization name of the SPDX creator
CREATOR_ORG = "your-organization-name"

# This is the email address of the SPDX creator
CREATOR_EMAIL = "sbom@your-organization-name"

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


def find_all_regular_files(builddir, extra_opt=''):
    """
    Find all regular files in the build dir, excluding symbolic link files.

    It simply runs the shell's find command and saves the result.

    :param builddir: String, build dir of the workspace
    :returns a list that contains all the regular file names.
    """
    #verbose("entering find_all_regular_files: the build dir is " + builddir, LEVEL_4)
    #builddir = os.path.abspath(builddir)
    findcmd = "find " + cmd_quote(builddir) + ' ' + extra_opt + ' -type f -print || true '
    output = subprocess.check_output(findcmd, shell=True, universal_newlines=True, errors='backslashreplace')
    files = output.splitlines()
    return files


def get_filetype(afile):
    """
    Returns the output of the shell command "file afile".

    :param afile: the file to check its file type
    """
    cmd = "file " + cmd_quote(afile) + " || true"
    #print (cmd)
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    res = re.split(r":\s+", output.strip())
    if len(res) > 1:
        return ": ".join(res[1:])
    return "empty"


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


# This generates a 16 digit unique hex string that can be appended to values to make them unique
# syft does this via IDByHash()
# In theory we could have the caller add the number of digits they want
def unique():
    return secrets.token_hex(8)


def valid_spdx_id(name):
    # spdx_id must only contain letters, numbers, "." and "-"
    # If we find a "_" change it to a "-"
    n = name.replace("_", "-")

    # If there are other substitutions, we can place them here
    return n


def build_base_spdx(pkg_name, doc_uuid):
    """
    Create the base SPDX doc for the package.
    """
    # First up, we need general information about the creation of the document, summarised by the CreationInfo class.
    creation_info = CreationInfo(
        # This is a hard coded value (cisco standard is 2.3 for now)
        spdx_version = "SPDX-2.3",
        # Another hard coded value
        spdx_id = "SPDXRef-DOCUMENT",
        # This will be the name of the package for which we are creating the SBOM
        name = pkg_name,
        # Another hard coded value
        data_license = "CC0-1.0",
        # This is the current cisco standard
        document_namespace = f'{SBOM_SERVER_URL}/spdxdocs/SBOM_BOMSH-{pkg_name}-{doc_uuid}',
        # Not sure about the e-mail, but I left it in as a placeholder.  It is an optional parameter
        creators=[Actor(ActorType.ORGANIZATION, CREATOR_ORG, CREATOR_EMAIL)],
        creator_comment='This document has been automatically generated by Bomsh.',
        created=datetime.now()
    )
    # Create our document instance
    return Document(creation_info)


def get_spdx_file_type(afile):
    """
    Get the proper value for the SPDX File type field of a file.
    """
    filetype = get_filetype(afile)
    filetype_lower = filetype.lower()
    verbose(afile + " filetype: " + filetype, LEVEL_4)
    if " script" in filetype:
        return FileType.SOURCE
    elif filetype.startswith("ELF ") or filetype.startswith("ARM ") or " pure executable" in filetype:
        return FileType.BINARY
    elif " image" in filetype_lower:
        return FileType.IMAGE
    elif " text" in filetype_lower:
        return FileType.TEXT
    else:
        return FileType.SOURCE


def analyze_files(img_file, unpack_dir):
    """
    Analyze files of the img_file.
    :param img_file: the image file to analyze
    :param unpack_dir: the unbundle directory of the img_file
    returns a list of file_rec
    """
    files = find_all_regular_files(unpack_dir, "-size +0")
    len_prefix = len(unpack_dir.rstrip("/")) + 1

    file_list = []
    for f in files:
        spdx_file_ref = f'SPDXRef-File-{unique()}'
        # The parser does not like filenames that start with '/'
        file_name = f[len_prefix:]
        file_sha1 = calculate_file_checksum(f, hash_algorithm=ChecksumAlgorithm.SHA1)
        file_sha256 = calculate_file_checksum(f, hash_algorithm=ChecksumAlgorithm.SHA256)
        file_rec = File(
            name=file_name,
            spdx_id=spdx_file_ref,
            file_types=[get_spdx_file_type(f)],
            checksums=[
                Checksum(ChecksumAlgorithm.SHA1, file_sha1),
                Checksum(ChecksumAlgorithm.SHA256, file_sha256),
            ],
        #     license_concluded=spdx_licensing.parse("MIT"),
        #     license_info_in_file=[spdx_licensing.parse("MIT")],
        #     copyright_text="Copyright 2022 Jane Doe",
        )
        # Append the file record
        file_list.append(file_rec)

    # The list of file records
    return file_list


def spdx_add_files(spdx_doc, file_list):
    """
    Add a list of file_rec to spdx_doc.
    """
    for file_rec in file_list:
        spdx_doc.files += [file_rec]

        # Create the contains relationship
        # TODO: We may want to look into a better way of referencing the package but this will do for now since
        # we know we only have one package
        contains_relationship = Relationship(spdx_doc.packages[0].spdx_id, RelationshipType.CONTAINS, file_rec.spdx_id)

        # The spdx library uses run-time type checks when assigning properties.
        # Because in-place alterations like .append() circumvent these checks, we don't use them here.
        spdx_doc.relationships += [contains_relationship]
    return spdx_doc


def create_basic_spdx_package(pkg, pkg_value):
    """
    Create a basic SPDX package for a specific pkg in the image.
    """
    # assume pkg key is format of "path name version"
    pkg_path, pkg_name, pkg_ver = pkg.split()
    # There are only a couple of mandatory package fields
    package = Package(
        name = pkg_name,
        spdx_id = f'SPDXRef-Package-{valid_spdx_id(pkg_name)}-{unique()}',
        download_location = SpdxNoAssertion(),
        files_analyzed = False,
        # Everything else is optional
        version = f'{pkg_ver}',
        #file_name = pkg_path,
        #external_references=[ make_purl_ref(pkg_data, os_rel_data) ]
    )
    if pkg_path != "DERIVED_PKG":
        package.file_name = pkg_path
    return package


def create_all_image_subpackages(pkg_db):
    """
    Create basic SPDX Packages for all packages in the image.
    """
    spdx_pkgs = []
    for pkg in pkg_db:
        if pkg in ("file_path", "build_cmd", "UNKNOWN_PATH UNKNOWN_PKG UNKNOWN_VERSION"):
            continue
        pkg_value = pkg_db[pkg]
        spdx_pkgs.append( create_basic_spdx_package(pkg, pkg_value) )
    return spdx_pkgs


def get_image_pkg_db(pkg_db_file, img_file=''):
    """
    Read the pkg_db_file and get the DB for all sub-packages in the image.
    :param pkg_db_file: the JSON file with { gitoid of img_file => { pkg => pkg_info} } dict
    :param img_file: the specific image file to get the pkg_db
    returns the dict of { pkg => pkg_info}
    """
    db = load_json_db(pkg_db_file)
    if img_file:
        ahash = get_file_hash(img_file)
        if ahash in db:
            return db[ahash]
    for img in db:
        # if img_file is not specified, return first one
        return db[img]


def spdx_add_main_package(spdx_doc, img_file, bom_id, file_verification_code, img_name, img_version, os_rel_data=None):
    """
    Add the main package (the image itself) to spdx_doc.
    """
    # Only name, spdx_id and download_location are mandatory in SPDX v2.3.

    if img_name:
        pkg_name, pkg_ver = img_name, img_version
    else:
        pkg_name, pkg_ver = os.path.basename(img_file), img_version

    sha1_hash = calculate_file_checksum(img_file, hash_algorithm=ChecksumAlgorithm.SHA1)
    md5_hash = calculate_file_checksum(img_file, hash_algorithm=ChecksumAlgorithm.MD5)
    # This was not parsing.  We will have to figure out how to handle non-standard license stuff.
    # pkg_license = rpm_query("{LICENSE}", rpm_file)

    package = Package(
        name = pkg_name,
        spdx_id = f'SPDXRef-Package-{valid_spdx_id(pkg_name)}-{unique()}',
        download_location = SpdxNoAssertion(),
        license_concluded = SpdxNoAssertion(),
        version = f'{pkg_ver}',
        file_name = os.path.basename(img_file),
        # TODO: In theory, we could have the file verification code default to None and if
        # there was a value, then set the file_analyzed / verification_code but since we
        # know we want all the files in the package this should always be here
        files_analyzed = True,
        verification_code = file_verification_code,
        checksums=[
            Checksum(ChecksumAlgorithm.SHA1, sha1_hash),
            Checksum(ChecksumAlgorithm.MD5, md5_hash),
        ],
        external_references=[
            ExternalPackageRef(
                category=ExternalPackageRefCategory.PERSISTENT_ID,
                reference_type="gitoid",
                locator=f'gitoid:blob:sha1:{bom_id}',
                comment=f'{ADG_SERVER_URL}/adg/tree/{bom_id}',
            ),
        ]
        # license_concluded=spdx_licensing.parse("GPL-2.0-only OR MIT"),
        # license_info_from_files=[spdx_licensing.parse("GPL-2.0-only"), spdx_licensing.parse("MIT")],
        # license_declared=spdx_licensing.parse("GPL-2.0-or-later"),
        # license_comment="license comment",
        # supplier=Actor(ActorType.PERSON, "Jane Doe", "jane.doe@example.com"),
        # originator=Actor(ActorType.ORGANIZATION, "some organization", "contact@example.com"),
        # copyright_text="Copyright 2022 Jane Doe",
        # description="package description",
        # attribution_texts=["package attribution"],
        # primary_package_purpose=PackagePurpose.LIBRARY,
        # release_date=datetime(2015, 1, 1),
        # ],
    )

    # Now that we have a package defined, we can add it to the document's package property.
    spdx_doc.packages = [package]

    # A DESCRIBES relationship asserts that the document indeed describes the package.
    describes_relationship = Relationship("SPDXRef-DOCUMENT", RelationshipType.DESCRIBES, package.spdx_id)
    spdx_doc.relationships = [describes_relationship]

    return spdx_doc


def spdx_add_sub_pkgs(spdx_doc, pkg_list):
    """
    Add a list of SPDX Packages to spdx_doc of the image.
    These packages are sub-packages of this image.
    :param spdx_doc: the spdx_doc to update
    :param pkg_list: a list of SPDX Packages
    """
    for package in pkg_list:
        spdx_doc.packages += [package]
        # Then we add the the CONTAINS relationship: the image contains these sub-packages.
        # We assume that the generated package is always Package 0
        depends_relationship = Relationship(spdx_doc.packages[0].spdx_id, RelationshipType.CONTAINS, package.spdx_id)
        # Perhaps we should use DEPENDS_ON relationship?
        spdx_doc.relationships += [depends_relationship]


def build_image_sbom(img_file, unpack_dir, img_name, img_version):
    """
    Create the SPDX doc for an image file.
    :param img_file: the image file to build SBOM
    :param unpack_dir: the unbundle directory for the image file
    :param img_name: the pkg_name to use for this image
    :param img_version: the version to use for this image
    """
    # We will assume that the package name is the basename of the file if not provided
    # If needed we can probably pull / construct this from the package itself
    if img_name:
        pkg_name = img_name
    else:
        pkg_name = os.path.basename(img_file)

    # This will be a random value that will be provided for the document namespace
    doc_uuid = uuid.uuid4()

    # Build the basic SPDX structure
    spdx_doc = build_base_spdx(pkg_name, doc_uuid)

    # In order to compute the packageVerificationCode for a package you need to have a list
    # of the files in the package (along with their SHA1 hash)
    # packageVerificationCode is mandatory if filesAnalyzed = True
    file_list = analyze_files(img_file, unpack_dir)

    # We want to include the OMNIBOR BOM ID for our package
    pkg_blob_id = get_file_hash(img_file)
    if g_bom_mappings_db and pkg_blob_id in g_bom_mappings_db:
        pkg_bom_id = g_bom_mappings_db[pkg_blob_id]
    else:
        pkg_bom_id = pkg_blob_id

    # Now that we have the files, we can calculate the verification_code
    verification_code = calculate_package_verification_code(file_list)

    # The main package is the image file itself
    spdx_doc = spdx_add_main_package(spdx_doc, img_file, pkg_bom_id, verification_code, img_name, img_version)

    # Add the files from the unbundled directory to the document
    spdx_doc = spdx_add_files(spdx_doc, file_list)

    # And add the imaginery sub-packages for binary files in the image
    pkg_db_file = args.img_pkg_db_file
    pkg_list = create_all_image_subpackages(get_image_pkg_db(pkg_db_file, img_file))
    spdx_add_sub_pkgs(spdx_doc, pkg_list)

    # This library provides comprehensive validation against the SPDX specification.
    # Note that details of the validation depend on the SPDX version of the document.
    validation_messages: List[ValidationMessage] = validate_full_spdx_document(spdx_doc)

    # You can have a look at each entry's message and context (like spdx_id, parent_id, full_element)
    # which will help you pinpoint the location of the invalidity.
    for message in validation_messages:
        logging.warning(message.validation_message)
        logging.warning(message.context)

    return (doc_uuid, pkg_bom_id, spdx_doc, validation_messages)


def get_img_name_version(img_file, unpack_dir):
    """
    Get the image name/version for an image file.
    """
    filename = os.path.basename(img_file)
    pkg_name, pkg_version = filename, "UNKNOWN_VERSION"
    tokens = filename.split(".")
    for i, token in enumerate(tokens):
        if token.isdigit():
            pkg_name, pkg_version = ".".join(tokens[:i]), ".".join(tokens[i:])
            break
    # try to get the version from the files in the unpack_dir
    version_file = os.path.join(unpack_dir, "info.ver")
    if os.path.isfile(version_file):
        content = read_text_file(version_file)
        lines = content.splitlines()
        for line in lines:
            tokens = line.split(": ")
            if len(tokens) < 2:
                continue
            if tokens[0].endswith("version"):
                pkg_version = tokens[1].strip()
    else:
        cmd = 'find ' + unpack_dir + ' -name "*BUILD" -type f | xargs cat || true'
        verbose(cmd, LEVEL_3)
        output = get_shell_cmd_output(cmd)
        if output:
            pkg_version = output.strip().split()[0]
    return pkg_name, pkg_version


def handle_files(img_files):
    """
    Handle a list of image files.
    :param img_files: a list of image files.
    """
    if args.output_dir:
        output_dir = get_or_create_dir(args.output_dir)
    else:
        output_dir = os.getcwd()

    num_img_files = len(img_files)
    unbundle_dirs = []
    if args.img_unbundle_dir:
        unbundle_dirs = args.img_unbundle_dir.split(",")
    num_unbundle_dir = len(unbundle_dirs)
    if num_unbundle_dir < num_img_files:
        print(f'Number of unbundle dir {num_unbundle_dir} is smaller than number of image files {num_img_files}')
        exit(1)
    img_names = []
    if args.img_name:
        img_names = args.img_name.split(",")
        if len(img_names) < num_img_files:
            print(f'Number of image name {len(img_names)} is smaller than number of image files {num_img_files}')
            exit(1)
    img_versions = []
    if args.img_version:
        img_versions = args.img_version.split(",")
        if len(img_versions) < num_img_files:
            print(f'Number of image version {len(img_versions)} is smaller than number of image files {num_img_files}')
            exit(1)

    # build the SPDX doc for user provided image files
    omnibor_sbom_docs = []
    img_index = 0
    for img_file in img_files:
        if not os.path.exists(img_file):
            print(f'File ({img_file}) does not exist')
            exit(1)

        # get the associated unbundle dir, image name and version
        unbundle_dir = unbundle_dirs[img_index]
        img_name = ''
        if img_versions:
            img_version = img_versions[img_index]
        else:
            img_name, img_version = get_img_name_version(img_file, unbundle_dir)
        if img_names:
            img_name = img_names[img_index]
        img_index += 1

        # build the SPDX document for the image file
        (doc_uuid, pkg_bom_id, spdx_doc, validation_messages) = build_image_sbom(img_file, unbundle_dir, img_name, img_version)

        # If the document is valid, validation_messages will be empty.
        if validation_messages != []:
            print(f'Could not validate SBOM generated for file: {img_file}')
            exit(1)

        # Finally, we can serialize the document to any of the five supported formats.
        # Using the write_file() method from the write_anything module,
        # the format will be determined by the file ending: .spdx (tag-value), .json, .xml, .yaml. or .rdf (or .rdf.xml)
        # The document namespace will be something like this:
        #    https://sbom.your-org.com/spdxdocs/SBOM_BOMSH-sysstat-11.7.3-9.el8.src.rpm-b184657e-6b09-48d5-a5fc-df2f106f40b5
        # so the path will be: SBOM_BOMSH-sysstat-11.7.3-9.el8.src.rpm-b184657e-6b09-48d5-a5fc-df2f106f40b5.spdx.json
        doc_basename = os.path.basename(urlsplit(spdx_doc.creation_info.document_namespace).path)
        if args.spdx_format:
            format_list = args.spdx_format.split(",")
        else:
            format_list = ["spdx",]
            format_list = ["spdx", "spdx.json", "spdx.rdf", "spdx.xml", "spdx.yaml"]
        for suffix in format_list:
            output_fn = f'{doc_basename}.{suffix}'
            output_file = os.path.join(output_dir, output_fn)
            write_file(spdx_doc, output_file)
            omnibor_sbom_docs.append(output_file)

    print("\nDone. All bomsh created SPDX SBOM documents with OmniBOR info are: " + str(omnibor_sbom_docs))

#########################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool creates SPDX documents for software product images")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument("-i", '--img_file',
                    help = "comma-separated list of image files to create SPDX documents")
    parser.add_argument('--img_name',
                    help = "comma-separated list of names to use for image files")
    parser.add_argument('--img_version',
                    help = "comma-separated list of versions to use for image files")
    parser.add_argument('-O', '--output_dir',
                    help = "the output directory to store the created SPDX documents, the default is current dir")
    parser.add_argument('--sbom_server_url',
                    help = "the URL of the SBOM database server")
    parser.add_argument('--adg_server_url',
                    help = "the URL of the OmniBOR ADG database server")
    parser.add_argument('--creator_organization',
                    help = "the organization name of the creator used in SPDX document")
    parser.add_argument('--creator_email',
                    help = "the email address of the creator used in SPDX document")
    parser.add_argument("--bom_mappings_file",
                    help = "the JSON file with blob-id to bom-id mappings")
    parser.add_argument("--img_pkg_db_file",
                    help = "the JSON file with list of sub-packages in the image")
    parser.add_argument("--img_unbundle_dir",
                    help = "comma-separated unbundle directory of the images")
    parser.add_argument('--spdx_format',
                    help = "comma-separated list of output SPDX SBOM format, like spdx,json,rdf,xml,yaml, etc.")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    global SBOM_SERVER_URL
    if args.sbom_server_url:
        SBOM_SERVER_URL = args.sbom_server_url
    global ADG_SERVER_URL
    if args.adg_server_url:
        ADG_SERVER_URL = args.adg_server_url
    if not ADG_SERVER_URL:
        # if adg server is not configured, then make it same as sbom server
        ADG_SERVER_URL = SBOM_SERVER_URL
    global CREATOR_ORG
    if args.creator_organization:
        CREATOR_ORG = args.creator_organization
    global CREATOR_EMAIL
    if args.creator_email:
        CREATOR_EMAIL = args.creator_email

    if not (args.img_file):
        print ("Please specify the img_file with -i option!")
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

    # this bom_mappings_db is to get the associated bom-id for a blob-id of an artifact
    if args.bom_mappings_file:
        global g_bom_mappings_db
        g_bom_mappings_db = load_json_db(args.bom_mappings_file)

    # real work
    handle_files(args.img_file.split(","))


if __name__ == "__main__":
    main()

