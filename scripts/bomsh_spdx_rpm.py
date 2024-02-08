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
Bomsh script to create SPDX documents for RPM packages built from its src RPM.
"""

import sys
import stat
import os
import logging
from datetime import datetime
from typing import List
import tempfile

import subprocess
import uuid
import secrets
import requests
import argparse

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

import json
from urllib.parse import urlsplit

from packageurl import PackageURL

from pathlib import Path
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

TOOL_VERSION = '0.0.1'
VERSION = '%(prog)s ' + TOOL_VERSION

args = None

# This is the database of blob_id => bom_id mappings
g_bom_mappings_db = None

# This is the database of blob_id => SBOM-info mappings
g_pkg_sbom_db = None

# This is the database of pkg_name => blobs/pkg-info mappings
g_pkg_index_db = None

# This is the server where all the SBOM info goes
SBOM_SERVER_URL = ""

# This is the server where all the OmniBOR ADG info goes
ADG_SERVER_URL = ""

# This is the organization name of the SPDX creator
CREATOR_ORG = "your-organization-name"

# This is the email address of the SPDX creator
CREATOR_EMAIL = "sbom@your-organization-name"

# This is the dir where all the built RPMs end up
RPMS_DIR = "/out/bomsher_out/rpms"

# TODO: this is for development purposes.  Once we figure out how we are going to leverage this script we will
# come up with a better way of identifying where our DB files live
LOGFILE_DIR = "/out/bomsher_out/bomsh_logfiles"

# This is the file name of the generated file that contains package dependency information for each generated package
PKG_SBOM_DB = "bomsh_search_jsonfile-sbom.json"

# This is the file name of the generated file that contains package manager information on the dependent packages
PKG_INDEX_DB = "bomsh-index-pkg-db.json"

# This is the file I created that holds the OS Release environment variables.
OS_REL_INFO = "mock-os-release"

DB_FN = "bomsh_search_jsonfile-details.json"
BOM_MAPPING_FN = "bomsh_search_jsonfile-bom-mappings.json"

def get_or_create_dir(destdir):
    """
    Create a directory if it does not exist. otherwise, return it directly
    return absolute path of destdir
    """
    if destdir and os.path.exists(destdir):
        return os.path.abspath(destdir)
    os.makedirs(destdir)
    return os.path.abspath(destdir)

def load_json_db(db_file):
    """ Load the the data from a JSON file

    :param db_file: the JSON database file
    :returns a dictionary that contains the data
    """
    db = dict()
    with open(db_file, 'r') as f:
        db = json.load(f)
    return db

# This generates a 16 digit unique hex string that can be appended to values to make them unique
# syft does this via IDByHash()
# In theory we could have the caller add the number of digits they want
def unique():
    return secrets.token_hex(8)

def rpm_unpack(rpm_name):
    unpack_base = "/tmp/expand"
    unpack_cmd_1 = f'/usr/bin/rpm2cpio {rpm_name}'
    unpack_cmd_2 = 'cpio -idm'

    os.makedirs(unpack_base, exist_ok=True)
    rpm_unpack_dir = tempfile.mkdtemp(dir=unpack_base, prefix=f'{os.path.basename(rpm_name)}-')

    # Extract CPIO arechive from RPM
    # The result ends up in the pipe
    p1 = subprocess.Popen(unpack_cmd_1.split(' '), stdout=subprocess.PIPE)
    # Set our current dir to our temp dir
    # Use CPIO to unpack the archive in the pipe to our temp dir
    # NOTE: if this starts doing weird things (especially for large archives) then we may need
    # to go low level with subprocess.Popen and subprocess.communicate() here
    p2 = subprocess.run(unpack_cmd_2.split(' '), stdin=p1.stdout, capture_output=True, text=True,
        cwd=rpm_unpack_dir)

    print(f'Unpacking archive: {rpm_name} to dir: {rpm_unpack_dir}\n{p2.stdout}')
    return rpm_unpack_dir

def rpm_query_fmt(query_tag, rpm):
    # You quote braces with a '{{'
    cmd_str = f'rpm -qp --queryformat=%{{{query_tag}}} {rpm}'
    query_data = subprocess.run(cmd_str.split(" "), capture_output=True, text=True)
    return query_data.stdout

def rpm_query_files(rpm):
    # I'm putting the fixed width / number stuff first in the output
    cmd_str = 'rpm -q --queryformat=[%{FILEMD5S}\t%{FILEMODES}\t%{FILESIZES}\t%{FILENAMES}\n] ' + rpm

    query_data = subprocess.run(cmd_str.split(" "), capture_output=True, text=True)

    # The cmd output is a list of \n terminated lines with the fields in each line separated by a \t
    # We need to kill the last \n to make the zip work out
    tags = ["file_sha256", "file_mode", "file_size", "file_name"]
    return [dict(zip(tags, x.split('\t'))) for x in query_data.stdout.rstrip('\n').split('\n')]

# Instead of getting the full pkg info from the DB, this one gets it from the package itself
def rpm_query_pkg(rpm):
    cmd_str = f'rpm -qpi {rpm}'
    query_data = subprocess.run(cmd_str.split(" "), capture_output=True, text=True)

    pkg_info = query_data.stdout.splitlines()
    pkg_data = parse_pkg_info(pkg_info)
    return pkg_data

def rpm_pkg_nvra(pkg_data):
    # "Name        : gcc"
    pkg_name = pkg_data['Name']

    # "Version     : 8.5.0"
    pkg_ver = pkg_data['Version']

    # "Release     : 18.el8.alma"
    pkg_rel = pkg_data['Release']

    # "Architecture: x86_64"
    pkg_arch = pkg_data['Architecture']

    return (pkg_name, pkg_ver, pkg_rel, pkg_arch)

def valid_spdx_id(name):
    # spdx_id must only contain letters, numbers, "." and "-"
    # If we find a "_" change it to a "-"
    n = name.replace("_", "-")

    # If there are other substitutions, we can place them here
    return n

def get_pkg_gitoid(pkg_name):
    cmd_str = f'git hash-object {pkg_name}'
    hash_data = subprocess.run(cmd_str.split(" "), capture_output=True, text=True)
    return hash_data.stdout.strip()

def parse_pkg_info(pkg_info_array):
    # Our return value
    pkg_info = dict()

    # Set a description list to hold all the lines of the description
    desc_list = list()

    # Get the length of the array for later use
    end = len(pkg_info_array)

    # Just in case this changes - we only want to specify it once.
    desc_tag = "Description"

    for idx, l in enumerate(pkg_info_array):
        # Every line will have a '<tag>: <value>' format except the description field
        # We only want to split at the first ':' (or else we will be splitting timestamps)
        v = l.split(':', 1)
        # The tag will most likely have trailing spaces
        tag = v[0].rstrip()
        if tag == desc_tag:
            # Just in case we have a value sitting on the same line as the Description
            desc_list += v[1].lstrip()
            # Everything after the Description tag is the description value
            break

        # For everything else we just assign the left-trimmed value to the tag
        value = v[1].lstrip()
        # There will be stuff like this in the list:
        #   "Signature   : (none)",
        #   "Source RPM  : (none)",
        # We could either put in a tag and a None value or not even put in the tag.
        # TODO: Are all these fields deemed "required" and thus something that someone would expect
        # to find?
        if value != "(none)":
            pkg_info[tag] = value

    # We are done with the loop.  Everything else is the desription
    desc_list += pkg_info_array[idx+1:end]
    pkg_info[desc_tag] = desc_list

    return pkg_info

def build_pkg_purl(rel_data, pkg_data):

    # scheme:type/namespace/name@version?qualifiers#subpath

    qual_d = dict()
    arch = pkg_data.get('Architecture')
    if arch:
        qual_d['arch'] = arch

    epoch = pkg_data.get('Epoch')
    if epoch:
        qual_d['epoch'] = epoch

    src_pkg = pkg_data.get('Source RPM')
    if src_pkg:
        qual_d['upstream'] = src_pkg

    qual_d['distro'] = f"{rel_data['ID']}-{rel_data['VERSION_ID']}"

    # TODO: Need to figure out where subpath comes into play.  Where do I find an example

    purl = PackageURL(type='rpm',
                      namespace=rel_data['ID'],
                      name=pkg_data['Name'],
                      version=f"{pkg_data['Version']}-{pkg_data['Release']}",
                      qualifiers=qual_d,
                      subpath=None)

    return str(purl)

def make_purl_ref(pkg_data, os_rel_data):
    purl = build_pkg_purl(os_rel_data, pkg_data)

    ref = ExternalPackageRef(
        category=ExternalPackageRefCategory.PACKAGE_MANAGER,
        reference_type="purl",
        locator=purl,
        # comment="external reference comment",
    )

    return ref

def build_base_spdx(pkg_name, doc_uuid):

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
        document_namespace = f'{SBOM_SERVER_URL}/spdxdocs/{pkg_name}-{doc_uuid}',
        # Not sure about the e-mail, but I left it in as a placeholder.  It is an optional parameter
        creators=[Actor(ActorType.ORGANIZATION, CREATOR_ORG, CREATOR_EMAIL)],
        created=datetime.now()
    )

    # Create our document instance
    return Document(creation_info)

def spdx_add_package(spdx_doc, rpm_file, bom_id, file_verification_code, os_rel_data):
    # Only name, spdx_id and download_location are mandatory in SPDX v2.3.

    # This one
    pkg_data = rpm_query_pkg(rpm_file)

    (pkg_name, pkg_ver, pkg_rel, pkg_arch) = rpm_pkg_nvra(pkg_data)
    sha1_hash = calculate_file_checksum(rpm_file, hash_algorithm=ChecksumAlgorithm.SHA1)
    md5_hash = calculate_file_checksum(rpm_file, hash_algorithm=ChecksumAlgorithm.MD5)
    # This was not parsing.  We will have to figure out how to handle non-standard license stuff.
    # pkg_license = rpm_query("{LICENSE}", rpm_file)

    package = Package(
        name = pkg_name,
        spdx_id = f'SPDXRef-Package-{valid_spdx_id(pkg_name)}-{unique()}',
        download_location = SpdxNoAssertion(),
        license_concluded = SpdxNoAssertion(),
        version = f'{pkg_ver}-{pkg_rel}',
        file_name = os.path.basename(rpm_file),
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
            make_purl_ref(pkg_data, os_rel_data)
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

def analyze_files(rpm_file, unpack_dir):
    # The list of file records
    file_list = []

    # We have a choice as to how we want to analyze our files
    # We can use the RPM tool to query the package or we can look at the extracted CPIO archive
    # A very non-scientific test using sysstat shows that the regular file count (meaning things not directories
    # or symlinks) is the same both ways.
    # We will use the RPM tool to query the package as the preferred mechanism and use the extracted files when that
    # proves unsatisfactory
    file_data = rpm_query_files(rpm_file)

    for idx, f in enumerate(file_data):
        # if the file is a symlink or a directory it won't have a hash and we should probably skip it.
        # Note: if you dump the file mode you need to wrap it in oct(file_mode) for it to look like a normal mode
        if not stat.S_ISREG(int(f['file_mode'])):
            continue

        # NOTE: Another design choice here.  If we want we can also add the file to the reference
        #
        spdx_file_ref = f'SPDXRef-File-{unique()}'
        # The parser does not like filenames that start with '/'
        file_name = f['file_name'].lstrip('/')
        file_sha1 = calculate_file_checksum(os.path.join(unpack_dir, file_name), hash_algorithm=ChecksumAlgorithm.SHA1)
        file_rec = File(
            name=file_name,
            spdx_id=spdx_file_ref,

            # TODO: There are ways we can do a better job of figuring out the file type.
            # In particular, there are these options from the RPM cmd
            #  -c, --configfiles                  list all configuration files
            #  -d, --docfiles                     list all documentation files
            #  -L, --licensefiles                 list all license files
            #  -A, --artifactfiles                list all artifact files
            # and then there is the linux "file" command

            file_types=[FileType.SOURCE],
            checksums=[
                Checksum(ChecksumAlgorithm.SHA1, file_sha1),
                Checksum(ChecksumAlgorithm.SHA256, f['file_sha256']),
            ],
        #     license_concluded=spdx_licensing.parse("MIT"),
        #     license_info_in_file=[spdx_licensing.parse("MIT")],
        #     copyright_text="Copyright 2022 Jane Doe",
        )

        # Append the file record
        file_list.append(file_rec)

    return file_list

def spdx_add_files(spdx_doc, file_list):
    for file in file_list:
        spdx_doc.files += [file]

        # Create the contains relationship
        # TODO: We may want to look into a better way of referencing the package but this will do for now since
        # we know we only have one package
        contains_relationship = Relationship(spdx_doc.packages[0].spdx_id, RelationshipType.CONTAINS, file.spdx_id)

        # The spdx library uses run-time type checks when assigning properties.
        # Because in-place alterations like .append() circumvent these checks, we don't use them here.
        spdx_doc.relationships += [contains_relationship]
    return spdx_doc

def pkg_exists(spdx_doc, pkg):
    pkg_file_name = f'{os.path.basename(pkg)}.rpm'

    for p in spdx_doc.packages:
        if p.file_name == pkg_file_name:
            print(f'Found package: {p.file_name}')
            return p
    return None

def build_basic_spdx_package(pkg, pkg_db, os_rel_data):
    db_entry = pkg_db.get(pkg)
    if not db_entry:
        print(f'Could not find package in DB: {pkg}')
        return None

    pkg_data = parse_pkg_info(db_entry['pkg_info'])

    (pkg_name, pkg_ver, pkg_rel, pkg_arch) = rpm_pkg_nvra(pkg_data)

    # There are only a couple of mandatory package fields
    package = Package(
        name = pkg_name,
        spdx_id = f'SPDXRef-Package-{valid_spdx_id(pkg_name)}-{unique()}',
        download_location = SpdxNoAssertion(),
        files_analyzed = False,
        # Everything else is optional
        version = f'{pkg_ver}-{pkg_rel}',
        file_name = f'{os.path.basename(pkg)}.rpm',
        external_references=[ make_purl_ref(pkg_data, os_rel_data) ]
    )

    return package

def spdx_add_src_pkg_dependency(spdx_doc, gitoid, sbom_db, pkg_db, os_rel_data, key, dependency):
    # For this to work, we will need to add each of the packages in the package section (though we could also
    # add them as external documents)

    # TODO: We should probably harmonize this with the other package add method above

    # Pull out the list of dependent source packages names
    pkg_list = [ _ for _ in sbom_db[gitoid][key].keys()]

    # If we currently don't have a package entry, add one.
    for pkg in pkg_list:
        # The summerization of the sbom detail output leaves the following string in the list
        # of packages.  We don't want that in our output
        if pkg == "UNKNOWN_COMPONENT_VERSION":
            continue
        # All files that were generated during a build will not have an origination package.
        # They are listed under the package name that starts with "GENERATED "
        # The input files used to generate that file will have an origination pkg and those will be captured elsewhere
        if pkg.startswith('DERIVED_PKG '):
            continue
        package = pkg_exists(spdx_doc, pkg)
        if not package:
            package = build_basic_spdx_package(pkg, pkg_db, os_rel_data)
            spdx_doc.packages += [package]

        # Then we add the the dependency relationship.
        # We assume that the generated package is always Package 0
        depends_relationship = Relationship(spdx_doc.packages[0].spdx_id, dependency, package.spdx_id)
        spdx_doc.relationships += [depends_relationship]

    return spdx_doc

def build_sbom(rpm_file, os_rel_db):

    # We will assume that the package name is the basename of the file provided
    # If needed we can probably pull / construct this from the package itself
    pkg_name = os.path.basename(rpm_file)

    # This will be a random value that will be provided for the document namespace
    doc_uuid = uuid.uuid4()

    # At a minimum, we will need to get some SHA1 information from the package files
    # so unpack the RPM and save the directory name
    unpack_dir = rpm_unpack(rpm_file)

    # Build the basic SPDX structure
    spdx_doc = build_base_spdx(pkg_name, doc_uuid)

    # In order to compute the packageVerificationCode for a package you need to have a list
    # of the files in the package (along with their SHA1 hash)
    # packageVerificationCode is mandatory if filesAnalyzed = True
    file_list = analyze_files(rpm_file, unpack_dir)

    # We want to include the OMNIBOR BOM ID for our package
    pkg_blob_id = get_pkg_gitoid(rpm_file)
    if pkg_blob_id in g_bom_mappings_db:
        pkg_bom_id = g_bom_mappings_db[pkg_blob_id]
    else:
        pkg_bom_id = pkg_blob_id

    # Now that we have a files, we can calculate the verification_code
    verification_code = calculate_package_verification_code(file_list)

    # The only package will be the package we generated
    spdx_doc = spdx_add_package(spdx_doc, rpm_file, pkg_bom_id, verification_code, os_rel_db)

    # Add the files from the package to the document
    spdx_doc = spdx_add_files(spdx_doc, file_list)

    # Now for the special sauce.
    # For each file in the package file list, there are input files that were used to create that file.
    # In some cases, the file came directly from the package upstream source.
    # The files could also be patched versions of the upstream source using patches in the distro source package.
    # In other cases (particularly for binary files) there are a number of source files that were used
    # in the compilation process both from the upstream source and other packages.
    # We want to know all the packages from whence all those files came.
    #
    # Each file in our package should have a set of those input / source packages
    #
    # This information is generated as part of the bomsh script and stored in a JSON file (bomsh_search_jsonfile-sbom.json)

    # This file is indexed by the generated package gitoid and contains the build time and dynamic link package dependency info
    pkg_sbom_db = g_pkg_sbom_db

    # This file is indexed by the package name and contains the build time package manager info for the package
    pkg_index_db = g_pkg_index_db

    # And add the build dependency info for the input file source packages
    # BUILD_DEPENDENCY_OF - Is to be used when SPDXRef-A is a build dependency of SPDXRef-B.
    #    EX: A is in the compile scope of B in a Maven project.
    spdx_doc = spdx_add_src_pkg_dependency(spdx_doc, pkg_blob_id, pkg_sbom_db, pkg_index_db, os_rel_db,
                                           'prov_pkgs', RelationshipType.BUILD_DEPENDENCY_OF)

    # These are the run-time dependencies
    # DEPENDS_ON - Is to be used when SPDXRef-A depends on SPDXRef-B.
    #    EX: Package A depends on the presence of package B in order to build and run
    spdx_doc = spdx_add_src_pkg_dependency(spdx_doc, pkg_blob_id, pkg_sbom_db, pkg_index_db, os_rel_db,
                                           'dyn_libs', RelationshipType.DEPENDS_ON)

    # TODO: At this point we should cleanup our extract dir

    # This library provides comprehensive validation against the SPDX specification.
    # Note that details of the validation depend on the SPDX version of the document.
    validation_messages: List[ValidationMessage] = validate_full_spdx_document(spdx_doc)

    # You can have a look at each entry's message and context (like spdx_id, parent_id, full_element)
    # which will help you pinpoint the location of the invalidity.
    for message in validation_messages:
        logging.warning(message.validation_message)
        logging.warning(message.context)

    return (doc_uuid, pkg_bom_id, spdx_doc, validation_messages)

def rest_put(url, payload):
    headers = {
        'Content-Type': 'application/json'
    }

    # Add custom timeout since artifactory seems to have issues at times
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)

    session = requests.Session()
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # DEBUG
    # print ( f' PUT URL = {url}')

    response = session.request("PUT", url,
                                auth=None,
                                # auth=(self._art_usr, self._art_token),
                                headers=headers, data=json.dumps(payload))
    return response

def build_all_spdx(env_data, tree_db):
    if not (SBOM_SERVER_URL and ADG_SERVER_URL):
        print("Please configure the SBOM server and OmniBOR ADG server")
        return

    SBOM_URL = f"{SBOM_SERVER_URL}/sbom/db/"
    OMNIBOR_URL = f"{ADG_SERVER_URL}/adg/db"

    rpm_path = Path(RPMS_DIR)
    # We could also add an "if  _.suffix == '.rpm'" to the end if we want that restriction
    # This will put a full posix path for each RPM in the array
    # use .name if you only want the name
    rpms = [_ for _ in rpm_path.iterdir()]

    # For now there will be a key for each package that we built
    for rpm_path in rpms:
        (doc_uuid, gitoid, spdx_doc, validation_messages) = build_sbom(str(rpm_path), env_data)

        # If the document is valid, validation_messages will be empty.
        if validation_messages != []:
            print(f'Could not validate SBOM generated for file: {rpm_path}')
            # See if we can process the rest
            continue

        # This is basically what the write file command does but it takes the extra step of writing to a file
        validated_doc = validate_and_deduplicate(spdx_doc)
        sbom_dict = convert(validated_doc, None)

        print(f'Package_name: {rpm_path.name}')
        print(f'Package gitoid: {gitoid}')

        pkg_nvra = rpm_query_fmt('NVRA', str(rpm_path))
        # If this is a source package, the result will be the string '(none)'
        # TODO: Can we make this True / False?
        source_pkg = rpm_query_fmt('SOURCERPM', str(rpm_path))

        print(f'NVRA = {pkg_nvra}')
        print(f'Source Package: {source_pkg}')

        sbom_payload = {
            "sbom_name": rpm_path.name,
            "sbom_uuid": str(doc_uuid),
            "nvra": pkg_nvra,
            "source_pkg" : source_pkg,
            "distro" : env_data['ID'],
            "release" : env_data['VERSION_ID'],
            "gitoid": gitoid,
            "sbom": sbom_dict
        }

        response = rest_put(SBOM_URL, sbom_payload)
        print(f'Storing SBOM: {response}\n')

        omnibor_payload = {
            "gitoid": gitoid,
            "pkg_name": rpm_path.name,
            "distro" : env_data['ID'],
            "release" : env_data['VERSION_ID'],
            "adg": tree_db[gitoid]
        }

        response = rest_put(OMNIBOR_URL, omnibor_payload)
        print(f'Storing ADG: {response}\n')

        print("==========\n")

#########################################

def rtd_parse_options():
    """
    Parse command options.
    """
    parser = argparse.ArgumentParser(
        description = "This tool creates SPDX documents for RPM packages built from its src RPM")
    parser.add_argument("--version",
                    action = "version",
                    version=VERSION)
    parser.add_argument('-r', '--rpm_files',
                    help = "comma-separated list of RPM files to create SPDX documents")
    parser.add_argument('-o', '--output_dir',
                    help = "the output directory to store the created SPDX documents, the default is current dir")
    parser.add_argument('--sbom_server_url',
                    help = "the URL of the SBOM database server")
    parser.add_argument('--adg_server_url',
                    help = "the URL of the OmniBOR ADG database server")
    parser.add_argument('--creator_organization',
                    help = "the organization name of the creator used in SPDX document")
    parser.add_argument('--creator_email',
                    help = "the email address of the creator used in SPDX document")
    parser.add_argument("-l", "--logs_dir",
                    help = "the directory with bomsh log files")
    parser.add_argument("--rpms_dir",
                    help = "the directory with RPM files")
    parser.add_argument("-v", "--verbose",
                    action = "count",
                    default = 0,
                    help = "verbose output, can be supplied multiple times"
                           " to increase verbosity")

    # Parse the command line arguments
    args = parser.parse_args()

    global LOGFILE_DIR
    if args.logs_dir:
        LOGFILE_DIR = args.logs_dir
    global RPMS_DIR
    if args.rpms_dir:
        RPMS_DIR = args.rpms_dir
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

    if not (LOGFILE_DIR):
        print ("Please specify the directory of bomsh log files with -l option!")
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

    # We will need the build env OS information regardless of how we build
    ENV_PATH = os.path.join(LOGFILE_DIR, OS_REL_INFO)
    if not os.path.exists(ENV_PATH):
        print(f'File ({ENV_PATH}) does not exist')
        exit(1)

    with open(ENV_PATH, 'r') as f:
        rel_info = f.readlines()

    DB_PATH = os.path.join(LOGFILE_DIR, DB_FN)
    if not os.path.exists(DB_PATH):
        print(f'File ({DB_PATH}) does not exist')
        exit(1)

    # Pull in our the entire tree DB
    tree_db = load_json_db(DB_PATH)

    # Just in case someone hid a second '=' somewhere in there
    # We also don't want the redundant double quotes
    rel_data = dict([_.strip().replace('"','').split('=', 1) for _ in rel_info if '=' in _])

    # This file is indexed by the generated package gitoid and contains the OmniBOR bom-id info
    global g_bom_mappings_db
    g_bom_mappings_db = load_json_db(os.path.join(LOGFILE_DIR, BOM_MAPPING_FN))

    # This file is indexed by the generated package gitoid and contains the build time and dynamic link package dependency info
    global g_pkg_sbom_db
    g_pkg_sbom_db = load_json_db(os.path.join(LOGFILE_DIR, PKG_SBOM_DB))

    # This file is indexed by the package name and contains the build time package manager info for the package
    global g_pkg_index_db
    g_pkg_index_db = load_json_db(os.path.join(LOGFILE_DIR, PKG_INDEX_DB))

    if not args.rpm_files:
        build_all_spdx(rel_data, tree_db)
        return

    if args.output_dir:
        output_dir = get_or_create_dir(args.output_dir)
    else:
        output_dir = os.getcwd()

    # If we supply an argument then build the SPDX doc for those RPM packages
    omnibor_sbom_docs = []
    for rpm_file in args.rpm_files.split(","):
        if not os.path.exists(rpm_file):
            print(f'File ({rpm_file}) does not exist')
            exit(1)

        (doc_uuid, pkg_bom_id, spdx_doc, validation_messages) = build_sbom(rpm_file, rel_data)

        # If the document is valid, validation_messages will be empty.
        if validation_messages != []:
            print(f'Could not validate SBOM generated for file: {rpm_file}')
            exit(1)

        # Finally, we can serialize the document to any of the five supported formats.
        # Using the write_file() method from the write_anything module,
        # the format will be determined by the file ending: .spdx (tag-value), .json, .xml, .yaml. or .rdf (or .rdf.xml)
        # The document namespace will be something like this:
        #    https://sbom.your-org.com/spdxdocs/sysstat-11.7.3-9.el8.src.rpm-b184657e-6b09-48d5-a5fc-df2f106f40b5
        # so the path will be: sysstat-11.7.3-9.el8.src.rpm-b184657e-6b09-48d5-a5fc-df2f106f40b5.spdx.json
        output_fn = f'{os.path.basename(urlsplit(spdx_doc.creation_info.document_namespace).path)}.spdx.json'
        output_file = os.path.join(output_dir, output_fn)
        write_file(spdx_doc, output_file)
        omnibor_sbom_docs.append(output_file)

    print("\nDone. All bomsh created SPDX SBOM documents with OmniBOR info are: " + str(omnibor_sbom_docs))


if __name__ == "__main__":
    main()

