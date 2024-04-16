#! /usr/bin/bash

# This is an example Debian build script to illustrace the usage of
# the --deb_build_script option of the bomsh_rebuild_deb.py script.
# This shell script builds the OpenOSC Debian *.deb package files.
# It also copies the built *.deb files to expected directory.
# It also copies the src tarball files to expected directory.
# These copied *.deb and tarball files are later used by the
# bomsh_spdx_deb.py script to generate SPDX documents.

# pwd should always be the /out/bomsher_out directory inside the docker container
git clone https://github.com/cisco/OpenOSC.git
cd OpenOSC
autoreconf -vfi
./configure
make deb
# also the workspace should not be deleted or cleaned after the build

# must copy the generated *.deb files to the /out/bomsher_out/debs directory
cp ../*.deb ../debs/

# must copy the src tarball files to the /out/bomsher_out/bomsh_logfiles directory
# also need to generate the src tarball first
dpkg-source -b .
cp ../*.dsc ../bomsh_logfiles/
cp ../*.tar.gz ../bomsh_logfiles/

# In the end, everything is ready for the bomsh_spdx_deb.py script
