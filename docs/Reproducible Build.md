# Reproducible Build

Reproducible Build and Bomsh
----------------------------

A lot of Linux packages are now build-reproducible: byte-to-byte identical binaries are rebuilt when the same build environment is reproduced.
About 95% of Debian package are already build-reproducible at the end of 2021, and future Debian Linux distros may enforce reproducible-build.
Bomsh can record the build steps of these build-reproducible packages, and generate the gitBOM docs, without altering the generated binary files.
The created bomsh_gitbom_doc_mapping file can be signed for trust and distributed offline (via packaging or website access).
This makes gitBOM immediately ready for use by people for >90% of official Debian Linux packages, not only for newly built Linux packages.
This holds true for other build-reproducible software like RPM packages, etc.

For reproducible build, the -n option must be specified when running bomsh_hook2.py script, in order to not embed any .bom section into the generated binary files.
This requires the use of "-c bomtrace.conf" option when running bomtrace2.

Using bomsh, we have successfully reproduced the build for some officially released versions of Debian packages: hostname, linux (Linux-kernel), openssl, sysstat, etc.
We also created a repo to store these gitBOM docs.
Please check the [gitbom-repo](https://github.com/yonhan3/gitbom-repo) for some examples.

Such gitBOM repo allows easy and convenient distribution of gitBOM artifact trees for released binaries.
This will motivate people to create various metadata and associate them with gitBOM artifact trees.
CVEs, bugs, features, licensing, security compliance, compatibility, build info, attestations, or declarations of mitigations can all be created as metadata for gitBOM.
When more gitBOM metadata is public available, people will be more motivated to use gitBOM docs and artifact trees.
This way, positive-feedback cycle will be formed to greatly help gitBOM wide adoption.

We believe more use scenarios will be found for the gitBOM repo.
For example, the checksums of known-vulnerable binary files, like OpenSSL releases with HeartBleed vulnerability (CVE-2014-0160),
grub2 releases with BootHole vulnerability (CVE-2020-10713), or Log4j2 releases with Log4Shell vulnerability (CVE-2021-44228)
can be put into a blacklist or alert-list in our repo. People can easily download such a blacklist from our
repo and use it to prevent the execution of such vulnerable binaries or alert the user.

If you have any good ideas, please share with us. More people involved, more useful gitBOM will be!

